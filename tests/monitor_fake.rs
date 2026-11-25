//! The monitor's bookkeeping with every operating-system result scripted. The
//! hooks are really installed on the static fixture, then the record ring is
//! written by hand, as the entry and exit code would write it.

mod common;

use std::collections::BTreeMap;

use common::*;
use leakgc::install::{DEFAULT_HINT, HEAD_OFFSET, RECORDS_OFFSET, REGION_LEN};
use leakgc::ledger::{ImageReport, Reachability, Site};
use leakgc::monitor::Monitor;
use leakgc::ring::{CAPACITY, Kind, RECORD_LEN, Record};
use nix::unistd::Pid;

const CALLER: u64 = 0x40_1000;
const CLONE_VM: u64 = 0x100;
const SHARED_BLOCK: u64 = 0x6000_0000;
/// The stack mapping. `initial_regs` puts `rsp` at 0x7fff_f000, inside it.
const STACK: (u64, u64) = (0x7fff_e000, 0x7fff_f800);
const RSP: u64 = 0x7fff_f000;

/// A process whose hooks are installed, with the bytes the install wrote last.
struct Hooked {
    monitor: Monitor,
    fake: Fake,
    /// The eight jumps and the bytes each one holds after the install.
    jumps: Vec<(u64, Vec<u8>)>,
    /// The memory before the install, which holds the bytes a restore must bring back.
    pristine: BTreeMap<u64, u8>,
}

impl Hooked {
    fn jumps_in_place(&self) -> bool {
        self.jumps
            .iter()
            .all(|(at, bytes)| self.fake.bytes(*at, bytes.len()) == *bytes)
    }

    fn jumps_restored(&self) -> bool {
        self.jumps.iter().all(|(at, bytes)| {
            let original: Vec<u8> = (0..bytes.len() as u64)
                .map(|i| self.pristine[&(at + i)])
                .collect();
            self.fake.bytes(*at, bytes.len()) == original
        })
    }
}

/// A process checked at every trapped call, so most tests need no allocation count.
fn hooked() -> Hooked {
    hooked_every(0)
}

fn hooked_every(collect_every: u64) -> Hooked {
    let mut fake = Fake::new(static_image(), vec![trap(), seccomp(), trap()]);
    let pristine = fake.mem.clone();
    map_writable(&mut fake, STACK.0, STACK.1);
    map_line(&mut fake, DEFAULT_HINT, DEFAULT_HINT + REGION_LEN, "rwxp");
    let mut monitor = Monitor::new(collect_every);
    assert!(monitor.exec(&mut fake, pid()).is_empty());
    assert_eq!(fake.writes.len(), 19, "the install wrote every hook");
    let jumps = fake.writes[11..]
        .iter()
        .map(|(at, bytes)| (*at, bytes.clone()))
        .collect();
    Hooked {
        monitor,
        fake,
        jumps,
        pristine,
    }
}

fn set_head(fake: &mut Fake, head: u64) {
    fake.poke(DEFAULT_HINT + HEAD_OFFSET, &head.to_le_bytes());
}

/// Writes ring slot `index` as the entry and exit code would. An open slot
/// has no result yet.
fn write_slot(fake: &mut Fake, index: u64, record: Record, done: bool) {
    let mut bytes = [0u8; RECORD_LEN];
    for (at, word) in [
        (0, record.size),
        (8, record.caller),
        (16, record.arg),
        (24, record.result),
        (32, record.kind as u64),
        (40, u64::from(done)),
    ] {
        bytes[at..at + 8].copy_from_slice(&word.to_le_bytes());
    }
    let at = DEFAULT_HINT + RECORDS_OFFSET + (index % CAPACITY) * RECORD_LEN as u64;
    fake.poke(at, &bytes);
}

fn malloc_record(size: u64, result: u64) -> Record {
    Record {
        kind: Kind::Malloc,
        size,
        caller: CALLER,
        arg: 0,
        result,
    }
}

fn only(reports: Vec<ImageReport>) -> ImageReport {
    assert_eq!(reports.len(), 1, "one report: {reports:?}");
    reports.into_iter().next().expect("one report")
}

fn has_note(report: &ImageReport, prefix: &str) -> bool {
    report.notes.iter().any(|note| note.starts_with(prefix))
}

#[test]
fn a_trapped_call_drains_the_finished_records_into_the_report() {
    let mut h = hooked();
    set_head(&mut h.fake, 1);
    write_slot(&mut h.fake, 0, malloc_record(16, 0x7000), true);

    h.monitor.trapped(&mut h.fake, pid(), None);

    let report = only(h.monitor.finish());
    assert_eq!(report.label, "image 1 (pid 100)");
    assert_eq!(
        report.sites,
        vec![Site {
            caller: CALLER,
            blocks: 1,
            bytes: 16
        }]
    );
    assert_eq!(
        report.notes.last().map(String::as_str),
        Some("no exit was observed")
    );
}

#[test]
fn an_open_record_stops_the_drain_until_it_finishes() {
    let mut h = hooked();
    set_head(&mut h.fake, 2);
    write_slot(&mut h.fake, 0, malloc_record(16, 0), false);
    write_slot(&mut h.fake, 1, malloc_record(32, 0x8000), true);

    h.monitor.trapped(&mut h.fake, pid(), Some(libc::SYS_mmap));
    write_slot(&mut h.fake, 0, malloc_record(16, 0x7000), true);
    h.monitor.trapped(&mut h.fake, pid(), Some(libc::SYS_mmap));

    let report = only(h.monitor.finish());
    assert_eq!(
        report.sites,
        vec![Site {
            caller: CALLER,
            blocks: 2,
            bytes: 48
        }],
        "the record after the open one was read once, in order"
    );
}

#[test]
fn a_record_that_does_not_decode_stops_reading_and_drops_the_hooks() {
    let mut h = hooked();
    set_head(&mut h.fake, 1);
    h.fake
        .poke(DEFAULT_HINT + RECORDS_OFFSET, &[0u8; RECORD_LEN]);
    h.monitor.trapped(&mut h.fake, pid(), None);

    h.fake.regs.rdi = CLONE_VM;
    h.monitor.trapped(&mut h.fake, pid(), Some(libc::SYS_clone));

    let report = only(h.monitor.finish());
    assert_eq!(report.notes.len(), 3, "{:?}", report.notes);
    assert!(has_note(&report, "record 0 is corrupt"));
    assert_eq!(
        report.reachability,
        Reachability::Incomplete("record 0 is corrupt".to_string())
    );
}

#[test]
fn an_unreadable_head_is_noted_and_no_record_is_read() {
    let mut h = hooked();
    set_head(&mut h.fake, 1);
    h.fake.fail_at = Some(h.fake.calls);

    h.monitor.trapped(&mut h.fake, pid(), None);

    let report = only(h.monitor.finish());
    assert!(report.sites.is_empty());
    assert!(has_note(
        &report,
        "cannot read the record head: injected read failure"
    ));
}

#[test]
fn unreadable_records_are_noted() {
    let mut h = hooked();
    set_head(&mut h.fake, 1);
    h.fake.fail_at = Some(h.fake.calls + 1);

    h.monitor.trapped(&mut h.fake, pid(), None);

    let report = only(h.monitor.finish());
    assert!(report.sites.is_empty());
    assert!(has_note(
        &report,
        "cannot read the records: injected read failure"
    ));
}

#[test]
fn overwritten_records_are_noted_before_the_read() {
    let mut h = hooked();
    set_head(&mut h.fake, CAPACITY + 5);

    h.monitor.trapped(&mut h.fake, pid(), None);

    let report = only(h.monitor.finish());
    assert!(has_note(
        &report,
        "5 records were overwritten before they were read"
    ));
    assert!(has_note(&report, "cannot read the records"));
}

#[test]
fn a_clone_that_shares_memory_removes_the_hooks() {
    let mut h = hooked();
    set_head(&mut h.fake, 0);
    h.fake.regs.rdi = CLONE_VM;

    h.monitor.trapped(&mut h.fake, pid(), Some(libc::SYS_clone));

    assert!(h.jumps_restored());
    let report = only(h.monitor.finish());
    assert!(has_note(
        &report,
        "hooks removed at a clone that shares memory"
    ));
}

#[test]
fn a_clone_without_shared_memory_keeps_the_hooks() {
    let mut h = hooked();
    set_head(&mut h.fake, 0);

    h.monitor.trapped(&mut h.fake, pid(), Some(libc::SYS_clone));

    assert!(h.jumps_in_place());
    let report = only(h.monitor.finish());
    assert_eq!(report.notes.len(), 2, "{:?}", report.notes);
}

#[test]
fn a_clone3_reads_its_flags_from_the_argument_block() {
    let mut h = hooked();
    set_head(&mut h.fake, 0);
    h.fake.poke(SHARED_BLOCK, &CLONE_VM.to_le_bytes());
    h.fake.regs.rdi = SHARED_BLOCK;

    h.monitor
        .trapped(&mut h.fake, pid(), Some(libc::SYS_clone3));

    assert!(h.jumps_restored());
}

#[test]
fn a_clone3_without_shared_memory_keeps_the_hooks() {
    let mut h = hooked();
    set_head(&mut h.fake, 0);
    h.fake.poke(SHARED_BLOCK, &0u64.to_le_bytes());
    h.fake.regs.rdi = SHARED_BLOCK;

    h.monitor
        .trapped(&mut h.fake, pid(), Some(libc::SYS_clone3));

    assert!(h.jumps_in_place());
}

#[test]
fn a_clone3_whose_flags_cannot_be_read_removes_the_hooks() {
    let mut h = hooked();
    set_head(&mut h.fake, 0);
    h.fake.regs.rdi = SHARED_BLOCK;

    h.monitor
        .trapped(&mut h.fake, pid(), Some(libc::SYS_clone3));

    assert!(h.jumps_restored());
}

#[test]
fn a_clone_whose_registers_cannot_be_read_removes_the_hooks() {
    let mut h = hooked();
    set_head(&mut h.fake, 0);
    h.fake.fail_at = Some(h.fake.calls + 1);

    h.monitor.trapped(&mut h.fake, pid(), Some(libc::SYS_clone));

    assert!(h.jumps_restored());
}

#[test]
fn a_failed_removal_at_a_shared_clone_is_noted_as_unreliable() {
    let mut h = hooked();
    set_head(&mut h.fake, 0);
    h.fake.regs.rdi = CLONE_VM;
    h.fake.fail_at = Some(h.fake.calls + 2);

    h.monitor.trapped(&mut h.fake, pid(), Some(libc::SYS_clone));

    assert!(h.jumps_in_place());
    let report = only(h.monitor.finish());
    assert!(has_note(
        &report,
        "hooks could not be removed at a clone that shares memory (injected write failure): counts after this point are not reliable"
    ));
}

#[test]
fn a_forked_child_inherits_the_parent_and_reads_from_the_same_cursor() {
    let mut h = hooked();
    set_head(&mut h.fake, 1);
    write_slot(&mut h.fake, 0, malloc_record(16, 0x7000), true);
    h.monitor.trapped(&mut h.fake, pid(), None);

    h.monitor.forked(&mut h.fake, pid(), Pid::from_raw(101));
    h.monitor
        .forked(&mut h.fake, Pid::from_raw(999), Pid::from_raw(1000));
    h.monitor.trapped(&mut h.fake, Pid::from_raw(101), None);

    let reports = h.monitor.finish();
    assert_eq!(reports.len(), 2, "the unknown parent adds nothing");
    let expected = vec![Site {
        caller: CALLER,
        blocks: 1,
        bytes: 16,
    }];
    let parent = reports
        .iter()
        .find(|r| r.label == "image 1 (pid 100)")
        .expect("parent report");
    assert_eq!(parent.sites, expected);
    let child = reports
        .iter()
        .find(|r| r.label == "image 1 (pid 100) forked as pid 101")
        .expect("child report");
    assert_eq!(
        child.sites, expected,
        "the child does not count the record twice"
    );
    assert!(
        child
            .notes
            .iter()
            .any(|note| note == "forked from pid 100: inherits the parent's outstanding blocks")
    );
}

#[test]
fn an_exit_is_archived_with_its_reason_and_an_unknown_pid_is_ignored() {
    let mut h = hooked();
    set_head(&mut h.fake, 1);
    write_slot(&mut h.fake, 0, malloc_record(16, 0x7000), true);
    h.monitor.trapped(&mut h.fake, pid(), None);

    h.monitor.exited(pid(), "exit code 0".to_string());
    h.monitor
        .exited(Pid::from_raw(999), "exit code 0".to_string());

    let report = only(h.monitor.finish());
    assert_eq!(report.notes.last(), Some(&"exit code 0".to_string()));
    assert_eq!(report.sites.len(), 1);
}

#[test]
fn a_new_image_archives_the_old_one_and_a_dynamic_image_is_not_covered() {
    let mut h = hooked();
    let mut dynamic = Fake::new(dynamic_image(), vec![]);

    assert!(h.monitor.exec(&mut dynamic, pid()).is_empty());

    let reports = h.monitor.finish();
    assert_eq!(reports.len(), 2, "{reports:?}");
    assert_eq!(reports[0].label, "image 1 (pid 100)");
    assert_eq!(
        reports[0].notes.last(),
        Some(&"replaced by exec".to_string())
    );
    assert_eq!(reports[1].label, "image 2 (pid 100)");
    assert!(
        reports[1]
            .notes
            .iter()
            .any(|note| note == "not covered: NotStaticExecutable"),
        "{:?}",
        reports[1].notes
    );
}

#[test]
fn a_trap_from_an_unknown_process_is_ignored() {
    let mut fake = Fake::new(static_image(), vec![]);
    let mut monitor = Monitor::new(0);

    monitor.trapped(&mut fake, pid(), Some(libc::SYS_clone));

    assert_eq!(fake.calls, 0);
    assert!(monitor.finish().is_empty());
}

#[test]
fn a_checked_report_lists_the_blocks_that_nothing_reaches() {
    let mut h = hooked();
    map_writable(&mut h.fake, 0x7000, 0x9000);
    set_head(&mut h.fake, 2);
    write_slot(&mut h.fake, 0, malloc_record(16, 0x7000), true);
    write_slot(&mut h.fake, 1, malloc_record(32, 0x8000), true);
    put_word(&mut h.fake, RSP + 0x100, 0x7000);

    h.monitor.trapped(&mut h.fake, pid(), None);

    let report = only(h.monitor.finish());
    assert_eq!(
        report.reachability,
        Reachability::Checked {
            lost: vec![Site {
                caller: CALLER,
                blocks: 1,
                bytes: 32
            }]
        }
    );
}

#[test]
fn a_check_waits_until_collect_every_allocations_are_counted() {
    let mut h = hooked_every(3);
    map_writable(&mut h.fake, 0x7000, 0x9000);
    set_head(&mut h.fake, 2);
    write_slot(&mut h.fake, 0, malloc_record(16, 0x7000), true);
    write_slot(&mut h.fake, 1, malloc_record(32, 0x8000), true);
    put_word(&mut h.fake, RSP + 0x100, 0x7000);

    h.monitor.trapped(&mut h.fake, pid(), None);

    let report = only(h.monitor.finish());
    assert_eq!(report.reachability, Reachability::Unchecked);
}

#[test]
fn a_check_runs_at_the_trapped_call_that_reaches_collect_every() {
    let mut h = hooked_every(2);
    map_writable(&mut h.fake, 0x7000, 0x9000);
    set_head(&mut h.fake, 2);
    write_slot(&mut h.fake, 0, malloc_record(16, 0x7000), true);
    write_slot(&mut h.fake, 1, malloc_record(32, 0x8000), true);
    put_word(&mut h.fake, RSP + 0x100, 0x7000);

    h.monitor.trapped(&mut h.fake, pid(), None);

    let report = only(h.monitor.finish());
    assert_eq!(
        report.reachability,
        Reachability::Checked {
            lost: vec![Site {
                caller: CALLER,
                blocks: 1,
                bytes: 32
            }]
        }
    );
}

#[test]
fn frees_do_not_count_toward_collect_every() {
    let mut h = hooked_every(2);
    map_writable(&mut h.fake, 0x7000, 0x9000);
    set_head(&mut h.fake, 2);
    write_slot(&mut h.fake, 0, malloc_record(16, 0x7000), true);
    write_slot(
        &mut h.fake,
        1,
        Record {
            kind: Kind::Free,
            size: 0,
            caller: CALLER,
            arg: 0x7000,
            result: 0,
        },
        true,
    );

    h.monitor.trapped(&mut h.fake, pid(), None);

    let report = only(h.monitor.finish());
    assert_eq!(report.reachability, Reachability::Unchecked);
}

#[test]
fn a_check_restarts_the_count() {
    let mut h = hooked_every(2);
    map_writable(&mut h.fake, 0x7000, 0x9000);
    put_word(&mut h.fake, RSP + 0x100, 0x7000);
    set_head(&mut h.fake, 2);
    write_slot(&mut h.fake, 0, malloc_record(16, 0x7000), true);
    write_slot(&mut h.fake, 1, malloc_record(32, 0x8000), true);
    h.monitor.trapped(&mut h.fake, pid(), None);

    // Nothing reaches the 16-byte block now, but one allocation is below the count.
    put_word(&mut h.fake, RSP + 0x100, 0);
    set_head(&mut h.fake, 3);
    write_slot(&mut h.fake, 2, malloc_record(8, 0x8100), true);
    h.monitor.trapped(&mut h.fake, pid(), None);

    let report = only(h.monitor.finish());
    assert_eq!(
        report.reachability,
        Reachability::Checked {
            lost: vec![Site {
                caller: CALLER,
                blocks: 1,
                bytes: 32
            }]
        }
    );
}

#[test]
fn a_check_that_meets_an_open_call_waits_for_the_next_trapped_call() {
    let mut h = hooked_every(2);
    map_writable(&mut h.fake, 0x7000, 0x9000);
    put_word(&mut h.fake, RSP + 0x100, 0x7000);
    put_word(&mut h.fake, RSP + 0x108, 0x8000);
    set_head(&mut h.fake, 3);
    write_slot(&mut h.fake, 0, malloc_record(16, 0x7000), true);
    write_slot(&mut h.fake, 1, malloc_record(32, 0x8000), true);
    write_slot(&mut h.fake, 2, malloc_record(8, 0), false);

    h.monitor.trapped(&mut h.fake, pid(), None);
    write_slot(&mut h.fake, 2, malloc_record(8, 0x8100), true);
    h.monitor.trapped(&mut h.fake, pid(), None);

    let report = only(h.monitor.finish());
    assert_eq!(
        report.reachability,
        Reachability::Checked {
            lost: vec![Site {
                caller: CALLER,
                blocks: 1,
                bytes: 8
            }]
        }
    );
}

#[test]
fn a_fork_is_checked_whatever_the_count() {
    let mut h = hooked_every(100);
    map_writable(&mut h.fake, 0x7000, 0x9000);
    set_head(&mut h.fake, 1);
    write_slot(&mut h.fake, 0, malloc_record(16, 0x7000), true);

    h.monitor.forked(&mut h.fake, pid(), Pid::from_raw(101));

    let reports = h.monitor.finish();
    assert_eq!(reports.len(), 2, "{reports:?}");
    for report in reports {
        assert_eq!(
            report.reachability,
            Reachability::Checked {
                lost: vec![Site {
                    caller: CALLER,
                    blocks: 1,
                    bytes: 16
                }]
            }
        );
    }
}

#[test]
fn a_clone_that_shares_memory_ends_the_reachability_checks() {
    let mut h = hooked();
    set_head(&mut h.fake, 0);
    h.monitor.trapped(&mut h.fake, pid(), None);
    h.fake.regs.rdi = CLONE_VM;

    h.monitor.trapped(&mut h.fake, pid(), Some(libc::SYS_clone));

    let report = only(h.monitor.finish());
    assert!(matches!(
        &report.reachability,
        Reachability::Incomplete(reason) if reason.starts_with("threads started")
    ));
}

#[test]
fn an_unparsable_memory_map_is_reported_as_not_checked() {
    let mut h = hooked();
    set_head(&mut h.fake, 0);
    h.fake.maps = "not a mapping\n".to_string();

    h.monitor.trapped(&mut h.fake, pid(), None);

    let report = only(h.monitor.finish());
    assert_eq!(
        report.reachability,
        Reachability::Incomplete("the memory map cannot be parsed".to_string())
    );
}

#[test]
fn an_image_that_is_not_hooked_is_never_checked() {
    let mut fake = Fake::new(dynamic_image(), vec![]);
    let mut monitor = Monitor::new(0);
    assert!(monitor.exec(&mut fake, pid()).is_empty());

    monitor.trapped(&mut fake, pid(), None);

    let report = only(monitor.finish());
    assert_eq!(report.reachability, Reachability::Unchecked);
}

#[test]
fn a_trap_inside_a_hooked_call_keeps_the_last_complete_check() {
    let mut h = hooked();
    set_head(&mut h.fake, 0);
    h.monitor.trapped(&mut h.fake, pid(), None);
    set_head(&mut h.fake, 1);
    write_slot(&mut h.fake, 0, malloc_record(16, 0), false);
    h.fake.maps = "not a mapping\n".to_string();

    h.monitor.trapped(&mut h.fake, pid(), Some(libc::SYS_mmap));

    let report = only(h.monitor.finish());
    assert_eq!(report.reachability, Reachability::Checked { lost: vec![] });
}

#[test]
fn an_unreadable_record_makes_that_check_incomplete() {
    let mut h = hooked();
    set_head(&mut h.fake, 1);
    h.fake.fail_at = Some(h.fake.calls + 1);

    h.monitor.trapped(&mut h.fake, pid(), None);

    let report = only(h.monitor.finish());
    assert_eq!(
        report.reachability,
        Reachability::Incomplete("cannot read the records: injected read failure".to_string())
    );
}

#[test]
fn a_later_drain_that_reads_the_records_gives_a_checked_result_again() {
    let mut h = hooked();
    set_head(&mut h.fake, 1);
    write_slot(&mut h.fake, 0, malloc_record(16, 0x7000), true);
    h.fake.fail_at = Some(h.fake.calls + 1);
    h.monitor.trapped(&mut h.fake, pid(), None);

    h.monitor.trapped(&mut h.fake, pid(), None);

    let report = only(h.monitor.finish());
    assert_eq!(
        report.reachability,
        Reachability::Checked {
            lost: vec![Site {
                caller: CALLER,
                blocks: 1,
                bytes: 16
            }]
        }
    );
}

#[test]
fn overwritten_records_make_every_later_check_incomplete() {
    let mut h = hooked();
    set_head(&mut h.fake, CAPACITY + 5);

    h.monitor.trapped(&mut h.fake, pid(), None);
    h.monitor.trapped(&mut h.fake, pid(), None);

    let report = only(h.monitor.finish());
    assert_eq!(
        report.reachability,
        Reachability::Incomplete("5 records were overwritten before they were read".to_string())
    );
}

#[test]
fn a_forked_child_inherits_a_check_of_the_memory_it_copies() {
    let mut h = hooked();
    map_writable(&mut h.fake, 0x7000, 0x8000);
    set_head(&mut h.fake, 1);
    write_slot(&mut h.fake, 0, malloc_record(16, 0x7000), true);

    h.monitor.forked(&mut h.fake, pid(), Pid::from_raw(101));

    let reports = h.monitor.finish();
    let child = reports
        .iter()
        .find(|r| r.label == "image 1 (pid 100) forked as pid 101")
        .expect("child report");
    assert_eq!(
        child.reachability,
        Reachability::Checked {
            lost: vec![Site {
                caller: CALLER,
                blocks: 1,
                bytes: 16
            }]
        }
    );
}

#[test]
fn a_shared_clone_in_an_image_that_is_not_hooked_changes_nothing() {
    let mut fake = Fake::new(dynamic_image(), vec![]);
    let mut monitor = Monitor::new(0);
    assert!(monitor.exec(&mut fake, pid()).is_empty());
    fake.regs.rdi = CLONE_VM;

    monitor.trapped(&mut fake, pid(), Some(libc::SYS_clone));

    let report = only(monitor.finish());
    assert_eq!(report.reachability, Reachability::Unchecked);
    assert_eq!(report.notes.len(), 2, "{:?}", report.notes);
}
