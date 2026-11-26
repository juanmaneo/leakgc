//! The monitor's bookkeeping with every operating-system result scripted. The
//! hooks are really installed on the static fixture, then the record ring is
//! written by hand, as the entry and exit code would write it.

mod common;

use std::collections::BTreeMap;

use common::*;
use leakgc::install::{DEFAULT_HINT, RECORDS_OFFSET, REGION_LEN};
use leakgc::ledger::{ImageReport, Reachability, Site};
use leakgc::monitor::Monitor;
use leakgc::quarantine::POISON;
use leakgc::ring::{CAPACITY, Kind, RECORD_LEN, Record};
use nix::sys::signal::Signal;
use nix::unistd::Pid;

const CLONE_VM: u64 = 0x100;
const SHARED_BLOCK: u64 = 0x6000_0000;
/// The stack mapping. `initial_regs` puts `rsp` at 0x7fff_f000, inside it.
const STACK: (u64, u64) = (0x7fff_e000, 0x7fff_f800);
const RSP: u64 = 0x7fff_f000;

/// A process whose hooks are installed, with the bytes the install wrote last.
struct Hooked {
    monitor: Monitor,
    fake: Fake,
    /// The ten jumps and the bytes each one holds after the install.
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

/// The entries the static fixture hooks. musl has no `pvalloc` or `malloc_trim`.
const STATIC_HOOKS: usize = if cfg!(target_env = "gnu") { 10 } else { 8 };

/// The writes an install makes when `hooked` entries get a hook: the syscall bytes
/// twice, the exit code and the trampoline once, then one block and one jump per hook.
fn install_writes(hooked: usize) -> usize {
    4 + 2 * hooked
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
    assert_eq!(
        fake.writes.len(),
        install_writes(STATIC_HOOKS),
        "the install wrote every hook"
    );
    let jumps = fake.writes[fake.writes.len() - STATIC_HOOKS..]
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

fn only(reports: Vec<ImageReport>) -> ImageReport {
    assert_eq!(reports.len(), 1, "one report: {reports:?}");
    reports.into_iter().next().expect("one report")
}

fn has_note(report: &ImageReport, prefix: &str) -> bool {
    report.notes.iter().any(|note| note.starts_with(prefix))
}

/// The notes except those about entries the libc does not have. Which entries
/// a libc has differs between libcs, so counting every note would not travel.
fn notes_but_skips(report: &ImageReport) -> Vec<&String> {
    report
        .notes
        .iter()
        .filter(|note| !note.starts_with("not hooked: "))
        .collect()
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
    assert_eq!(notes_but_skips(&report).len(), 3, "{:?}", report.notes);
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
fn a_nested_call_from_outside_its_allocator_makes_the_ledger_untrusted() {
    let mut h = hooked();
    map_writable(&mut h.fake, 0x7000, 0x9000);
    set_head(&mut h.fake, 2);
    write_slot(&mut h.fake, 0, malloc_record(16, 0x7000), true);
    write_slot(
        &mut h.fake,
        1,
        Record {
            kind: Kind::Nested,
            size: 0,
            caller: CALLER,
            arg: 0,
            result: 0,
        },
        true,
    );
    put_word(&mut h.fake, RSP + 0x100, 0x7000);

    h.monitor.trapped(&mut h.fake, pid(), None);

    let report = only(h.monitor.finish());
    let reason =
        "record 1 is a hooked call from outside its allocator, made while another was open (R40)";
    assert!(has_note(&report, "record 1 is a hooked call"));
    assert_eq!(
        report.reachability,
        Reachability::Incomplete(reason.to_string())
    );
    assert_eq!(
        report.sites,
        vec![Site {
            caller: CALLER,
            blocks: 1,
            bytes: 16
        }]
    );
}

#[test]
fn a_nested_call_does_not_count_toward_collect_every() {
    let mut h = hooked_every(1);
    set_head(&mut h.fake, 1);
    write_slot(
        &mut h.fake,
        0,
        Record {
            kind: Kind::Nested,
            size: 0,
            caller: CALLER,
            arg: 0,
            result: 0,
        },
        true,
    );

    h.monitor.trapped(&mut h.fake, pid(), None);

    let report = only(h.monitor.finish());
    assert_eq!(report.reachability, Reachability::Unchecked);
}

#[test]
fn a_malloc_trim_does_not_count_toward_collect_every() {
    let mut h = hooked_every(1);
    set_head(&mut h.fake, 1);
    write_slot(
        &mut h.fake,
        0,
        Record {
            kind: Kind::MallocTrim,
            size: 0,
            caller: CALLER,
            arg: 0,
            result: 0,
        },
        true,
    );

    h.monitor.trapped(&mut h.fake, pid(), None);

    let report = only(h.monitor.finish());
    assert_eq!(report.reachability, Reachability::Unchecked);
}

/// A trap inside `malloc_trim` finds its call open, so the check waits (R39).
#[test]
fn a_trap_inside_malloc_trim_keeps_the_last_complete_check() {
    let mut h = hooked();
    set_head(&mut h.fake, 0);
    h.monitor.trapped(&mut h.fake, pid(), None);
    set_head(&mut h.fake, 1);
    write_slot(
        &mut h.fake,
        0,
        Record {
            kind: Kind::MallocTrim,
            size: 0,
            caller: CALLER,
            arg: 0,
            result: 0,
        },
        false,
    );
    h.fake.maps = "not a mapping\n".to_string();

    h.monitor.trapped(&mut h.fake, pid(), Some(libc::SYS_brk));

    let report = only(h.monitor.finish());
    assert_eq!(report.reachability, Reachability::Checked { lost: vec![] });
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
    assert_eq!(notes_but_skips(&report).len(), 2, "{:?}", report.notes);
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
fn a_new_image_archives_the_old_one_and_a_dynamic_image_waits_for_its_library() {
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
            .any(|note| note == "hooks wait until the C library is mapped"),
        "{:?}",
        reports[1].notes
    );
    assert!(has_note(&reports[1], "the C library was never mapped"));
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

/// Maps the stack and the hook region, then execs the static process in `fake`.
/// Any hooks land at `DEFAULT_HINT`, as in `hooked_every`.
fn exec_static(fake: &mut Fake) -> Monitor {
    map_writable(fake, STACK.0, STACK.1);
    map_line(fake, DEFAULT_HINT, DEFAULT_HINT + REGION_LEN, "rwxp");
    let mut monitor = Monitor::new(0);
    assert!(monitor.exec(fake, pid()).is_empty());
    monitor
}

#[test]
fn a_static_image_without_free_says_its_frees_are_not_seen() {
    let image = without_function_name(static_image(), "free");
    let mut fake = Fake::new(&image, vec![trap(), seccomp(), trap()]);
    let mut monitor = exec_static(&mut fake);

    monitor.exited(pid(), "exit code 0".to_string());

    let report = only(monitor.finish());
    assert!(has_note(
        &report,
        "not hooked: free is not found as a function in an executable section, so its calls are not recorded"
    ));
    assert!(has_note(
        &report,
        "free is not hooked, so no block is freed by injection"
    ));
    assert_eq!(
        report.reachability,
        Reachability::Incomplete(
            "free not hooked, so the program's frees are not seen".to_string()
        )
    );
}

#[test]
fn a_library_without_realloc_says_its_frees_are_not_seen() {
    let image = with_renamed_symbol(stripped_library_image(), "realloc", "xealloc");
    let mut h = dynamic_hooked_with(&image, 9);

    let report = only(h.monitor.finish());
    assert!(has_note(
        &report,
        "not hooked: realloc is not found as a function in an executable section, so its calls are not recorded"
    ));
    assert_eq!(
        report.reachability,
        Reachability::Incomplete(
            "realloc not hooked, so the program's frees are not seen".to_string()
        )
    );
}

#[test]
fn an_image_with_no_executable_allocator_code_is_not_covered() {
    let image = without_exec_flag(static_image(), ".text");
    let mut fake = Fake::new(&image, vec![]);
    let mut monitor = exec_static(&mut fake);

    assert!(fake.writes.is_empty(), "nothing is written");
    let report = only(monitor.finish());
    assert!(has_note(
        &report,
        "not covered: no allocator entry can be hooked"
    ));
    let named = report
        .notes
        .iter()
        .filter(|note| note.starts_with("not hooked: "))
        .count();
    assert_eq!(named, 10, "every entry is named: {:?}", report.notes);
    assert_eq!(report.reachability, Reachability::Unchecked);
}

#[test]
fn a_refused_malloc_is_named_and_the_ledger_stays_trusted() {
    let image = static_image();
    let malloc = function_symbol(image, "malloc");
    let mut fake = Fake::new(image, vec![trap(), seccomp(), trap()]);
    let patch = patch_point(&fake, malloc);
    fake.poke(patch, &[0xe8, 0x00, 0x00, 0x00, 0x00]);
    let mut monitor = exec_static(&mut fake);

    set_head(&mut fake, 0);
    monitor.trapped(&mut fake, pid(), None);

    let report = only(monitor.finish());
    assert!(has_note(
        &report,
        "not hooked: malloc is refused by the planner ("
    ));
    assert!(has_note(&report, "hooked free, realloc, calloc"));
    assert_eq!(report.reachability, Reachability::Checked { lost: vec![] });
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

/// A dynamically linked process whose C library is mapped, and whose hooks are
/// installed at the first trapped `mmap` exit after the mapping. The hook region
/// lands at `DEFAULT_HINT`, so the record helpers apply.
fn dynamic_hooked(image: &[u8]) -> Hooked {
    dynamic_hooked_with(image, 10)
}

/// `dynamic_hooked` for an image in which `hooked` entries get a jump.
fn dynamic_hooked_with(image: &[u8], hooked: usize) -> Hooked {
    let mut fake = dynamic_fake(vec![trap(), seccomp(), trap()]);
    map_writable(&mut fake, STACK.0, STACK.1);
    let mut monitor = Monitor::new(0);
    assert!(monitor.exec(&mut fake, pid()).is_empty());
    map_library(
        &mut fake,
        image,
        library_base_at_hint(image),
        LIBRARY_INODE,
        LIBRARY_PATH,
        "r-xp",
    );
    assert!(monitor.trapped(&mut fake, pid(), Some(libc::SYS_mmap)));
    let pristine = fake.mem.clone();
    assert!(monitor.syscall_exited(&mut fake, pid()).is_empty());
    assert_eq!(
        fake.writes.len(),
        install_writes(hooked),
        "the install wrote its hooks"
    );
    let jumps = fake.writes[fake.writes.len() - hooked..]
        .iter()
        .map(|(at, bytes)| (*at, bytes.clone()))
        .collect();
    map_line(&mut fake, DEFAULT_HINT, DEFAULT_HINT + REGION_LEN, "rwxp");
    Hooked {
        monitor,
        fake,
        jumps,
        pristine,
    }
}

#[test]
fn a_dynamic_process_is_hooked_at_the_first_mmap_exit_after_its_library_is_mapped() {
    let mut fake = dynamic_fake(vec![trap(), seccomp(), trap()]);
    map_writable(&mut fake, STACK.0, STACK.1);
    let mut monitor = Monitor::new(0);
    assert!(monitor.exec(&mut fake, pid()).is_empty());

    assert!(monitor.trapped(&mut fake, pid(), Some(libc::SYS_mmap)));
    assert!(monitor.syscall_exited(&mut fake, pid()).is_empty());
    assert!(fake.writes.is_empty(), "the library is not mapped yet");

    map_library(
        &mut fake,
        library_image(),
        library_base_at_hint(library_image()),
        LIBRARY_INODE,
        LIBRARY_PATH,
        "r-xp",
    );
    assert!(monitor.trapped(&mut fake, pid(), Some(libc::SYS_mmap)));
    assert!(monitor.syscall_exited(&mut fake, pid()).is_empty());

    assert_eq!(fake.writes.len(), 24, "the install wrote every hook");
    let report = only(monitor.finish());
    assert!(has_note(
        &report,
        "hooks were installed after the C library was mapped"
    ));
    assert!(
        !report
            .notes
            .iter()
            .any(|note| note.starts_with("not covered"))
    );
}

#[test]
fn a_library_that_is_never_mapped_is_reported_as_not_covered() {
    let mut fake = dynamic_fake(vec![]);
    let mut monitor = Monitor::new(0);
    assert!(monitor.exec(&mut fake, pid()).is_empty());

    monitor.exited(pid(), "exit code 0".to_string());

    let report = only(monitor.finish());
    assert!(has_note(
        &report,
        "the C library was never mapped, so no hooks were installed: not covered"
    ));
    assert_eq!(report.notes.last().map(String::as_str), Some("exit code 0"));
}

#[test]
fn an_image_that_does_not_parse_is_reported_as_not_covered() {
    let mut fake = Fake::new(b"not an elf", vec![]);
    let mut monitor = Monitor::new(0);
    assert!(monitor.exec(&mut fake, pid()).is_empty());

    monitor.exited(pid(), "exit code 0".to_string());

    let report = only(monitor.finish());
    assert!(has_note(&report, "not covered: Parse("));
    assert!(fake.writes.is_empty());
}

#[test]
fn a_library_whose_file_was_replaced_is_reported_as_not_covered() {
    let mut fake = dynamic_fake(vec![]);
    let mut monitor = Monitor::new(0);
    assert!(monitor.exec(&mut fake, pid()).is_empty());
    map_library(
        &mut fake,
        library_image(),
        library_base_at_hint(library_image()),
        LIBRARY_INODE,
        LIBRARY_PATH,
        "r-xp",
    );
    fake.files.insert(
        LIBRARY_PATH.to_string(),
        (LIBRARY_INODE + 1, library_image().to_vec()),
    );

    assert!(monitor.trapped(&mut fake, pid(), Some(libc::SYS_mmap)));
    assert!(monitor.syscall_exited(&mut fake, pid()).is_empty());

    assert!(fake.writes.is_empty());
    let report = only(monitor.finish());
    assert!(has_note(
        &report,
        "not covered: LibraryChanged(\"the file on disk is not the file that is mapped\")"
    ));
}

#[test]
fn a_thread_started_before_the_library_is_mapped_cancels_the_wait() {
    let mut fake = dynamic_fake(vec![]);
    let mut monitor = Monitor::new(0);
    assert!(monitor.exec(&mut fake, pid()).is_empty());
    fake.regs.rdi = CLONE_VM;

    monitor.trapped(&mut fake, pid(), Some(libc::SYS_clone));
    assert!(
        !monitor.trapped(&mut fake, pid(), Some(libc::SYS_mmap)),
        "no mmap exit is awaited any more"
    );

    let report = only(monitor.finish());
    assert_eq!(report.reachability, Reachability::Unchecked);
    assert!(has_note(
        &report,
        "threads started before the C library was mapped"
    ));
    assert!(!has_note(&report, "the C library was never mapped"));
    assert_eq!(report.notes.len(), 3, "{:?}", report.notes);
}

#[test]
fn a_hooked_library_poisons_a_block_it_holds() {
    let mut h = dynamic_hooked(library_image());
    hold_a_block(&mut h);

    h.monitor.trapped(&mut h.fake, pid(), None);

    assert_eq!(h.fake.bytes(0x8000, 32), vec![POISON; 32]);
}

#[test]
fn a_stripped_library_holds_a_block_without_poisoning_it() {
    let mut h = dynamic_hooked(stripped_library_image());
    hold_a_block(&mut h);

    h.monitor.trapped(&mut h.fake, pid(), None);

    assert_eq!(h.fake.bytes(0x8000, 32), vec![0; 32], "nothing is poisoned");
    let report = only(h.monitor.finish());
    assert!(has_note(
        &report,
        "the allocator's internal functions have no symbol table entries"
    ));
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

/// A process with a live block at 0x7000 and an unreached block at 0x8000,
/// which the first check holds in quarantine.
fn with_a_held_block() -> Hooked {
    let mut h = hooked();
    hold_a_block(&mut h);
    h
}

/// Adds the live block at 0x7000 and the unreached block at 0x8000 that
/// [`with_a_held_block`] describes, to a process whose hooks are installed.
fn hold_a_block(h: &mut Hooked) {
    map_writable(&mut h.fake, 0x7000, 0x9000);
    set_head(&mut h.fake, 2);
    write_slot(&mut h.fake, 0, malloc_record(16, 0x7000), true);
    write_slot(&mut h.fake, 1, malloc_record(32, 0x8000), true);
    put_word(&mut h.fake, RSP + 0x100, 0x7000);
}

#[test]
fn a_check_poisons_the_unreached_block_it_holds() {
    let mut h = with_a_held_block();

    h.monitor.trapped(&mut h.fake, pid(), None);

    assert_eq!(h.fake.bytes(0x8000, 32), vec![POISON; 32]);
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
fn a_free_of_a_held_block_makes_every_later_check_incomplete() {
    let mut h = with_a_held_block();
    h.monitor.trapped(&mut h.fake, pid(), None);
    set_head(&mut h.fake, 3);
    write_slot(&mut h.fake, 2, free_record(0x8000), true);

    h.monitor.trapped(&mut h.fake, pid(), None);

    let report = only(h.monitor.finish());
    assert_eq!(
        report.reachability,
        Reachability::Incomplete(
            "a held block at 0x8000 was freed: the scan missed a reference to it (R2)".to_string()
        )
    );
    assert!(has_note(&report, "a held block at 0x8000 was freed"));
}

#[test]
fn a_block_that_cannot_be_poisoned_makes_the_process_untrusted() {
    let mut h = with_a_held_block();
    h.fake.fail_writes = true;
    h.monitor.trapped(&mut h.fake, pid(), None);
    h.fake.fail_writes = false;

    h.monitor.trapped(&mut h.fake, pid(), None);

    let report = only(h.monitor.finish());
    assert_eq!(
        report.reachability,
        Reachability::Incomplete(
            "a block at 0x8000 could not be poisoned: injected write failure".to_string()
        )
    );
}

/// The address and size of the first function in the static fixture with this
/// name and a body. Some names appear twice in the fixture.
fn symbol(name: &str) -> (u64, u64) {
    let elf = goblin::elf::Elf::parse(static_image()).expect("the fixture parses");
    elf.syms
        .iter()
        .find(|sym| {
            sym.is_function() && sym.st_size > 0 && elf.strtab.get_at(sym.st_name) == Some(name)
        })
        .map(|sym| (sym.st_value, sym.st_size))
        .expect("the fixture has the function")
}

/// A process whose first check has held the unreached block at 0x8000, and
/// whose second check, at a memory call, has confirmed it for injection.
fn confirmed_held() -> Hooked {
    let mut h = with_a_held_block();
    h.monitor.trapped(&mut h.fake, pid(), None);
    assert!(
        h.monitor.trapped(&mut h.fake, pid(), Some(libc::SYS_mmap)),
        "the confirmed block waits for the exit of this call"
    );
    h
}

/// Two unreached blocks, at 0x8000 and 0xa000, both confirmed for injection.
fn with_two_confirmed_blocks() -> Hooked {
    let mut h = hooked();
    map_writable(&mut h.fake, 0x7000, 0xb000);
    set_head(&mut h.fake, 3);
    write_slot(&mut h.fake, 0, malloc_record(16, 0x7000), true);
    write_slot(&mut h.fake, 1, malloc_record(32, 0x8000), true);
    write_slot(&mut h.fake, 2, malloc_record(16, 0xa000), true);
    put_word(&mut h.fake, RSP + 0x100, 0x7000);
    h.monitor.trapped(&mut h.fake, pid(), None);
    assert!(h.monitor.trapped(&mut h.fake, pid(), Some(libc::SYS_mmap)));
    h
}

fn signal_stop(h: &mut Hooked, signal: Signal) -> Option<Vec<Signal>> {
    h.monitor.injected_stop(&mut h.fake, pid(), signal)
}

/// The program frees the held block at 0x8000 itself. A block that is still
/// held makes the process untrusted, and the next trapped call reports it.
fn program_frees_held_block(h: &mut Hooked) {
    write_slot(&mut h.fake, 2, free_record(0x8000), true);
    set_head(&mut h.fake, 3);
    h.monitor.trapped(&mut h.fake, pid(), None);
}

#[test]
fn a_confirmed_block_is_freed_by_an_injected_call_at_the_exit_of_a_memory_call() {
    let mut h = confirmed_held();
    let (start, stop) = trampoline(&h.fake);
    let saved = h.fake.regs;

    h.monitor.syscall_exited(&mut h.fake, pid());

    assert_eq!(h.fake.regs.rip, start);
    assert_eq!(h.fake.regs.rdi, 0x8000);
    assert_eq!(
        h.fake.regs.rsp, 0x7fff_ef00,
        "the call runs below the stack pointer, clear of the red zone"
    );
    // The injected free records itself in the ring, then the trampoline reaches its int3.
    write_slot(&mut h.fake, 2, free_record(0x8000), true);
    set_head(&mut h.fake, 3);
    h.fake.regs.rip = stop + 1;

    assert_eq!(signal_stop(&mut h, Signal::SIGTRAP), Some(vec![]));
    assert_eq!(
        h.fake.regs,
        libc::user_regs_struct {
            orig_rax: u64::MAX,
            ..saved
        }
    );
    assert!(!h.monitor.trapped(&mut h.fake, pid(), None));
    assert!(h.fake.signals.is_empty());
    let report = only(h.monitor.finish());
    assert!(has_note(
        &report,
        "freed 1 unreached blocks by injected free calls"
    ));
    assert_eq!(report.reachability, Reachability::Checked { lost: vec![] });
}

#[test]
fn an_injected_free_leaves_the_ledger_when_the_injection_ends() {
    let mut h = confirmed_held();
    let (_, stop) = trampoline(&h.fake);
    h.monitor.syscall_exited(&mut h.fake, pid());
    write_slot(&mut h.fake, 2, free_record(0x8000), true);
    set_head(&mut h.fake, 3);
    h.fake.regs.rip = stop + 1;

    assert_eq!(signal_stop(&mut h, Signal::SIGTRAP), Some(vec![]));

    let report = only(h.monitor.finish());
    assert_eq!(
        report.sites,
        vec![Site {
            caller: CALLER,
            blocks: 1,
            bytes: 16
        }],
        "the freed block is gone without waiting for a trapped call"
    );
}

#[test]
fn two_confirmed_blocks_are_freed_one_after_the_other() {
    let mut h = with_two_confirmed_blocks();
    let (start, stop) = trampoline(&h.fake);
    let saved = h.fake.regs;
    h.monitor.syscall_exited(&mut h.fake, pid());
    assert_eq!(h.fake.regs.rdi, 0x8000);

    h.fake.regs.rip = stop + 1;
    assert_eq!(signal_stop(&mut h, Signal::SIGTRAP), Some(vec![]));
    assert_eq!(h.fake.regs.rdi, 0xa000);
    assert_eq!(h.fake.regs.rip, start);

    h.fake.regs.rip = stop + 1;
    assert_eq!(signal_stop(&mut h, Signal::SIGTRAP), Some(vec![]));
    assert_eq!(
        h.fake.regs,
        libc::user_regs_struct {
            orig_rax: u64::MAX,
            ..saved
        }
    );
    let report = only(h.monitor.finish());
    assert!(has_note(
        &report,
        "freed 2 unreached blocks by injected free calls"
    ));
}

#[test]
fn a_block_that_is_only_held_is_not_injected_at_the_first_memory_call() {
    let mut h = with_a_held_block();
    assert!(!h.monitor.trapped(&mut h.fake, pid(), Some(libc::SYS_mmap)));
    let before = h.fake.regs;

    h.monitor.syscall_exited(&mut h.fake, pid());

    assert_eq!(h.fake.regs, before);
    assert!(h.fake.signals.is_empty());
}

#[test]
fn a_confirmed_block_waits_for_a_memory_call_and_is_not_injected_at_another_call() {
    let mut h = confirmed_held();
    assert!(
        !h.monitor
            .trapped(&mut h.fake, pid(), Some(libc::SYS_getpid))
    );
    let before = h.fake.regs;

    h.monitor.syscall_exited(&mut h.fake, pid());

    assert_eq!(h.fake.regs, before);
}

#[test]
fn an_exit_that_no_check_asked_for_changes_nothing() {
    let mut h = hooked();
    let before = h.fake.regs;

    h.monitor.syscall_exited(&mut h.fake, pid());

    assert_eq!(h.fake.regs, before);
    assert!(h.fake.signals.is_empty());
}

#[test]
fn an_unknown_process_is_ignored_by_the_injection_calls() {
    let mut h = hooked();
    let other = Pid::from_raw(TRACEE + 1);

    assert!(!h.monitor.trapped(&mut h.fake, other, Some(libc::SYS_mmap)));
    h.monitor.syscall_exited(&mut h.fake, other);
    assert_eq!(
        h.monitor.injected_stop(&mut h.fake, other, Signal::SIGTRAP),
        None
    );
    assert!(h.fake.signals.is_empty());
}

#[test]
fn an_injection_is_not_started_when_the_registers_cannot_be_read() {
    let mut h = confirmed_held();
    let before = h.fake.regs;
    h.fake.fail_regs = true;

    h.monitor.syscall_exited(&mut h.fake, pid());

    h.fake.fail_regs = false;
    assert_eq!(h.fake.regs, before);
    assert!(h.fake.signals.is_empty());
    program_frees_held_block(&mut h);
    let report = only(h.monitor.finish());
    assert!(has_note(&report, "a held block at 0x8000 was freed"));
}

#[test]
fn an_injection_is_not_started_when_the_stack_cannot_be_read() {
    let mut h = confirmed_held();
    let before = h.fake.regs;
    h.fake.fail_reads = true;

    h.monitor.syscall_exited(&mut h.fake, pid());

    h.fake.fail_reads = false;
    assert_eq!(h.fake.regs, before);
    assert!(h.fake.signals.is_empty());
    program_frees_held_block(&mut h);
    let report = only(h.monitor.finish());
    assert!(has_note(&report, "a held block at 0x8000 was freed"));
}

#[test]
fn an_injection_is_refused_inside_the_allocator() {
    let mut h = confirmed_held();
    let (start, _) = symbol("_int_malloc");
    h.fake.regs.rip = start;
    let before = h.fake.regs;

    h.monitor.syscall_exited(&mut h.fake, pid());

    assert_eq!(h.fake.regs, before);
    assert!(h.fake.signals.is_empty());
}

#[test]
fn an_injection_is_refused_when_the_stack_points_into_the_allocator() {
    let mut h = confirmed_held();
    put_word(&mut h.fake, RSP + 0x200, symbol("_int_malloc").0);
    let before = h.fake.regs;

    h.monitor.syscall_exited(&mut h.fake, pid());

    assert_eq!(h.fake.regs, before);
    assert!(h.fake.signals.is_empty());
}

#[test]
fn an_injection_is_refused_without_room_below_the_stack_pointer() {
    let mut h = confirmed_held();
    map_writable(&mut h.fake, 0, 0x1000);
    h.fake.regs.rsp = 0x80;
    let before = h.fake.regs;

    h.monitor.syscall_exited(&mut h.fake, pid());

    assert_eq!(h.fake.regs, before);
    assert!(h.fake.signals.is_empty());
}

#[test]
fn an_injection_that_cannot_start_leaves_its_block_held() {
    let mut h = confirmed_held();
    h.fake.fail_set_regs = true;

    h.monitor.syscall_exited(&mut h.fake, pid());

    h.fake.fail_set_regs = false;
    assert!(h.fake.signals.is_empty());
    program_frees_held_block(&mut h);
    let report = only(h.monitor.finish());
    assert!(has_note(
        &report,
        "the injected free of 0x8000 could not start ("
    ));
    assert!(has_note(&report, "a held block at 0x8000 was freed"));
}

#[test]
fn a_second_free_that_cannot_start_kills_the_process() {
    let mut h = with_two_confirmed_blocks();
    let (_, stop) = trampoline(&h.fake);
    h.monitor.syscall_exited(&mut h.fake, pid());
    h.fake.regs.rip = stop + 1;
    h.fake.fail_set_regs = true;

    assert_eq!(signal_stop(&mut h, Signal::SIGTRAP), Some(vec![]));

    h.fake.fail_set_regs = false;
    assert_eq!(h.fake.signals, vec![Signal::SIGKILL]);
    let report = only(h.monitor.finish());
    assert!(report.notes.iter().any(|note| {
        note.starts_with("the injected free of 0xa000 could not start (")
            && note.ends_with("): the process was killed")
    }));
}

#[test]
fn a_process_whose_registers_cannot_be_restored_is_killed() {
    let mut h = confirmed_held();
    let (_, stop) = trampoline(&h.fake);
    h.monitor.syscall_exited(&mut h.fake, pid());
    h.fake.regs.rip = stop + 1;
    h.fake.fail_set_regs = true;

    assert_eq!(signal_stop(&mut h, Signal::SIGTRAP), Some(vec![]));

    h.fake.fail_set_regs = false;
    assert_eq!(h.fake.signals, vec![Signal::SIGKILL]);
    let report = only(h.monitor.finish());
    assert!(has_note(
        &report,
        "registers could not be restored after injected code"
    ));
}

#[test]
fn a_kill_makes_the_report_incomplete_without_a_later_check() {
    let mut h = confirmed_held();
    h.monitor.syscall_exited(&mut h.fake, pid());

    assert_eq!(signal_stop(&mut h, Signal::SIGSEGV), Some(vec![]));

    let report = only(h.monitor.finish());
    assert_eq!(
        report.reachability,
        Reachability::Incomplete("signal SIGSEGV in injected code".to_string())
    );
}

#[test]
fn a_trap_away_from_the_injected_stop_kills_the_process() {
    let mut h = confirmed_held();
    h.monitor.syscall_exited(&mut h.fake, pid());

    assert_eq!(signal_stop(&mut h, Signal::SIGTRAP), Some(vec![]));

    assert_eq!(h.fake.signals, vec![Signal::SIGKILL]);
    let report = only(h.monitor.finish());
    assert!(has_note(&report, "unexpected SIGTRAP at 0x"));
}

#[test]
fn a_fault_in_injected_code_kills_the_process() {
    let mut h = confirmed_held();
    h.monitor.syscall_exited(&mut h.fake, pid());

    assert_eq!(signal_stop(&mut h, Signal::SIGSEGV), Some(vec![]));

    assert_eq!(h.fake.signals, vec![Signal::SIGKILL]);
    assert!(!h.monitor.trapped(&mut h.fake, pid(), None));
    let report = only(h.monitor.finish());
    assert_eq!(
        report.reachability,
        Reachability::Incomplete("signal SIGSEGV in injected code".to_string())
    );
}

#[test]
fn a_failed_kill_is_reported_and_the_process_is_untrusted() {
    let mut h = confirmed_held();
    h.monitor.syscall_exited(&mut h.fake, pid());
    h.fake.fail_kill = true;

    assert_eq!(signal_stop(&mut h, Signal::SIGSEGV), Some(vec![]));

    let report = only(h.monitor.finish());
    assert!(has_note(
        &report,
        "signal SIGSEGV in injected code: the process could not be killed"
    ));
}

#[test]
fn a_signal_during_injected_code_is_held_until_the_process_is_restored() {
    let mut h = confirmed_held();
    let (_, stop) = trampoline(&h.fake);
    h.monitor.syscall_exited(&mut h.fake, pid());
    let armed = h.fake.regs;

    assert_eq!(signal_stop(&mut h, Signal::SIGCHLD), Some(vec![]));

    assert_eq!(h.fake.regs, armed, "the process is not moved by the signal");
    h.fake.regs.rip = stop + 1;
    assert_eq!(
        signal_stop(&mut h, Signal::SIGTRAP),
        Some(vec![Signal::SIGCHLD])
    );
    assert!(h.fake.signals.is_empty());
}

#[test]
fn an_unreadable_stop_inside_injected_code_kills_the_process() {
    let mut h = confirmed_held();
    h.monitor.syscall_exited(&mut h.fake, pid());
    h.fake.fail_regs = true;

    assert_eq!(signal_stop(&mut h, Signal::SIGTRAP), Some(vec![]));

    h.fake.fail_regs = false;
    assert_eq!(h.fake.signals, vec![Signal::SIGKILL]);
    let report = only(h.monitor.finish());
    assert!(has_note(
        &report,
        "registers unreadable at the end of injected code"
    ));
}

#[test]
fn a_memory_call_during_injected_code_is_not_checked() {
    let mut h = confirmed_held();
    h.monitor.syscall_exited(&mut h.fake, pid());
    write_slot(&mut h.fake, 2, malloc_record(16, 0xa000), true);
    set_head(&mut h.fake, 3);
    let writes = h.fake.writes.len();

    assert!(!h.monitor.trapped(&mut h.fake, pid(), Some(libc::SYS_mmap)));

    assert_eq!(h.fake.writes.len(), writes, "no check runs while injected");
}

#[test]
fn a_stop_that_is_not_an_injection_is_left_to_the_supervisor() {
    let mut h = hooked();

    assert_eq!(signal_stop(&mut h, Signal::SIGTRAP), None);
    assert_eq!(signal_stop(&mut h, Signal::SIGCHLD), None);
}

#[test]
fn a_block_changed_before_its_injected_free_is_not_freed() {
    let mut h = confirmed_held();
    h.fake.poke(0x8000, &[0x42]);
    let before = h.fake.regs;

    h.monitor.syscall_exited(&mut h.fake, pid());

    assert_eq!(h.fake.regs, before, "nothing is injected");
    assert!(h.fake.signals.is_empty());
    let report = only(h.monitor.finish());
    assert_eq!(
        report.reachability,
        Reachability::Incomplete(
            "a held block at 0x8000 was written to: the program used a block the scan missed (R2)"
                .to_string()
        )
    );
    assert!(has_note(&report, "a held block at 0x8000 was written to"));
}

#[test]
fn a_block_unmapped_before_its_injected_free_is_not_freed() {
    let mut h = confirmed_held();
    for addr in 0x8000..0x8020 {
        h.fake.mem.remove(&addr);
    }
    let before = h.fake.regs;

    h.monitor.syscall_exited(&mut h.fake, pid());

    assert_eq!(h.fake.regs, before, "nothing is injected");
    assert!(h.fake.signals.is_empty());
    let report = only(h.monitor.finish());
    assert_eq!(
        report.reachability,
        Reachability::Incomplete(
            "a held block at 0x8000 could not be read: unmapped 0x8000".to_string()
        )
    );
}

#[test]
fn a_changed_block_ends_the_injection_before_the_rest_of_the_queue_is_freed() {
    let mut h = with_two_confirmed_blocks();
    let (_, stop) = trampoline(&h.fake);
    let saved = h.fake.regs;
    h.monitor.syscall_exited(&mut h.fake, pid());
    assert_eq!(h.fake.regs.rdi, 0x8000);
    h.fake.poke(0xa000, &[0x42]);

    h.fake.regs.rip = stop + 1;
    assert_eq!(signal_stop(&mut h, Signal::SIGTRAP), Some(vec![]));

    assert_eq!(
        h.fake.regs,
        libc::user_regs_struct {
            orig_rax: u64::MAX,
            ..saved
        }
    );
    assert!(h.fake.signals.is_empty());
    let report = only(h.monitor.finish());
    assert!(has_note(
        &report,
        "freed 1 unreached blocks by injected free calls"
    ));
    assert_eq!(
        report.reachability,
        Reachability::Incomplete(
            "a held block at 0xa000 was written to: the program used a block the scan missed (R2)"
                .to_string()
        )
    );
}

#[test]
fn refused_injections_are_counted_in_one_note_at_exit() {
    let mut h = confirmed_held();
    let (start, _) = symbol("_int_malloc");
    h.fake.regs.rip = start;
    h.monitor.syscall_exited(&mut h.fake, pid());
    for _ in 0..2 {
        assert!(h.monitor.trapped(&mut h.fake, pid(), Some(libc::SYS_mmap)));
        h.monitor.syscall_exited(&mut h.fake, pid());
    }

    assert!(h.fake.signals.is_empty());
    let report = only(h.monitor.finish());
    assert!(has_note(&report, "3 blocks were not freed by injection"));
    assert_eq!(
        report
            .notes
            .iter()
            .filter(|note| note.contains("were not freed by injection"))
            .count(),
        1,
        "{:?}",
        report.notes
    );
}

/// A fault inside the injected free of 0x8000 gives a report that names the
/// block, the function the fault is in, and the stack word that names a function.
#[test]
fn a_fault_in_injected_code_gives_a_crash_report() {
    let mut h = confirmed_held();
    h.monitor.syscall_exited(&mut h.fake, pid());
    let (start, _) = symbol("_int_malloc");
    h.fake.regs.rip = start + 0x10;
    let sp = h.fake.regs.rsp;
    h.fake.poke(sp + 8, &(start + 0x20).to_le_bytes());

    assert_eq!(signal_stop(&mut h, Signal::SIGSEGV), Some(vec![]));

    let alerts = h.monitor.take_alerts();
    assert_eq!(alerts[0], "crash report: SIGSEGV during an injected free");
    assert_eq!(alerts[1], "  while freeing the block at 0x8000");
    assert_eq!(
        alerts[2],
        format!("  crashed at 0x{:x}, in _int_malloc+0x10", start + 0x10)
    );
    assert!(
        alerts.contains(&format!("    0x{:x}  _int_malloc+0x20", start + 0x20)),
        "{alerts:?}"
    );
    assert!(h.monitor.take_alerts().is_empty(), "taken once");
}

#[test]
fn a_fault_in_leakgc_code_is_named_as_such() {
    let mut h = confirmed_held();
    h.monitor.syscall_exited(&mut h.fake, pid());
    let (start, _) = trampoline(&h.fake);

    assert_eq!(signal_stop(&mut h, Signal::SIGSEGV), Some(vec![]));

    let alerts = h.monitor.take_alerts();
    assert_eq!(
        alerts[2],
        format!("  crashed at 0x{start:x}, in leakgc's own code")
    );
}

#[test]
fn a_fault_at_an_address_no_function_covers_says_so() {
    let mut h = confirmed_held();
    h.monitor.syscall_exited(&mut h.fake, pid());
    h.fake.regs.rip = 1;

    assert_eq!(signal_stop(&mut h, Signal::SIGSEGV), Some(vec![]));

    let alerts = h.monitor.take_alerts();
    assert_eq!(alerts[2], "  crashed at 0x1, in no known function");
}

#[test]
fn unreadable_registers_leave_the_dump_out_and_the_process_is_still_killed() {
    let mut h = confirmed_held();
    h.monitor.syscall_exited(&mut h.fake, pid());
    h.fake.fail_regs = true;

    assert_eq!(signal_stop(&mut h, Signal::SIGSEGV), Some(vec![]));

    assert_eq!(h.fake.signals, vec![Signal::SIGKILL]);
    let alerts = h.monitor.take_alerts();
    assert_eq!(alerts.len(), 5, "{alerts:?}");
    assert!(
        alerts[2].starts_with("  the registers could not be read: "),
        "{alerts:?}"
    );
    assert!(!alerts.iter().any(|line| line == "  registers:"));
}

#[test]
fn an_unreadable_stack_is_reported_after_the_registers() {
    let mut h = confirmed_held();
    h.monitor.syscall_exited(&mut h.fake, pid());
    h.fake.fail_reads = true;

    assert_eq!(signal_stop(&mut h, Signal::SIGSEGV), Some(vec![]));

    let alerts = h.monitor.take_alerts();
    assert!(
        alerts.contains(&"    the stack could not be read: injected read failure".to_string()),
        "{alerts:?}"
    );
}

#[test]
fn an_unreadable_image_leaves_the_function_names_out() {
    let mut h = confirmed_held();
    h.monitor.syscall_exited(&mut h.fake, pid());
    let (start, _) = symbol("_int_malloc");
    h.fake.regs.rip = start + 0x10;
    h.fake.fail_image = true;

    assert_eq!(signal_stop(&mut h, Signal::SIGSEGV), Some(vec![]));

    let alerts = h.monitor.take_alerts();
    assert_eq!(
        alerts[2],
        format!(
            "  crashed at 0x{:x}, function names are unavailable: injected image failure",
            start + 0x10
        )
    );
}

#[test]
fn an_image_that_is_not_an_elf_leaves_the_function_names_out() {
    let mut h = confirmed_held();
    h.monitor.syscall_exited(&mut h.fake, pid());
    let (start, _) = symbol("_int_malloc");
    h.fake.regs.rip = start + 0x10;
    h.fake.image = b"not an elf".to_vec();

    assert_eq!(signal_stop(&mut h, Signal::SIGSEGV), Some(vec![]));

    let alerts = h.monitor.take_alerts();
    assert!(
        alerts[2].starts_with(&format!(
            "  crashed at 0x{:x}, function names are unavailable: ",
            start + 0x10
        )),
        "{alerts:?}"
    );
}
