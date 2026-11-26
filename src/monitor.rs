//! Follows every traced process and keeps one ledger per process image (P2b-3a).
//!
//! The record ring is read at each trapped system call and at each fork.
//! Records written after a process's last trapped call are never read (D34).
//! Once a process has made `COLLECT_EVERY` allocations since its last check,
//! its next trapped call checks it for reachability. Each fork is checked
//! whatever the count (D42, D47, D53). A check also holds the unreached blocks
//! in quarantine, which poisons them (P5). Freeing is not built yet. Threads
//! are not handled yet: the first clone that shares memory
//! removes the hooks from that process, and its reachability checks end for
//! good (P2b-3b).

use std::collections::BTreeMap;
use std::io;

use nix::sys::signal::Signal;
use nix::unistd::Pid;

use crate::install::{
    HEAD_OFFSET, Installed, RECORDS_OFFSET, REGION_LEN, install_hooks, uninstall,
};
use crate::ledger::{ImageReport, Ledger, Reachability, released};
use crate::quarantine::Quarantine;
use crate::reach::reachable;
use crate::ring::{Kind, RECORD_LEN, Slot, decode, plan_drain, slot_runs};
use crate::supervisor::Tracer;

/// `CLONE_VM`: the new task shares the caller's memory.
const CLONE_VM: u64 = 0x0000_0100;

/// Allocations between two reachability checks: the oracle's value (D42).
pub const COLLECT_EVERY: u64 = 64;

/// How far a drain got. Only `Settled` means the ledger matches the process now.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Drained {
    /// Every finished record is applied, and no hooked call is open.
    Settled,
    /// A hooked call has not returned. Its block may be about to leave the
    /// ledger, so a check now could report a live block as unreachable.
    InCall,
    /// The records could not be read. A later drain may catch up, so the reason
    /// applies only to the check that follows this drain.
    Behind(String),
}

/// The state of one process: its image's hooks, how far its ring has been read,
/// its ledger, and the notes that explain gaps in the report.
#[derive(Debug, Clone)]
struct Process {
    label: String,
    hook: Option<Installed>,
    cursor: u64,
    ledger: Ledger,
    notes: Vec<String>,
    /// Set once the ledger can no longer be trusted, such as after lost or
    /// undecodable records. Every later check reports this reason.
    untrusted: Option<String>,
    reach: Reachability,
    /// Allocations applied since the last completed check (D53).
    allocations_since_check: u64,
    /// Unreached blocks held and poisoned at a check (P5).
    quarantine: Quarantine,
}

impl Process {
    fn new(label: String) -> Self {
        Process {
            label,
            hook: None,
            cursor: 0,
            ledger: Ledger::default(),
            notes: Vec::new(),
            untrusted: None,
            reach: Reachability::Unchecked,
            allocations_since_check: 0,
            quarantine: Quarantine::default(),
        }
    }

    fn archive(mut self, reason: String) -> ImageReport {
        self.notes.push(reason);
        let mut report = ImageReport::new(self.label, &self.ledger, self.notes);
        report.reachability = self.reach;
        report
    }

    /// Reads and applies the records written since the last drain. It stops at
    /// the first open record, which is read on a later drain, and at a record
    /// that does not decode, after which nothing more is read.
    fn drain<T: Tracer>(&mut self, tracer: &mut T, pid: Pid) -> Drained {
        let Some(hook) = self.hook.clone() else {
            return Drained::Settled;
        };
        let head = match read_word(tracer, pid, hook.base + HEAD_OFFSET) {
            Ok(head) => head,
            Err(error) => {
                let reason = format!("cannot read the record head: {error}");
                self.notes.push(reason.clone());
                return Drained::Behind(reason);
            }
        };
        let drain = plan_drain(self.cursor, head);
        if drain.lost > 0 {
            let reason = format!(
                "{} records were overwritten before they were read",
                drain.lost
            );
            self.notes.push(format!("{reason}: counts are incomplete"));
            self.untrusted.get_or_insert(reason);
        }
        let records = hook.base + RECORDS_OFFSET;
        let mut index = drain.first;
        let mut outcome = Drained::Settled;
        'runs: for (slot, len) in slot_runs(drain.first, drain.count) {
            let at = records + slot * RECORD_LEN as u64;
            let bytes = match tracer.read_mem(pid, at, len as usize * RECORD_LEN) {
                Ok(bytes) => bytes,
                Err(error) => {
                    let reason = format!("cannot read the records: {error}");
                    self.notes.push(reason.clone());
                    outcome = Drained::Behind(reason);
                    break;
                }
            };
            let (chunks, _) = bytes.as_chunks::<RECORD_LEN>();
            for chunk in chunks {
                match decode(chunk) {
                    Some(Slot::Open) => {
                        outcome = Drained::InCall;
                        break 'runs;
                    }
                    Some(Slot::Done(record)) => {
                        if let Some(ptr) = released(&record)
                            && let Some(reason) = self.quarantine.released(ptr)
                        {
                            self.notes.push(format!("{reason}: counts are incomplete"));
                            self.untrusted.get_or_insert(reason);
                        }
                        self.ledger.apply(record);
                        if record.kind == Kind::Nested {
                            let reason = format!(
                                "record {index} is a hooked call from outside its allocator, made while another was open (R40)"
                            );
                            self.notes.push(format!("{reason}: counts are incomplete"));
                            self.untrusted.get_or_insert(reason);
                        }
                        if !matches!(record.kind, Kind::Free | Kind::Nested | Kind::MallocTrim) {
                            self.allocations_since_check += 1;
                        }
                        index += 1;
                    }
                    None => {
                        self.notes.push(format!(
                            "record {index} is corrupt: reading stopped, counts are incomplete"
                        ));
                        self.untrusted
                            .get_or_insert(format!("record {index} is corrupt"));
                        self.hook = None;
                        break 'runs;
                    }
                }
            }
        }
        self.cursor = index;
        outcome
    }

    /// Runs a reachability check over the ledger as it stands, unless the
    /// ledger does not match the process now. A result is a snapshot of the
    /// outstanding blocks, so later records do not change it.
    fn check<T: Tracer>(&mut self, tracer: &mut T, pid: Pid, drained: Drained) {
        if let Some(reason) = &self.untrusted {
            self.reach = Reachability::Incomplete(reason.clone());
            return;
        }
        let Some(hook) = self.hook.clone() else {
            return;
        };
        match drained {
            Drained::Settled => {
                // Reset even if the scan fails, so a failing scan is not retried at every trap.
                self.allocations_since_check = 0;
                let blocks: Vec<(u64, u64)> = self.ledger.live_blocks().collect();
                let region = hook.base..hook.base + REGION_LEN;
                self.reach = match reachable(tracer, pid, region, &blocks) {
                    Ok(scan) => match self.quarantine.update(tracer, pid, &blocks, &scan) {
                        Ok(()) => Reachability::Checked {
                            lost: self.ledger.unreached_sites(&scan.reached),
                        },
                        Err(reason) => {
                            self.untrusted.get_or_insert(reason.clone());
                            Reachability::Incomplete(reason)
                        }
                    },
                    Err(reason) => Reachability::Incomplete(reason),
                };
            }
            // The last complete result stays, and is still a snapshot of an earlier state.
            Drained::InCall => {}
            Drained::Behind(reason) => self.reach = Reachability::Incomplete(reason),
        }
    }

    /// Removes the hooks, after a clone that shares memory. The ledger is
    /// untrusted from here on, because only one thread is ever scanned. If the
    /// removal fails, the process stays patched, so its counts are not reported
    /// as complete.
    fn unhook<T: Tracer>(&mut self, tracer: &mut T, pid: Pid) {
        let Some(hook) = self.hook.take() else {
            return;
        };
        self.untrusted.get_or_insert(
            "threads started: only one thread is scanned, so reachability is not checked from here on"
                .to_string(),
        );
        match uninstall(tracer, pid, &hook) {
            Ok(()) => self.notes.push(
                "hooks removed at a clone that shares memory: later allocations are not recorded"
                    .to_string(),
            ),
            Err(error) => self.notes.push(format!(
                "hooks could not be removed at a clone that shares memory ({error}): counts after this point are not reliable"
            )),
        }
    }
}

/// The per-process state for a whole run.
#[derive(Debug)]
pub struct Monitor {
    states: BTreeMap<Pid, Process>,
    reports: Vec<ImageReport>,
    images: u64,
    collect_every: u64,
}

impl Monitor {
    /// A monitor that checks a process once `collect_every` allocations have
    /// been counted since its last check. Zero checks at every trapped call.
    pub fn new(collect_every: u64) -> Self {
        Monitor {
            states: BTreeMap::new(),
            reports: Vec::new(),
            images: 0,
            collect_every,
        }
    }

    /// A new image: the process just reached its exec-stop. Any state the pid
    /// had is archived first, because the exec replaces the image.
    pub fn exec<T: Tracer>(&mut self, tracer: &mut T, pid: Pid) -> Vec<Signal> {
        if let Some(old) = self.states.remove(&pid) {
            self.reports
                .push(old.archive("replaced by exec".to_string()));
        }
        self.images += 1;
        let mut process = Process::new(format!("image {} (pid {})", self.images, pid.as_raw()));
        let mut pending_signals = Vec::new();
        match install_hooks(tracer, pid, &mut pending_signals) {
            Ok(hook) => {
                process.hook = Some(hook);
                process.notes.push(
                    "hooked malloc, free, realloc, calloc, memalign, aligned_alloc, valloc, pvalloc, posix_memalign and malloc_trim; allocations after the last trapped call are not read (D34)"
                        .to_string(),
                );
            }
            Err(error) => process.notes.push(format!("not covered: {error:?}")),
        }
        self.states.insert(pid, process);
        pending_signals
    }

    /// A process stopped at a trapped system call, which `syscall` names when
    /// it could be read. The ring is drained. A clone that shares memory removes
    /// the hooks. Then the process is checked for reachability, if enough
    /// allocations have been counted since its last check.
    pub fn trapped<T: Tracer>(&mut self, tracer: &mut T, pid: Pid, syscall: Option<i64>) {
        let Some(process) = self.states.get_mut(&pid) else {
            return;
        };
        let drained = process.drain(tracer, pid);
        if let Some(nr) = syscall
            && (nr == libc::SYS_clone || nr == libc::SYS_clone3)
            && shares_memory(tracer, pid, nr)
        {
            process.unhook(tracer, pid);
        }
        if process.allocations_since_check >= self.collect_every {
            process.check(tracer, pid, drained);
        }
    }

    /// A process forked. Its ring is drained and checked first. The child copies
    /// the ring and the memory, so it starts from the same cursor and inherits a
    /// result for the memory it copies. Forks that are not trapped get a check too.
    pub fn forked<T: Tracer>(&mut self, tracer: &mut T, parent: Pid, child: Pid) {
        let Some(process) = self.states.get_mut(&parent) else {
            return;
        };
        let drained = process.drain(tracer, parent);
        process.check(tracer, parent, drained);
        let mut inherited = process.clone();
        inherited.label = format!("{} forked as pid {}", process.label, child.as_raw());
        inherited.notes.push(format!(
            "forked from pid {}: inherits the parent's outstanding blocks",
            parent.as_raw()
        ));
        self.states.insert(child, inherited);
    }

    pub fn exited(&mut self, pid: Pid, reason: String) {
        if let Some(process) = self.states.remove(&pid) {
            self.reports.push(process.archive(reason));
        }
    }

    /// Archives the processes that never reported an exit, and returns every report.
    pub fn finish(&mut self) -> Vec<ImageReport> {
        for (_, process) in std::mem::take(&mut self.states) {
            self.reports
                .push(process.archive("no exit was observed".to_string()));
        }
        std::mem::take(&mut self.reports)
    }
}

/// Whether a clone is about to share the caller's memory. When the flags cannot
/// be read, the answer is yes: the hooks are removed rather than trusted.
fn shares_memory<T: Tracer>(tracer: &mut T, pid: Pid, nr: i64) -> bool {
    let Ok(regs) = tracer.regs(pid) else {
        return true;
    };
    // clone3 passes a pointer to its arguments. The flags are their first word.
    let flags = if nr == libc::SYS_clone3 {
        read_word(tracer, pid, regs.rdi)
    } else {
        Ok(regs.rdi)
    };
    flags.map_or(true, |flags| flags & CLONE_VM != 0)
}

fn read_word<T: Tracer>(tracer: &mut T, pid: Pid, addr: u64) -> io::Result<u64> {
    let bytes = tracer.read_mem(pid, addr, 8)?;
    Ok(u64::from_le_bytes(bytes.try_into().expect("8 bytes")))
}
