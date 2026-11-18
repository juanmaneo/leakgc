//! Follows every traced process and keeps one ledger per process image (P2b-3a).
//!
//! The record ring is read at each trapped system call, at each fork, and when
//! a process exits. Records written after a process's last trapped call are
//! never read (D34). Threads are not handled yet: the first clone that shares
//! memory removes the hooks from that process (P2b-3b).

use std::collections::BTreeMap;
use std::io;

use nix::unistd::Pid;

use crate::install::{HEAD_OFFSET, Installed, RECORDS_OFFSET, install_hooks, uninstall};
use crate::ledger::{ImageReport, Ledger};
use crate::ring::{RECORD_LEN, Slot, decode, plan_drain, slot_runs};
use crate::supervisor::Tracer;

/// `CLONE_VM`: the new task shares the caller's memory.
const CLONE_VM: u64 = 0x0000_0100;

/// The state of one process: its image's hooks, how far its ring has been read,
/// its ledger, and the notes that explain gaps in the report.
#[derive(Debug, Clone)]
struct Process {
    label: String,
    hook: Option<Installed>,
    cursor: u64,
    ledger: Ledger,
    notes: Vec<String>,
}

impl Process {
    fn new(label: String) -> Self {
        Process {
            label,
            hook: None,
            cursor: 0,
            ledger: Ledger::default(),
            notes: Vec::new(),
        }
    }

    fn archive(mut self, reason: String) -> ImageReport {
        self.notes.push(reason);
        ImageReport::new(self.label, &self.ledger, self.notes)
    }

    /// Reads and applies the records written since the last drain. It stops at
    /// the first open record, which is read on a later drain, and at a record
    /// that does not decode, after which nothing more is read.
    fn drain<T: Tracer>(&mut self, tracer: &mut T, pid: Pid) {
        let Some(hook) = self.hook.clone() else {
            return;
        };
        let head = match read_word(tracer, pid, hook.base + HEAD_OFFSET) {
            Ok(head) => head,
            Err(error) => {
                self.notes
                    .push(format!("cannot read the record head: {error}"));
                return;
            }
        };
        let drain = plan_drain(self.cursor, head);
        if drain.lost > 0 {
            self.notes.push(format!(
                "{} records were overwritten before they were read: counts are incomplete",
                drain.lost
            ));
        }
        let records = hook.base + RECORDS_OFFSET;
        let mut index = drain.first;
        for (slot, len) in slot_runs(drain.first, drain.count) {
            let at = records + slot * RECORD_LEN as u64;
            let bytes = match tracer.read_mem(pid, at, len as usize * RECORD_LEN) {
                Ok(bytes) => bytes,
                Err(error) => {
                    self.notes.push(format!("cannot read the records: {error}"));
                    break;
                }
            };
            let (chunks, _) = bytes.as_chunks::<RECORD_LEN>();
            for chunk in chunks {
                match decode(chunk) {
                    Some(Slot::Open) => {
                        self.cursor = index;
                        return;
                    }
                    Some(Slot::Done(record)) => {
                        self.ledger.apply(record);
                        index += 1;
                    }
                    None => {
                        self.notes.push(format!(
                            "record {index} is corrupt: reading stopped, counts are incomplete"
                        ));
                        self.hook = None;
                        self.cursor = index;
                        return;
                    }
                }
            }
        }
        self.cursor = index;
    }

    /// Removes the hooks, after a clone that shares memory. If the removal
    /// fails, the process stays patched, so its counts are not reported as complete.
    fn unhook<T: Tracer>(&mut self, tracer: &mut T, pid: Pid) {
        let Some(hook) = self.hook.take() else {
            return;
        };
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
#[derive(Debug, Default)]
pub struct Monitor {
    states: BTreeMap<Pid, Process>,
    reports: Vec<ImageReport>,
    images: u64,
}

impl Monitor {
    /// A new image: the process just reached its exec-stop. Any state the pid
    /// had is archived first, because the exec replaces the image.
    pub fn exec<T: Tracer>(&mut self, tracer: &mut T, pid: Pid) {
        if let Some(old) = self.states.remove(&pid) {
            self.reports
                .push(old.archive("replaced by exec".to_string()));
        }
        self.images += 1;
        let mut process = Process::new(format!("image {} (pid {})", self.images, pid.as_raw()));
        match install_hooks(tracer, pid) {
            Ok(hook) => {
                process.hook = Some(hook);
                process.notes.push(
                    "hooked malloc, free and realloc; allocations after the last trapped call are not read (D34)"
                        .to_string(),
                );
            }
            Err(error) => process.notes.push(format!("not covered: {error:?}")),
        }
        self.states.insert(pid, process);
    }

    /// A process stopped at a trapped system call, which `syscall` names when
    /// it could be read. The ring is drained, and a clone that shares memory
    /// removes the hooks.
    pub fn trapped<T: Tracer>(&mut self, tracer: &mut T, pid: Pid, syscall: Option<i64>) {
        let Some(process) = self.states.get_mut(&pid) else {
            return;
        };
        process.drain(tracer, pid);
        if let Some(nr) = syscall
            && (nr == libc::SYS_clone || nr == libc::SYS_clone3)
            && shares_memory(tracer, pid, nr)
        {
            process.unhook(tracer, pid);
        }
    }

    /// A process forked. Its ring is drained first, so the child, which copies
    /// the ring, starts from the same cursor and does not repeat records.
    pub fn forked<T: Tracer>(&mut self, tracer: &mut T, parent: Pid, child: Pid) {
        let Some(process) = self.states.get_mut(&parent) else {
            return;
        };
        process.drain(tracer, parent);
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
