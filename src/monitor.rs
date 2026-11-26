//! Follows every traced process and keeps one ledger per process image (P2b-3a).
//!
//! The record ring is read at each trapped system call and at each fork.
//! Records written after a process's last trapped call are never read (D34).
//! Once a process has made `COLLECT_EVERY` allocations since its last check,
//! its next trapped call checks it for reachability. Each fork is checked
//! whatever the count (D42, D47, D53). A check also holds the unreached blocks
//! in quarantine, which poisons them (P5). Once a check has confirmed held
//! blocks, the next memory call that returns frees them, one injected `free`
//! at a time (P5). Each block is checked again just before its free (R42).
//! Threads are not handled yet: the first clone that shares memory removes the
//! hooks from that process, and its reachability checks end for good (P2b-3b).

use std::collections::{BTreeMap, VecDeque};
use std::io;

use nix::sys::signal::Signal;
use nix::unistd::Pid;

use crate::crash::{self, Crash, Snapshot, Symbols};
use crate::inject::{may_inject, xsave_available};
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
/// The trapped calls at whose exit an injected `free` may start (P5). These
/// change the memory map. Clone and execve are left out: a clone can share
/// memory with the injected call, and execve replaces the image.
const EXIT_CALLS: [i64; 4] = [
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_brk,
];
/// Bytes below the saved stack pointer that stay clear of injected code: the
/// 128-byte red zone, and a margin.
const CLEARANCE: u64 = 256;
/// The words above the stack pointer that the R37 check reads.
const STACK_WORDS: usize = 128;
/// The direction flag, which the ABI requires to be clear on entry to a function.
const DIRECTION_FLAG: u64 = 0x400;

/// Where an injected `free` starts from. `saved` is the state the process
/// stopped in, and the last injected call restores it. The calls run below
/// `rsp`, which lies clear of the red zone of `saved`.
#[derive(Debug, Clone, Copy)]
struct Frame {
    saved: libc::user_regs_struct,
    rsp: u64,
    trampoline: u64,
    stop: u64,
}

impl Frame {
    /// The registers that start an injected `free` of `block`. `orig_rax` is
    /// -1, so no system call is restarted when the process resumes.
    fn armed(&self, block: u64) -> libc::user_regs_struct {
        libc::user_regs_struct {
            rip: self.trampoline,
            rsp: self.rsp,
            rdi: block,
            orig_rax: u64::MAX,
            eflags: self.saved.eflags & !DIRECTION_FLAG,
            ..self.saved
        }
    }
}

/// An injected `free` in progress, and the blocks still waiting for one.
#[derive(Debug, Clone, Default)]
struct Injection {
    /// Set from the first free until the last one returns.
    frame: Option<Frame>,
    /// Blocks still to be freed, in the order they were confirmed.
    queue: VecDeque<u64>,
    /// Signals that stopped the process while injected code ran. They are
    /// delivered once the process is restored.
    deferred: Vec<Signal>,
    /// Injected frees started so far.
    freed: u64,
    /// The block whose injected free is running, if any.
    freeing: Option<u64>,
}

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
    /// The injected `free` in progress, if any (P5).
    injection: Injection,
    /// Blocks that the trapped call asked to free at its exit (P5). Empty
    /// unless the call was trapped with confirmed blocks waiting.
    inject_at_exit: Vec<u64>,
    /// Blocks whose injected free did not start, because the process was not at
    /// a point where one is known to be safe (R37). Counted, and noted at exit.
    skipped_frees: u64,
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
            injection: Injection::default(),
            inject_at_exit: Vec::new(),
            skipped_frees: 0,
        }
    }

    fn archive(mut self, reason: String) -> ImageReport {
        if self.skipped_frees > 0 {
            self.notes.push(format!(
                "{} blocks were not freed by injection: the program was not at a point where an injected free is known to be safe (R37), so they stay held",
                self.skipped_frees
            ));
        }
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
    /// outstanding blocks, so later records do not change it. Returns whether
    /// the check completed (P5).
    fn check<T: Tracer>(&mut self, tracer: &mut T, pid: Pid, drained: Drained) -> bool {
        if let Some(reason) = &self.untrusted {
            self.reach = Reachability::Incomplete(reason.clone());
            return false;
        }
        let Some(hook) = self.hook.clone() else {
            return false;
        };
        match drained {
            Drained::Settled => {
                // Reset even if the scan fails, so a failing scan is not retried at every trap.
                self.allocations_since_check = 0;
                let blocks: Vec<(u64, u64)> = self.ledger.live_blocks().collect();
                let region = hook.base..hook.base + REGION_LEN;
                let (reach, checked) = match reachable(tracer, pid, region, &blocks) {
                    Ok(scan) => match self.quarantine.update(tracer, pid, &blocks, &scan) {
                        Ok(()) => (
                            Reachability::Checked {
                                lost: self.ledger.unreached_sites(&scan.reached),
                            },
                            true,
                        ),
                        Err(reason) => {
                            self.untrusted.get_or_insert(reason.clone());
                            (Reachability::Incomplete(reason), false)
                        }
                    },
                    Err(reason) => (Reachability::Incomplete(reason), false),
                };
                self.reach = reach;
                checked
            }
            // The last complete result stays, and is still a snapshot of an earlier state.
            Drained::InCall => false,
            Drained::Behind(reason) => {
                self.reach = Reachability::Incomplete(reason);
                false
            }
        }
    }

    /// Starts an injected `free` of `blocks` at the exit of the trapped call,
    /// which is a safe point only when the R37 check allows it. Otherwise the
    /// blocks stay held and are counted for the report.
    fn start_injection<T: Tracer>(&mut self, tracer: &mut T, pid: Pid, blocks: Vec<u64>) {
        let hook = self.hook.clone().expect("a checked process has hooks");
        let Some(frame) = safe_frame(tracer, pid, &hook) else {
            self.skipped_frees += blocks.len() as u64;
            return;
        };
        self.injection = Injection {
            frame: Some(frame),
            queue: VecDeque::from(blocks),
            ..Injection::default()
        };
        let Some(first) = self.next_block(tracer, pid) else {
            self.injection = Injection::default();
            return;
        };
        if let Err(error) = self.arm(tracer, pid, frame, first) {
            self.injection = Injection::default();
            self.notes.push(format!(
                "the injected free of 0x{first:x} could not start ({error}): the blocks stay held"
            ));
        }
    }

    /// Points the process at the injected `free` of `block`. The block stops
    /// being held, because the program is freeing it on purpose.
    fn arm<T: Tracer>(
        &mut self,
        tracer: &mut T,
        pid: Pid,
        frame: Frame,
        block: u64,
    ) -> nix::Result<()> {
        tracer.set_regs(pid, frame.armed(block))?;
        self.quarantine.forget(block);
        self.injection.freed += 1;
        self.injection.freeing = Some(block);
        Ok(())
    }

    /// The next block to free, after its span is checked again (R42). A block
    /// that the program changed or unmapped makes the process untrusted. The
    /// rest of the queue then stays held, so nothing more is freed by injection.
    fn next_block<T: Tracer>(&mut self, tracer: &mut T, pid: Pid) -> Option<u64> {
        let block = self.injection.queue.pop_front()?;
        let Err(reason) = self.quarantine.verify(tracer, pid, block) else {
            return Some(block);
        };
        self.notes.push(format!(
            "{reason}: this block and the rest of its queue stay held, and no more blocks are freed by injection"
        ));
        self.injection.queue.clear();
        let untrusted = self.untrusted.get_or_insert(reason).clone();
        self.reach = Reachability::Incomplete(untrusted);
        None
    }

    /// A signal stopped the process while it may be running injected code.
    /// Returns the signals to deliver once the process is restored, or `None`
    /// when the stop is not part of an injection. A fault adds its crash report
    /// to `alerts` (decision 3).
    fn injected_stop<T: Tracer>(
        &mut self,
        tracer: &mut T,
        pid: Pid,
        signal: Signal,
        alerts: &mut Vec<String>,
    ) -> Option<Vec<Signal>> {
        let frame = self.injection.frame?;
        if signal != Signal::SIGTRAP {
            if is_fault(signal) {
                alerts.extend(crash::report(&self.crash_at_fault(tracer, pid, signal)));
                return Some(self.abandon(
                    tracer,
                    pid,
                    format!("signal {signal} in injected code"),
                ));
            }
            self.injection.deferred.push(signal);
            return Some(Vec::new());
        }
        let Ok(regs) = tracer.regs(pid) else {
            return Some(self.abandon(
                tracer,
                pid,
                "registers unreadable at the end of injected code".to_string(),
            ));
        };
        if regs.rip != frame.stop + 1 {
            return Some(self.abandon(
                tracer,
                pid,
                format!("unexpected SIGTRAP at 0x{:x} in injected code", regs.rip),
            ));
        }
        if let Some(next) = self.next_block(tracer, pid) {
            return Some(match self.arm(tracer, pid, frame, next) {
                Ok(()) => Vec::new(),
                Err(error) => self.abandon(
                    tracer,
                    pid,
                    format!("the injected free of 0x{next:x} could not start ({error})"),
                ),
            });
        }
        let restored = libc::user_regs_struct {
            orig_rax: u64::MAX,
            ..frame.saved
        };
        if let Err(error) = tracer.set_regs(pid, restored) {
            return Some(self.abandon(
                tracer,
                pid,
                format!("registers could not be restored after injected code ({error})"),
            ));
        }
        // The injected frees wrote their own records, so the ledger catches up
        // now rather than at the next trapped call.
        self.drain(tracer, pid);
        let injection = std::mem::take(&mut self.injection);
        self.notes.push(format!(
            "freed {} unreached blocks by injected free calls",
            injection.freed
        ));
        Some(injection.deferred)
    }

    /// Ends an injection that cannot finish safely. The process is killed, and
    /// the ledger is untrusted from here on. If the kill fails, the process
    /// resumes where it stopped. No signals are returned for delivery.
    fn abandon<T: Tracer>(&mut self, tracer: &mut T, pid: Pid, reason: String) -> Vec<Signal> {
        self.injection = Injection::default();
        let outcome = match tracer.send_signal(pid, Signal::SIGKILL) {
            Ok(()) => "the process was killed".to_string(),
            Err(error) => {
                format!("the process could not be killed ({error}) and resumes where it stopped")
            }
        };
        self.notes.push(format!("{reason}: {outcome}"));
        let untrusted = self.untrusted.get_or_insert(reason).clone();
        self.reach = Reachability::Incomplete(untrusted);
        Vec::new()
    }

    /// What a fault in injected code left behind. It is read while the process
    /// is stopped, before the process is killed.
    fn crash_at_fault<T: Tracer>(&self, tracer: &mut T, pid: Pid, signal: Signal) -> Crash {
        let hook = self.hook.as_ref().expect("an injection has hooks");
        let state = match tracer.regs(pid) {
            Ok(regs) => Ok(Snapshot {
                regs,
                stack: read_stack(tracer, pid, regs.rsp).map_err(|error| error.to_string()),
            }),
            Err(error) => Err(error.to_string()),
        };
        let symbols = tracer
            .exe_image(pid)
            .map_err(|error| error.to_string())
            .and_then(|image| Symbols::parse(&image));
        Crash {
            signal,
            freeing: self.injection.freeing,
            state,
            symbols,
            own_code: hook.base..hook.base + REGION_LEN,
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
    /// Crash report lines not yet taken by the supervisor (decision 3).
    alerts: Vec<String>,
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
            alerts: Vec::new(),
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
    /// allocations have been counted since its last check. Nothing is checked
    /// while injected code runs.
    ///
    /// Returns whether the call must be resumed to its exit, because a check
    /// has confirmed blocks for an injected free there (P5). The caller then
    /// reports that exit with [`Monitor::syscall_exited`].
    pub fn trapped<T: Tracer>(&mut self, tracer: &mut T, pid: Pid, syscall: Option<i64>) -> bool {
        let Some(process) = self.states.get_mut(&pid) else {
            return false;
        };
        let drained = process.drain(tracer, pid);
        if let Some(nr) = syscall
            && (nr == libc::SYS_clone || nr == libc::SYS_clone3)
            && shares_memory(tracer, pid, nr)
        {
            process.unhook(tracer, pid);
        }
        process.inject_at_exit.clear();
        if process.injection.frame.is_some() {
            return false;
        }
        let checked = process.allocations_since_check >= self.collect_every
            && process.check(tracer, pid, drained);
        if checked && syscall.is_some_and(|nr| EXIT_CALLS.contains(&nr)) {
            process.inject_at_exit = process
                .quarantine
                .confirmed()
                .into_iter()
                .map(|(start, _)| start)
                .collect();
        }
        !process.inject_at_exit.is_empty()
    }

    /// A trapped call returned, at the exit that [`Monitor::trapped`] asked for.
    /// If confirmed blocks are waiting, the first injected free starts here.
    pub fn syscall_exited<T: Tracer>(&mut self, tracer: &mut T, pid: Pid) {
        let Some(process) = self.states.get_mut(&pid) else {
            return;
        };
        let blocks = std::mem::take(&mut process.inject_at_exit);
        if !blocks.is_empty() {
            process.start_injection(tracer, pid, blocks);
        }
    }

    /// A process stopped on a signal. Returns the signals to deliver instead,
    /// or `None` when the stop is not part of an injected free (P5). A fault in
    /// injected code adds its crash report, which [`Monitor::take_alerts`] returns.
    pub fn injected_stop<T: Tracer>(
        &mut self,
        tracer: &mut T,
        pid: Pid,
        signal: Signal,
    ) -> Option<Vec<Signal>> {
        self.states
            .get_mut(&pid)?
            .injected_stop(tracer, pid, signal, &mut self.alerts)
    }

    /// The crash report lines written since the last call, in the order they
    /// were written. The supervisor prints them to stderr at once (decision 3).
    pub fn take_alerts(&mut self) -> Vec<String> {
        std::mem::take(&mut self.alerts)
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

/// Whether a signal means that the injected code itself faulted.
fn is_fault(signal: Signal) -> bool {
    matches!(
        signal,
        Signal::SIGSEGV | Signal::SIGBUS | Signal::SIGILL | Signal::SIGFPE | Signal::SIGABRT
    )
}

/// Where an injected `free` may start, or `None` when the process is not at a
/// point where one is known to be safe (R37). Nothing is written.
fn safe_frame<T: Tracer>(tracer: &mut T, pid: Pid, hook: &Installed) -> Option<Frame> {
    let saved = tracer.regs(pid).ok()?;
    let stack = read_stack(tracer, pid, saved.rsp).ok();
    if !may_inject(
        xsave_available(),
        hook.internal.as_deref(),
        saved.rip,
        stack.as_deref(),
    ) {
        return None;
    }
    let rsp = saved.rsp.checked_sub(CLEARANCE).map(|rsp| rsp & !63)?;
    Some(Frame {
        saved,
        rsp,
        trampoline: hook.trampoline,
        stop: hook.stop,
    })
}

/// The words from `rsp` upwards, which the R37 check reads.
fn read_stack<T: Tracer>(tracer: &mut T, pid: Pid, rsp: u64) -> io::Result<Vec<u64>> {
    let bytes = tracer.read_mem(pid, rsp, STACK_WORDS * 8)?;
    let (words, _) = bytes.as_chunks::<8>();
    Ok(words.iter().map(|word| u64::from_le_bytes(*word)).collect())
}

fn read_word<T: Tracer>(tracer: &mut T, pid: Pid, addr: u64) -> io::Result<u64> {
    let bytes = tracer.read_mem(pid, addr, 8)?;
    Ok(u64::from_le_bytes(bytes.try_into().expect("8 bytes")))
}
