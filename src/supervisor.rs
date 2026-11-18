//! The supervisor starts the target through the stub, traces its memory
//! system calls, and returns the root's exit code once every traced process
//! is gone. Everything it does not trap runs natively: each stop is resumed
//! at once, and the target's instructions are never interpreted.
//!
//! All operating-system calls go through [`Tracer`], so the control flow can
//! be tested with scripted results, including every error path.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::FileExt;

use nix::errno::Errno;
use nix::sys::ptrace::{self, Options};
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;

use crate::maps;
use crate::monitor::Monitor;
use crate::trap;

/// Set to any value to log each trapped call and a summary to stderr.
pub const LOG_ENV: &str = "LEAKGC_LOG";

/// `PTRACE_EVENT_SECCOMP`, the event reported when a trapped call stops.
pub(crate) const PTRACE_EVENT_SECCOMP: i32 = 7;

/// What a wait status means to the supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Exited(Pid, i32),
    Killed(Pid, Signal),
    Trap(Pid),
    /// The process replaced its image. The parent of a fork or clone is named by `Fork` or `Spawn`.
    Exec(Pid),
    Fork(Pid),
    /// A `vfork` or `clone`. The new task is named by `event_message`.
    Spawn(Pid),
    PtraceStop(Pid),
    SignalStop(Pid, Signal),
    Ignored,
}

pub fn classify(status: WaitStatus) -> Event {
    match status {
        WaitStatus::Exited(pid, code) => Event::Exited(pid, code),
        WaitStatus::Signaled(pid, signal, _) => Event::Killed(pid, signal),
        WaitStatus::PtraceEvent(pid, _, PTRACE_EVENT_SECCOMP) => Event::Trap(pid),
        WaitStatus::PtraceEvent(pid, _, libc::PTRACE_EVENT_EXEC) => Event::Exec(pid),
        WaitStatus::PtraceEvent(pid, _, libc::PTRACE_EVENT_FORK) => Event::Fork(pid),
        WaitStatus::PtraceEvent(pid, _, libc::PTRACE_EVENT_VFORK | libc::PTRACE_EVENT_CLONE) => {
            Event::Spawn(pid)
        }
        WaitStatus::PtraceEvent(pid, _, _) | WaitStatus::PtraceSyscall(pid) => {
            Event::PtraceStop(pid)
        }
        WaitStatus::Stopped(pid, signal) => Event::SignalStop(pid, signal),
        WaitStatus::Continued(_) | WaitStatus::StillAlive => Event::Ignored,
    }
}

/// Every operating-system call the supervisor makes.
pub trait Tracer {
    /// Starts `leakgc __stub <args>` as a child of this process.
    fn spawn_stub(&mut self, args: &[OsString]) -> io::Result<Pid>;
    /// Waits for `pid` to stop or exit.
    fn wait_stopped(&mut self, pid: Pid) -> nix::Result<WaitStatus>;
    /// Waits for any traced process or child, including ones that are not
    /// stopped.
    fn wait_any(&mut self) -> nix::Result<WaitStatus>;
    fn seize(&mut self, pid: Pid) -> nix::Result<()>;
    fn cont(&mut self, pid: Pid, sig: Option<Signal>) -> nix::Result<()>;
    fn send_signal(&mut self, pid: Pid, sig: Signal) -> nix::Result<()>;
    fn syscall_nr(&mut self, pid: Pid) -> nix::Result<i64>;
    fn read_maps(&mut self, pid: Pid) -> io::Result<String>;
    /// The executable image as stored on disk, read through `/proc/<pid>/exe`.
    fn exe_image(&mut self, pid: Pid) -> io::Result<Vec<u8>>;
    fn regs(&mut self, pid: Pid) -> nix::Result<libc::user_regs_struct>;
    fn set_regs(&mut self, pid: Pid, regs: libc::user_regs_struct) -> nix::Result<()>;
    /// Runs one instruction. If the stopped thread is at a trapped system call,
    /// the call completes instead of stopping again.
    fn step(&mut self, pid: Pid) -> nix::Result<()>;
    /// The new task's pid, reported with a fork, vfork or clone event.
    fn event_message(&mut self, pid: Pid) -> nix::Result<i64>;
    fn read_mem(&mut self, pid: Pid, addr: u64, len: usize) -> io::Result<Vec<u8>>;
    fn write_mem(&mut self, pid: Pid, addr: u64, bytes: &[u8]) -> io::Result<()>;
}

/// The real operating system. Each method forwards one call without
/// branching, so the logic lives in [`supervise_with`].
pub struct OsTracer;

impl Tracer for OsTracer {
    fn spawn_stub(&mut self, args: &[OsString]) -> io::Result<Pid> {
        let exe = std::env::current_exe().expect("leakgc can locate its own executable");
        std::process::Command::new(exe)
            .arg("__stub")
            .args(args)
            .spawn()
            // The child is not waited on through `Child`: waitpid must see ptrace events.
            .map(|child| Pid::from_raw(i32::try_from(child.id()).expect("pids fit in i32")))
    }

    fn wait_stopped(&mut self, pid: Pid) -> nix::Result<WaitStatus> {
        waitpid(pid, Some(WaitPidFlag::WUNTRACED))
    }

    fn wait_any(&mut self) -> nix::Result<WaitStatus> {
        waitpid(None, Some(WaitPidFlag::__WALL))
    }

    fn seize(&mut self, pid: Pid) -> nix::Result<()> {
        let options = Options::PTRACE_O_TRACESECCOMP
            | Options::PTRACE_O_TRACEEXEC
            | Options::PTRACE_O_TRACECLONE
            | Options::PTRACE_O_TRACEFORK
            | Options::PTRACE_O_TRACEVFORK
            | Options::PTRACE_O_EXITKILL;
        ptrace::seize(pid, options)
    }

    fn cont(&mut self, pid: Pid, sig: Option<Signal>) -> nix::Result<()> {
        ptrace::cont(pid, sig)
    }

    fn send_signal(&mut self, pid: Pid, sig: Signal) -> nix::Result<()> {
        signal::kill(pid, sig)
    }

    fn syscall_nr(&mut self, pid: Pid) -> nix::Result<i64> {
        ptrace::getregs(pid).map(|regs| regs.orig_rax as i64)
    }

    fn read_maps(&mut self, pid: Pid) -> io::Result<String> {
        std::fs::read_to_string(format!("/proc/{}/maps", pid.as_raw()))
    }

    fn exe_image(&mut self, pid: Pid) -> io::Result<Vec<u8>> {
        std::fs::read(format!("/proc/{}/exe", pid.as_raw()))
    }

    fn regs(&mut self, pid: Pid) -> nix::Result<libc::user_regs_struct> {
        ptrace::getregs(pid)
    }

    fn set_regs(&mut self, pid: Pid, regs: libc::user_regs_struct) -> nix::Result<()> {
        ptrace::setregs(pid, regs)
    }

    fn step(&mut self, pid: Pid) -> nix::Result<()> {
        ptrace::step(pid, None)
    }

    fn event_message(&mut self, pid: Pid) -> nix::Result<i64> {
        ptrace::getevent(pid)
    }

    fn read_mem(&mut self, pid: Pid, addr: u64, len: usize) -> io::Result<Vec<u8>> {
        open_mem(pid, false).and_then(|mem| {
            let mut bytes = vec![0; len];
            mem.read_exact_at(&mut bytes, addr).map(|()| bytes)
        })
    }

    fn write_mem(&mut self, pid: Pid, addr: u64, bytes: &[u8]) -> io::Result<()> {
        open_mem(pid, true).and_then(|mem| mem.write_all_at(bytes, addr))
    }
}

/// The target's memory, through `/proc/<pid>/mem`. The tracee must be stopped.
fn open_mem(pid: Pid, write: bool) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(write)
        .open(format!("/proc/{}/mem", pid.as_raw()))
}

/// Repeats a wait that a signal interrupted.
fn retry(mut wait: impl FnMut() -> nix::Result<WaitStatus>) -> nix::Result<WaitStatus> {
    loop {
        match wait() {
            Err(Errno::EINTR) => {}
            result => return result,
        }
    }
}

/// One supervised run. The `armed` flag is a guard: while it is set, dropping
/// the session kills the stub, so a failure before the stub is resumed never
/// leaves it stopped and untraced (a hang we observed in P0-b).
struct Session<'t, 'l, T: Tracer> {
    tracer: &'t mut T,
    stub: Pid,
    armed: bool,
    log: Option<&'l mut dyn Write>,
    tracees: BTreeSet<Pid>,
    traps: BTreeMap<&'static str, u64>,
    root_code: Option<i32>,
    monitor: Monitor,
    /// Children whose initial stop came before their fork or clone event. They
    /// stay stopped until the event names them.
    early: BTreeSet<Pid>,
    /// Children named by their event before their initial stop arrived.
    announced: BTreeSet<Pid>,
}

impl<T: Tracer> Drop for Session<'_, '_, T> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.tracer.send_signal(self.stub, Signal::SIGKILL);
        }
    }
}

impl<T: Tracer> Session<'_, '_, T> {
    fn run(&mut self) -> i32 {
        if let Err(code) = self.start() {
            return code;
        }
        self.drain();
        self.summarise();
        self.root_code.unwrap_or(1)
    }

    /// Waits for the stub's self-stop, attaches, and resumes it. Returns the
    /// exit code when the stub finished before it could be attached.
    fn start(&mut self) -> Result<(), i32> {
        let stub = self.stub;
        match retry(|| self.tracer.wait_stopped(stub)) {
            Ok(WaitStatus::Stopped(_, Signal::SIGSTOP)) => {}
            Ok(WaitStatus::Exited(_, code)) => {
                self.armed = false;
                return Err(code);
            }
            Ok(WaitStatus::Signaled(_, signal, _)) => {
                self.armed = false;
                return Err(128 + signal as i32);
            }
            _ => return Err(1),
        }
        if self.tracer.seize(stub).is_err() {
            return Err(1);
        }
        if self.tracer.send_signal(stub, Signal::SIGCONT).is_err() {
            return Err(1);
        }
        self.armed = false;
        Ok(())
    }

    /// Services events until no traced process or child is left. Returning
    /// earlier would leave tracees mid-call, which fail with ENOSYS, or kill
    /// them through EXITKILL. Wine leaves `wineserver` running, so this drain
    /// is required (PLAN 4.4).
    fn drain(&mut self) {
        loop {
            match retry(|| self.tracer.wait_any()) {
                Ok(status) => self.handle(classify(status)),
                Err(Errno::ECHILD) => return,
                Err(_) => {
                    self.root_code = Some(1);
                    return;
                }
            }
        }
    }

    fn handle(&mut self, event: Event) {
        match event {
            Event::Exited(pid, code) => {
                if pid == self.stub {
                    self.root_code = Some(code);
                }
                self.monitor.exited(pid, format!("exit code {code}"));
            }
            Event::Killed(pid, signal) => {
                if pid == self.stub {
                    self.root_code = Some(128 + signal as i32);
                }
                self.monitor.exited(pid, format!("killed by {signal}"));
            }
            Event::Trap(pid) => {
                self.tracees.insert(pid);
                let nr = self.tracer.syscall_nr(pid);
                let name = match nr {
                    Ok(nr) => trap::name_of(nr),
                    Err(_) => "unknown",
                };
                *self.traps.entry(name).or_insert(0) += 1;
                if let Some(log) = self.log.as_deref_mut() {
                    let writable = self
                        .tracer
                        .read_maps(pid)
                        .map_or(0, |maps| maps::writable_count(&maps));
                    let _ = writeln!(
                        log,
                        "leakgc: trap {name} pid {} writable mappings {writable}",
                        pid.as_raw()
                    );
                }
                self.monitor.trapped(&mut *self.tracer, pid, nr.ok());
                let _ = self.tracer.cont(pid, None);
            }
            Event::Exec(pid) => {
                self.tracees.insert(pid);
                self.monitor.exec(&mut *self.tracer, pid);
                let _ = self.tracer.cont(pid, None);
            }
            Event::Fork(parent) => {
                self.tracees.insert(parent);
                if let Some(child) = self.new_task(parent) {
                    self.monitor.forked(&mut *self.tracer, parent, child);
                    self.announce(child);
                }
                let _ = self.tracer.cont(parent, None);
            }
            Event::Spawn(parent) => {
                self.tracees.insert(parent);
                if let Some(child) = self.new_task(parent) {
                    self.announce(child);
                }
                let _ = self.tracer.cont(parent, None);
            }
            Event::PtraceStop(pid) => {
                self.tracees.insert(pid);
                let _ = self.tracer.cont(pid, None);
            }
            Event::SignalStop(pid, signal) => {
                let first = self.tracees.insert(pid);
                if first && signal == Signal::SIGSTOP {
                    // A new task's initial stop. It runs once its fork or clone event names it.
                    if self.announced.remove(&pid) {
                        let _ = self.tracer.cont(pid, None);
                    } else {
                        self.early.insert(pid);
                    }
                    return;
                }
                // SIGSTOP and SIGTRAP are ptrace's own stops, so they are not
                // delivered to the target.
                let pass = match signal {
                    Signal::SIGSTOP | Signal::SIGTRAP => None,
                    other => Some(other),
                };
                let _ = self.tracer.cont(pid, pass);
            }
            Event::Ignored => {}
        }
    }

    /// The pid of the task that `parent`'s fork or clone event created. `None`
    /// when ptrace cannot name it.
    fn new_task(&mut self, parent: Pid) -> Option<Pid> {
        match self.tracer.event_message(parent) {
            Ok(raw) => i32::try_from(raw).ok().map(Pid::from_raw),
            Err(_) => None,
        }
    }

    /// Records that `child` was named by its event. If its initial stop already
    /// arrived, it runs now.
    fn announce(&mut self, child: Pid) {
        if self.early.remove(&child) {
            let _ = self.tracer.cont(child, None);
        } else {
            self.announced.insert(child);
        }
    }

    fn summarise(&mut self) {
        let reports = self.monitor.finish();
        let Some(log) = self.log.as_deref_mut() else {
            return;
        };
        let _ = writeln!(log, "leakgc: {} tracees", self.tracees.len());
        for (name, count) in &self.traps {
            let _ = writeln!(log, "leakgc: {name} traps: {count}");
        }
        for report in reports {
            for line in report.lines() {
                let _ = writeln!(log, "leakgc: {line}");
            }
        }
    }
}

/// Runs `args` under supervision with the given tracer. Trap logging and the
/// summary go to `log` when it is given. Returns the exit code `leakgc` should
/// report.
pub fn supervise_with<T: Tracer>(
    tracer: &mut T,
    args: &[OsString],
    log: Option<&mut dyn Write>,
) -> i32 {
    let stub = match tracer.spawn_stub(args) {
        Ok(pid) => pid,
        Err(error) => {
            eprintln!("leakgc: cannot start supervision: {error}");
            return 1;
        }
    };
    let mut session = Session {
        tracer,
        stub,
        armed: true,
        log,
        tracees: BTreeSet::new(),
        traps: BTreeMap::new(),
        root_code: None,
        monitor: Monitor::default(),
        early: BTreeSet::new(),
        announced: BTreeSet::new(),
    };
    session.run()
}

/// Runs `args` under supervision on the real operating system. Logging is on
/// when [`LOG_ENV`] is set.
pub fn supervise(args: &[OsString]) -> i32 {
    let mut tracer = OsTracer;
    let mut stderr = io::stderr();
    let log: Option<&mut dyn Write> = if std::env::var_os(LOG_ENV).is_some() {
        Some(&mut stderr)
    } else {
        None
    };
    supervise_with(&mut tracer, args, log)
}
