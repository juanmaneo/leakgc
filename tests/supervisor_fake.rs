//! Supervisor control flow with every operating-system result scripted. The
//! real-process behaviour is covered in `supervisor_real.rs`.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::{self, Write};

use nix::errno::Errno;
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;
use win_games_leak_garbage_collector::supervisor::{Event, Tracer, classify, supervise_with};

const STUB: i32 = 100;
const CHILD: i32 = 101;
const PTRACE_EVENT_EXEC: i32 = 4;
const PTRACE_EVENT_SECCOMP: i32 = 7;
const MAPS: &str = "\
00400000-00401000 r-xp 00000000 08:01 1 /bin/game
00601000-00602000 rw-p 00001000 08:01 1 /bin/game
7f000000-7f001000 rwxp 00000000 00:00 0
7fff0000-7fff1000 ---p 00000000 00:00 0
";

#[derive(Debug, PartialEq, Eq)]
enum Call {
    Spawn,
    WaitStopped(i32),
    WaitAny,
    Seize(i32),
    Cont(i32, Option<Signal>),
    Kill(i32, Signal),
    SyscallNr(i32),
    ReadMaps(i32),
}

type Scripted = nix::Result<WaitStatus>;

struct Fake {
    stopped: VecDeque<Scripted>,
    any: VecDeque<Scripted>,
    fail_spawn: bool,
    seize_result: nix::Result<()>,
    cont_result: nix::Result<()>,
    fail_signal: Option<Signal>,
    syscall_result: nix::Result<i64>,
    maps: Option<&'static str>,
    calls: Vec<Call>,
}

impl Fake {
    fn new(stopped: Vec<Scripted>, any: Vec<Scripted>) -> Self {
        Self {
            stopped: stopped.into(),
            any: any.into(),
            fail_spawn: false,
            seize_result: Ok(()),
            cont_result: Ok(()),
            fail_signal: None,
            syscall_result: Ok(libc::SYS_execve),
            maps: Some(MAPS),
            calls: Vec::new(),
        }
    }
}

impl Tracer for Fake {
    fn spawn_stub(&mut self, _args: &[OsString]) -> io::Result<Pid> {
        self.calls.push(Call::Spawn);
        if self.fail_spawn {
            Err(io::Error::other("fork refused"))
        } else {
            Ok(Pid::from_raw(STUB))
        }
    }

    fn wait_stopped(&mut self, pid: Pid) -> nix::Result<WaitStatus> {
        self.calls.push(Call::WaitStopped(pid.as_raw()));
        self.stopped.pop_front().unwrap_or(Err(Errno::ECHILD))
    }

    fn wait_any(&mut self) -> nix::Result<WaitStatus> {
        self.calls.push(Call::WaitAny);
        self.any.pop_front().unwrap_or(Err(Errno::ECHILD))
    }

    fn seize(&mut self, pid: Pid) -> nix::Result<()> {
        self.calls.push(Call::Seize(pid.as_raw()));
        self.seize_result
    }

    fn cont(&mut self, pid: Pid, sig: Option<Signal>) -> nix::Result<()> {
        self.calls.push(Call::Cont(pid.as_raw(), sig));
        self.cont_result
    }

    fn send_signal(&mut self, pid: Pid, sig: Signal) -> nix::Result<()> {
        self.calls.push(Call::Kill(pid.as_raw(), sig));
        if self.fail_signal == Some(sig) {
            Err(Errno::ESRCH)
        } else {
            Ok(())
        }
    }

    fn syscall_nr(&mut self, pid: Pid) -> nix::Result<i64> {
        self.calls.push(Call::SyscallNr(pid.as_raw()));
        self.syscall_result
    }

    fn read_maps(&mut self, pid: Pid) -> io::Result<String> {
        self.calls.push(Call::ReadMaps(pid.as_raw()));
        self.maps
            .map(str::to_owned)
            .ok_or_else(|| io::Error::other("no /proc"))
    }
}

fn stopped(pid: i32, sig: Signal) -> Scripted {
    Ok(WaitStatus::Stopped(Pid::from_raw(pid), sig))
}

fn exited(pid: i32, code: i32) -> Scripted {
    Ok(WaitStatus::Exited(Pid::from_raw(pid), code))
}

fn killed(pid: i32, sig: Signal) -> Scripted {
    Ok(WaitStatus::Signaled(Pid::from_raw(pid), sig, false))
}

fn trap(pid: i32) -> Scripted {
    Ok(WaitStatus::PtraceEvent(
        Pid::from_raw(pid),
        Signal::SIGTRAP,
        PTRACE_EVENT_SECCOMP,
    ))
}

fn exec_event(pid: i32) -> Scripted {
    Ok(WaitStatus::PtraceEvent(
        Pid::from_raw(pid),
        Signal::SIGTRAP,
        PTRACE_EVENT_EXEC,
    ))
}

fn run(tracer: &mut Fake, with_log: bool) -> (i32, String) {
    let args = [OsString::from("game.exe")];
    let mut buf = Vec::new();
    let code = if with_log {
        supervise_with(tracer, &args, Some(&mut buf as &mut dyn Write))
    } else {
        supervise_with(tracer, &args, None)
    };
    (code, String::from_utf8(buf).expect("log is UTF-8"))
}

#[test]
fn happy_path_resumes_every_stop_and_returns_the_root_exit_code() {
    let mut tracer = Fake::new(
        vec![stopped(STUB, Signal::SIGSTOP)],
        vec![
            trap(STUB),
            exec_event(STUB),
            stopped(CHILD, Signal::SIGCHLD),
            stopped(CHILD, Signal::SIGTRAP),
            stopped(CHILD, Signal::SIGSTOP),
            Ok(WaitStatus::Continued(Pid::from_raw(CHILD))),
            exited(STUB, 0),
        ],
    );
    let (code, _) = run(&mut tracer, false);

    assert_eq!(code, 0);
    assert_eq!(
        tracer.calls,
        [
            Call::Spawn,
            Call::WaitStopped(STUB),
            Call::Seize(STUB),
            Call::Kill(STUB, Signal::SIGCONT),
            Call::WaitAny,
            Call::SyscallNr(STUB),
            Call::Cont(STUB, None),
            Call::WaitAny,
            Call::Cont(STUB, None),
            Call::WaitAny,
            Call::Cont(CHILD, Some(Signal::SIGCHLD)),
            Call::WaitAny,
            Call::Cont(CHILD, None),
            Call::WaitAny,
            Call::Cont(CHILD, None),
            Call::WaitAny,
            Call::WaitAny,
            Call::WaitAny,
        ]
    );
}

#[test]
fn logs_each_trap_and_a_summary_with_writable_mappings() {
    let mut tracer = Fake::new(
        vec![stopped(STUB, Signal::SIGSTOP)],
        vec![trap(STUB), trap(CHILD), exited(STUB, 0)],
    );
    tracer.syscall_result = Ok(libc::SYS_mmap);
    let (code, log) = run(&mut tracer, true);

    assert_eq!(code, 0);
    assert!(log.contains("leakgc: trap mmap pid 100 writable mappings 2\n"));
    assert!(log.contains("leakgc: trap mmap pid 101 writable mappings 2\n"));
    assert!(log.contains("leakgc: 2 tracees\n"));
    assert!(log.contains("leakgc: mmap traps: 2\n"));
    assert!(tracer.calls.contains(&Call::ReadMaps(STUB)));
}

#[test]
fn unknown_call_and_unreadable_maps_are_logged_defensively() {
    let mut tracer = Fake::new(
        vec![stopped(STUB, Signal::SIGSTOP)],
        vec![trap(STUB), exited(STUB, 0)],
    );
    tracer.syscall_result = Err(Errno::ESRCH);
    tracer.maps = None;
    let (code, log) = run(&mut tracer, true);

    assert_eq!(code, 0);
    assert!(log.contains("leakgc: trap unknown pid 100 writable mappings 0\n"));
    assert!(log.contains("leakgc: unknown traps: 1\n"));
}

#[test]
fn refused_resume_of_a_trapped_call_is_ignored() {
    let mut tracer = Fake::new(
        vec![stopped(STUB, Signal::SIGSTOP)],
        vec![trap(STUB), exited(STUB, 0)],
    );
    tracer.cont_result = Err(Errno::ESRCH);
    let (code, _) = run(&mut tracer, false);

    assert_eq!(code, 0);
}

#[test]
fn only_the_root_exit_decides_the_code() {
    let mut tracer = Fake::new(
        vec![stopped(STUB, Signal::SIGSTOP)],
        vec![
            exited(CHILD, 5),
            killed(CHILD, Signal::SIGKILL),
            exited(STUB, 3),
        ],
    );
    let (code, _) = run(&mut tracer, false);

    assert_eq!(code, 3);
}

#[test]
fn root_killed_by_a_signal_reports_128_plus_the_signal() {
    let mut tracer = Fake::new(
        vec![stopped(STUB, Signal::SIGSTOP)],
        vec![killed(STUB, Signal::SIGKILL)],
    );
    let (code, _) = run(&mut tracer, false);

    assert_eq!(code, 137);
}

#[test]
fn interrupted_waits_are_retried() {
    let mut tracer = Fake::new(
        vec![Err(Errno::EINTR), stopped(STUB, Signal::SIGSTOP)],
        vec![Err(Errno::EINTR), exited(STUB, 0)],
    );
    let (code, _) = run(&mut tracer, false);

    assert_eq!(code, 0);
    assert_eq!(
        tracer
            .calls
            .iter()
            .filter(|call| **call == Call::WaitStopped(STUB))
            .count(),
        2
    );
}

#[test]
fn drain_that_ends_without_a_root_exit_reports_1() {
    let mut tracer = Fake::new(
        vec![stopped(STUB, Signal::SIGSTOP)],
        vec![Err(Errno::EINTR)],
    );
    let (code, _) = run(&mut tracer, false);

    assert_eq!(code, 1);
}

#[test]
fn wait_error_after_root_exit_reports_1() {
    let mut tracer = Fake::new(
        vec![stopped(STUB, Signal::SIGSTOP)],
        vec![exited(STUB, 0), Err(Errno::EIO)],
    );
    let (code, _) = run(&mut tracer, false);

    assert_eq!(code, 1);
}

#[test]
fn stub_exit_before_the_stop_returns_its_code_without_a_kill() {
    let mut tracer = Fake::new(vec![exited(STUB, 2)], vec![]);
    let (code, _) = run(&mut tracer, false);

    assert_eq!(code, 2);
    assert!(
        !tracer
            .calls
            .iter()
            .any(|call| matches!(call, Call::Kill(..)))
    );
}

#[test]
fn stub_killed_before_the_stop_returns_128_plus_the_signal() {
    let mut tracer = Fake::new(vec![killed(STUB, Signal::SIGSEGV)], vec![]);
    let (code, _) = run(&mut tracer, false);

    assert_eq!(code, 139);
    assert!(
        !tracer
            .calls
            .iter()
            .any(|call| matches!(call, Call::Kill(..)))
    );
}

#[test]
fn unexpected_stop_before_attach_kills_the_stub() {
    let mut tracer = Fake::new(vec![stopped(STUB, Signal::SIGTRAP)], vec![]);
    let (code, _) = run(&mut tracer, false);

    assert_eq!(code, 1);
    assert!(tracer.calls.contains(&Call::Kill(STUB, Signal::SIGKILL)));
    assert!(
        !tracer
            .calls
            .iter()
            .any(|call| matches!(call, Call::Seize(_)))
    );
}

#[test]
fn wait_error_before_the_stop_kills_the_stub() {
    let mut tracer = Fake::new(vec![Err(Errno::EIO)], vec![]);
    let (code, _) = run(&mut tracer, false);

    assert_eq!(code, 1);
    assert!(tracer.calls.contains(&Call::Kill(STUB, Signal::SIGKILL)));
}

#[test]
fn refused_seize_kills_the_stub_without_resuming_it() {
    let mut tracer = Fake::new(vec![stopped(STUB, Signal::SIGSTOP)], vec![]);
    tracer.seize_result = Err(Errno::EPERM);
    let (code, _) = run(&mut tracer, false);

    assert_eq!(code, 1);
    assert!(tracer.calls.contains(&Call::Kill(STUB, Signal::SIGKILL)));
    assert!(!tracer.calls.contains(&Call::Kill(STUB, Signal::SIGCONT)));
}

#[test]
fn refused_resume_kills_the_stub() {
    let mut tracer = Fake::new(vec![stopped(STUB, Signal::SIGSTOP)], vec![]);
    tracer.fail_signal = Some(Signal::SIGCONT);
    let (code, _) = run(&mut tracer, false);

    assert_eq!(code, 1);
    assert_eq!(
        tracer.calls[tracer.calls.len() - 2..],
        [
            Call::Kill(STUB, Signal::SIGCONT),
            Call::Kill(STUB, Signal::SIGKILL)
        ]
    );
}

#[test]
fn failed_spawn_reports_1_without_waiting() {
    let mut tracer = Fake::new(vec![], vec![]);
    tracer.fail_spawn = true;
    let (code, _) = run(&mut tracer, false);

    assert_eq!(code, 1);
    assert_eq!(tracer.calls, [Call::Spawn]);
}

#[test]
fn classify_maps_every_wait_status() {
    let pid = Pid::from_raw(STUB);
    assert_eq!(classify(WaitStatus::Exited(pid, 4)), Event::Exited(pid, 4));
    assert_eq!(
        classify(WaitStatus::Signaled(pid, Signal::SIGKILL, true)),
        Event::Killed(pid, Signal::SIGKILL)
    );
    assert_eq!(
        classify(WaitStatus::PtraceEvent(
            pid,
            Signal::SIGTRAP,
            PTRACE_EVENT_SECCOMP
        )),
        Event::Trap(pid)
    );
    assert_eq!(
        classify(WaitStatus::PtraceEvent(
            pid,
            Signal::SIGTRAP,
            PTRACE_EVENT_EXEC
        )),
        Event::PtraceStop(pid)
    );
    assert_eq!(
        classify(WaitStatus::PtraceSyscall(pid)),
        Event::PtraceStop(pid)
    );
    assert_eq!(
        classify(WaitStatus::Stopped(pid, Signal::SIGCHLD)),
        Event::SignalStop(pid, Signal::SIGCHLD)
    );
    assert_eq!(classify(WaitStatus::Continued(pid)), Event::Ignored);
    assert_eq!(classify(WaitStatus::StillAlive), Event::Ignored);
}
