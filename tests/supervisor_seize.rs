//! The only test in this file. It spawns a stub in this process and kills it
//! with `waitpid(pid)`, so keeping it alone means no other test's wait can
//! reap it first.

use std::ffi::OsString;
use std::io;
use std::process::Command;

use leakgc::supervisor::{OsTracer, Tracer, supervise_with};
use nix::errno::Errno;
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;

/// The real operating system, except that seizing the stub is refused. The
/// stub is started from the `leakgc` binary, because `current_exe` here would
/// be the test harness.
struct RefuseSeize {
    os: OsTracer,
    stub: Option<Pid>,
}

impl Tracer for RefuseSeize {
    fn spawn_stub(&mut self, args: &[OsString]) -> io::Result<Pid> {
        let child = Command::new(env!("CARGO_BIN_EXE_leakgc"))
            .arg("__stub")
            .args(args)
            .spawn()?;
        let pid = Pid::from_raw(i32::try_from(child.id()).expect("pids fit in i32"));
        self.stub = Some(pid);
        Ok(pid)
    }

    fn wait_stopped(&mut self, pid: Pid) -> nix::Result<WaitStatus> {
        self.os.wait_stopped(pid)
    }

    fn wait_any(&mut self) -> nix::Result<WaitStatus> {
        self.os.wait_any()
    }

    fn seize(&mut self, _pid: Pid) -> nix::Result<()> {
        Err(Errno::EPERM)
    }

    fn cont(&mut self, pid: Pid, sig: Option<Signal>) -> nix::Result<()> {
        self.os.cont(pid, sig)
    }

    fn syscall(&mut self, pid: Pid) -> nix::Result<()> {
        self.os.syscall(pid)
    }

    fn send_signal(&mut self, pid: Pid, sig: Signal) -> nix::Result<()> {
        self.os.send_signal(pid, sig)
    }

    fn syscall_nr(&mut self, pid: Pid) -> nix::Result<i64> {
        self.os.syscall_nr(pid)
    }

    fn read_maps(&mut self, pid: Pid) -> io::Result<String> {
        self.os.read_maps(pid)
    }

    fn exe_image(&mut self, pid: Pid) -> io::Result<Vec<u8>> {
        self.os.exe_image(pid)
    }

    fn file_image(&mut self, path: &str) -> io::Result<(u64, Vec<u8>)> {
        self.os.file_image(path)
    }

    fn regs(&mut self, pid: Pid) -> nix::Result<libc::user_regs_struct> {
        self.os.regs(pid)
    }

    fn set_regs(&mut self, pid: Pid, regs: libc::user_regs_struct) -> nix::Result<()> {
        self.os.set_regs(pid, regs)
    }

    fn step(&mut self, pid: Pid) -> nix::Result<()> {
        self.os.step(pid)
    }

    fn is_single_step_trap(&mut self, pid: Pid) -> nix::Result<bool> {
        self.os.is_single_step_trap(pid)
    }

    fn event_message(&mut self, pid: Pid) -> nix::Result<i64> {
        self.os.event_message(pid)
    }

    fn read_mem(&mut self, pid: Pid, addr: u64, len: usize) -> io::Result<Vec<u8>> {
        self.os.read_mem(pid, addr, len)
    }

    fn write_mem(&mut self, pid: Pid, addr: u64, bytes: &[u8]) -> io::Result<()> {
        self.os.write_mem(pid, addr, bytes)
    }
}

#[test]
fn refused_seize_kills_the_stopped_stub_and_reports_1() {
    let mut tracer = RefuseSeize {
        os: OsTracer,
        stub: None,
    };
    let args = [OsString::from("true")];
    let code = supervise_with(&mut tracer, &args, None);

    assert_eq!(code, 1);
    let stub = tracer.stub.expect("the stub was spawned");
    assert_eq!(
        waitpid(stub, None),
        Ok(WaitStatus::Signaled(stub, Signal::SIGKILL, false))
    );
}
