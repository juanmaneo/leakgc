//! The only test in this file. It waits on any child with `waitpid(-1)`, so
//! keeping it alone means no other test's wait can reap the stub first.

use std::path::{Path, PathBuf};
use std::process::Command;

use goblin::elf::Elf;
use leakgc::install::{HEAD_OFFSET, RECORDS_OFFSET, install_hooks};
use leakgc::ring::{CAPACITY, Kind, RECORD_LEN, Slot, decode, plan_drain};
use leakgc::supervisor::{OsTracer, Tracer};
use nix::errno::Errno;
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;

fn build_fixture() -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hooks_static.c");
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("install_real_hooks_static");
    let status = Command::new("cc")
        .arg(&src)
        .args(["-static", "-no-pie", "-o"])
        .arg(&out)
        .status()
        .expect("run cc");
    assert!(status.success(), "cc failed for the hooks fixture");
    out
}

/// The address and size of a function or object symbol.
fn symbol(image: &[u8], name: &str) -> (u64, u64) {
    let elf = Elf::parse(image).expect("fixture parses");
    let sym = elf
        .syms
        .iter()
        .find(|sym| elf.strtab.get_at(sym.st_name) == Some(name))
        .expect("symbol present");
    (sym.st_value, sym.st_size)
}

/// Starts the stub from the `leakgc` binary, because `current_exe` here would
/// be the test harness. The child is reaped through `waitpid(-1)` in the test.
fn spawn_stub(fixture: &Path) -> std::io::Result<Pid> {
    let child = Command::new(env!("CARGO_BIN_EXE_leakgc"))
        .arg("__stub")
        .arg(fixture)
        .spawn()?;
    Ok(Pid::from_raw(
        i32::try_from(child.id()).expect("pids fit in i32"),
    ))
}

fn read_u64(os: &mut OsTracer, pid: Pid, addr: u64) -> u64 {
    let bytes = os.read_mem(pid, addr, 8).expect("read a word");
    u64::from_le_bytes(bytes.try_into().expect("8 bytes"))
}

#[test]
fn the_hooks_record_each_call_from_main_and_not_the_calls_inside_them() {
    let fixture = build_fixture();
    let image = std::fs::read(&fixture).expect("read the fixture");
    let (main, main_len) = symbol(&image, "main");
    let (keep, _) = symbol(&image, "keep");

    let stub = spawn_stub(&fixture).expect("spawn the stub");

    let mut os = OsTracer;
    assert_eq!(
        os.wait_stopped(stub),
        Ok(WaitStatus::Stopped(stub, Signal::SIGSTOP))
    );
    os.seize(stub).expect("seize the stub");
    os.send_signal(stub, Signal::SIGCONT)
        .expect("resume the stub");

    let mut base = None;
    let mut records_checked = false;
    let mut exit_code = None;
    loop {
        match os.wait_any() {
            Err(Errno::ECHILD) => break,
            Err(error) => panic!("wait failed: {error}"),
            Ok(WaitStatus::PtraceEvent(pid, _, libc::PTRACE_EVENT_EXEC)) => {
                let installed = install_hooks(&mut os, pid, &mut Vec::new())
                    .unwrap_or_else(|error| panic!("install failed: {error:?}"));
                base = Some(installed.base);
                os.cont(pid, None).expect("resume after install");
            }
            Ok(WaitStatus::Stopped(pid, Signal::SIGSTOP)) => {
                let base = base.expect("the hooks are installed before main raises SIGSTOP");
                let head = read_u64(&mut os, pid, base + HEAD_OFFSET);
                let drain = plan_drain(0, head);
                assert_eq!(drain.lost, 0, "no record was overwritten");

                let mut records = Vec::new();
                for i in drain.first..drain.first + drain.count {
                    let at = base + RECORDS_OFFSET + (i % CAPACITY) * RECORD_LEN as u64;
                    let bytes: [u8; RECORD_LEN] = os
                        .read_mem(pid, at, RECORD_LEN)
                        .expect("read a record")
                        .try_into()
                        .expect("a record is 64 bytes");
                    match decode(&bytes) {
                        Some(Slot::Done(record)) => records.push(record),
                        other => panic!("record {i} is not a finished record: {other:?}"),
                    }
                }

                // Static glibc calls malloc before main, so the run starts at main's first call.
                let in_main = |caller: u64| (main..main + main_len).contains(&caller);
                let first = records
                    .iter()
                    .position(|r| in_main(r.caller))
                    .expect("main made calls");
                let from_main = &records[first..];
                assert_eq!(
                    from_main.len(),
                    5,
                    "realloc's own malloc and free are not recorded: {from_main:?}"
                );
                assert!(
                    from_main.iter().all(|r| in_main(r.caller)),
                    "every call after main's first is from main: {from_main:?}"
                );

                let kinds: Vec<Kind> = from_main.iter().map(|r| r.kind).collect();
                assert_eq!(
                    kinds,
                    vec![
                        Kind::Malloc,
                        Kind::Malloc,
                        Kind::Realloc,
                        Kind::Realloc,
                        Kind::Free
                    ]
                );
                let sizes: Vec<u64> = from_main.iter().map(|r| r.size).collect();
                assert_eq!(sizes, vec![16, 100, 200, 40000, 0]);
                let args: Vec<u64> = from_main.iter().map(|r| r.arg).collect();
                assert_eq!(args[0], 0);
                assert_eq!(args[1], 0);
                assert_eq!(
                    args[2], from_main[1].result,
                    "realloc took the malloc(100) block"
                );
                assert_eq!(args[3], 0, "realloc(NULL, n) takes no block");
                assert_eq!(
                    args[4], from_main[0].result,
                    "free took the malloc(16) block"
                );

                let kept: Vec<u64> = (0..2)
                    .map(|i| read_u64(&mut os, pid, keep + 8 * i))
                    .collect();
                assert_eq!(
                    kept,
                    vec![from_main[2].result, from_main[3].result],
                    "each record holds the pointer main kept"
                );
                records_checked = true;
                os.cont(pid, None).expect("resume after the records");
            }
            Ok(WaitStatus::Exited(_, code)) => exit_code = Some(code),
            Ok(status) => {
                let pid = match status {
                    WaitStatus::PtraceEvent(pid, _, _)
                    | WaitStatus::PtraceSyscall(pid)
                    | WaitStatus::Stopped(pid, _) => pid,
                    other => panic!("unexpected wait status {other:?}"),
                };
                os.cont(pid, None).expect("resume a stop");
            }
        }
    }

    assert!(records_checked, "main reached its SIGSTOP");
    assert_eq!(exit_code, Some(0));
}
