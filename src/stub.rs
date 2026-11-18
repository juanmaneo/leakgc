//! The stub is the first program the supervisor starts. It installs the trap
//! filter, stops itself so the supervisor can attach, and then replaces itself
//! with the target. The filter survives `execve`, so the target stays trapped.

use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStrExt;

use nix::sys::signal::{Signal, raise};
use nix::unistd::execvp;
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch, apply_filter};

use crate::trap::TRAPPED;

/// Runs the stub with `args` (the target's command line). Returns only on
/// failure, with the exit code to report.
pub fn run_stub(args: &[OsString]) -> i32 {
    let Some(program) = args.first() else {
        eprintln!("usage: leakgc __stub <command> [args...]");
        return 2;
    };
    let Ok(argv) = args
        .iter()
        .map(|arg| CString::new(arg.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
    else {
        eprintln!("leakgc: an argument contains a NUL byte");
        return 2;
    };

    // Everything that allocates happens before the filter is installed. The
    // supervisor is not attached yet, so a trapped call here would fail.
    let rules = TRAPPED.iter().map(|&(nr, _)| (nr, Vec::new())).collect();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Trace(0),
        TargetArch::x86_64,
    )
    .expect("the trap filter is well formed");
    let bpf = BpfProgram::try_from(filter).expect("the trap filter compiles");
    apply_filter(&bpf).expect("the trap filter installs");

    // Stopped until the supervisor seizes this process and sends SIGCONT.
    raise(Signal::SIGSTOP).expect("the stub can stop itself");

    let Err(error) = execvp(&argv[0], &argv);
    eprintln!("leakgc: failed to spawn {program:?}: {error}");
    127
}
