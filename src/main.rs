//! leakgc — Valgrind-style launcher: `leakgc wine game.exe`
//!
//! Spawns the given command as a child process and propagates its exit
//! code. The child is expected to be an interchangeable wine (real wine
//! or the Rust port, MustumProtonusFerrous) — leakgc sits *outside* the
//! wine process, so either works.
//!
//! Later phases will interpose the child's allocator (LD_PRELOAD shim)
//! and stream allocation events into the OCaml mark-and-sweep core, so
//! leaks get freed at runtime instead of merely being contained until
//! process exit.

use std::ffi::OsString;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus};

fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| status.signal().map_or(1, |signal| 128 + signal))
}

fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: leakgc <command> [args...]");
        eprintln!("example: leakgc wine game.exe");
        std::process::exit(2);
    }

    let (program, rest) = args.split_first().expect("args checked non-empty");

    let status = Command::new(program)
        .args(rest)
        .status()
        .unwrap_or_else(|e| {
            eprintln!("leakgc: failed to spawn {program:?}: {e}");
            std::process::exit(127); // conventional "command not found"
        });

    // Preserve ordinary exit codes and use the shell convention for a child
    // terminated by a signal (128 + signal), so wrappers can inspect status.
    std::process::exit(exit_code(status));
}
