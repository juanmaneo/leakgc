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

use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
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
            eprintln!("leakgc: failed to spawn {program}: {e}");
            std::process::exit(127); // conventional "command not found"
        });

    // Propagate the child's exit code so scripts can rely on it, exactly
    // like valgrind does for the supervised program.
    std::process::exit(status.code().unwrap_or(1));
}
