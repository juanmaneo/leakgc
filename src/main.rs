//! leakgc: a Valgrind-style leak launcher. `leakgc wine game.exe` runs the
//! command under supervision. The supervisor traces the memory system calls
//! and passes everything else through to the real kernel. Wine is an argument,
//! not a dependency, so the real Wine and the Rust port both work.
//!
//! The supervisor starts the target through a stub (`leakgc __stub ...`) that
//! installs the trap filter before the target runs. See PLAN.md.

use std::ffi::OsString;

use win_games_leak_garbage_collector::{stub, supervisor};

fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let code = match args.split_first() {
        None => {
            eprintln!("usage: leakgc <command> [args...]");
            eprintln!("example: leakgc wine game.exe");
            2
        }
        Some((first, rest)) if first == "__stub" => stub::run_stub(rest),
        Some(_) => supervisor::supervise(&args),
    };
    std::process::exit(code);
}
