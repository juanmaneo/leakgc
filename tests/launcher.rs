//! End-to-end tests for the `leakgc` launcher. They run the real binary, so
//! they also cover `main` and every exit path.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::process::Command;

fn leakgc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_leakgc"))
}

#[test]
fn no_arguments_prints_usage_and_exits_2() {
    let output = leakgc().output().expect("run leakgc");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage: leakgc"));
}

#[test]
fn propagates_child_exit_code() {
    let status = leakgc()
        .args(["sh", "-c", "exit 23"])
        .status()
        .expect("run leakgc");
    assert_eq!(status.code(), Some(23));
}

#[test]
fn reports_signal_termination_as_128_plus_signal() {
    let status = leakgc()
        .args(["sh", "-c", "kill -TERM $$"])
        .status()
        .expect("run leakgc");
    assert_eq!(status.code(), Some(128 + 15));
}

#[test]
fn missing_program_exits_127() {
    let output = leakgc()
        .arg("/nonexistent/leakgc-test-program")
        .output()
        .expect("run leakgc");
    assert_eq!(output.status.code(), Some(127));
    assert!(String::from_utf8_lossy(&output.stderr).contains("failed to spawn"));
}

#[test]
fn passes_non_utf8_arguments_unchanged() {
    let raw = OsStr::from_bytes(b"x\xff");
    let status = leakgc()
        .args(["sh", "-c", r#"test "$1" = "$(printf 'x\377')""#, "sh"])
        .arg(raw)
        .status()
        .expect("run leakgc");
    assert!(status.success());
}
