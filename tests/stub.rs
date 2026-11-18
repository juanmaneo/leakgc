//! Only the failure paths that return before the stub stops itself. A valid
//! program would raise SIGSTOP in this test process, so that path is covered
//! through the binary in `supervisor_real.rs` and `launcher.rs`.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;

use win_games_leak_garbage_collector::stub::run_stub;

#[test]
fn no_arguments_is_a_usage_error() {
    assert_eq!(run_stub(&[]), 2);
}

#[test]
fn nul_byte_in_an_argument_is_a_usage_error() {
    let arg = OsString::from_vec(b"a\0b".to_vec());
    assert_eq!(run_stub(&[arg]), 2);
}
