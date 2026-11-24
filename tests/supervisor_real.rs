//! Supervision of real processes through the `leakgc` binary. Each run has a
//! deadline, so a supervision hang fails the test instead of stalling it.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(60);

fn target_dir() -> &'static Path {
    Path::new(env!("CARGO_TARGET_TMPDIR"))
}

/// Compiles `tests/fixtures/<source>` into the target temp directory.
fn build_c(source: &str, flags: &[&str]) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(source);
    let out = target_dir().join(source.trim_end_matches(".c"));
    let status = Command::new("cc")
        .arg(&src)
        .arg("-o")
        .arg(&out)
        .args(flags)
        .status()
        .expect("run cc");
    assert!(status.success(), "cc failed for {source}");
    out
}

fn run_leakgc(args: &[&str], env: &[(&str, &str)]) -> (ExitStatus, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_leakgc"))
        .args(args)
        .envs(env.iter().copied())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn leakgc");
    let mut stderr = child.stderr.take().expect("stderr is piped");
    let reader = thread::spawn(move || {
        let mut text = String::new();
        stderr
            .read_to_string(&mut text)
            .expect("read leakgc stderr");
        text
    });

    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll leakgc") {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill hung leakgc");
            child.wait().expect("reap hung leakgc");
            panic!("leakgc did not finish within {TIMEOUT:?}");
        }
        thread::sleep(Duration::from_millis(10));
    };
    (status, reader.join().expect("stderr reader"))
}

#[test]
fn static_binary_runs_to_completion_with_its_calls_traced() {
    let hello = build_c("hello.c", &["-static"]);
    let path = hello.to_str().expect("UTF-8 path");
    let (status, log) = run_leakgc(&[path], &[("LEAKGC_LOG", "1")]);

    assert_eq!(status.code(), Some(0), "log:\n{log}");
    assert!(log.contains("trap execve"), "log:\n{log}");
    assert!(log.contains("trap brk"), "log:\n{log}");
}

#[test]
fn threaded_dynamic_binary_runs_to_completion_without_hanging() {
    let threads = build_c("threads.c", &["-pthread"]);
    let path = threads.to_str().expect("UTF-8 path");
    let (status, log) = run_leakgc(&[path], &[("LEAKGC_LOG", "1")]);

    assert_eq!(status.code(), Some(0), "log:\n{log}");
    assert!(log.contains("trap mmap"), "log:\n{log}");
    assert!(log.contains("trap clone3"), "log:\n{log}");
}

#[test]
fn static_binary_reports_its_outstanding_blocks_by_caller() {
    let hooks = build_c("hooks_static.c", &["-static", "-no-pie"]);
    let path = hooks.to_str().expect("UTF-8 path");
    let (status, log) = run_leakgc(&[path], &[("LEAKGC_LOG", "1")]);

    assert_eq!(status.code(), Some(0), "log:\n{log}");
    assert!(
        log.contains("hooked malloc, free and realloc"),
        "log:\n{log}"
    );
    assert!(log.contains("1 blocks, 200 bytes"), "log:\n{log}");
    assert!(log.contains("1 blocks, 40000 bytes"), "log:\n{log}");
    assert!(log.contains("exit code 0"), "log:\n{log}");
    assert!(!log.contains("not covered"), "log:\n{log}");
    assert!(!log.contains("unknown frees"), "log:\n{log}");
}

/// The 333-byte block is the only one nothing points to when the trapped
/// `mmap` runs. `local` and `kept` still hold the other two. The fixture is
/// built at -O0 so that `local` stays in main's frame. glibc's startup blocks
/// that only RELRO data points to are also reported, because read-only memory
/// is not scanned (PLAN section 9). They are not asserted here.
#[test]
fn static_binary_reports_only_the_block_nothing_points_to() {
    let reach = build_c(
        "reach_static.c",
        &["-static", "-no-pie", "-O0", "-fno-builtin"],
    );
    let path = reach.to_str().expect("UTF-8 path");
    let (status, log) = run_leakgc(&[path], &[("LEAKGC_LOG", "1")]);

    assert_eq!(status.code(), Some(0), "log:\n{log}");
    assert!(log.contains("unreachable at the last check"), "log:\n{log}");
    let unreachable: Vec<&str> = log
        .lines()
        .filter(|line| line.contains("unreachable caller"))
        .collect();
    assert!(
        unreachable
            .iter()
            .any(|line| line.ends_with("1 blocks, 333 bytes")),
        "log:\n{log}"
    );
    assert!(
        unreachable
            .iter()
            .all(|line| !line.ends_with("777 bytes") && !line.ends_with("555 bytes")),
        "log:\n{log}"
    );
}

#[test]
fn background_jobs_are_waited_for() {
    let (status, _) = run_leakgc(&["sh", "-c", "sleep 0.1 & wait"], &[]);

    assert_eq!(status.code(), Some(0));
}

#[test]
fn orphaned_descendants_finish_before_leakgc_returns() {
    let mark = target_dir().join("drain-mark");
    let _ = fs::remove_file(&mark);
    let script = format!("(sleep 0.3; touch '{}') & exit 0", mark.display());
    let (status, log) = run_leakgc(&["sh", "-c", &script], &[]);

    assert_eq!(status.code(), Some(0), "log:\n{log}");
    assert!(mark.exists(), "leakgc returned before the orphaned job ran");
}
