//! relibc programs (PLAN D74, beta). relibc is Redox OS's C library, written in
//! Rust. Its sysroot is built from a pinned revision in the relibc test image,
//! so these tests need the `relibc` feature and the sysroot named by
//! `LEAKGC_RELIBC_SYSROOT`. A plain `cargo test` does not build them. Run them
//! with `scripts/libc-tests.sh relibc`, which builds that image and runs them
//! with `--ignored`.

mod common;

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::run_leakgc;

fn target_dir() -> &'static Path {
    Path::new(env!("CARGO_TARGET_TMPDIR"))
}

/// The sysroot from `make install`. Without it the tests cannot run, so a
/// missing variable fails the test rather than skipping it.
fn sysroot() -> PathBuf {
    PathBuf::from(
        env::var_os("LEAKGC_RELIBC_SYSROOT")
            .expect("LEAKGC_RELIBC_SYSROOT must name the relibc sysroot (see Dockerfile.libc)"),
    )
}

/// Compiles `tests/fixtures/<source>` statically against relibc's headers and
/// `libc.a`, as relibc's own tests link. The host C library is not used.
fn build_relibc(source: &str, out_name: &str) -> PathBuf {
    let sys = sysroot();
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(source);
    let out = target_dir().join(out_name);
    let status = Command::new("cc")
        .args(["-static", "-nostdinc", "-nostdlib"])
        .arg("-isystem")
        .arg(sys.join("include"))
        .arg(sys.join("lib/crt0.o"))
        .arg(sys.join("lib/crti.o"))
        .arg(sys.join("lib/crtn.o"))
        .arg(&src)
        .arg(sys.join("lib/libc.a"))
        .arg("-o")
        .arg(&out)
        .status()
        .expect("run cc");
    assert!(status.success(), "cc failed for {source}");
    out
}

/// relibc has every allocator entry except `malloc_trim`, so the others are
/// hooked and their blocks are reported by caller. Nothing is freed: relibc's
/// allocator has no glibc-style internal names, so injection is off (R37).
#[test]
#[ignore = "needs the relibc sysroot; run by scripts/libc-tests.sh relibc"]
fn relibc_hooks_its_allocator_and_reports_its_blocks() {
    let exe = build_relibc("hooks_static.c", "relibc_hooks");
    let path = exe.to_str().expect("UTF-8 path");
    let (status, log) = run_leakgc(&[path], &[("LEAKGC_LOG", "1")]);

    assert_eq!(status.code(), Some(0), "log:\n{log}");
    assert!(
        log.contains(
            "hooked malloc, free, realloc, calloc, memalign, aligned_alloc, valloc, \
             pvalloc, posix_memalign;"
        ),
        "log:\n{log}"
    );
    assert!(log.contains("malloc_trim is not found"), "log:\n{log}");
    assert!(log.contains("1 blocks, 200 bytes"), "log:\n{log}");
    assert!(log.contains("1 blocks, 40000 bytes"), "log:\n{log}");
    assert!(
        log.contains("no block is freed by injection"),
        "log:\n{log}"
    );
    assert!(!log.contains("not covered"), "log:\n{log}");
}

/// relibc's `realloc` starts with `push rbx` and then calls the platform
/// realloc. The hook relocates that direct call (D88), so the growing block is
/// moved and copied many times. The program checks its own contents after each
/// move. It runs alone first, so a failure under leakgc is not a fixture bug.
#[test]
#[ignore = "needs the relibc sysroot; run by scripts/libc-tests.sh relibc"]
fn relibc_realloc_that_moves_keeps_the_contents_under_leakgc() {
    let exe = build_relibc("relibc_realloc_moves.c", "relibc_realloc_moves");
    let path = exe.to_str().expect("UTF-8 path");

    let plain = Command::new(path)
        .env_clear()
        .status()
        .expect("run the program alone");
    assert_eq!(plain.code(), Some(0), "the program fails without leakgc");

    let (status, log) = run_leakgc(&[path], &[("LEAKGC_LOG", "1")]);

    assert_eq!(status.code(), Some(0), "log:\n{log}");
    assert!(log.contains("hooked malloc, free, realloc,"), "log:\n{log}");
    assert!(!log.contains("not covered"), "log:\n{log}");
}
