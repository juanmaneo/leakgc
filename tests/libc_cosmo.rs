//! Cosmopolitan Libc programs (PLAN D72). `cosmocc` is installed only in the
//! cosmo test image, so these tests are ignored by a plain `cargo test`. Run
//! them with `scripts/libc-tests.sh cosmo`, which builds that image and runs
//! them with `--ignored`.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::run_leakgc;

fn target_dir() -> &'static Path {
    Path::new(env!("CARGO_TARGET_TMPDIR"))
}

/// Compiles `tests/fixtures/<source>` with `cosmocc` at -O0, as the other
/// real-process tests do. Returns the APE file and the unstripped ELF beside
/// it (`<out>.com.dbg`). Each test gives its own output name, so tests never
/// write the same file.
fn build_cosmo(source: &str, out_name: &str) -> (PathBuf, PathBuf) {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(source);
    let out = target_dir().join(out_name);
    let status = Command::new("cosmocc")
        .arg("-O0")
        .arg(&src)
        .arg("-o")
        .arg(&out)
        .status()
        .expect("run cosmocc");
    assert!(status.success(), "cosmocc failed for {source}");
    let elf = PathBuf::from(format!("{}.com.dbg", out.display()));
    (out, elf)
}

/// The unstripped ELF keeps its symbols, so the allocator entries are hooked and
/// the blocks are reported by caller. Nothing is freed: cosmo's allocator has
/// no glibc-style internal names, so injection is off (R37).
#[test]
#[ignore = "needs the cosmo image; run by scripts/libc-tests.sh cosmo"]
fn cosmo_elf_hooks_its_allocator_and_reports_its_blocks() {
    let (_, elf) = build_cosmo("hooks_static.c", "cosmo_hooks");
    let path = elf.to_str().expect("UTF-8 path");
    let (status, log) = run_leakgc(&[path], &[("LEAKGC_LOG", "1")]);

    assert_eq!(status.code(), Some(0), "log:\n{log}");
    assert!(log.contains("hooked malloc, free, realloc;"), "log:\n{log}");
    assert!(log.contains("1 blocks, 200 bytes"), "log:\n{log}");
    assert!(log.contains("1 blocks, 40000 bytes"), "log:\n{log}");
    assert!(log.contains("exit code 0"), "log:\n{log}");
    assert!(
        log.contains("no block is freed by injection"),
        "log:\n{log}"
    );
    assert!(!log.contains("not covered"), "log:\n{log}");
    assert!(!log.contains("unknown frees"), "log:\n{log}");
    assert!(!log.contains("R40"), "log:\n{log}");
}

/// The APE file is what ships. `sh` runs it, and the program inside is extracted
/// as a stripped ELF with no symbols to hook. Hooks need symbols (D7), so the
/// report says the program is not covered.
#[test]
#[ignore = "needs the cosmo image; run by scripts/libc-tests.sh cosmo"]
fn cosmo_ape_run_through_sh_is_reported_as_not_covered() {
    let (ape, _) = build_cosmo("hooks_static.c", "cosmo_hooks_ape");
    let path = ape.to_str().expect("UTF-8 path");
    // The APE loader writes its extracted helper under HOME, or into the working
    // directory when HOME is unset. The run has no environment, so point HOME
    // at the test temp directory to keep the repository clean.
    let home = target_dir().join("cosmo-ape-home");
    fs::create_dir_all(&home).expect("create the loader's home");
    let home = home.to_str().expect("UTF-8 path");
    let (status, log) = run_leakgc(
        &["sh", path],
        &[("LEAKGC_LOG", "1"), ("HOME", home), ("TMPDIR", home)],
    );

    assert_eq!(status.code(), Some(0), "log:\n{log}");
    assert!(
        log.contains("not hooked: malloc is not found as a function"),
        "log:\n{log}"
    );
    assert!(
        log.contains("not covered: no allocator entry can be hooked"),
        "log:\n{log}"
    );
}
