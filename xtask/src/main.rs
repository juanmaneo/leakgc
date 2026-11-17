//! Project automation for `leakgc`, run as `cargo xtask <command>`.
//!
//! - `coverage`: runs the workspace tests under cargo-llvm-cov and fails
//!   unless every file in `src/` reports 100% functions, lines and regions.
//! - `lint`: rustfmt check plus clippy with warnings denied.
//!
//! `xtask` is excluded from the coverage gate: its job is to spawn
//! cargo-llvm-cov, so gating it would mean running the gate inside itself.
//! Unsafe code is forbidden for every workspace member via `[workspace.lints]`.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const REPORT: &str = "target/llvm-cov/coverage.json";

fn main() -> ExitCode {
    let outcome = match std::env::args().nth(1).as_deref() {
        Some("coverage") => coverage(),
        Some("lint") => lint(),
        _ => {
            eprintln!("usage: cargo xtask <coverage|lint>");
            return ExitCode::from(2);
        }
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("xtask: {message}");
            ExitCode::FAILURE
        }
    }
}

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives one level below the workspace root")
}

fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .current_dir(root())
        .status()
        .map_err(|e| format!("failed to start `{program}`: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`{program} {}` failed ({status})", args.join(" ")))
    }
}

fn lint() -> Result<(), String> {
    run("cargo", &["fmt", "--all", "--check"])?;
    run(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )
}

fn coverage() -> Result<(), String> {
    fs::create_dir_all(root().join("target/llvm-cov")).map_err(|e| e.to_string())?;
    run(
        "cargo",
        &[
            "llvm-cov",
            "--workspace",
            "--exclude",
            "xtask",
            "--json",
            "--summary-only",
            "--output-path",
            REPORT,
        ],
    )?;

    let text = fs::read_to_string(root().join(REPORT))
        .map_err(|e| format!("cannot read {REPORT}: {e}"))?;
    let report: Value =
        serde_json::from_str(&text).map_err(|e| format!("cannot parse {REPORT}: {e}"))?;
    let expected = rust_sources(&root().join("src"))?;
    let problems = check_report(&report, root(), &expected);

    if problems.is_empty() {
        println!(
            "coverage: all {} source files at 100% functions, lines and regions",
            expected.len()
        );
        Ok(())
    } else {
        Err(format!("coverage below 100%:\n  {}", problems.join("\n  ")))
    }
}

fn rust_sources(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut found = Vec::new();
    let entries = fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() {
            found.extend(rust_sources(&path)?);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
    found.sort();
    Ok(found)
}

/// Returns one message per violation; an empty list means the gate passes.
fn check_report(report: &Value, root: &Path, expected: &[PathBuf]) -> Vec<String> {
    let Some(files) = report["data"][0]["files"].as_array() else {
        return vec!["coverage report has no `data[0].files` array".to_string()];
    };

    let mut problems = Vec::new();
    let mut seen = Vec::new();
    for file in files {
        let path = PathBuf::from(file["filename"].as_str().unwrap_or_default());
        let display = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        for metric in ["functions", "lines", "regions"] {
            let count = file["summary"][metric]["count"].as_u64().unwrap_or(0);
            let covered = file["summary"][metric]["covered"].as_u64().unwrap_or(0);
            if covered != count {
                problems.push(format!("{display}: {metric} {covered}/{count} covered"));
            }
        }
        seen.push(path);
    }

    for path in expected {
        if !seen.contains(path) {
            let display = path.strip_prefix(root).unwrap_or(path).display();
            problems.push(format!("{display}: missing from coverage report"));
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry(filename: &str, covered: u64, count: u64) -> Value {
        let metric = json!({ "count": count, "covered": covered });
        json!({
            "filename": filename,
            "summary": { "functions": metric.clone(), "lines": metric.clone(), "regions": metric },
        })
    }

    fn report(files: Vec<Value>) -> Value {
        json!({ "data": [{ "files": files }] })
    }

    #[test]
    fn accepts_fully_covered_expected_files() {
        let root = Path::new("/repo");
        let report = report(vec![entry("/repo/src/main.rs", 10, 10)]);
        let expected = [root.join("src/main.rs")];
        assert!(check_report(&report, root, &expected).is_empty());
    }

    #[test]
    fn flags_partially_covered_file_per_metric() {
        let root = Path::new("/repo");
        let problems = check_report(&report(vec![entry("/repo/src/main.rs", 9, 10)]), root, &[]);
        assert_eq!(
            problems,
            [
                "src/main.rs: functions 9/10 covered",
                "src/main.rs: lines 9/10 covered",
                "src/main.rs: regions 9/10 covered",
            ]
        );
    }

    #[test]
    fn flags_expected_file_missing_from_report() {
        let root = Path::new("/repo");
        let problems = check_report(&report(vec![]), root, &[root.join("src/lib.rs")]);
        assert_eq!(problems, ["src/lib.rs: missing from coverage report"]);
    }

    #[test]
    fn rejects_report_without_files_array() {
        let problems = check_report(&json!({}), Path::new("/repo"), &[]);
        assert_eq!(problems, ["coverage report has no `data[0].files` array"]);
    }

    #[test]
    fn finds_rust_sources_recursively() {
        let sources = rust_sources(&root().join("src")).expect("read src");
        assert!(sources.iter().any(|path| path.ends_with("main.rs")));
    }
}
