# Acknowledgements

`leakgc` is released under the MIT License (see `LICENSE`). This file credits the projects whose ideas, code, or tests the project relies on, and records the license of each third-party crate. Licenses were checked with `cargo metadata` on the current `Cargo.lock` and on the spike lock files.

## Ideas

No code from these projects is copied.

- **Valgrind** (memcheck). The leak taxonomy (definitely lost, indirectly lost, possibly lost, still reachable) and the report style. Valgrind is GPL, so its code is not used.
- **Boehm-Demers-Weiser conservative garbage collector.** The conservative-root model: a word that looks like a pointer keeps a block alive.
- **OCaml runtime.** The tri-color mark-and-sweep reference. The OCaml prototype in `ocaml/leakcheck.ml` is original code for this project, and it is the test oracle for the Rust core.
- **Blink** (jart/blink, ISC). The structure of a user-space monitor that passes most calls through and intercepts a selected set. `leakgc` does not interpret instructions, and no Blink code is used.

Investigated and not used: **Cosmopolitan Libc** (ISC). It does not intercept syscalls from foreign code, so neither its design nor its code is taken.

## Shipped code

`leakgc` has no runtime dependencies today. The `[dependencies]` table in `Cargo.toml` is empty.

## Planned runtime dependencies (license checked, added in P2 if used)

Only the crates P2 actually uses will stay. This table is a license check, not a commitment.

| Crate | Version | License |
|---|---|---|
| nix | 0.31.2 | MIT |
| libc | 0.2.189 | MIT OR Apache-2.0 |
| seccompiler | 0.5.0 | Apache-2.0 OR BSD-3-Clause |
| iced-x86 | 1.22.0 | MIT |
| goblin | 0.10.7 | MIT |
| bitflags | 2.13.2 | MIT OR Apache-2.0 |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 |
| cfg_aliases | 0.2.2 | MIT |
| scroll | 0.13.0 | MIT |
| scroll_derive | 0.13.2 | MIT (build-time, proc macro) |
| plain | 0.2.3 | MIT/Apache-2.0 |
| log | 0.4.35 | MIT OR Apache-2.0 |
| lazy_static | 1.5.1 | MIT OR Apache-2.0 |
| proc-macro2, quote, syn | 1.0.107, 1.0.47, 3.0.10 | MIT OR Apache-2.0 (build-time, proc macros) |

## Development tools (not shipped)

`xtask` uses `serde_json` and its dependencies: `serde`, `serde_core`, `serde_derive` (MIT OR Apache-2.0), `itoa` (MIT OR Apache-2.0), `memchr` (Unlicense OR MIT), `zmij` (MIT), `proc-macro2`, `quote`, `syn` (MIT OR Apache-2.0), and `unicode-ident` ((MIT OR Apache-2.0) AND Unicode-3.0).

`unicode-ident` ships Unicode data under the Unicode License v3 (SPDX `Unicode-3.0`). That license requires its copyright and permission notice to stay with any redistributed copy of the crate. This repository does not vendor it, so no notice is included here. If the crate is ever vendored or redistributed, its notice must be kept with it.

`cargo-llvm-cov`, used by `cargo xtask coverage`, is installed separately and is not part of this repository.

## Test targets (not distributed)

The spikes and the planned P3 test matrix run programs against these allocators and runtimes. This repository does not vendor or distribute any of them.

- glibc and musl (C libraries)
- mimalloc, jemalloc, gperftools tcmalloc, oneTBB (tbbmalloc and its malloc proxy)
- Scudo and LeakSanitizer (LLVM compiler-rt)
- Boehm gc
- relibc (test only, D13)
- Wine (the real build and the user's Rust port) and firejail (the sandbox wrapper from D15). They are run under test and are not distributed.
