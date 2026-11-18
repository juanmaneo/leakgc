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

The shipped binary is built from the following crates. The list comes from `cargo tree --locked -p win-games-leak-garbage-collector --edges normal` and `cargo metadata` on the current `Cargo.lock`.

| Crate | Version | License | Kind |
|---|---|---|---|
| libc | 0.2.191 | MIT OR Apache-2.0 | runtime |
| nix | 0.31.4 | MIT | runtime |
| seccompiler | 0.5.0 | Apache-2.0 OR BSD-3-Clause | runtime |
| bitflags | 2.13.2 | MIT OR Apache-2.0 | runtime, via nix |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 | runtime, via nix |
| iced-x86 | 1.22.0 | MIT | runtime (decoder, encoder, block_encoder features only) |
| lazy_static | 1.5.1 | MIT OR Apache-2.0 | runtime, via iced-x86 |
| cfg_aliases | 0.2.2 | MIT | build-time, via nix |

The `[dependencies]` table in `Cargo.toml` names `libc`, `nix` (with `process`, `signal` and `ptrace` features only), `seccompiler` and `iced-x86` (with `decoder`, `encoder` and `block_encoder` features only). The crates from the earlier planned list that are not used (goblin, scroll, plain, log) are not in the lock file. `proc-macro2`, `quote` and `syn` are in the lock file, but only through `xtask`, so they are not shipped.

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
