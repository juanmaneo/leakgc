# Handover: `leakgc` — Runtime Leak-Freeing GC (OCaml core + Rust launcher)

## Purpose of this document

Briefing for an AI model (or human) taking over this project mid-stream. It contains full context, verified current state, architecture decisions, and the next phase of work. Everything below reflects the **actual, tested state** of the code as of this handover — not plans.

## Project origin & intent

The user reminisced about running leaky old Windows games under Wine + Valgrind: leaks never escaped the process because the kernel reclaims all memory at exit — "containment by design." From this grew the idea: replicate Valgrind-style leak accounting but **free the memory at runtime**, before exit, with a mark-and-sweep GC modeled on OCaml's major GC.

The end goal is a launcher binary used like valgrind:

```
leakgc wine game.exe
```

**Critical constraint:** the user is rewriting a binary-compatible Rust port of Wine (WIP: https://github.com/juanmaneo/MustumProtonusFerrous). Wine must be **interchangeable** — real wine or their Rust port. Therefore interposition must sit **below wine at the libc allocator level**, never inside wine.

## Non-goals (do not drift)

- Not replacing OCaml's real GC.
- Not instrumenting wine itself.
- Not a debugger. Valgrind-style launcher + allocator interposition only.

## Locked architecture decisions (do not silently change)

1. **GC core in OCaml** (`ocaml/leakcheck.ml`), single file, stdlib only. Rust is for the launcher binary and future crates; a C-export bridge from the OCaml core comes later only if needed.
2. **Shadow-heap model**: allocations go through `alloc ?(refs=[]) ~site size`, registering each block in a `Hashtbl` with id, size, site string, refs, `marked`, `freed`. Sites are manual strings (the simulator's stand-in for Valgrind stack traces).
3. **Explicit roots** via `add_root` / `remove_root`. Documented, accepted limitation vs. a real GC's automatic stack/register scanning.
4. **Iterative tri-color mark** (worklist, gray→black) — safe for deep and cyclic graphs. Cycles are explicitly demoed and collected.
5. **Sweep with two modes**: `~free_leaks:true` frees unreachable blocks (runtime containment); `false` reports only. Reports are Valgrind-style, grouped by site, sorted by wasted bytes descending.
6. **Pacing**: a collection triggers automatically every `collect_every = 64` allocations inside `alloc`. Known simplification vs. OCaml's word-based amortized slices.
7. **Plain OCaml, no dune**: run with `ocaml ocaml/leakcheck.ml` or `ocamlopt ocaml/leakcheck.ml -o leakcheck`. OCaml 5.5.0, Rust 1.100.0.
8. **Launcher model**: `leakgc <command> [args...]` spawns the command as a child and propagates its exit code. Wine is just an argument — interchangeable by construction.

## Current state (verified this session)

Workspace layout:

```
Cargo.toml            — package win-games-leak-garbage-collector, edition 2024,
                        [[bin]] name = "leakgc", path = "src/main.rs"
src/main.rs           — leakgc launcher: arg passthrough spawn, exit-code
                        propagation (127 on spawn failure, 2 on usage error)
ocaml/leakcheck.ml    — the GC core + demo (see below)
```

`ocaml/verify_scratch.ml` was a temporary test file; it passed and was **deleted** per plan. Its two tests (pacing regression; 5000-step randomized stress with invariant checks every 250 steps) are described in "Regression testing" below so they can be recreated.

### leakcheck.ml structure (in file order — this order matters)

1. `type block`, heap/roots/counters globals, `log` (respects `verbose`).
2. **Mark phase**: `mark_from` (recursive worklist) + `mark` (seeds from roots).
3. **Sweep phase**: `leak_report` record; `sweep ~free_leaks` gathers lost blocks *before* mutating the Hashtbl (mutating during `H.iter` is unspecified), resets marks, groups by site, computes `retained_bytes` via `H.fold` over the live table (immune to cumulative-counter drift).
4. `print_report` — Valgrind-style summary.
5. `collect ?(free_leaks = true) ?(report = !verbose) ()` — mark, sweep, optionally print.
6. **Allocation API**: `alloc`, `add_root`/`remove_root`, `connect` (dedupes edges), `disconnect`.
7. `demo ()` — three scenarios (clean, cyclic garbage, "old Windows game" texture leak), then `let () = demo ()`.

**Structural note baked into the file**: mark/sweep/collect are defined *before* `alloc` because `alloc` triggers collections. OCaml top-level bindings are sequential — a later `collect` definition would NOT rebind `alloc`'s reference. Plain reordering suffices; no `let rec` needed (nothing in mark/sweep/collect calls alloc).

### The pacing bug — fixed and verified this session

**Bug (now fixed):** in `alloc`, the pacing check ran *after* the new block was registered. Nothing roots the fresh block yet, so the 64th alloc's collection swept the very block being returned → `alloc` returned an already-freed id.

**Fix:** the pacing check now runs **before** block registration; the refs filter stays after the trigger so pointees freed by the collection are dropped. Comment in the file explains this.

**Test lesson learned:** the original Test 1 checked only the 100th alloc's id — but pacing fires at 64 and 128, so the 100th alloc never coincided with a trigger and the test passed spuriously. The fixed test checks **every** returned id over 200 allocs (guaranteeing ≥2 triggers fire) and also asserts the trigger actually fired. When writing regression tests for pacing, iterate over *all* returned ids, not just the last.

### Verified outputs

`ocaml ocaml/leakcheck.ml` produces exactly:

- Scenario 1 (clean): "no leaks are possible", retained 4608 bytes.
- Scenario 2 (3-node cycle, unrooted): definitely lost 3 blocks / 192 bytes at `build_node:41`.
- Scenario 3 (4× 64KB textures, never rooted/freed): definitely lost 4 blocks / 262144 bytes at `load_level_textures:210`.
- Final line: `done: 3 collections, 266944 bytes total allocated`.

`cargo build` succeeds; `./target/debug/leakgc ocaml ocaml/leakcheck.ml` runs the demo through the launcher and propagates exit 0.

## Regression testing (recreate as needed)

Two tests were run by concatenating `cat ocaml/leakcheck.ml ocaml/verify_scratch.ml > /tmp/lk_verify.ml && ocaml /tmp/lk_verify.ml`, then the scratch file was deleted:

1. **Pacing regression**: 200 allocs of 16 bytes at `pacing_test`; after each alloc assert `H.mem heap id`; assert `!collections > 0`. With `verbose := false` first.
2. **Randomized stress**: 5000 steps, weighted ops — 40% alloc+retain (root it if no live block exists, else `connect` from a random live block), 15% connect, 10% disconnect, 10% remove_root, 25% garbage alloc (never rooted). Every 250 steps, `check_collect`: compute the reachable set from roots, then assert `collect ~free_leaks:true ~report:false` loses exactly the unreachable blocks/bytes, `retained_bytes` matches live bytes, no reachable block was swept, heap == reachable set afterward, no stale `marked`/`freed` flags, no dangling edges. Expected result: "stress OK: ~77 collections, 2 blocks live".

Note: the scratch `fail` was `Printf.eprintf`-style, which emits Warning 20 for extra args — harmless warnings, exit 1 on failure is what matters.

## Next phase (in order)

1. **LD_PRELOAD shim (C)**: interpose `malloc`/`free`/`calloc`/`realloc` in the child process. Emit alloc/free events (size, pointer, ideally a site hint) to leakgc over a pipe/unix socket. This is the piece that makes the whole thing work on real programs — and it sits at libc level, below either wine, which is what keeps wine interchangeable. Note: Rust's `System` allocator also routes through malloc, so the Rust wine port is covered too.
2. **OCaml core via C ABI**: expose `alloc`/`connect`/`disconnect`/`add_root`/`remove_root`/`collect` as C symbols from a compiled OCaml archive (`ocamlopt` + `-ccopt`/cclib flags; no dune). leakgc links it and translates shim events into core calls.
3. **Root discovery**: conservative stack/register scan of the child (ptrace, valgrind-style) so roots aren't manual. This is the hardest part; until then, roots can be approximated (e.g., treat all allocations as rooted = report-only mode, or scan the child's writable segments for pointer-sized values).
4. **CLI/config for leakgc**: report-only vs. free-leaks mode, `collect_every` tuning, verbose toggle.

### Design footgun to surface to the user (do not silently change)

Auto-collect with `free_leaks:true` can sweep blocks the caller hasn't rooted yet — inherent to the manual-roots design. A **report-only auto-sweep** (free only on explicit collect) is the recommended default once real programs are in the loop; freeing live data in a game would crash it.

## Pitfalls (learned the hard way)

- `=!` lexes as one infix token — `?(x=!)` is a syntax error; write `?(x = !y)`.
- OCaml top-level bindings are sequential; later definitions do not rebind earlier references. Reorder instead of `let rec ... and ...` when nothing actually recurses.
- Mutating a `Hashtbl` during `H.iter` is unspecified — gather first, mutate after (sweep already does this).
- The demo only does 9 allocations; the 64-alloc pacing path is only exercised by the stress test.
- Run dependent terminal calls **sequentially** — a parallel check once read stale file content before an edit landed.
- Avoid shell substitutions (`$?`, `$(...)`) in terminal tool commands.
- `write_file` can't write outside the project; use terminal + `/tmp` for scratch, or write in-project and delete.

## User preferences (communication)

Enjoys systems metaphors (Wine/Valgrind/kernel-reaping anecdotes, old Windows games, OCaml GC internals) and **honest caveats over reassurance**. Keep explanations grounded in real-runtime comparisons (Valgrind leak kinds like "definitely lost / still reachable", tri-color marking, GC pacing) rather than generic filler. Concise, direct, friendly tone. Flag design tradeoffs explicitly instead of quietly picking one.
