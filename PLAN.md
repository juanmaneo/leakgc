# leakgc: architecture plan (v3, proposal)

Status: **PLAN v3. Product: P1 (GC core) is done; nothing else is implemented yet.** Spikes P0-b (section 7a) and P0-c (section 7b) are done. Open items are in section 9.
Supersedes the architecture sections of `HANDOVER.md` (left untouched).
No push. Each phase is its own commit, gated by `cargo xtask lint` and `cargo xtask coverage`.
Spikes live in `spikes/` (git-excluded, throwaway, not covered by the gate).

## 1. What changed from HANDOVER.md (and from v1)

| Area | Old (HANDOVER) | v3 (this plan) |
|---|---|---|
| Interposition | LD_PRELOAD / libc malloc | Dropped. Works for static binaries and for allocators that bypass the dynamic linker. |
| Launcher role | Spawns child | Process supervisor. Owns the child tree's memory syscalls and allocator entry points, and passes everything else through to the kernel. |
| Where the supervisor runs | Not considered | **Inside the Wine sandbox** when Wine is firejail-wrapped (D15). Verified: an outside supervisor cannot trace a firejail sandbox. |
| Object boundaries | Manual `alloc` calls | Observed from allocator entry points (malloc family), per family. |
| Roots | Manual `add_root` | Conservative: registers, stacks, writable memory (Boehm / Valgrind "still reachable" style). |
| Default behaviour | Auto-free | Report-only. Freeing is opt-in and needs a safe point. |
| Rust | Safe launcher | `#![forbid(unsafe_code)]` in all our crates. Verified in the spike. Dependencies do contain unsafe (section 8, R7). |
| Process lifecycle | Not considered | Supervisor drains every tracee before exiting, and always resumes or kills the stub on error (4.4). Learned from spike failures. |

Honest scope note: "like a VM" here means the supervisor owns the child's memory syscalls and allocator entry points, and reports on them. It is **not** a hardware VM and it is **not** an emulator. The child runs on the real Linux kernel, with the real GPU, at near-native speed. If you need literal VM semantics, that is option E1 (D17).

## 2. Research findings (verified vs. not verified)

- **Cosmopolitan Libc** (ISC): **verified, and the answer is no.** Its README and its strace implementation (`--strace` / `--ftrace`, in `libc/intrin/strace*` and the `sys_*` wrappers) only log calls made by Cosmopolitan's own runtime. It does not intercept syscalls from foreign code, so it cannot be used for Wine, games, or prebuilt binaries. Its APE format runs natively on several OSes, which is a different feature. I know you expected it to be the mechanism. It is not.
- **Blink** (`jart/blink`, ISC): **verified from its README.** A user-mode x86-64 interpreter. It runs static and dynamic Linux ELF. Every `SYSCALL` goes through the emulator (`-s` logs them). It is the only existing "VM that sees every instruction and memory access". Costs: no GPU, Linux 4.5 personality, 500+ instructions and 150+ syscalls implemented, C, and no hook for allocation boundaries (it would need a patched fork). See D17.
- **Wine's `ntdll.dll`** exports `RtlAllocateHeap`, `RtlFreeHeap`, `RtlReAllocateHeap`, `RtlSizeHeap` (checked earlier with `x86_64-w64-mingw32-objdump -p`). The Win32 heap can be identified by name. Hooking it is D1.
- **relibc** (MIT, Rust): **verified in P0-b.** It builds as a static libc. The malloc family is exported unprefixed and survives into the static binary. It is a test target only (D13). It pins `nightly-2026-05-24`.
- **Installed allocators (verified on this machine, symbols checked with `nm -D --defined-only`).** gperftools 2.18.1 (four tcmalloc variants, same exports), oneTBB 2.19 (`libtbbmalloc` exports `scalable_*` only, `libtbbmalloc_proxy` overrides the malloc family), jemalloc 5.4.0, mimalloc 3.5 (`mi_*` plus malloc overrides), musl 1.2.6 (`/usr/lib/musl/lib/libc.so`), Boehm `gc` 8.2.12 (`GC_malloc`, does not override malloc), and LLVM compiler-rt 23 with Scudo standalone (overrides malloc) and LeakSanitizer (`.a` only). `talloc` (Samba's pool library) and `libionic` (owned by `rdma-core`) are not allocator families and are excluded.
- **Valgrind** is still the ground truth. memcheck reports 64 bytes definitely lost on the dynamic build of a test program, and "no leaks are possible" on the static build of the same program. That silent miss is the failure mode this design must never repeat.
- **Environment (verified):** Linux, `ptrace_scope=1`. LSMs active: `capability, landlock, lockdown, yama, bpf` (no AppArmor). firejail 0.9.80 is what `/usr/local/bin/wine` is (a symlink). It picks `/etc/firejail/wine.profile` by program name. That profile sets `allow-debuggers`, `noroot`, `nonewprivs`, `caps.drop all`, `seccomp`, `restrict-namespaces`.

## 3. Execution engine options

| Option | Static binaries | Allocator-agnostic | Sees every memory access | GPU works | Speed | Notes |
|---|---|---|---|---|---|---|
| **E1** Emulator (Blink-style) | yes | yes, with adapters | yes | no | roughly 10x or worse | The only literal "VM". Good oracle for hard cases. C dependency. |
| **E2** Supervisor (seccomp TRACE + ptrace + int3 probes) | yes | yes, with adapters | at memory syscalls and probes only | yes | near native (about 27 µs per trap, see 7a) | Former recommendation, now the fallback (D17). Verified end to end. Not a VM, and I want to be clear about that. |
| **E3** Hardware VM (KVM guest with Linux and Wine) | yes | yes, with adapters | yes (EPT / introspection) | no (unless passthrough) | near native CPU | Heavy: needs a guest image. Hard GPU story. |
| **E4** Rust monitor, native execution, allocation hooks and memory-syscall trap. No instruction interpretation (Blink-style structure only). | yes | yes, for identified allocators, same limits as E2 | at allocator entry points and memory syscalls only | yes | near native, about 35 ns per hooked call (7b) | Chosen by the user (D17). Validated for single-threaded static glibc in P0-c (7b). Threads, dynamic and stripped binaries are not validated yet. |

**Status (D17): E4 chosen by the user, validated for the single-threaded static case (P0-c).** E2 remains the fallback if a remaining gate fails (threads, dynamic linking, or self-checking code, see 7b).

## 4. Recommended architecture (E4)

```mermaid
flowchart TD
    U[leakgc wine game.exe] --> F[firejail with wine.profile]
    F --> S[leakgc monitor, inside the sandbox]
    S -->|spawns stub, seizes it at exec-stop| T[target process, running natively]
    S -->|injects mmap, writes entry and exit trampolines| T
    T -->|malloc hooks append records to a ring| R[ring in target memory]
    T -->|memory syscalls trap via seccomp| S
    T -->|everything else runs natively| K[Linux kernel]
    S -->|stop the world at collection, read ring| G[shadow heap, mark, report]
```

If Wine is not sandboxed, the `firejail` box is simply removed. The supervisor then runs at the top level.

### 4.1 Components

1. **Stub and launch (verified).** The supervisor spawns `leakgc __stub <target> [args]`. The stub builds the seccomp filter (all CStrings and argv are built before the filter is installed), calls `apply_filter`, raises `SIGSTOP`, and then `execv`s the target. The supervisor waits for the stub's group-stop (polling `/proc/<pid>/stat` for state `T`), then calls `PTRACE_SEIZE` with `TRACESECCOMP | TRACEEXEC | TRACECLONE | TRACEFORK | TRACEVFORK | EXITKILL`, and then `SIGCONT`. We do **not** use `PTRACE_TRACEME` (it would have the tracer be the child, and it makes the exec-trace logic harder). Filters survive `execve`.
2. **Syscall filter.** The spike traps `mmap` only, using `SECCOMP_RET_TRACE`. The P2 plan is to add `munmap`, `mremap`, `mprotect`, `madvise`, `brk`, `clone`, `clone3`, and `execve`. Each addition is measured in P2 against the cost in 7a. Everything not on the list runs natively at full speed.
3. **Memory map.** `/proc/<pid>/maps` gives the writable regions (the spike reads it and counts `rw` mappings). File-backed `MAP_SHARED`, device (`/dev/dri`, `/dev/nvidia*`) and SysV shm mappings are excluded from the heap and from scanning (R3).
4. **Hooks (E4).** At exec-stop, the monitor injects an `mmap` into the target (RWX, within 2 GB of the allocator) and writes an entry trampoline and an exit stub there. It replaces the first 5 bytes of each hooked allocator entry point (after `endbr64`) with a `jmp rel32` to the entry trampoline. Displaced instructions are re-encoded at the trampoline address with iced-x86 (4.6). The entry trampoline saves the caller's return address in a pending table keyed by the caller's rsp, and replaces it with the exit stub's address. The exit stub writes the returned pointer into the ring record and jumps back. The target never stops per call. Measured: about 35 ns per hooked call (7b). The E2 int3 probes from P0-b (7a) remain only as a per-family fallback (4.6). Their lessons still apply: glibc's `free` tail-jumps to its own entry, so a free hook must dedupe re-entries by (rsp, return address) or it over-counts. Pre-main allocations are real (7a), so hooks must be in place before `main`.
5. **Shadow heap.** Built only from ring records: `(family, returned address, requested size, call site)`. The usable size comes from the family's adapter, not from the record. An interval map, so interior pointers resolve to the containing block. It does not read allocator internals. The map logic is allocator-agnostic. The hooks are not: each family still needs its entry points (item 9).
6. **Stop the world.** `PTRACE_INTERRUPT` (or `SIGSTOP`) on every thread, then `PTRACE_GETREGS`. Ring records are read only in this state, so the reader never races a writer. Open: a thread stopped between its `lock xadd` and its record store leaves one slot unwritten. Records need a validity marker written last. The spike's 32-byte record has a spare `pad` field that could hold it (not validated, R22).
7. **Roots and mark.** Conservative roots: all registers of all threads, all thread stacks, all other writable mappings, excluding known-free blocks. Every word inside a live block's `[start, start+usable)` marks it (interior pointers count). Iterative tri-color worklist, as in the OCaml prototype.
8. **Sweep.** Unmarked live blocks are candidates. Report mode prints a Valgrind-style summary grouped by call site (the site is the hook's return address, symbolised when possible). Free mode calls the family's `free` inside the child at a safe point (4.3).
9. **Allocator adapters.** A family is a table of symbol names plus a usable-size function. Discovery reads `.dynsym` and `.symtab` of every loaded ELF object. Stripped static binaries have no names, so they are detected but not supported until a signature mode exists (later phase). A recognised family whose entry points cannot be resolved is **fail-closed**: its blocks are never freed.
10. **Install point.** Verified for static non-PIE glibc at exec-stop (7b). Hooks must be installed again after every `execve`, because a new image has no hooks. Dynamic and PIE binaries map libc later, so they need a second install point after the library's executable mapping appears. Not built. This is the first task of P3.
11. **Ring and pending table.** The ring is 2^20 records of 32 bytes in target memory, with the head advanced by `lock xadd`. The pending table is keyed by the caller's rsp. In the spike it is global and unsynchronised, so the design is valid only for single-threaded targets until R16 is solved. Ring overflow is R21.

### 4.2 Why this shape

- Works for static binaries, because it hooks the process directly and does not depend on the dynamic linker. Verified for static non-PIE glibc (7b).
- Works for Wine and for the Rust port, because it sits below both, at the allocator and syscall boundary. Wine is an argument, not a dependency.
- Keeps our code safe. Ptrace, seccomp and `/proc` are reached through crates (`nix`, `seccompiler`), and displaced-instruction relocation goes through `iced-x86`. Our code contains no `unsafe` (verified). The crates do contain unsafe (R7).
- Near native, with no per-call stop. A hooked `malloc` costs about 35 ns (7b). An E2 seccomp trap costs about 27 µs (7a). E2 int3 probes were never timed on their own, and each needs at least two stops per call (entry and return), so the comparison is an estimate.

### 4.3 Safe point and free injection

A block may only be freed when:

1. Its family is supported, and its entry points resolved.
2. It is unmarked after a full scan (no word in any root points into it, interior pointers included).
3. **No thread is inside a hooked call.** The pending table shows it: we saw the entry and have not yet seen the exit. If any thread has a pending entry, the collection is skipped and retried.
4. The freeing happens by injecting a call to the family's `free` into one stopped thread: save registers, set up a scratch return address on a page we own, call, restore. This is the gdb "inferior call" technique.

Residual risk: a thread can hold an allocator lock inside a function we did not hook. See R1.

### 4.4 Process lifecycle rules (learned from the P0-b spike)

These are requirements, not suggestions. Each one came from a failure we actually hit.

1. **Drain before exit.** Keep servicing ptrace events until `waitpid` returns `ECHILD`, even after the root has exited. Wine leaves `wineserver` running. If the supervisor returns early, its tracees either get `ENOMEM` from `ld.so` (no `EXITKILL`, the trap has no tracer and returns an error) or are killed by `EXITKILL`, which made the whole sandbox report exit 137 on a successful run.
2. **Never leave a stub stopped.** If the supervisor fails after the stub self-stops, the stub stays in group-stop forever. In the spike this hung the firejail monitor waiting on it. Every error path must `SIGCONT` the stub, or `SIGKILL` it. This is a `Drop` guard in P2.
3. **Exit code.** The root's exit code (or `128+sig`) is the exit code of `leakgc`, and it is reported only after the drain completes.
4. **Fail-closed on supervisor death.** `EXITKILL` ensures the traced tree dies with the supervisor. Without a tracer, a trapped `mmap` returns `ENOSYS`, so the program sees an allocation failure rather than silently running untracked. This is the mmap trap window: keep the code between `apply_filter` and the stop free of allocation (verified: the window is only the `raise`).

### 4.5 Wrapper placement (D15)

The real `wine` is a firejail sandbox, and that changes where the supervisor has to run.

- A supervisor **outside** the sandbox cannot seize a process inside it. Verified: `PTRACE_SEIZE` returns EPERM, with yama descendant checks satisfied. Strong inference (not proven in kernel source): firejail puts the sandbox in a child user namespace (`uid_map` is `1001 1001 1`), and Linux refuses a cross-namespace ptrace unless the tracer has `CAP_SYS_PTRACE` in the child's namespace. `strace` fails the same way.
- A stub that installs seccomp **and then** runs firejail fails. `seccompiler` sets `NO_NEW_PRIVS`, and firejail's setuid exec then fails with a lockfile error (verified earlier).
- A supervisor **inside** the sandbox works. Verified: the spike, run inside `firejail --profile=/etc/firejail/wine.profile`, seizes its own stub and runs real Wine (hello and `cmd`) to exit 0, with output intact.
- A plain firejail (no profile) blocks `ptrace` with EPERM in its default seccomp filter. `wine.profile` allows it with `allow-debuggers`. The profile must keep that line.

So the launch becomes: `leakgc wine game.exe` → (configured wrapper) `firejail --profile=/etc/firejail/wine.profile leakgc __supervise wine game.exe`. The wrapper is configuration (D15), and `leakgc` must know it.

### 4.6 Hook mechanics and fallback

Install sequence (static non-PIE, verified in 7b):

1. Stop at exec-stop. Burn one `PTRACE_SINGLESTEP` before any injected syscall. Without it the injected `syscall` silently does not run (`rip` unchanged, `rax` 0).
2. Inject `mmap` (RWX, hint near the allocator, so a `jmp rel32` can reach the trampoline).
3. Write the entry trampoline, the exit stub, the ring and the pending table through `/proc/<pid>/mem`.
4. Write the 5-byte patch last. No thread may execute a half-written trampoline.

Refusal rules. Each rule refuses one entry point, which then stays fail-closed (its blocks are never freed):

- Another branch in the function targets a byte inside the 5 patched bytes (R19).
- An instruction in the displaced bytes cannot be decoded, or cannot be relocated correctly.
- The displaced instructions do not cover 5 whole bytes, so the patch would split an instruction or overlap the next function.

Decoding: the monitor decodes instruction lengths and the operands needed to relocate the displaced instructions. It executes nothing and does not interpret what the instructions do. This is the answer to open question (3) in D17.

Free hooks: glibc's `free` tail-jumps to its own entry, so a free hook must dedupe re-entries by (rsp, return address). `realloc`, `calloc` and `memalign` each need their own analysis before they are hooked. Until then their frees, or their allocations, are not seen. A block whose free is not seen looks live and is never freed, so the report must say the family is only partly covered.

Fallback per family: if the hooks cannot be installed, the family uses the E2 int3 probes (7a), or it is reported as not covered.

Process tree (design, not tested): a forked child inherits the hooks and the ring mapping, copy-on-write. Each process is its own tracee. The monitor resets the child's ring head and pending table at its fork-stop, and reads each process's ring separately. Threads share one ring and need per-thread pending state (R16).

### 4.7 What E4 removes compared with E2

- The per-call stops for allocator calls. The target keeps running between hooks.
- The ptrace round trip for each call. The ring is read at collection time only.

What E4 adds: code patching (R17, R18, R19), instruction relocation, and new races (threads, install points, re-install after `execve` and fork).

Unchanged: memory syscalls still trap through seccomp (D16, D18).

## 5. Roots and what counts as "reachable"

- Reachable = marked by a conservative scan. A word that merely looks like a pointer keeps a block alive. This is the **safe** direction: false retention means a leak goes unreported. A false free means a crash, so we never take that risk silently.
- **Unknown allocators** (a region of writable memory that no family owns) are treated as roots. Blocks they point to are reported as "still reachable", not "definitely lost". Nothing inside an unknown region is ever freed.
- Report categories follow Valgrind: definitely lost, indirectly lost, possibly lost, still reachable, and "not covered" (bytes under an unsupported allocator).

## 6. Allocator coverage plan

| Family | Entry points | Test link modes |
|---|---|---|
| glibc | `malloc`, `free`, `calloc`, `realloc`, `memalign`, `posix_memalign`, `aligned_alloc`, `malloc_usable_size`, plus `__libc_*` variants | dynamic, static (with symbols), static stripped |
| mimalloc (installed, v3.5.4) | `mi_malloc`, `mi_free`, `mi_realloc`, `mi_calloc`, `mi_usable_size`, plus unprefixed overrides in `libmimalloc.so.3` | dynamic (`/usr/lib/libmimalloc.so.3`), static (source build, see 7a) |
| jemalloc (installed) | unprefixed `malloc` family, `malloc_usable_size`, `mallctl` (not used for tracking) | dynamic, static |
| gperftools tcmalloc 2.18.1 (installed): `libtcmalloc.so.4.6.5`, `libtcmalloc_minimal.so.4.6.5`, `libtcmalloc_debug.so.4.6.5`, `libtcmalloc_and_profiler.so.4.7.5` | `malloc` family (unprefixed), `tc_malloc`, `tc_malloc_size` for usable size. All four export the same set. | dynamic, one test row per variant (each is a separate build, so each is tested) |
| oneTBB tbbmalloc 2.19 (installed): `libtbbmalloc.so.2.19` | `scalable_malloc`, `scalable_calloc`, `scalable_realloc`, `scalable_free`, `scalable_posix_memalign`, `scalable_msize` for usable size. Not a malloc override. | dynamic, linked directly |
| oneTBB malloc proxy (installed): `libtbbmalloc_proxy.so.2.19` | `malloc` family (unprefixed), as a malloc override | dynamic, preloaded by the test program |
| Scudo standalone (LLVM compiler-rt 23, installed): `libclang_rt.scudo_standalone-x86_64.so` | `malloc` family (unprefixed), `malloc_usable_size` | dynamic. Static `.a` exists but is not verified. Hardened, so a good stress target. |
| Boehm GC `gc` 8.2.12 (installed): `libgc.so.1.5.6` | `GC_malloc`, `GC_free`, `GC_init`. Does not override malloc. | **Covered, report-only (D19).** Boehm frees its own unreachable memory, so leakgc never frees its blocks. Reports for Boehm-managed blocks are labelled as such. |
| LeakSanitizer (LLVM compiler-rt 23, installed): `libclang_rt.lsan-x86_64.a` | Not an allocator. Exit-time leak checker. | **Oracle only**, for ASan-built test programs. It has the same blind spot as Valgrind for objects still reachable at exit. |
| musl 1.2.6 (installed, `/usr/lib/musl/lib/libc.so`) | `malloc`, `free`, `calloc`, `realloc`, `memalign`, `posix_memalign`, `aligned_alloc`, `malloc_usable_size` (verified with `nm -D`) | dynamic. Static not yet checked. |
| relibc (Rust libc, dlmalloc-rs) | `malloc`, `free`, `calloc`, `realloc`, `memalign` family from `libc.a` (verified in P0-b) | static only, built from source with the pinned nightly. **TEST ONLY (D13).** Never a production family. |
| Unknown / custom | none (fail-closed) | any; must show as "not covered" |

Test matrix: each allocator x each link mode x each test program. Each row is checked against Valgrind on the dynamic builds (ground truth). The static builds are checked against the leak count written into the test program, because Valgrind is blind there.

Note for static glibc: small allocations use `brk`, not `mmap`. A syscall-only view would see none of them. Object boundaries must come from entry-point hooks (E4) or probes (E2). Verified in P0-b for relibc, in the probe table in 7a for glibc and mimalloc, and in 7b for E4 hooks on static glibc.

## 7. Phases (each its own commit, no push)

- **P0-a (this document).** Done in v2. No LICENSE or acknowledgements, as requested.
- **P0-c: E4 mechanism spike (throwaway, not committed).** **Done.** Results in 7b. PASS for single-threaded static non-PIE glibc.
- **P0-b: feasibility spikes (throwaway, not committed).** **Done.** Results in 7a. Spikes covered: stub and seccomp trace (safe Rust), int3 probes (glibc, mimalloc, relibc), `/proc/<pid>/maps`, firejail behaviour (both placements), Wine syscall rate.
- **P1: GC core in Rust. Done** (commits `23e4b77` to `951b685`). Port of `ocaml/leakcheck.ml` semantics: block model, tri-color mark, sweep, Valgrind-style report, pacing, stress tests, and a demo transcript that matches the OCaml oracle byte for byte. Gates pass: `cargo xtask lint`, and `cargo xtask coverage` at 100% for all 9 source files. Known gaps before P2: pacing in `alloc` frees by default, which conflicts with D4, so it must be gated by mode. `Block.freed` is set on a block that is dropped right after, which is harmless but should go.
- **P2a: supervisor and memory-syscall trap. Done** (commit `f45e32f`). Stub, seccomp TRACE on mmap, munmap, mremap, brk, clone, clone3 and execve, drain rules (4.4), `Drop` guard, root exit code. Results in 7c, decisions in D22 to D27. Pacing gated by mode (D4) was done earlier, in `be27f23`.
- **P2b: E4 hooks for static non-PIE single-threaded glibc only (4.6).** Split into three commits, as the user approved: P2b-1, the pure planner and ring (done in `27abae5`, see 7d); P2b-2, the install sequence through the `Tracer` trait (done in `253746d`, see 7e); P2b-3, the ring read and report for glibc malloc and free, with multi-threaded targets refused (not started, waiting for the user's go-ahead). The original P2 scope below is the starting point. Some of its items are already covered by P2a tests. Multi-threaded targets are refused for hooks and reported as not covered (D5). Logs memory syscalls. Tests: static and dynamic hello-world (the dynamic one runs and is reported as not covered until the second install point exists), multi-threaded (refused, must not hang), fork, a leftover daemon, supervisor error injected after stub stop (must not hang), seccomp TRACE combined with hooks (7b item 5), ring wrap (7b item 6). Runs inside the wrapper when one is configured (D15).
- **P3: allocator adapters and hooks (E4), report only.** First task: the dynamic and PIE install point (4.1 item 10), because most real programs are dynamic. Then per-thread pending state (R16) before any multi-threaded family is hooked, and the free, realloc, calloc and memalign analysis from 4.6. Then identification of stripped static binaries (D7), which needs its own spike before it is committed to. glibc first, then mimalloc, then jemalloc, tcmalloc and relibc. Test matrix from section 6. relibc is a compatibility check: its static test programs must report the same leak counts as the other static builds, and any mismatch is a finding to investigate, not a reason to skip it.
- **P4: conservative roots and report.** Stop the world, register and stack scanning, mark, Valgrind-style report. Known-leak test programs with expected output.
- **P5: free injection.** Safe-point logic, pending-call tracking, injected `free`, quarantine mode (delay frees by one cycle and poison the block, so a wrong free shows up as a clear failure rather than silent corruption). Opt-in `--free`.
- **P6: Wine integration.** Real Wine first (`/usr/lib/wine`, through the wrapper from D15). The Rust port when it is available. The Win32 heap is handled according to D1.
- **P7: CLI and config.** `--report` (default) / `--free`, wrapper configuration, time-based pacing (replaces `collect_every = 64`), verbosity, pid filter.
- **P8: LICENSE and ACKNOWLEDGEMENTS. Done.** MIT (D12) in `LICENSE`, and `ACKNOWLEDGEMENTS.md` from a `cargo metadata` audit of the current lock file and the spike lock files. At P8 the shipped binary had no runtime dependencies. P2a added `libc`, `nix` and `seccompiler`, P2b-1 added `iced-x86`, and P2b-2 added `goblin` and its dependencies (see `ACKNOWLEDGEMENTS.md`).

Gate for every phase: `cargo xtask lint`, `cargo xtask coverage` (files, lines, regions, functions at 100% for `src/**`), and the phase's tests.

## 7a. P0-b results (verified, throwaway spikes in `spikes/`, excluded from git)

### Seccomp stub and tracing (`spikes/seccomp_spike`, safe Rust, `#![forbid(unsafe_code)]`)

| Run | Result |
|---|---|
| Direct, `glibc_dyn` | exit 0, 8 mmap stops, output unchanged (native and traced both silent) |
| Direct, `sh -c 'echo; exit 3'` (fork, exec, exit code) | output intact, exit 3, 36 stops, 3 tracees |
| Direct, `glibc_static` | exit 0, **0 mmap stops** (small allocations use `brk`, which is not trapped yet) |
| Direct, `mi_static` / `mi_dyn` | exit 0, 3 / 16 mmap stops |
| Direct, Wine hello, warm wineserver | exit 0, about 280 mmap stops, 3 tracees |
| Direct, Wine `cmd /c echo` | output intact, exit 0, **4562 stops**. Timed: 351 ms native vs 475 ms traced (debug build, about 27 µs per trap). |
| Outside supervisor, firejail (any profile) | `PTRACE_SEIZE` EPERM on the sandboxed stub (section 4.5) |
| Inside supervisor, plain firejail | EPERM from the firejail default seccomp, which blocks `ptrace` |
| **Inside supervisor, `wine.profile`, `glibc_dyn`** | exit 0, 8 stops, output intact |
| **Inside supervisor, `wine.profile`, Wine hello** (2 runs) | exit 0 both times, about 12.4k stops, 89 to 90 tracees. A fresh wineserver starts every run inside the sandbox, so this is a cold-start cost. |
| **Inside supervisor, `wine.profile`, Wine `cmd`** | output intact, exit 0, 15.3k stops |
| User's real `/usr/local/bin/wine`, no spike | exit 0 for hello and `cmd` (baseline) |

Lifecycle bugs the spike hit and the fixes (now rules in 4.4): an early-returning supervisor produced `ENOMEM` in a surviving daemon (no `EXITKILL`) or exit 137 (with `EXITKILL`). A panic after the stub self-stopped left it stopped, and firejail hung waiting on it. The fix was to keep draining until `ECHILD`.

Cost of the trap: about 27 µs per mmap stop in a debug build (measured on `cmd`). The release build is not measured yet. Wine cold start under the sandbox: about 12.4k traps, so about 0.33 s of trap overhead, before any allocation work.

### R7 audit (unsafe in dependencies, from the spike's `Cargo.lock`)

- Our code: 0 `unsafe` (`#![forbid(unsafe_code)]`).
- `libc` 0.2.189: FFI declarations and helpers, in many files.
- `nix` 0.31.2: syscall wrappers, in most files.
- `seccompiler` 0.5.0: 2 real `unsafe` blocks in `apply_filter` (`prctl(NO_NEW_PRIVS)` and the seccomp syscall). The rest are in its tests.
- `bitflags` 2.13.2: a few. `cfg-if`, `cfg_aliases`: none.

Counts are approximate (grep, which includes comments). "Rust must be safe" holds for our code. It does not hold transitively, because `nix` and `libc` are FFI layers by design. This is the decision in D3 and R7.

### Probes (glibc and mimalloc, from the earlier P0-b run, `spikes/probe3`)

| Binary | malloc | free | reentries | Notes |
|---|---|---|---|---|
| `glibc_static` | 9 | 3 | 1 | 6 mallocs are glibc startup |
| `glibc_dyn` + libc.so.6 | 3 | 1 | 1 | free tail-jumps to its own entry |
| `mi_dyn` + `/usr/lib/libmimalloc.so.3` | 3 | 1 | 0 | calls resolve to mi_malloc / mi_free |
| `mi_static` (mimalloc v3.5.4 source build, malloc override) | 9 | 3 | 0 | static startup mallocs go through mimalloc |

Mimalloc static: the installed `/usr/lib/libmimalloc.a` (LTO-slim) does not expose `mi_malloc` to the linker. The workable substitute is a source build: `cmake -DMI_OVERRIDE=ON -DMI_BUILD_SHARED=OFF -DMI_BUILD_STATIC=ON -DMI_BUILD_OBJECT=OFF -DMI_BUILD_TESTS=OFF` of v3.5.4. An `mi_static` built from the installed archive is byte-identical to `glibc_static`, so it silently tested the wrong allocator. Keep this in mind for the test matrix.

### relibc (test only, D13)

- Builds on the pinned `nightly-2026-05-24` with `-Z build-std`. Its Redox-only git dependencies resolved.
- Exports the malloc family unprefixed. The symbols survive into the final static binary, so name-based adapters work.
- The syscall view alone is not enough (three mallocs produced two mmaps). Object boundaries must come from entry-point probes.
- An int3 probe on relibc `malloc` and `free` reports 3 mallocs and 1 free with correct sizes, return values, and free argument.

### Lessons (now test-authoring rules)

- GCC deletes unused `malloc`/`free` pairs as built-ins. Test programs must use `-fno-builtin` and make the pointers escape, or the probe sees nothing.
- A probe that restores the wrong bytes silently corrupts code. The first version did this. Every probe test must assert the exact sequence of calls and arguments, not just that the child exits.
- Addresses shift on relink. Adapters resolve symbols at run time, not at fixed addresses.
- Empty rule vector in `seccompiler` means "match any arguments" (verified in the crate's docs and code).

## 7b. P0-c results (E4 mechanism, verified; throwaway spike in `spikes/hook_spike`, excluded from git)

Question: can a safe-Rust tracer hook the allocator inside a running process at its exec-stop, record every call and its returned pointer, and let the process run without stopping it per call?

| Run | Result |
|---|---|
| `bare` (no hook), `hook_target` | `sequence ok`, exit 0 |
| `run` (hook), `hook_target` | `sequence ok`, exit 0. Four allocations from `main` (sizes 16, 100, 1000, 40000) match in order, and their returned pointers equal the target's `keep[]` exactly. Seven other calls (libc init, stdio) are recorded too and must be filtered by call site. |
| `run` inside `firejail --profile=/etc/firejail/wine.profile` | Same result, exit 0 (addresses differ, as expected). The hook works inside the D15 sandbox. |
| Overhead, 1M `malloc(64)`+`free` pairs, debug build | bare 10.5 to 11.4 ms, hooked 41 to 58 ms. About 31 to 40 ns added per hooked call. |
| Overhead, same, release build | bare 10.4 to 11.4 ms, hooked 41 to 42 ms. |

For scale: E2 trapped syscalls cost about 27 µs each (7a). A hooked `malloc` costs roughly 700 to 900 times less. At 1M allocations per second, the hook costs roughly 3 to 4 % CPU. That is a guess from one microbenchmark, not a game measurement.

Mechanism facts, all observed:

- The exec-stop sits inside `execve`'s return path. The kernel writes `rax = 0` after the stop, and the first single-step traps before any user instruction. Without one burned single-step, an injected `syscall` silently does not run (`rip` unchanged, `rax` 0). Injection must burn one step first.
- Inferior `mmap` (RWX, hint `0x10000000`, within 2 GB of `malloc` at `0x4179a0`) succeeded.
- The entry patch is a 5-byte `jmp rel32` at `malloc+4`, after `endbr64`, which stays in place. It replaces `test %rdi,%rdi` and `js`. Those two instructions are displaced and re-encoded with iced-x86 `BlockEncoder` at the trampoline address. Entry trampoline 165 bytes, exit stub 62 bytes.
- Writing trampolines and the patch through `/proc/<pid>/mem` into a `r-x` text page works for a ptrace-attached tracer.
- The return-side hook works as follows. The entry trampoline saves the caller's return address, stores it in a pending table keyed by the caller's rsp, and replaces it with the exit stub's address. The exit stub writes `rax` (the returned pointer) into the record and jumps back. This gives object identity without any stop.
- Record ring: `lock xadd` on the head, 2^20 records of 32 bytes (size, caller return address, returned pointer). The ring read at the stop was consistent.

Not validated yet (each is a gate before P3 or the feature that needs it):

1. **Multi-threaded targets.** The pending table is global, so the spike is single-threaded only. A per-thread pending state is needed (R16).
2. **Other entry points.** `free`, `realloc`, `calloc` and `memalign` are not hooked. glibc's `free` tail-jumps to its own entry (7a), so it needs its own analysis.
3. **Dynamic and PIE binaries.** The spike uses a static non-PIE binary, so the malloc address is fixed at exec-stop. A dynamic binary's libc is mapped later, so a second install point (after `ld.so` maps libc) is needed. Not built.
4. **Stripped binaries.** The spike looks up `malloc` in the ELF symbol table. The no-symbol path is not exercised (D7, D21).
5. **Interaction with seccomp TRACE.** The spike ran without the memory-syscall filter. Combining them is a P2 test.
6. **Ring wrap.** The 1M loop wrote about 1.0M records, which stays below 2^20, so wrap-around was not exercised. The overflow policy is R21.
7. **Self-checking code and CET enforcement.** Not tested. `endbr64` is kept, but the patch still changes the function's bytes (R18).

Verdict: **PASS for the single-threaded static glibc case, which is the case P0-c had to decide.** E4 is not refuted, and E2 is not needed yet. Threads and dynamic linking are gates inside P2 and P3, not reasons to switch engines. Reproduce: `cd spikes/hook_spike && cargo build && ./target/debug/hook_spike run ../hook_target/hook_target`.

## 7c. P2a results (verified, tests in `tests/`)

- **Mechanism.** `leakgc __stub <cmd>` installs a seccomp filter that traps mmap, munmap, mremap, brk, clone, clone3 and execve, then stops itself. The supervisor seizes it, resumes it, and drains until ECHILD. The root exit code is returned. Non-memory syscalls are not trapped, so they run natively.
- **Observed behaviour (used as test assertions).** A static glibc hello traps execve and brk. A 1 MB malloc in a static binary did not show mmap. A dynamic threaded program traps mmap and clone3. Orphaned grandchildren are still waited for, because forks are auto-attached and stay traced after reparenting. leakgc is not a subreaper.
- **Tests.** `tests/supervisor_fake.rs` has 17 scripted-tracer tests covering every error arm. `tests/supervisor_real.rs` has 4 real-process tests, with C fixtures in `tests/fixtures/`. `tests/supervisor_seize.rs` has 1 test and stays alone in its file, because waiting on the whole process group would race with other tests. `tests/trap.rs`, `tests/maps.rs` and `tests/stub.rs` cover the rest.
- **Stub limits.** The stub's success path is covered only by the missing-program run, because execve replaces the process image. A stub started in-process with a valid program raises SIGSTOP, so that path is tested only through the binary.
- **Gates.** `cargo test --workspace` passed three runs in a row. `cargo xtask lint` passed. `cargo xtask coverage` passed: all 13 `src/` files at 100% functions, lines and regions.
- **Not covered.** Hooks, dynamic and PIE install points, multi-threaded hooks and stripped binaries are all P2b or P3 work.

## 7d. P2b-1 results (verified by `tests/hook.rs` and `tests/ring.rs`, 18 tests)

- **Planner.** `hook::plan` skips a leading `endbr64`. It displaces whole instructions until at least 5 bytes are covered. It refuses: undecodable bytes anywhere in the function, a function too short for the patch, a near branch in the function that lands inside the 5 patched bytes (R19), and a call among the displaced instructions. A branch to the patch start is allowed.
- **Relocation.** `Plan::relocate` re-encodes the displaced instructions with `BlockEncoder`. A relative jump and a rip-relative load keep their absolute targets. A rip-relative target that is out of rel32 reach but fits in 32 bits gets an address-size prefix (0x67), and its effective address is unchanged. A target above 4 GiB, relocated to a low address, fails with `Relocation`.
- **Ring.** `ring::plan_drain` returns the records since the last drain and the number lost to overwrite (R21). The collection is incomplete when `lost` is above zero.
- **Not covered yet.** This slice touches no process. The install address, trampoline placement and decoding of a real binary are P2b-2. The branch scan covers only the function's own bytes (D29). Jump-table targets are not checked (R19).
- **Gates.** `cargo xtask lint` passed. `cargo xtask coverage` passed: all 15 `src/` files at 100% functions, lines and regions.

## 7e. P2b-2 results (verified by `tests/install_fake.rs` (17 tests), `tests/install_real.rs` (1 test) and `tests/hook.rs`)

- **Install sequence.** `install::install_malloc` uses hint `0x1000_0000`. It reads the image through `/proc/<pid>/exe`, parses it with goblin, and refuses anything that is not a static `ET_EXEC` with no interpreter. It reads every executable section from live memory, finds `malloc` as a function symbol, and plans the patch. Only then does it burn one instruction, inject an RWX `mmap` (`MAP_FIXED_NOREPLACE`) at the hint through the seccomp trap, and write the entry trampoline, the displaced instructions and the exit stub. The 5-byte jump is written last. Registers and bytes changed for an injected call are restored, even when the call fails.
- **Verified in a real process.** `tests/fixtures/malloc_static.c` is a static, non-PIE binary. Its `main` calls `malloc` with sizes 16, 100, 1000 and 40000, then raises SIGSTOP. At the stop the ring holds exactly those four records from `main`. Their sizes match, and each returned pointer equals the value `main` stored in `keep[]`. This confirms the trampolines and the record layout. It also settles the open injection question: an injected `mmap` trapped by seccomp completes after one more single-step stop, with SIGTRAP at rip+2 and the returned address in rax.
- **Text scan (D29 experiment, run before this slice).** A static glibc hello and a threaded static build decode with zero invalid instructions over `.text`, `.init`, `.plt` and `.fini`.
- **Refusals and errors.** Each planner refusal and each `InstallError` has a test. The planner cases are undecodable bytes, a short patch, a branch into the patch from inside the function and from another section, a call in the patch, a relocation that cannot reach its target, and a hook out of rel32 reach. The install cases are a non-static or position-independent image, a missing `malloc`, a `malloc` outside every executable section, a parse failure, a refused or moved `mmap`, an unexpected stop, more than four seccomp stops, and a syscall that does not finish at rip+2.
- **Failure injection.** `a_failure_at_any_call_leaves_the_jump_unwritten` fails each operating-system call of the install in turn. No failure leaves the jump written.
- **Caveats.**
  - The entry trampoline is about 165 bytes, and the displaced code and tail add at most about 35 bytes. The exit stub sits at +0x800. Nothing checks at run time that the code fits. The test asserts it only for the static fixture, so a later change to the template must keep the total below 0x800.
  - The 5-byte jump is one write to `/proc/<pid>/mem`. A short write of the jump itself is returned as an error and is not tested.
  - Install does not count threads. It is safe only because the exec-stop has one thread. P2b-3 must refuse multi-threaded targets.
  - The region is RWX (R23).
  - `tests/install_fake.rs` takes about 40 s in debug, because each failure-injection case rebuilds the fake memory and plans all of `.text`. Shrinking it is a possible follow-up.
- **Gates.** `cargo test --workspace` passed three runs in a row. `cargo xtask lint` passed. `cargo xtask coverage` passed: all 16 `src/` files at 100% functions, lines and regions.

## 8. Risks (stated plainly)

- **R1 Allocator lock held at a stop.** Freeing with a thread inside an allocator lock can deadlock or corrupt. Mitigation: pending-call tracking (4.3) and skipping busy collections. Residual risk remains, so free mode stays opt-in until P5 is validated on all families.
- **R2 Hidden pointers.** Pointers stored XORed, tagged, compressed or NaN-boxed are invisible to a conservative scan, so they cause false frees. Mitigation: quarantine (P5), report-only default, and the rule "free nothing you cannot see".
- **R3 Memory the scan does not see.** Pointers held only in the kernel (in-flight I/O, io_uring), in GPU or DMA buffers, or in shared memory. Freeing a block that DMA is writing into corrupts it. Mitigation: exclude device and shm mappings from frees, and report them as "not covered".
- **R4 Undercounted allocations.** A call path we did not hook means a live block is not in the shadow heap. Safe, because unknown regions are roots, but those blocks are never freed and the report must say so.
- **R5 Performance.** A hooked malloc costs about 35 ns in one microbenchmark (7b). A trapped memory syscall costs about 27 µs (debug, 7a). Wine cold start inside the sandbox is about 12.4k syscall traps, about 0.33 s before any allocation work. Steady state for a real game is still unmeasured. Measure in P3 on a real workload, not only the 64-byte microbenchmark.
- **R6 Firejail.** Verified: the sandbox blocks outside tracing (4.5), and its default seccomp blocks `ptrace` unless `allow-debuggers` is set. Mitigation: the supervisor runs inside the sandbox, and the profile must keep `allow-debuggers`.
- **R7 "Rust must be safe" depends on dependencies.** Our code is unsafe-free (verified). `nix`, `libc`, and `seccompiler` contain unsafe internally (section 7a). Decide whether that is acceptable (D3). `cargo xtask audit` should fail if any of our crates lack `forbid(unsafe_code)`. The E4 spike adds `iced-x86` and `goblin`, which must go through the same audit before P2 commits them.
- **R8 "Any allocator" is limited to families we support.** An unknown allocator is reported as "not covered" and never freed. Fail-closed, not "works for everything".
- **R9 Linux only.** E4 depends on Linux ptrace, seccomp and `/proc/<pid>/mem`. Fine for Wine. It does not give the FreeBSD or bare-metal personality (D11).
- **R10 relibc is not a real-world allocator.** Its malloc is dlmalloc, which behaves differently from glibc, mimalloc and jemalloc under fragmentation and thread caches. A clean result says the hooks and shadow heap work. It says nothing about Wine or games.
- **R11 Outside supervision of a sandbox is impossible (new).** Verified EPERM. Any design that supervises from outside a firejail-wrapped Wine fails. Mitigation: 4.5.
- **R12 Lingering daemons (new).** `wineserver` and similar processes outlive the root. Supervision must drain them (4.4 rule 1), or they are killed or left untraced. Verified in the spike.
- **R13 Supervisor error leaves a stopped stub (new).** Verified hang. Mitigation: `Drop` guard (4.4 rule 2).
- **R14 `brk` and `munmap` are not trapped yet (new).** The spike traps `mmap` only. Static glibc small allocations use `brk`, so their region growth is invisible to the trap. Mitigation: read `/proc/<pid>/maps` at each collection, and trap `brk` in P2 (D18). Status (P2b-2): P2a traps `brk` and `munmap` (7c), so region growth is visible to the trap. Reading `/proc/<pid>/maps` at each collection is not implemented yet.
- **R15 Cold start cost (new).** Each sandboxed Wine run starts a fresh wineserver, so the first seconds carry about 12.4k traps. Measure in P3 whether this matters for the user's workflow.
- **R16 Threads (new, E4).** The spike's pending table is global and has no synchronisation, so two threads can race on a slot. Mitigation: per-thread pending state. Until it is validated, multi-threaded targets are refused for hooks and their blocks are reported as not covered (D5). Status (P2b-2): the install runs at the exec-stop, when only one thread exists, so the hook itself does not race. Per-thread pending state is not built. P2b-3 refuses multi-threaded targets. Not tested.
- **R17 Patch race and cross-modifying code (new, E4).** Another thread may execute the bytes being patched. Mitigation: install only while every thread is stopped, and never patch a range another thread may execute. The exec-stop install avoids this case because only one thread exists. Not tested beyond that.
- **R18 Self-checking code and CET (new, E4).** `endbr64` is kept, but the patch still changes the function's bytes. A program that checksums its own code can behave differently, and the monitor cannot detect that. CET enforcement is not tested. Mitigation: test with a self-checking target before P3. Until then this is a known unknown.
- **R19 Branches into patched bytes, and relocation (new, E4).** Another branch can target the middle of the 5 patched bytes, which then decode as something else. Displaced instructions with rip-relative operands must be relocated correctly. Mitigation: scan the function for branch targets inside the patched range, and refuse those hooks (4.6). P2b-1 tests the planner and relocation on hand-encoded cases (7d). Status (P2b-2): the branch scan covers every executable section of the live image (D29). Jump-table and computed targets are still unchecked.
- **R20 Per-call cost is real (new, E4).** The 35 ns figure comes from one microbenchmark with 64-byte blocks. An allocation-heavy game pays it on every call, and a locked `xadd` costs more under contention. Mitigation: measure on a real workload in P3 before calling it negligible.
- **R21 Ring overflow (new, E4).** The ring holds 2^20 records. If the target makes more calls between two drains, old records are overwritten. Mitigation: drain at every collection and count wraps. If the ring wrapped before a drain, that collection is marked incomplete, no block is freed in it, and the report says so. The spike never wrapped the ring (7b item 6).
- **R22 Half-written ring slots (new, E4).** A thread stopped between its `lock xadd` and its record store leaves one stale slot (4.1 item 6). Mitigation: a validity marker written last. The spike's `pad` field is a candidate. Not tested.
- **R23 Writable and executable hook region (new, E4).** The hook region is mapped RWX, because the install writes it through `/proc/<pid>/mem` and the trampolines and the ring share one mapping. A bug in a trampoline, or a target that writes to the region, can alter the hook. Mitigation: the region is created with `MAP_FIXED_NOREPLACE`, so it never replaces an existing mapping. Splitting it into RW for the ring and RX for the code is a possible hardening step, and it is not done.

## 9. Decisions (status per item)

Key: **DECIDED** means chosen or confirmed by the user. **SUPERSEDED** means replaced by a later decision. Every item is DECIDED or SUPERSEDED, except D28, which is OPEN and needs the user's answer.

- **D1 Win32 heap (`RtlAllocateHeap` etc.). DECIDED (confirmed).** Options: (a) hook the exports in `ntdll`. This instruments Wine, which contradicts the locked rule "never inside wine". (b) Leave it as "not covered" and report it. (c) An explicit opt-in adapter you enable. **Recommendation: (b)**, because it respects the locked rule. Game allocations made through HeapAlloc are then never freed.
- **D2 Engine. SUPERSEDED by D17 (E4).** E2 is the fallback (section 3). E1 and E3 are not chosen.
- **D3 GC core language. DECIDED (confirmed).** The locked decision was OCaml. A Rust supervisor cannot call OCaml without `unsafe` FFI, which violates the Rust rule. Options: (a) keep OCaml as a separate process fed over a pipe (no unsafe, but a second runtime and latency); (b) port the core to Rust and keep OCaml as the executable spec and oracle. **Recommendation: (b)**, with OCaml as the reference for differential tests. P1 already follows (b).
- **D4 Default mode. DECIDED (confirmed).** Report-only by default, free only with `--free`. **Recommendation: yes.**
- **D5 Multi-threaded freeing. DECIDED (confirmed).** Allow freeing in multi-threaded processes, or only report until P5 is validated? **Recommendation: report-only for multi-threaded processes until validated.**
- **D6 "Any allocator". DECIDED (confirmed).** Interpreted as: any family with an adapter, and everything else is reported as not covered. **Recommendation: confirm.**
- **D7 Static binaries (DECIDED by the user): support all binaries, including stripped ones.** Stripped static binaries have no symbol names, so their allocator entry points must be found another way (for example, byte signatures of known allocator builds, or the entry-point hooks from P3 combined with a code scan). This is the hardest part of P3 and is not proven yet. Known limit: no method can guarantee that every unknown allocator is found. The fail-closed rule stays as the fallback. Anything that cannot be identified is reported as "not covered" and is never freed, and the report says so explicitly.
- **D8 Uncovered memory. DECIDED (confirmed).** Warn in the report and never free it. **Recommendation: confirm.**
- **D9 Allocator-agnostic region tracking. DECIDED (confirmed).** Use all writable memory as conservative roots (recommended). Do not use it for object boundaries. **Recommendation: confirm.**
- **D10 Process scope. DECIDED (confirmed).** Which processes in the tree are managed? All, only those with a supported family, or a `--pid` filter. Wineserver should probably be excluded from freeing, but still drained (4.4). **Recommendation: only processes with a supported family, and always drain.**
- **D11 Personality. DECIDED (confirmed).** The child sees the real Linux kernel (transparent). FreeBSD or bare-metal personalities would be a separate, much larger project (closer to E1). Confirm that transparent Linux is enough.
- **D12 Project license.** Needed for `LICENSE` and `ACKNOWLEDGEMENTS`. Blink and Cosmopolitan (both ISC) need attribution only if their code or design is reused. Valgrind is GPL, so we take the idea and never its code, which keeps the project MIT-clean. **DECIDED: MIT** (chosen by the user). Written in P8: `LICENSE` and `ACKNOWLEDGEMENTS.md`.
- **D13 relibc scope. DECIDED: test target only.**
- **D14 Toolchain for relibc. APPROVED** and used in P0-b (`nightly-2026-05-24`, `rust-src`). Scratch work stays outside the repo.
- **D15 Where the supervisor runs when Wine is sandboxed (new, verified).** Options: (a) **leakgc runs inside the same firejail profile** as the payload: `firejail --profile=/etc/firejail/wine.profile leakgc __supervise wine game.exe`. Verified end to end. Needs `allow-debuggers` (already in `wine.profile`) and a config entry naming the wrapper. (b) Drop the sandbox and supervise bare Wine. Verified to work, but it loses the isolation the user already has. (c) Keep an outside supervisor. Verified impossible (EPERM). **DECIDED: (a), with `/etc/firejail/wine.profile`.**
- **D16 Seccomp or pure ptrace (new). DECIDED (confirmed).** Keep seccomp TRACE for memory syscalls (verified, gives exact region lifetimes at about 27 µs per trap), or drop it and poll `/proc/<pid>/maps` at each collection (no per-mmap cost, but new libraries and regions are found late, and `munmap` is invisible). **Recommendation: keep seccomp for P2**, then decide with P2 measurements on real games. Both need the allocator hooks anyway (E4).
- **D17 Engine (DECIDED by the user): E4.** A transparent process monitor written in Rust that does not interpret instructions. It is not a hypervisor: there is no hardware virtualization and no isolation boundary. The guest runs on the real kernel and sees the real OS, and the monitor passes everything through except memory calls. The guest runs natively, and the monitor intercepts only memory allocation: allocator entry points, plus memory syscalls such as `mmap`, `munmap` and `brk`. Effects: the GPU works and the speed is near native. It is not a VM in Blink's sense, because instructions are not emulated, so a memory access that bypasses the hooked entry points is invisible. Status after P0-c (7b): (1) answered for the single-threaded static case. Hooks are injected in-process at exec-stop, and a dynamic install point is still open (4.1 item 10). (2) Open. The patch race is R17, and nothing is tested beyond exec-stop. (3) Answered by design (4.6). The monitor decodes instruction lengths and relocation operands, and executes nothing. E2 remains the fallback if a remaining gate fails (R16 to R19). The identification problem for stripped and custom-allocator binaries (D7, D21) is unchanged. Future option, not part of E4: page-level tracking of all memory accesses (EPT via KVM, or `mprotect`/`userfaultfd`) would also cover non-allocator accesses, at page granularity, with higher cost and possible timing changes.
- **D18 Trap set and cost budget (new). DECIDED (confirmed).** The P2 trap list (section 4.1, item 2) includes `brk`, `munmap`, `mprotect` and `clone*`. Each adds stops. **Recommendation: start with `mmap`, `munmap`, `mremap`, `brk`, `clone`, `clone3`, and `execve`, and measure in P2 on a real game before adding more.**
- **D19 Boehm `libgc` (DECIDED, amended after D21): covered in report-only mode.** leakgc observes the `GC_malloc` family and reports leaks like any other family, but never frees a Boehm block. Reason: Boehm already reclaims unreachable memory itself, so freeing its blocks would conflict with its collector. Caveat: leakgc's roots can differ from Boehm's (for example, roots registered with `GC_add_roots`), so a block that Boehm keeps alive may be reported as leaked. Such reports must be labelled as Boehm-managed, not as definitely lost.
- **D21 Rust custom global allocators (DECIDED by the user): covered.** Any binary is in scope, including Rust programs with a custom `#[global_allocator]` that never calls `malloc`, the same rule as D7. Consequence: to report leaks for such an allocator, its allocation and free entry points must be identified in the binary, which is the D7 identification problem. Region-level tracking (`mmap`, `brk`, `/proc/<pid>/maps`) alone cannot report leaks. D17 (E4) is decided. Identifying these allocators is still open and belongs to P3.
- **D20 Allocator families in scope (DECIDED).** Support glibc, mimalloc, jemalloc, gperftools tcmalloc (4 variants), oneTBB tbbmalloc (including its malloc proxy), Scudo standalone and musl. relibc is test only (D13). Boehm is covered in report-only mode (D19). LeakSanitizer is oracle only. Priority order for P3: glibc, then mimalloc, then the rest. Caveat: most Windows game memory goes through Wine's heap, which is "not covered" under D1, so these families mainly cover Wine internals and native Linux code.

- **D22 Tracer trait as the seam (P2a). DECIDED (implementation; not yet confirmed by the user).** Every OS call in the supervisor goes through the `Tracer` trait. Control flow, including every error arm, is tested with scripted results.
- **D23 Public event model (P2a). DECIDED (implementation).** `Event` and `classify` are public, so each wait status maps to one event that tests can check directly.
- **D24 Fail-closed stub (P2a). DECIDED (implementation; rule 4.4.2).** A failed seize or resume kills the stub with SIGKILL, through the `Drop` guard. The stub never stays in group-stop.
- **D25 `wait_any` errors (P2a). DECIDED (implementation).** EINTR is retried. ECHILD ends the drain. Any other error makes `leakgc` exit with 1.
- **D26 Trace logging (P2a). DECIDED (implementation).** Trace logging is best-effort. Logging failures are ignored.
- **D27 Coverage scope (P2a). DECIDED (implementation; open option).** `tests/` is not in the coverage report, because cargo-llvm-cov excludes it by default. The gate covers `src/**` only. Making this explicit in `xtask` is an open option.
- **D28 Package name. OPEN.** `Cargo.toml` still says `win-games-leak-garbage-collector`. The binary is `leakgc`. Renaming the package to `leakgc` needs the user's answer.
- **D29 Branch scan scope (P2b-1). DECIDED (implementation; not yet confirmed by the user).** The branch check covers only the bytes of the function's own symbol, as passed to `hook::plan`. Branches from other functions into the middle of the patch are not checked. Neither are jump-table entries or computed targets. These are residual R19 risks. **Decided in P2b-2:** the check covers every executable section of the live image, read from memory at exec-stop. The user said 'continue' after the experiment in 7e. That is not an explicit confirmation of this scope, so please confirm it.
- **D30 Decoder (P2b-1). DECIDED (the user approved the P2b plan, which recommended iced-x86).** `iced-x86` 1.22.0 (MIT) decodes and re-encodes, with the `decoder`, `encoder` and `block_encoder` features. `goblin` is not needed until P2b-2, for ELF symbols. The R7 audit that `cargo xtask audit` would perform does not exist yet, so the unsafe code in iced-x86 is not audited.
- **D31 ELF parser (P2b-2). DECIDED (implementation; not yet confirmed by the user).** `goblin` 0.10.7 (MIT), with `elf32`, `elf64`, `endian_fd` and `std` and no default features. `elf32` is enabled as well, because it was required in the P2b-2 build. Its dependencies are `scroll` (MIT), `plain` (MIT/Apache-2.0) and `log` (MIT OR Apache-2.0), plus `scroll_derive` (proc macro, build time only) with `proc-macro2`, `quote` and `syn`. The R7 audit has not been run for goblin or these crates.
- **D32 Refusals before any write (P2b-2). DECIDED (implementation).** Every check that can refuse runs before the target is written: the image, the static-executable check, the `malloc` lookup and the planner. The first write is the injected system call's bytes, and they are restored. The 5-byte jump is the last write. If a failure comes after the `mmap`, the target's code is unchanged and the mapping stays unreferenced.
- **D33 Injection bounds and hint (P2b-2). DECIDED (implementation).** The region sits at `0x1000_0000` and is 192 KiB of code and head plus 32 MiB of records. The injected `mmap` must return that address, or the install fails with `MmapFailed`. Up to four seccomp stops are allowed while one injected call completes. Any other stop is refused, and the call must finish with SIGTRAP at rip+2.

## 10. Acknowledgements (finalised in P8, see `ACKNOWLEDGEMENTS.md`)

The full list, with license notes, is in `ACKNOWLEDGEMENTS.md`. Candidates considered: Valgrind (leak-kind taxonomy, the idea), relibc (MIT, if its code or build is used), Blink and Cosmopolitan Libc (ISC, if code or design is reused), Boehm-Demers-Weiser conservative GC (conservative-root model), the OCaml runtime (tri-color marking reference), and the authors of `nix`, `libc`, `seccompiler`, `iced-x86`, `goblin` and any other crate we depend on.
