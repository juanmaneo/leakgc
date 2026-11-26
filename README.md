# leakgc

`leakgc` adds a garbage collector to a program that does not have one. It runs the program under supervision, finds memory the program has leaked, and frees it in the running process. The program keeps running and never knows its memory was collected.

The target is Wine and Windows game processes. Wine is only an argument, not a dependency, so the real Wine and a Rust port should both work. Wine integration is not built or tested yet (phase P6 in `PLAN.md`).

It does not use `LD_PRELOAD`. The program runs natively. A seccomp filter traps the memory system calls, and allocator entry points are hooked by patching their code.

## How it works

1. **Observe.** Hooks on the allocator record every block the program allocates and frees.
2. **Find leaks.** Stop the program, scan its registers, stacks and writable memory for pointers, and mark every block that is still reachable. A block nothing points to is a leak.
3. **Free.** Call the allocator's own `free` on each leaked block, inside the target, at a point where no thread is inside the allocator.

## Status

Early work. Freeing works for static, non-PIE glibc programs that run in one thread (P5). Dynamic and PIE programs get hooks through their C library, but nothing is freed from them yet (`PLAN.md`, section 9, D71). musl programs, static or dynamic, get hooks and reports, but nothing is freed from them yet (D80). Other programs get no hooks, or stop being checked when they start a thread.

- Traces `mmap`, `munmap`, `mremap`, `brk`, `clone`, `clone3` and `execve`, and passes everything else through to the kernel.
- Hooks the allocator entry points of **static, non-PIE glibc** programs, and of the C library of **dynamic and PIE** programs once it is mapped (`malloc`, `free`, `realloc`, `calloc`, `memalign`, `aligned_alloc`, `valloc`, `pvalloc`, `posix_memalign` and `malloc_trim`) and keeps a ledger of the blocks still outstanding. An entry that the program's libc lacks is skipped, and the others are still hooked. If `free` or `realloc` is skipped, the ledger is untrusted and nothing is freed (D79). A hooked call made while another is open, such as glibc's `realloc(p, 0)` freeing `p`, makes the ledger untrusted (R40). With `LEAKGC_LOG` set, it prints the trap counts, the ledger, and the number of blocks that injection did not free. This is a debugging aid.
- Once 64 allocations have been counted since the last check, the next trapped call checks which outstanding blocks the process still reaches from its registers, writable memory and readable data. Executable code is not scanned (see `PLAN.md`, R35). A process that makes fewer than 64 allocations is not checked, and its report says so.
- **Freeing.** A block that one check finds unreached is poisoned with `0xDB` and held. If a later check still finds it unreached and unchanged, leakgc calls the program's own `free` on it at the exit of the trapped `mmap`, `munmap`, `mremap` or `brk` where that check ran. A check at another trapped call frees nothing. No block is freed while the stopped thread is inside glibc's allocator (a heuristic, R37). A block that is refused stays held and is retried at a later check. Just before each injected free, the block's bytes are checked again. If they changed, the ledger is untrusted from then on, and no more blocks are freed. A fault in the injected code kills the process (exit code 137) and prints a crash report to stderr, even without `LEAKGC_LOG`. The report names the block being freed and the function that faulted. It also lists the registers and the code addresses found on the stack. Stack addresses are a guess. The faulting memory address is not shown (see `PLAN.md`, section 7n). Once freed, a block is no longer watched, so a reference the scan missed becomes an ordinary use-after-free (`PLAN.md`, section 7m and D64).
- Not built: `--report-only` (P7), so freeing is always on for the programs above. Also not built: threads, freeing in dynamic and PIE programs (D71), freeing in musl programs (D80), stripped binaries, other allocators, and the Win32 heap (P6).

Freeing memory the program still uses corrupts it. The design is fail-closed: a block that cannot be seen, or is not understood, is never freed. See `PLAN.md` (risks R1 to R3) for what that does and does not guarantee.

## Supported C libraries

| C library | Hooks and reports | Freeing |
|---|---|---|
| glibc, static non-PIE, one thread | yes | yes |
| glibc, dynamic or PIE | yes | no (D71) |
| musl, static or dynamic | yes | no (D80) |
| Cosmopolitan, the ELF inside the APE | yes | no (D86) |
| relibc, static (beta, D74) | yes | no (no internal allocator names, R37) |

Stripped binaries get no hooks yet (D7). The Cosmopolitan APE that ships is stripped, so it gets none.

## Requirements

- Linux with `ptrace` and seccomp. Run `leakgc` outside sandboxes that block tracing (for example, a firejail profile without `allow-debuggers`).
- A CPU with XSAVE. Injected code needs it, and without it nothing is freed.
- Rust, to build it.

## Usage

```sh
cargo build
LEAKGC_LOG=1 ./target/debug/leakgc ./my-static-program
```

The exit code of the program is returned. `leakgc` exits with 2 on a usage error.

## Development

```sh
cargo test --workspace
cargo xtask lint
cargo xtask coverage
```

`cargo xtask coverage` requires every file in `src/` to be at 100% functions, lines and regions. The `tests/` directory is not part of that gate.

The C library tests run in one Docker image per library: `sh scripts/libc-tests.sh glibc`, `musl`, `cosmo` or `relibc` (the beta).

## Documents

- `PLAN.md`: architecture, phases, risks and decisions.
- `ACKNOWLEDGEMENTS.md`: dependencies and their licenses.

## License

MIT (see `Cargo.toml`).
