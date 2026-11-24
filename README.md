# leakgc

`leakgc` adds a garbage collector to a program that does not have one. It runs the program under supervision, finds memory the program has leaked, and frees it in the running process. The program keeps running and never knows its memory was collected.

The target is Wine and Windows game processes. Wine is only an argument, not a dependency, so the real Wine and a Rust port should both work. Wine integration is not built or tested yet (phase P6 in `PLAN.md`).

It does not use `LD_PRELOAD`. The program runs natively. A seccomp filter traps the memory system calls, and allocator entry points are hooked by patching their code.

## How it works

1. **Observe.** Hooks on the allocator record every block the program allocates and frees.
2. **Find leaks.** Stop the program, scan its registers, stacks and writable memory for pointers, and mark every block that is still reachable. A block nothing points to is a leak.
3. **Free.** Call the allocator's own `free` on each leaked block, inside the target, at a point where no thread is inside the allocator.

## Status

Early work. Steps 1 and 2 exist, in part. Nothing is freed yet.

- Traces `mmap`, `munmap`, `mremap`, `brk`, `clone`, `clone3` and `execve`, and passes everything else through to the kernel.
- Hooks `malloc`, `free` and `realloc` in **static, non-PIE glibc** programs and keeps a ledger of the blocks still outstanding. With `LEAKGC_LOG` set, it prints that ledger. This is a debugging aid for the later steps.
- At each trapped call, checks which outstanding blocks the process still reaches from its registers and writable memory. This is report only: `LEAKGC_LOG` prints the result, and nothing is freed. Read-only memory is not scanned, so some glibc startup blocks are reported as unreachable (see `PLAN.md`, R29 and D51).
- Not built: the count-based trigger and the free (P4 remainder and P5), threads, dynamic and PIE binaries, stripped binaries, other allocators.

Freeing memory the program still uses corrupts it. The design is fail-closed: a block that cannot be seen, or is not understood, is never freed. See `PLAN.md` (risks R1 to R3) for what that does and does not guarantee.

## Requirements

- Linux with `ptrace` and seccomp. Run `leakgc` outside sandboxes that block tracing (for example, a firejail profile without `allow-debuggers`).
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

## Documents

- `PLAN.md`: architecture, phases, risks and decisions.
- `ACKNOWLEDGEMENTS.md`: dependencies and their licenses.

## License

MIT (see `Cargo.toml`).
