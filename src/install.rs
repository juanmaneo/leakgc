//! Installs the E4 entry hooks on the glibc allocator entries in a stopped,
//! static, non-PIE process (PLAN 4.6). It runs at the exec-stop, before the
//! target executes anything.
//!
//! Every check that can refuse runs before the target is touched. Each function
//! is planned and its original bytes are read first. Only then is an `mmap`
//! injected. The three 5-byte jumps are written last, so no thread runs a
//! half-written trampoline. If a jump write fails, the jumps already written
//! are restored.
//!
//! The hooks share one depth counter. A hooked function that calls another
//! hooked function (`realloc` calls `malloc` and `free`) records only the outer
//! call. Nested calls run their displaced code and nothing more.

use std::io;

use goblin::elf::Elf;
use goblin::elf::header::ET_EXEC;
use goblin::elf::section_header::SHT_NOBITS;
use iced_x86::code_asm::*;
use libc::user_regs_struct;
use nix::errno::Errno;
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;

use crate::hook::{self, JMP_LEN, Refusal};
use crate::ring::{CAPACITY, Kind, RECORD_LEN};
use crate::supervisor::{PTRACE_EVENT_SECCOMP, Tracer};

/// Where the hook region goes when the caller does not choose. It lies within
/// rel32 reach of the static non-PIE binaries we test (PLAN 4.6).
pub const DEFAULT_HINT: u64 = 0x1000_0000;
/// Offset of the ring head, a `u64` counter that the entry trampoline bumps with `lock xadd`.
pub const HEAD_OFFSET: u64 = 0x1_0000;
/// Offset of the first record. Record `i` lives at `i % CAPACITY`.
pub const RECORDS_OFFSET: u64 = 0x3_0000;

const DEPTH_OFFSET: u64 = HEAD_OFFSET + 8;
const PENDING_OFFSET: u64 = 0x2_0000;
const EXIT_OFFSET: u64 = 0x1000;
/// Each hook's entry trampoline, displaced instructions and tail share one block.
const BLOCK_LEN: u64 = 0x200;
/// Where the displaced instructions start within a block. The entry trampoline
/// must assemble to fewer bytes than this. The displaced instructions and the
/// tail share the rest of the block.
const DISPLACED_OFFSET: u64 = 0x1c0;
/// The hook region's length. Reachability scans skip this mapping (P4b).
pub const REGION_LEN: u64 = RECORDS_OFFSET + CAPACITY * RECORD_LEN as u64;
const INDEX_MASK: i32 = (CAPACITY - 1) as i32;
const PROT_RWX: u64 = 0x7;
/// `MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE`.
const MAP_FLAGS: u64 = 0x02 | 0x20 | 0x10_0000;
const SYSCALL: [u8; 2] = [0x0f, 0x05];
/// Seccomp stops allowed while one injected call completes. The stub's filter
/// is inherited across exec, so the injected `mmap` is trapped.
const MAX_SECCOMP_STOPS: usize = 4;
const ASM: &str = "trampoline instruction assembles";
const ASM_NEW: &str = "64-bit assembler is available";
const LAYOUT: &str = "block code fits its slot";

const _: () = assert!(RECORD_LEN == 64);
const _: () = assert!(PENDING_OFFSET + 0x1_0000 == RECORDS_OFFSET);
const _: () = assert!(DEPTH_OFFSET + 8 <= PENDING_OFFSET);
const _: () = assert!(HOOKS.len() as u64 * BLOCK_LEN <= EXIT_OFFSET);

/// One hooked function: its symbol, the kind of its record, the argument
/// registers the record holds as `(size, pointer argument)`, and its block.
struct Hook {
    symbol: &'static str,
    kind: Kind,
    captured: (Option<AsmRegister64>, Option<AsmRegister64>),
    block: u64,
}

/// `calloc`, `memalign`, `aligned_alloc`, `valloc` and `pvalloc` call glibc's
/// internal `_int_malloc` or `_int_memalign`, not the hooked `malloc`, so they
/// are hooked on their own. Otherwise their blocks are never recorded, and a
/// trap inside them would look like a safe point (PLAN 4.8, D54).
const HOOKS: [Hook; 8] = [
    Hook {
        symbol: "malloc",
        kind: Kind::Malloc,
        captured: (Some(rdi), None),
        block: 0,
    },
    Hook {
        symbol: "free",
        kind: Kind::Free,
        captured: (None, Some(rdi)),
        block: BLOCK_LEN,
    },
    Hook {
        symbol: "realloc",
        kind: Kind::Realloc,
        captured: (Some(rsi), Some(rdi)),
        block: 2 * BLOCK_LEN,
    },
    Hook {
        symbol: "calloc",
        kind: Kind::Calloc,
        captured: (Some(rdi), Some(rsi)),
        block: 3 * BLOCK_LEN,
    },
    Hook {
        symbol: "memalign",
        kind: Kind::Memalign,
        captured: (Some(rsi), None),
        block: 4 * BLOCK_LEN,
    },
    Hook {
        symbol: "aligned_alloc",
        kind: Kind::Memalign,
        captured: (Some(rsi), None),
        block: 5 * BLOCK_LEN,
    },
    Hook {
        symbol: "valloc",
        kind: Kind::Valloc,
        captured: (Some(rdi), None),
        block: 6 * BLOCK_LEN,
    },
    Hook {
        symbol: "pvalloc",
        kind: Kind::Valloc,
        captured: (Some(rdi), None),
        block: 7 * BLOCK_LEN,
    },
];

/// A jump written into the target, with the bytes it replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Patch {
    pub at: u64,
    pub original: [u8; JMP_LEN],
}

/// The hooks as installed. `base` is the region, and `patches` lists every
/// jump written into the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub base: u64,
    pub patches: Vec<Patch>,
}

/// Why the hooks were not installed. Every variant leaves the target unpatched,
/// except that a region may stay mapped (see `install_hooks_at`).
#[derive(Debug)]
pub enum InstallError {
    /// Reading the image or the target's memory failed.
    Io(io::Error),
    /// A ptrace call failed.
    Os(Errno),
    /// The ELF image does not parse.
    Parse(String),
    /// The image is not a static, non-PIE executable (PLAN 4.6).
    NotStaticExecutable,
    /// No function symbol with this name lies in an executable section.
    MissingSymbol(&'static str),
    /// The planner refused an entry point, which stays fail-closed (D29).
    Refused(Refusal),
    /// The region was not mapped at the hint. The value is what `mmap` returned.
    MmapFailed(i64),
    /// A wait returned a stop that the injection does not expect.
    UnexpectedStop(WaitStatus),
    /// The injected system call did not finish at the next instruction.
    SyscallIncomplete { rip: u64 },
}

impl From<io::Error> for InstallError {
    fn from(error: io::Error) -> Self {
        InstallError::Io(error)
    }
}

impl From<Errno> for InstallError {
    fn from(errno: Errno) -> Self {
        InstallError::Os(errno)
    }
}

impl From<Refusal> for InstallError {
    fn from(refusal: Refusal) -> Self {
        InstallError::Refused(refusal)
    }
}

/// Installs the hooks at [`DEFAULT_HINT`]. Signal-delivery stops are appended
/// to `pending_signals`, including when installation later returns an error;
/// the caller must re-queue them after the tracee is safe to resume.
pub fn install_hooks<T: Tracer>(
    tracer: &mut T,
    pid: Pid,
    pending_signals: &mut Vec<Signal>,
) -> Result<Installed, InstallError> {
    install_hooks_at(tracer, pid, DEFAULT_HINT, pending_signals)
}

/// Installs the hooks with their region at `hint`, which must lie within rel32
/// reach of every hooked function. If the injected `mmap` does not return
/// `hint`, nothing else is written. A failure after the region is mapped
/// leaves the region mapped and the target unpatched. Signal-delivery stops
/// are appended to `pending_signals`, including when installation later fails;
/// the caller must re-queue them after the tracee is safe to resume.
pub fn install_hooks_at<T: Tracer>(
    tracer: &mut T,
    pid: Pid,
    hint: u64,
    pending_signals: &mut Vec<Signal>,
) -> Result<Installed, InstallError> {
    let image = tracer.exe_image(pid)?;
    let elf = Elf::parse(&image).map_err(|error| InstallError::Parse(error.to_string()))?;
    if elf.header.e_type != ET_EXEC || elf.interpreter.is_some() {
        return Err(InstallError::NotStaticExecutable);
    }
    let text = exec_sections(tracer, pid, &elf)?;
    let refs: Vec<(u64, &[u8])> = text
        .iter()
        .map(|(start, code)| (*start, code.as_slice()))
        .collect();

    let mut planned = Vec::with_capacity(HOOKS.len());
    for hook in &HOOKS {
        let (addr, function) = function_symbol(&elf, &text, hook.symbol)
            .ok_or(InstallError::MissingSymbol(hook.symbol))?;
        let block = hint + hook.block;
        let plan = hook::plan(addr, function, &refs, block, block + DISPLACED_OFFSET)?;
        let original = tracer.read_mem(pid, plan.patch_at, JMP_LEN)?;
        let original: [u8; JMP_LEN] = original.try_into().expect("read JMP_LEN bytes");
        planned.push((hook, plan, original, (addr, addr + function.len() as u64)));
    }

    burn_exec_step(tracer, pid, pending_signals)?;
    let mapped = run_syscall(
        tracer,
        pid,
        libc::SYS_mmap as u64,
        [hint, REGION_LEN, PROT_RWX, MAP_FLAGS, u64::MAX, 0],
        pending_signals,
    )?;
    if mapped as u64 != hint {
        return Err(InstallError::MmapFailed(mapped));
    }

    for (hook, plan, _, outer) in &planned {
        let block = hint + hook.block;
        let mut code = pad_to(entry_code(hint, block, hook, *outer), DISPLACED_OFFSET);
        code.extend_from_slice(&plan.displaced_code);
        let resume = plan.patch_at + plan.patch_len as u64;
        let tail_at = block + DISPLACED_OFFSET + plan.displaced_code.len() as u64;
        code.extend_from_slice(&tail_code(resume, tail_at));
        tracer.write_mem(pid, block, &pad_to(code, BLOCK_LEN))?;
    }
    tracer.write_mem(pid, hint + EXIT_OFFSET, &exit_code(hint))?;

    let mut patches = Vec::with_capacity(planned.len());
    for (_, plan, original, _) in planned {
        if let Err(error) = tracer.write_mem(pid, plan.patch_at, &plan.jump) {
            restore(tracer, pid, &patches);
            return Err(error.into());
        }
        patches.push(Patch {
            at: plan.patch_at,
            original,
        });
    }
    Ok(Installed {
        base: hint,
        patches,
    })
}

/// Writes the original bytes back over every jump in `installed`. The region
/// stays mapped, and its trampolines are left in place. They are unreachable
/// once the jumps are gone.
pub fn uninstall<T: Tracer>(tracer: &mut T, pid: Pid, installed: &Installed) -> io::Result<()> {
    for patch in &installed.patches {
        tracer.write_mem(pid, patch.at, &patch.original)?;
    }
    Ok(())
}

/// Best effort: a failure here leaves the process patched, and the caller
/// already has an error to report.
fn restore<T: Tracer>(tracer: &mut T, pid: Pid, patches: &[Patch]) {
    for patch in patches {
        let _ = tracer.write_mem(pid, patch.at, &patch.original);
    }
}

/// The executable sections, read from the live process rather than the file,
/// so the bytes planned are the bytes that will run.
fn exec_sections<T: Tracer>(
    tracer: &mut T,
    pid: Pid,
    elf: &Elf,
) -> Result<Vec<(u64, Vec<u8>)>, InstallError> {
    elf.section_headers
        .iter()
        .filter(|sh| sh.is_executable() && sh.sh_type != SHT_NOBITS && sh.sh_size > 0)
        .map(|sh| -> Result<(u64, Vec<u8>), InstallError> {
            let bytes = tracer.read_mem(pid, sh.sh_addr, sh.sh_size as usize)?;
            Ok((sh.sh_addr, bytes))
        })
        .collect()
}

/// The address and bytes of the function symbol `name`.
fn function_symbol<'a>(
    elf: &Elf,
    text: &'a [(u64, Vec<u8>)],
    name: &str,
) -> Option<(u64, &'a [u8])> {
    let sym = elf
        .syms
        .iter()
        .find(|sym| sym.is_function() && elf.strtab.get_at(sym.st_name) == Some(name))?;
    let (start, code) = text
        .iter()
        .find(|(start, code)| (*start..*start + code.len() as u64).contains(&sym.st_value))?;
    let from = (sym.st_value - *start) as usize;
    let function = code.get(from..from + sym.st_size as usize).unwrap_or(&[]);
    Some((sym.st_value, function))
}

/// Runs one instruction so the exec-stop's pending kernel state is consumed.
/// Without this, an injected `syscall` silently does not run (PLAN 7b).
fn burn_exec_step<T: Tracer>(
    tracer: &mut T,
    pid: Pid,
    pending_signals: &mut Vec<Signal>,
) -> Result<(), InstallError> {
    loop {
        tracer.step(pid)?;
        match tracer.wait_stopped(pid)? {
            WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                if step_completed(tracer, pid, pending_signals)? {
                    return Ok(());
                }
            }
            WaitStatus::Stopped(_, signal) => pending_signals.push(signal),
            other => return Err(InstallError::UnexpectedStop(other)),
        }
    }
}

/// Whether a SIGTRAP stop is the end of the single-step we asked for. If it is
/// a SIGTRAP sent to the target, it is added to `pending_signals`, and the
/// caller steps again.
fn step_completed<T: Tracer>(
    tracer: &mut T,
    pid: Pid,
    pending_signals: &mut Vec<Signal>,
) -> Result<bool, InstallError> {
    let is_step = match tracer.is_single_step_trap(pid) {
        Ok(is_step) => is_step,
        Err(error) => {
            pending_signals.push(Signal::SIGTRAP);
            return Err(error.into());
        }
    };
    if is_step {
        return Ok(true);
    }
    pending_signals.push(Signal::SIGTRAP);
    Ok(false)
}

/// Runs one system call at the target's instruction pointer and returns its
/// result. The bytes and registers it used are restored afterwards, even when
/// the call fails.
fn run_syscall<T: Tracer>(
    tracer: &mut T,
    pid: Pid,
    nr: u64,
    args: [u64; 6],
    pending_signals: &mut Vec<Signal>,
) -> Result<i64, InstallError> {
    let saved = tracer.regs(pid)?;
    let original = tracer.read_mem(pid, saved.rip, SYSCALL.len())?;
    tracer.write_mem(pid, saved.rip, &SYSCALL)?;
    let outcome = arm_and_finish(tracer, pid, saved, nr, args, pending_signals);
    let restored_bytes = tracer.write_mem(pid, saved.rip, &original);
    let restored_regs = tracer.set_regs(pid, saved);
    let result = outcome?;
    restored_bytes?;
    restored_regs?;
    Ok(result)
}

fn arm_and_finish<T: Tracer>(
    tracer: &mut T,
    pid: Pid,
    saved: user_regs_struct,
    nr: u64,
    args: [u64; 6],
    pending_signals: &mut Vec<Signal>,
) -> Result<i64, InstallError> {
    let armed = user_regs_struct {
        rax: nr,
        rdi: args[0],
        rsi: args[1],
        rdx: args[2],
        r10: args[3],
        r8: args[4],
        r9: args[5],
        // Stops the kernel from restarting the call after it returns.
        orig_rax: u64::MAX,
        ..saved
    };
    tracer.set_regs(pid, armed)?;
    tracer.step(pid)?;
    let mut seccomp_stops = 0;
    loop {
        match tracer.wait_stopped(pid)? {
            WaitStatus::PtraceEvent(_, _, PTRACE_EVENT_SECCOMP)
                if seccomp_stops < MAX_SECCOMP_STOPS =>
            {
                seccomp_stops += 1;
                tracer.step(pid)?;
            }
            WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                if step_completed(tracer, pid, pending_signals)? {
                    break;
                }
                tracer.step(pid)?;
            }
            WaitStatus::Stopped(_, signal) => {
                pending_signals.push(signal);
                tracer.step(pid)?;
            }
            other => return Err(InstallError::UnexpectedStop(other)),
        }
    }
    let after = tracer.regs(pid)?;
    if after.rip != saved.rip + SYSCALL.len() as u64 {
        return Err(InstallError::SyscallIncomplete { rip: after.rip });
    }
    Ok(after.rax as i64)
}

/// Pads `code` with zeros to exactly `len` bytes. Code that is already longer
/// would overrun the next part of the layout, so that is a panic, not a silent
/// overlap.
fn pad_to(code: Vec<u8>, len: u64) -> Vec<u8> {
    let len = len as usize;
    (code.len() <= len)
        .then(move || {
            let mut code = code;
            code.resize(len, 0);
            code
        })
        .expect(LAYOUT)
}

/// The entry trampoline for `hook`, assembled to run at `block`. When no call
/// is already being recorded, it stores the call's arguments in a new record,
/// parks the caller's return address and the address range of the function
/// with the record, and returns through the exit stub. A nested call is
/// recorded as `Kind::Nested` unless it is harmless (R40). Then it runs the
/// displaced instructions. `outer` is the range `[start, end)` of the hooked
/// function's own code.
fn entry_code(base: u64, block: u64, hook: &Hook, outer: (u64, u64)) -> Vec<u8> {
    let head = base + HEAD_OFFSET;
    let depth = base + DEPTH_OFFSET;
    let records = base + RECORDS_OFFSET;
    let pending = base + PENDING_OFFSET;
    let exit = base + EXIT_OFFSET;
    let displaced = block + DISPLACED_OFFSET;
    let (size, arg) = hook.captured;

    let mut a = CodeAssembler::new(64).expect(ASM_NEW);
    let mut nested = a.create_label();
    let mut record_nested = a.create_label();
    let mut done = a.create_label();
    a.pushfq().expect(ASM);
    for reg in [rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11] {
        a.push(reg).expect(ASM);
    }
    a.mov(r11, depth).expect(ASM);
    a.cmp(qword_ptr(r11), 0i32).expect(ASM);
    a.jne(nested).expect(ASM);
    a.mov(qword_ptr(r11), 1i32).expect(ASM);
    // rax = record index: the ring head, bumped and masked.
    a.mov(r11, head).expect(ASM);
    a.mov(eax, 1).expect(ASM);
    a.lock().xadd(qword_ptr(r11), rax).expect(ASM);
    a.and(rax, INDEX_MASK).expect(ASM);
    a.mov(rcx, rax).expect(ASM);
    a.shl(rcx, 6).expect(ASM);
    a.mov(r11, records).expect(ASM);
    a.add(rcx, r11).expect(ASM);
    if let Some(reg) = size {
        a.mov(qword_ptr(rcx), reg).expect(ASM);
    } else {
        a.mov(qword_ptr(rcx), 0i32).expect(ASM);
    }
    a.mov(rdx, qword_ptr(rsp + 80)).expect(ASM);
    a.mov(qword_ptr(rcx + 8), rdx).expect(ASM);
    if let Some(reg) = arg {
        a.mov(qword_ptr(rcx + 16), reg).expect(ASM);
    } else {
        a.mov(qword_ptr(rcx + 16), 0i32).expect(ASM);
    }
    a.mov(qword_ptr(rcx + 32), hook.kind as i32).expect(ASM);
    a.mov(qword_ptr(rcx + 40), 0i32).expect(ASM);
    // Pending: the caller's return address, the record it belongs to, and the
    // address range of the function that made the call.
    a.mov(r10, pending).expect(ASM);
    a.mov(qword_ptr(r10), rdx).expect(ASM);
    a.mov(qword_ptr(r10 + 8), rcx).expect(ASM);
    a.mov(r9, outer.0).expect(ASM);
    a.mov(qword_ptr(r10 + 16), r9).expect(ASM);
    a.mov(r9, outer.1).expect(ASM);
    a.mov(qword_ptr(r10 + 24), r9).expect(ASM);
    // Return through the exit stub, which stores the result.
    a.mov(rdx, exit).expect(ASM);
    a.mov(qword_ptr(rsp + 80), rdx).expect(ASM);
    a.jmp(done).expect(ASM);
    // A nested call. A return address at the exit stub is a tail jump from
    // another hooked function, and one inside the outer function is glibc calling
    // a hooked entry from its own body. Both are harmless and are not recorded.
    // Any other caller is recorded as `Kind::Nested`, so the monitor stops
    // trusting the ledger (R40). Nothing here touches the depth counter or the
    // pending slot, which belong to the outer call.
    a.set_label(&mut nested).expect(ASM);
    a.mov(rdx, qword_ptr(rsp + 80)).expect(ASM);
    a.mov(r9, exit).expect(ASM);
    a.cmp(rdx, r9).expect(ASM);
    a.je(done).expect(ASM);
    a.mov(r10, pending).expect(ASM);
    a.mov(r9, qword_ptr(r10 + 16)).expect(ASM);
    a.cmp(rdx, r9).expect(ASM);
    a.jb(record_nested).expect(ASM);
    a.mov(r9, qword_ptr(r10 + 24)).expect(ASM);
    a.cmp(rdx, r9).expect(ASM);
    a.jb(done).expect(ASM);
    a.set_label(&mut record_nested).expect(ASM);
    a.mov(r11, head).expect(ASM);
    a.mov(eax, 1).expect(ASM);
    a.lock().xadd(qword_ptr(r11), rax).expect(ASM);
    a.and(rax, INDEX_MASK).expect(ASM);
    a.mov(rcx, rax).expect(ASM);
    a.shl(rcx, 6).expect(ASM);
    a.mov(r11, records).expect(ASM);
    a.add(rcx, r11).expect(ASM);
    a.mov(qword_ptr(rcx), 0i32).expect(ASM);
    a.mov(qword_ptr(rcx + 8), rdx).expect(ASM);
    a.mov(qword_ptr(rcx + 16), 0i32).expect(ASM);
    a.mov(qword_ptr(rcx + 24), 0i32).expect(ASM);
    a.mov(qword_ptr(rcx + 32), Kind::Nested as i32).expect(ASM);
    a.mov(qword_ptr(rcx + 40), 1i32).expect(ASM);
    a.set_label(&mut done).expect(ASM);
    for reg in [r11, r10, r9, r8, rdi, rsi, rdx, rcx, rax] {
        a.pop(reg).expect(ASM);
    }
    a.popfq().expect(ASM);
    a.jmp(displaced).expect(ASM);
    a.assemble(block).expect(ASM)
}

/// The exit stub, placed at `base + EXIT_OFFSET`. It stores `rax` (the result)
/// in the record the pending slot names, clears the depth counter, and returns
/// to the caller.
fn exit_code(base: u64) -> Vec<u8> {
    let depth = base + DEPTH_OFFSET;
    let pending = base + PENDING_OFFSET;

    let mut a = CodeAssembler::new(64).expect(ASM_NEW);
    a.mov(r10, pending).expect(ASM);
    a.mov(r11, qword_ptr(r10)).expect(ASM);
    a.mov(rcx, qword_ptr(r10 + 8)).expect(ASM);
    a.mov(qword_ptr(rcx + 24), rax).expect(ASM);
    a.mov(qword_ptr(rcx + 40), 1i32).expect(ASM);
    a.mov(r10, depth).expect(ASM);
    a.mov(qword_ptr(r10), 0i32).expect(ASM);
    a.jmp(r11).expect(ASM);
    a.assemble(base + EXIT_OFFSET).expect(ASM)
}

/// Runs the displaced instructions, then jumps back to `resume`. `r11` is
/// caller-saved and is not an argument register of any hooked function.
fn tail_code(resume: u64, ip: u64) -> Vec<u8> {
    let mut a = CodeAssembler::new(64).expect(ASM_NEW);
    a.mov(r11, resume).expect(ASM);
    a.jmp(r11).expect(ASM);
    a.assemble(ip).expect(ASM)
}
