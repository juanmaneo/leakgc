//! Installs the E4 entry hook on `malloc` in a stopped, static, non-PIE process
//! (PLAN 4.6). It runs at the exec-stop, before the target executes anything.
//!
//! Every check that can refuse runs before the target is touched. The image is
//! parsed, its live text is read and planned, and only then is an `mmap`
//! injected. The 5-byte jump is written last, so no thread runs a half-written
//! trampoline.

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

use crate::hook::{self, Refusal};
use crate::ring::{CAPACITY, RECORD_LEN};
use crate::supervisor::{PTRACE_EVENT_SECCOMP, Tracer};

/// Where the hook region goes when the caller does not choose. It lies within
/// rel32 reach of the static non-PIE binaries we test (PLAN 4.6).
pub const DEFAULT_HINT: u64 = 0x1000_0000;
/// Offset of the ring head, a `u64` counter that the entry trampoline bumps with `lock xadd`.
pub const HEAD_OFFSET: u64 = 0x1_0000;
/// Offset of the first record. Record `i` lives at `i % CAPACITY`.
pub const RECORDS_OFFSET: u64 = 0x3_0000;

const PENDING_OFFSET: u64 = 0x2_0000;
const EXIT_OFFSET: u64 = 0x800;
const REGION_LEN: u64 = RECORDS_OFFSET + CAPACITY * RECORD_LEN as u64;
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

const _: () = assert!(RECORD_LEN == 32);
const _: () = assert!(PENDING_OFFSET + 0x1_0000 == RECORDS_OFFSET);

/// The hook as installed. `base` is the region, and `patch_at` is the address of the jump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Installed {
    pub base: u64,
    pub patch_at: u64,
}

/// Why the hook was not installed. Every variant leaves the target unpatched,
/// except that a region may stay mapped (see `install_malloc_at`).
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
    /// No `malloc` function symbol lies in an executable section.
    NoMalloc,
    /// The planner refused the entry point, which stays fail-closed (D29).
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

/// Installs the hook at [`DEFAULT_HINT`].
pub fn install_malloc<T: Tracer>(tracer: &mut T, pid: Pid) -> Result<Installed, InstallError> {
    install_malloc_at(tracer, pid, DEFAULT_HINT)
}

/// Installs the hook with its region at `hint`, which must lie within rel32
/// reach of `malloc`. If the injected `mmap` does not return `hint`, nothing
/// else is written.
pub fn install_malloc_at<T: Tracer>(
    tracer: &mut T,
    pid: Pid,
    hint: u64,
) -> Result<Installed, InstallError> {
    let image = tracer.exe_image(pid)?;
    let elf = Elf::parse(&image).map_err(|error| InstallError::Parse(error.to_string()))?;
    if elf.header.e_type != ET_EXEC || elf.interpreter.is_some() {
        return Err(InstallError::NotStaticExecutable);
    }
    let text = exec_sections(tracer, pid, &elf)?;
    let (addr, function) = malloc_function(&elf, &text).ok_or(InstallError::NoMalloc)?;
    let refs: Vec<(u64, &[u8])> = text
        .iter()
        .map(|(start, code)| (*start, code.as_slice()))
        .collect();

    let entry = entry_code(hint);
    let displaced_at = hint + entry.len() as u64;
    let plan = hook::plan(addr, function, &refs, hint, displaced_at)?;

    burn_exec_step(tracer, pid)?;
    let mapped = run_syscall(
        tracer,
        pid,
        libc::SYS_mmap as u64,
        [hint, REGION_LEN, PROT_RWX, MAP_FLAGS, u64::MAX, 0],
    )?;
    if mapped as u64 != hint {
        return Err(InstallError::MmapFailed(mapped));
    }

    let mut code = entry;
    code.extend_from_slice(&plan.displaced_code);
    let resume = plan.patch_at + plan.patch_len as u64;
    code.extend_from_slice(&tail_code(
        resume,
        displaced_at + plan.displaced_code.len() as u64,
    ));
    tracer.write_mem(pid, hint, &code)?;
    tracer.write_mem(pid, hint + EXIT_OFFSET, &exit_code(hint))?;
    tracer.write_mem(pid, plan.patch_at, &plan.jump)?;
    Ok(Installed {
        base: hint,
        patch_at: plan.patch_at,
    })
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

/// The address and bytes of the `malloc` function symbol.
fn malloc_function<'a>(elf: &Elf, text: &'a [(u64, Vec<u8>)]) -> Option<(u64, &'a [u8])> {
    let sym = elf
        .syms
        .iter()
        .find(|sym| sym.is_function() && elf.strtab.get_at(sym.st_name) == Some("malloc"))?;
    let (start, code) = text
        .iter()
        .find(|(start, code)| (*start..*start + code.len() as u64).contains(&sym.st_value))?;
    let from = (sym.st_value - *start) as usize;
    let function = code.get(from..from + sym.st_size as usize).unwrap_or(&[]);
    Some((sym.st_value, function))
}

/// Runs one instruction so the exec-stop's pending kernel state is consumed.
/// Without this, an injected `syscall` silently does not run (PLAN 7b).
fn burn_exec_step<T: Tracer>(tracer: &mut T, pid: Pid) -> Result<(), InstallError> {
    tracer.step(pid)?;
    match tracer.wait_stopped(pid)? {
        WaitStatus::Stopped(_, Signal::SIGTRAP) => Ok(()),
        other => Err(InstallError::UnexpectedStop(other)),
    }
}

/// Runs one system call at the target's instruction pointer and returns its
/// result. The bytes and registers it used are restored afterwards, even when
/// the call fails.
fn run_syscall<T: Tracer>(
    tracer: &mut T,
    pid: Pid,
    nr: u64,
    args: [u64; 6],
) -> Result<i64, InstallError> {
    let saved = tracer.regs(pid)?;
    let original = tracer.read_mem(pid, saved.rip, SYSCALL.len())?;
    tracer.write_mem(pid, saved.rip, &SYSCALL)?;
    let outcome = arm_and_finish(tracer, pid, saved, nr, args);
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
            WaitStatus::Stopped(_, Signal::SIGTRAP) => break,
            other => return Err(InstallError::UnexpectedStop(other)),
        }
    }
    let after = tracer.regs(pid)?;
    if after.rip != saved.rip + SYSCALL.len() as u64 {
        return Err(InstallError::SyscallIncomplete { rip: after.rip });
    }
    Ok(after.rax as i64)
}

/// The entry trampoline, assembled to run at `base`. It appends a record, parks
/// the original return address, and returns through the exit stub.
fn entry_code(base: u64) -> Vec<u8> {
    let head = base + HEAD_OFFSET;
    let records = base + RECORDS_OFFSET;
    let pending = base + PENDING_OFFSET;
    let exit = base + EXIT_OFFSET;

    let mut a = CodeAssembler::new(64).expect(ASM_NEW);
    a.pushfq().expect(ASM);
    for reg in [rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11] {
        a.push(reg).expect(ASM);
    }
    // rax = record index: the ring head, bumped and masked.
    a.mov(r11, head).expect(ASM);
    a.mov(eax, 1).expect(ASM);
    a.lock().xadd(qword_ptr(r11), rax).expect(ASM);
    a.and(rax, INDEX_MASK).expect(ASM);
    // Record: size from rdi, caller return address from the stack.
    a.mov(rcx, rax).expect(ASM);
    a.shl(rcx, 5).expect(ASM);
    a.mov(r11, records).expect(ASM);
    a.add(rcx, r11).expect(ASM);
    a.mov(qword_ptr(rcx), rdi).expect(ASM);
    a.mov(rdx, qword_ptr(rsp + 80)).expect(ASM);
    a.mov(qword_ptr(rcx + 8), rdx).expect(ASM);
    // Pending slot keyed by the caller's rsp: (original return, record index).
    a.mov(r10, rsp).expect(ASM);
    a.add(r10, 88).expect(ASM);
    a.shr(r10, 3).expect(ASM);
    a.and(r10, 0xfff).expect(ASM);
    a.shl(r10, 4).expect(ASM);
    a.mov(r8, pending).expect(ASM);
    a.add(r10, r8).expect(ASM);
    a.mov(qword_ptr(r10), rdx).expect(ASM);
    a.mov(qword_ptr(r10 + 8), rax).expect(ASM);
    // Return through the exit stub, which stores the returned pointer.
    a.mov(rdx, exit).expect(ASM);
    a.mov(qword_ptr(rsp + 80), rdx).expect(ASM);
    for reg in [r11, r10, r9, r8, rdi, rsi, rdx, rcx, rax] {
        a.pop(reg).expect(ASM);
    }
    a.popfq().expect(ASM);
    a.assemble(base).expect(ASM)
}

/// The exit stub, placed at `base + EXIT_OFFSET`. It stores `rax` (the returned
/// pointer) in the record its pending slot names, then returns to the caller.
fn exit_code(base: u64) -> Vec<u8> {
    let records = base + RECORDS_OFFSET;
    let pending = base + PENDING_OFFSET;

    let mut a = CodeAssembler::new(64).expect(ASM_NEW);
    a.mov(rcx, rsp).expect(ASM);
    a.shr(rcx, 3).expect(ASM);
    a.and(rcx, 0xfff).expect(ASM);
    a.shl(rcx, 4).expect(ASM);
    a.mov(rdx, pending).expect(ASM);
    a.add(rcx, rdx).expect(ASM);
    a.mov(rdx, qword_ptr(rcx + 8)).expect(ASM);
    a.shl(rdx, 5).expect(ASM);
    a.mov(r11, records).expect(ASM);
    a.add(rdx, r11).expect(ASM);
    a.mov(qword_ptr(rdx + 16), rax).expect(ASM);
    a.mov(r11, qword_ptr(rcx)).expect(ASM);
    a.jmp(r11).expect(ASM);
    a.assemble(base + EXIT_OFFSET).expect(ASM)
}

/// Runs the displaced instructions, then jumps back to `resume`. `r11` is
/// caller-saved and is not an argument register of `malloc`.
fn tail_code(resume: u64, ip: u64) -> Vec<u8> {
    let mut a = CodeAssembler::new(64).expect(ASM_NEW);
    a.mov(r11, resume).expect(ASM);
    a.jmp(r11).expect(ASM);
    a.assemble(ip).expect(ASM)
}
