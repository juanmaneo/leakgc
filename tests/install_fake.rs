//! `install_malloc_at` with every operating-system result scripted. The images
//! are real static and dynamic glibc binaries, so the planner sees real
//! `malloc` bytes. The real-process run is in `install_real.rs`.

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

use goblin::elf::Elf;
use goblin::elf::section_header::{SHF_ALLOC, SHF_EXECINSTR, SHT_PROGBITS};
use iced_x86::{Decoder, DecoderOptions, Instruction};
use libc::user_regs_struct;
use nix::errno::Errno;
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;
use win_games_leak_garbage_collector::hook::{Refusal, jmp_rel32};
use win_games_leak_garbage_collector::install::{
    DEFAULT_HINT, InstallError, Installed, install_malloc, install_malloc_at,
};
use win_games_leak_garbage_collector::supervisor::Tracer;

const TRACEE: i32 = 100;
const PTRACE_EVENT_SECCOMP: i32 = 7;
const SYSCALL: [u8; 2] = [0x0f, 0x05];
const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];

fn pid() -> Pid {
    Pid::from_raw(TRACEE)
}

fn trap() -> nix::Result<WaitStatus> {
    Ok(WaitStatus::Stopped(pid(), Signal::SIGTRAP))
}

fn seccomp() -> nix::Result<WaitStatus> {
    Ok(WaitStatus::PtraceEvent(
        pid(),
        Signal::SIGTRAP,
        PTRACE_EVENT_SECCOMP,
    ))
}

fn stopped(signal: Signal) -> nix::Result<WaitStatus> {
    Ok(WaitStatus::Stopped(pid(), signal))
}

fn initial_regs(rip: u64) -> user_regs_struct {
    user_regs_struct {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        rbp: 0,
        rbx: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rax: 0,
        rcx: 0,
        rdx: 0,
        rsi: 0,
        rdi: 0,
        orig_rax: u64::MAX,
        rip,
        cs: 0x33,
        eflags: 0x202,
        rsp: 0x7fff_f000,
        ss: 0x2b,
        fs_base: 0,
        gs_base: 0,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    }
}

/// A stopped tracee whose memory is the image's allocated sections. Each
/// injected system call completes on the step that reaches it, and `mmap`
/// returns `mmap_result`. The wait script decides which stops are reported.
struct Fake {
    image: Vec<u8>,
    mem: BTreeMap<u64, u8>,
    regs: user_regs_struct,
    waits: VecDeque<nix::Result<WaitStatus>>,
    mmap_result: i64,
    syscall_advances: bool,
    fail_at: Option<usize>,
    calls: usize,
    writes: Vec<(u64, Vec<u8>)>,
}

impl Fake {
    fn new(image: &[u8], waits: Vec<nix::Result<WaitStatus>>) -> Self {
        let mut mem = BTreeMap::new();
        let mut entry = 0;
        if let Ok(elf) = Elf::parse(image) {
            entry = elf.header.e_entry;
            for sh in elf
                .section_headers
                .iter()
                .filter(|sh| sh.sh_flags & u64::from(SHF_ALLOC) != 0 && sh.sh_type == SHT_PROGBITS)
            {
                let start = sh.sh_offset as usize;
                let end = start + sh.sh_size as usize;
                for (i, byte) in image[start..end].iter().enumerate() {
                    mem.insert(sh.sh_addr + i as u64, *byte);
                }
            }
        }
        Self {
            image: image.to_vec(),
            mem,
            regs: initial_regs(entry),
            waits: waits.into(),
            mmap_result: DEFAULT_HINT as i64,
            syscall_advances: true,
            fail_at: None,
            calls: 0,
            writes: Vec::new(),
        }
    }

    /// Counts one trait call and reports whether it is the one scheduled to fail.
    fn fails(&mut self) -> bool {
        let hit = self.fail_at == Some(self.calls);
        self.calls += 1;
        hit
    }

    fn at(&self, addr: u64) -> u8 {
        self.mem.get(&addr).copied().unwrap_or(0)
    }

    fn bytes(&self, addr: u64, len: usize) -> Vec<u8> {
        (0..len as u64).map(|i| self.at(addr + i)).collect()
    }

    fn poke(&mut self, addr: u64, bytes: &[u8]) {
        for (i, byte) in bytes.iter().enumerate() {
            self.mem.insert(addr + i as u64, *byte);
        }
    }
}

impl Tracer for Fake {
    fn spawn_stub(&mut self, _args: &[std::ffi::OsString]) -> io::Result<Pid> {
        unreachable!("install never spawns a stub")
    }

    fn wait_stopped(&mut self, _pid: Pid) -> nix::Result<WaitStatus> {
        if self.fails() {
            return Err(Errno::EIO);
        }
        self.waits.pop_front().unwrap_or(Err(Errno::ECHILD))
    }

    fn wait_any(&mut self) -> nix::Result<WaitStatus> {
        unreachable!("install waits on the one tracee")
    }

    fn seize(&mut self, _pid: Pid) -> nix::Result<()> {
        unreachable!("install runs after seize")
    }

    fn cont(&mut self, _pid: Pid, _sig: Option<Signal>) -> nix::Result<()> {
        unreachable!("install never resumes the tracee")
    }

    fn send_signal(&mut self, _pid: Pid, _sig: Signal) -> nix::Result<()> {
        unreachable!("install never signals")
    }

    fn syscall_nr(&mut self, _pid: Pid) -> nix::Result<i64> {
        unreachable!("install reads registers, not the trap log")
    }

    fn read_maps(&mut self, _pid: Pid) -> io::Result<String> {
        unreachable!("install reads the image, not the maps")
    }

    fn exe_image(&mut self, _pid: Pid) -> io::Result<Vec<u8>> {
        if self.fails() {
            return Err(io::Error::other("injected image failure"));
        }
        Ok(self.image.clone())
    }

    fn regs(&mut self, _pid: Pid) -> nix::Result<user_regs_struct> {
        if self.fails() {
            return Err(Errno::EIO);
        }
        Ok(self.regs)
    }

    fn set_regs(&mut self, _pid: Pid, regs: user_regs_struct) -> nix::Result<()> {
        if self.fails() {
            return Err(Errno::EIO);
        }
        self.regs = regs;
        Ok(())
    }

    fn step(&mut self, _pid: Pid) -> nix::Result<()> {
        if self.fails() {
            return Err(Errno::EIO);
        }
        let rip = self.regs.rip;
        if self.syscall_advances && self.at(rip) == SYSCALL[0] && self.at(rip + 1) == SYSCALL[1] {
            self.regs.rax = if self.regs.rax == libc::SYS_mmap as u64 {
                self.mmap_result as u64
            } else {
                0
            };
            self.regs.rip += SYSCALL.len() as u64;
        }
        Ok(())
    }

    fn read_mem(&mut self, _pid: Pid, addr: u64, len: usize) -> io::Result<Vec<u8>> {
        if self.fails() {
            return Err(io::Error::other("injected read failure"));
        }
        (0..len as u64)
            .map(|i| {
                self.mem
                    .get(&(addr + i))
                    .copied()
                    .ok_or_else(|| io::Error::other(format!("unmapped {:#x}", addr + i)))
            })
            .collect()
    }

    fn write_mem(&mut self, _pid: Pid, addr: u64, bytes: &[u8]) -> io::Result<()> {
        if self.fails() {
            return Err(io::Error::other("injected write failure"));
        }
        self.poke(addr, bytes);
        self.writes.push((addr, bytes.to_vec()));
        Ok(())
    }
}

fn build_c(out_name: &str, flags: &[&str]) -> Vec<u8> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/malloc_static.c");
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join(out_name);
    let status = Command::new("cc")
        .arg(&src)
        .arg("-o")
        .arg(&out)
        .args(flags)
        .status()
        .expect("run cc");
    assert!(status.success(), "cc failed for {out_name}");
    std::fs::read(&out).expect("read the built image")
}

static STATIC_IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
static DYNAMIC_IMAGE: OnceLock<Vec<u8>> = OnceLock::new();

fn static_image() -> &'static [u8] {
    STATIC_IMAGE.get_or_init(|| build_c("install_fake_static", &["-static", "-no-pie"]))
}

fn dynamic_image() -> &'static [u8] {
    DYNAMIC_IMAGE.get_or_init(|| build_c("install_fake_dynamic", &["-no-pie"]))
}

/// A 64-byte ELF header with no sections or segments.
fn header_only(e_type: u16) -> Vec<u8> {
    let mut header = vec![0u8; 64];
    header[0..4].copy_from_slice(b"\x7fELF");
    header[4] = 2; // ELFCLASS64
    header[5] = 1; // little-endian
    header[6] = 1; // EV_CURRENT
    header[16..18].copy_from_slice(&e_type.to_le_bytes());
    header[18..20].copy_from_slice(&0x3eu16.to_le_bytes()); // EM_X86_64
    header[20..24].copy_from_slice(&1u32.to_le_bytes());
    header[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    header[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    header[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    header
}

/// A copy of `image` whose named section no longer has `SHF_EXECINSTR`.
fn without_exec_flag(image: &[u8], name: &str) -> Vec<u8> {
    let elf = Elf::parse(image).expect("test image parses");
    let index = elf
        .section_headers
        .iter()
        .position(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(name))
        .expect("section present");
    let flags_at = elf.header.e_shoff as usize + index * elf.header.e_shentsize as usize + 8;
    let mut out = image.to_vec();
    let flags = u64::from_le_bytes(out[flags_at..flags_at + 8].try_into().expect("8 bytes"));
    let cleared = flags & !u64::from(SHF_EXECINSTR);
    out[flags_at..flags_at + 8].copy_from_slice(&cleared.to_le_bytes());
    out
}

fn function_symbol(image: &[u8], name: &str) -> u64 {
    let elf = Elf::parse(image).expect("test image parses");
    elf.syms
        .iter()
        .find(|sym| sym.is_function() && elf.strtab.get_at(sym.st_name) == Some(name))
        .expect("symbol present")
        .st_value
}

/// The address and size of `.text`.
fn text_section(image: &[u8]) -> (u64, u64) {
    let elf = Elf::parse(image).expect("test image parses");
    let sh = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".text"))
        .expect(".text present");
    (sh.sh_addr, sh.sh_size)
}

/// Where the patch goes for `malloc`: after `endbr64` when it is present.
fn patch_point(fake: &Fake, malloc: u64) -> u64 {
    if fake.bytes(malloc, ENDBR64.len()) == ENDBR64 {
        malloc + ENDBR64.len() as u64
    } else {
        malloc
    }
}

fn text_instructions(fake: &Fake) -> Vec<Instruction> {
    let (addr, size) = text_section(&fake.image);
    let code = fake.bytes(addr, size as usize);
    let mut decoder = Decoder::with_ip(64, &code, addr, DecoderOptions::NONE);
    let mut out = Vec::new();
    while decoder.can_decode() {
        out.push(decoder.decode());
    }
    out
}

fn refusal(result: Result<Installed, InstallError>) -> Refusal {
    match result {
        Err(InstallError::Refused(refusal)) => refusal,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn installs_the_jump_last_at_the_entry_point() {
    let image = static_image();
    let malloc = function_symbol(image, "malloc");
    let mut fake = Fake::new(image, vec![trap(), seccomp(), trap()]);
    let patch = patch_point(&fake, malloc);
    let rip = fake.regs.rip;

    let installed = install_malloc(&mut fake, pid()).expect("installs");

    assert_eq!(
        installed,
        Installed {
            base: DEFAULT_HINT,
            patch_at: patch
        }
    );
    let writes = &fake.writes;
    assert_eq!(writes[0], (rip, SYSCALL.to_vec()), "syscall bytes");
    assert_eq!(writes[1].0, rip, "syscall bytes restored");
    let n = writes.len();
    assert_eq!(writes[n - 3].0, DEFAULT_HINT, "entry code at the region");
    assert!(
        writes[n - 3].1.len() < 0x800,
        "entry code fits before the exit stub"
    );
    assert_eq!(writes[n - 2].0, DEFAULT_HINT + 0x800, "exit stub");
    assert_eq!(
        writes[n - 1],
        (
            patch,
            jmp_rel32(patch, DEFAULT_HINT).expect("in reach").to_vec()
        ),
        "the jump is the last write"
    );
    assert_eq!(fake.regs.rip, rip, "registers restored");
}

#[test]
fn a_failure_at_any_call_leaves_the_jump_unwritten() {
    let image = static_image();
    let malloc = function_symbol(image, "malloc");
    let script = || vec![trap(), seccomp(), trap()];

    let mut probe = Fake::new(image, script());
    let patch = patch_point(&probe, malloc);
    install_malloc(&mut probe, pid()).expect("installs without a failure");
    let total = probe.calls;

    for k in 0..total {
        let mut fake = Fake::new(image, script());
        fake.fail_at = Some(k);
        let result = install_malloc(&mut fake, pid());
        assert!(
            matches!(result, Err(InstallError::Io(_) | InstallError::Os(_))),
            "failing call {k} of {total} gave {result:?}"
        );
        assert!(
            fake.writes.iter().all(|(addr, _)| *addr != patch),
            "failing call {k} still wrote the jump"
        );
    }
}

#[test]
fn a_refused_mmap_restores_the_target_and_writes_nothing_else() {
    let image = static_image();
    let mut fake = Fake::new(image, vec![trap(), trap()]);
    fake.mmap_result = -17;
    let rip = fake.regs.rip;
    let original = fake.bytes(rip, SYSCALL.len());
    let before = fake.regs;

    let result = install_malloc(&mut fake, pid());

    assert!(
        matches!(result, Err(InstallError::MmapFailed(-17))),
        "got {result:?}"
    );
    assert_eq!(
        fake.writes,
        vec![(rip, SYSCALL.to_vec()), (rip, original.clone())]
    );
    assert_eq!(fake.bytes(rip, SYSCALL.len()), original);
    assert_eq!((fake.regs.rip, fake.regs.rax), (before.rip, before.rax));
}

#[test]
fn an_mmap_at_another_address_is_refused() {
    let image = static_image();
    let mut fake = Fake::new(image, vec![trap(), trap()]);
    fake.mmap_result = 0x2000_0000;

    let result = install_malloc(&mut fake, pid());

    assert!(
        matches!(result, Err(InstallError::MmapFailed(0x2000_0000))),
        "got {result:?}"
    );
    assert!(fake.writes.iter().all(|(addr, _)| *addr != DEFAULT_HINT));
}

#[test]
fn a_stop_other_than_the_exec_trap_is_refused_before_injection() {
    let image = static_image();
    let mut fake = Fake::new(image, vec![stopped(Signal::SIGSTOP)]);

    let result = install_malloc(&mut fake, pid());

    assert!(
        matches!(
            result,
            Err(InstallError::UnexpectedStop(WaitStatus::Stopped(
                _,
                Signal::SIGSTOP
            )))
        ),
        "got {result:?}"
    );
    assert!(fake.writes.is_empty());
}

#[test]
fn a_stop_other_than_the_syscall_trap_is_refused() {
    let image = static_image();
    let mut fake = Fake::new(image, vec![trap(), stopped(Signal::SIGSTOP)]);

    let result = install_malloc(&mut fake, pid());

    assert!(
        matches!(result, Err(InstallError::UnexpectedStop(_))),
        "got {result:?}"
    );
    assert_eq!(fake.writes.len(), 2, "the syscall bytes are still restored");
}

#[test]
fn four_seccomp_stops_are_allowed_and_a_fifth_is_refused() {
    let image = static_image();

    let mut allowed = Fake::new(
        image,
        vec![trap(), seccomp(), seccomp(), seccomp(), seccomp(), trap()],
    );
    assert!(install_malloc(&mut allowed, pid()).is_ok());

    let mut refused = Fake::new(
        image,
        vec![
            trap(),
            seccomp(),
            seccomp(),
            seccomp(),
            seccomp(),
            seccomp(),
        ],
    );
    let result = install_malloc(&mut refused, pid());
    assert!(
        matches!(
            result,
            Err(InstallError::UnexpectedStop(WaitStatus::PtraceEvent(
                _,
                _,
                PTRACE_EVENT_SECCOMP
            )))
        ),
        "got {result:?}"
    );
}

#[test]
fn a_syscall_that_does_not_advance_is_refused() {
    let image = static_image();
    let mut fake = Fake::new(image, vec![trap(), trap()]);
    fake.syscall_advances = false;
    let rip = fake.regs.rip;

    let result = install_malloc(&mut fake, pid());

    assert!(
        matches!(result, Err(InstallError::SyscallIncomplete { rip: got }) if got == rip),
        "got {result:?}"
    );
}

#[test]
fn a_hint_beyond_rel32_reach_is_refused_before_anything_is_written() {
    let image = static_image();
    let mut fake = Fake::new(image, vec![]);

    let result = install_malloc_at(&mut fake, pid(), 1 << 40);

    assert_eq!(refusal(result), Refusal::OutOfReach);
    assert!(fake.writes.is_empty());
}

#[test]
fn a_call_in_the_patch_is_refused() {
    let image = static_image();
    let malloc = function_symbol(image, "malloc");
    let mut fake = Fake::new(image, vec![]);
    let patch = patch_point(&fake, malloc);
    fake.poke(patch, &[0xe8, 0x00, 0x00, 0x00, 0x00]);

    assert_eq!(
        refusal(install_malloc(&mut fake, pid())),
        Refusal::CallInPatch { at: patch }
    );
}

#[test]
fn an_undecodable_instruction_elsewhere_in_text_is_refused() {
    let image = static_image();
    let (text, _) = text_section(image);
    let mut fake = Fake::new(image, vec![]);
    let at = text_instructions(&fake)
        .iter()
        .map(Instruction::ip)
        .find(|ip| *ip >= text + 0x20000)
        .expect("an instruction past 0x20000 into .text");
    fake.poke(at, &[0x06]);

    assert_eq!(
        refusal(install_malloc(&mut fake, pid())),
        Refusal::Undecodable { at }
    );
}

#[test]
fn a_branch_from_elsewhere_into_the_patch_is_refused() {
    let image = static_image();
    let malloc = function_symbol(image, "malloc");
    let mut fake = Fake::new(image, vec![]);
    let patch = patch_point(&fake, malloc);
    let site = text_instructions(&fake)
        .into_iter()
        .find(|ins| ins.len() == 5 && ins.ip() > malloc + 0x100)
        .expect("a five-byte instruction away from malloc");
    // Overwrite it with `jmp` to the second byte of the patch. Both are five bytes, so nothing else moves.
    let rel = i64::try_from(patch + 1).expect("fits") - i64::try_from(site.ip() + 5).expect("fits");
    let rel = i32::try_from(rel).expect("within rel32");
    let mut jmp = vec![0xe9];
    jmp.extend_from_slice(&rel.to_le_bytes());
    fake.poke(site.ip(), &jmp);

    assert_eq!(
        refusal(install_malloc(&mut fake, pid())),
        Refusal::BranchIntoPatch {
            at: site.ip(),
            target: patch + 1,
        }
    );
}

#[test]
fn a_header_without_malloc_is_refused() {
    let mut fake = Fake::new(&header_only(2), vec![]);

    let result = install_malloc(&mut fake, pid());

    assert!(
        matches!(result, Err(InstallError::NoMalloc)),
        "got {result:?}"
    );
}

#[test]
fn a_malloc_outside_every_executable_section_is_refused() {
    let image = without_exec_flag(static_image(), ".text");
    let mut fake = Fake::new(&image, vec![]);

    let result = install_malloc(&mut fake, pid());

    assert!(
        matches!(result, Err(InstallError::NoMalloc)),
        "got {result:?}"
    );
}

#[test]
fn a_position_independent_image_is_not_static() {
    let mut fake = Fake::new(&header_only(3), vec![]);

    let result = install_malloc(&mut fake, pid());

    assert!(
        matches!(result, Err(InstallError::NotStaticExecutable)),
        "got {result:?}"
    );
}

#[test]
fn a_dynamic_image_is_not_static() {
    let mut fake = Fake::new(dynamic_image(), vec![]);

    let result = install_malloc(&mut fake, pid());

    assert!(
        matches!(result, Err(InstallError::NotStaticExecutable)),
        "got {result:?}"
    );
}

#[test]
fn an_image_that_does_not_parse_is_refused() {
    let mut fake = Fake::new(b"not an ELF image at all", vec![]);

    let result = install_malloc(&mut fake, pid());

    assert!(
        matches!(result, Err(InstallError::Parse(_))),
        "got {result:?}"
    );
}
