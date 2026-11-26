//! Shared scripted tracee for the install and monitor tests. Every operating-system
//! result is scripted. The images are real static and dynamic glibc binaries,
//! so the planner sees real `malloc`, `free` and `realloc` bytes.

#![allow(dead_code)]

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

use goblin::elf::Elf;
use goblin::elf::section_header::{SHF_ALLOC, SHT_PROGBITS};
use leakgc::install::DEFAULT_HINT;
use leakgc::supervisor::Tracer;
use libc::user_regs_struct;
use nix::errno::Errno;
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;

pub const TRACEE: i32 = 100;
pub const PTRACE_EVENT_SECCOMP: i32 = 7;
pub const SYSCALL: [u8; 2] = [0x0f, 0x05];
pub const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];

pub fn pid() -> Pid {
    Pid::from_raw(TRACEE)
}

pub fn trap() -> nix::Result<WaitStatus> {
    Ok(WaitStatus::Stopped(pid(), Signal::SIGTRAP))
}

pub fn seccomp() -> nix::Result<WaitStatus> {
    Ok(WaitStatus::PtraceEvent(
        pid(),
        Signal::SIGTRAP,
        PTRACE_EVENT_SECCOMP,
    ))
}

pub fn stopped(signal: Signal) -> nix::Result<WaitStatus> {
    Ok(WaitStatus::Stopped(pid(), signal))
}

pub fn initial_regs(rip: u64) -> user_regs_struct {
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
pub struct Fake {
    pub image: Vec<u8>,
    pub mem: BTreeMap<u64, u8>,
    pub regs: user_regs_struct,
    pub waits: VecDeque<nix::Result<WaitStatus>>,
    pub events: VecDeque<nix::Result<i64>>,
    pub mmap_result: i64,
    pub syscall_advances: bool,
    pub step_results: VecDeque<nix::Result<()>>,
    pub single_step_results: VecDeque<nix::Result<bool>>,
    pub fail_at: Option<usize>,
    pub calls: usize,
    pub writes: Vec<(u64, Vec<u8>)>,
    pub maps: String,
}

impl Fake {
    pub fn new(image: &[u8], waits: Vec<nix::Result<WaitStatus>>) -> Self {
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
            events: VecDeque::new(),
            mmap_result: DEFAULT_HINT as i64,
            syscall_advances: true,
            step_results: VecDeque::new(),
            single_step_results: VecDeque::new(),
            fail_at: None,
            calls: 0,
            writes: Vec::new(),
            maps: String::new(),
        }
    }

    /// Counts one trait call and reports whether it is the one scheduled to fail.
    pub fn fails(&mut self) -> bool {
        let hit = self.fail_at == Some(self.calls);
        self.calls += 1;
        hit
    }

    pub fn at(&self, addr: u64) -> u8 {
        self.mem.get(&addr).copied().unwrap_or(0)
    }

    pub fn bytes(&self, addr: u64, len: usize) -> Vec<u8> {
        (0..len as u64).map(|i| self.at(addr + i)).collect()
    }

    pub fn poke(&mut self, addr: u64, bytes: &[u8]) {
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

    fn syscall(&mut self, _pid: Pid) -> nix::Result<()> {
        unreachable!("install never resumes a trapped call")
    }

    fn send_signal(&mut self, _pid: Pid, _sig: Signal) -> nix::Result<()> {
        unreachable!("install never signals")
    }

    fn syscall_nr(&mut self, _pid: Pid) -> nix::Result<i64> {
        unreachable!("install reads registers, not the trap log")
    }

    fn read_maps(&mut self, _pid: Pid) -> io::Result<String> {
        if self.fails() {
            return Err(io::Error::other("injected maps failure"));
        }
        Ok(self.maps.clone())
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
        let failed = self.fails();
        if let Some(result) = self.step_results.pop_front() {
            result?;
        } else if failed {
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

    fn is_single_step_trap(&mut self, _pid: Pid) -> nix::Result<bool> {
        self.single_step_results.pop_front().unwrap_or(Ok(true))
    }

    fn event_message(&mut self, _pid: Pid) -> nix::Result<i64> {
        self.events.pop_front().unwrap_or(Err(Errno::ESRCH))
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

/// Adds a mapping line to the fake's memory map without any bytes behind it.
/// Reading an address without bytes fails, so the test decides which ranges are readable.
pub fn map_line(fake: &mut Fake, start: u64, end: u64, perms: &str) {
    fake.maps
        .push_str(&format!("{start:x}-{end:x} {perms} 00000000 00:00 0\n"));
}

/// Adds a writable mapping whose bytes are all zero, so every byte can be read.
pub fn map_writable(fake: &mut Fake, start: u64, end: u64) {
    map_line(fake, start, end, "rw-p");
    for addr in start..end {
        fake.mem.entry(addr).or_insert(0);
    }
}

/// Writes one little-endian word at `addr`.
pub fn put_word(fake: &mut Fake, addr: u64, value: u64) {
    fake.poke(addr, &value.to_le_bytes());
}

pub fn build_c(out_name: &str, flags: &[&str]) -> Vec<u8> {
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

pub static STATIC_IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
pub static DYNAMIC_IMAGE: OnceLock<Vec<u8>> = OnceLock::new();

pub fn static_image() -> &'static [u8] {
    STATIC_IMAGE.get_or_init(|| build_c("install_fake_static", &["-static", "-no-pie"]))
}

pub fn dynamic_image() -> &'static [u8] {
    DYNAMIC_IMAGE.get_or_init(|| build_c("install_fake_dynamic", &["-no-pie"]))
}
