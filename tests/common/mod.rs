//! Shared scripted tracee for the install and monitor tests. Every operating-system
//! result is scripted. The images are real static and dynamic glibc binaries,
//! so the planner sees real `malloc`, `free` and `realloc` bytes.

#![allow(dead_code)]

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use goblin::elf::Elf;
use goblin::elf::section_header::{SHF_ALLOC, SHF_EXECINSTR, SHT_PROGBITS};
use leakgc::install::{DEFAULT_HINT, HEAD_OFFSET, INJECT_LEN, INJECT_OFFSET, RECORDS_OFFSET};
use leakgc::ring::{CAPACITY, Kind, RECORD_LEN, Record};
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
    /// Makes every `write_mem` fail, without counting toward `fail_at`.
    pub fail_writes: bool,
    /// Each of these makes its call fail, without counting toward `fail_at`.
    pub fail_regs: bool,
    pub fail_set_regs: bool,
    pub fail_reads: bool,
    pub fail_kill: bool,
    pub fail_image: bool,
    pub calls: usize,
    pub writes: Vec<(u64, Vec<u8>)>,
    pub signals: Vec<Signal>,
    pub maps: String,
    /// The files `file_image` can read, by path: the inode and the bytes.
    pub files: BTreeMap<String, (u64, Vec<u8>)>,
    /// Makes an injected `mmap` return its requested address, as a real kernel does
    /// for a fixed hint, instead of `mmap_result`.
    pub mmap_echoes_hint: bool,
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
            fail_writes: false,
            fail_regs: false,
            fail_set_regs: false,
            fail_reads: false,
            fail_kill: false,
            fail_image: false,
            calls: 0,
            writes: Vec::new(),
            signals: Vec::new(),
            maps: String::new(),
            files: BTreeMap::new(),
            mmap_echoes_hint: false,
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

    fn send_signal(&mut self, _pid: Pid, sig: Signal) -> nix::Result<()> {
        self.signals.push(sig);
        if self.fail_kill {
            return Err(Errno::EPERM);
        }
        Ok(())
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
        if self.fail_image || self.fails() {
            return Err(io::Error::other("injected image failure"));
        }
        Ok(self.image.clone())
    }

    fn file_image(&mut self, path: &str) -> io::Result<(u64, Vec<u8>)> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }

    fn regs(&mut self, _pid: Pid) -> nix::Result<user_regs_struct> {
        if self.fail_regs || self.fails() {
            return Err(Errno::EIO);
        }
        Ok(self.regs)
    }

    fn set_regs(&mut self, _pid: Pid, regs: user_regs_struct) -> nix::Result<()> {
        if self.fail_set_regs || self.fails() {
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
                if self.mmap_echoes_hint {
                    self.regs.rdi
                } else {
                    self.mmap_result as u64
                }
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
        if self.fail_reads || self.fails() {
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
        if self.fail_writes || self.fails() {
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

/// The caller address that every scripted record names.
pub const CALLER: u64 = 0x40_1000;

pub fn set_head(fake: &mut Fake, head: u64) {
    fake.poke(DEFAULT_HINT + HEAD_OFFSET, &head.to_le_bytes());
}

/// Writes ring slot `index` as the entry and exit code would. An open slot
/// has no result yet.
pub fn write_slot(fake: &mut Fake, index: u64, record: Record, done: bool) {
    let mut bytes = [0u8; RECORD_LEN];
    for (at, word) in [
        (0, record.size),
        (8, record.caller),
        (16, record.arg),
        (24, record.result),
        (32, record.kind as u64),
        (40, u64::from(done)),
    ] {
        bytes[at..at + 8].copy_from_slice(&word.to_le_bytes());
    }
    let at = DEFAULT_HINT + RECORDS_OFFSET + (index % CAPACITY) * RECORD_LEN as u64;
    fake.poke(at, &bytes);
}

pub fn malloc_record(size: u64, result: u64) -> Record {
    Record {
        kind: Kind::Malloc,
        size,
        caller: CALLER,
        arg: 0,
        result,
    }
}

pub fn free_record(ptr: u64) -> Record {
    Record {
        kind: Kind::Free,
        size: 0,
        caller: CALLER,
        arg: ptr,
        result: 0,
    }
}

/// The start of the injected-free trampoline written at install, and the
/// address of the `int3` that ends it.
pub fn trampoline(fake: &Fake) -> (u64, u64) {
    let start = DEFAULT_HINT + INJECT_OFFSET;
    let code = fake.bytes(start, INJECT_LEN as usize);
    let last = code
        .iter()
        .rposition(|&byte| byte != 0)
        .expect("the trampoline is written");
    assert_eq!(code[last], 0xcc, "the trampoline ends at an int3");
    (start, start + last as u64)
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

const TIMEOUT: Duration = Duration::from_secs(60);

/// Runs `leakgc` with only the variables given here. `cargo test` sets
/// `LD_LIBRARY_PATH`, and a static C library reads it at startup and allocates
/// for it. That changes the traced program's blocks and its reachability, so a
/// run must not inherit the test runner's environment.
///
/// The run has a deadline, so a supervision hang fails the test instead of
/// stalling it.
pub fn run_leakgc(args: &[&str], env: &[(&str, &str)]) -> (ExitStatus, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_leakgc"));
    command.args(args).env_clear().envs(env.iter().copied());
    // cargo-llvm-cov sets this so the binary saves its counters. Keeping it keeps
    // these runs in the coverage report.
    if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", profile);
    }
    let mut child = command
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn leakgc");
    let mut stderr = child.stderr.take().expect("stderr is piped");
    let reader = thread::spawn(move || {
        let mut text = String::new();
        stderr
            .read_to_string(&mut text)
            .expect("read leakgc stderr");
        text
    });

    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll leakgc") {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill hung leakgc");
            child.wait().expect("reap hung leakgc");
            panic!("leakgc did not finish within {TIMEOUT:?}");
        }
        thread::sleep(Duration::from_millis(10));
    };
    (status, reader.join().expect("stderr reader"))
}

pub static STATIC_IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
pub static DYNAMIC_IMAGE: OnceLock<Vec<u8>> = OnceLock::new();

pub fn static_image() -> &'static [u8] {
    STATIC_IMAGE.get_or_init(|| build_c("install_fake_static", &["-static", "-no-pie"]))
}

pub fn dynamic_image() -> &'static [u8] {
    DYNAMIC_IMAGE.get_or_init(|| build_c("install_fake_dynamic", &["-no-pie"]))
}

/// A copy of `image` whose function symbol `name` no longer has that name, by
/// changing the first byte of its entry in `.strtab`. Linkers share the tail of
/// one name with another, so the bytes `name\0` may not occur on their own.
pub fn without_function_name(image: &[u8], name: &str) -> Vec<u8> {
    let elf = Elf::parse(image).expect("test image parses");
    let sym = elf
        .syms
        .iter()
        .find(|sym| sym.is_function() && elf.strtab.get_at(sym.st_name) == Some(name))
        .expect("symbol present");
    let strtab = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".strtab"))
        .expect(".strtab present");
    let mut out = image.to_vec();
    out[strtab.sh_offset as usize + sym.st_name] = b'x';
    out
}

/// A copy of `image` with the first occurrence of the symbol name `from`
/// replaced by `to`, which must be the same length.
pub fn with_renamed_symbol(image: &[u8], from: &str, to: &str) -> Vec<u8> {
    assert_eq!(from.len(), to.len());
    let needle = format!("\0{from}\0");
    let at = image
        .windows(needle.len())
        .position(|window| window == needle.as_bytes())
        .expect("name present")
        + 1;
    let mut out = image.to_vec();
    out[at..at + to.len()].copy_from_slice(to.as_bytes());
    out
}

/// A copy of `image` whose named section no longer has `SHF_EXECINSTR`.
pub fn without_exec_flag(image: &[u8], name: &str) -> Vec<u8> {
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

pub fn function_symbol(image: &[u8], name: &str) -> u64 {
    let elf = Elf::parse(image).expect("test image parses");
    elf.syms
        .iter()
        .find(|sym| sym.is_function() && elf.strtab.get_at(sym.st_name) == Some(name))
        .expect("symbol present")
        .st_value
}

/// Where the patch goes for `malloc`: after `endbr64` when it is present.
pub fn patch_point(fake: &Fake, malloc: u64) -> u64 {
    if fake.bytes(malloc, ENDBR64.len()) == ENDBR64 {
        malloc + ENDBR64.len() as u64
    } else {
        malloc
    }
}

pub const LIBRARY_BASE: u64 = 0x7f00_0000_0000;
pub const LIBRARY_PATH: &str = "/fake/libc.so.6";
pub const LIBRARY_INODE: u64 = 42;
pub const PAGE: u64 = 0x1000;
/// The rel32 reach that the install's hook region must lie within.
pub const REL32_WINDOW: u64 = 0x7000_0000;

pub static LIBRARY_IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
pub static STRIPPED_LIBRARY_IMAGE: OnceLock<Vec<u8>> = OnceLock::new();

fn build_library(out_name: &str, flags: &[&str]) -> Vec<u8> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake_libc.c");
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join(out_name);
    let status = Command::new("cc")
        .args(["-O0", "-shared", "-fPIC", "-Wl,-soname,libc.so.6"])
        .arg(&src)
        .arg("-o")
        .arg(&out)
        .args(flags)
        .status()
        .expect("run cc");
    assert!(status.success(), "cc failed for {out_name}");
    std::fs::read(&out).expect("read the built library")
}

/// A shared object named `libc.so.6` with its symbol table.
pub fn library_image() -> &'static [u8] {
    LIBRARY_IMAGE.get_or_init(|| build_library("fake_libc", &[]))
}

/// The same library with its symbol table removed, as distributions ship it.
pub fn stripped_library_image() -> &'static [u8] {
    STRIPPED_LIBRARY_IMAGE.get_or_init(|| build_library("fake_libc_stripped", &["-Wl,--strip-all"]))
}

/// Adds one `/proc/<pid>/maps` line for a file mapping.
pub fn map_file(
    fake: &mut Fake,
    start: u64,
    end: u64,
    perms: &str,
    offset: u64,
    inode: u64,
    path: &str,
) {
    fake.maps.push_str(&format!(
        "{start:x}-{end:x} {perms} {offset:08x} 08:01 {inode} {path}\n"
    ));
}

/// The page-rounded length of the mapping that `map_library` makes for `image`.
pub fn library_len(image: &[u8]) -> u64 {
    let elf = Elf::parse(image).expect("library parses");
    elf.section_headers
        .iter()
        .filter(|sh| sh.sh_flags & u64::from(SHF_ALLOC) != 0)
        .map(|sh| sh.sh_addr + sh.sh_size)
        .max()
        .unwrap_or(0)
        .next_multiple_of(PAGE)
}

/// A load base for `image` that puts the install's hook region at `DEFAULT_HINT`,
/// the address that the record helpers in this module assume.
pub fn library_base_at_hint(image: &[u8]) -> u64 {
    DEFAULT_HINT + REL32_WINDOW - library_len(image)
}

/// Maps `image` at `base` as one mapping of `path`, and makes the file readable
/// under that path. Only the loaded sections are written to memory, at their
/// addresses, as the dynamic loader leaves them.
pub fn map_library(fake: &mut Fake, image: &[u8], base: u64, inode: u64, path: &str, perms: &str) {
    let elf = Elf::parse(image).expect("library parses");
    let loaded = || {
        elf.section_headers
            .iter()
            .filter(|sh| sh.sh_flags & u64::from(SHF_ALLOC) != 0)
    };
    map_file(fake, base, base + library_len(image), perms, 0, inode, path);
    for sh in loaded().filter(|sh| sh.sh_type == SHT_PROGBITS) {
        let start = sh.sh_offset as usize;
        let end = start + sh.sh_size as usize;
        fake.poke(base + sh.sh_addr, &image[start..end]);
    }
    fake.files.insert(path.to_string(), (inode, image.to_vec()));
}

/// A dynamically linked tracee, with `mmap` returning the address it asks for.
/// The install needs that, since a real kernel honours the hint it is given.
pub fn dynamic_fake(waits: Vec<nix::Result<WaitStatus>>) -> Fake {
    let mut fake = Fake::new(dynamic_image(), waits);
    fake.mmap_echoes_hint = true;
    fake
}
