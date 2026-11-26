//! `install_hooks` with every operating-system result scripted. The images are
//! real static and dynamic glibc binaries, so the planner sees real `malloc`,
//! `free` and `realloc` bytes. The real-process run is in `install_real.rs`.

mod common;

use goblin::elf::Elf;
use goblin::elf::program_header::PT_LOAD;
use goblin::elf::section_header::SHF_EXECINSTR;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic};
use leakgc::hook::{Refusal, jmp_rel32};
use leakgc::install::{
    DEFAULT_HINT, InstallError, Installed, install_hooks as install_hooks_with_signals,
    install_hooks_at as install_hooks_at_with_signals, install_library_hooks, uninstall,
};
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;

use common::*;

fn install_hooks(fake: &mut Fake, pid: nix::unistd::Pid) -> Result<Installed, InstallError> {
    install_hooks_with_signals(fake, pid, &mut Vec::new())
}

fn install_hooks_at(
    fake: &mut Fake,
    pid: nix::unistd::Pid,
    hint: u64,
) -> Result<Installed, InstallError> {
    install_hooks_at_with_signals(fake, pid, hint, &mut Vec::new())
}

fn install_library(fake: &mut Fake) -> Result<Option<Installed>, InstallError> {
    install_library_hooks(fake, pid(), &mut Vec::new())
}

/// A shared-object header with one loadable segment and no sections or
/// symbols, so it parses, and the segment's file offset and address are as given.
fn header_with_segment(p_offset: u64, p_vaddr: u64) -> Vec<u8> {
    let mut image = header_only(3);
    image[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    image[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
    let mut segment = vec![0u8; 56];
    segment[0..4].copy_from_slice(&PT_LOAD.to_le_bytes());
    segment[4..8].copy_from_slice(&5u32.to_le_bytes()); // read and execute
    segment[8..16].copy_from_slice(&p_offset.to_le_bytes());
    segment[16..24].copy_from_slice(&p_vaddr.to_le_bytes());
    segment[48..56].copy_from_slice(&PAGE.to_le_bytes()); // p_align
    image.extend_from_slice(&segment);
    image
}

/// A copy of `image` with the first occurrence of the symbol name `from`
/// replaced by `to`, which must be the same length.
fn with_renamed_symbol(image: &[u8], from: &str, to: &str) -> Vec<u8> {
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

/// The address and size of `.text` in a library mapped at `base`.
fn library_text(base: u64) -> u64 {
    base + text_section(library_image()).0
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
fn installs_the_jumps_last_in_hook_order() {
    let image = static_image();
    let mut fake = Fake::new(image, vec![trap(), seccomp(), trap()]);
    let rip = fake.regs.rip;

    let installed = install_hooks(&mut fake, pid()).expect("installs");

    assert_eq!(installed.base, DEFAULT_HINT);
    assert_eq!(installed.patches.len(), 10, "ten allocator entries");
    let blocks: Vec<u64> = (0..10).map(|i| i * 0x200).collect();
    let writes = &fake.writes;
    assert_eq!(writes.len(), 2 + blocks.len() + 1 + 1 + 10, "write count");
    assert_eq!(writes[0], (rip, SYSCALL.to_vec()), "syscall bytes");
    assert_eq!(writes[1].0, rip, "syscall bytes restored");
    for (i, block) in blocks.iter().enumerate() {
        let (addr, code) = &writes[2 + i];
        assert_eq!(*addr, DEFAULT_HINT + block, "entry block {i}");
        assert_eq!(code.len(), 0x200, "block {i} is written whole");
    }
    assert_eq!(writes[12].0, DEFAULT_HINT + 0x1400, "exit stub");
    assert_eq!(writes[13].0, DEFAULT_HINT + 0x1800, "trampoline");
    for (i, patch) in installed.patches.iter().enumerate() {
        let jump = jmp_rel32(patch.at, DEFAULT_HINT + blocks[i]).expect("in reach");
        assert_eq!(
            writes[14 + i],
            (patch.at, jump.to_vec()),
            "jump {i} is written last, in hook order"
        );
    }
    assert_eq!(fake.regs.rip, rip, "registers restored");
}

#[test]
fn the_trampoline_saves_calls_free_restores_and_stops_at_an_int3() {
    let image = static_image();
    let mut fake = Fake::new(image, vec![trap(), seccomp(), trap()]);
    let installed = install_hooks(&mut fake, pid()).expect("installs");
    let elf = Elf::parse(image).expect("test image parses");
    let free = elf
        .syms
        .iter()
        .find(|sym| sym.is_function() && elf.strtab.get_at(sym.st_name) == Some("free"))
        .expect("static image defines free")
        .st_value;

    assert_eq!(installed.trampoline, DEFAULT_HINT + 0x1800);
    let code = fake.bytes(
        installed.trampoline,
        (installed.stop - installed.trampoline + 1) as usize,
    );
    assert_eq!(fake.bytes(installed.stop, 1), [0xcc], "the stop is an int3");
    let mut decoder = Decoder::with_ip(64, &code, installed.trampoline, DecoderOptions::NONE);
    let mut instructions: Vec<Instruction> = Vec::new();
    while decoder.can_decode() {
        instructions.push(decoder.decode());
    }
    let mnemonics: Vec<Mnemonic> = instructions.iter().map(Instruction::mnemonic).collect();
    assert_eq!(
        mnemonics,
        [
            Mnemonic::Sub,
            Mnemonic::Mov,
            Mnemonic::Mov,
            Mnemonic::Xsave64,
            Mnemonic::Mov,
            Mnemonic::Call,
            Mnemonic::Mov,
            Mnemonic::Mov,
            Mnemonic::Xrstor64,
            Mnemonic::Add,
            Mnemonic::Int3,
        ]
    );
    assert_eq!(instructions[0].immediate32(), 0x4000, "the save window");
    for mask in [1, 2, 6, 7] {
        assert_eq!(instructions[mask].immediate32(), u32::MAX, "all state");
    }
    assert_eq!(instructions[4].immediate64(), free, "calls the hooked free");
    assert_eq!(instructions[9].immediate32(), 0x4000, "releases the window");
}

#[test]
fn the_allocator_internals_of_a_glibc_build_are_known_by_address() {
    let image = static_image();
    let mut fake = Fake::new(image, vec![trap(), seccomp(), trap()]);
    let installed = install_hooks(&mut fake, pid()).expect("installs");
    let elf = Elf::parse(image).expect("test image parses");
    let range = |name: &str| {
        let sym = elf
            .syms
            .iter()
            .find(|sym| sym.is_function() && elf.strtab.get_at(sym.st_name) == Some(name))
            .expect("static image defines the symbol");
        (sym.st_value, sym.st_value + sym.st_size)
    };

    let internal = installed
        .internal
        .expect("a glibc build has internal ranges");
    assert!(
        internal.contains(&range("_int_malloc")),
        "_int_malloc is guarded"
    );
    assert!(internal.contains(&range("free")), "free is guarded");
}

#[test]
fn an_image_without_int_malloc_has_no_internal_ranges() {
    let elf = Elf::parse(static_image()).expect("test image parses");
    let sym = elf
        .syms
        .iter()
        .find(|sym| sym.is_function() && elf.strtab.get_at(sym.st_name) == Some("_int_malloc"))
        .expect("static image defines _int_malloc");
    let strtab = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".strtab"))
        .expect(".strtab present");
    // The name also appears in .rodata as `__func__`, which the symbol does not use.
    let mut image = static_image().to_vec();
    image[strtab.sh_offset as usize + sym.st_name] = b'x';
    let mut fake = Fake::new(&image, vec![trap(), seccomp(), trap()]);

    let installed = install_hooks(&mut fake, pid()).expect("installs");

    assert_eq!(installed.internal, None);
}

#[test]
fn a_failure_at_any_call_leaves_every_jump_original() {
    let image = static_image();
    let script = || vec![trap(), seccomp(), trap()];

    let mut probe = Fake::new(image, script());
    let installed = install_hooks(&mut probe, pid()).expect("installs without a failure");
    let total = probe.calls;

    for k in 0..total {
        let mut fake = Fake::new(image, script());
        fake.fail_at = Some(k);
        let result = install_hooks(&mut fake, pid());
        assert!(
            matches!(result, Err(InstallError::Io(_) | InstallError::Os(_))),
            "failing call {k} of {total} gave {result:?}"
        );
        for patch in &installed.patches {
            assert_eq!(
                fake.bytes(patch.at, patch.original.len()),
                patch.original.to_vec(),
                "failing call {k} left a jump at {:#x}",
                patch.at
            );
        }
    }
}

#[test]
fn uninstall_restores_the_original_bytes_of_every_jump() {
    let image = static_image();
    let mut fake = Fake::new(image, vec![trap(), seccomp(), trap()]);
    let before = fake.mem.clone();
    let installed = install_hooks(&mut fake, pid()).expect("installs");

    uninstall(&mut fake, pid(), &installed).expect("uninstalls");

    for patch in &installed.patches {
        let original: Vec<u8> = (0..5).map(|i| before[&(patch.at + i)]).collect();
        assert_eq!(fake.bytes(patch.at, 5), original, "jump at {:#x}", patch.at);
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

    let result = install_hooks(&mut fake, pid());

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

    let result = install_hooks(&mut fake, pid());

    assert!(
        matches!(result, Err(InstallError::MmapFailed(0x2000_0000))),
        "got {result:?}"
    );
    assert!(fake.writes.iter().all(|(addr, _)| *addr != DEFAULT_HINT));
}

#[test]
fn a_signal_during_the_exec_step_is_deferred_until_install_finishes() {
    let image = static_image();
    let mut fake = Fake::new(
        image,
        vec![stopped(Signal::SIGWINCH), trap(), trap(), trap()],
    );
    let mut signals = Vec::new();

    let result = install_hooks_with_signals(&mut fake, pid(), &mut signals);

    assert!(result.is_ok(), "got {result:?}");
    assert_eq!(signals, [Signal::SIGWINCH]);
}

#[test]
fn an_unexpected_stop_during_the_exec_step_is_refused() {
    let image = static_image();
    let mut fake = Fake::new(
        image,
        vec![Ok(WaitStatus::PtraceEvent(
            pid(),
            Signal::SIGTRAP,
            libc::PTRACE_EVENT_EXEC,
        ))],
    );

    let result = install_hooks(&mut fake, pid());

    assert!(matches!(result, Err(InstallError::UnexpectedStop(_))));
}

#[test]
fn a_non_signal_stop_other_than_the_syscall_trap_is_refused() {
    let image = static_image();
    let mut fake = Fake::new(
        image,
        vec![
            trap(),
            Ok(WaitStatus::PtraceEvent(
                pid(),
                Signal::SIGTRAP,
                libc::PTRACE_EVENT_EXEC,
            )),
        ],
    );

    let result = install_hooks(&mut fake, pid());

    assert!(
        matches!(result, Err(InstallError::UnexpectedStop(_))),
        "got {result:?}"
    );
    assert_eq!(fake.writes.len(), 2, "the syscall bytes are still restored");
}

#[test]
fn a_target_sigtrap_is_distinguished_from_the_single_step_trap() {
    let image = static_image();
    let mut fake = Fake::new(
        image,
        vec![stopped(Signal::SIGTRAP), trap(), seccomp(), trap()],
    );
    fake.single_step_results
        .extend([Ok(false), Ok(true), Ok(true)]);
    let mut signals = Vec::new();

    let result = install_hooks_with_signals(&mut fake, pid(), &mut signals);

    assert!(result.is_ok(), "got {result:?}");
    assert_eq!(signals, [Signal::SIGTRAP]);
}

#[test]
fn a_target_sigtrap_during_the_injected_syscall_is_carried() {
    let image = static_image();
    let mut fake = Fake::new(image, vec![trap(), trap(), trap()]);
    fake.single_step_results
        .extend([Ok(true), Ok(false), Ok(true)]);
    let mut signals = Vec::new();

    let result = install_hooks_with_signals(&mut fake, pid(), &mut signals);

    assert!(result.is_ok(), "got {result:?}");
    assert_eq!(signals, [Signal::SIGTRAP]);
}

#[test]
fn a_siginfo_error_aborts_the_install_and_restores_the_target() {
    let image = static_image();
    let mut fake = Fake::new(image, vec![stopped(Signal::SIGTRAP)]);
    fake.single_step_results
        .push_back(Err(nix::errno::Errno::EIO));
    let mut signals = Vec::new();

    let result = install_hooks_with_signals(&mut fake, pid(), &mut signals);

    assert!(matches!(
        result,
        Err(InstallError::Os(nix::errno::Errno::EIO))
    ));
    assert_eq!(signals, [Signal::SIGTRAP]);
}

#[test]
fn a_siginfo_error_during_the_injected_syscall_keeps_sigtrap_pending() {
    let image = static_image();
    let mut fake = Fake::new(image, vec![trap(), trap()]);
    fake.single_step_results
        .extend([Ok(true), Err(nix::errno::Errno::EIO)]);
    let mut signals = Vec::new();

    let result = install_hooks_with_signals(&mut fake, pid(), &mut signals);

    assert!(matches!(
        result,
        Err(InstallError::Os(nix::errno::Errno::EIO))
    ));
    assert_eq!(signals, [Signal::SIGTRAP]);
    assert_eq!(fake.writes.len(), 2, "the injected bytes are restored");
}

#[test]
fn a_step_error_after_a_target_sigtrap_keeps_the_signal_and_restores_state() {
    let image = static_image();
    let mut fake = Fake::new(image, vec![trap(), stopped(Signal::SIGTRAP)]);
    fake.single_step_results.extend([Ok(true), Ok(false)]);
    fake.step_results
        .extend([Ok(()), Ok(()), Err(nix::errno::Errno::EIO)]);
    let mut signals = Vec::new();

    let result = install_hooks_with_signals(&mut fake, pid(), &mut signals);

    assert!(matches!(
        result,
        Err(InstallError::Os(nix::errno::Errno::EIO))
    ));
    assert_eq!(signals, [Signal::SIGTRAP]);
    assert_eq!(fake.writes.len(), 2, "the injected bytes are restored");
}

#[test]
fn a_step_error_after_a_non_trap_signal_preserves_it_and_restores_state() {
    let image = static_image();
    let mut fake = Fake::new(image, vec![trap(), stopped(Signal::SIGTERM)]);
    fake.step_results
        .extend([Ok(()), Ok(()), Err(nix::errno::Errno::EIO)]);
    let mut signals = Vec::new();

    let result = install_hooks_with_signals(&mut fake, pid(), &mut signals);

    assert!(matches!(
        result,
        Err(InstallError::Os(nix::errno::Errno::EIO))
    ));
    assert_eq!(signals, [Signal::SIGTERM]);
    assert_eq!(fake.writes.len(), 2, "the injected bytes are restored");
}

#[test]
fn a_signal_during_the_injected_syscall_is_carried_even_if_install_later_fails() {
    let image = static_image();
    let mut fake = Fake::new(
        image,
        vec![trap(), seccomp(), stopped(Signal::SIGTERM), trap()],
    );
    fake.mmap_result = -17;
    let mut signals = Vec::new();

    let result = install_hooks_with_signals(&mut fake, pid(), &mut signals);

    assert!(matches!(result, Err(InstallError::MmapFailed(-17))));
    assert_eq!(signals, [Signal::SIGTERM]);
    assert_eq!(fake.writes.len(), 2, "the injected bytes are restored");
}

#[test]
fn four_seccomp_stops_are_allowed_and_a_fifth_is_refused() {
    let image = static_image();

    let mut allowed = Fake::new(
        image,
        vec![trap(), seccomp(), seccomp(), seccomp(), seccomp(), trap()],
    );
    assert!(install_hooks(&mut allowed, pid()).is_ok());

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
    let result = install_hooks(&mut refused, pid());
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

    let result = install_hooks(&mut fake, pid());

    assert!(
        matches!(result, Err(InstallError::SyscallIncomplete { rip: got }) if got == rip),
        "got {result:?}"
    );
}

#[test]
fn a_hint_beyond_rel32_reach_is_refused_before_anything_is_written() {
    let image = static_image();
    let mut fake = Fake::new(image, vec![]);

    let result = install_hooks_at(&mut fake, pid(), 1 << 40);

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
        refusal(install_hooks(&mut fake, pid())),
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
        refusal(install_hooks(&mut fake, pid())),
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
        refusal(install_hooks(&mut fake, pid())),
        Refusal::BranchIntoPatch {
            at: site.ip(),
            target: patch + 1,
        }
    );
}

#[test]
fn a_header_without_malloc_is_refused() {
    let mut fake = Fake::new(&header_only(2), vec![]);

    let result = install_hooks(&mut fake, pid());

    assert!(
        matches!(result, Err(InstallError::MissingSymbol("malloc"))),
        "got {result:?}"
    );
}

#[test]
fn a_malloc_outside_every_executable_section_is_refused() {
    let image = without_exec_flag(static_image(), ".text");
    let mut fake = Fake::new(&image, vec![]);

    let result = install_hooks(&mut fake, pid());

    assert!(
        matches!(result, Err(InstallError::MissingSymbol("malloc"))),
        "got {result:?}"
    );
}

#[test]
fn a_position_independent_image_is_not_static() {
    let mut fake = Fake::new(&header_only(3), vec![]);

    let result = install_hooks(&mut fake, pid());

    assert!(
        matches!(result, Err(InstallError::NotStaticExecutable)),
        "got {result:?}"
    );
}

#[test]
fn a_dynamic_image_is_refused_by_the_static_install() {
    let mut fake = Fake::new(dynamic_image(), vec![]);

    let result = install_hooks(&mut fake, pid());

    assert!(
        matches!(result, Err(InstallError::Dynamic)),
        "got {result:?}"
    );
}

#[test]
fn a_mapped_library_is_hooked_within_reach_of_its_code() {
    let mut fake = dynamic_fake(vec![trap(), seccomp(), trap()]);
    map_library(
        &mut fake,
        library_image(),
        LIBRARY_BASE,
        LIBRARY_INODE,
        LIBRARY_PATH,
        "r-xp",
    );

    let installed = install_library(&mut fake)
        .expect("installs")
        .expect("the library is mapped");

    assert_eq!(installed.patches.len(), 10);
    assert!(installed.base.abs_diff(LIBRARY_BASE) < 0x7000_0000);
    for patch in &installed.patches {
        assert_eq!(fake.at(patch.at), 0xe9, "jump at {:#x}", patch.at);
    }
    let int_malloc = LIBRARY_BASE + function_symbol(library_image(), "_int_malloc");
    assert!(
        installed
            .internal
            .is_some_and(|ranges| ranges.iter().any(|&(start, _)| start == int_malloc))
    );
    assert_eq!(fake.writes.len(), 24);
}

#[test]
fn a_stripped_library_is_hooked_without_internal_ranges() {
    let mut fake = dynamic_fake(vec![trap(), seccomp(), trap()]);
    map_library(
        &mut fake,
        stripped_library_image(),
        LIBRARY_BASE,
        LIBRARY_INODE,
        LIBRARY_PATH,
        "r-xp",
    );

    let installed = install_library(&mut fake)
        .expect("installs")
        .expect("the library is mapped");

    assert_eq!(installed.patches.len(), 10);
    assert!(installed.internal.is_none());
}

#[test]
fn a_library_without_an_executable_mapping_is_not_hooked_yet() {
    let mut fake = dynamic_fake(vec![]);
    map_library(
        &mut fake,
        library_image(),
        LIBRARY_BASE,
        LIBRARY_INODE,
        LIBRARY_PATH,
        "r--p",
    );

    let result = install_library(&mut fake).expect("no error");

    assert!(result.is_none());
    assert!(fake.writes.is_empty());
}

#[test]
fn a_library_that_is_not_mapped_is_not_hooked_yet() {
    let mut fake = dynamic_fake(vec![]);

    let result = install_library(&mut fake).expect("no error");

    assert!(result.is_none());
    assert!(fake.writes.is_empty());
}

#[test]
fn a_library_replaced_on_disk_is_refused() {
    let mut fake = dynamic_fake(vec![]);
    map_library(
        &mut fake,
        library_image(),
        LIBRARY_BASE,
        LIBRARY_INODE,
        LIBRARY_PATH,
        "r-xp",
    );
    fake.files.insert(
        LIBRARY_PATH.to_string(),
        (LIBRARY_INODE + 1, library_image().to_vec()),
    );

    let result = install_library(&mut fake);

    assert!(
        matches!(result, Err(InstallError::LibraryChanged(reason)) if reason == "the file on disk is not the file that is mapped"),
        "got {result:?}"
    );
    assert!(fake.writes.is_empty());
}

#[test]
fn live_library_code_that_differs_from_the_file_is_refused() {
    let mut fake = dynamic_fake(vec![]);
    map_library(
        &mut fake,
        library_image(),
        LIBRARY_BASE,
        LIBRARY_INODE,
        LIBRARY_PATH,
        "r-xp",
    );
    let text = library_text(LIBRARY_BASE);
    let flipped = fake.at(text) ^ 0xff;
    fake.poke(text, &[flipped]);

    let result = install_library(&mut fake);

    assert!(
        matches!(result, Err(InstallError::LibraryChanged(reason)) if reason == "the mapped code differs from the file"),
        "got {result:?}"
    );
    assert!(fake.writes.is_empty());
}

#[test]
fn a_mapped_library_whose_file_is_missing_is_an_io_error() {
    let mut fake = dynamic_fake(vec![]);
    map_file(
        &mut fake,
        LIBRARY_BASE,
        LIBRARY_BASE + PAGE,
        "r-xp",
        0,
        LIBRARY_INODE,
        LIBRARY_PATH,
    );

    let result = install_library(&mut fake);

    assert!(matches!(result, Err(InstallError::Io(_))), "got {result:?}");
}

#[test]
fn a_mapped_library_whose_file_does_not_parse_is_a_parse_error() {
    let mut fake = dynamic_fake(vec![]);
    map_file(
        &mut fake,
        LIBRARY_BASE,
        LIBRARY_BASE + PAGE,
        "r-xp",
        0,
        LIBRARY_INODE,
        LIBRARY_PATH,
    );
    fake.files
        .insert(LIBRARY_PATH.to_string(), (LIBRARY_INODE, b"junk".to_vec()));

    let result = install_library(&mut fake);

    assert!(
        matches!(result, Err(InstallError::Parse(_))),
        "got {result:?}"
    );
}

#[test]
fn a_library_with_no_segment_at_file_offset_zero_is_refused() {
    let mut fake = dynamic_fake(vec![]);
    map_file(
        &mut fake,
        LIBRARY_BASE,
        LIBRARY_BASE + PAGE,
        "r-xp",
        0,
        LIBRARY_INODE,
        LIBRARY_PATH,
    );
    fake.files.insert(
        LIBRARY_PATH.to_string(),
        (LIBRARY_INODE, header_with_segment(PAGE, PAGE)),
    );

    let result = install_library(&mut fake);

    assert!(
        matches!(result, Err(InstallError::LibraryChanged(reason)) if reason == "no loadable segment maps file offset zero at a valid address"),
        "got {result:?}"
    );
}

#[test]
fn a_library_whose_base_would_lie_below_address_zero_is_refused() {
    let mut fake = dynamic_fake(vec![]);
    map_file(
        &mut fake,
        PAGE,
        2 * PAGE,
        "r-xp",
        0,
        LIBRARY_INODE,
        LIBRARY_PATH,
    );
    fake.files.insert(
        LIBRARY_PATH.to_string(),
        (LIBRARY_INODE, header_with_segment(0, 0x2000)),
    );

    let result = install_library(&mut fake);

    assert!(
        matches!(result, Err(InstallError::LibraryChanged(reason)) if reason == "no loadable segment maps file offset zero at a valid address"),
        "got {result:?}"
    );
}

#[test]
fn a_stripped_library_missing_a_hooked_name_is_refused() {
    let mut fake = dynamic_fake(vec![]);
    let image = with_renamed_symbol(stripped_library_image(), "realloc", "xealloc");
    map_library(
        &mut fake,
        &image,
        LIBRARY_BASE,
        LIBRARY_INODE,
        LIBRARY_PATH,
        "r-xp",
    );

    let result = install_library(&mut fake);

    assert!(
        matches!(result, Err(InstallError::MissingSymbol("realloc"))),
        "got {result:?}"
    );
    assert!(fake.writes.is_empty());
}

#[test]
fn a_library_with_no_room_in_reach_is_refused() {
    let mut fake = dynamic_fake(vec![]);
    map_library(
        &mut fake,
        library_image(),
        LIBRARY_BASE,
        LIBRARY_INODE,
        LIBRARY_PATH,
        "r-xp",
    );
    map_line(&mut fake, 0, 0x7fff_ffff_ffff, "rw-p");

    let result = install_library(&mut fake);

    assert!(
        matches!(result, Err(InstallError::NoRegion)),
        "got {result:?}"
    );
    assert!(fake.writes.is_empty());
}

#[test]
fn a_failed_read_of_the_library_code_is_an_io_error() {
    let mut fake = dynamic_fake(vec![]);
    map_library(
        &mut fake,
        library_image(),
        LIBRARY_BASE,
        LIBRARY_INODE,
        LIBRARY_PATH,
        "r-xp",
    );
    fake.fail_reads = true;

    let result = install_library(&mut fake);

    assert!(matches!(result, Err(InstallError::Io(_))), "got {result:?}");
}

#[test]
fn a_failed_maps_read_is_an_io_error() {
    let mut fake = dynamic_fake(vec![]);
    fake.fail_at = Some(0);

    let result = install_library(&mut fake);

    assert!(matches!(result, Err(InstallError::Io(_))), "got {result:?}");
}

#[test]
fn an_image_that_does_not_parse_is_refused() {
    let mut fake = Fake::new(b"not an ELF image at all", vec![]);

    let result = install_hooks(&mut fake, pid());

    assert!(
        matches!(result, Err(InstallError::Parse(_))),
        "got {result:?}"
    );
}
