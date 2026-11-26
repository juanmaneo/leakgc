use iced_x86::{Code, Decoder, DecoderOptions};
use leakgc::hook::{JMP_LEN, Plan, Refusal, jmp_rel32, plan};

const ADDR: u64 = 0x1000;
const ENTRY: u64 = 0x2000;
const DISPLACED: u64 = 0x2100;

/// Plans a function whose executable section holds nothing else.
fn plan_alone(addr: u64, function: &[u8]) -> Result<Plan, Refusal> {
    plan(addr, function, &[], ENTRY, DISPLACED)
}

#[test]
fn patch_skips_endbr64_and_displaces_whole_instructions() {
    // endbr64; test rdi,rdi; jz +0; ret
    let bytes = [0xf3, 0x0f, 0x1e, 0xfa, 0x48, 0x85, 0xff, 0x74, 0x00, 0xc3];
    let p = plan_alone(ADDR, &bytes).unwrap();
    assert_eq!((p.patch_at, p.patch_len), (ADDR + 4, 5));
}

#[test]
fn patch_starts_at_function_start_without_endbr64() {
    // test rdi,rdi; jz +0; ret
    let p = plan_alone(ADDR, &[0x48, 0x85, 0xff, 0x74, 0x00, 0xc3]).unwrap();
    assert_eq!((p.patch_at, p.patch_len), (ADDR, 5));
}

#[test]
fn displaced_region_ends_on_an_instruction_boundary() {
    // push rbx; mov rax,[rip+0x10]; ret: 1 + 7 bytes, so the patch covers 8
    let bytes = [0x53, 0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00, 0xc3];
    let p = plan_alone(ADDR, &bytes).unwrap();
    assert!(p.patch_len >= JMP_LEN);
    assert_eq!(p.patch_len, 8);
}

#[test]
fn short_function_is_refused() {
    // endbr64; ret: one byte follows the patch point
    assert_eq!(
        plan_alone(ADDR, &[0xf3, 0x0f, 0x1e, 0xfa, 0xc3]),
        Err(Refusal::ShortPatch)
    );
    // test rdi,rdi; ret: four bytes, not five
    assert_eq!(
        plan_alone(ADDR, &[0x48, 0x85, 0xff, 0xc3]),
        Err(Refusal::ShortPatch)
    );
    assert_eq!(plan_alone(ADDR, &[]), Err(Refusal::ShortPatch));
}

#[test]
fn undecodable_bytes_are_refused() {
    // 0x06 (push es) is invalid in 64-bit mode
    assert_eq!(
        plan_alone(ADDR, &[0x06, 0xc3, 0, 0, 0, 0]),
        Err(Refusal::Undecodable { at: ADDR })
    );
}

#[test]
fn undecodable_bytes_elsewhere_in_text_do_not_refuse_the_function() {
    // 0x06 is invalid, so the sweep of this section fails. Nothing branches into the patch.
    let function = [0x48, 0x85, 0xff, 0x74, 0x00, 0xc3];
    assert!(
        plan(
            ADDR,
            &function,
            &[(0x5000, &[0x06, 0xc3])],
            ENTRY,
            DISPLACED
        )
        .is_ok()
    );
}

#[test]
fn branch_hidden_behind_undecodable_bytes_into_the_patch_is_refused() {
    // 0x06 at 0x1020 stops the sweep. The jmp rel8 at 0x1021 lands on 0x1002, inside the patch.
    let function = [0x48, 0x85, 0xff, 0x74, 0x00, 0xc3];
    assert_eq!(
        plan(
            ADDR,
            &function,
            &[(0x1020, &[0x06, 0xeb, 0xdf])],
            ENTRY,
            DISPLACED
        ),
        Err(Refusal::BranchIntoPatch {
            at: 0x1021,
            target: ADDR + 2,
        })
    );
}

#[test]
fn decodable_text_elsewhere_is_accepted() {
    let function = [0x48, 0x85, 0xff, 0x74, 0x00, 0xc3];
    assert!(plan(ADDR, &function, &[(0x5000, &[0xc3])], ENTRY, DISPLACED).is_ok());
}

#[test]
fn displaced_branch_into_the_patch_is_refused() {
    // test rdi,rdi; js 0x1001; ret. The js at 0x1003 targets a displaced byte.
    let bytes = [0x48, 0x85, 0xff, 0x78, 0xfc, 0xc3];
    assert_eq!(
        plan_alone(ADDR, &bytes),
        Err(Refusal::BranchIntoPatch {
            at: ADDR + 3,
            target: ADDR + 1,
        })
    );
}

#[test]
fn branch_from_within_the_function_into_the_patch_is_refused() {
    // test rdi,rdi; jz +0; jz 0x1002; ret. The second jz at 0x1005 lands inside.
    let bytes = [0x48, 0x85, 0xff, 0x74, 0x00, 0x74, 0xfb, 0xc3];
    assert_eq!(
        plan_alone(ADDR, &bytes),
        Err(Refusal::BranchIntoPatch {
            at: ADDR + 5,
            target: ADDR + 2,
        })
    );
}

#[test]
fn branch_from_another_section_into_the_patch_is_refused() {
    // jmp 0x1002 at 0x5000 (rel32 0xffffbffd), from outside the function.
    let function = [0x48, 0x85, 0xff, 0x74, 0x00, 0xc3];
    let other = [0xe9, 0xfd, 0xbf, 0xff, 0xff];
    assert_eq!(
        plan(ADDR, &function, &[(0x5000, &other)], ENTRY, DISPLACED),
        Err(Refusal::BranchIntoPatch {
            at: 0x5000,
            target: ADDR + 2,
        })
    );
}

#[test]
fn branch_to_the_patch_start_is_allowed() {
    // test rdi,rdi; jz +0; jz 0x1000; ret
    let bytes = [0x48, 0x85, 0xff, 0x74, 0x00, 0x74, 0xf9, 0xc3];
    assert!(plan_alone(ADDR, &bytes).is_ok());
}

#[test]
fn indirect_call_in_the_patch_is_refused() {
    // call rax; nop; nop; nop; ret
    assert_eq!(
        plan_alone(ADDR, &[0xff, 0xd0, 0x90, 0x90, 0x90, 0xc3]),
        Err(Refusal::CallInPatch { at: ADDR })
    );
}

#[test]
fn direct_call_in_the_patch_becomes_push_and_jump() {
    // call +0x10 (target 0x1015); ret. The return address is 0x1005.
    let p = plan_alone(ADDR, &[0xe8, 0x10, 0x00, 0x00, 0x00, 0xc3]).unwrap();
    assert_eq!(p.patch_len, JMP_LEN);

    let mut dec = Decoder::with_ip(64, &p.displaced_code, DISPLACED, DecoderOptions::NONE);
    let push = dec.decode();
    assert_eq!(push.code(), Code::Pushq_imm32);
    assert_eq!(push.immediate32(), (ADDR + 5) as u32);
    let jump = dec.decode();
    assert_eq!(jump.code(), Code::Jmp_rel32_64);
    assert_eq!(jump.near_branch_target(), ADDR + 0x15);
    assert!(!dec.can_decode());
}

#[test]
fn relocated_call_whose_return_address_needs_more_than_31_bits_is_refused() {
    // call +0 at 0x7fff_fffb. Its return address 0x8000_0000 does not fit a sign-extended push imm32.
    assert_eq!(
        plan(
            0x7fff_fffb,
            &[0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3],
            &[],
            ENTRY,
            DISPLACED
        ),
        Err(Refusal::Relocation)
    );
}

#[test]
fn relocated_call_to_a_far_target_jumps_through_an_absolute_address() {
    // call +0x1800_0000 at 0x7000_0000 targets 0x8800_0005, which a rel32 jump at
    // 0x2100 cannot reach. The encoder emits `jmp [rip+x]` to an 8-byte address.
    let p = plan(
        0x7000_0000,
        &[0xe8, 0x00, 0x00, 0x00, 0x18, 0xc3],
        &[],
        ENTRY,
        DISPLACED,
    )
    .unwrap();

    let mut dec = Decoder::with_ip(64, &p.displaced_code, DISPLACED, DecoderOptions::NONE);
    assert_eq!(dec.decode().code(), Code::Pushq_imm32);
    let jump = dec.decode();
    assert_eq!(jump.code(), Code::Jmp_rm64);
    let slot = (jump.ip_rel_memory_address() - DISPLACED) as usize;
    let target: [u8; 8] = p.displaced_code[slot..slot + 8].try_into().unwrap();
    assert_eq!(u64::from_le_bytes(target), 0x8800_0005);
}

#[test]
fn relocation_keeps_branch_and_rip_relative_targets() {
    // jz +0x10 (target 0x1012); mov rax,[rip+0] (target 0x1009); ret
    let bytes = [0x74, 0x10, 0x48, 0x8b, 0x05, 0x00, 0x00, 0x00, 0x00, 0xc3];
    let p = plan_alone(ADDR, &bytes).unwrap();

    let mut dec = Decoder::with_ip(64, &p.displaced_code, DISPLACED, DecoderOptions::NONE);
    let jz = dec.decode();
    assert_eq!(jz.near_branch_target(), ADDR + 0x12);
    let mov = dec.decode();
    assert!(mov.is_ip_rel_memory_operand());
    assert_eq!(mov.ip_rel_memory_address(), ADDR + 9);
}

#[test]
fn relocation_fails_when_a_target_is_out_of_reach() {
    // mov rax,[rip+0x10] at 4 GiB + 0x1000 targets 4 GiB + 0x1017. Relocated to
    // 0x2100, neither a rel32 nor a 32-bit address can reach it. The jump from
    // the patch to the entry is in reach, so only relocation can fail.
    let bytes = [0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00, 0xc3];
    assert_eq!(
        plan(0x1_0000_1000, &bytes, &[], 0x1_0000_2000, DISPLACED),
        Err(Refusal::Relocation)
    );
}

#[test]
fn entry_beyond_rel32_reach_is_refused() {
    let bytes = [0x48, 0x85, 0xff, 0x74, 0x00, 0xc3];
    assert_eq!(
        plan(ADDR, &bytes, &[], 1 << 40, DISPLACED),
        Err(Refusal::OutOfReach)
    );
}

#[test]
fn jmp_rel32_encodes_forward_and_backward_targets() {
    assert_eq!(
        jmp_rel32(ADDR, ADDR + 0x100),
        Some([0xe9, 0xfb, 0x00, 0x00, 0x00])
    );
    assert_eq!(
        jmp_rel32(ADDR, 0x0f00),
        Some([0xe9, 0xfb, 0xfe, 0xff, 0xff])
    );
}

#[test]
fn jmp_rel32_refuses_targets_beyond_two_gigabytes() {
    assert_eq!(jmp_rel32(0, 1 << 40), None);
}
