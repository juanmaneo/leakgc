//! Install planning for the E4 entry hooks (PLAN 4.6).
//!
//! Everything here is pure. It reads the bytes of one function and of the
//! image's executable sections, and decides whether a 5-byte `jmp rel32` may be
//! written at its entry point. It also produces the displaced instructions,
//! re-encoded for the address where they will run. It never touches a process.
//! A refusal leaves that entry point fail-closed: its blocks are never freed.

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Decoder, DecoderOptions, Instruction, InstructionBlock,
    Mnemonic, OpKind,
};

/// Length of the `jmp rel32` written at the entry point.
pub const JMP_LEN: usize = 5;

const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];

/// Why an entry point is not hooked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// An instruction in the function or its executable sections does not decode.
    Undecodable { at: u64 },
    /// The function ends before the displaced instructions cover `JMP_LEN` bytes.
    ShortPatch,
    /// A near branch lands inside the patched bytes (R19).
    BranchIntoPatch { at: u64, target: u64 },
    /// A displaced instruction is a call. Its return address would point into
    /// the trampoline, not into the original code.
    CallInPatch { at: u64 },
    /// The displaced instructions cannot be re-encoded at their new address.
    Relocation,
    /// The `jmp rel32` at the entry point cannot reach the trampoline.
    OutOfReach,
}

/// A checked patch: where the jump goes, and what replaces the displaced code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Address of the `jmp rel32`. It is `addr + 4` when the function starts
    /// with `endbr64`, so the CET marker stays in place.
    pub patch_at: u64,
    /// Bytes covered by the displaced whole instructions, always at least `JMP_LEN`.
    pub patch_len: usize,
    /// The `jmp rel32` written at `patch_at`, which lands on the trampoline.
    pub jump: [u8; JMP_LEN],
    /// The displaced instructions, re-encoded to run at `displaced_at`.
    pub displaced_code: Vec<u8>,
}

/// Checks the function at `addr` and returns the patch plan or the reason to
/// refuse.
///
/// `function` holds the bytes of the whole symbol. `text` holds the image's
/// executable sections as `(address, bytes)`. Every byte in them must decode, and
/// no near branch in them may land inside the patched bytes, so the scan covers
/// all of `.text` and not only the function (D29). `entry` is where the jump
/// lands. `displaced_at` is where the displaced instructions will run.
pub fn plan(
    addr: u64,
    function: &[u8],
    text: &[(u64, &[u8])],
    entry: u64,
    displaced_at: u64,
) -> Result<Plan, Refusal> {
    let patch_at = if function.starts_with(&ENDBR64) {
        addr + ENDBR64.len() as u64
    } else {
        addr
    };
    let patch_end = patch_at + JMP_LEN as u64;

    let mut insns = Vec::new();
    let mut decoder = Decoder::with_ip(64, function, addr, DecoderOptions::NONE);
    while decoder.can_decode() {
        let ins = decoder.decode();
        if ins.is_invalid() {
            return Err(Refusal::Undecodable { at: ins.ip() });
        }
        insns.push(ins);
    }

    for &(start, code) in text {
        let mut decoder = Decoder::with_ip(64, code, start, DecoderOptions::NONE);
        while decoder.can_decode() {
            let ins = decoder.decode();
            if ins.is_invalid() {
                return Err(Refusal::Undecodable { at: ins.ip() });
            }
            branch_into_patch(&ins, patch_at, patch_end)?;
        }
    }
    for ins in &insns {
        branch_into_patch(ins, patch_at, patch_end)?;
    }

    let mut displaced = Vec::new();
    let mut patch_len = 0;
    for ins in insns.iter().filter(|ins| ins.ip() >= patch_at) {
        if patch_len >= JMP_LEN {
            break;
        }
        if ins.mnemonic() == Mnemonic::Call {
            return Err(Refusal::CallInPatch { at: ins.ip() });
        }
        displaced.push(*ins);
        patch_len += ins.len();
    }
    if patch_len < JMP_LEN {
        return Err(Refusal::ShortPatch);
    }

    let jump = jmp_rel32(patch_at, entry).ok_or(Refusal::OutOfReach)?;

    // Branch and rip-relative operands keep their absolute targets. A
    // rip-relative target that is out of rel32 reach but fits in 32 bits gets an
    // address-size prefix (0x67), and its effective address is unchanged.
    let displaced_code = BlockEncoder::encode(
        64,
        InstructionBlock::new(&displaced, displaced_at),
        BlockEncoderOptions::NONE,
    )
    .map(|encoded| encoded.code_buffer)
    .map_err(|_| Refusal::Relocation)?;

    Ok(Plan {
        patch_at,
        patch_len,
        jump,
        displaced_code,
    })
}

fn branch_into_patch(ins: &Instruction, patch_at: u64, patch_end: u64) -> Result<(), Refusal> {
    let near = matches!(
        ins.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    );
    if near {
        let target = ins.near_branch_target();
        // The patch itself starts at `patch_at`, so a branch there is safe.
        if target > patch_at && target < patch_end {
            return Err(Refusal::BranchIntoPatch {
                at: ins.ip(),
                target,
            });
        }
    }
    Ok(())
}

/// The `jmp rel32` at `from` that lands on `to`, or `None` if `to` is out of reach.
pub fn jmp_rel32(from: u64, to: u64) -> Option<[u8; JMP_LEN]> {
    let disp = i128::from(to) - i128::from(from) - JMP_LEN as i128;
    let disp = i32::try_from(disp).ok()?;
    let mut out = [0xe9, 0, 0, 0, 0];
    out[1..].copy_from_slice(&disp.to_le_bytes());
    Some(out)
}
