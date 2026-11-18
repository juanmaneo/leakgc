//! Install planning for the E4 entry hooks (PLAN 4.6).
//!
//! Everything here is pure. It reads the bytes of one function and decides
//! whether a 5-byte `jmp rel32` may be written at its entry point, and what the
//! displaced instructions become when they move into a trampoline. It never
//! touches a process. A refusal leaves that entry point fail-closed: its blocks
//! are never freed.

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
    /// An instruction in the function does not decode.
    Undecodable { at: u64 },
    /// The function ends before the displaced instructions cover `JMP_LEN` bytes.
    ShortPatch,
    /// A near branch in the function lands inside the patched bytes (R19).
    BranchIntoPatch { at: u64, target: u64 },
    /// A displaced instruction is a call. Its return address would point into
    /// the trampoline, not into the original code.
    CallInPatch { at: u64 },
    /// The displaced instructions cannot be re-encoded at the trampoline address.
    Relocation,
}

/// A checked patch: where the jump is written and which instructions it displaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Address of the `jmp rel32`. It is `addr + 4` when the function starts
    /// with `endbr64`, so the CET marker stays in place.
    pub patch_at: u64,
    /// Bytes covered by the displaced whole instructions, always at least `JMP_LEN`.
    pub patch_len: usize,
    displaced: Vec<Instruction>,
}

/// Checks the function at `addr`, whose bytes are `function`, and returns the
/// patch plan or the reason to refuse. `function` must cover the whole symbol,
/// and the scan for branches is limited to it (see D29).
pub fn plan(addr: u64, function: &[u8]) -> Result<Plan, Refusal> {
    let patch_at = if function.starts_with(&ENDBR64) {
        addr + ENDBR64.len() as u64
    } else {
        addr
    };

    let mut insns = Vec::new();
    let mut decoder = Decoder::with_ip(64, function, addr, DecoderOptions::NONE);
    while decoder.can_decode() {
        let ins = decoder.decode();
        if ins.is_invalid() {
            return Err(Refusal::Undecodable { at: ins.ip() });
        }
        insns.push(ins);
    }

    let patch_end = patch_at + JMP_LEN as u64;
    for ins in &insns {
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

    Ok(Plan {
        patch_at,
        patch_len,
        displaced,
    })
}

impl Plan {
    /// Re-encodes the displaced instructions so they run at `new_ip`, the
    /// trampoline address. Branch and rip-relative operands keep their absolute
    /// targets, and the encoder picks the displacement for the new address. A
    /// rip-relative target that is out of rel32 reach but fits in 32 bits gets an
    /// address-size prefix (0x67). The effective address is unchanged.
    pub fn relocate(&self, new_ip: u64) -> Result<Vec<u8>, Refusal> {
        BlockEncoder::encode(
            64,
            InstructionBlock::new(&self.displaced, new_ip),
            BlockEncoderOptions::NONE,
        )
        .map(|encoded| encoded.code_buffer)
        .map_err(|_| Refusal::Relocation)
    }
}

/// The `jmp rel32` at `from` that lands on `to`, or `None` if `to` is out of reach.
pub fn jmp_rel32(from: u64, to: u64) -> Option<[u8; JMP_LEN]> {
    let disp = i128::from(to) - i128::from(from) - JMP_LEN as i128;
    let disp = i32::try_from(disp).ok()?;
    let mut out = [0xe9, 0, 0, 0, 0];
    out[1..].copy_from_slice(&disp.to_le_bytes());
    Some(out)
}
