//! Which outstanding blocks a stopped process still reaches (P4b). Report only:
//! nothing is freed from here.
//!
//! The roots are the registers and every writable mapping, with three
//! exclusions. The hook region is skipped, because its records hold the
//! pointers the ledger was built from. Outstanding blocks are skipped, so a
//! block is kept only by something outside the heap bookkeeping, and a leaked
//! block that points at another block does not keep it alive. Below the stack
//! pointer only the red zone is scanned, because the rest is dead stack.
//!
//! Caveats, before any freeing (P5): words are read at 8-byte alignment, so a
//! pointer at an odd offset is not seen. A block whose memory is not inside
//! one writable mapping is never read, so it is never a source of references.

use std::collections::BTreeSet;
use std::io;
use std::ops::Range;

use libc::user_regs_struct;
use nix::unistd::Pid;

use crate::gc::conservative::{Object, Words, mark};
use crate::maps::writable_ranges;
use crate::supervisor::Tracer;

/// The x86-64 red zone: leaf functions may keep live data this far below `rsp`.
const RED_ZONE: u64 = 128;
/// The most bytes read in one request, so a large mapping is read in pieces.
const CHUNK: u64 = 64 * 1024;

/// The start addresses of the blocks that a root or a reached block points into.
/// `blocks` holds `(start, size)` pairs of outstanding blocks and may be in any
/// order. `hook` is the hook region, which is never read. Returns `Err` with a
/// reason when the result cannot be trusted, and the caller must not claim one.
pub fn reachable<T: Tracer>(
    tracer: &mut T,
    pid: Pid,
    hook: Range<u64>,
    blocks: &[(u64, u64)],
) -> Result<BTreeSet<u64>, String> {
    let maps = tracer
        .read_maps(pid)
        .map_err(|error| format!("cannot read the memory map: {error}"))?;
    let mut writable = writable_ranges(&maps)
        .filter(|ranges| !ranges.is_empty())
        .ok_or("the memory map cannot be parsed")?;
    writable.sort_unstable();
    let regs = tracer
        .regs(pid)
        .map_err(|error| format!("cannot read the registers: {error}"))?;

    let mut blocks = blocks.to_vec();
    blocks.sort_unstable();
    if blocks
        .windows(2)
        .any(|pair| pair[0].0.saturating_add(pair[0].1.max(1)) > pair[1].0)
    {
        return Err("outstanding blocks overlap".to_string());
    }
    let mut excluded: Vec<(u64, u64)> = blocks
        .iter()
        .map(|&(start, size)| (start, start.saturating_add(size.max(1))))
        .collect();
    excluded.push((hook.start, hook.end));
    excluded.sort_unstable();
    let excluded = coalesce(excluded);

    let mut roots = vec![Words::Read(register_words(&regs))];
    for (start, end) in root_ranges(&writable, regs.rsp, &excluded) {
        let mut at = start;
        while at < end {
            let len = (end - at).min(CHUNK);
            let words = words(tracer, pid, at, len).map_err(|error| {
                format!("a writable range could not be read at 0x{at:x}: {error}")
            })?;
            roots.push(Words::Read(words));
            at += len;
        }
    }

    let objects: Vec<Object> = blocks
        .iter()
        .map(|&(start, size)| Object {
            start,
            size,
            words: block_words(tracer, pid, &writable, start, size),
        })
        .collect();
    mark(&roots, &objects).map_err(|_| "a reached block could not be read".to_string())
}

/// Every register field that can hold a pointer: all 27 of `user_regs_struct`.
fn register_words(regs: &user_regs_struct) -> Vec<u64> {
    vec![
        regs.r15,
        regs.r14,
        regs.r13,
        regs.r12,
        regs.rbp,
        regs.rbx,
        regs.r11,
        regs.r10,
        regs.r9,
        regs.r8,
        regs.rax,
        regs.rcx,
        regs.rdx,
        regs.rsi,
        regs.rdi,
        regs.orig_rax,
        regs.rip,
        regs.cs,
        regs.eflags,
        regs.rsp,
        regs.ss,
        regs.fs_base,
        regs.gs_base,
        regs.ds,
        regs.es,
        regs.fs,
        regs.gs,
    ]
}

/// The word-aligned address ranges to scan as roots: the writable mappings
/// minus the excluded intervals. In the mapping that holds `rsp`, scanning
/// starts at the red zone.
fn root_ranges(writable: &[(u64, u64)], rsp: u64, excluded: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    for &(start, end) in writable {
        let start = if (start..end).contains(&rsp) {
            rsp.saturating_sub(RED_ZONE).max(start)
        } else {
            start
        };
        for (start, end) in uncovered(start, end, excluded) {
            // Rounding outwards only scans more, which keeps more blocks alive.
            out.push((start & !7, end.next_multiple_of(8)));
        }
    }
    out
}

/// The parts of `[start, end)` that no interval in `excluded` covers. The
/// intervals must be sorted and disjoint, as `coalesce` returns them.
fn uncovered(start: u64, end: u64, excluded: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut at = start;
    let first = excluded.partition_point(|&(_, end)| end <= start);
    for &(s, e) in &excluded[first..] {
        if s >= end {
            break;
        }
        if s > at {
            out.push((at, s));
        }
        at = at.max(e);
    }
    if at < end {
        out.push((at, end));
    }
    out
}

/// Merges sorted intervals that overlap or touch.
fn coalesce(sorted: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (start, end) in sorted {
        match out.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out
}

/// The words of one block, read only when the whole block lies in one writable
/// mapping. Any other block is unreadable, so it is never trusted as a source
/// of references.
fn block_words<T: Tracer>(
    tracer: &mut T,
    pid: Pid,
    writable: &[(u64, u64)],
    start: u64,
    size: u64,
) -> Words {
    let len = (size / 8) * 8;
    if len == 0 {
        return Words::Read(Vec::new());
    }
    let end = start.saturating_add(len);
    let index = writable.partition_point(|&(s, _)| s <= start);
    if index == 0 || end > writable[index - 1].1 {
        return Words::Unreadable;
    }
    match words(tracer, pid, start, len) {
        Ok(words) => Words::Read(words),
        Err(_) => Words::Unreadable,
    }
}

/// The 8-byte little-endian words of `len` bytes at `start`. `len` must be a multiple of 8.
fn words<T: Tracer>(tracer: &mut T, pid: Pid, start: u64, len: u64) -> io::Result<Vec<u64>> {
    let bytes = tracer.read_mem(pid, start, len as usize)?;
    let (chunks, _) = bytes.as_chunks::<8>();
    Ok(chunks
        .iter()
        .map(|chunk| u64::from_le_bytes(*chunk))
        .collect())
}
