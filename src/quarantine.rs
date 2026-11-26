//! The quarantine (P5, D54, D41). A block that a scan finds unreached is not
//! freed at once. It is poisoned and held, and a free is allowed only after
//! it has survived one full scan cycle unchanged and still unreached.
//!
//! A held block that is reached again, changed, missing or freed by the
//! program makes the process untrusted, so nothing else is freed. Holding
//! changes the process. A block that the scan missed (R2, R3) now reads as
//! poison, which is not a canonical address, so the program faults rather
//! than corrupting silently. Reads of poison are not detected, only writes.

use std::collections::BTreeMap;
use std::io;

use nix::unistd::Pid;

use crate::reach::Scan;
use crate::supervisor::Tracer;

/// The byte a held block is filled with. Eight copies of it form a value that
/// is not a canonical x86-64 address, so a pointer read from it faults.
pub const POISON: u8 = 0xDB;
/// The most bytes read or written in one request.
const CHUNK: u64 = 64 * 1024;

/// A held block. `size` is the size it was held at, which must not change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Held {
    size: u64,
    /// Set once the block has survived one full scan cycle.
    confirmed: bool,
}

/// The blocks in quarantine, keyed by start address.
#[derive(Debug, Clone, Default)]
pub struct Quarantine {
    held: BTreeMap<u64, Held>,
}

impl Quarantine {
    /// The reason the process is untrusted if the program frees `ptr` while it
    /// is held. Such a free means the program still owned the block, so the scan
    /// missed a reference to it.
    pub fn released(&self, ptr: u64) -> Option<String> {
        self.held.get(&ptr).map(|_| {
            format!("a held block at 0x{ptr:x} was freed: the scan missed a reference to it (R2)")
        })
    }

    /// The `(start, size)` of every block that has survived a full cycle, in address order.
    pub fn confirmed(&self) -> Vec<(u64, u64)> {
        self.held
            .iter()
            .filter(|(_, held)| held.confirmed)
            .map(|(&start, held)| (start, held.size))
            .collect()
    }

    /// Checks every held block against the scan that has just finished, then
    /// holds the blocks it found unreached. `blocks` are the outstanding blocks
    /// that the scan read. Returns the reason the process is untrusted when a
    /// held block fails the check. Blocks held before the failure stay held.
    pub fn update<T: Tracer>(
        &mut self,
        tracer: &mut T,
        pid: Pid,
        blocks: &[(u64, u64)],
        scan: &Scan,
    ) -> Result<(), String> {
        let live: BTreeMap<u64, u64> = blocks.iter().copied().collect();
        for (&start, held) in &mut self.held {
            if scan.reached.contains(&start) {
                return Err(format!(
                    "a held block at 0x{start:x} is reachable again: the scan missed a reference to it (R2)"
                ));
            }
            if live.get(&start) != Some(&held.size) {
                return Err(format!(
                    "a held block at 0x{start:x} is no longer outstanding at its size"
                ));
            }
            match unchanged(tracer, pid, start, held.size) {
                Ok(true) => held.confirmed = true,
                Ok(false) => {
                    return Err(format!(
                        "a held block at 0x{start:x} was written to: the program used a block the scan missed (R2)"
                    ));
                }
                Err(error) => {
                    return Err(format!(
                        "a held block at 0x{start:x} could not be read: {error}"
                    ));
                }
            }
        }
        for &(start, size) in blocks {
            if scan.reached.contains(&start)
                || !scan.freeable.contains(&start)
                || self.held.contains_key(&start)
            {
                continue;
            }
            poison(tracer, pid, start, size).map_err(|error| {
                format!("a block at 0x{start:x} could not be poisoned: {error}")
            })?;
            self.held.insert(
                start,
                Held {
                    size,
                    confirmed: false,
                },
            );
        }
        Ok(())
    }
}

/// The `(address, length)` pieces of the span of a block, at most `CHUNK` bytes
/// each. A zero-size block has a span of one byte.
fn pieces(start: u64, size: u64) -> impl Iterator<Item = (u64, usize)> {
    let end = start.saturating_add(size.max(1));
    (start..end)
        .step_by(CHUNK as usize)
        .map(move |at| (at, (end - at).min(CHUNK) as usize))
}

/// Whether every byte of the block's span still holds `POISON`.
fn unchanged<T: Tracer>(tracer: &mut T, pid: Pid, start: u64, size: u64) -> io::Result<bool> {
    for (at, len) in pieces(start, size) {
        if tracer
            .read_mem(pid, at, len)?
            .iter()
            .any(|&byte| byte != POISON)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn poison<T: Tracer>(tracer: &mut T, pid: Pid, start: u64, size: u64) -> io::Result<()> {
    for (at, len) in pieces(start, size) {
        tracer.write_mem(pid, at, &vec![POISON; len])?;
    }
    Ok(())
}
