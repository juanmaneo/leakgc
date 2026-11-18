//! The blocks an image still holds, built from finished hooked calls (P2b-3a).
//!
//! A block is outstanding from the call that returned it until a call frees it.
//! Nothing here checks whether a block is still reachable. That is P4.

use std::collections::BTreeMap;

use crate::ring::{Kind, Record};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Block {
    size: u64,
    caller: u64,
}

/// The blocks an image holds, keyed by pointer. `unknown_frees` counts frees of
/// pointers the ledger never saw allocated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ledger {
    live: BTreeMap<u64, Block>,
    unknown_frees: u64,
}

/// Outstanding blocks that one call site allocated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Site {
    pub caller: u64,
    pub blocks: u64,
    pub bytes: u64,
}

impl Ledger {
    /// Applies one finished call, in the order the process made it.
    pub fn apply(&mut self, record: Record) {
        match record.kind {
            Kind::Malloc => self.insert(record),
            Kind::Free => {
                if record.arg != 0 {
                    self.release(record.arg);
                }
            }
            Kind::Realloc => {
                // A failed realloc leaves its argument valid. Size zero frees it.
                if record.result == 0 && record.size != 0 {
                    return;
                }
                if record.arg != 0 {
                    self.release(record.arg);
                }
                self.insert(record);
            }
        }
    }

    fn insert(&mut self, record: Record) {
        if record.result != 0 {
            let block = Block {
                size: record.size,
                caller: record.caller,
            };
            self.live.insert(record.result, block);
        }
    }

    fn release(&mut self, ptr: u64) {
        if self.live.remove(&ptr).is_none() {
            self.unknown_frees += 1;
        }
    }

    /// Outstanding blocks grouped by the call site that allocated them, by address.
    pub fn sites(&self) -> Vec<Site> {
        let mut by_caller: BTreeMap<u64, Site> = BTreeMap::new();
        for block in self.live.values() {
            let site = by_caller.entry(block.caller).or_insert(Site {
                caller: block.caller,
                blocks: 0,
                bytes: 0,
            });
            site.blocks += 1;
            site.bytes += block.size;
        }
        by_caller.into_values().collect()
    }

    pub fn unknown_frees(&self) -> u64 {
        self.unknown_frees
    }
}

/// The report for one process image, printed when it ends (or is replaced).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReport {
    pub label: String,
    pub sites: Vec<Site>,
    pub unknown_frees: u64,
    pub notes: Vec<String>,
}

impl ImageReport {
    pub fn new(label: String, ledger: &Ledger, notes: Vec<String>) -> Self {
        ImageReport {
            label,
            sites: ledger.sites(),
            unknown_frees: ledger.unknown_frees(),
            notes,
        }
    }

    /// The report as lines of text, without the `leakgc:` prefix.
    pub fn lines(&self) -> Vec<String> {
        let blocks: u64 = self.sites.iter().map(|site| site.blocks).sum();
        let bytes: u64 = self.sites.iter().map(|site| site.bytes).sum();
        let mut lines = vec![format!(
            "{}: {blocks} blocks, {bytes} bytes outstanding (not yet checked for reachability, P4)",
            self.label
        )];
        for note in &self.notes {
            lines.push(format!("  note: {note}"));
        }
        for site in &self.sites {
            lines.push(format!(
                "  caller 0x{:x}: {} blocks, {} bytes",
                site.caller, site.blocks, site.bytes
            ));
        }
        if self.unknown_frees > 0 {
            lines.push(format!("  unknown frees: {}", self.unknown_frees));
        }
        lines
    }
}
