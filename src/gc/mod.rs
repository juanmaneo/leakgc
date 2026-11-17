//! Simulated heap with explicit roots, tri-color mark and sweep, and
//! Valgrind-style reporting. Blocks are bookkeeping records, never real memory.

mod alloc;
mod collect;
mod mark;
mod sweep;

use std::collections::{BTreeMap, BTreeSet};

pub use sweep::{LeakReport, SiteLoss};

pub type BlockId = u64;

/// One simulated allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub id: BlockId,
    pub size: u64,
    /// Allocation call-site, the stand-in for a Valgrind stack trace.
    pub site: String,
    /// Outgoing edges. Never contains duplicates.
    pub refs: Vec<BlockId>,
    pub marked: bool,
    pub freed: bool,
}

/// Heap state, held as a value so that tests and callers can own several
/// independent heaps.
#[derive(Debug, Default)]
pub struct Heap {
    blocks: BTreeMap<BlockId, Block>,
    roots: BTreeSet<BlockId>,
    next_id: BlockId,
    bytes_allocated: u64,
    collections: u64,
}

impl Heap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn block(&self, id: BlockId) -> Option<&Block> {
        self.blocks.get(&id)
    }

    /// Live blocks in ascending id order.
    pub fn blocks(&self) -> impl Iterator<Item = &Block> {
        self.blocks.values()
    }

    /// Root ids in ascending order.
    pub fn roots(&self) -> impl Iterator<Item = BlockId> {
        self.roots.iter().copied()
    }

    /// Total bytes ever allocated, including blocks since freed.
    pub fn bytes_allocated(&self) -> u64 {
        self.bytes_allocated
    }

    pub fn collections(&self) -> u64 {
        self.collections
    }
}
