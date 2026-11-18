use super::{Block, BlockId, Heap, LeakReport, Mode};

/// Allocations between automatic collections. Matches `collect_every` in the oracle.
pub const COLLECT_EVERY: u64 = 64;

impl Heap {
    /// Registers a block of `size` bytes allocated at `site` and returns its id.
    /// Every `COLLECT_EVERY` allocations a collection runs first, freeing lost
    /// blocks only in `Mode::Free`; its report is queued for
    /// `take_pacing_reports`. Refs to blocks that are not live are dropped and
    /// duplicates are removed.
    pub fn alloc(&mut self, refs: &[BlockId], site: &str, size: u64) -> BlockId {
        // Pacing runs before registration. The new block is not rooted yet, so a
        // collection after registration would sweep the block this call returns.
        // The refs filter runs after it, so pointees freed by that collection are dropped.
        self.allocs_since_gc += 1;
        if self.allocs_since_gc >= COLLECT_EVERY {
            self.allocs_since_gc = 0;
            let report = self.run_collection(self.mode == Mode::Free);
            self.pacing_reports.push(report);
        }

        self.next_id += 1;
        let id = self.next_id;
        let mut edges: Vec<BlockId> = Vec::new();
        for &target in refs {
            if self.blocks.contains_key(&target) && !edges.contains(&target) {
                edges.push(target);
            }
        }
        self.blocks.insert(
            id,
            Block {
                id,
                size,
                site: site.to_owned(),
                refs: edges,
                marked: false,
            },
        );
        self.bytes_allocated += size;
        id
    }

    /// Returns and clears the reports of the collections that `alloc` ran.
    pub fn take_pacing_reports(&mut self) -> Vec<LeakReport> {
        std::mem::take(&mut self.pacing_reports)
    }

    /// Declares `id` a root. Roots are always retained; an id that is not live
    /// is ignored by the mark.
    pub fn add_root(&mut self, id: BlockId) {
        self.roots.insert(id);
    }

    pub fn remove_root(&mut self, id: BlockId) {
        self.roots.remove(&id);
    }

    /// Adds the edge `from -> to` if both blocks are live and the edge is new.
    pub fn connect(&mut self, from: BlockId, to: BlockId) {
        if self.blocks.contains_key(&to)
            && let Some(block) = self.blocks.get_mut(&from)
            && !block.refs.contains(&to)
        {
            block.refs.push(to);
        }
    }

    /// Removes the edge `from -> to`. The target may become garbage.
    pub fn disconnect(&mut self, from: BlockId, to: BlockId) {
        if let Some(block) = self.blocks.get_mut(&from) {
            block.refs.retain(|&target| target != to);
        }
    }
}
