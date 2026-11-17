use super::{BlockId, Heap};

impl Heap {
    /// Tri-color mark with an explicit worklist, so deep or cyclic graphs
    /// cannot exhaust the call stack. A queued block is gray; a block whose
    /// `marked` flag is set is black. Ids that are not live are skipped.
    pub(super) fn mark(&mut self) {
        let mut worklist: Vec<BlockId> = self.roots.iter().copied().collect();
        while let Some(id) = worklist.pop() {
            if let Some(block) = self.blocks.get_mut(&id)
                && !block.marked
            {
                block.marked = true;
                worklist.extend_from_slice(&block.refs);
            }
        }
    }
}
