use super::{Block, BlockId, Heap};

impl Heap {
    /// Registers a block of `size` bytes allocated at `site` and returns its id.
    /// Refs to blocks that are not live are dropped and duplicates are removed.
    pub fn alloc(&mut self, refs: &[BlockId], site: &str, size: u64) -> BlockId {
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
                freed: false,
            },
        );
        self.bytes_allocated += size;
        id
    }
}
