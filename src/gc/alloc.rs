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
