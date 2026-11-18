use std::collections::BTreeMap;

use super::{BlockId, Heap};

/// Lost blocks and bytes for one allocation site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteLoss {
    pub site: String,
    pub blocks: u64,
    pub bytes: u64,
}

/// Result of one collection, mirroring `leak_report` in the oracle.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LeakReport {
    pub total_lost_blocks: u64,
    pub total_lost_bytes: u64,
    /// Bytes descending. Equal totals are ordered by site name, which the
    /// oracle leaves to hash-table iteration order.
    pub by_site: Vec<SiteLoss>,
    /// Bytes of every block still in the table after the sweep.
    pub retained_bytes: u64,
}

impl Heap {
    /// Gathers the unmarked blocks before touching the table, then frees them
    /// (if `free_leaks`) and clears every mark for the next cycle.
    pub(super) fn sweep(&mut self, free_leaks: bool) -> LeakReport {
        let lost: Vec<BlockId> = self
            .blocks
            .values()
            .filter(|block| !block.marked)
            .map(|block| block.id)
            .collect();

        let mut sites: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
        let mut report = LeakReport::default();
        for id in &lost {
            let block = &self.blocks[id];
            report.total_lost_blocks += 1;
            report.total_lost_bytes += block.size;
            let (blocks, bytes) = sites.entry(block.site.as_str()).or_default();
            *blocks += 1;
            *bytes += block.size;
        }
        let mut by_site: Vec<SiteLoss> = sites
            .into_iter()
            .map(|(site, (blocks, bytes))| SiteLoss {
                site: site.to_owned(),
                blocks,
                bytes,
            })
            .collect();
        by_site.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.site.cmp(&b.site)));
        report.by_site = by_site;

        if free_leaks {
            for id in &lost {
                // Ids were gathered from the table above, so they are present.
                self.blocks.remove(id).expect("gathered from the table");
            }
        }
        for block in self.blocks.values_mut() {
            block.marked = false;
        }
        report.retained_bytes = self.blocks.values().map(|block| block.size).sum();
        report
    }
}
