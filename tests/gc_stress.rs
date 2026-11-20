//! Pacing regression and randomized invariant checks. The reachability model
//! below is written independently of the collector and is the oracle for
//! every check.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io;

use leakgc::gc::{Block, BlockId, Heap, LeakReport, Mode};

/// Deterministic PRNG so every run replays the same trace.
struct XorShift64(u64);

impl XorShift64 {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// Value in `0..bound`. The modulo bias is irrelevant for test traces.
    fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }

    fn index(&mut self, len: usize) -> usize {
        usize::try_from(self.below(u64::try_from(len).expect("len fits in u64")))
            .expect("index below len fits in usize")
    }
}

/// Collects without a report writer, which cannot fail.
fn collect(heap: &mut Heap, free_leaks: bool) -> LeakReport {
    heap.collect(free_leaks, None::<&mut dyn io::Write>)
        .expect("collecting without a writer cannot fail")
}

fn live_ids(heap: &Heap) -> Vec<BlockId> {
    heap.blocks().map(|block| block.id).collect()
}

/// Ids reachable from the roots, found by a plain breadth-first walk.
fn reachable_from_roots(heap: &Heap) -> BTreeSet<BlockId> {
    let mut seen = BTreeSet::new();
    let mut queue: VecDeque<BlockId> = heap.roots().collect();
    while let Some(id) = queue.pop_front() {
        if seen.insert(id) {
            let block = heap.block(id).expect("roots are always live");
            queue.extend(block.refs.iter().copied());
        }
    }
    seen
}

/// Runs a collection and checks it against the reachability model. Returns the
/// number of blocks reported lost and the size of the reachable set.
fn check_collection(heap: &mut Heap) -> (u64, usize) {
    let before: Vec<Block> = heap.blocks().cloned().collect();
    let reachable = reachable_from_roots(heap);
    let (live, dead): (Vec<&Block>, Vec<&Block>) = before
        .iter()
        .partition(|block| reachable.contains(&block.id));

    let expected_lost_blocks = u64::try_from(dead.len()).expect("count fits in u64");
    let expected_lost_bytes: u64 = dead.iter().map(|block| block.size).sum();
    let expected_retained: u64 = live.iter().map(|block| block.size).sum();
    let mut expected_sites: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    for block in &dead {
        let entry = expected_sites.entry(block.site.as_str()).or_default();
        entry.0 += 1;
        entry.1 += block.size;
    }

    let report = collect(heap, true);

    assert_eq!(report.total_lost_blocks, expected_lost_blocks);
    assert_eq!(report.total_lost_bytes, expected_lost_bytes);
    assert_eq!(report.retained_bytes, expected_retained);
    let sites: BTreeMap<&str, (u64, u64)> = report
        .by_site
        .iter()
        .map(|loss| (loss.site.as_str(), (loss.blocks, loss.bytes)))
        .collect();
    assert_eq!(sites.len(), report.by_site.len(), "one entry per site");
    assert_eq!(sites, expected_sites);
    assert!(
        report
            .by_site
            .windows(2)
            .all(|pair| pair[0].bytes >= pair[1].bytes)
    );

    let after: BTreeSet<BlockId> = live_ids(heap).into_iter().collect();
    let lost: BTreeSet<BlockId> = before
        .iter()
        .map(|block| block.id)
        .filter(|id| !after.contains(id))
        .collect();
    let unreachable: BTreeSet<BlockId> = dead.iter().map(|block| block.id).collect();
    assert_eq!(
        lost, unreachable,
        "exactly the unreachable blocks were swept"
    );
    assert_eq!(after, reachable, "the heap is the reachable set afterwards");
    for block in heap.blocks() {
        assert!(!block.marked, "stale flags on block {}", block.id);
        let unique: BTreeSet<BlockId> = block.refs.iter().copied().collect();
        assert_eq!(
            unique.len(),
            block.refs.len(),
            "duplicate edge on {}",
            block.id
        );
        for target in &block.refs {
            assert!(
                after.contains(target),
                "dangling edge {} -> {target}",
                block.id
            );
        }
    }
    (report.total_lost_blocks, reachable.len())
}

#[test]
fn every_returned_id_survives_pacing_over_200_allocs() {
    let mut heap = Heap::with_mode(Mode::Free);
    for _ in 0..200 {
        let id = heap.alloc(&[], "garbage", 16);
        assert!(heap.block(id).is_some(), "block {id} was swept by pacing");
    }

    assert_eq!(heap.collections(), 3);
    assert_eq!(heap.take_pacing_reports().len(), 3);
}

#[test]
fn randomized_trace_keeps_the_heap_equal_to_the_reachable_set() {
    const STEPS: u64 = 5000;
    const CHECK_EVERY: u64 = 250;

    let mut rng = XorShift64(0x9E37_79B9_7F4A_7C15);
    let mut heap = Heap::with_mode(Mode::Free);
    let mut checks = 0;
    let mut lost_blocks = 0;
    let mut max_reachable = 0;
    let mut nonempty_checks = 0;

    for step in 0..STEPS {
        match rng.below(100) {
            0..40 => {
                // The retain source is drawn from the reachable set, not from every
                // unswept block: pacing sweeps garbage long before the heap empties,
                // so a "no live block" root rule would almost never fire.
                let pool: Vec<BlockId> = reachable_from_roots(&heap).into_iter().collect();
                let size = 1 + rng.below(4096);
                let id = heap.alloc(&[], "alloc_retain", size);
                if pool.is_empty() {
                    heap.add_root(id);
                } else {
                    heap.connect(pool[rng.index(pool.len())], id);
                }
            }
            40..55 => {
                let live = live_ids(&heap);
                if !live.is_empty() {
                    let from = live[rng.index(live.len())];
                    let to = live[rng.index(live.len())];
                    heap.connect(from, to);
                }
            }
            55..65 => {
                let live = live_ids(&heap);
                if !live.is_empty() {
                    let from = live[rng.index(live.len())];
                    let to = live[rng.index(live.len())];
                    heap.disconnect(from, to);
                }
            }
            65..75 => {
                let roots: Vec<BlockId> = heap.roots().collect();
                if !roots.is_empty() {
                    heap.remove_root(roots[rng.index(roots.len())]);
                }
            }
            _ => {
                let size = 1 + rng.below(4096);
                heap.alloc(&[], "garbage", size);
            }
        }

        if (step + 1).is_multiple_of(CHECK_EVERY) {
            checks += 1;
            let (lost, reachable) = check_collection(&mut heap);
            lost_blocks += lost;
            max_reachable = max_reachable.max(reachable);
            if reachable > 0 {
                nonempty_checks += 1;
            }
        }
    }

    // The trace must keep a non-trivial reachable set, or the checks prove little.
    assert!(
        nonempty_checks >= 10,
        "only {nonempty_checks} non-empty checks"
    );
    assert!(
        max_reachable >= 10,
        "reachable set never exceeded {max_reachable}"
    );

    let pacing_reports = heap.take_pacing_reports();
    let pacing = u64::try_from(pacing_reports.len()).expect("count fits in u64");
    assert_eq!(heap.collections(), checks + pacing);
    assert_eq!(heap.collections(), 70);
    assert_eq!(heap.blocks().count(), 1);
    assert_eq!(lost_blocks, 648);
}
