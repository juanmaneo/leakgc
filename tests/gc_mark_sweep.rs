//! Mark, sweep and collect, exercised through the public API.

use std::io;

use win_games_leak_garbage_collector::gc::{Heap, LeakReport, SiteLoss};

fn site(name: &str, blocks: u64, bytes: u64) -> SiteLoss {
    SiteLoss {
        site: name.to_owned(),
        blocks,
        bytes,
    }
}

/// Collects without a report writer, which cannot fail.
fn collect(heap: &mut Heap, free_leaks: bool) -> LeakReport {
    heap.collect(free_leaks, None::<&mut dyn io::Write>)
        .expect("collecting without a writer cannot fail")
}

#[test]
fn unrooted_cycle_is_lost_and_freed() {
    let mut heap = Heap::new();
    let a = heap.alloc(&[], "build_node:41", 64);
    let b = heap.alloc(&[], "build_node:41", 64);
    let c = heap.alloc(&[], "build_node:41", 64);
    heap.connect(a, b);
    heap.connect(b, c);
    heap.connect(c, a);

    let report = collect(&mut heap, true);

    assert_eq!(report.total_lost_blocks, 3);
    assert_eq!(report.total_lost_bytes, 192);
    assert_eq!(report.by_site, [site("build_node:41", 3, 192)]);
    assert_eq!(report.retained_bytes, 0);
    assert_eq!(heap.blocks().count(), 0);
    assert_eq!(heap.collections(), 1);
}

#[test]
fn rooted_graph_survives_while_unrooted_garbage_is_lost() {
    let mut heap = Heap::new();
    let root = heap.alloc(&[], "main.scenario1:12", 512);
    let child = heap.alloc(&[], "load_texture:88", 4096);
    heap.add_root(root);
    heap.connect(root, child);
    let garbage = heap.alloc(&[], "leak", 100);

    let report = collect(&mut heap, true);

    assert_eq!(report.total_lost_blocks, 1);
    assert_eq!(report.total_lost_bytes, 100);
    assert_eq!(report.by_site, [site("leak", 1, 100)]);
    assert_eq!(report.retained_bytes, 4608);
    assert!(heap.block(root).is_some());
    assert!(heap.block(child).is_some());
    assert!(heap.block(garbage).is_none());
}

#[test]
fn report_only_collection_keeps_garbage_until_a_freeing_collection() {
    let mut heap = Heap::new();
    heap.alloc(&[], "leak", 64);

    let first = collect(&mut heap, false);
    assert_eq!(first.total_lost_blocks, 1);
    assert_eq!(first.retained_bytes, 64);
    assert_eq!(heap.blocks().count(), 1);

    let second = collect(&mut heap, true);
    assert_eq!(second.total_lost_blocks, 1);
    assert_eq!(second.total_lost_bytes, 64);
    assert_eq!(second.retained_bytes, 0);
    assert_eq!(heap.blocks().count(), 0);
    assert_eq!(heap.collections(), 2);
}

#[test]
fn clean_heap_reports_no_loss() {
    let mut heap = Heap::new();
    let root = heap.alloc(&[], "main", 512);
    heap.add_root(root);

    let report = collect(&mut heap, true);

    assert_eq!(report.total_lost_blocks, 0);
    assert_eq!(report.total_lost_bytes, 0);
    assert!(report.by_site.is_empty());
    assert_eq!(report.retained_bytes, 512);
}

#[test]
fn retained_bytes_come_from_the_live_table_not_a_running_total() {
    let mut heap = Heap::new();
    let root = heap.alloc(&[], "root", 100);
    heap.add_root(root);
    heap.alloc(&[], "garbage", 50);

    collect(&mut heap, true);
    collect(&mut heap, true);
    let report = collect(&mut heap, true);

    assert_eq!(heap.bytes_allocated(), 150);
    assert_eq!(report.retained_bytes, 100);
}

#[test]
fn marks_and_freed_flags_are_clear_after_every_sweep() {
    let mut heap = Heap::new();
    let root = heap.alloc(&[], "root", 8);
    heap.add_root(root);
    heap.alloc(&[], "garbage", 8);

    collect(&mut heap, true);

    assert!(heap.blocks().all(|block| !block.marked && !block.freed));
}

#[test]
fn deep_chain_is_marked_without_recursion() {
    // Pacing re-marks the growing chain every 64 allocations, so the build is quadratic.
    const DEPTH: u64 = 20_000;
    let mut heap = Heap::new();
    // Pacing collects during the build, so the tip is rooted while the chain grows.
    let mut tip = heap.alloc(&[], "chain", 1);
    heap.add_root(tip);
    for _ in 1..DEPTH {
        let next = heap.alloc(&[tip], "chain", 1);
        heap.add_root(next);
        heap.remove_root(tip);
        tip = next;
    }

    let kept = collect(&mut heap, true);
    assert_eq!(kept.total_lost_blocks, 0);
    assert_eq!(kept.retained_bytes, DEPTH);

    heap.remove_root(tip);
    let lost = collect(&mut heap, true);
    assert_eq!(lost.total_lost_blocks, DEPTH);
    assert_eq!(lost.total_lost_bytes, DEPTH);
    assert_eq!(heap.blocks().count(), 0);
}

#[test]
fn shared_and_cyclic_nodes_are_marked_once_and_retained() {
    let mut heap = Heap::new();
    let root = heap.alloc(&[], "root", 1);
    let left = heap.alloc(&[], "left", 1);
    let right = heap.alloc(&[], "right", 1);
    let shared = heap.alloc(&[], "shared", 1);
    heap.add_root(root);
    heap.connect(root, left);
    heap.connect(root, right);
    heap.connect(left, shared);
    heap.connect(right, shared);
    heap.connect(shared, root);

    let report = collect(&mut heap, true);

    assert_eq!(report.total_lost_blocks, 0);
    assert_eq!(report.retained_bytes, 4);
}

#[test]
fn roots_that_are_not_live_are_ignored_by_the_mark() {
    let mut heap = Heap::new();
    heap.add_root(42);
    heap.alloc(&[], "leak", 8);

    let report = collect(&mut heap, true);

    assert_eq!(report.total_lost_blocks, 1);
    assert_eq!(heap.roots().collect::<Vec<_>>(), [42]);
}

#[test]
fn by_site_is_sorted_by_bytes_then_by_site_name() {
    let mut heap = Heap::new();
    heap.alloc(&[], "b:1", 10);
    heap.alloc(&[], "b:1", 10);
    heap.alloc(&[], "a:1", 20);
    heap.alloc(&[], "c:1", 100);

    let report = collect(&mut heap, true);

    assert_eq!(report.total_lost_blocks, 4);
    assert_eq!(report.total_lost_bytes, 140);
    assert_eq!(
        report.by_site,
        [site("c:1", 1, 100), site("a:1", 1, 20), site("b:1", 2, 20)]
    );
}
