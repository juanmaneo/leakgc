//! Automatic pacing of collections inside `alloc`.

use win_games_leak_garbage_collector::gc::{COLLECT_EVERY, Heap};

#[test]
fn collect_every_matches_the_oracle() {
    assert_eq!(COLLECT_EVERY, 64);
}

#[test]
fn pacing_collects_on_every_collect_every_th_allocation() {
    let mut heap = Heap::new();
    for _ in 1..COLLECT_EVERY {
        heap.alloc(&[], "garbage", 1);
    }
    assert_eq!(heap.collections(), 0);

    let last = heap.alloc(&[], "garbage", 1);

    assert_eq!(heap.collections(), 1);
    assert!(heap.block(last).is_some());
    assert_eq!(heap.blocks().count(), 1);
}

#[test]
fn pacing_reports_are_queued_and_taken_once() {
    let mut heap = Heap::new();
    for _ in 0..COLLECT_EVERY {
        heap.alloc(&[], "garbage", 8);
    }

    let reports = heap.take_pacing_reports();

    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].total_lost_blocks, COLLECT_EVERY - 1);
    assert_eq!(reports[0].total_lost_bytes, (COLLECT_EVERY - 1) * 8);
    assert!(heap.take_pacing_reports().is_empty());
}

#[test]
fn pacing_keeps_rooted_blocks() {
    let mut heap = Heap::new();
    let root = heap.alloc(&[], "root", 16);
    heap.add_root(root);
    for _ in 1..(2 * COLLECT_EVERY) {
        heap.alloc(&[], "garbage", 1);
    }

    assert!(heap.block(root).is_some());
    assert_eq!(heap.collections(), 2);
}

#[test]
fn refs_to_blocks_freed_by_the_pacing_collection_are_dropped() {
    let mut heap = Heap::new();
    let pointee = heap.alloc(&[], "pointee", 8);
    for _ in 2..COLLECT_EVERY {
        heap.alloc(&[], "filler", 1);
    }

    let holder = heap.alloc(&[pointee], "holder", 8);

    assert!(heap.block(pointee).is_none());
    assert!(heap.block(holder).expect("live").refs.is_empty());
}

#[test]
fn refs_to_blocks_that_survive_pacing_are_kept() {
    let mut heap = Heap::new();
    let pointee = heap.alloc(&[], "pointee", 8);
    heap.add_root(pointee);
    for _ in 2..COLLECT_EVERY {
        heap.alloc(&[], "filler", 1);
    }

    let holder = heap.alloc(&[pointee], "holder", 8);

    assert_eq!(heap.block(holder).expect("live").refs, [pointee]);
}
