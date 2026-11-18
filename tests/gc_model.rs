//! Block model and heap state, exercised through the public API.

use win_games_leak_garbage_collector::gc::Heap;

#[test]
fn new_heap_is_empty() {
    let heap = Heap::new();
    assert_eq!(heap.blocks().count(), 0);
    assert_eq!(heap.roots().count(), 0);
    assert_eq!(heap.bytes_allocated(), 0);
    assert_eq!(heap.collections(), 0);
    assert!(heap.block(1).is_none());
}

#[test]
fn default_is_the_same_empty_heap() {
    let heap = Heap::default();
    assert_eq!(heap.blocks().count(), 0);
    assert_eq!(heap.bytes_allocated(), 0);
}

#[test]
fn alloc_registers_an_unmarked_block_with_its_fields() {
    let mut heap = Heap::new();
    let id = heap.alloc(&[], "build_node:41", 64);
    assert_eq!(id, 1);
    let block = heap.block(id).expect("block is registered");
    assert_eq!(block.id, id);
    assert_eq!(block.size, 64);
    assert_eq!(block.site, "build_node:41");
    assert!(block.refs.is_empty());
    assert!(!block.marked);
    assert_eq!(heap.bytes_allocated(), 64);
}

#[test]
fn ids_increase_and_bytes_accumulate_in_id_order() {
    let mut heap = Heap::new();
    let first = heap.alloc(&[], "a", 10);
    let second = heap.alloc(&[], "b", 20);
    assert_eq!((first, second), (1, 2));
    assert_eq!(heap.bytes_allocated(), 30);
    let ids: Vec<_> = heap.blocks().map(|block| block.id).collect();
    assert_eq!(ids, [1, 2]);
}

#[test]
fn alloc_keeps_live_refs_in_order_without_duplicates() {
    let mut heap = Heap::new();
    let target = heap.alloc(&[], "target", 8);
    let other = heap.alloc(&[], "other", 8);
    let id = heap.alloc(&[other, target, other], "holder", 8);
    assert_eq!(heap.block(id).expect("registered").refs, [other, target]);
}

#[test]
fn alloc_drops_refs_to_blocks_that_are_not_live() {
    let mut heap = Heap::new();
    let target = heap.alloc(&[], "target", 8);
    let id = heap.alloc(&[target, 999], "holder", 8);
    assert_eq!(heap.block(id).expect("registered").refs, [target]);
}
