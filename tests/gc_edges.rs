//! Roots and edges, exercised through the public API.

use win_games_leak_garbage_collector::gc::Heap;

#[test]
fn connect_adds_each_edge_once() {
    let mut heap = Heap::new();
    let a = heap.alloc(&[], "a", 1);
    let b = heap.alloc(&[], "b", 1);
    heap.connect(a, b);
    heap.connect(a, b);
    assert_eq!(heap.block(a).expect("live").refs, [b]);
}

#[test]
fn connect_ignores_missing_endpoints() {
    let mut heap = Heap::new();
    let a = heap.alloc(&[], "a", 1);
    heap.connect(999, a);
    heap.connect(a, 999);
    assert!(heap.block(a).expect("live").refs.is_empty());
}

#[test]
fn self_edges_are_allowed() {
    let mut heap = Heap::new();
    let a = heap.alloc(&[], "a", 1);
    heap.connect(a, a);
    assert_eq!(heap.block(a).expect("live").refs, [a]);
}

#[test]
fn disconnect_removes_the_edge() {
    let mut heap = Heap::new();
    let a = heap.alloc(&[], "a", 1);
    let b = heap.alloc(&[], "b", 1);
    heap.connect(a, b);
    heap.disconnect(a, b);
    assert!(heap.block(a).expect("live").refs.is_empty());
}

#[test]
fn disconnect_of_a_missing_edge_or_source_is_a_no_op() {
    let mut heap = Heap::new();
    let a = heap.alloc(&[], "a", 1);
    let b = heap.alloc(&[], "b", 1);
    heap.connect(a, b);
    heap.disconnect(a, 999);
    heap.disconnect(999, a);
    assert_eq!(heap.block(a).expect("live").refs, [b]);
}

#[test]
fn disconnecting_the_last_edge_orphans_the_target() {
    let mut heap = Heap::new();
    let root = heap.alloc(&[], "root", 1);
    let child = heap.alloc(&[], "child", 1);
    heap.add_root(root);
    heap.connect(root, child);
    heap.disconnect(root, child);

    let report = heap
        .collect(true, None::<&mut dyn std::io::Write>)
        .expect("no writer, no io error");

    assert_eq!(report.total_lost_blocks, 1);
    assert!(heap.block(child).is_none());
    assert!(heap.block(root).is_some());
}

#[test]
fn removing_a_root_orphans_its_subtree() {
    let mut heap = Heap::new();
    let root = heap.alloc(&[], "root", 1);
    let child = heap.alloc(&[], "child", 1);
    heap.add_root(root);
    heap.connect(root, child);
    heap.remove_root(root);

    let report = heap
        .collect(true, None::<&mut dyn std::io::Write>)
        .expect("no writer, no io error");

    assert_eq!(report.total_lost_blocks, 2);
    assert_eq!(heap.blocks().count(), 0);
}

#[test]
fn roots_are_a_set_and_removing_a_missing_root_is_a_no_op() {
    let mut heap = Heap::new();
    let a = heap.alloc(&[], "a", 1);
    heap.add_root(a);
    heap.add_root(a);
    assert_eq!(heap.roots().collect::<Vec<_>>(), [a]);

    heap.remove_root(999);
    assert_eq!(heap.roots().collect::<Vec<_>>(), [a]);

    heap.remove_root(a);
    assert_eq!(heap.roots().count(), 0);
}
