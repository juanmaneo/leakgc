use super::{Heap, render_report};

/// Runs the three demo scenarios of `ocaml/leakcheck.ml` and returns the
/// transcript the oracle prints, byte for byte.
pub fn demo_transcript() -> String {
    let mut heap = Heap::new();
    let mut text = String::from("--- scenario 1: well-behaved code ---\n");

    let root = heap.alloc(&[], "main.scenario1:12", 512);
    heap.add_root(root);
    let child = heap.alloc(&[], "load_texture:88", 4096);
    heap.connect(root, child);
    text.push_str(&render_report(&heap.run_collection(true)));

    text.push_str("\n--- scenario 2: cyclic garbage (unreachable ring) ---\n");
    let a = heap.alloc(&[], "build_node:41", 64);
    let b = heap.alloc(&[], "build_node:41", 64);
    let c = heap.alloc(&[], "build_node:41", 64);
    heap.connect(a, b);
    heap.connect(b, c);
    heap.connect(c, a);
    text.push_str(&render_report(&heap.run_collection(true)));

    text.push_str("\n--- scenario 3: the old Windows game pattern ---\n");
    for _ in 0..4 {
        heap.alloc(&[], "load_level_textures:210", 65536);
    }
    text.push_str(&render_report(&heap.run_collection(true)));

    text.push_str(&format!(
        "\ndone: {} collections, {} bytes total allocated\n",
        heap.collections(),
        heap.bytes_allocated()
    ));
    text
}
