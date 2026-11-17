//! Core of `leakgc`: a pure, OS-free model of a heap in which unreachable
//! blocks are found by mark-and-sweep and can be freed at runtime.
//!
//! This is a port of `ocaml/leakcheck.ml`, which remains the oracle. Nothing
//! in this crate touches memory, processes or `/proc`; blocks are bookkeeping
//! records, so every behaviour can be tested without an operating system.

pub mod gc;

#[cfg(test)]
mod tests {
    use crate::gc::Heap;

    #[test]
    fn crate_root_exposes_the_gc_heap() {
        let mut heap = Heap::new();
        let id = heap.alloc(&[], "crate_root", 1);
        assert!(heap.block(id).is_some());
    }
}
