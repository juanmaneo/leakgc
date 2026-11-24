//! Core of `leakgc`.
//!
//! - [`gc`] is a pure, OS-free model of a heap in which unreachable blocks
//!   are found by mark-and-sweep. It is a port of `ocaml/leakcheck.ml`, which
//!   remains the oracle. Nothing in `gc` touches memory, processes or `/proc`.
//! - [`supervisor`], [`stub`], [`trap`] and [`maps`] start the target,
//!   trap its memory system calls and drain its processes. They sit behind the
//!   [`supervisor::Tracer`] trait so their control flow can be tested.
//! - [`hook`] plans the entry patches for the allocator hooks, and [`ring`]
//!   describes the record ring they write. Both are pure, as `gc` is.
//! - [`install`] injects the memory and writes the patches into a stopped
//!   static process through the [`supervisor::Tracer`] trait.
//! - [`ledger`] turns finished calls into the blocks an image still holds,
//!   [`reach`] tells which of them a stopped process still reaches (report
//!   only), and [`monitor`] keeps one ledger per traced process.

#[cfg(not(target_arch = "x86_64"))]
compile_error!("leakgc's trap filter and register access are x86_64-only");

pub mod gc;
pub mod hook;
pub mod install;
pub mod ledger;
pub mod maps;
pub mod monitor;
pub mod reach;
pub mod ring;
pub mod stub;
pub mod supervisor;
pub mod trap;

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
