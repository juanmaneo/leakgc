use super::{Heap, LeakReport};

impl Heap {
    /// Runs one full collection: mark from the roots, then sweep.
    pub fn collect(&mut self, free_leaks: bool) -> LeakReport {
        self.collections += 1;
        self.mark();
        self.sweep(free_leaks)
    }
}
