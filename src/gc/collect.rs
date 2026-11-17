use std::io::{self, Write};

use super::{Heap, LeakReport, render_report};

impl Heap {
    /// Runs one full collection. When `out` is given, the Valgrind-style
    /// summary is also written there.
    pub fn collect(
        &mut self,
        free_leaks: bool,
        out: Option<&mut dyn Write>,
    ) -> io::Result<LeakReport> {
        let report = self.run_collection(free_leaks);
        if let Some(out) = out {
            out.write_all(render_report(&report).as_bytes())?;
        }
        Ok(report)
    }

    /// Mark and sweep without any output.
    pub(super) fn run_collection(&mut self, free_leaks: bool) -> LeakReport {
        self.collections += 1;
        self.mark();
        self.sweep(free_leaks)
    }
}
