//! Reading `/proc/<pid>/maps` for the diagnostic log (P2a) and for the roots
//! and blocks of a reachability scan (P4b, D51).

/// Counts the mappings whose permissions allow writing, such as `rw-p`.
pub fn writable_count(maps: &str) -> usize {
    maps.lines()
        .filter(|line| {
            line.split_whitespace()
                .nth(1)
                .is_some_and(|perms| perms.chars().nth(1) == Some('w'))
        })
        .count()
}

/// The `[start, end)` address ranges that a reachability scan uses, from one
/// parse of the memory map.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ScanRanges {
    /// The writable mappings. A block's contents are read only inside one of them (D44).
    pub writable: Vec<(u64, u64)>,
    /// The roots: the writable mappings and the readable, non-executable
    /// mappings (D51). The kernel's `[vvar]` pages are left out. They cannot be
    /// read, and they hold no pointers of the process.
    pub roots: Vec<(u64, u64)>,
}

/// Parses `maps`. Returns `None` if any line does not parse, because a partial
/// list would leave part of the roots unscanned.
pub fn scan_ranges(maps: &str) -> Option<ScanRanges> {
    let mut ranges = ScanRanges::default();
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let (start, end) = fields.next()?.split_once('-')?;
        let start = u64::from_str_radix(start, 16).ok()?;
        let end = u64::from_str_radix(end, 16).ok()?;
        if start > end {
            return None;
        }
        let perms = fields.next()?.as_bytes();
        // Skips the offset, device and inode; the path is what remains.
        let path = fields.nth(3).unwrap_or("");
        let writable = perms.get(1) == Some(&b'w');
        let readable = perms.first() == Some(&b'r');
        let executable = perms.get(2) == Some(&b'x');
        if writable {
            ranges.writable.push((start, end));
        }
        if writable || (readable && !executable && !path.starts_with("[vvar")) {
            ranges.roots.push((start, end));
        }
    }
    Some(ranges)
}
