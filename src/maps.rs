//! Reading `/proc/<pid>/maps` for the diagnostic log (P2a) and for the roots
//! and blocks of a reachability scan (P4b, D51).

use std::ops::Range;

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
    /// The writable mappings that are private, not shared with another process.
    /// Only a block inside one of them may be poisoned or freed (D41).
    pub private: Vec<(u64, u64)>,
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
            if perms.get(3) == Some(&b'p') {
                ranges.private.push((start, end));
            }
        }
        if writable || (readable && !executable && !path.starts_with("[vvar")) {
            ranges.roots.push((start, end));
        }
    }
    Some(ranges)
}

/// The lowest `at` in `window` such that `[at, at + len)` lies inside no mapping,
/// `at` is a multiple of `align`, and `at + len` is at most `window.end`. Returns
/// `None` if any line does not parse, or if no such gap exists. It places the
/// hook region within `jmp rel32` reach of the hooked entries (D55). The result
/// is a snapshot, so the install must confirm it at run time.
pub fn find_gap(maps: &str, window: Range<u64>, len: u64, align: u64) -> Option<u64> {
    let mut mapped = maps
        .lines()
        .map(address_range)
        .collect::<Option<Vec<_>>>()?;
    mapped.sort_unstable();
    let align = align.max(1);
    let mut at = window.start.checked_next_multiple_of(align)?;
    for (start, end) in mapped {
        if end <= at {
            continue;
        }
        if start >= at.saturating_add(len) {
            break;
        }
        at = end.checked_next_multiple_of(align)?;
    }
    (at.checked_add(len)? <= window.end).then_some(at)
}

/// The `[start, end)` range at the start of one `/proc/<pid>/maps` line.
fn address_range(line: &str) -> Option<(u64, u64)> {
    let (start, end) = line.split_whitespace().next()?.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    (start <= end).then_some((start, end))
}
