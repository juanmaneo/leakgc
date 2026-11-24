//! Reading `/proc/<pid>/maps` for the diagnostic log (P2a) and for the roots
//! of a reachability scan (P4b).

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

/// The `[start, end)` address ranges of the mappings that allow writing.
/// Returns `None` if any line does not parse, because a partial list would
/// leave part of the roots unscanned.
pub fn writable_ranges(maps: &str) -> Option<Vec<(u64, u64)>> {
    let mut ranges = Vec::new();
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let (start, end) = fields.next()?.split_once('-')?;
        let start = u64::from_str_radix(start, 16).ok()?;
        let end = u64::from_str_radix(end, 16).ok()?;
        if start > end {
            return None;
        }
        if fields.next()?.as_bytes().get(1) == Some(&b'w') {
            ranges.push((start, end));
        }
    }
    Some(ranges)
}
