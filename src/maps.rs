//! Reading `/proc/<pid>/maps` for the diagnostic log.

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
