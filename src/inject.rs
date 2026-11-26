//! The allocator-internal guard (R37). An injected `free` must not run while
//! the stopped thread is inside the allocator, because the free could take a
//! lock that the thread already holds. This module decides that from the
//! instruction pointer and from the words at the top of the stack.
//!
//! It is a heuristic. It knows glibc's internal names, not every allocator's,
//! and it reads a fixed window of the stack. Anything it cannot check is
//! denied, so a missing answer never allows an injection.

/// glibc's allocator functions that run below the hooked entries, and the
/// hooked entries themselves. A stop inside any of them is not a safe point.
const INTERNAL_NAMES: &[&str] = &[
    "sysmalloc",
    "systrim",
    "heap_trim",
    "new_heap",
    "grow_heap",
    "shrink_heap",
    "mallopt",
    "mallinfo",
    "__libc_mallinfo",
    "_mid_memalign",
    "__libc_malloc",
    "__libc_calloc",
    "__libc_free",
    "__libc_realloc",
    "__libc_memalign",
    "malloc",
    "calloc",
    "free",
    "realloc",
    "memalign",
    "aligned_alloc",
    "valloc",
    "pvalloc",
    "posix_memalign",
];

/// Name prefixes of the other internal functions of glibc's allocator.
const INTERNAL_PREFIXES: &[&str] = &[
    "_int_", "malloc_", "__malloc", "ptmalloc", "arena_", "tcache",
];

/// Whether `name` is an allocator function that an injected free must not interrupt.
pub fn is_allocator_internal(name: &str) -> bool {
    INTERNAL_NAMES.contains(&name)
        || INTERNAL_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(*prefix))
}

/// Whether an injected free may run now. `internal` holds the `[start, end)`
/// ranges of the allocator's internal functions, and `stack` holds the words
/// read from the top of the stack. An unknown value on either side refuses the
/// injection. `xsave` says whether the trampoline's state save is available.
pub fn may_inject(
    xsave: bool,
    internal: Option<&[(u64, u64)]>,
    rip: u64,
    stack: Option<&[u64]>,
) -> bool {
    match (internal, stack) {
        (Some(internal), Some(stack)) => {
            xsave
                && !in_ranges(internal, rip)
                && !stack.iter().any(|&word| in_ranges(internal, word))
        }
        _ => false,
    }
}

/// Whether the CPU supports XSAVE, which the injected trampoline needs.
pub fn xsave_available() -> bool {
    is_x86_feature_detected!("xsave")
}

fn in_ranges(ranges: &[(u64, u64)], addr: u64) -> bool {
    ranges
        .iter()
        .any(|&(start, end)| (start..end).contains(&addr))
}
