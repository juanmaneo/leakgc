//! The allocator-internal guard (R37): which functions it denies, and when an
//! injected free may run. Every branch is pure, so no process is needed.

use leakgc::inject::{is_allocator_internal, may_inject, xsave_available};

const RANGES: &[(u64, u64)] = &[(0x1000, 0x2000), (0x5000, 0x5100)];
const CLEAR: &[u64] = &[0x7000, 0x8000];
const NO_WORDS: &[u64] = &[];

#[test]
fn the_allocator_entries_and_glibc_internals_are_denied() {
    for name in [
        "malloc",
        "free",
        "realloc",
        "calloc",
        "memalign",
        "aligned_alloc",
        "valloc",
        "pvalloc",
        "posix_memalign",
        "__libc_malloc",
        "__libc_free",
        "__libc_realloc",
        "__libc_calloc",
        "__libc_memalign",
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
        "_int_malloc",
        "_int_free",
        "malloc_consolidate",
        "malloc_printerr",
        "__malloc_fork_lock_parent",
        "ptmalloc_init",
        "arena_get2",
        "tcache_put",
    ] {
        assert!(is_allocator_internal(name), "{name} is denied");
    }
}

#[test]
fn ordinary_functions_are_not_denied() {
    for name in [
        "main",
        "printf",
        "__libc_start_main",
        "_start",
        "mallocx",
        "int_malloc",
        "_int",
        "free_hook",
    ] {
        assert!(!is_allocator_internal(name), "{name} is allowed");
    }
}

#[test]
fn an_injected_free_runs_when_every_check_passes() {
    assert!(may_inject(true, Some(RANGES), 0x3000, Some(CLEAR)));
    assert!(may_inject(true, Some(RANGES), 0x3000, Some(NO_WORDS)));
}

#[test]
fn an_unknown_answer_refuses_the_injection() {
    assert!(
        !may_inject(false, Some(RANGES), 0x3000, Some(CLEAR)),
        "no xsave"
    );
    assert!(
        !may_inject(true, None, 0x3000, Some(CLEAR)),
        "no symbol ranges"
    );
    assert!(!may_inject(true, Some(RANGES), 0x3000, None), "no stack");
}

#[test]
fn a_stop_inside_an_allocator_range_is_refused() {
    assert!(
        !may_inject(true, Some(RANGES), 0x1000, Some(CLEAR)),
        "range start"
    );
    assert!(
        !may_inject(true, Some(RANGES), 0x1fff, Some(CLEAR)),
        "range last byte"
    );
    assert!(
        !may_inject(true, Some(RANGES), 0x5050, Some(CLEAR)),
        "second range"
    );
}

#[test]
fn a_range_end_is_outside_the_range() {
    assert!(
        may_inject(true, Some(RANGES), 0x2000, Some(CLEAR)),
        "first end"
    );
    assert!(
        may_inject(true, Some(RANGES), 0x5100, Some(CLEAR)),
        "second end"
    );
}

#[test]
fn a_stack_word_inside_an_allocator_range_is_refused() {
    assert!(!may_inject(
        true,
        Some(RANGES),
        0x3000,
        Some(&[0x7000, 0x1234])
    ));
    assert!(may_inject(
        true,
        Some(RANGES),
        0x3000,
        Some(&[0x2000, 0x5100])
    ));
}

#[test]
fn this_host_has_xsave() {
    // The injected trampoline needs XSAVE, so leakgc refuses to inject without it.
    assert!(xsave_available());
}
