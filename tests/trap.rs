use leakgc::trap::{TRAPPED, name_of};

#[test]
fn names_every_trapped_call() {
    for &(nr, name) in TRAPPED {
        assert_eq!(name_of(nr), name);
    }
}

#[test]
fn unlisted_calls_are_named_unknown() {
    assert_eq!(name_of(libc::SYS_read), "unknown");
    assert_eq!(name_of(-1), "unknown");
}
