use leakgc::ledger::{ImageReport, Ledger, Site};
use leakgc::ring::{Kind, Record};

const A: u64 = 0xa;
const B: u64 = 0xb;

fn malloc(caller: u64, size: u64, result: u64) -> Record {
    Record {
        kind: Kind::Malloc,
        size,
        caller,
        arg: 0,
        result,
    }
}

fn free(caller: u64, ptr: u64) -> Record {
    Record {
        kind: Kind::Free,
        size: 0,
        caller,
        arg: ptr,
        result: 0,
    }
}

fn realloc(caller: u64, ptr: u64, size: u64, result: u64) -> Record {
    Record {
        kind: Kind::Realloc,
        size,
        caller,
        arg: ptr,
        result,
    }
}

fn site(caller: u64, blocks: u64, bytes: u64) -> Site {
    Site {
        caller,
        blocks,
        bytes,
    }
}

#[test]
fn a_malloc_holds_a_block_for_its_caller() {
    let mut ledger = Ledger::default();
    ledger.apply(malloc(A, 16, 0x1000));

    assert_eq!(ledger.sites(), vec![site(A, 1, 16)]);
    assert_eq!(ledger.unknown_frees(), 0);
}

#[test]
fn a_malloc_that_returned_null_holds_nothing() {
    let mut ledger = Ledger::default();
    ledger.apply(malloc(A, 16, 0));

    assert!(ledger.sites().is_empty());
}

#[test]
fn a_free_releases_its_block() {
    let mut ledger = Ledger::default();
    ledger.apply(malloc(A, 16, 0x1000));
    ledger.apply(free(B, 0x1000));

    assert!(ledger.sites().is_empty());
    assert_eq!(ledger.unknown_frees(), 0);
}

#[test]
fn a_free_of_null_does_nothing() {
    let mut ledger = Ledger::default();
    ledger.apply(free(B, 0));

    assert!(ledger.sites().is_empty());
    assert_eq!(ledger.unknown_frees(), 0);
}

#[test]
fn a_free_of_a_pointer_never_seen_is_counted() {
    let mut ledger = Ledger::default();
    ledger.apply(free(B, 0x9999));

    assert_eq!(ledger.unknown_frees(), 1);
}

#[test]
fn a_realloc_that_moves_releases_the_old_block_and_holds_the_new_one() {
    let mut ledger = Ledger::default();
    ledger.apply(malloc(A, 16, 0x1000));
    ledger.apply(realloc(B, 0x1000, 100, 0x2000));

    assert_eq!(ledger.sites(), vec![site(B, 1, 100)]);
    assert_eq!(ledger.unknown_frees(), 0);
}

#[test]
fn a_realloc_that_grows_in_place_keeps_one_block() {
    let mut ledger = Ledger::default();
    ledger.apply(malloc(A, 16, 0x1000));
    ledger.apply(realloc(B, 0x1000, 32, 0x1000));

    assert_eq!(ledger.sites(), vec![site(B, 1, 32)]);
    assert_eq!(ledger.unknown_frees(), 0);
}

#[test]
fn a_failed_realloc_keeps_the_old_block() {
    let mut ledger = Ledger::default();
    ledger.apply(malloc(A, 16, 0x1000));
    ledger.apply(realloc(B, 0x1000, 100, 0));

    assert_eq!(ledger.sites(), vec![site(A, 1, 16)]);
    assert_eq!(ledger.unknown_frees(), 0);
}

#[test]
fn a_realloc_to_zero_frees_the_block() {
    let mut ledger = Ledger::default();
    ledger.apply(malloc(A, 16, 0x1000));
    ledger.apply(realloc(B, 0x1000, 0, 0));

    assert!(ledger.sites().is_empty());
    assert_eq!(ledger.unknown_frees(), 0);
}

#[test]
fn a_realloc_of_null_allocates() {
    let mut ledger = Ledger::default();
    ledger.apply(realloc(B, 0, 50, 0x3000));

    assert_eq!(ledger.sites(), vec![site(B, 1, 50)]);
    assert_eq!(ledger.unknown_frees(), 0);
}

#[test]
fn a_realloc_of_a_pointer_never_seen_counts_the_free_and_holds_the_result() {
    let mut ledger = Ledger::default();
    ledger.apply(realloc(B, 0x9999, 10, 0x4000));

    assert_eq!(ledger.sites(), vec![site(B, 1, 10)]);
    assert_eq!(ledger.unknown_frees(), 1);
}

#[test]
fn sites_group_blocks_by_caller_in_address_order() {
    let mut ledger = Ledger::default();
    ledger.apply(malloc(B, 8, 0x1000));
    ledger.apply(malloc(A, 16, 0x2000));
    ledger.apply(malloc(A, 32, 0x3000));

    assert_eq!(ledger.sites(), vec![site(A, 2, 48), site(B, 1, 8)]);
}

#[test]
fn a_report_lists_its_totals_notes_sites_and_unknown_frees() {
    let mut ledger = Ledger::default();
    ledger.apply(malloc(A, 16, 0x1000));
    ledger.apply(malloc(A, 32, 0x2000));
    ledger.apply(malloc(B, 8, 0x3000));
    ledger.apply(free(B, 0x9999));
    let report = ImageReport::new(
        "image 1 (pid 100)".to_string(),
        &ledger,
        vec!["hooked".to_string()],
    );

    assert_eq!(
        report.lines(),
        vec![
            "image 1 (pid 100): 3 blocks, 56 bytes outstanding (not yet checked for reachability, P4)",
            "  note: hooked",
            "  caller 0xa: 2 blocks, 48 bytes",
            "  caller 0xb: 1 blocks, 8 bytes",
            "  unknown frees: 1",
        ]
    );
}

#[test]
fn an_empty_report_has_only_its_header() {
    let report = ImageReport::new("image 2 (pid 7)".to_string(), &Ledger::default(), vec![]);

    assert_eq!(
        report.lines(),
        vec![
            "image 2 (pid 7): 0 blocks, 0 bytes outstanding (not yet checked for reachability, P4)"
        ]
    );
}
