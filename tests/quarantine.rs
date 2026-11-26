//! The quarantine with every memory access scripted through the fake tracee:
//! which blocks are poisoned and held, which ones are confirmed, and which
//! changes make the update fail.

mod common;

use std::ops::Range;

use common::*;
use leakgc::quarantine::{POISON, Quarantine};
use leakgc::reach::reachable;

const STACK: (u64, u64) = (0x7fff_e000, 0x7fff_f800);
const RSP: u64 = 0x7fff_f000;
const HEAP: (u64, u64) = (0x6000_0000, 0x6000_4000);
const BIG: (u64, u64) = (0x6400_0000, 0x6402_0000);
const SHARED: (u64, u64) = (0x6200_0000, 0x6200_1000);
const READ_ONLY: (u64, u64) = (0x5000_0000, 0x5000_1000);
/// A hook region far from every mapping, so it excludes nothing by accident.
const FAR_HOOK: Range<u64> = 0x1000_0000..0x1000_1000;

/// Kept alive by a stack root.
const X: u64 = 0x6000_0000;
/// Unreached and inside a private writable mapping, so freeable.
const Y: u64 = 0x6000_0100;
const Z: u64 = 0x6000_0200;

fn scene() -> Fake {
    let mut fake = Fake::new(&[], vec![]);
    map_writable(&mut fake, STACK.0, STACK.1);
    map_writable(&mut fake, HEAP.0, HEAP.1);
    put_word(&mut fake, RSP + 0x100, X);
    fake
}

/// A mapping whose bytes are all present, so it can be read.
fn filled_mapping(fake: &mut Fake, start: u64, end: u64, perms: &str) {
    map_line(fake, start, end, perms);
    for addr in start..end {
        fake.mem.entry(addr).or_insert(0);
    }
}

/// Runs one scan of `blocks`, then one quarantine update on its result.
fn update(
    quarantine: &mut Quarantine,
    fake: &mut Fake,
    blocks: &[(u64, u64)],
) -> Result<(), String> {
    let scan = reachable(fake, pid(), FAR_HOOK, blocks).expect("the scan completes");
    quarantine.update(fake, pid(), blocks, &scan)
}

#[test]
fn an_unreached_block_is_poisoned_and_held_unconfirmed() {
    let mut fake = scene();
    let mut quarantine = Quarantine::default();

    update(&mut quarantine, &mut fake, &[(X, 16), (Y, 16)]).expect("the update holds Y");

    assert_eq!(fake.writes, vec![(Y, vec![POISON; 16])]);
    assert!(quarantine.released(Y).is_some());
    assert!(quarantine.released(X).is_none());
    assert!(quarantine.confirmed().is_empty());
}

#[test]
fn a_held_block_that_survives_another_cycle_is_confirmed_and_poisoned_once() {
    let mut fake = scene();
    let mut quarantine = Quarantine::default();
    let blocks = [(X, 16), (Y, 16)];
    update(&mut quarantine, &mut fake, &blocks).expect("the first cycle holds Y");

    update(&mut quarantine, &mut fake, &blocks).expect("the second cycle confirms Y");

    assert_eq!(quarantine.confirmed(), vec![(Y, 16)]);
    assert_eq!(fake.writes.len(), 1, "a held block is poisoned once");
}

#[test]
fn a_block_held_in_the_last_cycle_is_not_confirmed_yet() {
    let mut fake = scene();
    let mut quarantine = Quarantine::default();
    update(&mut quarantine, &mut fake, &[(X, 16), (Y, 16)]).expect("the first cycle");

    update(&mut quarantine, &mut fake, &[(X, 16), (Y, 16), (Z, 32)]).expect("the second cycle");

    assert_eq!(quarantine.confirmed(), vec![(Y, 16)]);
    assert!(quarantine.released(Z).is_some());
}

#[test]
fn a_reached_or_unfreeable_block_is_not_poisoned() {
    let mut fake = scene();
    filled_mapping(&mut fake, SHARED.0, SHARED.1, "rw-s");
    filled_mapping(&mut fake, READ_ONLY.0, READ_ONLY.1, "r--p");
    let mut quarantine = Quarantine::default();
    let blocks = [
        (X, 16),
        (SHARED.0, 16),
        (READ_ONLY.0, 16),
        (0x4000_0000, 16),
    ];

    update(&mut quarantine, &mut fake, &blocks).expect("nothing is held");

    assert!(fake.writes.is_empty());
    assert!(quarantine.released(SHARED.0).is_none());
    assert!(quarantine.released(READ_ONLY.0).is_none());
}

#[test]
fn a_held_block_that_is_reached_again_is_an_error() {
    let mut fake = scene();
    let mut quarantine = Quarantine::default();
    let blocks = [(X, 16), (Y, 16)];
    update(&mut quarantine, &mut fake, &blocks).expect("the first cycle holds Y");
    put_word(&mut fake, RSP + 0x108, Y);

    let error = update(&mut quarantine, &mut fake, &blocks).expect_err("Y is reached");

    assert!(
        error.starts_with("a held block at 0x60000100 is reachable again"),
        "{error}"
    );
}

#[test]
fn a_held_block_that_was_written_to_is_an_error() {
    let mut fake = scene();
    let mut quarantine = Quarantine::default();
    let blocks = [(X, 16), (Y, 16)];
    update(&mut quarantine, &mut fake, &blocks).expect("the first cycle holds Y");
    fake.poke(Y + 4, &[0x42]);

    let error = update(&mut quarantine, &mut fake, &blocks).expect_err("Y was written to");

    assert!(
        error.starts_with("a held block at 0x60000100 was written to"),
        "{error}"
    );
}

#[test]
fn a_held_block_whose_bytes_cannot_be_read_is_an_error() {
    let mut fake = scene();
    let mut quarantine = Quarantine::default();
    let blocks = [(X, 16), (Y, 16)];
    update(&mut quarantine, &mut fake, &blocks).expect("the first cycle holds Y");
    fake.mem.remove(&(Y + 4));

    let error = update(&mut quarantine, &mut fake, &blocks).expect_err("Y cannot be read");

    assert_eq!(
        error,
        "a held block at 0x60000100 could not be read: unmapped 0x60000104"
    );
}

#[test]
fn a_held_block_that_is_no_longer_outstanding_is_an_error() {
    let mut fake = scene();
    let mut quarantine = Quarantine::default();
    update(&mut quarantine, &mut fake, &[(X, 16), (Y, 16)]).expect("the first cycle holds Y");

    let error = update(&mut quarantine, &mut fake, &[(X, 16)]).expect_err("Y is gone");

    assert!(
        error.starts_with("a held block at 0x60000100 is no longer outstanding at its size"),
        "{error}"
    );
}

#[test]
fn a_held_block_whose_size_changed_is_an_error() {
    let mut fake = scene();
    let mut quarantine = Quarantine::default();
    update(&mut quarantine, &mut fake, &[(X, 16), (Y, 16)]).expect("the first cycle holds Y");

    let error = update(&mut quarantine, &mut fake, &[(X, 16), (Y, 32)]).expect_err("Y grew");

    assert!(
        error.starts_with("a held block at 0x60000100 is no longer outstanding at its size"),
        "{error}"
    );
}

#[test]
fn a_block_larger_than_one_chunk_is_poisoned_and_checked_in_pieces() {
    let mut fake = scene();
    map_writable(&mut fake, BIG.0, BIG.1);
    let size = 0x1_1000;
    let blocks = [(X, 16), (BIG.0, size)];
    let mut quarantine = Quarantine::default();

    update(&mut quarantine, &mut fake, &blocks).expect("the first cycle holds the big block");
    assert_eq!(
        fake.writes,
        vec![
            (BIG.0, vec![POISON; 0x1_0000]),
            (BIG.0 + 0x1_0000, vec![POISON; 0x1000]),
        ]
    );

    update(&mut quarantine, &mut fake, &blocks).expect("the second cycle reads it back");
    assert_eq!(quarantine.confirmed(), vec![(BIG.0, size)]);
}

#[test]
fn a_zero_size_block_is_poisoned_in_one_byte() {
    let mut fake = scene();
    let mut quarantine = Quarantine::default();
    let blocks = [(X, 16), (Z, 0)];

    update(&mut quarantine, &mut fake, &blocks).expect("the first cycle holds Z");
    assert_eq!(fake.writes, vec![(Z, vec![POISON])]);

    update(&mut quarantine, &mut fake, &blocks).expect("the second cycle confirms Z");
    assert_eq!(quarantine.confirmed(), vec![(Z, 0)]);
}

#[test]
fn a_free_of_a_held_block_is_reported_and_other_pointers_are_not() {
    let mut fake = scene();
    let mut quarantine = Quarantine::default();
    update(&mut quarantine, &mut fake, &[(X, 16), (Y, 16)]).expect("the first cycle holds Y");

    let reason = quarantine.released(Y).expect("Y is held");

    assert!(
        reason.starts_with("a held block at 0x60000100 was freed"),
        "{reason}"
    );
    assert!(quarantine.released(Y + 8).is_none());
    assert!(quarantine.released(X).is_none());
}

#[test]
fn a_block_that_cannot_be_poisoned_is_an_error_and_is_not_held() {
    let mut fake = scene();
    fake.fail_writes = true;
    let mut quarantine = Quarantine::default();

    let error = update(&mut quarantine, &mut fake, &[(X, 16), (Y, 16)])
        .expect_err("the poison write fails");

    assert_eq!(
        error,
        "a block at 0x60000100 could not be poisoned: injected write failure"
    );
    assert!(quarantine.released(Y).is_none());
}
