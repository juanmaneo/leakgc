//! Conservative reachability over raw words, exercised through the public API.

use std::collections::BTreeSet;

use leakgc::gc::conservative::{Incomplete, Object, Words, mark};

fn block(start: u64, size: u64, words: &[u64]) -> Object {
    Object {
        start,
        size,
        words: Words::Read(words.to_vec()),
    }
}

fn root(words: &[u64]) -> Words {
    Words::Read(words.to_vec())
}

fn set(starts: &[u64]) -> BTreeSet<u64> {
    starts.iter().copied().collect()
}

#[test]
fn no_roots_marks_nothing() {
    let objects = [block(0x1000, 16, &[])];
    assert_eq!(mark(&[], &objects), Ok(BTreeSet::new()));
}

#[test]
fn roots_with_no_tracked_objects_mark_nothing() {
    assert_eq!(mark(&[root(&[0, u64::MAX])], &[]), Ok(BTreeSet::new()));
}

#[test]
fn root_at_block_start_marks_it() {
    let objects = [block(0x1000, 16, &[])];
    assert_eq!(mark(&[root(&[0x1000])], &objects), Ok(set(&[0x1000])));
}

#[test]
fn interior_pointer_marks_the_block() {
    let objects = [block(0x1000, 16, &[])];
    assert_eq!(mark(&[root(&[0x100f])], &objects), Ok(set(&[0x1000])));
}

#[test]
fn one_past_the_end_does_not_mark_the_block() {
    let objects = [block(0x1000, 16, &[]), block(0x2000, 16, &[])];
    assert_eq!(mark(&[root(&[0x1010])], &objects), Ok(set(&[])));
}

#[test]
fn pointers_below_or_between_blocks_mark_nothing() {
    let objects = [block(0x1000, 16, &[]), block(0x2000, 16, &[])];
    assert_eq!(mark(&[root(&[0x0fff])], &objects), Ok(set(&[])));
    assert_eq!(mark(&[root(&[0x1800])], &objects), Ok(set(&[])));
}

#[test]
fn non_pointer_words_are_ignored() {
    let objects = [block(0x1000, 16, &[])];
    assert_eq!(mark(&[root(&[0, 1, u64::MAX])], &objects), Ok(set(&[])));
}

#[test]
fn non_pointer_words_in_reachable_objects_are_ignored() {
    let objects = [block(0x1000, 16, &[0, 1, u64::MAX])];
    assert_eq!(mark(&[root(&[0x1000])], &objects), Ok(set(&[0x1000])));
}

#[test]
fn zero_size_block_is_kept_by_its_start() {
    let objects = [block(0x1000, 0, &[])];
    assert_eq!(mark(&[root(&[0x1000])], &objects), Ok(set(&[0x1000])));
    assert_eq!(mark(&[root(&[0x1001])], &objects), Ok(set(&[])));
}

#[test]
fn marks_transitively_and_leaves_unreferenced_blocks() {
    let objects = [
        block(0x1000, 16, &[0x2000]),
        block(0x2000, 16, &[0x3008]),
        block(0x3000, 16, &[]),
        block(0x4000, 16, &[]),
    ];
    assert_eq!(
        mark(&[root(&[0x1000])], &objects),
        Ok(set(&[0x1000, 0x2000, 0x3000]))
    );
}

#[test]
fn cycles_terminate() {
    let objects = [
        block(0x1000, 16, &[0x2000]),
        block(0x2000, 16, &[0x1000, 0x2008]),
    ];
    assert_eq!(
        mark(&[root(&[0x1000])], &objects),
        Ok(set(&[0x1000, 0x2000]))
    );
}

#[test]
fn several_roots_to_one_block_mark_it_once() {
    let objects = [block(0x1000, 16, &[])];
    assert_eq!(
        mark(&[root(&[0x1000]), root(&[0x1004, 0x100c])], &objects),
        Ok(set(&[0x1000]))
    );
}

#[test]
fn unreadable_root_is_incomplete() {
    let objects = [block(0x1000, 16, &[])];
    assert_eq!(mark(&[Words::Unreadable], &objects), Err(Incomplete));
}

#[test]
fn unreadable_reached_block_is_incomplete() {
    let objects = [
        block(0x1000, 16, &[0x2000]),
        Object {
            start: 0x2000,
            size: 16,
            words: Words::Unreadable,
        },
    ];
    assert_eq!(mark(&[root(&[0x1000])], &objects), Err(Incomplete));
}

#[test]
fn unreadable_unreached_block_does_not_block_marking() {
    let objects = [
        block(0x1000, 16, &[]),
        Object {
            start: 0x2000,
            size: 16,
            words: Words::Unreadable,
        },
    ];
    assert_eq!(mark(&[root(&[0x1000])], &objects), Ok(set(&[0x1000])));
}

#[test]
fn block_at_the_top_of_the_address_space() {
    let objects = [block(u64::MAX - 15, 16, &[])];
    assert_eq!(
        mark(&[root(&[u64::MAX])], &objects),
        Ok(set(&[u64::MAX - 15]))
    );
}
