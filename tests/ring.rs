use win_games_leak_garbage_collector::ring::{
    CAPACITY, Drain, Kind, RECORD_LEN, Record, Slot, decode, plan_drain, slot_runs,
};

/// A slot with the given words. Padding after the done word is all ones.
fn slot(size: u64, caller: u64, arg: u64, result: u64, kind: u64, done: u64) -> [u8; RECORD_LEN] {
    let mut bytes = [0xffu8; RECORD_LEN];
    for (at, word) in [
        (0, size),
        (8, caller),
        (16, arg),
        (24, result),
        (32, kind),
        (40, done),
    ] {
        bytes[at..at + 8].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

#[test]
fn a_finished_record_decodes_its_five_words_and_ignores_padding() {
    let bytes = slot(16, 0x1234, 0, 0xdead_beef, 1, 1);
    assert_eq!(
        decode(&bytes),
        Some(Slot::Done(Record {
            kind: Kind::Malloc,
            size: 16,
            caller: 0x1234,
            arg: 0,
            result: 0xdead_beef,
        }))
    );
}

#[test]
fn each_hooked_function_has_its_own_kind() {
    for (word, kind) in [(2, Kind::Free), (3, Kind::Realloc)] {
        let bytes = slot(0, 0x10, 0x20, 0x30, word, 1);
        assert_eq!(
            decode(&bytes),
            Some(Slot::Done(Record {
                kind,
                size: 0,
                caller: 0x10,
                arg: 0x20,
                result: 0x30,
            }))
        );
    }
}

#[test]
fn a_slot_whose_call_has_not_returned_is_open() {
    let bytes = slot(16, 0x1234, 0, 0, 1, 0);
    assert_eq!(decode(&bytes), Some(Slot::Open));
}

#[test]
fn a_slot_with_an_unknown_kind_is_corrupt() {
    for word in [0, 4, u64::MAX] {
        assert_eq!(decode(&slot(0, 0, 0, 0, word, 1)), None, "kind {word}");
    }
}

#[test]
fn a_done_word_other_than_zero_or_one_is_corrupt() {
    assert_eq!(decode(&slot(0, 0, 0, 0, 1, 2)), None);
}

#[test]
fn drain_reads_only_records_since_the_last_drain() {
    assert_eq!(
        plan_drain(10, 15),
        Drain {
            first: 10,
            count: 5,
            lost: 0,
        }
    );
}

#[test]
fn empty_drain_reads_nothing() {
    assert_eq!(
        plan_drain(7, 7),
        Drain {
            first: 7,
            count: 0,
            lost: 0,
        }
    );
}

#[test]
fn exactly_full_ring_loses_nothing() {
    assert_eq!(
        plan_drain(0, CAPACITY),
        Drain {
            first: 0,
            count: CAPACITY,
            lost: 0,
        }
    );
}

#[test]
fn overwritten_records_are_counted_and_skipped() {
    assert_eq!(
        plan_drain(0, CAPACITY + 10),
        Drain {
            first: 10,
            count: CAPACITY,
            lost: 10,
        }
    );
}

#[test]
fn slot_runs_cover_records_in_one_read_when_the_ring_does_not_wrap() {
    assert_eq!(slot_runs(7, 5), vec![(7, 5)]);
    assert_eq!(slot_runs(CAPACITY + 3, 4), vec![(3, 4)]);
    assert_eq!(slot_runs(7, 0), Vec::<(u64, u64)>::new());
}

#[test]
fn slot_runs_split_where_the_ring_wraps() {
    assert_eq!(slot_runs(CAPACITY - 2, 5), vec![(CAPACITY - 2, 2), (0, 3)]);
    assert_eq!(slot_runs(0, CAPACITY), vec![(0, CAPACITY)]);
}
