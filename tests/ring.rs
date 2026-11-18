use win_games_leak_garbage_collector::ring::{CAPACITY, Drain, RECORD_LEN, Record, plan_drain};

#[test]
fn record_decodes_three_little_endian_words_and_ignores_padding() {
    let mut bytes = [0u8; RECORD_LEN];
    bytes[0..8].copy_from_slice(&16u64.to_le_bytes());
    bytes[8..16].copy_from_slice(&0x1234u64.to_le_bytes());
    bytes[16..24].copy_from_slice(&0xdead_beefu64.to_le_bytes());
    bytes[24..].fill(0xff);
    assert_eq!(
        Record::decode(&bytes),
        Record {
            size: 16,
            caller: 0x1234,
            ptr: 0xdead_beef,
        }
    );
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
