//! Layout of the allocation record ring that the hook trampolines write (PLAN 4.6, R21).
//!
//! Each hooked call appends one record, found through a monotonic head counter.
//! Only the newest `CAPACITY` records survive. A drain reads the records written
//! since the previous drain, and reports how many were overwritten first.

/// Records in the ring. A power of two, so the trampoline can mask the head.
pub const CAPACITY: u64 = 1 << 20;

/// Bytes per record: size, caller return address, returned pointer, padding.
pub const RECORD_LEN: usize = 32;

/// One hooked call: the requested size, the caller's return address, and the
/// pointer the allocator returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub size: u64,
    pub caller: u64,
    pub ptr: u64,
}

impl Record {
    pub fn decode(bytes: &[u8; RECORD_LEN]) -> Record {
        Record {
            size: word(bytes, 0),
            caller: word(bytes, 8),
            ptr: word(bytes, 16),
        }
    }
}

fn word(bytes: &[u8; RECORD_LEN], at: usize) -> u64 {
    let mut word = [0; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(word)
}

/// What a drain must read, given the head at the previous drain and the head now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Drain {
    /// Index of the first record to read, counted from the start of the run.
    pub first: u64,
    /// Number of records to read, starting at `first`.
    pub count: u64,
    /// Records overwritten since the last drain. Any value above zero means the
    /// collection is incomplete, and it must free nothing (R21).
    pub lost: u64,
}

pub fn plan_drain(cursor: u64, head: u64) -> Drain {
    let new = head.saturating_sub(cursor);
    let lost = new.saturating_sub(CAPACITY);
    Drain {
        first: cursor + lost,
        count: new - lost,
        lost,
    }
}
