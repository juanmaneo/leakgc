//! Layout of the allocation record ring that the hook trampolines write (PLAN 4.6, R21).
//!
//! Each hooked call appends one record, found through a monotonic head counter.
//! The entry trampoline fills the record in and marks it open. The exit stub
//! stores the result and marks it done. A drain stops at the first open record,
//! so a call still in progress is read on a later drain. Only the newest
//! `CAPACITY` records survive.

/// Records in the ring. A power of two, so the trampoline can mask the head.
pub const CAPACITY: u64 = 1 << 20;

/// Bytes per record: six words, then padding to a cache line.
pub const RECORD_LEN: usize = 64;

/// Which hooked function a record came from. The trampolines store these values.
/// `Memalign` covers `memalign` and `aligned_alloc`, which take the size second.
/// `Valloc` covers `valloc` and `pvalloc`, which take only the size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Malloc = 1,
    Free = 2,
    Realloc = 3,
    Calloc = 4,
    Memalign = 5,
    Valloc = 6,
}

impl Kind {
    fn from_word(word: u64) -> Option<Kind> {
        match word {
            1 => Some(Kind::Malloc),
            2 => Some(Kind::Free),
            3 => Some(Kind::Realloc),
            4 => Some(Kind::Calloc),
            5 => Some(Kind::Memalign),
            6 => Some(Kind::Valloc),
            _ => None,
        }
    }
}

/// A finished hooked call. `size` is the requested size, `arg` is the pointer
/// the call was given (zero when none), and `result` is what it returned. For
/// `Calloc`, `size` is the element count and `arg` is the element size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub kind: Kind,
    pub size: u64,
    pub caller: u64,
    pub arg: u64,
    pub result: u64,
}

/// One ring slot. `Open` means the call has not returned yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    Open,
    Done(Record),
}

/// Decodes a slot. `None` means the slot is neither a valid open nor a valid
/// done record, which the drain treats as corruption.
pub fn decode(bytes: &[u8; RECORD_LEN]) -> Option<Slot> {
    let kind = Kind::from_word(word(bytes, 32))?;
    match word(bytes, 40) {
        0 => Some(Slot::Open),
        1 => Some(Slot::Done(Record {
            kind,
            size: word(bytes, 0),
            caller: word(bytes, 8),
            arg: word(bytes, 16),
            result: word(bytes, 24),
        })),
        _ => None,
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

/// The ring slots that hold records `first..first + count`, as `(slot, len)`
/// runs. A run ends where the ring wraps, so each one is a single read.
pub fn slot_runs(first: u64, count: u64) -> Vec<(u64, u64)> {
    let mut runs = Vec::new();
    let mut at = first;
    let mut left = count;
    while left > 0 {
        let slot = at % CAPACITY;
        let len = left.min(CAPACITY - slot);
        runs.push((slot, len));
        at += len;
        left -= len;
    }
    runs
}
