//! Conservative reachability over raw words (P4a). A word keeps a block alive
//! if it points anywhere inside the block, so interior pointers count. Words
//! are never checked for being pointers, so a false positive only keeps a
//! block alive. This module reads no memory: the caller supplies the words.
//!
//! Fail-closed: if a root or a block that is reached by marking cannot be
//! read, the result is `Err(Incomplete)` and the caller must free nothing.

use std::collections::{BTreeMap, BTreeSet};

/// The words of one memory range, or a marker that the range could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Words {
    Read(Vec<u64>),
    Unreadable,
}

/// One allocated block, `[start, start + size)`. A zero-size block still
/// occupies one byte, because `malloc(0)` returns a pointer the program may
/// keep. Blocks must not overlap and starts must be unique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    pub start: u64,
    pub size: u64,
    pub words: Words,
}

/// A root or a reached block could not be read, so the marks cannot be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Incomplete;

/// Start addresses of every block reachable from `roots`.
pub fn mark(roots: &[Words], objects: &[Object]) -> Result<BTreeSet<u64>, Incomplete> {
    let index: BTreeMap<u64, &Object> = objects.iter().map(|o| (o.start, o)).collect();
    let mut worklist = Vec::new();
    for root in roots {
        worklist.extend(candidates(root)?.iter().filter_map(|&w| owner(&index, w)));
    }
    let mut marked = BTreeSet::new();
    while let Some(start) = worklist.pop() {
        if !marked.insert(start) {
            continue;
        }
        for &word in candidates(&index[&start].words)? {
            if let Some(next) = owner(&index, word) {
                worklist.push(next);
            }
        }
    }
    Ok(marked)
}

fn candidates(words: &Words) -> Result<&[u64], Incomplete> {
    match words {
        Words::Read(words) => Ok(words),
        Words::Unreadable => Err(Incomplete),
    }
}

/// The start of the block that contains `word`, if any.
fn owner(index: &BTreeMap<u64, &Object>, word: u64) -> Option<u64> {
    let (&start, object) = index.range(..=word).next_back()?;
    (word - start < object.size.max(1)).then_some(start)
}
