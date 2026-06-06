//! Byte matchers for memory search -- ported from
//! `ghidra.features.base.memsearch.matcher`.
//!
//! Provides the [`ByteMatcher`] trait and implementations for matching
//! byte patterns in memory, including masked sequences, regex, and bulk patterns.

mod byte_matcher;
mod search_data;
mod masked;
mod regex_matcher;
mod invalid;
mod bulk;
mod user_input;

pub use byte_matcher::ByteMatcher;
pub use search_data::SearchData;
pub use masked::MaskedByteSequenceByteMatcher;
pub use regex_matcher::RegExByteMatcher;
pub use invalid::InvalidByteMatcher;
pub use bulk::BulkPatternByteMatcher;
pub use user_input::UserInputByteMatcher;

/// A match found during a memory search.
#[derive(Debug, Clone)]
pub struct Match {
    /// The offset where the match was found.
    pub offset: u64,
    /// The matched bytes.
    pub bytes: Vec<u8>,
}

impl Match {
    /// Create a new match at the given offset.
    pub fn new(offset: u64, bytes: Vec<u8>) -> Self {
        Self { offset, bytes }
    }

    /// The length of the matched pattern in bytes.
    pub fn length(&self) -> usize {
        self.bytes.len()
    }
}

impl PartialOrd for Match {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Match {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.offset.cmp(&other.offset)
    }
}

impl PartialEq for Match {
    fn eq(&self, other: &Self) -> bool {
        self.offset == other.offset && self.bytes == other.bytes
    }
}

impl Eq for Match {}
