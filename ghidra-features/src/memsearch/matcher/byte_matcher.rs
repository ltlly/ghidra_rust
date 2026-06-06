//! `ByteMatcher` trait -- the core matching interface.
//!
//! Ported from `ghidra.features.base.memsearch.matcher.ByteMatcher`.

use crate::memsearch::matcher::Match;

/// Trait for objects that scan byte sequences looking for patterns.
///
/// This is the core interface for memory search matching. Implementations
/// define what byte sequences to match and how to search for them.
pub trait ByteMatcher {
    /// Search a byte slice for all matches of this matcher's pattern.
    ///
    /// Returns all matches found in the given bytes, starting from the
    /// given base offset.
    fn match_bytes(&self, bytes: &[u8], base_offset: u64) -> Vec<Match>;

    /// Return a description of what this matcher matches.
    fn description(&self) -> &str;

    /// Return the length (in bytes) of the pattern being matched.
    fn pattern_length(&self) -> usize;
}
