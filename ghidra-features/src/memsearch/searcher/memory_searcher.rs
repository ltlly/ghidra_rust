//! `MemorySearcher` -- the core search engine.
//!
//! Ported from `ghidra.features.base.memsearch.searcher.MemorySearcher`.

use crate::memsearch::matcher::ByteMatcher;
use crate::memsearch::searcher::MemoryMatch;

/// Default chunk size for feeding bytes to the matcher.
const DEFAULT_CHUNK_SIZE: usize = 16 * 1024;
/// Overlap size between adjacent chunks to avoid missing matches at boundaries.
const OVERLAP_SIZE: usize = 100;

/// Searches bytes from a byte source using a [`ByteMatcher`].
///
/// Handles breaking the search into manageable chunks, processing address
/// gaps, and respecting search limits.
///
/// Supports incremental searching via [`find_next`](MemorySearcher::find_next),
/// [`find_previous`](MemorySearcher::find_previous), and
/// [`find_all`](MemorySearcher::find_all).
///
/// Ported from `MemorySearcher.java`.
pub struct MemorySearcher {
    matcher: Box<dyn ByteMatcher>,
    search_limit: usize,
    chunk_size: usize,
    alignment: usize,
}

impl MemorySearcher {
    /// Create a new memory searcher.
    pub fn new(matcher: Box<dyn ByteMatcher>, search_limit: usize) -> Self {
        Self {
            matcher,
            search_limit,
            chunk_size: DEFAULT_CHUNK_SIZE,
            alignment: 1,
        }
    }

    /// Create a new memory searcher with a custom chunk size.
    pub fn with_chunk_size(mut self, chunk_size: usize) -> Self {
        self.chunk_size = chunk_size;
        self
    }

    /// Set the alignment for matches (address must be a multiple of this value).
    pub fn with_alignment(mut self, alignment: usize) -> Self {
        self.alignment = alignment.max(1);
        self
    }

    /// Search all bytes in the given data and collect all matches.
    pub fn find_all(&self, data: &[u8], base_offset: u64) -> Vec<MemoryMatch> {
        let mut all_matches = Vec::new();
        let chunks = self.split_into_chunks(data);

        for (chunk, chunk_offset) in chunks {
            let actual_offset = base_offset + chunk_offset as u64;
            let matches = self.matcher.match_bytes(chunk, actual_offset);

            for m in matches {
                if self.alignment > 1 && (m.offset % self.alignment as u64) != 0 {
                    continue;
                }
                all_matches.push(MemoryMatch::new(m.offset, m.bytes));

                if all_matches.len() >= self.search_limit {
                    return all_matches;
                }
            }
        }

        all_matches
    }

    /// Find the next match starting from the given offset within the data.
    pub fn find_next(&self, data: &[u8], start_offset: u64, base_offset: u64) -> Option<MemoryMatch> {
        let start_idx = (start_offset.saturating_sub(base_offset)) as usize;
        if start_idx >= data.len() {
            return None;
        }

        let search_data = &data[start_idx..];
        let matches = self.matcher.match_bytes(search_data, start_offset);

        for m in matches {
            if m.offset >= start_offset {
                if self.alignment > 1 && (m.offset % self.alignment as u64) != 0 {
                    continue;
                }
                return Some(MemoryMatch::new(m.offset, m.bytes));
            }
        }
        None
    }

    /// Find the previous match before the given offset within the data.
    pub fn find_previous(&self, data: &[u8], before_offset: u64, base_offset: u64) -> Option<MemoryMatch> {
        let end_idx = (before_offset.saturating_sub(base_offset)) as usize;
        let search_data = if end_idx > 0 {
            &data[..end_idx.min(data.len())]
        } else {
            return None;
        };

        let mut matches = self.matcher.match_bytes(search_data, base_offset);
        matches.sort_by(|a, b| b.offset.cmp(&a.offset)); // reverse sort

        for m in matches {
            if m.offset < before_offset {
                if self.alignment > 1 && (m.offset % self.alignment as u64) != 0 {
                    continue;
                }
                return Some(MemoryMatch::new(m.offset, m.bytes));
            }
        }
        None
    }

    /// Split data into overlapping chunks for search processing.
    fn split_into_chunks<'a>(&self, data: &'a [u8]) -> Vec<(&'a [u8], usize)> {
        if data.len() <= self.chunk_size {
            return vec![(data, 0)];
        }

        let mut chunks = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let end = (offset + self.chunk_size + OVERLAP_SIZE).min(data.len());
            chunks.push((&data[offset..end], offset));
            offset += self.chunk_size;
        }

        chunks
    }

    /// Get the pattern length from the matcher.
    pub fn pattern_length(&self) -> usize {
        self.matcher.pattern_length()
    }

    /// Get the description from the matcher.
    pub fn description(&self) -> &str {
        self.matcher.description()
    }

    /// Get the search limit.
    pub fn search_limit(&self) -> usize {
        self.search_limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memsearch::matcher::MaskedByteSequenceByteMatcher;

    #[test]
    fn test_find_all_basic() {
        let matcher = MaskedByteSequenceByteMatcher::new_exact("55 89", vec![0x55, 0x89]);
        let searcher = MemorySearcher::new(Box::new(matcher), 100);
        let data = [0x90, 0x55, 0x89, 0xE5, 0x55, 0x89, 0xC3];
        let matches = searcher.find_all(&data, 0);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_find_all_with_limit() {
        let matcher = MaskedByteSequenceByteMatcher::new_exact("55", vec![0x55]);
        let searcher = MemorySearcher::new(Box::new(matcher), 2);
        let data = [0x55, 0x55, 0x55, 0x55];
        let matches = searcher.find_all(&data, 0);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_find_next() {
        let matcher = MaskedByteSequenceByteMatcher::new_exact("55", vec![0x55]);
        let searcher = MemorySearcher::new(Box::new(matcher), 100);
        let data = [0x55, 0x90, 0x55, 0x90];
        let m = searcher.find_next(&data, 1, 0);
        assert!(m.is_some());
        assert_eq!(m.unwrap().address(), 2);
    }

    #[test]
    fn test_find_previous() {
        let matcher = MaskedByteSequenceByteMatcher::new_exact("55", vec![0x55]);
        let searcher = MemorySearcher::new(Box::new(matcher), 100);
        let data = [0x55, 0x90, 0x55, 0x90];
        let m = searcher.find_previous(&data, 3, 0);
        assert!(m.is_some());
        assert_eq!(m.unwrap().address(), 2);
    }

    #[test]
    fn test_find_next_not_found() {
        let matcher = MaskedByteSequenceByteMatcher::new_exact("CC", vec![0xCC]);
        let searcher = MemorySearcher::new(Box::new(matcher), 100);
        let data = [0x55, 0x90, 0x55];
        let m = searcher.find_next(&data, 0, 0);
        assert!(m.is_none());
    }

    #[test]
    fn test_alignment_filter() {
        let matcher = MaskedByteSequenceByteMatcher::new_exact("55", vec![0x55]);
        let searcher = MemorySearcher::new(Box::new(matcher), 100).with_alignment(4);
        let data = [0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55];
        let matches = searcher.find_all(&data, 0);
        // Only at offsets 0, 4
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].address(), 0);
        assert_eq!(matches[1].address(), 4);
    }

    #[test]
    fn test_with_base_offset() {
        let matcher = MaskedByteSequenceByteMatcher::new_exact("55", vec![0x55]);
        let searcher = MemorySearcher::new(Box::new(matcher), 100);
        let data = [0x55, 0x90];
        let matches = searcher.find_all(&data, 0x401000);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].address(), 0x401000);
    }
}
