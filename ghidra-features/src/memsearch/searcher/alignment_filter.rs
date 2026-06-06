//! `AlignmentFilter` -- filters search results by address alignment.
//!
//! Ported from `ghidra.features.base.memsearch.searcher.AlignmentFilter`.

use crate::memsearch::searcher::MemoryMatch;

/// Filter that accepts matches only at addresses aligned to a given boundary.
///
/// Ported from `AlignmentFilter.java`.
#[derive(Debug, Clone)]
pub struct AlignmentFilter {
    alignment: usize,
}

impl AlignmentFilter {
    /// Create a new alignment filter.
    pub fn new(alignment: usize) -> Self {
        Self {
            alignment: alignment.max(1),
        }
    }

    /// Test if a match passes this filter.
    pub fn accept(&self, match_item: &MemoryMatch) -> bool {
        match_item.address() % self.alignment as u64 == 0
    }

    /// Filter a set of matches.
    pub fn filter(&self, matches: &[MemoryMatch]) -> Vec<MemoryMatch> {
        matches.iter().filter(|m| self.accept(m)).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alignment_4() {
        let filter = AlignmentFilter::new(4);
        let m1 = MemoryMatch::new(0x1000, vec![0x55]);
        let m2 = MemoryMatch::new(0x1001, vec![0x55]);
        let m3 = MemoryMatch::new(0x1004, vec![0x55]);
        assert!(filter.accept(&m1));
        assert!(!filter.accept(&m2));
        assert!(filter.accept(&m3));
    }

    #[test]
    fn test_alignment_1() {
        let filter = AlignmentFilter::new(1);
        let m = MemoryMatch::new(0x1003, vec![0x55]);
        assert!(filter.accept(&m));
    }
}
