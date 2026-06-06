//! Scan algorithms for examining search result changes.
//!
//! Ported from `ghidra.features.base.memsearch.scan`.
//!
//! Each [`Scanner`] examines byte values of existing search results
//! and determines which results to keep based on value changes.

use crate::memsearch::searcher::MemoryMatch;

/// Scan algorithms that examine the byte values of existing search results
/// and look for changes.
///
/// Ported from `ghidra.features.base.memsearch.scan.Scanner`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scanner {
    /// Keep results whose values did not change.
    Equals,
    /// Keep results whose values changed.
    NotEquals,
    /// Keep results whose values increased.
    Increased,
    /// Keep results whose values decreased.
    Decreased,
}

impl Scanner {
    /// Get the display name of this scanner.
    pub fn name(&self) -> &str {
        match self {
            Scanner::Equals => "Equals",
            Scanner::NotEquals => "Not Equals",
            Scanner::Increased => "Increased",
            Scanner::Decreased => "Decreased",
        }
    }

    /// Get a description of what this scanner does.
    pub fn description(&self) -> &str {
        match self {
            Scanner::Equals => "Keep results whose values didn't change",
            Scanner::NotEquals => "Keep results whose values changed",
            Scanner::Increased => "Keep results whose values increased",
            Scanner::Decreased => "Keep results whose values decreased",
        }
    }

    /// Test whether a match should be accepted by this scanner.
    ///
    /// Compares the current bytes of the match against its previous bytes.
    pub fn accept(&self, match_item: &MemoryMatch) -> bool {
        let cmp = compare_bytes(match_item.current_bytes(), match_item.previous_bytes());
        match self {
            Scanner::Equals => cmp == 0,
            Scanner::NotEquals => cmp != 0,
            Scanner::Increased => cmp > 0,
            Scanner::Decreased => cmp < 0,
        }
    }

    /// Filter a set of matches using this scanner's criteria.
    pub fn filter(&self, matches: &[MemoryMatch]) -> Vec<MemoryMatch> {
        matches.iter().filter(|m| self.accept(m)).cloned().collect()
    }

    /// Get all available scanners.
    pub fn all() -> [Scanner; 4] {
        [
            Scanner::Equals,
            Scanner::NotEquals,
            Scanner::Increased,
            Scanner::Decreased,
        ]
    }
}

impl std::fmt::Display for Scanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Compare two byte arrays as unsigned values.
/// Returns negative, zero, or positive.
fn compare_bytes(a: &[u8], b: &[u8]) -> i32 {
    for (x, y) in a.iter().zip(b.iter()) {
        let cmp = (*x as i32) - (*y as i32);
        if cmp != 0 {
            return cmp;
        }
    }
    (a.len() as i32) - (b.len() as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: first value = old/previous, second = new/current
    fn make_match_with_bytes(addr: u64, old_value: Vec<u8>, new_value: Vec<u8>) -> MemoryMatch {
        let mut m = MemoryMatch::new(addr, old_value);
        m.update_bytes(new_value);
        m
    }

    #[test]
    fn test_equals_unchanged() {
        let m = make_match_with_bytes(0x1000, vec![0x55], vec![0x55]);
        assert!(Scanner::Equals.accept(&m));
    }

    #[test]
    fn test_equals_changed() {
        let m = make_match_with_bytes(0x1000, vec![0x55], vec![0x56]);
        assert!(!Scanner::Equals.accept(&m));
    }

    #[test]
    fn test_not_equals_changed() {
        let m = make_match_with_bytes(0x1000, vec![0x55], vec![0x56]);
        assert!(Scanner::NotEquals.accept(&m));
    }

    #[test]
    fn test_increased() {
        let m = make_match_with_bytes(0x1000, vec![0x55], vec![0x56]);
        assert!(Scanner::Increased.accept(&m));
    }

    #[test]
    fn test_decreased() {
        let m = make_match_with_bytes(0x1000, vec![0x55], vec![0x54]);
        assert!(Scanner::Decreased.accept(&m));
    }

    #[test]
    fn test_filter() {
        let matches = vec![
            make_match_with_bytes(0x1000, vec![0x55], vec![0x56]), // 55->56 increased
            make_match_with_bytes(0x1001, vec![0x55], vec![0x55]), // 55->55 equals
            make_match_with_bytes(0x1002, vec![0x55], vec![0x54]), // 55->54 decreased
        ];
        let filtered = Scanner::Increased.filter(&matches);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].address(), 0x1000);
    }

    #[test]
    fn test_all_scanners() {
        assert_eq!(Scanner::all().len(), 4);
    }

    #[test]
    fn test_name() {
        assert_eq!(Scanner::Equals.name(), "Equals");
        assert_eq!(Scanner::NotEquals.name(), "Not Equals");
        assert_eq!(Scanner::Increased.name(), "Increased");
        assert_eq!(Scanner::Decreased.name(), "Decreased");
    }
}
