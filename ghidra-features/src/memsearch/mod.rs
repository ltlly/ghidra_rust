//! Memory Search Plugin -- ported from
//! `ghidra.features.base.memsearch`.
//!
//! Provides functionality for searching bytes in program memory, supporting
//! multiple input formats (hex, binary, decimal, string, regex, float),
//! combinable result sets, scan-based result filtering, and mnemonic-based
//! instruction pattern searching.
//!
//! # Architecture
//!
//! - [`bytesource`] -- byte sources for reading program memory
//! - [`matcher`] -- byte pattern matching (masked sequences, regex, bulk patterns)
//! - [`format`] -- parsers for user input in various formats
//! - [`combiner`] -- set operations for combining search results
//! - [`scan`] -- result scanning for value changes
//! - [`searcher`] -- the core search engine
//! - [`mnemonic`] -- instruction-based pattern search
//! - [`gui`] -- search settings, model, history, and markers

pub mod bytesource;
pub mod combiner;
pub mod format;
pub mod gui;
pub mod matcher;
pub mod mnemonic;
pub mod scan;
pub mod searcher;

// Re-export commonly used types
pub use bytesource::{AddressableByteSource, ProgramByteSource, ProgramSearchRegion};
pub use combiner::Combiner;
pub use format::{SearchFormat, HexSearchFormat};
pub use gui::{SearchSettings, SearchGuiModel, SearchHistory, SearchMarkers};
pub use matcher::{ByteMatcher, MaskedByteSequenceByteMatcher, RegExByteMatcher, Match};
pub use mnemonic::{MaskValue, MaskGenerator, SLMaskControl};
pub use scan::Scanner;
pub use searcher::{MemorySearcher, MemoryMatch, AlignmentFilter, CodeUnitFilter};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memsearch::matcher::InvalidByteMatcher;

    #[test]
    fn test_hex_search_end_to_end() {
        let settings = SearchSettings::default();
        let hex_format = format::HexSearchFormat;
        let matcher = hex_format.parse("55 89 E5", &settings);

        let searcher = MemorySearcher::new(matcher, 100);
        let data = [0x90, 0x90, 0x55, 0x89, 0xE5, 0xC3, 0x55, 0x89, 0xE5];
        let matches = searcher.find_all(&data, 0x401000);

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].address(), 0x401002);
        assert_eq!(matches[1].address(), 0x401006);
    }

    #[test]
    fn test_wildcard_search() {
        let settings = SearchSettings::default();
        let hex_format = format::HexSearchFormat;
        let matcher = hex_format.parse("5? E5", &settings);

        let searcher = MemorySearcher::new(matcher, 100);
        let data = [0x55, 0xE5, 0x5A, 0xE5, 0x5F, 0xE5];
        let matches = searcher.find_all(&data, 0);

        assert_eq!(matches.len(), 3);
    }

    #[test]
    fn test_combiner_workflow() {
        let matches_a = vec![
            MemoryMatch::new(0x1000, vec![0x55]),
            MemoryMatch::new(0x2000, vec![0x89]),
            MemoryMatch::new(0x3000, vec![0xE5]),
        ];
        let matches_b = vec![
            MemoryMatch::new(0x2000, vec![0x89]),
            MemoryMatch::new(0x3000, vec![0xE5]),
            MemoryMatch::new(0x4000, vec![0xC3]),
        ];

        // Union: should have all 4 unique addresses
        let union = Combiner::Union.combine(&matches_a, &matches_b);
        assert_eq!(union.len(), 4);

        // Intersect: should have 2 common addresses
        let intersect = Combiner::Intersect.combine(&matches_a, &matches_b);
        assert_eq!(intersect.len(), 2);

        // A - B: should have only 0x1000
        let a_minus = Combiner::AMinusB.combine(&matches_a, &matches_b);
        assert_eq!(a_minus.len(), 1);
        assert_eq!(a_minus[0].address(), 0x1000);
    }

    #[test]
    fn test_scanner_workflow() {
        // Create matches with initial "old" bytes
        let mut matches = vec![
            MemoryMatch::new(0x1000, vec![0x55]), // old = 0x55
            MemoryMatch::new(0x2000, vec![0x55]), // old = 0x55
            MemoryMatch::new(0x3000, vec![0x55]), // old = 0x55
        ];

        // Simulate a refresh: update to new byte values
        matches[0].update_bytes(vec![0x56]); // 55 -> 56 (increased)
        matches[1].update_bytes(vec![0x55]); // 55 -> 55 (equals)
        matches[2].update_bytes(vec![0x54]); // 55 -> 54 (decreased)

        // Scanner: keep only increased
        let increased = Scanner::Increased.filter(&matches);
        assert_eq!(increased.len(), 1);
        assert_eq!(increased[0].address(), 0x1000);

        // Scanner: keep only decreased
        let decreased = Scanner::Decreased.filter(&matches);
        assert_eq!(decreased.len(), 1);
        assert_eq!(decreased[0].address(), 0x3000);

        // Scanner: keep only equals
        let equals = Scanner::Equals.filter(&matches);
        assert_eq!(equals.len(), 1);
        assert_eq!(equals[0].address(), 0x2000);

        // Scanner: keep changed (not equals)
        let changed = Scanner::NotEquals.filter(&matches);
        assert_eq!(changed.len(), 2);
    }

    #[test]
    fn test_search_history_workflow() {
        let settings = SearchSettings::default();
        let mut history = SearchHistory::new(5);

        let m1 = matcher::UserInputByteMatcher::new("Hex", "55 89", settings.clone());
        let m2 = matcher::UserInputByteMatcher::new("Hex", "E5 C3", settings);

        history.add_search(m1);
        history.add_search(m2);

        assert_eq!(history.len(), 2);
        assert_eq!(history.most_recent().unwrap().input(), "E5 C3");
    }

    #[test]
    fn test_alignment_filter_integration() {
        let settings = SearchSettings::default().with_alignment(4);
        let hex_format = format::HexSearchFormat;
        let matcher = hex_format.parse("55", &settings);

        let searcher = MemorySearcher::new(matcher, 100).with_alignment(4);
        let data = [0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55];
        let matches = searcher.find_all(&data, 0);

        // Only at offsets 0, 4
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_binary_search_format() {
        let settings = SearchSettings::default();
        let bin_format = format::BinarySearchFormat;
        let matcher = bin_format.parse("01010101", &settings);

        let searcher = MemorySearcher::new(matcher, 100);
        let data = [0x55, 0x89, 0x55];
        let matches = searcher.find_all(&data, 0);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_string_search() {
        let settings = SearchSettings::default();
        let str_format = format::StringSearchFormat;
        let matcher = str_format.parse("Hello", &settings);

        let searcher = MemorySearcher::new(matcher, 100);
        let data = b"xxxHelloxxx";
        let matches = searcher.find_all(data, 0);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_markers_integration() {
        let mut markers = SearchMarkers::new("search: 55 89");
        let matches = vec![
            MemoryMatch::new(0x1000, vec![0x55, 0x89]),
            MemoryMatch::new(0x2000, vec![0x55, 0x89]),
        ];
        markers.set_markers(&matches);
        assert_eq!(markers.len(), 2);
        assert!(markers.has_marker_at(0x1000));
    }

    #[test]
    fn test_program_byte_source_search() {
        let mut source = ProgramByteSource::new("test.exe", 0x400000);
        source.add_memory_block(0x401000, vec![0x90, 0x55, 0x89, 0xE5, 0xC3]);

        let mut buf = [0u8; 5];
        let n = source.get_bytes(0x401000, &mut buf, 5);
        assert_eq!(n, 5);

        let settings = SearchSettings::default();
        let hex_format = format::HexSearchFormat;
        let matcher = hex_format.parse("55 89", &settings);
        let searcher = MemorySearcher::new(matcher, 100);
        let matches = searcher.find_all(&buf, 0x401000);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].address(), 0x401001);
    }
}
