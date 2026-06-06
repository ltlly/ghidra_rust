//! Section map proposal implementation.
//!
//! Ported from Ghidra's `DefaultSectionMapProposal` in
//! `ghidra.app.plugin.core.debug.service.modules`.
//!
//! Provides the default section mapping proposal that matches trace sections
//! to static program memory blocks by name, address, and size.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;
use crate::services::mapping_proposals_impl::SectionMapProposal;

/// A section mapping entry that pairs a trace section with a static memory block.
///
/// Ported from Ghidra's `DefaultSectionMapEntry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionMapEntry {
    /// The trace module name.
    pub module_name: String,
    /// The trace section name.
    pub section_name: String,
    /// The trace section start address (relative to module base).
    pub section_start: u64,
    /// The trace section end address (relative to module base).
    pub section_end: u64,
    /// The static block name.
    pub block_name: String,
    /// The static block start address.
    pub block_start: u64,
    /// The static block end address.
    pub block_end: u64,
    /// The snap at which this mapping is valid.
    pub snap: i64,
    /// Whether the section and block names match.
    pub names_match: bool,
    /// Whether the section and block addresses match.
    pub addresses_match: bool,
}

impl SectionMapEntry {
    /// Create a new section map entry.
    pub fn new(
        module_name: impl Into<String>,
        section_name: impl Into<String>,
        section_start: u64,
        section_end: u64,
        block_name: impl Into<String>,
        block_start: u64,
        block_end: u64,
    ) -> Self {
        let sn = section_name.into();
        let bn = block_name.into();
        Self {
            names_match: sn == bn,
            addresses_match: section_start == block_start && section_end == block_end,
            module_name: module_name.into(),
            section_name: sn,
            section_start,
            section_end,
            block_name: bn,
            block_start,
            block_end,
            snap: 0,
        }
    }

    /// Set the snap.
    pub fn with_snap(mut self, snap: i64) -> Self {
        self.snap = snap;
        self
    }

    /// Get the section size.
    pub fn section_size(&self) -> u64 {
        self.section_end.saturating_sub(self.section_start) + 1
    }

    /// Get the block size.
    pub fn block_size(&self) -> u64 {
        self.block_end.saturating_sub(self.block_start) + 1
    }

    /// Check if the section and block are a good match.
    pub fn is_good_match(&self) -> bool {
        self.names_match || self.addresses_match
    }

    /// Compute the match score for sorting proposals.
    ///
    /// Higher is better. Name matches score higher than address matches.
    pub fn match_score(&self) -> u32 {
        let mut score = 0u32;
        if self.names_match {
            score += 10;
        }
        if self.addresses_match {
            score += 5;
        }
        // Bonus for matching sizes
        if self.section_size() == self.block_size() {
            score += 2;
        }
        score
    }
}

/// The result of computing a section map proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionMapProposalResult {
    /// The proposed entries.
    pub entries: Vec<SectionMapEntry>,
    /// The module name being mapped.
    pub module_name: String,
    /// The program name being mapped to.
    pub program_name: String,
}

impl SectionMapProposalResult {
    /// Create a new proposal result.
    pub fn new(
        module_name: impl Into<String>,
        program_name: impl Into<String>,
    ) -> Self {
        Self {
            entries: Vec::new(),
            module_name: module_name.into(),
            program_name: program_name.into(),
        }
    }

    /// Add an entry to the proposal.
    pub fn add_entry(&mut self, entry: SectionMapEntry) {
        self.entries.push(entry);
    }

    /// Get the number of proposed entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get entries sorted by match score (best first).
    pub fn sorted_by_score(&self) -> Vec<&SectionMapEntry> {
        let mut sorted: Vec<&SectionMapEntry> = self.entries.iter().collect();
        sorted.sort_by(|a, b| b.match_score().cmp(&a.match_score()));
        sorted
    }

    /// Get only the good matches.
    pub fn good_matches(&self) -> Vec<&SectionMapEntry> {
        self.entries.iter().filter(|e| e.is_good_match()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_map_proposal_re_export() {
        let p = SectionMapProposal::new(".text");
        assert_eq!(p.section_name, ".text");
    }

    #[test]
    fn test_section_map_entry_new() {
        let entry = SectionMapEntry::new(
            "libc", ".text", 0x0, 0xFFF,
            ".text", 0x400000, 0x400FFF,
        );
        assert_eq!(entry.module_name, "libc");
        assert_eq!(entry.section_name, ".text");
        assert!(entry.names_match);
        assert!(!entry.addresses_match);
    }

    #[test]
    fn test_section_map_entry_perfect_match() {
        let entry = SectionMapEntry::new(
            "libc", ".text", 0x400000, 0x400FFF,
            ".text", 0x400000, 0x400FFF,
        );
        assert!(entry.names_match);
        assert!(entry.addresses_match);
        assert!(entry.is_good_match());
        assert_eq!(entry.match_score(), 17); // 10 + 5 + 2
    }

    #[test]
    fn test_section_map_entry_name_only() {
        let entry = SectionMapEntry::new(
            "libc", ".text", 0x0, 0xFFF,
            ".text", 0x400000, 0x400FFF,
        );
        assert!(entry.names_match);
        assert!(!entry.addresses_match);
        assert!(entry.is_good_match());
        assert_eq!(entry.match_score(), 12); // 10 + 2 (sizes match)
    }

    #[test]
    fn test_section_map_entry_no_match() {
        let entry = SectionMapEntry::new(
            "libc", ".text", 0x0, 0xFFF,
            ".data", 0x500000, 0x500FFF,
        );
        assert!(!entry.names_match);
        assert!(!entry.addresses_match);
        assert!(!entry.is_good_match());
        assert_eq!(entry.match_score(), 2); // sizes match
    }

    #[test]
    fn test_section_map_entry_sizes() {
        let entry = SectionMapEntry::new(
            "mod", ".text", 0x0, 0xFFF,
            ".text", 0x400000, 0x400FFF,
        );
        assert_eq!(entry.section_size(), 0x1000);
        assert_eq!(entry.block_size(), 0x1000);
    }

    #[test]
    fn test_section_map_entry_with_snap() {
        let entry = SectionMapEntry::new(
            "mod", ".text", 0, 100, ".text", 0, 100,
        ).with_snap(3);
        assert_eq!(entry.snap, 3);
    }

    #[test]
    fn test_proposal_result_sorted() {
        let mut result = SectionMapProposalResult::new("mod", "prog");

        result.add_entry(SectionMapEntry::new(
            "mod", ".text", 0, 100, ".data", 200, 300,
        ));
        result.add_entry(SectionMapEntry::new(
            "mod", ".text", 0x400000, 0x400FFF,
            ".text", 0x400000, 0x400FFF,
        ));
        result.add_entry(SectionMapEntry::new(
            "mod", ".text", 0, 100, ".text", 200, 300,
        ));

        assert_eq!(result.entry_count(), 3);

        let sorted = result.sorted_by_score();
        // Perfect match should be first
        assert_eq!(sorted[0].section_name, ".text");
        assert_eq!(sorted[0].block_name, ".text");
        assert!(sorted[0].names_match && sorted[0].addresses_match);

        assert_eq!(result.good_matches().len(), 2);
    }
}
