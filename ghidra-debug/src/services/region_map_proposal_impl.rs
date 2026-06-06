//! Region map proposal implementation.
//!
//! Ported from Ghidra's `DefaultRegionMapProposal` in
//! `ghidra.app.plugin.core.debug.service.modules`.
//!
//! Provides the default region mapping proposal that matches trace memory
//! regions to static program memory blocks by name, address, and size.

use serde::{Deserialize, Serialize};


/// A region mapping entry that pairs a trace memory region with a static memory block.
///
/// Ported from Ghidra's `DefaultRegionMapEntry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionMapEntry {
    /// The trace region name.
    pub region_name: String,
    /// The trace region minimum address.
    pub region_min_addr: u64,
    /// The trace region maximum address.
    pub region_max_addr: u64,
    /// The static block name.
    pub block_name: String,
    /// The static block start address.
    pub block_start: u64,
    /// The static block end address.
    pub block_end: u64,
    /// The snap at which this mapping is valid.
    pub snap: i64,
    /// Whether the region and block names match.
    pub names_match: bool,
    /// Whether the region and block addresses match.
    pub addresses_match: bool,
}

impl RegionMapEntry {
    /// Create a new region map entry.
    pub fn new(
        region_name: impl Into<String>,
        region_min_addr: u64,
        region_max_addr: u64,
        block_name: impl Into<String>,
        block_start: u64,
        block_end: u64,
    ) -> Self {
        let rn = region_name.into();
        let bn = block_name.into();
        Self {
            names_match: rn == bn,
            addresses_match: region_min_addr == block_start && region_max_addr == block_end,
            region_name: rn,
            region_min_addr,
            region_max_addr,
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

    /// Get the trace address range size.
    pub fn region_size(&self) -> u64 {
        self.region_max_addr.saturating_sub(self.region_min_addr) + 1
    }

    /// Get the static block size.
    pub fn block_size(&self) -> u64 {
        self.block_end.saturating_sub(self.block_start) + 1
    }

    /// Check if the region and block are a good match.
    pub fn is_good_match(&self) -> bool {
        self.names_match || self.addresses_match
    }
}

/// The result of computing a region map proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionMapProposalResult {
    /// The proposed entries.
    pub entries: Vec<RegionMapEntry>,
    /// The trace name.
    pub trace_name: String,
}

impl RegionMapProposalResult {
    /// Create a new proposal result.
    pub fn new(trace_name: impl Into<String>) -> Self {
        Self {
            entries: Vec::new(),
            trace_name: trace_name.into(),
        }
    }

    /// Add an entry to the proposal.
    pub fn add_entry(&mut self, entry: RegionMapEntry) {
        self.entries.push(entry);
    }

    /// Get the number of proposed entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get only the good matches.
    pub fn good_matches(&self) -> Vec<&RegionMapEntry> {
        self.entries.iter().filter(|e| e.is_good_match()).collect()
    }

    /// Get only the entries with matching names.
    pub fn name_matches(&self) -> Vec<&RegionMapEntry> {
        self.entries.iter().filter(|e| e.names_match).collect()
    }
}

/// Match a region name to a block name using common heuristics.
///
/// Ported from Ghidra's `ModuleRegionMatcher.nameMatches()`.
pub fn region_name_matches_block(region_name: &str, block_name: &str) -> bool {
    if region_name == block_name {
        return true;
    }
    // Normalize common prefixes/suffixes
    let rn = region_name.to_lowercase();
    let bn = block_name.to_lowercase();
    if rn == bn {
        return true;
    }
    // Strip leading dots and common section prefixes
    let rn_stripped = rn.strip_prefix('.').unwrap_or(rn.as_str());
    let bn_stripped = bn.strip_prefix('.').unwrap_or(bn.as_str());
    if rn_stripped == bn_stripped {
        return true;
    }
    // Try stripping section prefixes
    for prefix in &[".text_", ".data_", ".rodata_", ".bss_"] {
        let rn_alt = rn.strip_prefix(prefix).unwrap_or(&rn);
        let bn_alt = bn.strip_prefix(prefix).unwrap_or(&bn);
        if rn_alt == bn_alt {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::mapping_proposals_impl::RegionMapProposal;

    #[test]
    fn test_region_map_proposal_re_export() {
        let p = RegionMapProposal::new("test");
        assert_eq!(p.region_name, "test");
    }

    #[test]
    fn test_region_map_entry_new() {
        let entry = RegionMapEntry::new(
            ".text", 0x400000, 0x400FFF,
            ".text", 0x400000, 0x400FFF,
        );
        assert!(entry.names_match);
        assert!(entry.addresses_match);
        assert!(entry.is_good_match());
    }

    #[test]
    fn test_region_map_entry_name_mismatch() {
        let entry = RegionMapEntry::new(
            ".text", 0x400000, 0x400FFF,
            ".data", 0x400000, 0x400FFF,
        );
        assert!(!entry.names_match);
        assert!(entry.addresses_match);
        assert!(entry.is_good_match());
    }

    #[test]
    fn test_region_map_entry_no_match() {
        let entry = RegionMapEntry::new(
            ".text", 0x400000, 0x400FFF,
            ".data", 0x500000, 0x500FFF,
        );
        assert!(!entry.names_match);
        assert!(!entry.addresses_match);
        assert!(!entry.is_good_match());
    }

    #[test]
    fn test_region_map_entry_sizes() {
        let entry = RegionMapEntry::new(
            ".text", 0x400000, 0x400FFF,
            ".text", 0x400000, 0x400FFF,
        );
        assert_eq!(entry.region_size(), 0x1000);
        assert_eq!(entry.block_size(), 0x1000);
    }

    #[test]
    fn test_region_map_entry_with_snap() {
        let entry = RegionMapEntry::new(
            ".text", 0, 100, ".text", 0, 100,
        ).with_snap(5);
        assert_eq!(entry.snap, 5);
    }

    #[test]
    fn test_proposal_result() {
        let mut result = RegionMapProposalResult::new("test_trace");
        assert_eq!(result.entry_count(), 0);

        result.add_entry(RegionMapEntry::new(
            ".text", 0x400000, 0x400FFF,
            ".text", 0x400000, 0x400FFF,
        ));
        result.add_entry(RegionMapEntry::new(
            ".data", 0x500000, 0x500FFF,
            ".bss", 0x500000, 0x500FFF,
        ));

        assert_eq!(result.entry_count(), 2);
        assert_eq!(result.good_matches().len(), 2);
        assert_eq!(result.name_matches().len(), 1);
    }

    #[test]
    fn test_region_name_matches() {
        assert!(region_name_matches_block(".text", ".text"));
        assert!(region_name_matches_block("TEXT", "text"));
        assert!(region_name_matches_block(".text_main", "text_main"));
        assert!(!region_name_matches_block(".text", ".data"));
    }
}
