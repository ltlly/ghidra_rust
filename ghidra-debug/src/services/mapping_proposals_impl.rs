//! Static mapping proposal implementations.
//!
//! Ported from Ghidra's `DefaultModuleMapProposal`, `DefaultRegionMapProposal`,
//! `DefaultSectionMapProposal`, and `DebuggerStaticMappingProposals` in
//! `ghidra.app.plugin.core.debug.service.modules`.
//!
//! These implement the mapping from trace addresses to static program addresses.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A single proposed mapping entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingProposalEntry {
    /// The trace address range start.
    pub trace_start: u64,
    /// The trace address range end.
    pub trace_end: u64,
    /// The static program address range start.
    pub static_start: u64,
    /// The static program address range end.
    pub static_end: u64,
    /// The trace address space.
    pub trace_space: String,
    /// The static address space.
    pub static_space: String,
    /// The lifespan of this mapping.
    pub lifespan: Lifespan,
    /// Description/source of this mapping.
    pub description: String,
}

impl MappingProposalEntry {
    /// Create a new mapping proposal entry.
    pub fn new(
        trace_start: u64,
        trace_end: u64,
        static_start: u64,
        static_end: u64,
        trace_space: impl Into<String>,
        static_space: impl Into<String>,
    ) -> Self {
        Self {
            trace_start,
            trace_end,
            static_start,
            static_end,
            trace_space: trace_space.into(),
            static_space: static_space.into(),
            lifespan: Lifespan::ALL,
            description: String::new(),
        }
    }

    /// Set the lifespan.
    pub fn with_lifespan(mut self, lifespan: Lifespan) -> Self {
        self.lifespan = lifespan;
        self
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Get the length of the mapped range.
    pub fn length(&self) -> u64 {
        self.trace_end.saturating_sub(self.trace_start)
    }
}

/// Module-level mapping proposal.
///
/// Ported from Ghidra's `DefaultModuleMapProposal`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMapProposal {
    /// The module name.
    pub module_name: String,
    /// The program name.
    pub program_name: String,
    /// The mapping entries.
    pub entries: Vec<MappingProposalEntry>,
    /// The confidence of this proposal (0.0 - 1.0).
    pub confidence: f64,
}

impl ModuleMapProposal {
    /// Create a new module map proposal.
    pub fn new(module_name: impl Into<String>, program_name: impl Into<String>) -> Self {
        Self {
            module_name: module_name.into(),
            program_name: program_name.into(),
            entries: Vec::new(),
            confidence: 0.0,
        }
    }

    /// Add an entry.
    pub fn add_entry(&mut self, entry: MappingProposalEntry) {
        self.entries.push(entry);
    }

    /// Set the confidence.
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Get the total mapped size.
    pub fn total_mapped_size(&self) -> u64 {
        self.entries.iter().map(|e| e.length()).sum()
    }
}

/// Region-level mapping proposal.
///
/// Ported from Ghidra's `DefaultRegionMapProposal`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionMapProposal {
    /// The region name.
    pub region_name: String,
    /// The mapping entries.
    pub entries: Vec<MappingProposalEntry>,
    /// Whether this maps a readable region.
    pub readable: bool,
    /// Whether this maps a writable region.
    pub writable: bool,
    /// Whether this maps an executable region.
    pub executable: bool,
}

impl RegionMapProposal {
    /// Create a new region map proposal.
    pub fn new(region_name: impl Into<String>) -> Self {
        Self {
            region_name: region_name.into(),
            entries: Vec::new(),
            readable: true,
            writable: false,
            executable: false,
        }
    }

    /// Add an entry.
    pub fn add_entry(&mut self, entry: MappingProposalEntry) {
        self.entries.push(entry);
    }

    /// Set permissions.
    pub fn with_permissions(mut self, read: bool, write: bool, exec: bool) -> Self {
        self.readable = read;
        self.writable = write;
        self.executable = exec;
        self
    }
}

/// Section-level mapping proposal.
///
/// Ported from Ghidra's `DefaultSectionMapProposal`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionMapProposal {
    /// The section name.
    pub section_name: String,
    /// The mapping entries.
    pub entries: Vec<MappingProposalEntry>,
    /// The section flags.
    pub flags: u32,
}

impl SectionMapProposal {
    /// Create a new section map proposal.
    pub fn new(section_name: impl Into<String>) -> Self {
        Self {
            section_name: section_name.into(),
            entries: Vec::new(),
            flags: 0,
        }
    }

    /// Add an entry.
    pub fn add_entry(&mut self, entry: MappingProposalEntry) {
        self.entries.push(entry);
    }

    /// Set the section flags.
    pub fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }
}

/// A set of mapping proposals for a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerStaticMappingProposals {
    /// Module-level proposals.
    pub module_proposals: Vec<ModuleMapProposal>,
    /// Region-level proposals.
    pub region_proposals: Vec<RegionMapProposal>,
    /// Section-level proposals.
    pub section_proposals: Vec<SectionMapProposal>,
}

impl DebuggerStaticMappingProposals {
    /// Create empty proposals.
    pub fn new() -> Self {
        Self {
            module_proposals: Vec::new(),
            region_proposals: Vec::new(),
            section_proposals: Vec::new(),
        }
    }

    /// Add a module proposal.
    pub fn add_module_proposal(&mut self, proposal: ModuleMapProposal) {
        self.module_proposals.push(proposal);
    }

    /// Add a region proposal.
    pub fn add_region_proposal(&mut self, proposal: RegionMapProposal) {
        self.region_proposals.push(proposal);
    }

    /// Add a section proposal.
    pub fn add_section_proposal(&mut self, proposal: SectionMapProposal) {
        self.section_proposals.push(proposal);
    }

    /// Get the total number of proposals.
    pub fn total_proposals(&self) -> usize {
        self.module_proposals.len()
            + self.region_proposals.len()
            + self.section_proposals.len()
    }

    /// Check if there are any proposals.
    pub fn is_empty(&self) -> bool {
        self.total_proposals() == 0
    }
}

impl Default for DebuggerStaticMappingProposals {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mapping_proposal_entry() {
        let entry = MappingProposalEntry::new(0x1000, 0x1FFF, 0x400000, 0x400FFF, "ram", "ram");
        assert_eq!(entry.length(), 0xFFF);
    }

    #[test]
    fn test_mapping_proposal_entry_builder() {
        let entry = MappingProposalEntry::new(0, 0xFF, 0x100, 0x1FF, "ram", "ram")
            .with_description("test mapping")
            .with_lifespan(Lifespan::span(0, 10));
        assert_eq!(entry.description, "test mapping");
    }

    #[test]
    fn test_module_map_proposal() {
        let mut proposal = ModuleMapProposal::new("libc.so", "libc")
            .with_confidence(0.95);
        proposal.add_entry(MappingProposalEntry::new(0x1000, 0x1FFF, 0x400000, 0x400FFF, "ram", "ram"));
        assert_eq!(proposal.entries.len(), 1);
        assert_eq!(proposal.confidence, 0.95);
    }

    #[test]
    fn test_region_map_proposal() {
        let proposal = RegionMapProposal::new("stack")
            .with_permissions(true, true, false);
        assert!(proposal.readable);
        assert!(proposal.writable);
        assert!(!proposal.executable);
    }

    #[test]
    fn test_section_map_proposal() {
        let proposal = SectionMapProposal::new(".text").with_flags(0x06);
        assert_eq!(proposal.flags, 0x06);
    }

    #[test]
    fn test_proposals_collection() {
        let mut proposals = DebuggerStaticMappingProposals::new();
        assert!(proposals.is_empty());
        proposals.add_module_proposal(ModuleMapProposal::new("m", "p"));
        proposals.add_region_proposal(RegionMapProposal::new("r"));
        assert_eq!(proposals.total_proposals(), 2);
    }

    #[test]
    fn test_module_proposal_total_size() {
        let mut proposal = ModuleMapProposal::new("test", "test");
        proposal.add_entry(MappingProposalEntry::new(0, 0xFF, 0, 0xFF, "ram", "ram"));
        proposal.add_entry(MappingProposalEntry::new(0x100, 0x1FF, 0x100, 0x1FF, "ram", "ram"));
        // 0xFF + 0xFF = 510 (each entry: trace_end - trace_start)
        assert_eq!(proposal.total_mapped_size(), 0xFF + 0xFF);
    }

    #[test]
    fn test_confidence_clamp() {
        let proposal = ModuleMapProposal::new("m", "p").with_confidence(1.5);
        assert_eq!(proposal.confidence, 1.0);
        let proposal = ModuleMapProposal::new("m", "p").with_confidence(-0.5);
        assert_eq!(proposal.confidence, 0.0);
    }
}
