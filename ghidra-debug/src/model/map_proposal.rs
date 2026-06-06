//! Section and region map proposal types for automatic mapping.
//!
//! Ported from Ghidra's `ghidra.debug.api.modules` package:
//! - `MapProposal`: A proposal for mapping trace memory to program memory.
//! - `ModuleMapProposal`: A proposal based on module information.
//! - `RegionMapProposal`: A proposal based on memory region information.
//! - `SectionMapProposal`: A proposal based on section information.
//! - `DefaultSectionMapProposal`: The default implementation of section mapping.
//!
//! These types support Ghidra's automatic mapping feature, which proposes
//! static-to-dynamic address mappings based on module, section, and region metadata.

use serde::{Deserialize, Serialize};

use super::Lifespan;

/// A proposal for mapping trace addresses to program addresses.
///
/// Ported from Ghidra's `MapProposal` interface. Represents a set of
/// proposed address mappings that could be applied to link a trace with
/// a static program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapProposal {
    /// A description of this proposal.
    pub description: String,
    /// The proposed mappings.
    pub entries: Vec<ProposedMapping>,
    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// The source of this proposal (e.g., "module", "section", "region").
    pub source: MapProposalSource,
}

/// A single proposed mapping entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedMapping {
    /// The name of the section/module this mapping is derived from.
    pub name: String,
    /// Trace address range start.
    pub trace_min: u64,
    /// Trace address range end (inclusive).
    pub trace_max: u64,
    /// Program address range start.
    pub program_min: u64,
    /// Program address range end (inclusive).
    pub program_max: u64,
    /// Length of the mapping.
    pub length: u64,
    /// The lifespan during which this mapping applies.
    pub lifespan: Lifespan,
    /// Whether this mapping is read-only.
    pub read_only: bool,
    /// The section name (if derived from a section).
    pub section_name: Option<String>,
    /// The module name (if derived from a module).
    pub module_name: Option<String>,
}

impl ProposedMapping {
    /// Create a new proposed mapping.
    pub fn new(
        name: impl Into<String>,
        trace_min: u64,
        trace_max: u64,
        program_min: u64,
        program_max: u64,
        lifespan: Lifespan,
    ) -> Self {
        let length = trace_max - trace_min + 1;
        Self {
            name: name.into(),
            trace_min,
            trace_max,
            program_min,
            program_max,
            length,
            lifespan,
            read_only: false,
            section_name: None,
            module_name: None,
        }
    }

    /// Mark as read-only.
    pub fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }

    /// Set the section name.
    pub fn with_section(mut self, section: impl Into<String>) -> Self {
        self.section_name = Some(section.into());
        self
    }

    /// Set the module name.
    pub fn with_module(mut self, module: impl Into<String>) -> Self {
        self.module_name = Some(module.into());
        self
    }

    /// Translate a trace address to a program address.
    pub fn translate(&self, trace_addr: u64) -> Option<u64> {
        if trace_addr >= self.trace_min && trace_addr <= self.trace_max {
            let offset = trace_addr - self.trace_min;
            Some(self.program_min + offset)
        } else {
            None
        }
    }

    /// Whether this mapping overlaps another.
    pub fn overlaps(&self, other: &ProposedMapping) -> bool {
        self.trace_min <= other.trace_max
            && other.trace_min <= self.trace_max
            && self.lifespan.intersects(&other.lifespan)
    }
}

/// The source of a map proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MapProposalSource {
    /// Based on module information.
    Module,
    /// Based on section information.
    Section,
    /// Based on memory region information.
    Region,
    /// Based on user specification.
    Manual,
    /// Based on heuristic matching.
    Heuristic,
}

impl std::fmt::Display for MapProposalSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Module => write!(f, "module"),
            Self::Section => write!(f, "section"),
            Self::Region => write!(f, "region"),
            Self::Manual => write!(f, "manual"),
            Self::Heuristic => write!(f, "heuristic"),
        }
    }
}

/// A map proposal based on module information.
///
/// Ported from Ghidra's `ModuleMapProposal`. Uses the base address and
/// length of loaded modules to propose mappings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMapProposal {
    /// The module name.
    pub module_name: String,
    /// The module's base address in the trace.
    pub trace_base: u64,
    /// The module's base address in the program.
    pub program_base: u64,
    /// The module length.
    pub length: u64,
    /// The lifespan of the module.
    pub lifespan: Lifespan,
    /// The module path (executable path on the target).
    pub module_path: Option<String>,
}

impl ModuleMapProposal {
    /// Create a new module map proposal.
    pub fn new(
        module_name: impl Into<String>,
        trace_base: u64,
        program_base: u64,
        length: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            module_name: module_name.into(),
            trace_base,
            program_base,
            length,
            lifespan,
            module_path: None,
        }
    }

    /// Set the module path.
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.module_path = Some(path.into());
        self
    }

    /// Convert to a `MapProposal`.
    pub fn to_proposal(&self) -> MapProposal {
        MapProposal {
            description: format!("Module mapping: {}", self.module_name),
            entries: vec![ProposedMapping::new(
                &self.module_name,
                self.trace_base,
                self.trace_base + self.length - 1,
                self.program_base,
                self.program_base + self.length - 1,
                self.lifespan,
            )
            .with_module(&self.module_name)],
            confidence: 0.8,
            source: MapProposalSource::Module,
        }
    }
}

/// A map proposal based on section information.
///
/// Ported from Ghidra's `SectionMapProposal` and `DefaultSectionMapProposal`.
/// Uses the section names and addresses to propose fine-grained mappings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionMapProposal {
    /// The module name this section belongs to.
    pub module_name: String,
    /// The section mappings.
    pub sections: Vec<SectionMapping>,
    /// The lifespan of the module.
    pub lifespan: Lifespan,
}

/// A single section mapping within a section map proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionMapping {
    /// The section name (e.g., ".text", ".data", ".bss").
    pub name: String,
    /// Start address in the trace.
    pub trace_start: u64,
    /// End address in the trace (inclusive).
    pub trace_end: u64,
    /// Start address in the program.
    pub program_start: u64,
    /// End address in the program (inclusive).
    pub program_end: u64,
    /// Whether this section is executable.
    pub executable: bool,
    /// Whether this section is writable.
    pub writable: bool,
    /// Whether this section is readable.
    pub readable: bool,
}

impl SectionMapping {
    /// Create a new section mapping.
    pub fn new(
        name: impl Into<String>,
        trace_start: u64,
        trace_end: u64,
        program_start: u64,
        program_end: u64,
    ) -> Self {
        Self {
            name: name.into(),
            trace_start,
            trace_end,
            program_start,
            program_end,
            executable: false,
            writable: false,
            readable: true,
        }
    }

    /// Mark as executable.
    pub fn executable(mut self) -> Self {
        self.executable = true;
        self
    }

    /// Mark as writable.
    pub fn writable(mut self) -> Self {
        self.writable = true;
        self
    }

    /// Mark as read-only.
    pub fn read_only(mut self) -> Self {
        self.writable = false;
        self.readable = true;
        self
    }

    /// The length of this section.
    pub fn length(&self) -> u64 {
        self.trace_end - self.trace_start + 1
    }

    /// Translate a trace address to a program address.
    pub fn translate(&self, trace_addr: u64) -> Option<u64> {
        if trace_addr >= self.trace_start && trace_addr <= self.trace_end {
            let offset = trace_addr - self.trace_start;
            Some(self.program_start + offset)
        } else {
            None
        }
    }
}

impl SectionMapProposal {
    /// Create a new section map proposal.
    pub fn new(
        module_name: impl Into<String>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            module_name: module_name.into(),
            sections: Vec::new(),
            lifespan,
        }
    }

    /// Add a section mapping.
    pub fn add_section(&mut self, section: SectionMapping) {
        self.sections.push(section);
    }

    /// Convert to a `MapProposal`.
    pub fn to_proposal(&self) -> MapProposal {
        let entries: Vec<ProposedMapping> = self
            .sections
            .iter()
            .map(|s| {
                ProposedMapping::new(
                    &s.name,
                    s.trace_start,
                    s.trace_end,
                    s.program_start,
                    s.program_end,
                    self.lifespan,
                )
                .with_section(&s.name)
                .with_module(&self.module_name)
            })
            .collect();

        MapProposal {
            description: format!(
                "Section mapping: {} ({} sections)",
                self.module_name,
                self.sections.len()
            ),
            entries,
            confidence: 0.9,
            source: MapProposalSource::Section,
        }
    }

    /// Get the total mapped bytes across all sections.
    pub fn total_bytes(&self) -> u64 {
        self.sections.iter().map(|s| s.length()).sum()
    }
}

/// A map proposal based on memory region information.
///
/// Ported from Ghidra's `RegionMapProposal`. Uses the memory region
/// attributes (address range, permissions) to propose mappings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionMapProposal {
    /// The region name.
    pub region_name: String,
    /// Trace address range start.
    pub trace_start: u64,
    /// Trace address range end (inclusive).
    pub trace_end: u64,
    /// Program address range start.
    pub program_start: u64,
    /// Program address range end (inclusive).
    pub program_end: u64,
    /// The lifespan of the region.
    pub lifespan: Lifespan,
    /// Region permissions.
    pub permissions: RegionPermissions,
}

/// Permissions for a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionPermissions {
    /// Whether the region is readable.
    pub read: bool,
    /// Whether the region is writable.
    pub write: bool,
    /// Whether the region is executable.
    pub execute: bool,
}

impl RegionPermissions {
    /// Read-only permissions.
    pub const READ: Self = Self {
        read: true,
        write: false,
        execute: false,
    };

    /// Read-write permissions.
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        execute: false,
    };

    /// Read-execute permissions.
    pub const READ_EXECUTE: Self = Self {
        read: true,
        write: false,
        execute: true,
    };

    /// Full permissions.
    pub const ALL: Self = Self {
        read: true,
        write: true,
        execute: true,
    };
}

impl RegionMapProposal {
    /// Create a new region map proposal.
    pub fn new(
        region_name: impl Into<String>,
        trace_start: u64,
        trace_end: u64,
        program_start: u64,
        program_end: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            region_name: region_name.into(),
            trace_start,
            trace_end,
            program_start,
            program_end,
            lifespan,
            permissions: RegionPermissions::READ,
        }
    }

    /// Set the permissions.
    pub fn with_permissions(mut self, perms: RegionPermissions) -> Self {
        self.permissions = perms;
        self
    }

    /// Convert to a `MapProposal`.
    pub fn to_proposal(&self) -> MapProposal {
        MapProposal {
            description: format!("Region mapping: {}", self.region_name),
            entries: vec![ProposedMapping::new(
                &self.region_name,
                self.trace_start,
                self.trace_end,
                self.program_start,
                self.program_end,
                self.lifespan,
            )
            .read_only()],
            confidence: 0.7,
            source: MapProposalSource::Region,
        }
    }
}

/// A collection of map proposals with ranking and selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapProposalSet {
    /// The proposals in this set.
    pub proposals: Vec<MapProposal>,
}

impl MapProposalSet {
    /// Create an empty proposal set.
    pub fn new() -> Self {
        Self {
            proposals: Vec::new(),
        }
    }

    /// Add a proposal.
    pub fn add(&mut self, proposal: MapProposal) {
        self.proposals.push(proposal);
    }

    /// Get the best proposal (highest confidence).
    pub fn best(&self) -> Option<&MapProposal> {
        self.proposals
            .iter()
            .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Get proposals sorted by confidence (highest first).
    pub fn sorted(&self) -> Vec<&MapProposal> {
        let mut sorted: Vec<&MapProposal> = self.proposals.iter().collect();
        sorted.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted
    }

    /// Number of proposals.
    pub fn len(&self) -> usize {
        self.proposals.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.proposals.is_empty()
    }
}

impl Default for MapProposalSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proposed_mapping_translate() {
        let mapping = ProposedMapping::new(
            ".text",
            0x400000,
            0x400fff,
            0x100000,
            0x100fff,
            Lifespan::ALL,
        );
        assert_eq!(mapping.translate(0x400100), Some(0x100100));
        assert_eq!(mapping.translate(0x500000), None);
    }

    #[test]
    fn test_proposed_mapping_overlap() {
        let a = ProposedMapping::new("a", 0x100, 0x200, 0, 0, Lifespan::ALL);
        let b = ProposedMapping::new("b", 0x150, 0x250, 0, 0, Lifespan::ALL);
        let c = ProposedMapping::new("c", 0x300, 0x400, 0, 0, Lifespan::ALL);
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn test_proposed_mapping_builder() {
        let m = ProposedMapping::new(".data", 0x1000, 0x1fff, 0x2000, 0x2fff, Lifespan::ALL)
            .read_only()
            .with_section(".data")
            .with_module("test.exe");
        assert!(m.read_only);
        assert_eq!(m.section_name.as_deref(), Some(".data"));
        assert_eq!(m.module_name.as_deref(), Some("test.exe"));
    }

    #[test]
    fn test_module_map_proposal() {
        let module = ModuleMapProposal::new(
            "libc.so",
            0x7f000000,
            0x7f000000,
            0x100000,
            Lifespan::ALL,
        )
        .with_path("/lib/libc.so");

        let proposal = module.to_proposal();
        assert_eq!(proposal.source, MapProposalSource::Module);
        assert_eq!(proposal.entries.len(), 1);
        assert_eq!(proposal.entries[0].module_name.as_deref(), Some("libc.so"));
    }

    #[test]
    fn test_section_map_proposal() {
        let mut proposal = SectionMapProposal::new("test.exe", Lifespan::ALL);
        proposal.add_section(
            SectionMapping::new(".text", 0x400000, 0x400fff, 0x1000, 0x1fff).executable(),
        );
        proposal.add_section(
            SectionMapping::new(".data", 0x401000, 0x401fff, 0x2000, 0x2fff).writable(),
        );

        assert_eq!(proposal.total_bytes(), 0x2000);
        let map_proposal = proposal.to_proposal();
        assert_eq!(map_proposal.entries.len(), 2);
        assert_eq!(map_proposal.source, MapProposalSource::Section);
        assert!((map_proposal.confidence - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn test_section_mapping_translate() {
        let section = SectionMapping::new(".text", 0x400000, 0x400fff, 0x1000, 0x1fff);
        assert_eq!(section.translate(0x400500), Some(0x1500));
        assert_eq!(section.translate(0x500000), None);
    }

    #[test]
    fn test_section_mapping_permissions() {
        let text = SectionMapping::new(".text", 0, 0xff, 0, 0xff).executable();
        assert!(text.executable);
        assert!(!text.writable);

        let data = SectionMapping::new(".data", 0, 0xff, 0, 0xff).writable();
        assert!(!data.executable);
        assert!(data.writable);
    }

    #[test]
    fn test_region_map_proposal() {
        let region = RegionMapProposal::new(
            "stack",
            0x7fff0000,
            0x7fffffff,
            0x7fff0000,
            0x7fffffff,
            Lifespan::ALL,
        )
        .with_permissions(RegionPermissions::READ_WRITE);

        assert_eq!(region.permissions, RegionPermissions::READ_WRITE);
        let proposal = region.to_proposal();
        assert_eq!(proposal.source, MapProposalSource::Region);
    }

    #[test]
    fn test_region_permissions() {
        assert!(RegionPermissions::ALL.read);
        assert!(RegionPermissions::ALL.write);
        assert!(RegionPermissions::ALL.execute);
        assert!(RegionPermissions::READ.read);
        assert!(!RegionPermissions::READ.write);
    }

    #[test]
    fn test_map_proposal_set() {
        let mut set = MapProposalSet::new();
        assert!(set.is_empty());

        set.add(MapProposal {
            description: "Low confidence".into(),
            entries: vec![],
            confidence: 0.3,
            source: MapProposalSource::Heuristic,
        });
        set.add(MapProposal {
            description: "High confidence".into(),
            entries: vec![],
            confidence: 0.95,
            source: MapProposalSource::Section,
        });

        assert_eq!(set.len(), 2);
        let best = set.best().unwrap();
        assert!((best.confidence - 0.95).abs() < f64::EPSILON);

        let sorted = set.sorted();
        assert!((sorted[0].confidence - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn test_map_proposal_source_display() {
        assert_eq!(MapProposalSource::Module.to_string(), "module");
        assert_eq!(MapProposalSource::Section.to_string(), "section");
        assert_eq!(MapProposalSource::Region.to_string(), "region");
    }

    #[test]
    fn test_proposed_mapping_length() {
        let m = ProposedMapping::new("test", 0x100, 0x1ff, 0, 0, Lifespan::ALL);
        assert_eq!(m.length, 0x100);
    }

    #[test]
    fn test_section_mapping_length() {
        let s = SectionMapping::new(".text", 0x1000, 0x1fff, 0, 0);
        assert_eq!(s.length(), 0x1000);
    }

    #[test]
    fn test_module_map_proposal_no_path() {
        let module = ModuleMapProposal::new("test", 0, 0, 0x100, Lifespan::ALL);
        assert!(module.module_path.is_none());
    }

    #[test]
    fn test_proposal_set_default() {
        let set = MapProposalSet::default();
        assert!(set.is_empty());
    }

    #[test]
    fn test_section_map_proposal_empty() {
        let proposal = SectionMapProposal::new("empty", Lifespan::ALL);
        assert_eq!(proposal.total_bytes(), 0);
        let map_proposal = proposal.to_proposal();
        assert!(map_proposal.entries.is_empty());
    }

    #[test]
    fn test_proposed_mapping_serde() {
        let m = ProposedMapping::new("test", 0, 0xff, 0x100, 0x1ff, Lifespan::ALL);
        let json = serde_json::to_string(&m).unwrap();
        let back: ProposedMapping = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "test");
    }

    #[test]
    fn test_section_map_proposal_serde() {
        let mut proposal = SectionMapProposal::new("test", Lifespan::ALL);
        proposal.add_section(SectionMapping::new(".text", 0, 0xff, 0, 0xff));
        let json = serde_json::to_string(&proposal).unwrap();
        let back: SectionMapProposal = serde_json::from_str(&json).unwrap();
        assert_eq!(back.module_name, "test");
    }
}
