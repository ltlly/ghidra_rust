//! Auto-mapping specifications for dynamic-to-static memory mapping.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.action` package.
//! Each specification defines how to automatically map dynamic (trace) memory
//! regions to static (program) memory regions.

use serde::{Deserialize, Serialize};

use crate::api::action::AutoMapSpec;
use crate::api::modules::{MapEntry, MapProposal, ModuleMapProposal, SectionMapProposal};
use crate::model::Lifespan;

/// A built-in auto-map specification.
///
/// Ported from Ghidra's `AutoMapSpec` implementations. Each variant corresponds
/// to a specific strategy for mapping dynamic memory to static programs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BuiltInAutoMapSpec {
    /// Map by loaded module.
    ByModule,
    /// Map by memory region.
    ByRegion,
    /// Map by section.
    BySection,
    /// Do not automatically map.
    None,
    /// One-to-one mapping (same addresses).
    OneToOne,
}

impl BuiltInAutoMapSpec {
    /// Get the configuration name for this spec.
    pub fn config_name(&self) -> &'static str {
        match self {
            Self::ByModule => "1_MAP_BY_MODULE",
            Self::ByRegion => "2_MAP_BY_REGION",
            Self::BySection => "3_MAP_BY_SECTION",
            Self::None => "0_MAP_NONE",
            Self::OneToOne => "4_MAP_ONE_TO_ONE",
        }
    }

    /// Get the menu display name for this spec.
    pub fn menu_name(&self) -> &'static str {
        match self {
            Self::ByModule => "Auto-Map by Module",
            Self::ByRegion => "Auto-Map by Region",
            Self::BySection => "Auto-Map by Section",
            Self::None => "No Auto-Map",
            Self::OneToOne => "Auto-Map One-to-One",
        }
    }

    /// Get the description for this spec.
    pub fn description(&self) -> &'static str {
        match self {
            Self::ByModule => "Automatically map modules to programs by matching module names.",
            Self::ByRegion => "Automatically map memory regions by matching addresses.",
            Self::BySection => "Automatically map sections by matching names and offsets.",
            Self::None => "Do not automatically map programs to traces.",
            Self::OneToOne => "Map programs using the same addresses as the trace.",
        }
    }

    /// Convert to an `AutoMapSpec`.
    pub fn to_auto_map_spec(&self) -> AutoMapSpec {
        AutoMapSpec::new(self.config_name(), self.menu_name(), self.description())
    }

    /// Whether this spec has an associated background task.
    pub fn has_task(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Get all built-in specs in order.
    pub fn all() -> &'static [BuiltInAutoMapSpec] {
        &[
            Self::None,
            Self::ByModule,
            Self::ByRegion,
            Self::BySection,
            Self::OneToOne,
        ]
    }
}

/// A mapping proposal from the by-module auto-map strategy.
///
/// Ported from Ghidra's `ByModuleAutoMapSpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMappingProposal {
    /// The module name from the trace.
    pub module_name: String,
    /// The program name that matches.
    pub program_name: String,
    /// The proposed address mappings.
    pub entries: Vec<ModuleMappingEntry>,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
}

/// A single entry in a module mapping proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMappingEntry {
    /// Trace address range start.
    pub trace_min: u64,
    /// Trace address range end.
    pub trace_max: u64,
    /// Program address range start.
    pub program_min: u64,
    /// Program address range end.
    pub program_max: u64,
    /// The section name.
    pub section_name: String,
}

/// A mapping proposal from the by-region auto-map strategy.
///
/// Ported from Ghidra's `ByRegionAutoMapSpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionMappingProposal {
    /// The region name.
    pub region_name: String,
    /// The trace address range.
    pub trace_range: AddressRange,
    /// The program address range.
    pub program_range: AddressRange,
    /// The lifespan of this mapping.
    pub lifespan: Lifespan,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
}

/// An address range helper.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AddressRange {
    /// Minimum address (inclusive).
    pub min: u64,
    /// Maximum address (inclusive).
    pub max: u64,
}

impl AddressRange {
    /// Create a new address range.
    pub fn new(min: u64, max: u64) -> Self {
        Self { min, max }
    }

    /// The size of this range in bytes.
    pub fn size(&self) -> u64 {
        self.max.saturating_sub(self.min).saturating_add(1)
    }

    /// Whether this range contains the given address.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.min && addr <= self.max
    }

    /// Whether this range overlaps with another.
    pub fn overlaps(&self, other: &AddressRange) -> bool {
        self.min <= other.max && other.min <= self.max
    }
}

/// A mapping proposal from the by-section auto-map strategy.
///
/// Ported from Ghidra's `BySectionAutoMapSpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionMappingProposal {
    /// The section name from the trace.
    pub trace_section_name: String,
    /// The section name from the program.
    pub program_section_name: String,
    /// The trace address range.
    pub trace_range: AddressRange,
    /// The program address range.
    pub program_range: AddressRange,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
}

/// A mapping proposal from the one-to-one auto-map strategy.
///
/// Ported from Ghidra's `OneToOneAutoMapSpec`. Uses the same addresses
/// for both the trace and the program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneToOneMappingProposal {
    /// The trace address range.
    pub trace_range: AddressRange,
    /// The program address range (same as trace).
    pub program_range: AddressRange,
    /// Confidence score (always 1.0 for one-to-one).
    pub confidence: f64,
}

impl OneToOneMappingProposal {
    /// Create a new one-to-one mapping proposal.
    pub fn new(trace_min: u64, trace_max: u64) -> Self {
        Self {
            trace_range: AddressRange::new(trace_min, trace_max),
            program_range: AddressRange::new(trace_min, trace_max),
            confidence: 1.0,
        }
    }
}

/// Result of performing an auto-mapping operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoMapResult {
    /// The number of mappings added.
    pub mappings_added: usize,
    /// The number of mappings that failed.
    pub mappings_failed: usize,
    /// Error messages for failed mappings.
    pub errors: Vec<String>,
}

impl AutoMapResult {
    /// Create a new empty result.
    pub fn new() -> Self {
        Self {
            mappings_added: 0,
            mappings_failed: 0,
            errors: Vec::new(),
        }
    }

    /// Record a successful mapping.
    pub fn add_success(&mut self) {
        self.mappings_added += 1;
    }

    /// Record a failed mapping.
    pub fn add_failure(&mut self, error: impl Into<String>) {
        self.mappings_failed += 1;
        self.errors.push(error.into());
    }

    /// Whether any mappings were added.
    pub fn has_mappings(&self) -> bool {
        self.mappings_added > 0
    }
}

impl Default for AutoMapResult {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_built_in_specs() {
        let specs = BuiltInAutoMapSpec::all();
        assert_eq!(specs.len(), 5);

        let by_module = &specs[1];
        assert_eq!(by_module.config_name(), "1_MAP_BY_MODULE");
        assert_eq!(by_module.menu_name(), "Auto-Map by Module");
        assert!(by_module.has_task());

        let none = &specs[0];
        assert_eq!(none.config_name(), "0_MAP_NONE");
        assert!(!none.has_task());
    }

    #[test]
    fn test_built_in_to_auto_map_spec() {
        let spec = BuiltInAutoMapSpec::ByModule.to_auto_map_spec();
        assert_eq!(spec.config_name, "1_MAP_BY_MODULE");
        assert_eq!(spec.menu_name, "Auto-Map by Module");
    }

    #[test]
    fn test_address_range() {
        let range = AddressRange::new(0x400000, 0x401000);
        assert_eq!(range.size(), 0x1001);
        assert!(range.contains(0x400000));
        assert!(range.contains(0x401000));
        assert!(!range.contains(0x399999));
        assert!(!range.contains(0x401001));

        let other = AddressRange::new(0x400500, 0x400600);
        assert!(range.overlaps(&other));

        let far = AddressRange::new(0x500000, 0x501000);
        assert!(!range.overlaps(&far));
    }

    #[test]
    fn test_one_to_one_proposal() {
        let proposal = OneToOneMappingProposal::new(0x400000, 0x401000);
        assert_eq!(proposal.confidence, 1.0);
        assert_eq!(proposal.trace_range.min, proposal.program_range.min);
        assert_eq!(proposal.trace_range.max, proposal.program_range.max);
    }

    #[test]
    fn test_auto_map_result() {
        let mut result = AutoMapResult::new();
        assert!(!result.has_mappings());

        result.add_success();
        result.add_success();
        result.add_failure("region overlaps");

        assert!(result.has_mappings());
        assert_eq!(result.mappings_added, 2);
        assert_eq!(result.mappings_failed, 1);
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn test_module_mapping_proposal() {
        let proposal = ModuleMappingProposal {
            module_name: "libc.so".into(),
            program_name: "libc.so.6".into(),
            entries: vec![ModuleMappingEntry {
                trace_min: 0x7f000000,
                trace_max: 0x7f010000,
                program_min: 0x0,
                program_max: 0x10000,
                section_name: ".text".into(),
            }],
            confidence: 0.95,
        };
        assert_eq!(proposal.entries.len(), 1);
        assert_eq!(proposal.module_name, "libc.so");
    }

    #[test]
    fn test_region_mapping_proposal() {
        let proposal = RegionMappingProposal {
            region_name: "heap".into(),
            trace_range: AddressRange::new(0x55000000, 0x55100000),
            program_range: AddressRange::new(0x1000, 0x101000),
            lifespan: Lifespan::now_on(0),
            confidence: 0.8,
        };
        assert_eq!(proposal.region_name, "heap");
        assert!(proposal.confidence > 0.0);
    }

    #[test]
    fn test_section_mapping_proposal() {
        let proposal = SectionMappingProposal {
            trace_section_name: ".text".into(),
            program_section_name: ".text".into(),
            trace_range: AddressRange::new(0x400000, 0x401000),
            program_range: AddressRange::new(0x0, 0x1000),
            confidence: 1.0,
        };
        assert_eq!(proposal.trace_section_name, ".text");
    }

    #[test]
    fn test_address_range_size() {
        let range = AddressRange::new(100, 199);
        assert_eq!(range.size(), 100);

        let zero = AddressRange::new(0, 0);
        assert_eq!(zero.size(), 1);
    }
}
