//! Static mapping context and proposal types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service.modules`:
//! - `DebuggerStaticMappingContext`: Context for static mapping actions.
//! - `DebuggerStaticMappingProposals`: Proposals for static-to-dynamic mapping.
//! - `DynamicStaticSynchronization`: Synchronization between dynamic and static.
//! - `MapModulesBackgroundCommand`: Background command for mapping modules.
//! - `MapRegionsBackgroundCommand`: Background command for mapping regions.
//! - `MapSectionsBackgroundCommand`: Background command for mapping sections.
//!
//! These types handle the automatic and manual mapping of dynamic trace addresses
//! to static program addresses, which is essential for correlating debug
//! information with disassembled code.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::model::Lifespan;

/// Context for a static mapping action.
///
/// Ported from `DebuggerStaticMappingContext`. Holds the information needed to
/// perform a mapping between a trace (dynamic) and a program (static).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticMappingContext {
    /// The trace ID.
    pub trace_id: String,
    /// The program name.
    pub program_name: String,
    /// The snap at which the mapping was created.
    pub snap: i64,
    /// The dynamic (trace) address range start.
    pub dynamic_start: u64,
    /// The dynamic address range length.
    pub dynamic_length: u64,
    /// The static (program) address range start.
    pub static_start: u64,
    /// The static address range length.
    pub static_length: u64,
    /// The address space name in the trace.
    pub trace_space: String,
    /// The address space name in the program.
    pub program_space: String,
}

impl StaticMappingContext {
    /// Create a new mapping context.
    pub fn new(
        trace_id: &str,
        program_name: &str,
        snap: i64,
        trace_space: &str,
        program_space: &str,
    ) -> Self {
        Self {
            trace_id: trace_id.to_string(),
            program_name: program_name.to_string(),
            snap,
            dynamic_start: 0,
            dynamic_length: 0,
            static_start: 0,
            static_length: 0,
            trace_space: trace_space.to_string(),
            program_space: program_space.to_string(),
        }
    }

    /// Set the dynamic range.
    pub fn with_dynamic_range(mut self, start: u64, length: u64) -> Self {
        self.dynamic_start = start;
        self.dynamic_length = length;
        self
    }

    /// Set the static range.
    pub fn with_static_range(mut self, start: u64, length: u64) -> Self {
        self.static_start = start;
        self.static_length = length;
        self
    }

    /// Check if the dynamic and static ranges have the same length.
    pub fn is_valid(&self) -> bool {
        self.dynamic_length > 0
            && self.dynamic_length == self.static_length
    }
}

/// A single mapping proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingProposal {
    /// The source (dynamic) address.
    pub source_address: u64,
    /// The destination (static) address.
    pub dest_address: u64,
    /// The length of the mapping.
    pub length: u64,
    /// The confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// The source of this proposal (e.g., module name, section name).
    pub source: String,
    /// Whether this proposal is recommended.
    pub is_recommended: bool,
}

impl MappingProposal {
    /// Create a new mapping proposal.
    pub fn new(source_addr: u64, dest_addr: u64, length: u64, confidence: f64, source: &str) -> Self {
        Self {
            source_address: source_addr,
            dest_address: dest_addr,
            length,
            confidence,
            source: source.to_string(),
            is_recommended: false,
        }
    }
}

/// Proposals for static-to-dynamic mapping.
///
/// Ported from `DebuggerStaticMappingProposals`. A collection of mapping
/// proposals organized by module/section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticMappingProposals {
    /// The proposals grouped by module name.
    pub proposals: BTreeMap<String, Vec<MappingProposal>>,
    /// The trace ID these proposals apply to.
    pub trace_id: String,
    /// The snap at which these proposals were generated.
    pub snap: i64,
}

impl StaticMappingProposals {
    /// Create a new empty proposals set.
    pub fn new(trace_id: &str, snap: i64) -> Self {
        Self {
            proposals: BTreeMap::new(),
            trace_id: trace_id.to_string(),
            snap,
        }
    }

    /// Add a proposal for a module.
    pub fn add_proposal(&mut self, module: &str, proposal: MappingProposal) {
        self.proposals
            .entry(module.to_string())
            .or_default()
            .push(proposal);
    }

    /// Get all proposals for a module.
    pub fn get_proposals(&self, module: &str) -> Option<&Vec<MappingProposal>> {
        self.proposals.get(module)
    }

    /// Get all module names with proposals.
    pub fn module_names(&self) -> Vec<&str> {
        self.proposals.keys().map(|s| s.as_str()).collect()
    }

    /// Get the total number of proposals.
    pub fn total_count(&self) -> usize {
        self.proposals.values().map(|v| v.len()).sum()
    }

    /// Check if there are any proposals.
    pub fn is_empty(&self) -> bool {
        self.proposals.is_empty()
    }
}

/// The kind of mapping change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MappingChangeKind {
    /// A mapping was added.
    Added,
    /// A mapping was modified.
    Modified,
    /// A mapping was removed.
    Removed,
}

/// Information per program being tracked for mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoPerProgram {
    /// The program name.
    pub name: String,
    /// The program's executable path.
    pub executable_path: Option<String>,
    /// The program's image base address.
    pub image_base: u64,
    /// The program's length.
    pub length: u64,
    /// Whether this program is currently open.
    pub is_open: bool,
    /// The language ID.
    pub language_id: String,
}

/// Information per trace being tracked for mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoPerTrace {
    /// The trace ID.
    pub trace_id: String,
    /// The trace name.
    pub name: String,
    /// Modules loaded in the trace.
    pub modules: Vec<TraceModuleInfo>,
    /// The current snap.
    pub current_snap: i64,
}

/// A module loaded in a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceModuleInfo {
    /// The module name.
    pub name: String,
    /// The module's base address in the trace.
    pub base_address: u64,
    /// The module length.
    pub length: u64,
    /// The module's section names.
    pub sections: Vec<TraceSectionInfo>,
}

/// A section within a trace module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSectionInfo {
    /// The section name.
    pub name: String,
    /// The section address.
    pub address: u64,
    /// The section length.
    pub length: u64,
    /// Whether this section is executable.
    pub is_executable: bool,
}

/// The kind of background mapping operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MapOperationKind {
    /// Mapping by module name.
    MapModules,
    /// Mapping by region.
    MapRegions,
    /// Mapping by section.
    MapSections,
}

/// A background command for mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapBackgroundCommand {
    /// The kind of mapping operation.
    pub kind: MapOperationKind,
    /// The trace ID.
    pub trace_id: String,
    /// The snap range.
    pub lifespan: Lifespan,
    /// The program name.
    pub program_name: String,
    /// Whether the command has completed.
    pub completed: bool,
    /// Progress (0.0 to 1.0).
    pub progress: f64,
    /// Error message if failed.
    pub error: Option<String>,
}

impl MapBackgroundCommand {
    /// Create a new mapping background command.
    pub fn new(kind: MapOperationKind, trace_id: &str, lifespan: Lifespan, program: &str) -> Self {
        Self {
            kind,
            trace_id: trace_id.to_string(),
            lifespan,
            program_name: program.to_string(),
            completed: false,
            progress: 0.0,
            error: None,
        }
    }
}

/// A mapping entry representing a static-to-dynamic address mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingEntry {
    /// The static (program) address.
    pub static_address: u64,
    /// The dynamic (trace) address.
    pub dynamic_address: u64,
    /// The length of the mapping.
    pub length: u64,
    /// The lifespan during which this mapping is valid.
    pub lifespan: Lifespan,
    /// The trace space name.
    pub trace_space: String,
    /// The program space name.
    pub program_space: String,
}

/// A module region matcher for aligning loaded modules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleRegionMatcher {
    /// The trace module name.
    pub module_name: String,
    /// The program name.
    pub program_name: String,
    /// Matched regions.
    pub matched_regions: Vec<MatchedRegion>,
}

/// A matched region between trace and program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedRegion {
    /// The trace region start.
    pub trace_start: u64,
    /// The program region start.
    pub program_start: u64,
    /// The matched length.
    pub length: u64,
    /// The match confidence.
    pub confidence: f64,
}

/// A peek into an opened domain object for program indexing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeekOpenedDomainObject {
    /// The program name.
    pub name: String,
    /// The image base.
    pub image_base: u64,
    /// The language ID.
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_mapping_context() {
        let ctx = StaticMappingContext::new("trace-1", "program.exe", 0, "ram", "ram")
            .with_dynamic_range(0x7FF00000, 0x10000)
            .with_static_range(0x00400000, 0x10000);

        assert!(ctx.is_valid());
        assert_eq!(ctx.dynamic_length, 0x10000);
    }

    #[test]
    fn test_static_mapping_context_invalid() {
        let ctx = StaticMappingContext::new("trace-1", "program.exe", 0, "ram", "ram")
            .with_dynamic_range(0x7FF00000, 0x10000)
            .with_static_range(0x00400000, 0x20000); // Different length

        assert!(!ctx.is_valid());
    }

    #[test]
    fn test_mapping_proposal() {
        let proposal = MappingProposal::new(
            0x7FF00000,
            0x00400000,
            0x10000,
            0.95,
            "module:libc.so",
        );
        assert_eq!(proposal.confidence, 0.95);
        assert_eq!(proposal.length, 0x10000);
    }

    #[test]
    fn test_static_mapping_proposals() {
        let mut proposals = StaticMappingProposals::new("trace-1", 0);

        proposals.add_proposal(
            "libc.so",
            MappingProposal::new(0x7FF00000, 0x00400000, 0x10000, 0.9, "module"),
        );
        proposals.add_proposal(
            "libc.so",
            MappingProposal::new(0x7FF10000, 0x00410000, 0x5000, 0.8, "section"),
        );

        assert_eq!(proposals.total_count(), 2);
        assert_eq!(proposals.module_names(), vec!["libc.so"]);
        assert!(!proposals.is_empty());
    }

    #[test]
    fn test_mapping_change_kind() {
        assert_ne!(MappingChangeKind::Added, MappingChangeKind::Removed);
    }

    #[test]
    fn test_map_background_command() {
        let cmd = MapBackgroundCommand::new(
            MapOperationKind::MapModules,
            "trace-1",
            Lifespan::span(0, 1),
            "program.exe",
        );

        assert_eq!(cmd.kind, MapOperationKind::MapModules);
        assert!(!cmd.completed);
        assert_eq!(cmd.progress, 0.0);
    }

    #[test]
    fn test_info_per_program() {
        let info = InfoPerProgram {
            name: "test.exe".to_string(),
            executable_path: Some("/usr/bin/test".to_string()),
            image_base: 0x00400000,
            length: 0x100000,
            is_open: true,
            language_id: "x86:LE:64:default".to_string(),
        };

        assert!(info.is_open);
        assert_eq!(info.image_base, 0x00400000);
    }

    #[test]
    fn test_trace_module_info() {
        let module = TraceModuleInfo {
            name: "libc.so".to_string(),
            base_address: 0x7FF00000,
            length: 0x200000,
            sections: vec![
                TraceSectionInfo {
                    name: ".text".to_string(),
                    address: 0x7FF01000,
                    length: 0x100000,
                    is_executable: true,
                },
                TraceSectionInfo {
                    name: ".data".to_string(),
                    address: 0x7FF101000,
                    length: 0x50000,
                    is_executable: false,
                },
            ],
        };

        assert_eq!(module.sections.len(), 2);
        assert!(module.sections[0].is_executable);
    }

    #[test]
    fn test_mapping_entry() {
        let entry = MappingEntry {
            static_address: 0x00400000,
            dynamic_address: 0x7FF00000,
            length: 0x10000,
            lifespan: Lifespan::span(0, 10),
            trace_space: "ram".to_string(),
            program_space: "ram".to_string(),
        };

        assert_eq!(entry.length, 0x10000);
    }
}
