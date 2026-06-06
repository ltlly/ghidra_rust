//! Dynamic-static synchronization for the debugger.
//!
//! Ported from Ghidra's `DynamicStaticSynchronizationPlugin` from
//! `ghidra.app.plugin.core.debug.service.modules`.
//!
//! Provides the data model for synchronizing between dynamic (trace)
//! and static (program) listings, including:
//! - Location synchronization (cursor position)
//! - Selection synchronization (address range selection)
//! - Automatic opening of programs matching trace modules
//! - Handling of missing modules

use serde::{Deserialize, Serialize};


/// Configuration for the dynamic-static synchronization plugin.
///
/// Ported from Ghidra's `DynamicStaticSynchronizationPlugin` action interfaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicStaticSyncConfig {
    /// Whether location synchronization is enabled.
    pub sync_locations: bool,
    /// Whether selection synchronization is enabled.
    pub sync_selections: bool,
    /// Whether to auto-open programs matching trace modules.
    pub auto_open_programs: bool,
    /// Whether to report missing modules in the console.
    pub report_missing_modules: bool,
}

impl Default for DynamicStaticSyncConfig {
    fn default() -> Self {
        Self {
            sync_locations: true,
            sync_selections: true,
            auto_open_programs: true,
            report_missing_modules: true,
        }
    }
}

/// The direction of synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncDirection {
    /// From dynamic (trace) to static (program).
    DynamicToStatic,
    /// From static (program) to dynamic (trace).
    StaticToDynamic,
    /// Bidirectional.
    Bidirectional,
}

/// An event indicating a location change that should be synchronized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncLocationEvent {
    /// The source of the change (dynamic or static).
    pub source: SyncDirection,
    /// The trace key (if source is dynamic).
    pub trace_key: Option<i64>,
    /// The snap (time point).
    pub snap: i64,
    /// The thread key (if applicable).
    pub thread_key: Option<i64>,
    /// The address in the source space.
    pub address: u64,
    /// The mapped address in the destination space (if known).
    pub mapped_address: Option<u64>,
}

/// An event indicating a selection change that should be synchronized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncSelectionEvent {
    /// The source of the change.
    pub source: SyncDirection,
    /// The trace key.
    pub trace_key: Option<i64>,
    /// The snap.
    pub snap: i64,
    /// Selection ranges (start, end) pairs.
    pub ranges: Vec<(u64, u64)>,
}

/// A missing module that was not found in the project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingModuleEntry {
    /// The module name.
    pub module_name: String,
    /// The module path (if available).
    pub module_path: Option<String>,
    /// The trace key this module belongs to.
    pub trace_key: i64,
    /// The snap at which the module was observed.
    pub snap: i64,
    /// The address range of the module.
    pub address_range: Option<(u64, u64)>,
}

/// Background command for mapping modules from a trace to static programs.
///
/// Ported from Ghidra's `MapModulesBackgroundCommand`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapModulesBackgroundCommand {
    /// The trace key.
    pub trace_key: i64,
    /// The snap to use for module lookup.
    pub snap: i64,
    /// Whether to open programs automatically.
    pub auto_open: bool,
}

impl MapModulesBackgroundCommand {
    /// Create a new map-modules command.
    pub fn new(trace_key: i64, snap: i64) -> Self {
        Self {
            trace_key,
            snap,
            auto_open: true,
        }
    }
}

/// Background command for mapping regions from a trace to static programs.
///
/// Ported from Ghidra's `MapRegionsBackgroundCommand`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapRegionsBackgroundCommand {
    /// The trace key.
    pub trace_key: i64,
    /// The snap to use for region lookup.
    pub snap: i64,
}

impl MapRegionsBackgroundCommand {
    /// Create a new map-regions command.
    pub fn new(trace_key: i64, snap: i64) -> Self {
        Self { trace_key, snap }
    }
}

/// Background command for mapping sections from a trace to static programs.
///
/// Ported from Ghidra's `MapSectionsBackgroundCommand`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapSectionsBackgroundCommand {
    /// The trace key.
    pub trace_key: i64,
    /// The snap to use for section lookup.
    pub snap: i64,
}

impl MapSectionsBackgroundCommand {
    /// Create a new map-sections command.
    pub fn new(trace_key: i64, snap: i64) -> Self {
        Self { trace_key, snap }
    }
}

/// Result of executing a background mapping command.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MapCommandResult {
    /// Modules that were successfully mapped.
    pub mapped: Vec<MappedModule>,
    /// Modules that could not be found in the project.
    pub missing: Vec<MissingModuleEntry>,
    /// Errors encountered during mapping.
    pub errors: Vec<String>,
}

/// A module that was successfully mapped to a program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappedModule {
    /// The trace module name.
    pub module_name: String,
    /// The matched program URL.
    pub program_url: String,
    /// The address ranges that were mapped.
    pub mapped_ranges: Vec<(u64, u64)>,
    /// The confidence of the mapping (0.0 - 1.0).
    pub confidence: f64,
}

/// Indexer for matching trace modules to static programs.
///
/// Ported from Ghidra's `ProgramModuleIndexer`. Indexes a program's
/// metadata (name, sections, symbols) for fast matching against trace modules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramModuleIndexer {
    /// The program URL.
    pub program_url: String,
    /// The program name (filename).
    pub program_name: String,
    /// The primary entry point address (if known).
    pub entry_point: Option<u64>,
    /// Section name -> (start, end) map.
    pub sections: Vec<IndexedSection>,
    /// External library names referenced by this program.
    pub external_libraries: Vec<String>,
}

/// A section in the indexed program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedSection {
    /// The section name.
    pub name: String,
    /// Start address.
    pub start: u64,
    /// End address (exclusive).
    pub end: u64,
    /// Whether the section is executable.
    pub is_executable: bool,
    /// Whether the section contains initialized data.
    pub is_initialized: bool,
}

impl ProgramModuleIndexer {
    /// Create a new indexer for a program.
    pub fn new(program_url: impl Into<String>, program_name: impl Into<String>) -> Self {
        Self {
            program_url: program_url.into(),
            program_name: program_name.into(),
            entry_point: None,
            sections: Vec::new(),
            external_libraries: Vec::new(),
        }
    }

    /// Add a section to the index.
    pub fn add_section(&mut self, section: IndexedSection) {
        self.sections.push(section);
    }

    /// Set the entry point.
    pub fn with_entry_point(mut self, addr: u64) -> Self {
        self.entry_point = Some(addr);
        self
    }

    /// Check if a module name could match this program.
    pub fn matches_module_name(&self, module_name: &str) -> bool {
        let lc_module = module_name.to_lowercase();
        let lc_program = self.program_name.to_lowercase();
        lc_module == lc_program
            || lc_module.ends_with(&lc_program)
            || lc_program.ends_with(&lc_module)
            || lc_module.contains(&lc_program)
            || lc_program.contains(&lc_module)
    }
}

/// Result of finding the best program match for a module.
///
/// Ported from Ghidra's `PeekOpenedDomainObject`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeekOpenedDomainObject {
    /// The program URL.
    pub url: String,
    /// Whether the program is currently open.
    pub is_open: bool,
    /// Whether the program is suitable for the given module.
    pub is_match: bool,
    /// Confidence score.
    pub confidence: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_config_default() {
        let config = DynamicStaticSyncConfig::default();
        assert!(config.sync_locations);
        assert!(config.sync_selections);
        assert!(config.auto_open_programs);
    }

    #[test]
    fn test_sync_location_event() {
        let evt = SyncLocationEvent {
            source: SyncDirection::DynamicToStatic,
            trace_key: Some(1),
            snap: 100,
            thread_key: Some(42),
            address: 0x400000,
            mapped_address: Some(0x100000),
        };
        assert_eq!(evt.address, 0x400000);
        assert_eq!(evt.mapped_address, Some(0x100000));
    }

    #[test]
    fn test_map_modules_command() {
        let cmd = MapModulesBackgroundCommand::new(1, 100);
        assert_eq!(cmd.trace_key, 1);
        assert_eq!(cmd.snap, 100);
        assert!(cmd.auto_open);
    }

    #[test]
    fn test_map_regions_command() {
        let cmd = MapRegionsBackgroundCommand::new(1, 100);
        assert_eq!(cmd.trace_key, 1);
    }

    #[test]
    fn test_map_sections_command() {
        let cmd = MapSectionsBackgroundCommand::new(1, 100);
        assert_eq!(cmd.trace_key, 1);
    }

    #[test]
    fn test_program_indexer() {
        let mut indexer = ProgramModuleIndexer::new("/path/to/libc.so", "libc.so");
        indexer.add_section(IndexedSection {
            name: ".text".into(),
            start: 0x1000,
            end: 0x2000,
            is_executable: true,
            is_initialized: true,
        });
        indexer.add_section(IndexedSection {
            name: ".data".into(),
            start: 0x3000,
            end: 0x4000,
            is_executable: false,
            is_initialized: true,
        });

        assert_eq!(indexer.sections.len(), 2);
        assert!(indexer.matches_module_name("libc.so"));
        assert!(indexer.matches_module_name("lib/libc.so"));
        assert!(!indexer.matches_module_name("libm.so"));
    }

    #[test]
    fn test_indexer_entry_point() {
        let indexer = ProgramModuleIndexer::new("/path/prog", "prog")
            .with_entry_point(0x400000);
        assert_eq!(indexer.entry_point, Some(0x400000));
    }

    #[test]
    fn test_missing_module_entry() {
        let entry = MissingModuleEntry {
            module_name: "libpthread.so.0".into(),
            module_path: Some("/lib/x86_64-linux-gnu/libpthread.so.0".into()),
            trace_key: 1,
            snap: 50,
            address_range: Some((0x7f0000, 0x7f5000)),
        };
        assert_eq!(entry.module_name, "libpthread.so.0");
    }

    #[test]
    fn test_map_command_result() {
        let result = MapCommandResult {
            mapped: vec![MappedModule {
                module_name: "libc.so".into(),
                program_url: "ghidra:///projects/test/libc.so".into(),
                mapped_ranges: vec![(0x7f0000, 0x7f5000)],
                confidence: 0.95,
            }],
            missing: vec![],
            errors: vec![],
        };
        assert_eq!(result.mapped.len(), 1);
        assert!(result.missing.is_empty());
    }

    #[test]
    fn test_peek_opened_domain_object() {
        let peek = PeekOpenedDomainObject {
            url: "ghidra:///test".into(),
            is_open: true,
            is_match: true,
            confidence: 0.9,
        };
        assert!(peek.is_open);
        assert!(peek.is_match);
    }

    #[test]
    fn test_serde_roundtrip() {
        let config = DynamicStaticSyncConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: DynamicStaticSyncConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.sync_locations, config.sync_locations);
    }
}
