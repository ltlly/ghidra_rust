//! Static mapping plugin types for synchronizing program and trace data.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.mapping` package.
//! Provides the mapping manager and helpers for the debugger's static
//! mapping service plugin.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::api::modules::MapEntry;
use crate::model::Lifespan;

/// The direction of a mapping synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MappingDirection {
    /// From trace to program (read from trace, write to program).
    TraceToProgram,
    /// From program to trace (read from program, write to trace).
    ProgramToTrace,
    /// Bidirectional.
    Bidirectional,
}

/// Configuration for a mapping synchronization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingSyncConfig {
    /// The direction of synchronization.
    pub direction: MappingDirection,
    /// Whether to synchronize data types.
    pub sync_data_types: bool,
    /// Whether to synchronize labels/symbols.
    pub sync_labels: bool,
    /// Whether to synchronize comments.
    pub sync_comments: bool,
    /// Whether to synchronize bookmarks.
    pub sync_bookmarks: bool,
    /// Whether to overwrite existing data in the destination.
    pub overwrite_existing: bool,
}

impl Default for MappingSyncConfig {
    fn default() -> Self {
        Self {
            direction: MappingDirection::Bidirectional,
            sync_data_types: false,
            sync_labels: true,
            sync_comments: true,
            sync_bookmarks: false,
            overwrite_existing: false,
        }
    }
}

impl MappingSyncConfig {
    /// Create a new config with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the direction.
    pub fn with_direction(mut self, direction: MappingDirection) -> Self {
        self.direction = direction;
        self
    }

    /// Enable data type synchronization.
    pub fn with_sync_data_types(mut self) -> Self {
        self.sync_data_types = true;
        self
    }
}

/// A mapping proposal result from the automatic mapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingProposalResult {
    /// The trace ID.
    pub trace_id: String,
    /// The program URL.
    pub program_url: String,
    /// Proposed entries.
    pub entries: Vec<MapEntry>,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
    /// The basis for the proposal.
    pub basis: MappingProposalBasis,
}

/// What the mapping proposal was based on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MappingProposalBasis {
    /// Based on module matching.
    ModuleMatch,
    /// Based on section matching.
    SectionMatch,
    /// Based on region matching.
    RegionMatch,
    /// Based on debug info.
    DebugInfo,
    /// Manual proposal.
    Manual,
}

impl MappingProposalResult {
    /// Create a new proposal result.
    pub fn new(
        trace_id: impl Into<String>,
        program_url: impl Into<String>,
        basis: MappingProposalBasis,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            program_url: program_url.into(),
            entries: Vec::new(),
            confidence: 0.0,
            basis,
        }
    }

    /// Add a mapping entry.
    pub fn add_entry(&mut self, entry: MapEntry) {
        self.entries.push(entry);
    }
}

/// The mapping manager that tracks all static mappings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MappingManager {
    /// All active mappings.
    mappings: Vec<MappingRecord>,
    /// The next mapping ID.
    next_id: u64,
}

/// A single mapping record with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingRecord {
    /// The unique ID.
    pub id: u64,
    /// The mapping entry.
    pub entry: MapEntry,
    /// Whether this mapping is currently active.
    pub active: bool,
    /// The sync configuration.
    pub sync_config: MappingSyncConfig,
}

impl MappingManager {
    /// Create a new mapping manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a mapping.
    pub fn add(&mut self, entry: MapEntry) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.mappings.push(MappingRecord {
            id,
            entry,
            active: true,
            sync_config: MappingSyncConfig::default(),
        });
        id
    }

    /// Remove a mapping by ID.
    pub fn remove(&mut self, id: u64) -> Option<MappingRecord> {
        if let Some(idx) = self.mappings.iter().position(|m| m.id == id) {
            Some(self.mappings.remove(idx))
        } else {
            None
        }
    }

    /// Get all mappings.
    pub fn mappings(&self) -> &[MappingRecord] {
        &self.mappings
    }

    /// Get active mappings only.
    pub fn active_mappings(&self) -> Vec<&MappingRecord> {
        self.mappings.iter().filter(|m| m.active).collect()
    }

    /// Find mappings that contain the given trace address at the given snap.
    pub fn find_for_trace_addr(&self, addr: u64, snap: i64) -> Vec<&MappingRecord> {
        self.mappings
            .iter()
            .filter(|m| m.active && m.entry.contains_from(addr, snap))
            .collect()
    }

    /// Number of mappings.
    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    /// Whether the manager has no mappings.
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mapping_sync_config() {
        let config = MappingSyncConfig::new()
            .with_direction(MappingDirection::TraceToProgram)
            .with_sync_data_types();
        assert_eq!(config.direction, MappingDirection::TraceToProgram);
        assert!(config.sync_data_types);
        assert!(config.sync_labels); // default true
    }

    #[test]
    fn test_mapping_proposal() {
        let mut proposal =
            MappingProposalResult::new("trace1", "file:///prog", MappingProposalBasis::ModuleMatch);
        proposal.confidence = 0.95;
        proposal.add_entry(MapEntry::new(
            "trace1",
            0x400000,
            0x400fff,
            0x7fff0000,
            0x7fff0fff,
            Lifespan::now_on(0),
        ));
        assert_eq!(proposal.entries.len(), 1);
    }

    #[test]
    fn test_mapping_manager() {
        let mut mgr = MappingManager::new();
        assert!(mgr.is_empty());

        let id1 = mgr.add(MapEntry::new(
            "trace1",
            0x400000,
            0x400fff,
            0x7fff0000,
            0x7fff0fff,
            Lifespan::now_on(0),
        ));
        let id2 = mgr.add(MapEntry::new(
            "trace1",
            0x401000,
            0x401fff,
            0x7fff1000,
            0x7fff1fff,
            Lifespan::now_on(0),
        ));

        assert_eq!(mgr.len(), 2);
        assert!(id1 != id2);

        let removed = mgr.remove(id1);
        assert!(removed.is_some());
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn test_mapping_manager_find() {
        let mut mgr = MappingManager::new();
        mgr.add(MapEntry::new(
            "trace1",
            0x7fff0000,
            0x7fff0fff,
            0x400000,
            0x400fff,
            Lifespan::now_on(0),
        ));

        let found = mgr.find_for_trace_addr(0x7fff0500, 0);
        assert_eq!(found.len(), 1);

        let not_found = mgr.find_for_trace_addr(0x80000000, 0);
        assert!(not_found.is_empty());
    }

    #[test]
    fn test_active_mappings() {
        let mut mgr = MappingManager::new();
        mgr.add(MapEntry::new(
            "t1", 0x100, 0x1ff, 0x200, 0x2ff, Lifespan::now_on(0),
        ));
        mgr.mappings[0].active = false;
        assert!(mgr.active_mappings().is_empty());
    }

    #[test]
    fn test_mapping_direction() {
        assert_ne!(
            MappingDirection::TraceToProgram,
            MappingDirection::ProgramToTrace
        );
    }

    #[test]
    fn test_mapping_manager_serde() {
        let mut mgr = MappingManager::new();
        mgr.add(MapEntry::new(
            "t1", 0x100, 0x1ff, 0x200, 0x2ff, Lifespan::now_on(0),
        ));
        let json = serde_json::to_string(&mgr).unwrap();
        let back: MappingManager = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
    }
}
