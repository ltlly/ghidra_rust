//! Static mapping types and change listeners.
//!
//! Ported from Ghidra's `DebuggerStaticMappingChangeListener` and related types.
//!
//! Provides listeners and types for tracking changes to static mappings
//! between programs and trace memory.

use serde::{Deserialize, Serialize};

/// An event describing a change to a static mapping.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StaticMappingChangeEvent {
    /// A new mapping was added.
    Added(StaticMappingEntry),
    /// An existing mapping was removed.
    Removed(StaticMappingEntry),
    /// An existing mapping was modified.
    Modified {
        /// The old mapping entry.
        old: StaticMappingEntry,
        /// The new mapping entry.
        new: StaticMappingEntry,
    },
}

/// An entry in the static mapping table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StaticMappingEntry {
    /// The program URL.
    pub program_url: String,
    /// The start address in the program.
    pub program_min: u64,
    /// The end address in the program.
    pub program_max: u64,
    /// The start address in the trace.
    pub trace_min: u64,
    /// The end address in the trace.
    pub trace_max: u64,
    /// The snap range (lifespan) of this mapping.
    pub min_snap: i64,
    /// The maximum snap for this mapping (i64::MAX for infinite).
    pub max_snap: i64,
}

impl StaticMappingEntry {
    /// Create a new static mapping entry.
    pub fn new(
        program_url: impl Into<String>,
        program_min: u64,
        program_max: u64,
        trace_min: u64,
        trace_max: u64,
        min_snap: i64,
        max_snap: i64,
    ) -> Self {
        Self {
            program_url: program_url.into(),
            program_min,
            program_max,
            trace_min,
            trace_max,
            min_snap,
            max_snap,
        }
    }

    /// Check if a given snap falls within this mapping's lifespan.
    pub fn contains_snap(&self, snap: i64) -> bool {
        snap >= self.min_snap && snap <= self.max_snap
    }

    /// Get the size of the mapped range.
    pub fn range_size(&self) -> u64 {
        self.program_max.saturating_sub(self.program_min)
    }

    /// Map a program address to a trace address.
    pub fn map_to_trace(&self, program_addr: u64) -> Option<u64> {
        if program_addr < self.program_min || program_addr > self.program_max {
            return None;
        }
        let offset = program_addr - self.program_min;
        Some(self.trace_min + offset)
    }

    /// Map a trace address to a program address.
    pub fn map_to_program(&self, trace_addr: u64) -> Option<u64> {
        if trace_addr < self.trace_min || trace_addr > self.trace_max {
            return None;
        }
        let offset = trace_addr - self.trace_min;
        Some(self.program_min + offset)
    }
}

/// A trait for listening to static mapping changes.
pub trait StaticMappingChangeListener: Send + Sync {
    /// Called when a mapping is added.
    fn mapping_added(&self, entry: &StaticMappingEntry);

    /// Called when a mapping is removed.
    fn mapping_removed(&self, entry: &StaticMappingEntry);

    /// Called when a mapping is modified.
    fn mapping_modified(&self, old: &StaticMappingEntry, new: &StaticMappingEntry);
}

/// The kind of mapping change that occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MappingChangeKind {
    /// A mapping was added.
    Added,
    /// A mapping was removed.
    Removed,
    /// A mapping was modified.
    Modified,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_mapping_entry_creation() {
        let entry = StaticMappingEntry::new("file:///test.exe", 0x400000, 0x401000, 0, 0x1000, 0, i64::MAX);
        assert_eq!(entry.program_url, "file:///test.exe");
        assert_eq!(entry.program_min, 0x400000);
        assert_eq!(entry.range_size(), 0x1000);
    }

    #[test]
    fn test_mapping_contains_snap() {
        let entry = StaticMappingEntry::new("test", 0, 0x100, 0, 0x100, 5, 10);
        assert!(!entry.contains_snap(4));
        assert!(entry.contains_snap(5));
        assert!(entry.contains_snap(7));
        assert!(entry.contains_snap(10));
        assert!(!entry.contains_snap(11));
    }

    #[test]
    fn test_mapping_to_trace() {
        let entry = StaticMappingEntry::new("test", 0x400000, 0x401000, 0, 0x1000, 0, i64::MAX);
        assert_eq!(entry.map_to_trace(0x400000), Some(0));
        assert_eq!(entry.map_to_trace(0x400500), Some(0x500));
        assert_eq!(entry.map_to_trace(0x401000), Some(0x1000));
        assert_eq!(entry.map_to_trace(0x300000), None);
        assert_eq!(entry.map_to_trace(0x500000), None);
    }

    #[test]
    fn test_mapping_to_program() {
        let entry = StaticMappingEntry::new("test", 0x400000, 0x401000, 0, 0x1000, 0, i64::MAX);
        assert_eq!(entry.map_to_program(0), Some(0x400000));
        assert_eq!(entry.map_to_program(0x500), Some(0x400500));
        assert_eq!(entry.map_to_program(0x1000), Some(0x401000));
        assert_eq!(entry.map_to_program(0x2000), None);
    }

    #[test]
    fn test_mapping_change_event() {
        let entry = StaticMappingEntry::new("test", 0, 0x100, 0, 0x100, 0, 10);
        let event = StaticMappingChangeEvent::Added(entry.clone());
        match event {
            StaticMappingChangeEvent::Added(e) => assert_eq!(e.program_url, "test"),
            _ => panic!("Expected Added event"),
        }
    }

    #[test]
    fn test_mapping_change_kind() {
        assert_ne!(MappingChangeKind::Added, MappingChangeKind::Removed);
        assert_eq!(MappingChangeKind::Modified, MappingChangeKind::Modified);
    }
}
