//! TraceStaticMapManager - manages static mappings between trace and program.
//!
//! Ported from Ghidra's `StaticMappingEntryManager` interface and
//! `DBTraceMapManager` implementation.
//!
//! Static mappings allow correlating addresses in a dynamic trace
//! with addresses in a static program (Ghidra listing). This is essential
//! for the "merge" view that overlays dynamic execution onto static analysis.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::Lifespan;

/// A static mapping between a trace address range and a program address range.
///
/// Ported from Ghidra's `StaticMappingEntry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticMappingEntry {
    /// Unique key for this mapping.
    pub key: i64,
    /// Trace address space name.
    pub trace_space: String,
    /// Trace minimum offset.
    pub trace_min: u64,
    /// Trace maximum offset.
    pub trace_max: u64,
    /// Program (static) minimum address.
    pub static_min: u64,
    /// Program (static) maximum address.
    pub static_max: u64,
    /// The lifespan during which this mapping is valid.
    pub lifespan: Lifespan,
}

impl StaticMappingEntry {
    /// Create a new static mapping.
    pub fn new(
        key: i64,
        trace_space: impl Into<String>,
        trace_min: u64,
        trace_max: u64,
        static_min: u64,
        static_max: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            key,
            trace_space: trace_space.into(),
            trace_min,
            trace_max,
            static_min,
            static_max,
            lifespan,
        }
    }

    /// Get the size of the mapped range (in bytes).
    pub fn size(&self) -> u64 {
        self.trace_max - self.trace_min + 1
    }

    /// Check if a trace address falls within this mapping.
    pub fn contains_trace_address(&self, address: u64) -> bool {
        address >= self.trace_min && address <= self.trace_max
    }

    /// Translate a trace address to the corresponding static address.
    pub fn trace_to_static(&self, trace_addr: u64) -> Option<u64> {
        if self.contains_trace_address(trace_addr) {
            let offset = trace_addr - self.trace_min;
            Some(self.static_min + offset)
        } else {
            None
        }
    }

    /// Translate a static address to the corresponding trace address.
    pub fn static_to_trace(&self, static_addr: u64) -> Option<u64> {
        if static_addr >= self.static_min && static_addr <= self.static_max {
            let offset = static_addr - self.static_min;
            Some(self.trace_min + offset)
        } else {
            None
        }
    }
}

/// A listener for changes to static mappings.
///
/// Ported from Ghidra's `DebuggerStaticMappingChangeListener`.
pub trait TraceStaticMappingChangeListener {
    /// Called when a mapping is added.
    fn mapping_added(&self, mapping: &StaticMappingEntry);

    /// Called when a mapping is removed.
    fn mapping_removed(&self, mapping: &StaticMappingEntry);

    /// Called when a mapping is changed.
    fn mapping_changed(&self, old: &StaticMappingEntry, new: &StaticMappingEntry);
}

/// Manages a collection of static mappings.
///
/// Ported from Ghidra's `StaticMappingEntryManager`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceStaticMapManager {
    mappings: BTreeMap<i64, StaticMappingEntry>,
    next_key: i64,
}

impl TraceStaticMapManager {
    /// Create a new empty mapping manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new static mapping.
    ///
    /// Returns the key assigned to the new mapping.
    pub fn add_mapping(
        &mut self,
        trace_space: &str,
        trace_min: u64,
        trace_max: u64,
        static_min: u64,
        static_max: u64,
        lifespan: Lifespan,
    ) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        let mapping = StaticMappingEntry::new(
            key,
            trace_space,
            trace_min,
            trace_max,
            static_min,
            static_max,
            lifespan,
        );
        self.mappings.insert(key, mapping);
        key
    }

    /// Get a mapping by key.
    pub fn get_mapping(&self, key: i64) -> Option<&StaticMappingEntry> {
        self.mappings.get(&key)
    }

    /// Get all mappings.
    pub fn all_mappings(&self) -> Vec<&StaticMappingEntry> {
        self.mappings.values().collect()
    }

    /// Remove a mapping by key.
    pub fn remove_mapping(&mut self, key: i64) -> bool {
        self.mappings.remove(&key).is_some()
    }

    /// Find the mapping that covers the given trace address at the given snap.
    pub fn find_mapping_for_trace(
        &self,
        trace_space: &str,
        address: u64,
        snap: i64,
    ) -> Option<&StaticMappingEntry> {
        self.mappings.values().find(|m| {
            m.trace_space == trace_space
                && m.contains_trace_address(address)
                && m.lifespan.contains(snap)
        })
    }

    /// Translate a trace address to a static address at the given snap.
    pub fn trace_to_static(
        &self,
        trace_space: &str,
        address: u64,
        snap: i64,
    ) -> Option<u64> {
        self.find_mapping_for_trace(trace_space, address, snap)
            .and_then(|m| m.trace_to_static(address))
    }

    /// Translate a static address to a trace address at the given snap.
    pub fn static_to_trace(
        &self,
        trace_space: &str,
        static_addr: u64,
        snap: i64,
    ) -> Option<u64> {
        self.mappings.values().find_map(|m| {
            if m.trace_space == trace_space && m.lifespan.contains(snap) {
                m.static_to_trace(static_addr)
            } else {
                None
            }
        })
    }

    /// Get the number of mappings.
    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get() {
        let mut mgr = TraceStaticMapManager::new();
        let key = mgr.add_mapping("ram", 0x1000, 0x1FFF, 0x400000, 0x400FFF, Lifespan::at(0));
        assert_eq!(mgr.mapping_count(), 1);
        let m = mgr.get_mapping(key).unwrap();
        assert_eq!(m.trace_space, "ram");
        assert_eq!(m.size(), 0x1000);
    }

    #[test]
    fn test_trace_to_static() {
        let mut mgr = TraceStaticMapManager::new();
        mgr.add_mapping("ram", 0x1000, 0x1FFF, 0x400000, 0x400FFF, Lifespan::at(0));
        assert_eq!(mgr.trace_to_static("ram", 0x1050, 0), Some(0x400050));
        assert_eq!(mgr.trace_to_static("ram", 0x2000, 0), None);
    }

    #[test]
    fn test_static_to_trace() {
        let mut mgr = TraceStaticMapManager::new();
        mgr.add_mapping("ram", 0x1000, 0x1FFF, 0x400000, 0x400FFF, Lifespan::at(0));
        assert_eq!(mgr.static_to_trace("ram", 0x400050, 0), Some(0x1050));
    }

    #[test]
    fn test_remove() {
        let mut mgr = TraceStaticMapManager::new();
        let key = mgr.add_mapping("ram", 0, 0xFF, 0, 0xFF, Lifespan::at(0));
        assert!(mgr.remove_mapping(key));
        assert_eq!(mgr.mapping_count(), 0);
        assert!(!mgr.remove_mapping(key));
    }

    #[test]
    fn test_mapping_contains() {
        let m = StaticMappingEntry::new(1, "ram", 0x1000, 0x1FFF, 0x400000, 0x400FFF, Lifespan::at(0));
        assert!(m.contains_trace_address(0x1000));
        assert!(m.contains_trace_address(0x1FFF));
        assert!(!m.contains_trace_address(0x2000));
    }

    #[test]
    fn test_mapping_translation() {
        let m = StaticMappingEntry::new(1, "ram", 0x1000, 0x1FFF, 0x400000, 0x400FFF, Lifespan::at(0));
        assert_eq!(m.trace_to_static(0x1000), Some(0x400000));
        assert_eq!(m.trace_to_static(0x1080), Some(0x400080));
        assert_eq!(m.static_to_trace(0x400080), Some(0x1080));
        assert_eq!(m.trace_to_static(0x2000), None);
    }
}
