//! Database-backed static mapping manager.
//!
//! Ported from Ghidra's `ghidra.trace.database.module.DBTraceStaticMappingManager`
//! and `DBTraceStaticMapping`.
//!
//! Static mappings record the correspondence between addresses in a
//! (static) program and addresses in a (dynamic) trace. This is essential
//! for features like "map program to trace" which allows navigation
//! between the disassembly listing and the live trace.
//!
//! Each mapping specifies:
//! - A program URL (identifying the static program)
//! - A program address range
//! - A trace address range
//! - A lifespan (when the mapping is valid in trace time)

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

// ---------------------------------------------------------------------------
// StaticMapping
// ---------------------------------------------------------------------------

/// A mapping between a program address range and a trace address range.
///
/// Ported from `ghidra.trace.database.module.DBTraceStaticMapping`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticMapping {
    /// Unique key for this mapping.
    pub key: i64,
    /// The program URL identifying the static program.
    pub program_url: String,
    /// Start address in the program.
    pub program_start: u64,
    /// End address in the program (inclusive).
    pub program_end: u64,
    /// Start address in the trace.
    pub trace_start: u64,
    /// End address in the trace (inclusive).
    pub trace_end: u64,
    /// The lifespan during which this mapping is valid.
    pub lifespan: Lifespan,
}

impl StaticMapping {
    /// Create a new static mapping.
    pub fn new(
        key: i64,
        program_url: impl Into<String>,
        program_start: u64,
        program_end: u64,
        trace_start: u64,
        trace_end: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            key,
            program_url: program_url.into(),
            program_start,
            program_end,
            trace_start,
            trace_end,
            lifespan,
        }
    }

    /// The size of the mapped region in the program.
    pub fn program_length(&self) -> u64 {
        self.program_end - self.program_start + 1
    }

    /// The size of the mapped region in the trace.
    pub fn trace_length(&self) -> u64 {
        self.trace_end - self.trace_start + 1
    }

    /// Translate a program address to a trace address.
    ///
    /// Returns `None` if the program address is outside this mapping.
    pub fn program_to_trace(&self, program_addr: u64) -> Option<u64> {
        if program_addr < self.program_start || program_addr > self.program_end {
            return None;
        }
        let offset = program_addr - self.program_start;
        Some(self.trace_start + offset)
    }

    /// Translate a trace address to a program address.
    ///
    /// Returns `None` if the trace address is outside this mapping.
    pub fn trace_to_program(&self, trace_addr: u64) -> Option<u64> {
        if trace_addr < self.trace_start || trace_addr > self.trace_end {
            return None;
        }
        let offset = trace_addr - self.trace_start;
        Some(self.program_start + offset)
    }

    /// Check whether this mapping overlaps the given trace address range at the given snap.
    pub fn overlaps_trace(&self, trace_min: u64, trace_max: u64, snap: i64) -> bool {
        if !self.lifespan.contains(snap) {
            return false;
        }
        self.trace_start <= trace_max && self.trace_end >= trace_min
    }
}

// ---------------------------------------------------------------------------
// DBTraceStaticMappingManager
// ---------------------------------------------------------------------------

/// The database-backed static mapping manager.
///
/// Ported from `ghidra.trace.database.module.DBTraceStaticMappingManager`.
/// Manages all static-to-dynamic address mappings in a trace.
#[derive(Debug, Default)]
pub struct DbTraceStaticMappingManager {
    mappings: Vec<StaticMapping>,
    next_key: i64,
}

impl DbTraceStaticMappingManager {
    /// Create a new mapping manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new static mapping.
    pub fn add_mapping(
        &mut self,
        program_url: impl Into<String>,
        program_start: u64,
        program_end: u64,
        trace_start: u64,
        trace_end: u64,
        lifespan: Lifespan,
    ) -> &StaticMapping {
        let key = self.next_key;
        self.next_key += 1;
        let mapping = StaticMapping::new(
            key,
            program_url,
            program_start,
            program_end,
            trace_start,
            trace_end,
            lifespan,
        );
        self.mappings.push(mapping);
        self.mappings.last().unwrap()
    }

    /// Get a mapping by its key.
    pub fn get_mapping(&self, key: i64) -> Option<&StaticMapping> {
        self.mappings.iter().find(|m| m.key == key)
    }

    /// Remove a mapping by its key.
    pub fn remove_mapping(&mut self, key: i64) -> Option<StaticMapping> {
        if let Some(pos) = self.mappings.iter().position(|m| m.key == key) {
            Some(self.mappings.remove(pos))
        } else {
            None
        }
    }

    /// Get all mappings.
    pub fn all_mappings(&self) -> &[StaticMapping] {
        &self.mappings
    }

    /// Get all mappings for a given program URL.
    pub fn mappings_for_program(&self, program_url: &str) -> Vec<&StaticMapping> {
        self.mappings
            .iter()
            .filter(|m| m.program_url == program_url)
            .collect()
    }

    /// Find mappings that cover the given trace address at the given snap.
    pub fn mappings_at(&self, trace_addr: u64, snap: i64) -> Vec<&StaticMapping> {
        self.mappings
            .iter()
            .filter(|m| {
                m.lifespan.contains(snap)
                    && trace_addr >= m.trace_start
                    && trace_addr <= m.trace_end
            })
            .collect()
    }

    /// Translate a trace address to a program address using the best available mapping.
    ///
    /// Returns (program_url, program_addr) if a mapping is found.
    pub fn trace_to_program(&self, trace_addr: u64, snap: i64) -> Option<(String, u64)> {
        self.mappings
            .iter()
            .find(|m| {
                m.lifespan.contains(snap)
                    && trace_addr >= m.trace_start
                    && trace_addr <= m.trace_end
            })
            .and_then(|m| m.trace_to_program(trace_addr).map(|a| (m.program_url.clone(), a)))
    }

    /// Translate a program address to a trace address using the best available mapping.
    ///
    /// Returns trace_addr if a mapping is found.
    pub fn program_to_trace(&self, program_url: &str, program_addr: u64, snap: i64) -> Option<u64> {
        self.mappings
            .iter()
            .find(|m| {
                m.program_url == program_url
                    && m.lifespan.contains(snap)
                    && program_addr >= m.program_start
                    && program_addr <= m.program_end
            })
            .and_then(|m| m.program_to_trace(program_addr))
    }

    /// Get the number of mappings.
    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    /// Check if the manager is empty.
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }

    /// Clear all mappings.
    pub fn clear(&mut self) {
        self.mappings.clear();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_mapping_translate() {
        let mapping = StaticMapping::new(
            1,
            "file:///test",
            0x400000,
            0x400FFF,
            0x7FFF0000,
            0x7FFF0FFF,
            Lifespan::span(0, 100),
        );

        assert_eq!(mapping.program_to_trace(0x400000), Some(0x7FFF0000));
        assert_eq!(mapping.program_to_trace(0x400010), Some(0x7FFF0010));
        assert_eq!(mapping.program_to_trace(0x400FFF), Some(0x7FFF0FFF));
        assert_eq!(mapping.program_to_trace(0x500000), None);

        assert_eq!(mapping.trace_to_program(0x7FFF0000), Some(0x400000));
        assert_eq!(mapping.trace_to_program(0x7FFF0010), Some(0x400010));
        assert_eq!(mapping.trace_to_program(0x80000000), None);
    }

    #[test]
    fn test_static_mapping_dimensions() {
        let mapping = StaticMapping::new(
            1, "test", 0x1000, 0x1FFF, 0x2000, 0x2FFF, Lifespan::span(0, 100),
        );
        assert_eq!(mapping.program_length(), 0x1000);
        assert_eq!(mapping.trace_length(), 0x1000);
    }

    #[test]
    fn test_mapping_manager_add_and_get() {
        let mut mgr = DbTraceStaticMappingManager::new();
        assert!(mgr.is_empty());

        mgr.add_mapping("test.exe", 0x400000, 0x400FFF, 0x7FFF0000, 0x7FFF0FFF, Lifespan::span(0, 100));
        assert_eq!(mgr.len(), 1);

        let mapping = mgr.get_mapping(0).unwrap();
        assert_eq!(mapping.program_url, "test.exe");
    }

    #[test]
    fn test_mapping_manager_remove() {
        let mut mgr = DbTraceStaticMappingManager::new();
        mgr.add_mapping("test.exe", 0x400000, 0x400FFF, 0x7FFF0000, 0x7FFF0FFF, Lifespan::span(0, 100));

        let removed = mgr.remove_mapping(0);
        assert!(removed.is_some());
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_mapping_manager_by_program() {
        let mut mgr = DbTraceStaticMappingManager::new();
        mgr.add_mapping("a.exe", 0x400000, 0x400FFF, 0x7FFF0000, 0x7FFF0FFF, Lifespan::span(0, 100));
        mgr.add_mapping("b.dll", 0x10000000, 0x1000FFFF, 0x7FFE0000, 0x7FFEFFFF, Lifespan::span(0, 100));
        mgr.add_mapping("a.exe", 0x401000, 0x401FFF, 0x7FFF1000, 0x7FFF1FFF, Lifespan::span(0, 100));

        let a_mappings = mgr.mappings_for_program("a.exe");
        assert_eq!(a_mappings.len(), 2);

        let b_mappings = mgr.mappings_for_program("b.dll");
        assert_eq!(b_mappings.len(), 1);
    }

    #[test]
    fn test_mapping_manager_translate() {
        let mut mgr = DbTraceStaticMappingManager::new();
        mgr.add_mapping("test.exe", 0x400000, 0x400FFF, 0x7FFF0000, 0x7FFF0FFF, Lifespan::span(0, 100));

        // trace -> program
        let result = mgr.trace_to_program(0x7FFF0100, 50);
        assert_eq!(result, Some(("test.exe".to_string(), 0x400100)));

        // program -> trace
        let result = mgr.program_to_trace("test.exe", 0x400100, 50);
        assert_eq!(result, Some(0x7FFF0100));
    }

    #[test]
    fn test_mapping_manager_outside_lifespan() {
        let mut mgr = DbTraceStaticMappingManager::new();
        mgr.add_mapping("test.exe", 0x400000, 0x400FFF, 0x7FFF0000, 0x7FFF0FFF, Lifespan::span(10, 20));

        // Before lifespan
        assert!(mgr.trace_to_program(0x7FFF0100, 5).is_none());

        // During lifespan
        assert!(mgr.trace_to_program(0x7FFF0100, 15).is_some());

        // After lifespan
        assert!(mgr.trace_to_program(0x7FFF0100, 25).is_none());
    }

    #[test]
    fn test_mapping_manager_mappings_at() {
        let mut mgr = DbTraceStaticMappingManager::new();
        mgr.add_mapping("a.exe", 0x400000, 0x400FFF, 0x7FFF0000, 0x7FFF0FFF, Lifespan::span(0, 100));
        mgr.add_mapping("b.dll", 0x10000000, 0x1000FFFF, 0x7FFF1000, 0x7FFF1FFF, Lifespan::span(0, 100));

        let at_a = mgr.mappings_at(0x7FFF0100, 50);
        assert_eq!(at_a.len(), 1);
        assert_eq!(at_a[0].program_url, "a.exe");

        let at_b = mgr.mappings_at(0x7FFF1100, 50);
        assert_eq!(at_b.len(), 1);
        assert_eq!(at_b[0].program_url, "b.dll");

        let at_none = mgr.mappings_at(0x80000000, 50);
        assert!(at_none.is_empty());
    }
}
