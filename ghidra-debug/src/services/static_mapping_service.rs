//! Static mapping service - mapping between trace addresses and program addresses.
//!
//! Ported from Ghidra's `DebuggerStaticMappingServicePlugin` (which is part of
//! the 383-file Debugger/ directory) and related service interfaces.
//! This module manages the mapping between dynamic trace addresses and
//! static program addresses, including proposals, entries, and listeners.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A single static mapping entry maps a range of trace addresses to
/// a range of program addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticMappingEntry {
    /// The start of the trace address range.
    pub trace_start: u64,
    /// The length of the trace address range.
    pub trace_length: u64,
    /// The start of the program address range.
    pub program_start: u64,
    /// The length of the program address range.
    pub program_length: u64,
    /// The trace key.
    pub trace_key: String,
    /// The program URL.
    pub program_url: String,
    /// The thread key (None for all threads).
    pub thread_key: Option<i64>,
    /// Whether this mapping is currently active.
    pub is_active: bool,
}

impl StaticMappingEntry {
    /// Create a new mapping entry.
    pub fn new(
        trace_key: impl Into<String>,
        trace_start: u64,
        trace_length: u64,
        program_url: impl Into<String>,
        program_start: u64,
        program_length: u64,
    ) -> Self {
        Self {
            trace_start,
            trace_length,
            program_start,
            program_length,
            trace_key: trace_key.into(),
            program_url: program_url.into(),
            thread_key: None,
            is_active: true,
        }
    }

    /// Set the thread for this mapping.
    pub fn with_thread(mut self, thread_key: i64) -> Self {
        self.thread_key = Some(thread_key);
        self
    }

    /// The end of the trace range (exclusive).
    pub fn trace_end(&self) -> u64 {
        self.trace_start + self.trace_length
    }

    /// The end of the program range (exclusive).
    pub fn program_end(&self) -> u64 {
        self.program_start + self.program_length
    }

    /// Whether the given trace address falls within this mapping's trace range.
    pub fn contains_trace_address(&self, addr: u64) -> bool {
        addr >= self.trace_start && addr < self.trace_end()
    }

    /// Translate a trace address to a program address.
    ///
    /// Returns None if the address is outside the trace range.
    pub fn trace_to_program(&self, trace_addr: u64) -> Option<u64> {
        if !self.contains_trace_address(trace_addr) {
            return None;
        }
        let offset = trace_addr - self.trace_start;
        Some(self.program_start + offset)
    }

    /// Translate a program address to a trace address.
    ///
    /// Returns None if the address is outside the program range.
    pub fn program_to_trace(&self, program_addr: u64) -> Option<u64> {
        if program_addr < self.program_start || program_addr >= self.program_end() {
            return None;
        }
        let offset = program_addr - self.program_start;
        Some(self.trace_start + offset)
    }

    /// Whether this mapping overlaps with another.
    pub fn overlaps_trace(&self, other: &StaticMappingEntry) -> bool {
        self.trace_key == other.trace_key
            && self.trace_start < other.trace_end()
            && other.trace_start < self.trace_end()
    }
}

/// A change event for static mappings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MappingChangeEvent {
    /// A mapping was added.
    Added(StaticMappingEntry),
    /// A mapping was removed.
    Removed(StaticMappingEntry),
    /// A mapping was modified.
    Modified {
        /// The old entry.
        old: StaticMappingEntry,
        /// The new entry.
        new: StaticMappingEntry,
    },
}

/// The static mapping service manages all mappings between traces and programs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StaticMappingService {
    /// All mappings indexed by (trace_key, index).
    mappings: Vec<StaticMappingEntry>,
    /// Event log.
    events: Vec<MappingChangeEvent>,
}

impl StaticMappingService {
    /// Create a new static mapping service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a mapping entry.
    pub fn add_mapping(&mut self, entry: StaticMappingEntry) {
        self.events
            .push(MappingChangeEvent::Added(entry.clone()));
        self.mappings.push(entry);
    }

    /// Remove a mapping entry.
    pub fn remove_mapping(&mut self, index: usize) -> Option<StaticMappingEntry> {
        if index < self.mappings.len() {
            let entry = self.mappings.remove(index);
            self.events
                .push(MappingChangeEvent::Removed(entry.clone()));
            Some(entry)
        } else {
            None
        }
    }

    /// Get all mappings.
    pub fn mappings(&self) -> &[StaticMappingEntry] {
        &self.mappings
    }

    /// Get mappings for a specific trace.
    pub fn mappings_for_trace(&self, trace_key: &str) -> Vec<&StaticMappingEntry> {
        self.mappings
            .iter()
            .filter(|m| m.trace_key == trace_key)
            .collect()
    }

    /// Get mappings for a specific program.
    pub fn mappings_for_program(&self, program_url: &str) -> Vec<&StaticMappingEntry> {
        self.mappings
            .iter()
            .filter(|m| m.program_url == program_url)
            .collect()
    }

    /// Translate a trace address to a program address using all active mappings.
    pub fn translate_trace_to_program(&self, trace_key: &str, trace_addr: u64) -> Option<u64> {
        self.mappings
            .iter()
            .filter(|m| m.trace_key == trace_key && m.is_active)
            .find_map(|m| m.trace_to_program(trace_addr))
    }

    /// Translate a program address to a trace address using all active mappings.
    pub fn translate_program_to_trace(
        &self,
        program_url: &str,
        program_addr: u64,
    ) -> Option<u64> {
        self.mappings
            .iter()
            .filter(|m| m.program_url == program_url && m.is_active)
            .find_map(|m| m.program_to_trace(program_addr))
    }

    /// Get all events.
    pub fn events(&self) -> &[MappingChangeEvent] {
        &self.events
    }

    /// Clear the event log.
    pub fn clear_events(&mut self) {
        self.events.clear();
    }

    /// The number of mappings.
    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    /// Whether there are no mappings.
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }

    /// Remove all mappings for a given trace.
    pub fn remove_trace_mappings(&mut self, trace_key: &str) {
        let removed: Vec<StaticMappingEntry> = self
            .mappings
            .drain(..)
            .filter(|m| m.trace_key != trace_key)
            .collect();
        let old_mappings: Vec<StaticMappingEntry> = self
            .mappings
            .iter()
            .filter(|m| m.trace_key == trace_key)
            .cloned()
            .collect();
        for entry in &old_mappings {
            self.events
                .push(MappingChangeEvent::Removed(entry.clone()));
        }
        self.mappings = removed;
    }

    /// Check for overlapping mappings.
    pub fn find_overlapping(&self) -> Vec<(&StaticMappingEntry, &StaticMappingEntry)> {
        let mut overlaps = Vec::new();
        for i in 0..self.mappings.len() {
            for j in (i + 1)..self.mappings.len() {
                if self.mappings[i].overlaps_trace(&self.mappings[j]) {
                    overlaps.push((&self.mappings[i], &self.mappings[j]));
                }
            }
        }
        overlaps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mapping_entry_basics() {
        let entry = StaticMappingEntry::new("trace1", 0x1000, 0x100, "prog://test", 0x400000, 0x100);
        assert_eq!(entry.trace_start, 0x1000);
        assert_eq!(entry.trace_length, 0x100);
        assert_eq!(entry.trace_end(), 0x1100);
        assert_eq!(entry.program_start, 0x400000);
        assert_eq!(entry.program_end(), 0x400100);
    }

    #[test]
    fn test_mapping_entry_with_thread() {
        let entry = StaticMappingEntry::new("t", 0, 0x100, "p", 0x400000, 0x100)
            .with_thread(42);
        assert_eq!(entry.thread_key, Some(42));
    }

    #[test]
    fn test_mapping_contains_trace_address() {
        let entry = StaticMappingEntry::new("t", 0x1000, 0x100, "p", 0x400000, 0x100);
        assert!(entry.contains_trace_address(0x1000));
        assert!(entry.contains_trace_address(0x1050));
        assert!(entry.contains_trace_address(0x10FF));
        assert!(!entry.contains_trace_address(0x1100));
        assert!(!entry.contains_trace_address(0x0FFF));
    }

    #[test]
    fn test_mapping_trace_to_program() {
        let entry = StaticMappingEntry::new("t", 0x1000, 0x100, "p", 0x400000, 0x100);
        assert_eq!(entry.trace_to_program(0x1000), Some(0x400000));
        assert_eq!(entry.trace_to_program(0x1050), Some(0x400050));
        assert_eq!(entry.trace_to_program(0x2000), None);
    }

    #[test]
    fn test_mapping_program_to_trace() {
        let entry = StaticMappingEntry::new("t", 0x1000, 0x100, "p", 0x400000, 0x100);
        assert_eq!(entry.program_to_trace(0x400000), Some(0x1000));
        assert_eq!(entry.program_to_trace(0x400050), Some(0x1050));
        assert_eq!(entry.program_to_trace(0x500000), None);
    }

    #[test]
    fn test_mapping_overlaps_trace() {
        let a = StaticMappingEntry::new("t", 0x1000, 0x100, "p1", 0, 0x100);
        let b = StaticMappingEntry::new("t", 0x1050, 0x100, "p2", 0, 0x100);
        let c = StaticMappingEntry::new("t", 0x2000, 0x100, "p3", 0, 0x100);
        let d = StaticMappingEntry::new("other", 0x1050, 0x100, "p4", 0, 0x100);

        assert!(a.overlaps_trace(&b));  // overlap at 0x1050-0x1100
        assert!(!a.overlaps_trace(&c)); // no overlap
        assert!(!a.overlaps_trace(&d)); // different trace key
    }

    #[test]
    fn test_static_mapping_service_add() {
        let mut svc = StaticMappingService::new();
        assert!(svc.is_empty());

        svc.add_mapping(StaticMappingEntry::new("t1", 0x1000, 0x100, "p1", 0x400000, 0x100));
        svc.add_mapping(StaticMappingEntry::new("t1", 0x2000, 0x100, "p1", 0x500000, 0x100));
        assert_eq!(svc.len(), 2);
    }

    #[test]
    fn test_static_mapping_service_remove() {
        let mut svc = StaticMappingService::new();
        svc.add_mapping(StaticMappingEntry::new("t1", 0x1000, 0x100, "p1", 0x400000, 0x100));
        let removed = svc.remove_mapping(0);
        assert!(removed.is_some());
        assert!(svc.is_empty());
    }

    #[test]
    fn test_static_mapping_service_for_trace() {
        let mut svc = StaticMappingService::new();
        svc.add_mapping(StaticMappingEntry::new("t1", 0x1000, 0x100, "p1", 0x400000, 0x100));
        svc.add_mapping(StaticMappingEntry::new("t2", 0x1000, 0x100, "p2", 0x500000, 0x100));
        svc.add_mapping(StaticMappingEntry::new("t1", 0x2000, 0x100, "p1", 0x600000, 0x100));

        let t1_mappings = svc.mappings_for_trace("t1");
        assert_eq!(t1_mappings.len(), 2);
    }

    #[test]
    fn test_static_mapping_service_for_program() {
        let mut svc = StaticMappingService::new();
        svc.add_mapping(StaticMappingEntry::new("t1", 0x1000, 0x100, "p1", 0x400000, 0x100));
        svc.add_mapping(StaticMappingEntry::new("t1", 0x2000, 0x100, "p2", 0x500000, 0x100));

        let p1 = svc.mappings_for_program("p1");
        assert_eq!(p1.len(), 1);
    }

    #[test]
    fn test_static_mapping_service_translate() {
        let mut svc = StaticMappingService::new();
        svc.add_mapping(StaticMappingEntry::new("t1", 0x1000, 0x100, "p1", 0x400000, 0x100));

        assert_eq!(
            svc.translate_trace_to_program("t1", 0x1050),
            Some(0x400050)
        );
        assert_eq!(
            svc.translate_program_to_trace("p1", 0x400050),
            Some(0x1050)
        );
        assert_eq!(svc.translate_trace_to_program("t1", 0x9999), None);
    }

    #[test]
    fn test_static_mapping_service_events() {
        let mut svc = StaticMappingService::new();
        svc.add_mapping(StaticMappingEntry::new("t1", 0x1000, 0x100, "p1", 0x400000, 0x100));
        assert_eq!(svc.events().len(), 1);

        svc.remove_mapping(0);
        assert_eq!(svc.events().len(), 2);

        svc.clear_events();
        assert!(svc.events().is_empty());
    }

    #[test]
    fn test_static_mapping_service_find_overlapping() {
        let mut svc = StaticMappingService::new();
        svc.add_mapping(StaticMappingEntry::new("t1", 0x1000, 0x100, "p1", 0, 0x100));
        svc.add_mapping(StaticMappingEntry::new("t1", 0x1050, 0x100, "p2", 0, 0x100));
        svc.add_mapping(StaticMappingEntry::new("t1", 0x2000, 0x100, "p3", 0, 0x100));

        let overlaps = svc.find_overlapping();
        assert_eq!(overlaps.len(), 1);
    }

    #[test]
    fn test_static_mapping_service_serialization() {
        let mut svc = StaticMappingService::new();
        svc.add_mapping(StaticMappingEntry::new("t1", 0x1000, 0x100, "p1", 0x400000, 0x100));
        let json = serde_json::to_string(&svc).unwrap();
        let back: StaticMappingService = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
    }

    #[test]
    fn test_mapping_change_event_serialization() {
        let entry = StaticMappingEntry::new("t1", 0x1000, 0x100, "p1", 0x400000, 0x100);
        let event = MappingChangeEvent::Added(entry);
        let json = serde_json::to_string(&event).unwrap();
        let back: MappingChangeEvent = serde_json::from_str(&json).unwrap();
        match back {
            MappingChangeEvent::Added(e) => assert_eq!(e.trace_start, 0x1000),
            _ => panic!("Expected Added"),
        }
    }
}
