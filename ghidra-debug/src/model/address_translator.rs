//! Address translation between trace and program spaces.
//!
//! Ported from Ghidra's `ghidra.debug.api.modules.DebuggerAddressTranslator`
//! and related types. Provides bidirectional translation between trace
//! (dynamic) addresses and program (static) addresses using mapping entries.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::Lifespan;

/// Translates addresses between trace and program address spaces.
///
/// Ported from Ghidra's `DebuggerAddressTranslator`. Uses a set of
/// `TranslationEntry` mappings to convert addresses bidirectionally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressTranslator {
    /// The entries that define the translation.
    entries: Vec<TranslationEntry>,
    /// Index by trace address range for fast lookup.
    trace_index: BTreeMap<u64, usize>,
}

/// A single translation entry mapping a trace range to a program range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationEntry {
    /// The trace address range start.
    pub trace_min: u64,
    /// The trace address range end (inclusive).
    pub trace_max: u64,
    /// The program address range start.
    pub program_min: u64,
    /// The program address range end (inclusive).
    pub program_max: u64,
    /// The lifespan during which this entry is valid.
    pub lifespan: Lifespan,
    /// The address space name (for multi-space translation).
    pub space_name: Option<String>,
}

impl TranslationEntry {
    /// Create a new translation entry.
    pub fn new(
        trace_min: u64,
        trace_max: u64,
        program_min: u64,
        program_max: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            trace_min,
            trace_max,
            program_min,
            program_max,
            lifespan,
            space_name: None,
        }
    }

    /// Set the address space name.
    pub fn with_space(mut self, space: impl Into<String>) -> Self {
        self.space_name = Some(space.into());
        self
    }

    /// The length of this mapping.
    pub fn length(&self) -> u64 {
        self.trace_max - self.trace_min + 1
    }

    /// Translate a trace address to a program address.
    pub fn trace_to_program(&self, addr: u64) -> Option<u64> {
        if addr >= self.trace_min && addr <= self.trace_max {
            let offset = addr - self.trace_min;
            Some(self.program_min + offset)
        } else {
            None
        }
    }

    /// Translate a program address to a trace address.
    pub fn program_to_trace(&self, addr: u64) -> Option<u64> {
        if addr >= self.program_min && addr <= self.program_max {
            let offset = addr - self.program_min;
            Some(self.trace_min + offset)
        } else {
            None
        }
    }

    /// Whether this entry contains the given trace address at the given snap.
    pub fn contains_trace(&self, addr: u64, snap: i64) -> bool {
        addr >= self.trace_min && addr <= self.trace_max && self.lifespan.contains(snap)
    }

    /// Whether this entry overlaps another.
    pub fn overlaps(&self, other: &TranslationEntry) -> bool {
        self.trace_min <= other.trace_max
            && other.trace_min <= self.trace_max
            && self.lifespan.intersects(&other.lifespan)
    }
}

impl AddressTranslator {
    /// Create a new empty translator.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            trace_index: BTreeMap::new(),
        }
    }

    /// Add a translation entry.
    pub fn add_entry(&mut self, entry: TranslationEntry) {
        let idx = self.entries.len();
        self.trace_index.insert(entry.trace_min, idx);
        self.entries.push(entry);
    }

    /// Translate a trace address to a program address.
    pub fn trace_to_program(&self, addr: u64, snap: i64) -> Option<u64> {
        // Find the entry whose trace range contains addr
        for entry in &self.entries {
            if entry.contains_trace(addr, snap) {
                return entry.trace_to_program(addr);
            }
        }
        None
    }

    /// Translate a program address to a trace address.
    pub fn program_to_trace(&self, addr: u64, snap: i64) -> Option<u64> {
        for entry in &self.entries {
            if entry.lifespan.contains(snap) {
                if let Some(trace_addr) = entry.program_to_trace(addr) {
                    return Some(trace_addr);
                }
            }
        }
        None
    }

    /// Translate a trace address range to a program address range.
    pub fn translate_range(
        &self,
        trace_min: u64,
        trace_max: u64,
        snap: i64,
    ) -> Option<(u64, u64)> {
        let prog_min = self.trace_to_program(trace_min, snap)?;
        let prog_max = self.trace_to_program(trace_max, snap)?;
        Some((prog_min, prog_max))
    }

    /// Get all entries.
    pub fn entries(&self) -> &[TranslationEntry] {
        &self.entries
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the translator has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove entries that overlap with the given entry.
    pub fn remove_overlapping(&mut self, entry: &TranslationEntry) {
        self.entries.retain(|e| !e.overlaps(entry));
        self.rebuild_index();
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.trace_index.clear();
    }

    fn rebuild_index(&mut self) {
        self.trace_index.clear();
        for (idx, entry) in self.entries.iter().enumerate() {
            self.trace_index.insert(entry.trace_min, idx);
        }
    }

    /// Check if any entry contains the given trace address.
    pub fn has_mapping(&self, addr: u64, snap: i64) -> bool {
        self.trace_to_program(addr, snap).is_some()
    }
}

impl Default for AddressTranslator {
    fn default() -> Self {
        Self::new()
    }
}

/// Translated address result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranslatedAddress {
    /// The original (source) address.
    pub source: u64,
    /// The translated (destination) address.
    pub destination: u64,
    /// The snap at which the translation is valid.
    pub snap: i64,
    /// The length of the mapped region containing this address.
    pub region_length: u64,
}

impl TranslatedAddress {
    /// Create a new translated address.
    pub fn new(source: u64, destination: u64, snap: i64, region_length: u64) -> Self {
        Self {
            source,
            destination,
            snap,
            region_length,
        }
    }
}

/// A change event for address mapping changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingChangeEvent {
    /// The kind of change.
    pub kind: MappingChangeKind,
    /// The affected trace address range start.
    pub trace_min: u64,
    /// The affected trace address range end.
    pub trace_max: u64,
    /// The snap range affected.
    pub snap_min: i64,
    pub snap_max: i64,
}

/// The kind of mapping change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MappingChangeKind {
    /// A new mapping was added.
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
    fn test_translation_entry() {
        let entry = TranslationEntry::new(0x400000, 0x400fff, 0x1000, 0x1fff, Lifespan::ALL);
        assert_eq!(entry.length(), 0x1000);
        assert_eq!(entry.trace_to_program(0x400100), Some(0x1100));
        assert_eq!(entry.program_to_trace(0x1100), Some(0x400100));
        assert_eq!(entry.trace_to_program(0x500000), None);
    }

    #[test]
    fn test_translation_entry_with_space() {
        let entry = TranslationEntry::new(0, 0xff, 0x100, 0x1ff, Lifespan::ALL)
            .with_space("ram");
        assert_eq!(entry.space_name.as_deref(), Some("ram"));
    }

    #[test]
    fn test_address_translator_basic() {
        let mut translator = AddressTranslator::new();
        assert!(translator.is_empty());

        translator.add_entry(TranslationEntry::new(
            0x400000, 0x400fff, 0x1000, 0x1fff, Lifespan::ALL,
        ));
        assert_eq!(translator.len(), 1);
        assert!(!translator.is_empty());

        assert_eq!(translator.trace_to_program(0x400500, 0), Some(0x1500));
        assert_eq!(translator.program_to_trace(0x1500, 0), Some(0x400500));
    }

    #[test]
    fn test_address_translator_no_mapping() {
        let mut translator = AddressTranslator::new();
        translator.add_entry(TranslationEntry::new(
            0x400000, 0x400fff, 0x1000, 0x1fff, Lifespan::ALL,
        ));
        assert_eq!(translator.trace_to_program(0x500000, 0), None);
        assert!(!translator.has_mapping(0x500000, 0));
    }

    #[test]
    fn test_address_translator_range() {
        let mut translator = AddressTranslator::new();
        translator.add_entry(TranslationEntry::new(
            0x400000, 0x400fff, 0x1000, 0x1fff, Lifespan::ALL,
        ));
        let range = translator.translate_range(0x400000, 0x4000ff, 0);
        assert_eq!(range, Some((0x1000, 0x10ff)));
    }

    #[test]
    fn test_address_translator_multiple_entries() {
        let mut translator = AddressTranslator::new();
        translator.add_entry(TranslationEntry::new(
            0x400000, 0x400fff, 0x1000, 0x1fff, Lifespan::ALL,
        ));
        translator.add_entry(TranslationEntry::new(
            0x7f000000, 0x7f000fff, 0x2000, 0x2fff, Lifespan::ALL,
        ));
        assert_eq!(translator.len(), 2);
        assert_eq!(translator.trace_to_program(0x400500, 0), Some(0x1500));
        assert_eq!(translator.trace_to_program(0x7f000500, 0), Some(0x2500));
    }

    #[test]
    fn test_address_translator_lifespan() {
        let mut translator = AddressTranslator::new();
        translator.add_entry(TranslationEntry::new(
            0x400000,
            0x400fff,
            0x1000,
            0x1fff,
            Lifespan::span(5, 10),
        ));
        assert_eq!(translator.trace_to_program(0x400500, 7), Some(0x1500));
        assert_eq!(translator.trace_to_program(0x400500, 3), None);
        assert_eq!(translator.trace_to_program(0x400500, 15), None);
    }

    #[test]
    fn test_address_translator_remove_overlapping() {
        let mut translator = AddressTranslator::new();
        translator.add_entry(TranslationEntry::new(
            0x400000, 0x400fff, 0x1000, 0x1fff, Lifespan::ALL,
        ));
        translator.add_entry(TranslationEntry::new(
            0x500000, 0x500fff, 0x3000, 0x3fff, Lifespan::ALL,
        ));
        assert_eq!(translator.len(), 2);

        let new_entry = TranslationEntry::new(
            0x400800, 0x500200, 0x4000, 0x4a00, Lifespan::ALL,
        );
        translator.remove_overlapping(&new_entry);
        assert!(translator.is_empty());
    }

    #[test]
    fn test_address_translator_clear() {
        let mut translator = AddressTranslator::new();
        translator.add_entry(TranslationEntry::new(
            0x400000, 0x400fff, 0x1000, 0x1fff, Lifespan::ALL,
        ));
        translator.clear();
        assert!(translator.is_empty());
    }

    #[test]
    fn test_entry_overlap() {
        let a = TranslationEntry::new(0x100, 0x200, 0, 0, Lifespan::ALL);
        let b = TranslationEntry::new(0x150, 0x250, 0, 0, Lifespan::ALL);
        let c = TranslationEntry::new(0x300, 0x400, 0, 0, Lifespan::ALL);
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn test_translated_address() {
        let ta = TranslatedAddress::new(0x400500, 0x1500, 0, 0x1000);
        assert_eq!(ta.source, 0x400500);
        assert_eq!(ta.destination, 0x1500);
    }

    #[test]
    fn test_mapping_change_event() {
        let event = MappingChangeEvent {
            kind: MappingChangeKind::Added,
            trace_min: 0x400000,
            trace_max: 0x400fff,
            snap_min: 0,
            snap_max: 10,
        };
        assert_eq!(event.kind, MappingChangeKind::Added);
    }

    #[test]
    fn test_address_translator_has_mapping() {
        let mut translator = AddressTranslator::new();
        translator.add_entry(TranslationEntry::new(
            0x400000, 0x400fff, 0x1000, 0x1fff, Lifespan::ALL,
        ));
        assert!(translator.has_mapping(0x400500, 0));
        assert!(!translator.has_mapping(0x500000, 0));
    }

    #[test]
    fn test_translator_default() {
        let translator = AddressTranslator::default();
        assert!(translator.is_empty());
    }

    #[test]
    fn test_entry_contains_trace() {
        let entry = TranslationEntry::new(0x100, 0x200, 0, 0, Lifespan::span(5, 10));
        assert!(entry.contains_trace(0x150, 7));
        assert!(!entry.contains_trace(0x150, 3));
        assert!(!entry.contains_trace(0x300, 7));
    }
}
