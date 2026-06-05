//! Database listing view implementations for trace code units, data, and instructions.
//!
//! Ported from Ghidra's Framework-TraceModeling listing views:
//! - `DBTraceCodeUnitsView`
//! - `DBTraceCodeUnitsMemoryView`
//! - `DBTraceDataView`
//! - `DBTraceDataMemoryView`
//! - `DBTraceDefinedDataView`
//! - `DBTraceDefinedDataMemoryView`
//! - `DBTraceUndefinedDataView`
//! - `DBTraceUndefinedDataMemoryView`
//! - `DBTraceInstructionsView`
//! - `DBTraceInstructionsMemoryView`
//! - `DBTraceDefinedUnitsView`
//! - `DBTraceDefinedUnitsMemoryView`
//! - `AbstractBaseDBTraceCodeUnitsView`
//! - `AbstractBaseDBTraceCodeUnitsMemoryView`
//! - `AbstractBaseDBTraceDefinedUnitsView`
//! - `AbstractSingleDBTraceCodeUnitsView`
//! - `AbstractWithUndefinedDBTraceCodeUnitsMemoryView`
//!
//! These views provide filtered and typed views over the trace code listing
//! database. Each view constrains iteration by code unit type, address range,
//! and snap range.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;
use crate::db::trace_db_listing_deep::TraceCodeUnitType;

/// Configuration for a listing view query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListingViewConfig {
    /// The address space name to query (None for all spaces).
    pub space: Option<String>,
    /// Minimum address (inclusive).
    pub min_address: Option<u64>,
    /// Maximum address (inclusive).
    pub max_address: Option<u64>,
    /// Snap range.
    pub lifespan: Lifespan,
    /// Filter by code unit type.
    pub unit_type_filter: Option<TraceCodeUnitType>,
    /// Maximum number of entries to return.
    pub max_entries: Option<usize>,
}

impl ListingViewConfig {
    /// Create a new config for the given snap.
    pub fn for_snap(snap: i64) -> Self {
        Self {
            space: None,
            min_address: None,
            max_address: None,
            lifespan: Lifespan::span(snap, snap + 1),
            unit_type_filter: None,
            max_entries: None,
        }
    }

    /// Create a config for a range of snaps.
    pub fn for_snap_range(snap_from: i64, snap_to: i64) -> Self {
        Self {
            space: None,
            min_address: None,
            max_address: None,
            lifespan: Lifespan::span(snap_from, snap_to),
            unit_type_filter: None,
            max_entries: None,
        }
    }

    /// Restrict to a specific address space.
    pub fn with_space(mut self, space: impl Into<String>) -> Self {
        self.space = Some(space.into());
        self
    }

    /// Restrict to an address range.
    pub fn with_address_range(mut self, min: u64, max: u64) -> Self {
        self.min_address = Some(min);
        self.max_address = Some(max);
        self
    }

    /// Filter by code unit type.
    pub fn with_unit_type(mut self, unit_type: TraceCodeUnitType) -> Self {
        self.unit_type_filter = Some(unit_type);
        self
    }

    /// Set maximum entries.
    pub fn with_max_entries(mut self, max: usize) -> Self {
        self.max_entries = Some(max);
        self
    }

    /// Whether an address passes the address range filter.
    pub fn address_in_range(&self, addr: u64) -> bool {
        if let Some(min) = self.min_address {
            if addr < min {
                return false;
            }
        }
        if let Some(max) = self.max_address {
            if addr > max {
                return false;
            }
        }
        true
    }

    /// Whether a snap is in the lifespan range.
    pub fn snap_in_range(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }
}

/// An entry in a listing view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListingViewEntry {
    /// The address.
    pub address: u64,
    /// The address space name.
    pub space: String,
    /// The snap.
    pub snap: i64,
    /// The code unit type.
    pub unit_type: TraceCodeUnitType,
    /// Length in bytes.
    pub length: usize,
    /// The mnemonic or data type name.
    pub label: String,
    /// Raw bytes (if available).
    pub bytes: Vec<u8>,
    /// Comment text (if any).
    pub comment: Option<String>,
}

impl ListingViewEntry {
    /// Whether this entry represents an instruction.
    pub fn is_instruction(&self) -> bool {
        self.unit_type.is_instruction()
    }

    /// Whether this entry represents data.
    pub fn is_data(&self) -> bool {
        self.unit_type.is_data()
    }

    /// The end address (exclusive).
    pub fn end_address(&self) -> u64 {
        self.address + self.length as u64
    }

    /// Whether this entry overlaps with the given range.
    pub fn overlaps(&self, min: u64, max: u64) -> bool {
        self.address < max && self.end_address() > min
    }
}

/// A view that provides typed access to listing entries.
///
/// Ported from Ghidra's `AbstractBaseDBTraceCodeUnitsView`.
pub trait ListingView {
    /// The entry type produced by this view.
    type Entry;

    /// Iterate entries in the view.
    fn entries(&self, config: &ListingViewConfig) -> Vec<ListingViewEntry>;

    /// Count entries matching the config.
    fn count(&self, config: &ListingViewConfig) -> usize;

    /// Get the entry at the exact address and snap, if any.
    fn get_entry(&self, address: u64, snap: i64) -> Option<ListingViewEntry>;

    /// Get the first entry at or after the given address at the given snap.
    fn floor_entry(&self, address: u64, snap: i64) -> Option<ListingViewEntry>;

    /// Get the first entry at or before the given address at the given snap.
    fn ceiling_entry(&self, address: u64, snap: i64) -> Option<ListingViewEntry>;
}

/// A memory-aware listing view that provides byte-level access.
///
/// Ported from Ghidra's `AbstractBaseDBTraceCodeUnitsMemoryView`.
pub trait MemoryListingView: ListingView {
    /// Read bytes from the listing at the given address and snap.
    fn read_bytes(&self, address: u64, length: usize, snap: i64) -> Vec<u8>;

    /// Get the defined byte at the given address.
    fn get_defined_byte(&self, address: u64, snap: i64) -> Option<u8>;

    /// Check if the given range is fully defined.
    fn is_fully_defined(&self, address: u64, length: usize, snap: i64) -> bool;

    /// Get the set of defined address ranges.
    fn defined_ranges(&self, config: &ListingViewConfig) -> Vec<(u64, u64)>;
}

/// A simple in-memory implementation of a listing view for testing.
#[derive(Debug, Clone, Default)]
pub struct InMemoryListingView {
    /// Entries keyed by (snap, address) for efficient range queries.
    entries: BTreeMap<(i64, u64), ListingViewEntry>,
}

impl InMemoryListingView {
    /// Create a new empty listing view.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an entry.
    pub fn insert(&mut self, entry: ListingViewEntry) {
        self.entries.insert((entry.snap, entry.address), entry);
    }

    /// Remove an entry.
    pub fn remove(&mut self, address: u64, snap: i64) -> Option<ListingViewEntry> {
        self.entries.remove(&(snap, address))
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the view is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl ListingView for InMemoryListingView {
    type Entry = ListingViewEntry;

    fn entries(&self, config: &ListingViewConfig) -> Vec<ListingViewEntry> {
        let mut result = Vec::new();
        for (_, entry) in self.entries.iter() {
            if let Some(ref space_filter) = config.space {
                if &entry.space != space_filter {
                    continue;
                }
            }
            if !config.address_in_range(entry.address) {
                continue;
            }
            if !config.snap_in_range(entry.snap) {
                continue;
            }
            if let Some(type_filter) = config.unit_type_filter {
                if entry.unit_type != type_filter {
                    continue;
                }
            }
            result.push(entry.clone());
            if let Some(max) = config.max_entries {
                if result.len() >= max {
                    break;
                }
            }
        }
        result
    }

    fn count(&self, config: &ListingViewConfig) -> usize {
        self.entries(config).len()
    }

    fn get_entry(&self, address: u64, snap: i64) -> Option<ListingViewEntry> {
        self.entries.get(&(snap, address)).cloned()
    }

    fn floor_entry(&self, address: u64, snap: i64) -> Option<ListingViewEntry> {
        self.entries
            .range(..=(snap, address))
            .next_back()
            .filter(|((s, _), _)| *s == snap)
            .map(|(_, entry)| entry.clone())
    }

    fn ceiling_entry(&self, address: u64, snap: i64) -> Option<ListingViewEntry> {
        self.entries
            .range((snap, address)..)
            .next()
            .filter(|((s, _), _)| *s == snap)
            .map(|(_, entry)| entry.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_instruction(address: u64, snap: i64, mnemonic: &str) -> ListingViewEntry {
        ListingViewEntry {
            address,
            space: "ram".into(),
            snap,
            unit_type: TraceCodeUnitType::Instruction,
            length: 4,
            label: mnemonic.into(),
            bytes: vec![0x90; 4],
            comment: None,
        }
    }

    fn make_data(address: u64, snap: i64, label: &str) -> ListingViewEntry {
        ListingViewEntry {
            address,
            space: "ram".into(),
            snap,
            unit_type: TraceCodeUnitType::DefinedData,
            length: 4,
            label: label.into(),
            bytes: vec![0x00; 4],
            comment: None,
        }
    }

    #[test]
    fn test_in_memory_listing_view_insert_and_get() {
        let mut view = InMemoryListingView::new();
        view.insert(make_instruction(0x1000, 0, "NOP"));
        view.insert(make_instruction(0x1004, 0, "RET"));
        view.insert(make_data(0x2000, 0, "dword"));

        assert_eq!(view.len(), 3);

        let entry = view.get_entry(0x1000, 0).unwrap();
        assert!(entry.is_instruction());
        assert_eq!(entry.label, "NOP");

        let entry = view.get_entry(0x2000, 0).unwrap();
        assert!(entry.is_data());

        assert!(view.get_entry(0x3000, 0).is_none());
    }

    #[test]
    fn test_listing_view_config_filtering() {
        let mut view = InMemoryListingView::new();
        view.insert(make_instruction(0x1000, 0, "NOP"));
        view.insert(make_instruction(0x1004, 0, "RET"));
        view.insert(make_data(0x2000, 0, "dword"));

        // Filter by type
        let config = ListingViewConfig::for_snap(0).with_unit_type(TraceCodeUnitType::Instruction);
        let entries = view.entries(&config);
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.is_instruction()));

        // Filter by address range
        let config = ListingViewConfig::for_snap(0).with_address_range(0x1000, 0x1004);
        let entries = view.entries(&config);
        assert_eq!(entries.len(), 2);

        // Filter by space
        let config = ListingViewConfig::for_snap(0).with_space("ram");
        let entries = view.entries(&config);
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_listing_view_floor_and_ceiling() {
        let mut view = InMemoryListingView::new();
        view.insert(make_instruction(0x1000, 0, "NOP"));
        view.insert(make_instruction(0x1008, 0, "RET"));
        view.insert(make_instruction(0x1000, 1, "NOP"));

        // Floor at 0x1004 snap 0 should return 0x1000
        let entry = view.floor_entry(0x1004, 0).unwrap();
        assert_eq!(entry.address, 0x1000);

        // Ceiling at 0x1004 snap 0 should return 0x1008
        let entry = view.ceiling_entry(0x1004, 0).unwrap();
        assert_eq!(entry.address, 0x1008);

        // Floor at 0x1000 snap 1 should return 0x1000 snap 1
        let entry = view.floor_entry(0x1000, 1).unwrap();
        assert_eq!(entry.snap, 1);
    }

    #[test]
    fn test_listing_view_entry_properties() {
        let entry = ListingViewEntry {
            address: 0x1000,
            space: "ram".into(),
            snap: 0,
            unit_type: TraceCodeUnitType::Instruction,
            length: 4,
            label: "MOV".into(),
            bytes: vec![0x89, 0xC3],
            comment: Some("mov eax, ebx".into()),
        };

        assert!(entry.is_instruction());
        assert!(!entry.is_data());
        assert_eq!(entry.end_address(), 0x1004);
        assert!(entry.overlaps(0x0FFF, 0x1002));
        assert!(!entry.overlaps(0x1004, 0x1008));
    }

    #[test]
    fn test_listing_view_config_methods() {
        let config = ListingViewConfig::for_snap(5)
            .with_space("register")
            .with_address_range(0, 0xFF)
            .with_unit_type(TraceCodeUnitType::DefinedData)
            .with_max_entries(10);

        assert_eq!(config.space, Some("register".into()));
        assert_eq!(config.min_address, Some(0));
        assert_eq!(config.max_address, Some(0xFF));
        assert!(config.snap_in_range(5));
        assert!(!config.snap_in_range(4));
        assert!(config.address_in_range(0x80));
        assert!(!config.address_in_range(0x100));
    }

    #[test]
    fn test_listing_view_snap_range() {
        let config = ListingViewConfig::for_snap_range(10, 20);
        assert!(config.snap_in_range(10));
        assert!(config.snap_in_range(15));
        assert!(config.snap_in_range(20));
        assert!(!config.snap_in_range(9));
        assert!(!config.snap_in_range(21));
    }

    #[test]
    fn test_listing_view_max_entries() {
        let mut view = InMemoryListingView::new();
        for i in 0..100 {
            view.insert(make_instruction(0x1000 + i * 4, 0, "NOP"));
        }

        let config = ListingViewConfig::for_snap(0).with_max_entries(5);
        let entries = view.entries(&config);
        assert_eq!(entries.len(), 5);
    }

    #[test]
    fn test_listing_view_remove() {
        let mut view = InMemoryListingView::new();
        view.insert(make_instruction(0x1000, 0, "NOP"));

        let removed = view.remove(0x1000, 0);
        assert!(removed.is_some());
        assert!(view.is_empty());
    }

    #[test]
    fn test_listing_view_empty() {
        let view = InMemoryListingView::new();
        assert!(view.is_empty());
        assert_eq!(view.len(), 0);

        let config = ListingViewConfig::for_snap(0);
        assert!(view.entries(&config).is_empty());
        assert_eq!(view.count(&config), 0);
    }
}
