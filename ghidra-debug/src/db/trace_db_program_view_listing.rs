//! Program view listing implementation for the trace database.
//!
//! Ported from Ghidra's `DBTraceProgramViewListing` and
//! `AbstractDBTraceProgramViewListing` in
//! `ghidra.trace.database.program`. Provides the Listing interface
//! over a trace at a specific snap.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A listing entry visible through a program view.
///
/// Represents a code unit (instruction or data) as seen through the
/// program view's snap-filtered lens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewListingEntry {
    /// The address offset.
    pub address_offset: u64,
    /// The address space.
    pub address_space: String,
    /// The code unit type.
    pub unit_type: ProgramViewCodeUnitType,
    /// The mnemonic or label.
    pub mnemonic: String,
    /// The raw bytes.
    pub bytes: Vec<u8>,
    /// The length in bytes.
    pub length: u32,
    /// The snap at which this entry is visible.
    pub snap: i64,
}

/// Code unit types visible in a program view listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProgramViewCodeUnitType {
    /// An undefined byte.
    Undefined,
    /// An instruction.
    Instruction,
    /// A defined data unit.
    Data,
}

impl ProgramViewCodeUnitType {
    /// Get the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            ProgramViewCodeUnitType::Undefined => "undefined",
            ProgramViewCodeUnitType::Instruction => "instruction",
            ProgramViewCodeUnitType::Data => "data",
        }
    }
}

/// The program view listing manager.
///
/// Ported from Ghidra's `DBTraceProgramViewListing`. Provides a
/// read-only view of code units filtered by the view's snap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceProgramViewListing {
    /// The program view ID.
    pub view_id: i64,
    /// The snap this listing is filtered to.
    pub snap: i64,
    /// Cached listing entries.
    entries: Vec<ProgramViewListingEntry>,
}

impl DbTraceProgramViewListing {
    /// Create a new program view listing.
    pub fn new(view_id: i64, snap: i64) -> Self {
        Self {
            view_id,
            snap,
            entries: Vec::new(),
        }
    }

    /// Set the snap for this listing.
    pub fn set_snap(&mut self, snap: i64) {
        self.snap = snap;
    }

    /// Add an entry to the listing.
    pub fn add_entry(&mut self, entry: ProgramViewListingEntry) {
        self.entries.push(entry);
    }

    /// Get the entry at the given address offset.
    pub fn get_at(&self, address_offset: u64) -> Option<&ProgramViewListingEntry> {
        self.entries.iter().find(|e| e.address_offset == address_offset)
    }

    /// Get all entries in the listing.
    pub fn entries(&self) -> &[ProgramViewListingEntry] {
        &self.entries
    }

    /// Get the number of entries.
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Get entries in an address range.
    pub fn get_in_range(&self, min_offset: u64, max_offset: u64) -> Vec<&ProgramViewListingEntry> {
        self.entries
            .iter()
            .filter(|e| e.address_offset >= min_offset && e.address_offset <= max_offset)
            .collect()
    }

    /// Clear cached entries.
    pub fn invalidate_cache(&mut self) {
        self.entries.clear();
    }
}

/// A program view equate table entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewEquate {
    /// The equate name (e.g., "MY_CONSTANT").
    pub name: String,
    /// The equate value.
    pub value: i64,
    /// The address where this equate is referenced.
    pub address_offset: u64,
    /// The operand index.
    pub operand_index: i32,
    /// The snap range.
    pub min_snap: i64,
    pub max_snap: i64,
}

/// A program view equate table manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewEquateTable {
    /// Equate entries.
    equates: Vec<ProgramViewEquate>,
}

impl ProgramViewEquateTable {
    /// Create a new equate table.
    pub fn new() -> Self {
        Self {
            equates: Vec::new(),
        }
    }

    /// Add an equate.
    pub fn add_equate(&mut self, equate: ProgramViewEquate) {
        self.equates.push(equate);
    }

    /// Get equates at an address.
    pub fn get_at(&self, offset: u64, snap: i64) -> Vec<&ProgramViewEquate> {
        self.equates
            .iter()
            .filter(|e| {
                e.address_offset == offset && snap >= e.min_snap && snap <= e.max_snap
            })
            .collect()
    }

    /// Get an equate by name.
    pub fn get_by_name(&self, name: &str) -> Option<&ProgramViewEquate> {
        self.equates.iter().find(|e| e.name == name)
    }

    /// Total number of equates.
    pub fn count(&self) -> usize {
        self.equates.len()
    }
}

impl Default for ProgramViewEquateTable {
    fn default() -> Self {
        Self::new()
    }
}

/// A program view fragment (group of code units).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewFragment {
    /// Fragment name.
    pub name: String,
    /// Address ranges in this fragment (min, max pairs).
    pub ranges: Vec<(u64, u64)>,
    /// Parent tree node ID.
    pub parent_id: i64,
}

impl ProgramViewFragment {
    /// Create a new fragment.
    pub fn new(name: impl Into<String>, parent_id: i64) -> Self {
        Self {
            name: name.into(),
            ranges: Vec::new(),
            parent_id,
        }
    }

    /// Add an address range to this fragment.
    pub fn add_range(&mut self, min: u64, max: u64) {
        self.ranges.push((min, max));
    }

    /// Whether this fragment contains the given address.
    pub fn contains(&self, offset: u64) -> bool {
        self.ranges.iter().any(|(min, max)| offset >= *min && offset <= *max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_listing_entry() {
        let entry = ProgramViewListingEntry {
            address_offset: 0x1000,
            address_space: "ram".to_string(),
            unit_type: ProgramViewCodeUnitType::Instruction,
            mnemonic: "MOV".to_string(),
            bytes: vec![0x48, 0x89, 0xE5],
            length: 3,
            snap: 0,
        };
        assert_eq!(entry.unit_type, ProgramViewCodeUnitType::Instruction);
    }

    #[test]
    fn test_program_view_listing() {
        let mut listing = DbTraceProgramViewListing::new(1, 0);
        assert_eq!(listing.count(), 0);
        listing.add_entry(ProgramViewListingEntry {
            address_offset: 0x1000,
            address_space: "ram".to_string(),
            unit_type: ProgramViewCodeUnitType::Instruction,
            mnemonic: "NOP".to_string(),
            bytes: vec![0x90],
            length: 1,
            snap: 0,
        });
        assert_eq!(listing.count(), 1);
        let entry = listing.get_at(0x1000);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().mnemonic, "NOP");
    }

    #[test]
    fn test_listing_range_query() {
        let mut listing = DbTraceProgramViewListing::new(1, 0);
        for i in 0..10u64 {
            listing.add_entry(ProgramViewListingEntry {
                address_offset: 0x1000 + i * 4,
                address_space: "ram".to_string(),
                unit_type: ProgramViewCodeUnitType::Instruction,
                mnemonic: format!("INST_{}", i),
                bytes: vec![0x90],
                length: 1,
                snap: 0,
            });
        }
        let in_range = listing.get_in_range(0x1004, 0x1010);
        assert_eq!(in_range.len(), 4);
    }

    #[test]
    fn test_equate_table() {
        let mut table = ProgramViewEquateTable::new();
        table.add_equate(ProgramViewEquate {
            name: "MY_CONST".to_string(),
            value: 42,
            address_offset: 0x1000,
            operand_index: 1,
            min_snap: 0,
            max_snap: 100,
        });
        let eq = table.get_by_name("MY_CONST");
        assert!(eq.is_some());
        assert_eq!(eq.unwrap().value, 42);
        let at = table.get_at(0x1000, 50);
        assert_eq!(at.len(), 1);
    }

    #[test]
    fn test_fragment() {
        let mut frag = ProgramViewFragment::new("main", 0);
        frag.add_range(0x1000, 0x1FFF);
        frag.add_range(0x3000, 0x3FFF);
        assert!(frag.contains(0x1500));
        assert!(frag.contains(0x3500));
        assert!(!frag.contains(0x2500));
    }
}
