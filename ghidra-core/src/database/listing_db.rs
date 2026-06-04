//! Database listing implementation ported from Java's `ListingDB`.
//!
//! Provides the `ListingDB` struct that manages instruction and data code
//! units, delegates to sub-managers for specific operations, and exposes
//! the `Listing` interface to the rest of the program.

use crate::addr::{Address, AddressRange, AddressSet};
use crate::database::db::DbResult;
use crate::database::manager_db::{ManagerDB, OpenMode, ProgramContext};
use std::collections::BTreeMap;
use std::fmt;

// ============================================================================
// CodeUnitKind (port of Java CodeUnit types)
// ============================================================================

/// The kind of code unit stored at an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodeUnitKind {
    /// An instruction (disassembled machine code).
    Instruction,
    /// A data element (defined by a data type).
    Data,
    /// Undefined bytes.
    Undefined,
}

// ============================================================================
// ListingCodeUnit (port of Java CodeUnit)
// ============================================================================

/// A minimal code unit stored in the listing.
///
/// Full port of Java `CodeUnit` would include operand references, comments,
/// etc.  This is the database-level representation.
#[derive(Debug, Clone)]
pub struct ListingCodeUnit {
    /// Start address offset.
    pub address: u64,
    /// Length in bytes.
    pub length: u32,
    /// Kind of code unit.
    pub kind: CodeUnitKind,
    /// Human-readable mnemonic (instruction mnemonic or data type name).
    pub mnemonic: String,
    /// Comment text (may be empty).
    pub comment: String,
}

impl ListingCodeUnit {
    /// Create a new code unit.
    pub fn new(address: u64, length: u32, kind: CodeUnitKind, mnemonic: &str) -> Self {
        Self {
            address,
            length,
            kind,
            mnemonic: mnemonic.to_string(),
            comment: String::new(),
        }
    }

    /// End address offset (exclusive).
    pub fn end_address(&self) -> u64 {
        self.address + self.length as u64
    }

    /// Return true if this code unit contains the given offset.
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.address && offset < self.end_address()
    }
}

// ============================================================================
// ListingDB (port of Java ListingDB)
// ============================================================================

/// Database-backed implementation of a program listing.
///
/// Port of Java `ghidra.program.database.ListingDB`.  Stores code units
/// in a BTreeMap keyed by address offset for efficient range queries.
#[derive(Debug)]
pub struct ListingDB {
    /// Code units stored by address offset.
    code_units: BTreeMap<u64, ListingCodeUnit>,
    /// Whether the listing has been modified since last flush.
    dirty: bool,
}

impl ListingDB {
    /// Create a new empty listing.
    pub fn new() -> Self {
        Self {
            code_units: BTreeMap::new(),
            dirty: false,
        }
    }

    // ---- Code unit queries (port of ListingDB methods) ----

    /// Get the code unit at the given address.
    ///
    /// Port of Java `ListingDB.getCodeUnitAt(Address)`.
    pub fn get_code_unit_at(&self, addr: &Address) -> Option<&ListingCodeUnit> {
        self.code_units.get(&addr.offset)
    }

    /// Get the instruction at the given address.
    ///
    /// Port of Java `ListingDB.getInstructionAt(Address)`.
    pub fn get_instruction_at(&self, addr: &Address) -> Option<&ListingCodeUnit> {
        self.code_units.get(&addr.offset).filter(|cu| {
            cu.kind == CodeUnitKind::Instruction
        })
    }

    /// Get the data element at the given address.
    ///
    /// Port of Java `ListingDB.getDataAt(Address)`.
    pub fn get_data_at(&self, addr: &Address) -> Option<&ListingCodeUnit> {
        self.code_units.get(&addr.offset).filter(|cu| cu.kind == CodeUnitKind::Data)
    }

    /// Get the code unit that contains the given address.
    ///
    /// Port of Java `ListingDB.getCodeUnitContaining(Address)`.
    pub fn get_code_unit_containing(&self, addr: &Address) -> Option<&ListingCodeUnit> {
        let offset = addr.offset;
        // Find the entry with the largest key <= offset.
        self.code_units
            .range(..=offset)
            .next_back()
            .map(|(_, cu)| cu)
            .filter(|cu| cu.contains(offset))
    }

    // ---- Code unit mutation ----

    /// Insert or replace a code unit.
    pub fn put_code_unit(&mut self, cu: ListingCodeUnit) {
        self.code_units.insert(cu.address, cu);
        self.dirty = true;
    }

    /// Remove the code unit at the given address.
    pub fn remove_code_unit(&mut self, addr: &Address) -> Option<ListingCodeUnit> {
        let result = self.code_units.remove(&addr.offset);
        if result.is_some() {
            self.dirty = true;
        }
        result
    }

    /// Remove all code units.
    pub fn clear(&mut self) {
        self.code_units.clear();
        self.dirty = true;
    }

    /// Return the number of code units.
    pub fn len(&self) -> usize {
        self.code_units.len()
    }

    /// Return true if the listing has no code units.
    pub fn is_empty(&self) -> bool {
        self.code_units.is_empty()
    }

    /// Return true if modified since creation or last `mark_clean`.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark the listing as clean.
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    // ---- Iteration (port of Listing iterator methods) ----

    /// Iterate over all code units in address order.
    pub fn iter_code_units(&self) -> impl Iterator<Item = &ListingCodeUnit> {
        self.code_units.values()
    }

    /// Iterate over all instructions in address order.
    pub fn iter_instructions(&self) -> impl Iterator<Item = &ListingCodeUnit> {
        self.code_units.values().filter(|cu| cu.kind == CodeUnitKind::Instruction)
    }

    /// Iterate over all data elements in address order.
    pub fn iter_data(&self) -> impl Iterator<Item = &ListingCodeUnit> {
        self.code_units.values().filter(|cu| cu.kind == CodeUnitKind::Data)
    }

    /// Iterate over code units in the given address range.
    pub fn iter_range(&self, min: u64, max: u64) -> impl Iterator<Item = &ListingCodeUnit> {
        self.code_units
            .range(min..=max)
            .map(|(_, cu)| cu)
            .filter(move |cu| cu.address >= min && cu.address <= max)
    }

    /// Count instructions in the given address range.
    pub fn count_instructions_in_range(&self, min: u64, max: u64) -> usize {
        self.iter_range(min, max)
            .filter(|cu| cu.kind == CodeUnitKind::Instruction)
            .count()
    }

    /// Get the defined code unit address set.
    pub fn get_address_set(&self) -> AddressSet {
        let mut set = AddressSet::new();
        for cu in self.code_units.values() {
            set.add_range(Address::new(cu.address), Address::new(cu.end_address() - 1));
        }
        set
    }

    /// Get the instruction address set.
    pub fn get_instruction_address_set(&self) -> AddressSet {
        let mut set = AddressSet::new();
        for cu in self.code_units.values() {
            if cu.kind == CodeUnitKind::Instruction {
                set.add_range(Address::new(cu.address), Address::new(cu.end_address() - 1));
            }
        }
        set
    }
}

impl Default for ListingDB {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ListingDB {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ListingDB(units={}, dirty={})",
            self.code_units.len(),
            self.dirty
        )
    }
}

// ============================================================================
// ListingManager (implements ManagerDB for the listing)
// ============================================================================

/// The listing's ManagerDB implementation.
///
/// Bridges the `ListingDB` storage to the manager lifecycle.
#[derive(Debug)]
pub struct ListingManager {
    listing: ListingDB,
    initialized: bool,
}

impl ListingManager {
    /// Create a new listing manager.
    pub fn new() -> Self {
        Self {
            listing: ListingDB::new(),
            initialized: false,
        }
    }

    /// Get a reference to the underlying listing.
    pub fn listing(&self) -> &ListingDB {
        &self.listing
    }

    /// Get a mutable reference to the underlying listing.
    pub fn listing_mut(&mut self) -> &mut ListingDB {
        &mut self.listing
    }

    /// Return true if the manager has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for ListingManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ManagerDB for ListingManager {
    fn set_program(&mut self, _ctx: &ProgramContext) {
        self.initialized = true;
    }

    fn clear_cache(&mut self, _all: bool) {
        // Listing does not have a separate cache; code units are the data.
    }

    fn delete_address_range(&mut self, start: &Address, end: &Address) -> DbResult<()> {
        let min = start.get_offset();
        let max = end.get_offset();
        let keys_to_remove: Vec<u64> = self
            .listing
            .code_units
            .range(min..=max)
            .map(|(&k, _)| k)
            .collect();
        for k in keys_to_remove {
            self.listing.code_units.remove(&k);
        }
        self.listing.dirty = true;
        Ok(())
    }

    fn move_address_range(&mut self, from_addr: &Address, to_addr: &Address, length: u64) -> DbResult<()> {
        let from = from_addr.offset;
        let to = to_addr.offset;
        let from_end = from + length - 1;

        let entries: Vec<(u64, ListingCodeUnit)> = self
            .listing
            .code_units
            .range(from..=from_end)
            .map(|(&k, v)| (k, v.clone()))
            .collect();

        for (key, mut cu) in entries {
            let delta = key - from;
            let new_addr = to + delta;
            self.listing.code_units.remove(&key);
            cu.address = new_addr;
            self.listing.code_units.insert(new_addr, cu);
        }
        self.listing.dirty = true;
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_listing_put_and_get() {
        let mut listing = ListingDB::new();
        listing.put_code_unit(ListingCodeUnit::new(0x1000, 4, CodeUnitKind::Instruction, "MOV"));
        listing.put_code_unit(ListingCodeUnit::new(0x1004, 2, CodeUnitKind::Data, "word"));

        let cu = listing.get_code_unit_at(&addr(0x1000)).unwrap();
        assert_eq!(cu.kind, CodeUnitKind::Instruction);
        assert_eq!(cu.mnemonic, "MOV");

        let data = listing.get_data_at(&addr(0x1004)).unwrap();
        assert_eq!(data.kind, CodeUnitKind::Data);
    }

    #[test]
    fn test_listing_get_instruction_at_filter() {
        let mut listing = ListingDB::new();
        listing.put_code_unit(ListingCodeUnit::new(0x1000, 4, CodeUnitKind::Data, "dword"));

        // get_instruction_at returns None for a data code unit.
        assert!(listing.get_instruction_at(&addr(0x1000)).is_none());
        assert!(listing.get_data_at(&addr(0x1000)).is_some());
    }

    #[test]
    fn test_listing_containing() {
        let mut listing = ListingDB::new();
        listing.put_code_unit(ListingCodeUnit::new(0x1000, 8, CodeUnitKind::Instruction, "NOP"));

        // Address within the code unit.
        let cu = listing.get_code_unit_containing(&addr(0x1004)).unwrap();
        assert_eq!(cu.address, 0x1000);

        // Address before any code unit.
        assert!(listing.get_code_unit_containing(&addr(0x0500)).is_none());
    }

    #[test]
    fn test_listing_remove() {
        let mut listing = ListingDB::new();
        listing.put_code_unit(ListingCodeUnit::new(0x1000, 4, CodeUnitKind::Instruction, "RET"));
        assert_eq!(listing.len(), 1);
        listing.remove_code_unit(&addr(0x1000));
        assert!(listing.is_empty());
    }

    #[test]
    fn test_listing_iter_range() {
        let mut listing = ListingDB::new();
        for i in 0..10u64 {
            listing.put_code_unit(ListingCodeUnit::new(
                0x1000 + i * 4,
                4,
                CodeUnitKind::Instruction,
                "NOP",
            ));
        }
        let in_range: Vec<_> = listing.iter_range(0x1004, 0x1010).collect();
        assert_eq!(in_range.len(), 4); // 0x1004, 0x1008, 0x100c, 0x1010
    }

    #[test]
    fn test_listing_address_sets() {
        let mut listing = ListingDB::new();
        listing.put_code_unit(ListingCodeUnit::new(0x1000, 4, CodeUnitKind::Instruction, "MOV"));
        listing.put_code_unit(ListingCodeUnit::new(0x1004, 2, CodeUnitKind::Data, "byte"));
        listing.put_code_unit(ListingCodeUnit::new(0x1006, 4, CodeUnitKind::Instruction, "ADD"));

        assert_eq!(listing.len(), 3);
        assert_eq!(listing.get_address_set().num_address_ranges(), 3);
        assert_eq!(listing.get_instruction_address_set().num_address_ranges(), 2);
    }

    #[test]
    fn test_listing_manager_lifecycle() {
        let mut mgr = ListingManager::new();
        assert!(!mgr.is_initialized());

        let ctx = ProgramContext::new(1, 0, false);
        mgr.set_program(&ctx);
        assert!(mgr.is_initialized());

        mgr.listing_mut()
            .put_code_unit(ListingCodeUnit::new(0x4000, 4, CodeUnitKind::Instruction, "CALL"));
        assert_eq!(mgr.listing().len(), 1);
    }

    #[test]
    fn test_listing_manager_delete_range() {
        let mut mgr = ListingManager::new();
        mgr.listing_mut()
            .put_code_unit(ListingCodeUnit::new(0x1000, 4, CodeUnitKind::Instruction, "A"));
        mgr.listing_mut()
            .put_code_unit(ListingCodeUnit::new(0x1004, 4, CodeUnitKind::Instruction, "B"));
        mgr.listing_mut()
            .put_code_unit(ListingCodeUnit::new(0x1008, 4, CodeUnitKind::Instruction, "C"));

        mgr.delete_address_range(&addr(0x1000), &addr(0x1004)).unwrap();
        assert_eq!(mgr.listing().len(), 1);
        assert!(mgr.listing().get_code_unit_at(&addr(0x1008)).is_some());
    }

    #[test]
    fn test_listing_manager_move_range() {
        let mut mgr = ListingManager::new();
        mgr.listing_mut()
            .put_code_unit(ListingCodeUnit::new(0x1000, 4, CodeUnitKind::Instruction, "X"));
        mgr.listing_mut()
            .put_code_unit(ListingCodeUnit::new(0x1004, 4, CodeUnitKind::Instruction, "Y"));

        mgr.move_address_range(&addr(0x1000), &addr(0x2000), 8).unwrap();

        assert!(mgr.listing().get_code_unit_at(&addr(0x1000)).is_none());
        let x = mgr.listing().get_code_unit_at(&addr(0x2000)).unwrap();
        assert_eq!(x.mnemonic, "X");
        let y = mgr.listing().get_code_unit_at(&addr(0x2004)).unwrap();
        assert_eq!(y.mnemonic, "Y");
    }

    #[test]
    fn test_count_instructions() {
        let mut listing = ListingDB::new();
        listing.put_code_unit(ListingCodeUnit::new(0x1000, 4, CodeUnitKind::Instruction, "A"));
        listing.put_code_unit(ListingCodeUnit::new(0x1004, 2, CodeUnitKind::Data, "B"));
        listing.put_code_unit(ListingCodeUnit::new(0x1006, 4, CodeUnitKind::Instruction, "C"));

        assert_eq!(listing.count_instructions_in_range(0x1000, 0x1009), 2);
    }
}
