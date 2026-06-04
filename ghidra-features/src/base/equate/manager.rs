//! EquateManager -- core equate table operations.
//!
//! Ported from `ghidra.program.database.symbol.EquateManager` in Ghidra.
//!
//! Provides the high-level logic for creating, renaming, removing, and
//! querying equates (named constants) attached to instruction/data operands.

use super::{EquateReference, EquateValue, Scalar};
use ghidra_core::Address;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// EquateManager
// ---------------------------------------------------------------------------

/// Central manager for equates (named constants) in a program.
///
/// Backed by a `HashMap<String, EquateValue>` keyed by equate name, plus a
/// secondary index from `(Address, op_index, value)` to the equate name for
/// fast operand-level lookups.
#[derive(Debug, Clone, Default)]
pub struct EquateTable {
    /// Primary store: equate name -> equate data.
    equates: HashMap<String, EquateValue>,
    /// Secondary index: (address, op_index, value) -> equate name.
    /// Allows O(1) lookup by location.
    by_location: HashMap<(Address, i32, i64), String>,
}

impl EquateTable {
    /// Create a new empty equate table.
    pub fn new() -> Self {
        Self::default()
    }

    // -------------------------------------------------------------------
    // Creation
    // -------------------------------------------------------------------

    /// Create a new equate. Returns an error if the name already exists.
    pub fn create_equate(
        &mut self,
        name: impl Into<String>,
        value: i64,
    ) -> Result<&EquateValue, String> {
        let n = name.into();
        if self.equates.contains_key(&n) {
            return Err(format!("Duplicate equate name: {}", n));
        }
        self.equates.insert(n.clone(), EquateValue::new(&n, value));
        Ok(self.equates.get(&n).unwrap())
    }

    /// Create a new equate or return a reference to the existing one.
    pub fn get_or_create_equate(
        &mut self,
        name: impl Into<String>,
        value: i64,
    ) -> &EquateValue {
        let n = name.into();
        if !self.equates.contains_key(&n) {
            self.equates.insert(n.clone(), EquateValue::new(&n, value));
        }
        self.equates.get(&n).unwrap()
    }

    // -------------------------------------------------------------------
    // Query
    // -------------------------------------------------------------------

    /// Get an equate by name.
    pub fn get_equate(&self, name: &str) -> Option<&EquateValue> {
        self.equates.get(name)
    }

    /// Get an equate by name (mutable).
    pub fn get_equate_mut(&mut self, name: &str) -> Option<&mut EquateValue> {
        self.equates.get_mut(name)
    }

    /// Get the equate at a specific (address, op_index) with the given value.
    pub fn get_equate_at(
        &self,
        addr: &Address,
        op_index: i32,
        value: i64,
    ) -> Option<&EquateValue> {
        self.by_location
            .get(&(*addr, op_index, value))
            .and_then(|name| self.equates.get(name))
    }

    /// Get all equates at a specific (address, op_index).
    pub fn get_equates_at(&self, addr: &Address, op_index: i32) -> Vec<&EquateValue> {
        self.by_location
            .iter()
            .filter(|((a, o, _), _)| a == addr && *o == op_index)
            .filter_map(|(_, name)| self.equates.get(name))
            .collect()
    }

    /// Get all equate values in the table.
    pub fn get_all_equates(&self) -> Vec<&EquateValue> {
        self.equates.values().collect()
    }

    /// Get all equate values (mutable).
    pub fn get_all_equates_mut(&mut self) -> Vec<&mut EquateValue> {
        self.equates.values_mut().collect()
    }

    /// Total number of equates.
    pub fn num_equates(&self) -> usize {
        self.equates.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.equates.is_empty()
    }

    // -------------------------------------------------------------------
    // Modification
    // -------------------------------------------------------------------

    /// Remove an equate by name. Returns `true` if it existed.
    pub fn remove_equate(&mut self, name: &str) -> bool {
        if let Some(eq) = self.equates.remove(name) {
            // Clean up secondary index.
            for r in &eq.references {
                self.by_location
                    .remove(&(r.address, r.op_index, eq.value));
            }
            true
        } else {
            false
        }
    }

    /// Add a reference to an existing equate. Returns `false` if the equate
    /// does not exist.
    pub fn add_reference(
        &mut self,
        equate_name: &str,
        addr: Address,
        op_index: i32,
    ) -> bool {
        if let Some(eq) = self.equates.get_mut(equate_name) {
            eq.add_reference(addr, op_index);
            self.by_location
                .insert((addr, op_index, eq.value), equate_name.to_string());
            true
        } else {
            false
        }
    }

    /// Remove a reference from an equate. Returns `true` if removed.
    pub fn remove_reference(
        &mut self,
        equate_name: &str,
        addr: &Address,
        op_index: i32,
    ) -> bool {
        if let Some(eq) = self.equates.get_mut(equate_name) {
            let removed = eq.remove_reference(addr, op_index);
            if removed {
                self.by_location
                    .remove(&(*addr, op_index, eq.value));
            }
            removed
        } else {
            false
        }
    }

    /// Rename an equate. All references and the secondary index are moved.
    /// Returns `false` if `old_name` does not exist or `new_name` already exists.
    pub fn rename_equate(&mut self, old_name: &str, new_name: &str) -> bool {
        if old_name == new_name {
            return true;
        }
        if self.equates.contains_key(new_name) {
            return false;
        }
        if let Some(mut eq) = self.equates.remove(old_name) {
            // Update secondary index.
            for r in &eq.references {
                self.by_location
                    .remove(&(r.address, r.op_index, eq.value));
            }
            eq.name = new_name.to_string();
            for r in &eq.references {
                self.by_location
                    .insert((r.address, r.op_index, eq.value), new_name.to_string());
            }
            self.equates.insert(new_name.to_string(), eq);
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// EquateManager -- static formatting utilities
// ---------------------------------------------------------------------------

/// Static helper methods ported from `ghidra.program.database.symbol.EquateManager`.
pub struct EquateManager;

impl EquateManager {
    /// Prefix used by Ghidra to mark enum-based equate names.
    /// The format is `DATATYPE_TAG + UUID + '_' + hex_value`.
    pub const DATATYPE_TAG: &'static str = "dt_";

    /// Format a name for an enum-based equate.
    ///
    /// Mirrors `EquateManager.formatNameForEquate(UniversalID, long)`.
    ///
    /// The resulting name has the form: `dt_<uuid>_<hex_value>`.
    pub fn format_name_for_equate(enum_uuid: &str, value: i64) -> String {
        format!("{}{}_{:x}", Self::DATATYPE_TAG, enum_uuid, value)
    }

    /// Parse the enum UUID and value from an enum-based equate name.
    ///
    /// Returns `None` if the name does not start with the data-type tag.
    pub fn parse_enum_equate_name(name: &str) -> Option<(String, i64)> {
        let rest = name.strip_prefix(Self::DATATYPE_TAG)?;
        let underscore_pos = rest.rfind('_')?;
        let uuid = &rest[..underscore_pos];
        let hex_val = &rest[underscore_pos + 1..];
        let value = i64::from_str_radix(hex_val, 16).ok()?;
        Some((uuid.to_string(), value))
    }

    /// Check whether a name looks like an enum-based equate.
    pub fn is_enum_equate_name(name: &str) -> bool {
        name.starts_with(Self::DATATYPE_TAG)
    }
}

// ---------------------------------------------------------------------------
// EquateTable operations that use Scalar
// ---------------------------------------------------------------------------

impl EquateTable {
    /// Create or look up an equate from a [`Scalar`] value.
    ///
    /// If an equate already exists at `(addr, op_index)` with the same value,
    /// returns it; otherwise creates a new equate with `equate_name` and adds
    /// the reference.
    pub fn set_equate_for_scalar(
        &mut self,
        equate_name: &str,
        addr: Address,
        op_index: i32,
        scalar: &Scalar,
    ) -> Result<(), String> {
        let value = scalar.value();
        // If there is already an equate at this location with the same value, check names.
        if let Some(existing) = self.get_equate_at(&addr, op_index, value) {
            if existing.name == equate_name {
                return Ok(()); // already set
            }
            // Remove the old reference before adding new.
            let old_name = existing.name.clone();
            self.remove_reference(&old_name, &addr, op_index);
        }
        // Ensure equate exists.
        if !self.equates.contains_key(equate_name) {
            self.create_equate(equate_name, value)?;
        }
        self.add_reference(equate_name, addr, op_index);
        Ok(())
    }

    /// Remove the equate at a specific location if its ref count drops to 0.
    pub fn clear_equate_at(
        &mut self,
        equate_name: &str,
        addr: &Address,
        op_index: i32,
    ) -> bool {
        self.remove_reference(equate_name, addr, op_index);
        // If equate has no more references, remove it entirely.
        if let Some(eq) = self.equates.get(equate_name) {
            if eq.reference_count() == 0 {
                self.remove_equate(equate_name);
                return true;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_get() {
        let mut table = EquateTable::new();
        table.create_equate("MY_CONST", 42).unwrap();
        let eq = table.get_equate("MY_CONST").unwrap();
        assert_eq!(eq.value, 42);
        assert_eq!(eq.name, "MY_CONST");
    }

    #[test]
    fn test_duplicate_create_fails() {
        let mut table = EquateTable::new();
        table.create_equate("X", 1).unwrap();
        assert!(table.create_equate("X", 2).is_err());
    }

    #[test]
    fn test_remove_equate() {
        let mut table = EquateTable::new();
        table.create_equate("X", 1).unwrap();
        assert!(table.remove_equate("X"));
        assert!(!table.remove_equate("X"));
        assert!(table.get_equate("X").is_none());
    }

    #[test]
    fn test_add_and_remove_reference() {
        let mut table = EquateTable::new();
        table.create_equate("X", 10).unwrap();
        table.add_reference("X", Address::new(0x1000), 0);
        table.add_reference("X", Address::new(0x2000), 1);
        assert_eq!(table.get_equate("X").unwrap().reference_count(), 2);

        table.remove_reference("X", &Address::new(0x1000), 0);
        assert_eq!(table.get_equate("X").unwrap().reference_count(), 1);
    }

    #[test]
    fn test_get_equate_at_location() {
        let mut table = EquateTable::new();
        table.create_equate("X", 10).unwrap();
        table.add_reference("X", Address::new(0x1000), 0);

        let eq = table.get_equate_at(&Address::new(0x1000), 0, 10);
        assert!(eq.is_some());
        assert_eq!(eq.unwrap().name, "X");

        assert!(table.get_equate_at(&Address::new(0x9999), 0, 10).is_none());
    }

    #[test]
    fn test_rename_equate() {
        let mut table = EquateTable::new();
        table.create_equate("OLD", 5).unwrap();
        table.add_reference("OLD", Address::new(0x1000), 0);

        assert!(table.rename_equate("OLD", "NEW"));
        assert!(table.get_equate("OLD").is_none());
        let eq = table.get_equate("NEW").unwrap();
        assert_eq!(eq.value, 5);
        assert_eq!(eq.reference_count(), 1);

        // Lookup by location still works after rename.
        let eq = table.get_equate_at(&Address::new(0x1000), 0, 5).unwrap();
        assert_eq!(eq.name, "NEW");
    }

    #[test]
    fn test_rename_to_existing_name_fails() {
        let mut table = EquateTable::new();
        table.create_equate("A", 1).unwrap();
        table.create_equate("B", 2).unwrap();
        assert!(!table.rename_equate("A", "B"));
        assert!(table.get_equate("A").is_some());
    }

    #[test]
    fn test_get_or_create() {
        let mut table = EquateTable::new();
        table.get_or_create_equate("X", 10);
        table.get_or_create_equate("X", 20); // should not overwrite
        assert_eq!(table.get_equate("X").unwrap().value, 10);
    }

    #[test]
    fn test_set_equate_for_scalar() {
        let mut table = EquateTable::new();
        let s = Scalar::unsigned(32, 0xFF);
        table
            .set_equate_for_scalar("BYTE_MAX", Address::new(0x4000), 0, &s)
            .unwrap();
        let eq = table.get_equate("BYTE_MAX").unwrap();
        assert_eq!(eq.value, s.value());
        assert_eq!(eq.reference_count(), 1);
    }

    #[test]
    fn test_clear_equate_at_removes_when_no_refs() {
        let mut table = EquateTable::new();
        table.create_equate("X", 1).unwrap();
        table.add_reference("X", Address::new(0x1000), 0);
        table.clear_equate_at("X", &Address::new(0x1000), 0);
        assert!(table.get_equate("X").is_none());
    }

    #[test]
    fn test_format_enum_name() {
        let name = EquateManager::format_name_for_equate("abc-uuid", 255);
        assert_eq!(name, "dt_abc-uuid_ff");
    }

    #[test]
    fn test_parse_enum_name() {
        let (uuid, val) = EquateManager::parse_enum_equate_name("dt_abc-uuid_ff").unwrap();
        assert_eq!(uuid, "abc-uuid");
        assert_eq!(val, 255);
    }

    #[test]
    fn test_is_enum_equate_name() {
        assert!(EquateManager::is_enum_equate_name("dt_uuid_1"));
        assert!(!EquateManager::is_enum_equate_name("MY_CONST"));
    }
}
