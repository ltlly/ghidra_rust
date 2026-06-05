//! Top-level code unit manager.
//!
//! Ported from Ghidra's `DBTraceCodeManager`.
//!
//! Manages code units across all address spaces and snaps.

use std::collections::HashMap;

use crate::db::listing::code_space::DbTraceCodeSpace;
use crate::db::listing::code_unit::DbTraceData;
use crate::db::listing::instruction::DbTraceInstruction;
use crate::db::listing::undefined::UndefinedDbTraceData;
use crate::db::listing::view_types::*;
use crate::model::Lifespan;

/// Top-level manager for all code units across address spaces and snaps.
///
/// Ported from Ghidra's `DBTraceCodeManager`.
pub struct DbTraceCodeManager {
    /// Per-space code unit storage.
    spaces: HashMap<String, DbTraceCodeSpace>,
}

impl DbTraceCodeManager {
    /// Create a new code manager.
    pub fn new() -> Self {
        Self {
            spaces: HashMap::new(),
        }
    }

    /// Get or create the code space for the given address space name.
    pub fn get_or_create_space(&mut self, space_name: &str) -> &mut DbTraceCodeSpace {
        self.spaces
            .entry(space_name.to_string())
            .or_insert_with(|| DbTraceCodeSpace::new(space_name))
    }

    /// Get a reference to the code space, if it exists.
    pub fn get_space(&self, space_name: &str) -> Option<&DbTraceCodeSpace> {
        self.spaces.get(space_name)
    }

    /// Get a mutable reference to the code space, if it exists.
    pub fn get_space_mut(&mut self, space_name: &str) -> Option<&mut DbTraceCodeSpace> {
        self.spaces.get_mut(space_name)
    }

    /// Add an instruction to the specified address space.
    pub fn add_instruction(
        &mut self,
        space_name: &str,
        snap: i64,
        inst: DbTraceInstruction,
    ) {
        let space = self.get_or_create_space(space_name);
        space.add_instruction(snap, inst);
    }

    /// Add a defined data unit to the specified address space.
    pub fn add_data(&mut self, space_name: &str, snap: i64, data: DbTraceData) {
        let space = self.get_or_create_space(space_name);
        space.add_data(snap, data);
    }

    /// Add an undefined region to the specified address space.
    pub fn add_undefined(
        &mut self,
        space_name: &str,
        snap: i64,
        undef: UndefinedDbTraceData,
    ) {
        let space = self.get_or_create_space(space_name);
        space.add_undefined(snap, undef);
    }

    /// Get the instruction at the given location.
    pub fn get_instruction(
        &self,
        space_name: &str,
        snap: i64,
        offset: u64,
    ) -> Option<&DbTraceInstruction> {
        self.spaces
            .get(space_name)
            .and_then(|s| s.get_instruction(snap, offset))
    }

    /// Get the data at the given location.
    pub fn get_data(
        &self,
        space_name: &str,
        snap: i64,
        offset: u64,
    ) -> Option<&DbTraceData> {
        self.spaces
            .get(space_name)
            .and_then(|s| s.get_data(snap, offset))
    }

    /// Create a code units view for a space at a snap.
    pub fn code_units_view(
        &self,
        space_name: &str,
        snap: i64,
    ) -> Option<CodeUnitsView<'_>> {
        self.spaces
            .get(space_name)
            .map(|s| CodeUnitsView::new(s, snap))
    }

    /// Create a defined units view for a space at a snap.
    pub fn defined_units_view(
        &self,
        space_name: &str,
        snap: i64,
    ) -> Option<DefinedUnitsView<'_>> {
        self.spaces
            .get(space_name)
            .map(|s| DefinedUnitsView::new(s, snap))
    }

    /// Create an instructions view for a space at a snap.
    pub fn instructions_view(
        &self,
        space_name: &str,
        snap: i64,
    ) -> Option<InstructionsView<'_>> {
        self.spaces
            .get(space_name)
            .map(|s| InstructionsView::new(s, snap))
    }

    /// Clear all code units at a given snap across all spaces.
    pub fn clear_snap(&mut self, snap: i64) {
        for space in self.spaces.values_mut() {
            space.clear_snap(snap);
        }
    }

    /// Clear all code units within a lifespan across all spaces.
    pub fn clear_lifespan(&mut self, lifespan: &Lifespan) {
        for space in self.spaces.values_mut() {
            space.clear_lifespan(lifespan);
        }
    }

    /// Get the total number of code units across all spaces.
    pub fn total_count(&self) -> usize {
        self.spaces.values().map(|s| s.total_count()).sum()
    }

    /// Get the number of registered address spaces.
    pub fn space_count(&self) -> usize {
        self.spaces.len()
    }

    /// List all registered space names.
    pub fn space_names(&self) -> Vec<&str> {
        self.spaces.keys().map(|s| s.as_str()).collect()
    }

    /// Remove a space entirely.
    pub fn remove_space(&mut self, space_name: &str) -> Option<DbTraceCodeSpace> {
        self.spaces.remove(space_name)
    }
}

impl Default for DbTraceCodeManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_inst(offset: u64, snap: i64) -> DbTraceInstruction {
        DbTraceInstruction::new(offset, 1, snap, "x86", vec![0x90])
    }

    fn make_data(offset: u64, snap: i64) -> DbTraceData {
        DbTraceData::new(offset, 4, snap, "dword")
    }

    #[test]
    fn test_manager_add_and_get() {
        let mut mgr = DbTraceCodeManager::new();
        mgr.add_instruction("ram", 0, make_inst(0x1000, 0));
        mgr.add_data("ram", 0, make_data(0x2000, 0));

        assert!(mgr.get_instruction("ram", 0, 0x1000).is_some());
        assert!(mgr.get_data("ram", 0, 0x2000).is_some());
        assert_eq!(mgr.total_count(), 2);
    }

    #[test]
    fn test_multiple_spaces() {
        let mut mgr = DbTraceCodeManager::new();
        mgr.add_instruction("ram", 0, make_inst(0x1000, 0));
        mgr.add_instruction("register", 0, make_inst(0, 0));

        assert_eq!(mgr.space_count(), 2);
        assert!(mgr.space_names().contains(&"ram"));
        assert!(mgr.space_names().contains(&"register"));
    }

    #[test]
    fn test_clear_snap() {
        let mut mgr = DbTraceCodeManager::new();
        mgr.add_instruction("ram", 0, make_inst(0x1000, 0));
        mgr.add_instruction("ram", 1, make_inst(0x1000, 1));

        mgr.clear_snap(0);
        assert!(mgr.get_instruction("ram", 0, 0x1000).is_none());
        assert!(mgr.get_instruction("ram", 1, 0x1000).is_some());
    }

    #[test]
    fn test_views() {
        let mut mgr = DbTraceCodeManager::new();
        mgr.add_instruction("ram", 0, make_inst(0x1000, 0));
        mgr.add_data("ram", 0, make_data(0x2000, 0));

        let view = mgr.code_units_view("ram", 0).unwrap();
        assert!(view.has_instruction_at(0x1000));
        assert!(view.has_data_at(0x2000));

        let def_view = mgr.defined_units_view("ram", 0).unwrap();
        assert_eq!(def_view.total_count(), 2);

        assert!(mgr.code_units_view("nonexistent", 0).is_none());
    }
}
