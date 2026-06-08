//! Per-space code unit management.
//!
//! Ported from Ghidra's `DBTraceCodeSpace`.

use std::collections::BTreeMap;

use crate::db::listing::code_unit::DbTraceData;
use crate::db::listing::instruction::DbTraceInstruction;
use crate::db::listing::undefined::UndefinedDbTraceData;
use crate::model::Lifespan;

/// Manages code units within a single address space.
///
/// Each address space (e.g., "ram", "register") has its own `DbTraceCodeSpace`
/// that tracks all code units defined in that space.
#[derive(Debug)]
pub struct DbTraceCodeSpace {
    /// The address space name.
    pub space_name: String,
    /// Instructions indexed by (snap, offset).
    instructions: BTreeMap<(i64, u64), DbTraceInstruction>,
    /// Defined data indexed by (snap, offset).
    data: BTreeMap<(i64, u64), DbTraceData>,
    /// Undefined regions indexed by (snap, offset).
    undefined: BTreeMap<(i64, u64), UndefinedDbTraceData>,
}

impl DbTraceCodeSpace {
    /// Create a new code space for the given address space.
    pub fn new(space_name: impl Into<String>) -> Self {
        Self {
            space_name: space_name.into(),
            instructions: BTreeMap::new(),
            data: BTreeMap::new(),
            undefined: BTreeMap::new(),
        }
    }

    /// Add an instruction to this space.
    pub fn add_instruction(&mut self, snap: i64, inst: DbTraceInstruction) {
        self.instructions.insert((snap, inst.base.offset), inst);
    }

    /// Add a defined data unit to this space.
    pub fn add_data(&mut self, snap: i64, data: DbTraceData) {
        self.data.insert((snap, data.base.offset), data);
    }

    /// Add an undefined region to this space.
    pub fn add_undefined(&mut self, snap: i64, undef: UndefinedDbTraceData) {
        self.undefined.insert((snap, undef.base.offset), undef);
    }

    /// Get the instruction at the given snap and offset, if any.
    pub fn get_instruction(&self, snap: i64, offset: u64) -> Option<&DbTraceInstruction> {
        self.instructions.get(&(snap, offset))
    }

    /// Get the defined data at the given snap and offset, if any.
    pub fn get_data(&self, snap: i64, offset: u64) -> Option<&DbTraceData> {
        self.data.get(&(snap, offset))
    }

    /// Get the undefined data at the given snap and offset, if any.
    pub fn get_undefined(&self, snap: i64, offset: u64) -> Option<&UndefinedDbTraceData> {
        self.undefined.get(&(snap, offset))
    }

    /// Remove all code units at the given snap.
    pub fn clear_snap(&mut self, snap: i64) {
        self.instructions.retain(|(s, _), _| *s != snap);
        self.data.retain(|(s, _), _| *s != snap);
        self.undefined.retain(|(s, _), _| *s != snap);
    }

    /// Remove all entries within a lifespan.
    pub fn clear_lifespan(&mut self, lifespan: &Lifespan) {
        self.instructions
            .retain(|(s, _), _| !lifespan.contains(*s));
        self.data.retain(|(s, _), _| !lifespan.contains(*s));
        self.undefined
            .retain(|(s, _), _| !lifespan.contains(*s));
    }

    /// Get the total number of code units across all types.
    pub fn total_count(&self) -> usize {
        self.instructions.len() + self.data.len() + self.undefined.len()
    }

    /// Get the number of instructions.
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// Get the number of defined data units.
    pub fn data_count(&self) -> usize {
        self.data.len()
    }

    /// Get all instructions at a given snap.
    pub fn instructions_at_snap(&self, snap: i64) -> Vec<&DbTraceInstruction> {
        self.instructions
            .range((snap, 0)..=(snap, u64::MAX))
            .map(|(_, inst)| inst)
            .collect()
    }

    /// Get all data units at a given snap.
    pub fn data_at_snap(&self, snap: i64) -> Vec<&DbTraceData> {
        self.data
            .range((snap, 0)..=(snap, u64::MAX))
            .map(|(_, d)| d)
            .collect()
    }

    /// Remove an instruction at the given snap and offset.
    pub fn remove_instruction(&mut self, snap: i64, offset: u64) -> Option<DbTraceInstruction> {
        self.instructions.remove(&(snap, offset))
    }

    /// Remove a data unit at the given snap and offset.
    pub fn remove_data(&mut self, snap: i64, offset: u64) -> Option<DbTraceData> {
        self.data.remove(&(snap, offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    

    fn make_instruction(offset: u64, length: u32, snap: i64) -> DbTraceInstruction {
        DbTraceInstruction::new(offset, length, snap, "x86", vec![0x90; length as usize])
    }

    fn make_data(offset: u64, length: u32, snap: i64, name: &str) -> DbTraceData {
        DbTraceData::new(offset, length, snap, name)
    }

    #[test]
    fn test_add_and_get() {
        let mut space = DbTraceCodeSpace::new("ram");
        space.add_instruction(0, make_instruction(0x1000, 1, 0));
        space.add_data(0, make_data(0x2000, 4, 0, "dword"));

        assert!(space.get_instruction(0, 0x1000).is_some());
        assert!(space.get_data(0, 0x2000).is_some());
        assert!(space.get_instruction(0, 0x2000).is_none());
        assert_eq!(space.total_count(), 2);
    }

    #[test]
    fn test_clear_snap() {
        let mut space = DbTraceCodeSpace::new("ram");
        space.add_instruction(0, make_instruction(0x1000, 1, 0));
        space.add_instruction(1, make_instruction(0x1000, 2, 1));

        space.clear_snap(0);
        assert!(space.get_instruction(0, 0x1000).is_none());
        assert!(space.get_instruction(1, 0x1000).is_some());
    }

    #[test]
    fn test_instructions_at_snap() {
        let mut space = DbTraceCodeSpace::new("ram");
        space.add_instruction(5, make_instruction(0x1000, 1, 5));
        space.add_instruction(5, make_instruction(0x1001, 2, 5));
        space.add_instruction(6, make_instruction(0x1000, 1, 6));

        let at_5 = space.instructions_at_snap(5);
        assert_eq!(at_5.len(), 2);
    }

    #[test]
    fn test_remove() {
        let mut space = DbTraceCodeSpace::new("ram");
        space.add_data(0, make_data(0x2000, 4, 0, "dword"));
        assert!(space.remove_data(0, 0x2000).is_some());
        assert!(space.get_data(0, 0x2000).is_none());
    }
}
