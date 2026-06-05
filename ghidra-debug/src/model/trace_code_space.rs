//! TraceCodeSpace - a code unit space bound to a particular address space.
//!
//! Ported from Ghidra's `ghidra.trace.model.listing.TraceCodeSpace`.

use serde::{Deserialize, Serialize};

use super::Lifespan;
use super::listing::{CodeUnitType, TraceCodeUnit};

/// A code unit space bound to a specific address space.
///
/// Each address space (memory, register) in a trace has its own code space
/// where instructions and data are recorded over time.
#[derive(Debug, Clone)]
pub struct TraceCodeSpace {
    /// The address space name this code space is bound to (e.g., "ram", "register").
    pub space_name: String,
    /// Whether this is a register space.
    pub is_register: bool,
    /// The thread key if this is a register space.
    pub thread_key: Option<i64>,
    /// The frame level if this is a register space.
    pub frame_level: Option<i32>,
    /// Stored code units.
    pub entries: Vec<TraceCodeUnit>,
}

impl TraceCodeSpace {
    /// Create a new memory code space.
    pub fn new_memory(space_name: impl Into<String>) -> Self {
        Self {
            space_name: space_name.into(),
            is_register: false,
            thread_key: None,
            frame_level: None,
            entries: Vec::new(),
        }
    }

    /// Create a new register code space.
    pub fn new_register(
        thread_key: i64,
        frame_level: i32,
    ) -> Self {
        Self {
            space_name: "register".into(),
            is_register: true,
            thread_key: Some(thread_key),
            frame_level: Some(frame_level),
            entries: Vec::new(),
        }
    }

    /// Add a code unit to this space.
    pub fn add_unit(&mut self, unit: TraceCodeUnit) {
        self.entries.push(unit);
    }

    /// Get the instruction at the given snap and address.
    pub fn get_instruction_at(&self, snap: i64, address: u64) -> Option<&TraceCodeUnit> {
        self.entries.iter().find(|u| {
            u.unit_type == CodeUnitType::Instruction
                && u.address == address
                && u.lifespan.contains(snap)
        })
    }

    /// Get the data at the given snap and address.
    pub fn get_data_at(&self, snap: i64, address: u64) -> Option<&TraceCodeUnit> {
        self.entries.iter().find(|u| {
            u.unit_type == CodeUnitType::Data
                && u.address == address
                && u.lifespan.contains(snap)
        })
    }

    /// Get any code unit at the given snap and address.
    pub fn get_code_unit_at(&self, snap: i64, address: u64) -> Option<&TraceCodeUnit> {
        self.entries
            .iter()
            .find(|u| u.address == address && u.lifespan.contains(snap))
    }

    /// Get all instructions in this space at the given snap.
    pub fn get_instructions(&self, snap: i64) -> Vec<&TraceCodeUnit> {
        self.entries
            .iter()
            .filter(|u| u.unit_type == CodeUnitType::Instruction && u.lifespan.contains(snap))
            .collect()
    }

    /// Get all defined data in this space at the given snap.
    pub fn get_defined_data(&self, snap: i64) -> Vec<&TraceCodeUnit> {
        self.entries
            .iter()
            .filter(|u| u.unit_type == CodeUnitType::Data && u.lifespan.contains(snap))
            .collect()
    }

    /// Get code units in an address range at a given snap.
    pub fn get_units_in_range(
        &self,
        snap: i64,
        min_addr: u64,
        max_addr: u64,
    ) -> Vec<&TraceCodeUnit> {
        self.entries
            .iter()
            .filter(|u| {
                u.lifespan.contains(snap) && u.address >= min_addr && u.address <= max_addr
            })
            .collect()
    }

    /// Clear code units in a lifespan and address range.
    pub fn clear(&mut self, span: &Lifespan, min_addr: u64, max_addr: u64) {
        self.entries.retain(|u| {
            !(u.lifespan.intersects(span)
                && u.address >= min_addr
                && u.address <= max_addr)
        });
    }

    /// Get the number of code units at a given snap.
    pub fn count_at(&self, snap: i64) -> usize {
        self.entries.iter().filter(|u| u.lifespan.contains(snap)).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_instruction(key: i64, addr: u64, snap_min: i64, snap_max: i64) -> TraceCodeUnit {
        TraceCodeUnit::instruction(
            key,
            addr,
            "ram",
            Lifespan::span(snap_min, snap_max),
            4,
            "MOV",
            vec![0x90; 4],
        )
    }

    #[test]
    fn test_memory_code_space() {
        let mut space = TraceCodeSpace::new_memory("ram");
        assert!(!space.is_register);
        assert_eq!(space.space_name, "ram");

        space.add_unit(make_instruction(1, 0x1000, 0, 100));
        space.add_unit(make_instruction(2, 0x2000, 0, 100));

        assert!(space.get_instruction_at(50, 0x1000).is_some());
        assert!(space.get_instruction_at(50, 0x3000).is_none());
        assert_eq!(space.get_instructions(50).len(), 2);
    }

    #[test]
    fn test_register_code_space() {
        let space = TraceCodeSpace::new_register(1, 0);
        assert!(space.is_register);
        assert_eq!(space.thread_key, Some(1));
    }

    #[test]
    fn test_range_query() {
        let mut space = TraceCodeSpace::new_memory("ram");
        space.add_unit(make_instruction(1, 0x1000, 0, 100));
        space.add_unit(make_instruction(2, 0x2000, 0, 100));
        space.add_unit(make_instruction(3, 0x3000, 0, 100));

        let units = space.get_units_in_range(50, 0x1000, 0x2000);
        assert_eq!(units.len(), 2);
    }

    #[test]
    fn test_clear() {
        let mut space = TraceCodeSpace::new_memory("ram");
        space.add_unit(make_instruction(1, 0x1000, 0, 100));
        space.add_unit(make_instruction(2, 0x2000, 0, 100));

        space.clear(&Lifespan::span(50, 150), 0x1000, 0x1000);
        assert_eq!(space.entries.len(), 1);
    }

    #[test]
    fn test_data_space() {
        let mut space = TraceCodeSpace::new_memory("ram");
        space.add_unit(TraceCodeUnit::data(
            1,
            0x1000,
            "ram",
            Lifespan::span(0, 100),
            8,
            "QWORD",
            vec![0; 8],
        ));

        assert!(space.get_data_at(50, 0x1000).is_some());
        assert_eq!(space.get_defined_data(50).len(), 1);
    }
}
