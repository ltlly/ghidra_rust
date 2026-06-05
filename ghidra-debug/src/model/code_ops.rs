//! Code operations trait for trace listing.
//!
//! Ported from Ghidra's `ghidra.trace.model.listing.TraceCodeOperations`.
//!
//! Provides the interface for operating on code units of a trace through
//! various "views" (instructions, data, defined data, undefined data, etc.).

use super::listing::{CodeUnitType, TraceCodeUnit};
use super::Lifespan;

/// Operations for operating on code units in a trace listing.
///
/// This trait provides access to various "views" of the code units,
/// supporting a fluent syntax for operating on the units. The views
/// are various subsets of units by type.
pub trait TraceCodeOperations {
    /// Get all code units in the listing.
    fn code_units(&self) -> Vec<&TraceCodeUnit>;

    /// Get only the instruction code units.
    fn instructions(&self) -> Vec<&TraceCodeUnit>;

    /// Get only the data code units (both defined and undefined).
    fn data(&self) -> Vec<&TraceCodeUnit>;

    /// Get only the defined data code units.
    fn defined_data(&self) -> Vec<&TraceCodeUnit>;

    /// Get only the undefined data code units.
    fn undefined_data(&self) -> Vec<&TraceCodeUnit>;

    /// Get only the defined units (both data and instructions).
    fn defined_units(&self) -> Vec<&TraceCodeUnit>;

    /// Get a code unit at the given address and snap.
    fn get_code_unit_at(&self, snap: i64, address: u64, space: &str) -> Option<&TraceCodeUnit>;

    /// Get code units in the given lifespan and address range.
    fn get_code_units_in(
        &self,
        span: &Lifespan,
        min_address: u64,
        max_address: u64,
        space: &str,
    ) -> Vec<&TraceCodeUnit>;
}

/// A code space that manages code units for a specific address space.
#[derive(Debug, Clone, Default)]
pub struct TraceCodeSpace {
    /// The address space this code space operates on.
    pub address_space: String,
    /// The code units in this space, keyed by (snap, address).
    pub units: Vec<TraceCodeUnit>,
}

impl TraceCodeSpace {
    /// Create a new code space.
    pub fn new(address_space: impl Into<String>) -> Self {
        Self {
            address_space: address_space.into(),
            units: Vec::new(),
        }
    }

    /// Add a code unit to this space.
    pub fn add_unit(&mut self, unit: TraceCodeUnit) {
        self.units.push(unit);
    }

    /// Remove a code unit by key.
    pub fn remove_unit(&mut self, key: i64) -> Option<TraceCodeUnit> {
        if let Some(pos) = self.units.iter().position(|u| u.key == key) {
            Some(self.units.remove(pos))
        } else {
            None
        }
    }

    /// Get a code unit at the given address and snap.
    pub fn get_at(&self, snap: i64, address: u64) -> Option<&TraceCodeUnit> {
        self.units.iter().find(|u| {
            u.address == address
                && u.space == self.address_space
                && u.lifespan.contains(snap)
        })
    }

    /// Get code units intersecting the given lifespan and address range.
    pub fn get_intersecting(
        &self,
        span: &Lifespan,
        min_address: u64,
        max_address: u64,
    ) -> Vec<&TraceCodeUnit> {
        self.units
            .iter()
            .filter(|u| {
                u.space == self.address_space
                    && u.lifespan.intersects(span)
                    && u.address >= min_address
                    && u.address <= max_address
            })
            .collect()
    }

    /// Get instructions in this space.
    pub fn instructions(&self) -> Vec<&TraceCodeUnit> {
        self.units
            .iter()
            .filter(|u| u.unit_type == CodeUnitType::Instruction)
            .collect()
    }

    /// Get defined data in this space.
    pub fn defined_data(&self) -> Vec<&TraceCodeUnit> {
        self.units
            .iter()
            .filter(|u| u.unit_type == CodeUnitType::Data)
            .collect()
    }

    /// Get undefined data in this space.
    pub fn undefined_data(&self) -> Vec<&TraceCodeUnit> {
        self.units
            .iter()
            .filter(|u| u.unit_type == CodeUnitType::Undefined)
            .collect()
    }

    /// Get the number of code units.
    pub fn len(&self) -> usize {
        self.units.len()
    }

    /// Whether this space has no code units.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }
}

impl TraceCodeOperations for TraceCodeSpace {
    fn code_units(&self) -> Vec<&TraceCodeUnit> {
        self.units.iter().collect()
    }

    fn instructions(&self) -> Vec<&TraceCodeUnit> {
        self.instructions()
    }

    fn data(&self) -> Vec<&TraceCodeUnit> {
        self.units
            .iter()
            .filter(|u| {
                u.unit_type == CodeUnitType::Data || u.unit_type == CodeUnitType::Undefined
            })
            .collect()
    }

    fn defined_data(&self) -> Vec<&TraceCodeUnit> {
        self.defined_data()
    }

    fn undefined_data(&self) -> Vec<&TraceCodeUnit> {
        self.undefined_data()
    }

    fn defined_units(&self) -> Vec<&TraceCodeUnit> {
        self.units
            .iter()
            .filter(|u| {
                u.unit_type == CodeUnitType::Instruction || u.unit_type == CodeUnitType::Data
            })
            .collect()
    }

    fn get_code_unit_at(&self, snap: i64, address: u64, space: &str) -> Option<&TraceCodeUnit> {
        if space != self.address_space {
            return None;
        }
        self.get_at(snap, address)
    }

    fn get_code_units_in(
        &self,
        span: &Lifespan,
        min_address: u64,
        max_address: u64,
        space: &str,
    ) -> Vec<&TraceCodeUnit> {
        if space != self.address_space {
            return Vec::new();
        }
        self.get_intersecting(span, min_address, max_address)
    }
}

/// A code manager that holds multiple code spaces.
#[derive(Debug, Clone, Default)]
pub struct TraceCodeSpaceManager {
    /// The code spaces by address space name.
    pub spaces: std::collections::HashMap<String, TraceCodeSpace>,
}

impl TraceCodeSpaceManager {
    /// Create a new code space manager.
    pub fn new() -> Self {
        Self {
            spaces: std::collections::HashMap::new(),
        }
    }

    /// Get or create a code space for the given address space.
    pub fn get_or_create_space(&mut self, space: &str) -> &mut TraceCodeSpace {
        self.spaces
            .entry(space.to_string())
            .or_insert_with(|| TraceCodeSpace::new(space))
    }

    /// Get a code space.
    pub fn get_space(&self, space: &str) -> Option<&TraceCodeSpace> {
        self.spaces.get(space)
    }

    /// Get a mutable reference to a code space.
    pub fn get_space_mut(&mut self, space: &str) -> Option<&mut TraceCodeSpace> {
        self.spaces.get_mut(space)
    }

    /// Add a code unit to the appropriate space.
    pub fn add_unit(&mut self, unit: TraceCodeUnit) {
        let space_name = unit.space.clone();
        self.get_or_create_space(&space_name).add_unit(unit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_instruction(key: i64, addr: u64, snap_start: i64, snap_end: i64) -> TraceCodeUnit {
        TraceCodeUnit::instruction(
            key,
            addr,
            "ram",
            Lifespan::span(snap_start, snap_end),
            4,
            "MOV",
            vec![0x90; 4],
        )
    }

    fn make_data(key: i64, addr: u64, snap_start: i64, snap_end: i64) -> TraceCodeUnit {
        TraceCodeUnit::data(
            key,
            addr,
            "ram",
            Lifespan::span(snap_start, snap_end),
            8,
            "QWORD",
            vec![0; 8],
        )
    }

    #[test]
    fn test_code_space_basic() {
        let mut space = TraceCodeSpace::new("ram");
        assert!(space.is_empty());
        assert_eq!(space.len(), 0);

        space.add_unit(make_instruction(1, 0x1000, 0, 10));
        space.add_unit(make_data(2, 0x2000, 0, 10));
        assert_eq!(space.len(), 2);
    }

    #[test]
    fn test_code_space_get_at() {
        let mut space = TraceCodeSpace::new("ram");
        space.add_unit(make_instruction(1, 0x1000, 0, 10));

        let unit = space.get_at(5, 0x1000);
        assert!(unit.is_some());
        assert_eq!(unit.unwrap().key, 1);

        let missing = space.get_at(15, 0x1000);
        assert!(missing.is_none());
    }

    #[test]
    fn test_code_space_instructions() {
        let mut space = TraceCodeSpace::new("ram");
        space.add_unit(make_instruction(1, 0x1000, 0, 10));
        space.add_unit(make_instruction(2, 0x1004, 0, 10));
        space.add_unit(make_data(3, 0x2000, 0, 10));

        let instrs = space.instructions();
        assert_eq!(instrs.len(), 2);
    }

    #[test]
    fn test_code_space_intersecting() {
        let mut space = TraceCodeSpace::new("ram");
        space.add_unit(make_instruction(1, 0x1000, 0, 10));
        space.add_unit(make_instruction(2, 0x2000, 0, 10));
        space.add_unit(make_instruction(3, 0x3000, 5, 15));

        let in_range = space.get_intersecting(&Lifespan::span(3, 12), 0x1000, 0x2000);
        assert_eq!(in_range.len(), 2);
    }

    #[test]
    fn test_code_space_remove() {
        let mut space = TraceCodeSpace::new("ram");
        space.add_unit(make_instruction(1, 0x1000, 0, 10));

        let removed = space.remove_unit(1);
        assert!(removed.is_some());
        assert!(space.is_empty());
    }

    #[test]
    fn test_code_operations_trait() {
        let mut space = TraceCodeSpace::new("ram");
        space.add_unit(make_instruction(1, 0x1000, 0, 10));
        space.add_unit(make_data(2, 0x2000, 0, 10));

        let ops: &dyn TraceCodeOperations = &space;
        assert_eq!(ops.code_units().len(), 2);
        assert_eq!(ops.instructions().len(), 1);
        assert_eq!(ops.defined_data().len(), 1);
    }

    #[test]
    fn test_code_space_manager() {
        let mut mgr = TraceCodeSpaceManager::new();
        mgr.add_unit(make_instruction(1, 0x1000, 0, 10));
        assert!(mgr.get_space("ram").is_some());
        assert_eq!(mgr.get_space("ram").unwrap().len(), 1);
    }

    #[test]
    fn test_get_code_unit_at_wrong_space() {
        let space = TraceCodeSpace::new("ram");
        assert!(space.get_code_unit_at(0, 0x1000, "register").is_none());
    }
}
