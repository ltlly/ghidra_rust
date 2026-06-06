//! TraceDataView, TraceInstructionsView - views for data and instruction queries.
//!
//! Ported from Ghidra's `ghidra.trace.model.listing.TraceDataView`
//! and `ghidra.trace.model.listing.TraceInstructionsView`.

use super::listing::{CodeUnitType, TraceCodeUnit};
use serde::{Deserialize, Serialize};

/// A data type representation for trace data units.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDataType {
    /// The data type name (e.g., "byte", "word", "dword", "qword", "string").
    pub name: String,
    /// The size in bytes.
    pub size: u32,
    /// Whether this is a pointer type.
    pub is_pointer: bool,
    /// Whether this is a composite (struct/array) type.
    pub is_composite: bool,
}

impl TraceDataType {
    /// Create a primitive data type.
    pub fn primitive(name: impl Into<String>, size: u32) -> Self {
        Self {
            name: name.into(),
            size,
            is_pointer: false,
            is_composite: false,
        }
    }

    /// Create a pointer type.
    pub fn pointer(size: u32) -> Self {
        Self {
            name: "pointer".into(),
            size,
            is_pointer: true,
            is_composite: false,
        }
    }

    /// Byte type.
    pub fn byte() -> Self {
        Self::primitive("byte", 1)
    }

    /// Word (2 bytes) type.
    pub fn word() -> Self {
        Self::primitive("word", 2)
    }

    /// Dword (4 bytes) type.
    pub fn dword() -> Self {
        Self::primitive("dword", 4)
    }

    /// Qword (8 bytes) type.
    pub fn qword() -> Self {
        Self::primitive("qword", 8)
    }

    /// String type.
    pub fn string() -> Self {
        Self {
            name: "string".into(),
            size: 0, // Variable length
            is_pointer: false,
            is_composite: false,
        }
    }
}

/// A view for querying data units in the listing.
#[derive(Debug, Clone)]
pub struct TraceDataView;

impl TraceDataView {
    /// Get all data at a snap from a collection of code units.
    pub fn get_data_at<'a>(snap: i64, units: &'a [TraceCodeUnit]) -> Vec<&'a TraceCodeUnit> {
        units
            .iter()
            .filter(|u| u.unit_type == CodeUnitType::Data && u.lifespan.contains(snap))
            .collect()
    }

    /// Get data at a specific address and snap.
    pub fn get_at<'a>(
        snap: i64,
        address: u64,
        units: &'a [TraceCodeUnit],
    ) -> Option<&'a TraceCodeUnit> {
        units.iter().find(|u| {
            u.unit_type == CodeUnitType::Data
                && u.address == address
                && u.lifespan.contains(snap)
        })
    }

    /// Get data containing the given address at a snap.
    pub fn get_containing<'a>(
        snap: i64,
        address: u64,
        units: &'a [TraceCodeUnit],
    ) -> Option<&'a TraceCodeUnit> {
        units.iter().find(|u| {
            u.unit_type == CodeUnitType::Data
                && u.lifespan.contains(snap)
                && address >= u.address
                && address < u.address + u.length as u64
        })
    }

    /// Get data in an address range at a snap.
    pub fn get_in_range<'a>(
        snap: i64,
        min_addr: u64,
        max_addr: u64,
        units: &'a [TraceCodeUnit],
    ) -> Vec<&'a TraceCodeUnit> {
        units
            .iter()
            .filter(|u| {
                u.unit_type == CodeUnitType::Data
                    && u.lifespan.contains(snap)
                    && u.address >= min_addr
                    && u.address <= max_addr
            })
            .collect()
    }
}

/// A view for querying instructions in the listing.
#[derive(Debug, Clone)]
pub struct TraceInstructionsView;

impl TraceInstructionsView {
    /// Get all instructions at a snap from a collection of code units.
    pub fn get_instructions_at<'a>(
        snap: i64,
        units: &'a [TraceCodeUnit],
    ) -> Vec<&'a TraceCodeUnit> {
        units
            .iter()
            .filter(|u| u.unit_type == CodeUnitType::Instruction && u.lifespan.contains(snap))
            .collect()
    }

    /// Get instruction at a specific address and snap.
    pub fn get_at<'a>(
        snap: i64,
        address: u64,
        units: &'a [TraceCodeUnit],
    ) -> Option<&'a TraceCodeUnit> {
        units.iter().find(|u| {
            u.unit_type == CodeUnitType::Instruction
                && u.address == address
                && u.lifespan.contains(snap)
        })
    }

    /// Get instruction containing the given address at a snap.
    pub fn get_containing<'a>(
        snap: i64,
        address: u64,
        units: &'a [TraceCodeUnit],
    ) -> Option<&'a TraceCodeUnit> {
        units.iter().find(|u| {
            u.unit_type == CodeUnitType::Instruction
                && u.lifespan.contains(snap)
                && address >= u.address
                && address < u.address + u.length as u64
        })
    }

    /// Get the next instruction after the given address.
    pub fn get_next<'a>(
        snap: i64,
        after_address: u64,
        units: &'a [TraceCodeUnit],
    ) -> Option<&'a TraceCodeUnit> {
        units
            .iter()
            .filter(|u| {
                u.unit_type == CodeUnitType::Instruction
                    && u.lifespan.contains(snap)
                    && u.address > after_address
            })
            .min_by_key(|u| u.address)
    }

    /// Get the previous instruction before the given address.
    pub fn get_previous<'a>(
        snap: i64,
        before_address: u64,
        units: &'a [TraceCodeUnit],
    ) -> Option<&'a TraceCodeUnit> {
        units
            .iter()
            .filter(|u| {
                u.unit_type == CodeUnitType::Instruction
                    && u.lifespan.contains(snap)
                    && u.address < before_address
            })
            .max_by_key(|u| u.address)
    }

    /// Get instructions in an address range at a snap.
    pub fn get_in_range<'a>(
        snap: i64,
        min_addr: u64,
        max_addr: u64,
        units: &'a [TraceCodeUnit],
    ) -> Vec<&'a TraceCodeUnit> {
        units
            .iter()
            .filter(|u| {
                u.unit_type == CodeUnitType::Instruction
                    && u.lifespan.contains(snap)
                    && u.address >= min_addr
                    && u.address <= max_addr
            })
            .collect()
    }
}

/// A view for undefined data in the listing.
#[derive(Debug, Clone)]
pub struct TraceUndefinedDataView;

impl TraceUndefinedDataView {
    /// Get undefined bytes at a snap for a given address range.
    ///
    /// Returns addresses that have no defined instruction or data at the given snap.
    pub fn get_undefined_addresses(
        snap: i64,
        min_addr: u64,
        max_addr: u64,
        units: &[TraceCodeUnit],
    ) -> Vec<u64> {
        let defined: std::collections::HashSet<u64> = units
            .iter()
            .filter(|u| u.lifespan.contains(snap) && u.address >= min_addr && u.address <= max_addr)
            .map(|u| u.address)
            .collect();

        (min_addr..=max_addr)
            .filter(|a| !defined.contains(a))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Lifespan;

    fn make_units() -> Vec<TraceCodeUnit> {
        vec![
            TraceCodeUnit::instruction(1, 0x1000, "ram", Lifespan::span(0, 100), 4, "MOV", vec![0x90; 4]),
            TraceCodeUnit::instruction(2, 0x1004, "ram", Lifespan::span(0, 100), 4, "ADD", vec![0x90; 4]),
            TraceCodeUnit::data(3, 0x2000, "ram", Lifespan::span(0, 100), 8, "QWORD", vec![0; 8]),
            TraceCodeUnit::data(4, 0x2008, "ram", Lifespan::span(10, 100), 4, "DWORD", vec![0; 4]),
        ]
    }

    #[test]
    fn test_data_view() {
        let units = make_units();
        let data = TraceDataView::get_data_at(50, &units);
        assert_eq!(data.len(), 2);

        let found = TraceDataView::get_at(50, 0x2000, &units);
        assert!(found.is_some());
    }

    #[test]
    fn test_data_view_containing() {
        let units = make_units();
        let found = TraceDataView::get_containing(50, 0x2002, &units);
        assert!(found.is_some());
        assert_eq!(found.unwrap().address, 0x2000);
    }

    #[test]
    fn test_instructions_view() {
        let units = make_units();
        let instrs = TraceInstructionsView::get_instructions_at(50, &units);
        assert_eq!(instrs.len(), 2);
    }

    #[test]
    fn test_instructions_next_previous() {
        let units = make_units();
        let next = TraceInstructionsView::get_next(50, 0x1000, &units);
        assert!(next.is_some());
        assert_eq!(next.unwrap().address, 0x1004);

        let prev = TraceInstructionsView::get_previous(50, 0x1004, &units);
        assert!(prev.is_some());
        assert_eq!(prev.unwrap().address, 0x1000);
    }

    #[test]
    fn test_undefined_data_view() {
        let units = make_units();
        let undef = TraceUndefinedDataView::get_undefined_addresses(5, 0x1000, 0x1008, &units);
        // 0x1000 and 0x1004 are defined, so 0x1001-0x1003 and 0x1005-0x1008 are undefined
        assert!(undef.contains(&0x1001));
        assert!(!undef.contains(&0x1000));
    }

    #[test]
    fn test_data_types() {
        let byte = TraceDataType::byte();
        assert_eq!(byte.size, 1);

        let ptr = TraceDataType::pointer(8);
        assert!(ptr.is_pointer);
    }

    #[test]
    fn test_lifespan_gating() {
        let units = make_units();
        // At snap 5, only 2 data units should exist (snap 10+ has 3rd data)
        let data_at_5 = TraceDataView::get_data_at(5, &units);
        assert_eq!(data_at_5.len(), 1);
        let data_at_50 = TraceDataView::get_data_at(50, &units);
        assert_eq!(data_at_50.len(), 2);
    }
}
