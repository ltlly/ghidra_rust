//! Trace listing view types - typed views over code units in a trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.listing` package.
//! These views filter the trace listing to provide typed iterators over
//! specific kinds of code units (instructions, data, undefined, etc.).

use serde::{Deserialize, Serialize};

use super::listing::{CodeUnitType, TraceCodeUnit};

/// An iterator-style view over code units in the trace listing.
///
/// This trait models Ghidra's `TraceBaseCodeUnitsView<T>` generic interface.
/// Each view filters code units by type and provides iteration over a
/// specified address range and lifespan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCodeUnitsView {
    /// The underlying code units.
    pub units: Vec<TraceCodeUnit>,
}

impl TraceCodeUnitsView {
    /// Create an empty view.
    pub fn new() -> Self {
        Self { units: Vec::new() }
    }

    /// Add a code unit to this view.
    pub fn push(&mut self, unit: TraceCodeUnit) {
        self.units.push(unit);
    }

    /// Get the number of code units.
    pub fn len(&self) -> usize {
        self.units.len()
    }

    /// Check if the view is empty.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    /// Iterate over all code units.
    pub fn iter(&self) -> impl Iterator<Item = &TraceCodeUnit> {
        self.units.iter()
    }

    /// Filter to only instructions.
    pub fn instructions(&self) -> TraceInstructionsView {
        TraceInstructionsView {
            units: self
                .units
                .iter()
                .filter(|u| u.unit_type == CodeUnitType::Instruction)
                .cloned()
                .collect(),
        }
    }

    /// Filter to only data units (including undefined).
    pub fn data(&self) -> TraceDataView {
        TraceDataView {
            units: self
                .units
                .iter()
                .filter(|u| u.unit_type != CodeUnitType::Instruction)
                .cloned()
                .collect(),
        }
    }

    /// Filter to only defined data units (excluding undefined).
    pub fn defined_data(&self) -> TraceDefinedDataView {
        TraceDefinedDataView {
            units: self
                .units
                .iter()
                .filter(|u| u.unit_type == CodeUnitType::Data)
                .cloned()
                .collect(),
        }
    }

    /// Filter to only undefined data units.
    pub fn undefined_data(&self) -> TraceUndefinedDataView {
        TraceUndefinedDataView {
            units: self
                .units
                .iter()
                .filter(|u| u.unit_type == CodeUnitType::Undefined)
                .cloned()
                .collect(),
        }
    }

    /// Filter by address range and lifespan.
    pub fn in_range(&self, min_addr: u64, max_addr: u64, snap: i64) -> Vec<&TraceCodeUnit> {
        self.units
            .iter()
            .filter(|u| {
                u.address >= min_addr
                    && u.address <= max_addr
                    && u.lifespan.contains(snap)
            })
            .collect()
    }

    /// Find a code unit at a specific address and snap.
    pub fn get_at(&self, address: u64, snap: i64) -> Option<&TraceCodeUnit> {
        self.units.iter().find(|u| {
            u.address <= address
                && address < u.address + u.length as u64
                && u.lifespan.contains(snap)
        })
    }
}

impl Default for TraceCodeUnitsView {
    fn default() -> Self {
        Self::new()
    }
}

/// A view of instruction units only.
///
/// This view excludes all data units, defined or undefined.
/// Ported from Ghidra's `TraceInstructionsView` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceInstructionsView {
    /// The instruction code units.
    pub units: Vec<TraceCodeUnit>,
}

impl TraceInstructionsView {
    /// Create an empty instructions view.
    pub fn new() -> Self {
        Self { units: Vec::new() }
    }

    /// Get the number of instructions.
    pub fn len(&self) -> usize {
        self.units.len()
    }

    /// Check if the view is empty.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    /// Iterate over instructions.
    pub fn iter(&self) -> impl Iterator<Item = &TraceCodeUnit> {
        self.units.iter()
    }

    /// Find an instruction at a specific address and snap.
    pub fn get_at(&self, address: u64, snap: i64) -> Option<&TraceCodeUnit> {
        self.units.iter().find(|u| {
            u.address <= address
                && address < u.address + u.length as u64
                && u.lifespan.contains(snap)
        })
    }

    /// Get instructions in an address range at a given snap.
    pub fn in_range(&self, min_addr: u64, max_addr: u64, snap: i64) -> Vec<&TraceCodeUnit> {
        self.units
            .iter()
            .filter(|u| {
                u.address >= min_addr
                    && u.address <= max_addr
                    && u.lifespan.contains(snap)
            })
            .collect()
    }
}

impl Default for TraceInstructionsView {
    fn default() -> Self {
        Self::new()
    }
}

/// A view of data units (excluding instructions).
///
/// This includes default/undefined data units.
/// Ported from Ghidra's `TraceDataView` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDataView {
    /// The data code units.
    pub units: Vec<TraceCodeUnit>,
}

impl TraceDataView {
    /// Create an empty data view.
    pub fn new() -> Self {
        Self { units: Vec::new() }
    }

    /// Get the number of data units.
    pub fn len(&self) -> usize {
        self.units.len()
    }

    /// Check if the view is empty.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    /// Iterate over data units.
    pub fn iter(&self) -> impl Iterator<Item = &TraceCodeUnit> {
        self.units.iter()
    }

    /// Find a data unit at a specific address and snap.
    pub fn get_at(&self, address: u64, snap: i64) -> Option<&TraceCodeUnit> {
        self.units.iter().find(|u| {
            u.address <= address
                && address < u.address + u.length as u64
                && u.lifespan.contains(snap)
        })
    }
}

impl Default for TraceDataView {
    fn default() -> Self {
        Self::new()
    }
}

/// A view of defined data units only (excluding undefined).
///
/// Ported from Ghidra's `TraceDefinedDataView` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDefinedDataView {
    /// The defined data code units.
    pub units: Vec<TraceCodeUnit>,
}

impl TraceDefinedDataView {
    /// Create an empty view.
    pub fn new() -> Self {
        Self { units: Vec::new() }
    }

    /// Get the number of defined data units.
    pub fn len(&self) -> usize {
        self.units.len()
    }

    /// Check if the view is empty.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    /// Iterate over defined data units.
    pub fn iter(&self) -> impl Iterator<Item = &TraceCodeUnit> {
        self.units.iter()
    }
}

impl Default for TraceDefinedDataView {
    fn default() -> Self {
        Self::new()
    }
}

/// A view of undefined data units only.
///
/// Ported from Ghidra's `TraceUndefinedDataView` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceUndefinedDataView {
    /// The undefined data code units.
    pub units: Vec<TraceCodeUnit>,
}

impl TraceUndefinedDataView {
    /// Create an empty view.
    pub fn new() -> Self {
        Self { units: Vec::new() }
    }

    /// Get the number of undefined data units.
    pub fn len(&self) -> usize {
        self.units.len()
    }

    /// Check if the view is empty.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    /// Iterate over undefined data units.
    pub fn iter(&self) -> impl Iterator<Item = &TraceCodeUnit> {
        self.units.iter()
    }
}

impl Default for TraceUndefinedDataView {
    fn default() -> Self {
        Self::new()
    }
}

/// A view of defined units (both instructions and defined data,
/// excluding undefined data).
///
/// Ported from Ghidra's `TraceDefinedUnitsView` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDefinedUnitsView {
    /// The defined code units.
    pub units: Vec<TraceCodeUnit>,
}

impl TraceDefinedUnitsView {
    /// Create an empty view.
    pub fn new() -> Self {
        Self { units: Vec::new() }
    }

    /// Get the count.
    pub fn len(&self) -> usize {
        self.units.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    /// Iterate over defined units.
    pub fn iter(&self) -> impl Iterator<Item = &TraceCodeUnit> {
        self.units.iter()
    }
}

impl Default for TraceDefinedUnitsView {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_instruction(addr: u64, len: u32, snap_start: i64, snap_end: i64) -> TraceCodeUnit {
        TraceCodeUnit::instruction(
            addr as i64,
            addr,
            "ram",
            Lifespan::span(snap_start, snap_end),
            len,
            "MOV",
            vec![0x90; len as usize],
        )
    }

    fn make_data(addr: u64, len: u32, snap_start: i64, snap_end: i64) -> TraceCodeUnit {
        TraceCodeUnit::data(
            addr as i64 + 1000,
            addr,
            "ram",
            Lifespan::span(snap_start, snap_end),
            len,
            "dword",
            vec![0x00; len as usize],
        )
    }

    fn make_undefined(addr: u64, snap_start: i64, snap_end: i64) -> TraceCodeUnit {
        TraceCodeUnit::undefined(
            addr as i64 + 2000,
            addr,
            "ram",
            Lifespan::span(snap_start, snap_end),
            1,
        )
    }

    #[test]
    fn test_code_units_view_filters() {
        let mut view = TraceCodeUnitsView::new();
        view.push(make_instruction(0x1000, 3, 0, 100));
        view.push(make_data(0x2000, 4, 0, 100));
        view.push(make_undefined(0x3000, 0, 100));
        view.push(make_instruction(0x4000, 5, 0, 50));

        assert_eq!(view.len(), 4);
        assert_eq!(view.instructions().len(), 2);
        assert_eq!(view.data().len(), 2);
        assert_eq!(view.defined_data().len(), 1);
        assert_eq!(view.undefined_data().len(), 1);
    }

    #[test]
    fn test_code_units_view_get_at() {
        let mut view = TraceCodeUnitsView::new();
        view.push(make_instruction(0x1000, 3, 0, 100));

        let unit = view.get_at(0x1001, 50);
        assert!(unit.is_some());
        assert_eq!(unit.unwrap().address, 0x1000);

        assert!(view.get_at(0x1003, 50).is_none());
    }

    #[test]
    fn test_instructions_view_in_range() {
        let mut view = TraceInstructionsView::new();
        view.units.push(make_instruction(0x1000, 3, 0, 100));
        view.units.push(make_instruction(0x2000, 3, 0, 100));
        view.units.push(make_instruction(0x3000, 3, 0, 100));

        let in_range = view.in_range(0x1000, 0x2002, 50);
        assert_eq!(in_range.len(), 2);
    }

    #[test]
    fn test_data_view() {
        let mut view = TraceDataView::new();
        view.units.push(make_data(0x2000, 4, 0, 100));
        assert_eq!(view.len(), 1);
        assert!(!view.is_empty());
    }

    #[test]
    fn test_defined_units_view() {
        let view = TraceDefinedUnitsView::new();
        assert!(view.is_empty());
        assert_eq!(view.len(), 0);
    }

    #[test]
    fn test_serialization() {
        let mut view = TraceCodeUnitsView::new();
        view.push(make_instruction(0x1000, 3, 0, 100));
        let json = serde_json::to_string(&view).unwrap();
        let deserialized: TraceCodeUnitsView = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.len(), 1);
    }
}
