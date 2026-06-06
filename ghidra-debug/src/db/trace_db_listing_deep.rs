//! Deep listing operations for the trace database.
//!
//! Ported from Ghidra's Framework-TraceModeling listing types including
//! `TraceCodeUnit`, `TraceCodeOperations`, `TraceCodeSpace`, and
//! the various listing views for instructions, data, and comments.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The type of a code unit in a trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceCodeUnitType {
    /// An instruction.
    Instruction,
    /// A defined data unit.
    DefinedData,
    /// Undefined data (uninitialized or unknown).
    UndefinedData,
    /// A code unit that could not be disassembled.
    BadInstructionError,
}

impl TraceCodeUnitType {
    /// Whether this is an instruction.
    pub fn is_instruction(&self) -> bool {
        matches!(self, TraceCodeUnitType::Instruction)
    }

    /// Whether this is data (defined or undefined).
    pub fn is_data(&self) -> bool {
        matches!(
            self,
            TraceCodeUnitType::DefinedData | TraceCodeUnitType::UndefinedData
        )
    }
}

/// A code unit in a trace listing.
///
/// Ported from Ghidra's `TraceCodeUnit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCodeUnit {
    /// The address of this code unit.
    pub address: u64,
    /// The address space name.
    pub space: String,
    /// The snap at which this unit is valid.
    pub snap: i64,
    /// The length in bytes.
    pub length: usize,
    /// The type of code unit.
    pub unit_type: TraceCodeUnitType,
    /// The mnemonic string (for instructions).
    pub mnemonic: String,
    /// Pre-comment, if any.
    pub pre_comment: Option<String>,
    /// Post-comment, if any.
    pub post_comment: Option<String>,
    /// EOL comment, if any.
    pub eol_comment: Option<String>,
    /// The data type name (for data units).
    pub data_type: Option<String>,
    /// The raw bytes.
    pub bytes: Vec<u8>,
}

impl TraceCodeUnit {
    /// Create an instruction code unit.
    pub fn instruction(
        address: u64,
        space: &str,
        snap: i64,
        length: usize,
        mnemonic: &str,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            address,
            space: space.to_string(),
            snap,
            length,
            unit_type: TraceCodeUnitType::Instruction,
            mnemonic: mnemonic.to_string(),
            pre_comment: None,
            post_comment: None,
            eol_comment: None,
            data_type: None,
            bytes,
        }
    }

    /// Create a data code unit.
    pub fn data(
        address: u64,
        space: &str,
        snap: i64,
        length: usize,
        data_type: &str,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            address,
            space: space.to_string(),
            snap,
            length,
            unit_type: TraceCodeUnitType::DefinedData,
            mnemonic: String::new(),
            pre_comment: None,
            post_comment: None,
            eol_comment: None,
            data_type: Some(data_type.to_string()),
            bytes,
        }
    }

    /// Create an undefined data code unit.
    pub fn undefined(address: u64, space: &str, snap: i64, length: usize) -> Self {
        Self {
            address,
            space: space.to_string(),
            snap,
            length,
            unit_type: TraceCodeUnitType::UndefinedData,
            mnemonic: String::new(),
            pre_comment: None,
            post_comment: None,
            eol_comment: None,
            data_type: None,
            bytes: vec![0; length],
        }
    }

    /// Get the end address (exclusive).
    pub fn end_address(&self) -> u64 {
        self.address + self.length as u64
    }

    /// Whether this unit contains the given address.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.address && addr < self.end_address()
    }

    /// Set a pre-comment.
    pub fn with_pre_comment(mut self, comment: impl Into<String>) -> Self {
        self.pre_comment = Some(comment.into());
        self
    }

    /// Set a post-comment.
    pub fn with_post_comment(mut self, comment: impl Into<String>) -> Self {
        self.post_comment = Some(comment.into());
        self
    }

    /// Set an EOL comment.
    pub fn with_eol_comment(mut self, comment: impl Into<String>) -> Self {
        self.eol_comment = Some(comment.into());
        self
    }

    /// Whether this unit has any comments.
    pub fn has_comments(&self) -> bool {
        self.pre_comment.is_some() || self.post_comment.is_some() || self.eol_comment.is_some()
    }
}

/// An iterator over code units in a listing.
#[derive(Debug)]
pub struct CodeUnitIterator {
    units: Vec<TraceCodeUnit>,
    index: usize,
}

impl CodeUnitIterator {
    /// Create a new iterator over the given code units.
    pub fn new(units: Vec<TraceCodeUnit>) -> Self {
        Self { units, index: 0 }
    }

    /// Create an empty iterator.
    pub fn empty() -> Self {
        Self {
            units: Vec::new(),
            index: 0,
        }
    }

    /// Peek at the next code unit without advancing.
    pub fn peek(&self) -> Option<&TraceCodeUnit> {
        self.units.get(self.index)
    }

    /// Get the remaining count.
    pub fn remaining(&self) -> usize {
        self.units.len().saturating_sub(self.index)
    }
}

impl Iterator for CodeUnitIterator {
    type Item = TraceCodeUnit;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.units.len() {
            let item = self.units[self.index].clone();
            self.index += 1;
            Some(item)
        } else {
            None
        }
    }
}

/// A view of code units in a listing space at a given snap.
///
/// Ported from Ghidra's `TraceCodeUnitsView`.
#[derive(Debug, Clone)]
pub struct TraceCodeUnitsView {
    /// The address space name.
    pub space: String,
    /// The snap.
    pub snap: i64,
    /// Code units indexed by address.
    units: BTreeMap<u64, TraceCodeUnit>,
}

impl TraceCodeUnitsView {
    /// Create a new empty view.
    pub fn new(space: impl Into<String>, snap: i64) -> Self {
        Self {
            space: space.into(),
            snap,
            units: BTreeMap::new(),
        }
    }

    /// Add a code unit.
    pub fn add_unit(&mut self, unit: TraceCodeUnit) {
        self.units.insert(unit.address, unit);
    }

    /// Get a code unit at an address.
    pub fn get_unit(&self, addr: u64) -> Option<&TraceCodeUnit> {
        self.units.get(&addr)
    }

    /// Get the code unit containing an address.
    pub fn get_unit_containing(&self, addr: u64) -> Option<&TraceCodeUnit> {
        // Find the unit whose range contains addr
        self.units
            .range(..=addr)
            .next_back()
            .map(|(_, unit)| unit)
            .filter(|unit| unit.contains(addr))
    }

    /// Get an iterator over all units in an address range.
    pub fn get_units_in_range(&self, min: u64, max: u64) -> CodeUnitIterator {
        let units: Vec<_> = self
            .units
            .range(min..=max)
            .map(|(_, u)| u.clone())
            .collect();
        CodeUnitIterator::new(units)
    }

    /// Get an iterator over all units.
    pub fn iter_all(&self) -> CodeUnitIterator {
        let units: Vec<_> = self.units.values().cloned().collect();
        CodeUnitIterator::new(units)
    }

    /// Get the number of units.
    pub fn len(&self) -> usize {
        self.units.len()
    }

    /// Whether the view is empty.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    /// Get only instruction units.
    pub fn instructions(&self) -> Vec<&TraceCodeUnit> {
        self.units
            .values()
            .filter(|u| u.unit_type.is_instruction())
            .collect()
    }

    /// Get only defined data units.
    pub fn defined_data(&self) -> Vec<&TraceCodeUnit> {
        self.units
            .values()
            .filter(|u| u.unit_type == TraceCodeUnitType::DefinedData)
            .collect()
    }

    /// Remove a unit at the given address.
    pub fn remove_unit(&mut self, addr: u64) -> Option<TraceCodeUnit> {
        self.units.remove(&addr)
    }

    /// Clear all units.
    pub fn clear(&mut self) {
        self.units.clear();
    }
}

/// A blended listing color model for trace views.
///
/// Ported from Ghidra's `BlendedListingColorModel` concept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlendedListingColorModel {
    /// Color entries indexed by address.
    pub entries: BTreeMap<u64, ColorEntry>,
    /// Default background color (as ARGB).
    pub default_background: u32,
}

/// A color entry for a listing address.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ColorEntry {
    /// The foreground color (ARGB).
    pub foreground: u32,
    /// The background color (ARGB).
    pub background: u32,
    /// The blend factor (0.0 to 1.0).
    pub blend: f32,
}

impl ColorEntry {
    /// Create a new color entry.
    pub fn new(foreground: u32, background: u32, blend: f32) -> Self {
        Self {
            foreground,
            background,
            blend: blend.clamp(0.0, 1.0),
        }
    }

    /// Blend this color with another.
    pub fn blend_with(&self, other: &ColorEntry) -> ColorEntry {
        let blend = (self.blend + other.blend) / 2.0;
        ColorEntry {
            foreground: self.foreground, // simplified: just pick one
            background: other.background,
            blend,
        }
    }
}

impl BlendedListingColorModel {
    /// Create a new color model.
    pub fn new(default_background: u32) -> Self {
        Self {
            entries: BTreeMap::new(),
            default_background,
        }
    }

    /// Set a color entry.
    pub fn set_color(&mut self, addr: u64, entry: ColorEntry) {
        self.entries.insert(addr, entry);
    }

    /// Get the color at an address.
    pub fn get_color(&self, addr: u64) -> ColorEntry {
        self.entries.get(&addr).copied().unwrap_or(ColorEntry {
            foreground: 0xFF000000,
            background: self.default_background,
            blend: 0.0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_unit_type() {
        assert!(TraceCodeUnitType::Instruction.is_instruction());
        assert!(!TraceCodeUnitType::Instruction.is_data());
        assert!(TraceCodeUnitType::DefinedData.is_data());
        assert!(TraceCodeUnitType::UndefinedData.is_data());
    }

    #[test]
    fn test_instruction_code_unit() {
        let unit = TraceCodeUnit::instruction(
            0x400000,
            "ram",
            0,
            2,
            "NOP",
            vec![0x90, 0x90],
        )
        .with_eol_comment("padding");
        assert_eq!(unit.end_address(), 0x400002);
        assert!(unit.contains(0x400001));
        assert!(!unit.contains(0x400002));
        assert!(unit.has_comments());
    }

    #[test]
    fn test_data_code_unit() {
        let unit = TraceCodeUnit::data(0x1000, "ram", 0, 4, "dword", vec![0x78, 0x56, 0x34, 0x12]);
        assert_eq!(unit.unit_type, TraceCodeUnitType::DefinedData);
        assert_eq!(unit.data_type.as_deref(), Some("dword"));
        assert!(!unit.has_comments());
    }

    #[test]
    fn test_code_units_view() {
        let mut view = TraceCodeUnitsView::new("ram", 0);
        view.add_unit(TraceCodeUnit::instruction(0x400000, "ram", 0, 2, "NOP", vec![0x90, 0x90]));
        view.add_unit(TraceCodeUnit::instruction(0x400002, "ram", 0, 5, "MOV", vec![0x89, 0xC3, 0x00, 0x00, 0x00]));
        view.add_unit(TraceCodeUnit::data(0x400100, "ram", 0, 4, "dword", vec![0x00; 4]));

        assert_eq!(view.len(), 3);
        assert!(view.get_unit(0x400000).is_some());
        assert!(view.get_unit(0x999999).is_none());

        let containing = view.get_unit_containing(0x400001);
        assert!(containing.is_some());
        assert_eq!(containing.unwrap().address, 0x400000);

        assert_eq!(view.instructions().len(), 2);
        assert_eq!(view.defined_data().len(), 1);
    }

    #[test]
    fn test_code_units_view_range() {
        let mut view = TraceCodeUnitsView::new("ram", 0);
        for i in 0..10 {
            view.add_unit(TraceCodeUnit::instruction(
                0x400000 + i * 4,
                "ram",
                0,
                4,
                "NOP",
                vec![0x90; 4],
            ));
        }

        let range = view.get_units_in_range(0x400004, 0x400010);
        // Addresses 0x400004, 0x400008, 0x40000C, 0x400010 are all in range (inclusive)
        assert_eq!(range.remaining(), 4);

        let range2 = view.get_units_in_range(0x400004, 0x40000F);
        // Addresses 0x400004, 0x400008, 0x40000C are in range
        assert_eq!(range2.remaining(), 3);
    }

    #[test]
    fn test_code_unit_iterator() {
        let units = vec![
            TraceCodeUnit::instruction(0, "ram", 0, 1, "NOP", vec![0x90]),
            TraceCodeUnit::instruction(1, "ram", 0, 1, "NOP", vec![0x90]),
        ];
        let mut iter = CodeUnitIterator::new(units);
        assert_eq!(iter.remaining(), 2);
        assert!(iter.peek().is_some());
        iter.next();
        assert_eq!(iter.remaining(), 1);
    }

    #[test]
    fn test_blended_color_model() {
        let mut model = BlendedListingColorModel::new(0xFFFFFFFF);
        assert_eq!(model.get_color(0).background, 0xFFFFFFFF);

        model.set_color(0x400000, ColorEntry::new(0xFF000000, 0xFF00FF00, 0.5));
        let c = model.get_color(0x400000);
        assert_eq!(c.background, 0xFF00FF00);
    }

    #[test]
    fn test_color_entry() {
        let c = ColorEntry::new(0xFF000000, 0xFFFFFFFF, 0.7);
        assert_eq!(c.blend, 0.7);

        let c2 = ColorEntry::new(0xFF000000, 0xFFFFFFFF, 1.5);
        assert_eq!(c2.blend, 1.0); // clamped
    }

    #[test]
    fn test_remove_and_clear() {
        let mut view = TraceCodeUnitsView::new("ram", 0);
        view.add_unit(TraceCodeUnit::undefined(0, "ram", 0, 10));
        assert_eq!(view.len(), 1);

        view.remove_unit(0);
        assert!(view.is_empty());

        view.add_unit(TraceCodeUnit::undefined(0, "ram", 0, 10));
        view.clear();
        assert!(view.is_empty());
    }
}
