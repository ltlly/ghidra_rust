//! Bit-field editor dialog model.
//!
//! Ported from `ghidra.app.plugin.core.compositeeditor.BitFieldEditorDialog`
//! and `BitFieldEditorPanel`.
//!
//! Provides the data model for the bit-field editor dialog, which allows
//! users to create and edit bit-field components within a composite type.

use super::BitFieldEditorModel;

/// State of the bit-field editor dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitFieldDialogState {
    /// Dialog is in add mode (creating a new bit-field).
    Add,
    /// Dialog is in edit mode (modifying an existing bit-field).
    Edit,
    /// Dialog is in view mode (read-only).
    View,
}

/// A row in the bit-field allocation table.
///
/// Ported from `BitFieldPlacementComponent.BitFieldAllocation`.
#[derive(Debug, Clone)]
pub struct BitFieldAllocation {
    /// The bit-field name.
    pub name: String,
    /// The bit offset from the start of the storage unit.
    pub bit_offset: u32,
    /// The bit size of this allocation.
    pub bit_size: u32,
    /// The base data type mnemonic (e.g., "uint", "int", "bool").
    pub base_type: String,
    /// Whether this allocation is currently selected.
    pub selected: bool,
    /// The ordinal index.
    pub ordinal: usize,
}

impl BitFieldAllocation {
    /// Create a new allocation.
    pub fn new(
        name: impl Into<String>,
        bit_offset: u32,
        bit_size: u32,
        base_type: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            bit_offset,
            bit_size,
            base_type: base_type.into(),
            selected: false,
            ordinal: 0,
        }
    }

    /// End bit position (exclusive).
    pub fn end_bit(&self) -> u32 {
        self.bit_offset + self.bit_size
    }

    /// Whether this allocation overlaps with another.
    pub fn overlaps(&self, other: &BitFieldAllocation) -> bool {
        self.bit_offset < other.end_bit() && other.bit_offset < self.end_bit()
    }
}

/// Model for the bit-field editor dialog.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.BitFieldEditorDialog`.
#[derive(Debug)]
pub struct BitFieldDialogModel {
    /// The dialog state.
    pub state: BitFieldDialogState,
    /// The bit-field being edited.
    pub bitfield: BitFieldEditorModel,
    /// Allocations in the current storage unit.
    allocations: Vec<BitFieldAllocation>,
    /// The storage unit size in bytes.
    pub storage_size: u32,
    /// The number of bits per byte (usually 8).
    pub bits_per_byte: u32,
    /// Whether to show big-endian bit numbering.
    pub big_endian: bool,
    /// The selected allocation index.
    selected: Option<usize>,
}

impl BitFieldDialogModel {
    /// Create a new dialog model.
    pub fn new(storage_size: u32) -> Self {
        Self {
            state: BitFieldDialogState::Add,
            bitfield: BitFieldEditorModel::new("", "uint", 1, 0),
            allocations: Vec::new(),
            storage_size,
            bits_per_byte: 8,
            big_endian: false,
            selected: None,
        }
    }

    /// The total number of bits in the storage unit.
    pub fn total_bits(&self) -> u32 {
        self.storage_size * self.bits_per_byte
    }

    /// Add an allocation.
    pub fn add_allocation(&mut self, alloc: BitFieldAllocation) {
        let ordinal = self.allocations.len();
        let mut alloc = alloc;
        alloc.ordinal = ordinal;
        self.allocations.push(alloc);
    }

    /// Remove an allocation by index.
    pub fn remove_allocation(&mut self, index: usize) -> Option<BitFieldAllocation> {
        if index < self.allocations.len() {
            let removed = self.allocations.remove(index);
            self.reindex();
            Some(removed)
        } else {
            None
        }
    }

    /// Get all allocations.
    pub fn allocations(&self) -> &[BitFieldAllocation] {
        &self.allocations
    }

    /// Select an allocation.
    pub fn select(&mut self, index: usize) {
        if index < self.allocations.len() {
            if let Some(prev) = self.selected {
                if prev < self.allocations.len() {
                    self.allocations[prev].selected = false;
                }
            }
            self.allocations[index].selected = true;
            self.selected = Some(index);
        }
    }

    /// Get the selected allocation.
    pub fn selected_allocation(&self) -> Option<&BitFieldAllocation> {
        self.selected.and_then(|i| self.allocations.get(i))
    }

    /// Check if the current bit-field model is valid.
    pub fn is_valid(&self) -> bool {
        if !self.bitfield.valid {
            return false;
        }
        // Check bounds
        if self.bitfield.end_bit() > self.total_bits() {
            return false;
        }
        // Check overlaps with existing allocations
        let new_alloc = BitFieldAllocation::new(
            &self.bitfield.name,
            self.bitfield.bit_offset,
            self.bitfield.bit_size,
            &self.bitfield.base_type,
        );
        for existing in &self.allocations {
            if existing.overlaps(&new_alloc) {
                // Allow overlap if editing the same allocation
                if self.state == BitFieldDialogState::Edit
                    && self.selected == Some(existing.ordinal)
                {
                    continue;
                }
                return false;
            }
        }
        true
    }

    /// Get unallocated bit ranges.
    pub fn unallocated_bits(&self) -> Vec<(u32, u32)> {
        let total = self.total_bits();
        let mut used = vec![false; total as usize];
        for alloc in &self.allocations {
            for bit in alloc.bit_offset..alloc.end_bit() {
                if (bit as usize) < used.len() {
                    used[bit as usize] = true;
                }
            }
        }

        let mut ranges = Vec::new();
        let mut start = None;
        for (i, &is_used) in used.iter().enumerate() {
            if !is_used && start.is_none() {
                start = Some(i as u32);
            } else if is_used && start.is_some() {
                ranges.push((start.unwrap(), i as u32));
                start = None;
            }
        }
        if let Some(s) = start {
            ranges.push((s, total));
        }
        ranges
    }

    fn reindex(&mut self) {
        for (i, alloc) in self.allocations.iter_mut().enumerate() {
            alloc.ordinal = i;
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitfield_allocation() {
        let a = BitFieldAllocation::new("flags", 0, 3, "uint");
        assert_eq!(a.end_bit(), 3);
        assert!(!a.overlaps(&BitFieldAllocation::new("other", 3, 5, "uint")));
        assert!(a.overlaps(&BitFieldAllocation::new("overlap", 2, 3, "uint")));
    }

    #[test]
    fn test_bitfield_dialog_model_lifecycle() {
        let mut model = BitFieldDialogModel::new(4); // 4 bytes = 32 bits
        assert_eq!(model.total_bits(), 32);
        assert_eq!(model.allocations().len(), 0);

        model.add_allocation(BitFieldAllocation::new("flags", 0, 3, "uint"));
        model.add_allocation(BitFieldAllocation::new("type", 3, 5, "uint"));
        assert_eq!(model.allocations().len(), 2);
    }

    #[test]
    fn test_bitfield_dialog_model_remove() {
        let mut model = BitFieldDialogModel::new(4);
        model.add_allocation(BitFieldAllocation::new("a", 0, 3, "uint"));
        model.add_allocation(BitFieldAllocation::new("b", 3, 5, "uint"));

        model.remove_allocation(0);
        assert_eq!(model.allocations().len(), 1);
        assert_eq!(model.allocations()[0].name, "b");
        assert_eq!(model.allocations()[0].ordinal, 0);
    }

    #[test]
    fn test_bitfield_dialog_model_select() {
        let mut model = BitFieldDialogModel::new(4);
        model.add_allocation(BitFieldAllocation::new("a", 0, 3, "uint"));
        model.add_allocation(BitFieldAllocation::new("b", 3, 5, "uint"));

        model.select(0);
        assert!(model.selected_allocation().is_some());
        assert_eq!(model.selected_allocation().unwrap().name, "a");

        model.select(1);
        assert_eq!(model.selected_allocation().unwrap().name, "b");
        // Previous should be deselected
        assert!(!model.allocations()[0].selected);
    }

    #[test]
    fn test_bitfield_dialog_model_unallocated_bits() {
        let mut model = BitFieldDialogModel::new(1); // 8 bits
        model.add_allocation(BitFieldAllocation::new("a", 0, 3, "uint"));

        let ranges = model.unallocated_bits();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], (3, 8));
    }

    #[test]
    fn test_bitfield_dialog_model_unallocated_multiple() {
        let mut model = BitFieldDialogModel::new(1); // 8 bits
        model.add_allocation(BitFieldAllocation::new("a", 1, 2, "uint")); // bits 1-2
        model.add_allocation(BitFieldAllocation::new("b", 5, 2, "uint")); // bits 5-6

        let ranges = model.unallocated_bits();
        // unused: bit 0, bits 3-4, bit 7
        // Ranges: (0,1), (3,5), (7,8)
        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges[0], (0, 1));
        assert_eq!(ranges[1], (3, 5));
        assert_eq!(ranges[2], (7, 8));
    }

    #[test]
    fn test_bitfield_dialog_model_validation() {
        let mut model = BitFieldDialogModel::new(1); // 8 bits
        model.bitfield = BitFieldEditorModel::new("new_field", "uint", 3, 0);
        assert!(model.is_valid());

        // Out of bounds
        model.bitfield = BitFieldEditorModel::new("bad", "uint", 3, 7);
        assert!(!model.is_valid()); // 7+3=10 > 8

        // Zero size
        model.bitfield = BitFieldEditorModel::new("zero", "uint", 0, 0);
        assert!(!model.is_valid());
    }

    #[test]
    fn test_bitfield_dialog_model_validation_overlap() {
        let mut model = BitFieldDialogModel::new(1); // 8 bits
        model.add_allocation(BitFieldAllocation::new("existing", 0, 4, "uint"));

        // Try to add overlapping
        model.bitfield = BitFieldEditorModel::new("new", "uint", 3, 2);
        assert!(!model.is_valid());

        // Non-overlapping should work
        model.bitfield = BitFieldEditorModel::new("new", "uint", 3, 4);
        assert!(model.is_valid());
    }

    #[test]
    fn test_bitfield_dialog_state() {
        assert_ne!(BitFieldDialogState::Add, BitFieldDialogState::Edit);
        assert_ne!(BitFieldDialogState::Edit, BitFieldDialogState::View);
    }
}
