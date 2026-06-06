//! Relocation Fixup -- manage and apply program relocations.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.reloc` Java package.
//!
//! Handles relocation entries in loaded programs. When a binary is loaded
//! at a base address different from its link-time address, relocations must
//! be applied to fix up absolute references.
//!
//! # Architecture
//!
//! - [`Relocation`] -- a single relocation entry.
//! - [`RelocationType`] -- the type of relocation (absolute, relative, etc.).
//! - [`RelocationTable`] -- manages all relocations in a program.
//! - [`RelocationFixupModel`] -- the business logic for relocation operations.

/// Relocation table plugin, fixup handler, and table model.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.reloc` Java package.
pub mod plugin;

/// Relocation fixup handlers for ELF, PE32, PE64, and generic formats.
///
/// Ported from `ghidra.app.plugin.core.reloc.ElfRelocationFixupHandler`,
/// `Pe32RelocationFixupHandler`, `Pe64RelocationFixupHandler`,
/// `GenericReferenceBaseRelocationFixupHandler`, `InstructionStasher`,
/// `RelocationFixupCommand`, and `RelocationTableModel`.
pub mod handlers;

use ghidra_core::Address;
use std::collections::BTreeMap;

// ============================================================================
// RelocationType -- type of relocation
// ============================================================================

/// The type of a relocation entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelocationType {
    /// Absolute address fixup (add delta to value at address).
    Absolute,
    /// Relative address fixup (add delta to PC-relative value).
    Relative,
    /// Imagebase-relative fixup.
    ImageBaseRelative,
    /// A pointer-sized value that needs adjustment.
    Pointer,
    /// A MIPS-specific relocation.
    MipsHi16,
    /// A MIPS-specific relocation (low 16 bits).
    MipsLo16,
    /// Unknown / unhandled relocation type.
    Unknown,
}

impl RelocationType {
    /// Whether this relocation is a standard absolute fixup.
    pub fn is_absolute(&self) -> bool {
        matches!(self, Self::Absolute | Self::ImageBaseRelative | Self::Pointer)
    }
}

// ============================================================================
// Relocation -- a single relocation entry
// ============================================================================

/// A single relocation entry at an address.
#[derive(Debug, Clone)]
pub struct Relocation {
    /// The address where the relocation applies.
    pub address: Address,
    /// The type of relocation.
    pub reloc_type: RelocationType,
    /// The original value at this address (before relocation).
    pub original_value: u64,
    /// The symbol name this relocation refers to (if known).
    pub symbol_name: Option<String>,
    /// The addend for the relocation.
    pub addend: i64,
}

impl Relocation {
    /// Create a new relocation.
    pub fn new(
        address: Address,
        reloc_type: RelocationType,
        original_value: u64,
    ) -> Self {
        Self {
            address,
            reloc_type,
            original_value,
            symbol_name: None,
            addend: 0,
        }
    }

    /// Create a relocation with a symbol name.
    pub fn with_symbol(mut self, name: impl Into<String>) -> Self {
        self.symbol_name = Some(name.into());
        self
    }

    /// Create a relocation with an addend.
    pub fn with_addend(mut self, addend: i64) -> Self {
        self.addend = addend;
        self
    }
}

// ============================================================================
// RelocationTable -- manages all relocations
// ============================================================================

/// Manages relocation entries for a program.
#[derive(Debug, Default)]
pub struct RelocationTable {
    /// Relocation entries keyed by address offset.
    relocations: BTreeMap<u64, Relocation>,
}

impl RelocationTable {
    /// Create a new empty relocation table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a relocation entry.
    pub fn add(&mut self, relocation: Relocation) {
        self.relocations
            .insert(relocation.address.offset, relocation);
    }

    /// Remove the relocation at the given address.
    pub fn remove(&mut self, address: Address) -> Option<Relocation> {
        self.relocations.remove(&address.offset)
    }

    /// Get the relocation at the given address.
    pub fn get(&self, address: Address) -> Option<&Relocation> {
        self.relocations.get(&address.offset)
    }

    /// Get all relocations.
    pub fn get_all(&self) -> Vec<&Relocation> {
        self.relocations.values().collect()
    }

    /// Return the number of relocation entries.
    pub fn count(&self) -> usize {
        self.relocations.len()
    }

    /// Get relocations in an address range.
    pub fn get_in_range(&self, start: Address, end: Address) -> Vec<&Relocation> {
        self.relocations
            .range(start.offset..=end.offset)
            .map(|(_, r)| r)
            .collect()
    }

    /// Apply a base address delta to all relocations of absolute type.
    ///
    /// Returns the number of relocations modified.
    pub fn apply_base_delta(&mut self, delta: i64) -> usize {
        let mut count = 0;
        for reloc in self.relocations.values_mut() {
            if reloc.reloc_type.is_absolute() {
                if delta >= 0 {
                    reloc.original_value = reloc.original_value.wrapping_add(delta as u64);
                } else {
                    reloc.original_value = reloc.original_value.wrapping_sub((-delta) as u64);
                }
                count += 1;
            }
        }
        count
    }
}

// ============================================================================
// RelocationFixupModel -- business logic for relocation fixup
// ============================================================================

/// Business logic for managing relocations during load.
#[derive(Debug)]
pub struct RelocationFixupModel {
    /// The relocation table.
    table: RelocationTable,
    /// Whether the model has been modified.
    dirty: bool,
}

impl RelocationFixupModel {
    /// Create a new relocation fixup model.
    pub fn new() -> Self {
        Self {
            table: RelocationTable::new(),
            dirty: false,
        }
    }

    /// Add a relocation to the model.
    pub fn add_relocation(&mut self, relocation: Relocation) {
        self.table.add(relocation);
        self.dirty = true;
    }

    /// Get the underlying relocation table.
    pub fn table(&self) -> &RelocationTable {
        &self.table
    }

    /// Get mutable access to the relocation table.
    pub fn table_mut(&mut self) -> &mut RelocationTable {
        &mut self.table
    }

    /// Whether the model has been modified since creation.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Clear the dirty flag.
    pub fn clear_dirty(&mut self) {
        self.dirty = false;
    }

    /// Apply relocations for a given image base change.
    pub fn apply_image_base_change(&mut self, old_base: u64, new_base: u64) {
        let delta = new_base as i64 - old_base as i64;
        let count = self.table.apply_base_delta(delta);
        if count > 0 {
            self.dirty = true;
        }
    }
}

impl Default for RelocationFixupModel {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get_relocation() {
        let mut table = RelocationTable::new();
        table.add(Relocation::new(Address::new(0x1000), RelocationType::Absolute, 0x401000));
        assert_eq!(table.count(), 1);
        let r = table.get(Address::new(0x1000)).unwrap();
        assert_eq!(r.original_value, 0x401000);
    }

    #[test]
    fn test_relocation_with_symbol() {
        let mut table = RelocationTable::new();
        table.add(
            Relocation::new(Address::new(0x1000), RelocationType::Absolute, 0)
                .with_symbol("printf")
                .with_addend(0x10),
        );
        let r = table.get(Address::new(0x1000)).unwrap();
        assert_eq!(r.symbol_name.as_deref(), Some("printf"));
        assert_eq!(r.addend, 0x10);
    }

    #[test]
    fn test_remove_relocation() {
        let mut table = RelocationTable::new();
        table.add(Relocation::new(Address::new(0x1000), RelocationType::Absolute, 0));
        assert!(table.remove(Address::new(0x1000)).is_some());
        assert_eq!(table.count(), 0);
    }

    #[test]
    fn test_get_in_range() {
        let mut table = RelocationTable::new();
        table.add(Relocation::new(Address::new(0x1000), RelocationType::Absolute, 0));
        table.add(Relocation::new(Address::new(0x1004), RelocationType::Absolute, 0));
        table.add(Relocation::new(Address::new(0x2000), RelocationType::Absolute, 0));
        let in_range = table.get_in_range(Address::new(0x1000), Address::new(0x1FFF));
        assert_eq!(in_range.len(), 2);
    }

    #[test]
    fn test_apply_base_delta() {
        let mut table = RelocationTable::new();
        table.add(Relocation::new(Address::new(0x1000), RelocationType::Absolute, 0x401000));
        table.add(Relocation::new(Address::new(0x1004), RelocationType::Unknown, 0x402000));
        let count = table.apply_base_delta(0x1000);
        assert_eq!(count, 1);
        let r = table.get(Address::new(0x1000)).unwrap();
        assert_eq!(r.original_value, 0x402000);
        // Unknown type should not be modified
        let r = table.get(Address::new(0x1004)).unwrap();
        assert_eq!(r.original_value, 0x402000);
    }

    #[test]
    fn test_apply_base_delta_negative() {
        let mut table = RelocationTable::new();
        table.add(Relocation::new(Address::new(0x1000), RelocationType::Absolute, 0x402000));
        table.apply_base_delta(-0x1000);
        let r = table.get(Address::new(0x1000)).unwrap();
        assert_eq!(r.original_value, 0x401000);
    }

    #[test]
    fn test_fixup_model_image_base_change() {
        let mut model = RelocationFixupModel::new();
        model.add_relocation(Relocation::new(
            Address::new(0x1000),
            RelocationType::Absolute,
            0x401000,
        ));
        model.apply_image_base_change(0x400000, 0x500000);
        assert!(model.is_dirty());
        let r = model.table().get(Address::new(0x1000)).unwrap();
        assert_eq!(r.original_value, 0x501000);
    }

    #[test]
    fn test_relocation_type_is_absolute() {
        assert!(RelocationType::Absolute.is_absolute());
        assert!(RelocationType::Pointer.is_absolute());
        assert!(!RelocationType::Relative.is_absolute());
        assert!(!RelocationType::Unknown.is_absolute());
    }
}
