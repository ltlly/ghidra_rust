//! Relocation fixup handlers for different binary formats.
//!
//! Ported from `ghidra.app.plugin.core.reloc.ElfRelocationFixupHandler`,
//! `Pe32RelocationFixupHandler`, `Pe64RelocationFixupHandler`,
//! `GenericReferenceBaseRelocationFixupHandler`, `InstructionStasher`,
//! `RelocationFixupCommand`, `RelocationFixupHandler`, and
//! `RelocationTableModel`.

use super::{Relocation, RelocationType};
use ghidra_core::Address;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// RelocationFixupHandler trait
// ---------------------------------------------------------------------------

/// Trait for handling relocations in specific binary formats.
///
/// Ported from `ghidra.app.plugin.core.reloc.RelocationFixupHandler`.
pub trait RelocationFixupHandler: Send + Sync + std::fmt::Debug {
    /// The name of this handler.
    fn name(&self) -> &str;

    /// Whether this handler can process relocations for the given format.
    fn can_handle(&self, format: &str) -> bool;

    /// Apply a relocation to the program.
    ///
    /// Returns true if the relocation was successfully applied.
    fn apply_relocation(
        &self,
        relocation: &Relocation,
        image_base: u64,
        delta: i64,
    ) -> RelocationResult;

    /// The binary format this handler supports.
    fn format(&self) -> &str;
}

/// Result of applying a relocation.
#[derive(Debug, Clone)]
pub struct RelocationResult {
    /// Whether the relocation was applied.
    pub applied: bool,
    /// The address that was modified.
    pub address: Address,
    /// The new value written (if any).
    pub new_value: Option<u64>,
    /// Error message if the relocation failed.
    pub error: Option<String>,
}

impl RelocationResult {
    /// Create a successful result.
    pub fn success(address: Address, new_value: u64) -> Self {
        Self {
            applied: true,
            address,
            new_value: Some(new_value),
            error: None,
        }
    }

    /// Create a failure result.
    pub fn failure(address: Address, error: impl Into<String>) -> Self {
        Self {
            applied: false,
            address,
            new_value: None,
            error: Some(error.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// ElfRelocationFixupHandler
// ---------------------------------------------------------------------------

/// Handler for ELF relocations.
///
/// Ported from `ghidra.app.plugin.core.reloc.ElfRelocationFixupHandler`.
#[derive(Debug, Default)]
pub struct ElfRelocationFixupHandler;

impl ElfRelocationFixupHandler {
    /// Create a new ELF relocation handler.
    pub fn new() -> Self {
        Self
    }
}

impl RelocationFixupHandler for ElfRelocationFixupHandler {
    fn name(&self) -> &str {
        "ELF Relocation Fixup"
    }

    fn can_handle(&self, format: &str) -> bool {
        format.eq_ignore_ascii_case("ELF")
    }

    fn apply_relocation(
        &self,
        relocation: &Relocation,
        _image_base: u64,
        delta: i64,
    ) -> RelocationResult {
        match relocation.reloc_type {
            RelocationType::Absolute => {
                let new_val = (relocation.original_value as i64).wrapping_add(delta) as u64;
                RelocationResult::success(relocation.address, new_val)
            }
            RelocationType::Relative => {
                // PC-relative relocations typically don't need adjustment
                RelocationResult::success(relocation.address, relocation.original_value)
            }
            RelocationType::MipsHi16 => {
                // MIPS HI16: adjust upper 16 bits
                let val = relocation.original_value as u32;
                let hi = ((val.wrapping_add(delta as u32) >> 16) & 0xFFFF) as u64;
                RelocationResult::success(relocation.address, hi)
            }
            RelocationType::MipsLo16 => {
                // MIPS LO16: adjust lower 16 bits
                let val = relocation.original_value as u32;
                let lo = (val.wrapping_add(delta as u32) & 0xFFFF) as u64;
                RelocationResult::success(relocation.address, lo)
            }
            _ => RelocationResult::failure(
                relocation.address,
                format!("Unsupported ELF relocation type: {:?}", relocation.reloc_type),
            ),
        }
    }

    fn format(&self) -> &str {
        "ELF"
    }
}

// ---------------------------------------------------------------------------
// Pe32RelocationFixupHandler
// ---------------------------------------------------------------------------

/// Handler for PE32 (32-bit) relocations.
///
/// Ported from `ghidra.app.plugin.core.reloc.Pe32RelocationFixupHandler`.
#[derive(Debug, Default)]
pub struct Pe32RelocationFixupHandler;

impl Pe32RelocationFixupHandler {
    /// Create a new PE32 relocation handler.
    pub fn new() -> Self {
        Self
    }
}

impl RelocationFixupHandler for Pe32RelocationFixupHandler {
    fn name(&self) -> &str {
        "PE32 Relocation Fixup"
    }

    fn can_handle(&self, format: &str) -> bool {
        format.eq_ignore_ascii_case("PE") || format.eq_ignore_ascii_case("PE32")
    }

    fn apply_relocation(
        &self,
        relocation: &Relocation,
        _image_base: u64,
        delta: i64,
    ) -> RelocationResult {
        match relocation.reloc_type {
            RelocationType::Absolute | RelocationType::ImageBaseRelative => {
                // PE32: 32-bit absolute fixup
                let val = relocation.original_value as u32;
                let new_val = (val as i64).wrapping_add(delta) as u32;
                RelocationResult::success(relocation.address, new_val as u64)
            }
            _ => RelocationResult::failure(
                relocation.address,
                format!("Unsupported PE32 relocation type: {:?}", relocation.reloc_type),
            ),
        }
    }

    fn format(&self) -> &str {
        "PE32"
    }
}

// ---------------------------------------------------------------------------
// Pe64RelocationFixupHandler
// ---------------------------------------------------------------------------

/// Handler for PE32+ (64-bit) relocations.
///
/// Ported from `ghidra.app.plugin.core.reloc.Pe64RelocationFixupHandler`.
#[derive(Debug, Default)]
pub struct Pe64RelocationFixupHandler;

impl Pe64RelocationFixupHandler {
    /// Create a new PE64 relocation handler.
    pub fn new() -> Self {
        Self
    }
}

impl RelocationFixupHandler for Pe64RelocationFixupHandler {
    fn name(&self) -> &str {
        "PE64 Relocation Fixup"
    }

    fn can_handle(&self, format: &str) -> bool {
        format.eq_ignore_ascii_case("PE64") || format.eq_ignore_ascii_case("PE32+")
    }

    fn apply_relocation(
        &self,
        relocation: &Relocation,
        _image_base: u64,
        delta: i64,
    ) -> RelocationResult {
        match relocation.reloc_type {
            RelocationType::Absolute | RelocationType::ImageBaseRelative => {
                let new_val = (relocation.original_value as i64).wrapping_add(delta) as u64;
                RelocationResult::success(relocation.address, new_val)
            }
            _ => RelocationResult::failure(
                relocation.address,
                format!("Unsupported PE64 relocation type: {:?}", relocation.reloc_type),
            ),
        }
    }

    fn format(&self) -> &str {
        "PE64"
    }
}

// ---------------------------------------------------------------------------
// GenericReferenceBaseRelocationFixupHandler
// ---------------------------------------------------------------------------

/// Generic handler for reference-based relocations.
///
/// Ported from `ghidra.app.plugin.core.reloc.GenericReferenceBaseRelocationFixupHandler`.
#[derive(Debug, Default)]
pub struct GenericReferenceBaseRelocationFixupHandler;

impl GenericReferenceBaseRelocationFixupHandler {
    /// Create a new generic relocation handler.
    pub fn new() -> Self {
        Self
    }
}

impl RelocationFixupHandler for GenericReferenceBaseRelocationFixupHandler {
    fn name(&self) -> &str {
        "Generic Reference-Based Relocation Fixup"
    }

    fn can_handle(&self, _format: &str) -> bool {
        true // Fallback handler
    }

    fn apply_relocation(
        &self,
        relocation: &Relocation,
        _image_base: u64,
        delta: i64,
    ) -> RelocationResult {
        let new_val = (relocation.original_value as i64).wrapping_add(delta) as u64;
        RelocationResult::success(relocation.address, new_val)
    }

    fn format(&self) -> &str {
        "Generic"
    }
}

// ---------------------------------------------------------------------------
// InstructionStasher
// ---------------------------------------------------------------------------

/// Saves and restores instruction bytes around relocation fixups.
///
/// Ported from `ghidra.app.plugin.core.reloc.InstructionStasher`.
#[derive(Debug, Default)]
pub struct InstructionStasher {
    /// Stashed bytes: address -> original bytes.
    stashed: BTreeMap<u64, Vec<u8>>,
}

impl InstructionStasher {
    /// Create a new instruction stasher.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stash the bytes at the given address.
    pub fn stash(&mut self, address: Address, bytes: Vec<u8>) {
        self.stashed.insert(address.offset, bytes);
    }

    /// Restore the stashed bytes for an address.
    pub fn restore(&mut self, address: Address) -> Option<Vec<u8>> {
        self.stashed.remove(&address.offset)
    }

    /// Check if bytes are stashed for an address.
    pub fn has_stash(&self, address: Address) -> bool {
        self.stashed.contains_key(&address.offset)
    }

    /// Get the number of stashed entries.
    pub fn stash_count(&self) -> usize {
        self.stashed.len()
    }

    /// Clear all stashed bytes.
    pub fn clear(&mut self) {
        self.stashed.clear();
    }
}

// ---------------------------------------------------------------------------
// RelocationFixupCommand
// ---------------------------------------------------------------------------

/// Command to apply a relocation fixup.
///
/// Ported from `ghidra.app.plugin.core.reloc.RelocationFixupCommand`.
#[derive(Debug, Clone)]
pub struct RelocationFixupCommand {
    /// The relocation to apply.
    pub relocation: Relocation,
    /// The image base address.
    pub image_base: u64,
    /// The delta (new base - old base).
    pub delta: i64,
    /// Whether the command has been applied.
    applied: bool,
    result: Option<RelocationResult>,
}

impl RelocationFixupCommand {
    /// Create a new relocation fixup command.
    pub fn new(relocation: Relocation, image_base: u64, delta: i64) -> Self {
        Self {
            relocation,
            image_base,
            delta,
            applied: false,
            result: None,
        }
    }

    /// Apply the relocation using the given handler.
    pub fn apply<H: RelocationFixupHandler>(&mut self, handler: &H) -> &RelocationResult {
        self.result = Some(handler.apply_relocation(&self.relocation, self.image_base, self.delta));
        self.applied = true;
        self.result.as_ref().unwrap()
    }

    /// Whether the command has been applied.
    pub fn is_applied(&self) -> bool {
        self.applied
    }

    /// Get the result.
    pub fn result(&self) -> Option<&RelocationResult> {
        self.result.as_ref()
    }
}

// ---------------------------------------------------------------------------
// RelocationTableModel
// ---------------------------------------------------------------------------

/// Table model for displaying relocations.
///
/// Ported from `ghidra.app.plugin.core.reloc.RelocationTableModel`.
#[derive(Debug)]
pub struct RelocationTableModel {
    /// All relocations.
    relocations: Vec<Relocation>,
    /// Sort column index.
    sort_column: usize,
    /// Sort ascending.
    sort_ascending: bool,
}

impl RelocationTableModel {
    /// Column index for the address.
    pub const COL_ADDRESS: usize = 0;
    /// Column index for the type.
    pub const COL_TYPE: usize = 1;
    /// Column index for the original value.
    pub const COL_VALUE: usize = 2;
    /// Column index for the symbol name.
    pub const COL_SYMBOL: usize = 3;

    /// Create a new table model.
    pub fn new() -> Self {
        Self {
            relocations: Vec::new(),
            sort_column: Self::COL_ADDRESS,
            sort_ascending: true,
        }
    }

    /// Add a relocation.
    pub fn add(&mut self, relocation: Relocation) {
        self.relocations.push(relocation);
    }

    /// Get the number of relocations.
    pub fn len(&self) -> usize {
        self.relocations.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.relocations.is_empty()
    }

    /// Get a relocation by index.
    pub fn get(&self, index: usize) -> Option<&Relocation> {
        self.relocations.get(index)
    }

    /// Get all relocations.
    pub fn relocations(&self) -> &[Relocation] {
        &self.relocations
    }

    /// Sort by address.
    pub fn sort_by_address(&mut self) {
        self.relocations
            .sort_by_key(|r| r.address.offset);
    }

    /// Sort by type.
    pub fn sort_by_type(&mut self) {
        self.relocations.sort_by_key(|r| format!("{:?}", r.reloc_type));
    }

    /// Get the column names.
    pub fn column_names() -> &'static [&'static str] {
        &["Address", "Type", "Original Value", "Symbol"]
    }

    /// Get a cell value as string.
    pub fn cell_value(&self, row: usize, col: usize) -> Option<String> {
        let reloc = self.relocations.get(row)?;
        Some(match col {
            Self::COL_ADDRESS => format!("0x{:08X}", reloc.address.offset),
            Self::COL_TYPE => format!("{:?}", reloc.reloc_type),
            Self::COL_VALUE => format!("0x{:016X}", reloc.original_value),
            Self::COL_SYMBOL => reloc
                .symbol_name
                .clone()
                .unwrap_or_else(|| "-".to_string()),
            _ => return None,
        })
    }
}

impl Default for RelocationTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_reloc(addr: u64, rtype: RelocationType) -> Relocation {
        Relocation::new(Address::new(addr), rtype, 0x1000)
    }

    #[test]
    fn test_elf_handler() {
        let handler = ElfRelocationFixupHandler::new();
        assert_eq!(handler.name(), "ELF Relocation Fixup");
        assert!(handler.can_handle("ELF"));
        assert!(!handler.can_handle("PE"));

        let reloc = sample_reloc(0x400000, RelocationType::Absolute);
        let result = handler.apply_relocation(&reloc, 0x400000, 0x1000);
        assert!(result.applied);
        assert_eq!(result.new_value, Some(0x2000));
    }

    #[test]
    fn test_elf_handler_mips() {
        let handler = ElfRelocationFixupHandler::new();
        let reloc = Relocation::new(Address::new(0x1000), RelocationType::MipsHi16, 0x00010000);
        let result = handler.apply_relocation(&reloc, 0, 0x5000);
        assert!(result.applied);
    }

    #[test]
    fn test_pe32_handler() {
        let handler = Pe32RelocationFixupHandler::new();
        assert!(handler.can_handle("PE"));
        assert!(handler.can_handle("PE32"));

        let reloc = sample_reloc(0x400000, RelocationType::ImageBaseRelative);
        let result = handler.apply_relocation(&reloc, 0x400000, 0x10000000);
        assert!(result.applied);
    }

    #[test]
    fn test_pe64_handler() {
        let handler = Pe64RelocationFixupHandler::new();
        assert!(handler.can_handle("PE64"));
        assert!(handler.can_handle("PE32+"));

        let reloc = sample_reloc(0x140000000, RelocationType::ImageBaseRelative);
        let result = handler.apply_relocation(&reloc, 0x140000000, 0x100000);
        assert!(result.applied);
    }

    #[test]
    fn test_generic_handler() {
        let handler = GenericReferenceBaseRelocationFixupHandler::new();
        assert!(handler.can_handle("anything")); // Fallback

        let reloc = sample_reloc(0x1000, RelocationType::Pointer);
        let result = handler.apply_relocation(&reloc, 0, 0x100);
        assert!(result.applied);
    }

    #[test]
    fn test_relocation_result() {
        let success = RelocationResult::success(Address::new(0x1000), 0x2000);
        assert!(success.applied);
        assert_eq!(success.new_value, Some(0x2000));
        assert!(success.error.is_none());

        let failure = RelocationResult::failure(Address::new(0x1000), "bad reloc");
        assert!(!failure.applied);
        assert!(failure.new_value.is_none());
        assert_eq!(failure.error.as_deref(), Some("bad reloc"));
    }

    #[test]
    fn test_instruction_stasher() {
        let mut stasher = InstructionStasher::new();
        assert_eq!(stasher.stash_count(), 0);

        stasher.stash(Address::new(0x1000), vec![0x48, 0x89, 0xE5]);
        assert!(stasher.has_stash(Address::new(0x1000)));
        assert_eq!(stasher.stash_count(), 1);

        let bytes = stasher.restore(Address::new(0x1000));
        assert_eq!(bytes, Some(vec![0x48, 0x89, 0xE5]));
        assert!(!stasher.has_stash(Address::new(0x1000)));

        stasher.stash(Address::new(0x2000), vec![0x90]);
        stasher.clear();
        assert_eq!(stasher.stash_count(), 0);
    }

    #[test]
    fn test_relocation_fixup_command() {
        let reloc = sample_reloc(0x400000, RelocationType::Absolute);
        let mut cmd = RelocationFixupCommand::new(reloc, 0x400000, 0x10000000);
        assert!(!cmd.is_applied());

        let handler = ElfRelocationFixupHandler::new();
        let result = cmd.apply(&handler);
        assert!(result.applied);
        assert!(cmd.is_applied());
        assert!(cmd.result().is_some());
    }

    #[test]
    fn test_relocation_table_model() {
        let mut model = RelocationTableModel::new();
        assert!(model.is_empty());

        model.add(sample_reloc(0x3000, RelocationType::Absolute));
        model.add(sample_reloc(0x1000, RelocationType::Relative));
        model.add(sample_reloc(0x2000, RelocationType::Pointer));
        assert_eq!(model.len(), 3);

        model.sort_by_address();
        assert_eq!(model.get(0).unwrap().address.offset, 0x1000);
        assert_eq!(model.get(2).unwrap().address.offset, 0x3000);

        // Test cell values
        assert_eq!(
            model.cell_value(0, RelocationTableModel::COL_ADDRESS),
            Some("0x00001000".to_string())
        );
        assert_eq!(
            model.cell_value(0, RelocationTableModel::COL_SYMBOL),
            Some("-".to_string())
        );
        assert_eq!(model.cell_value(99, 0), None);
    }

    #[test]
    fn test_table_model_column_names() {
        let names = RelocationTableModel::column_names();
        assert_eq!(names.len(), 4);
        assert_eq!(names[0], "Address");
    }

    #[test]
    fn test_elf_handler_unsupported_type() {
        let handler = ElfRelocationFixupHandler::new();
        let reloc = sample_reloc(0x1000, RelocationType::Unknown);
        let result = handler.apply_relocation(&reloc, 0, 0);
        assert!(!result.applied);
        assert!(result.error.is_some());
    }
}
