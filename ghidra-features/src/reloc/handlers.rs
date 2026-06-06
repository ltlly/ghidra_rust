//! Relocation fixup handlers for different binary formats.
//!
//! Ported from `ghidra.app.plugin.core.reloc.ElfRelocationFixupHandler`,
//! `Pe32RelocationFixupHandler`, `Pe64RelocationFixupHandler`,
//! `GenericReferenceBaseRelocationFixupHandler`, `InstructionStasher`,
//! `RelocationFixupCommand`, `RelocationFixupHandler`, and
//! `RelocationRowTableModel`.

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

    /// Create a failed result.
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
// Relocation row object -- for the table model
// ---------------------------------------------------------------------------

/// A row in the relocation table UI.
///
/// Ported from `RelocationRowTableModel.RelocationRowObject`.
#[derive(Debug, Clone)]
pub struct RelocationRowObject {
    /// The relocation index (used to disambiguate multiple relocations at the same address).
    pub relocation_index: u32,
    /// The relocation data.
    pub relocation: Relocation,
    /// Status string ("Applied", "Pending", "Error").
    pub status: String,
}

impl RelocationRowObject {
    /// Create a new relocation row object.
    pub fn new(relocation: Relocation, relocation_index: u32) -> Self {
        Self {
            relocation_index,
            relocation,
            status: "Pending".to_string(),
        }
    }

    /// Get the address.
    pub fn address(&self) -> Address {
        self.relocation.address
    }

    /// Get a display string for the relocation values.
    pub fn values_display(&self) -> String {
        format!("0x{:X}", self.relocation.original_value)
    }

    /// Get original bytes as hex string.
    pub fn original_bytes_hex(&self) -> String {
        format_bytes(self.relocation.original_value, 4)
    }

    /// Get the relocation type as a hex string.
    pub fn type_hex(&self) -> String {
        format!("0x{:X}", self.relocation.reloc_type as u32)
    }
}

impl PartialEq for RelocationRowObject {
    fn eq(&self, other: &Self) -> bool {
        self.relocation.address == other.relocation.address
            && self.relocation_index == other.relocation_index
    }
}
impl Eq for RelocationRowObject {}

impl PartialOrd for RelocationRowObject {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RelocationRowObject {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.relocation
            .address
            .offset
            .cmp(&other.relocation.address.offset)
            .then_with(|| self.relocation_index.cmp(&other.relocation_index))
    }
}

/// Format a u64 value as a hex byte string.
///
/// Ported from `RelocationRowTableModel.formatBytes()`.
pub fn format_bytes(value: u64, num_bytes: usize) -> String {
    let mut result = String::new();
    for i in 0..num_bytes {
        if i > 0 {
            result.push(' ');
        }
        let byte = ((value >> (i * 8)) & 0xFF) as u8;
        result.push_str(&format!("{:02x}", byte));
    }
    result
}

// ---------------------------------------------------------------------------
// InstructionStasher -- saves/restores instruction data during relocation
// ---------------------------------------------------------------------------

/// Saves instruction state before relocation and restores it after.
///
/// Ported from `ghidra.app.plugin.core.reloc.InstructionStasher`.
///
/// When applying relocations, the original instruction data may be clobbered.
/// The stasher saves the instruction prototype, references, and flow override
/// so they can be restored after the relocation is applied.
#[derive(Debug, Clone)]
pub struct InstructionStasher {
    /// The address of the stashed instruction.
    pub address: Address,
    /// The instruction mnemonic (saved for restoration).
    pub mnemonic: String,
    /// The instruction length in bytes.
    pub length: usize,
    /// Saved flow override.
    pub flow_override: Option<FlowOverride>,
    /// Saved fallthrough override address.
    pub fallthrough_override: Option<Address>,
    /// Whether the stash contains valid data.
    pub valid: bool,
}

/// Flow override types for instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowOverride {
    /// No override.
    None,
    /// Override to call.
    Call,
    /// Override to call-return.
    CallReturn,
    /// Override to jump.
    Jump,
    /// Override to return.
    Return,
}

impl InstructionStasher {
    /// Create a new empty instruction stasher.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            mnemonic: String::new(),
            length: 0,
            flow_override: None,
            fallthrough_override: None,
            valid: false,
        }
    }

    /// Stash instruction data at the given address.
    pub fn stash(&mut self, mnemonic: impl Into<String>, length: usize) {
        self.mnemonic = mnemonic.into();
        self.length = length;
        self.valid = true;
    }

    /// Whether the stash has valid data.
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Clear the stash.
    pub fn clear(&mut self) {
        self.mnemonic.clear();
        self.length = 0;
        self.flow_override = None;
        self.fallthrough_override = None;
        self.valid = false;
    }
}

// ---------------------------------------------------------------------------
// RelocationToAddressMapper -- maps rows to addresses
// ---------------------------------------------------------------------------

/// Maps a [`RelocationRowObject`] to its address.
///
/// Ported from `RelocationToAddressTableRowMapper`.
#[derive(Debug, Clone, Copy)]
pub struct RelocationToAddressMapper;

impl RelocationToAddressMapper {
    /// Map a relocation row to its address.
    pub fn map(row: &RelocationRowObject) -> Address {
        row.relocation.address
    }
}

// ---------------------------------------------------------------------------
// RelocationRowTableModel -- table model for relocation entries
// ---------------------------------------------------------------------------

/// Column names for the relocation table.
pub mod columns {
    /// Status column.
    pub const STATUS: &str = "Status";
    /// Type column.
    pub const TYPE: &str = "Type";
    /// Values column.
    pub const VALUES: &str = "Values";
    /// Original bytes column.
    pub const ORIGINAL_BYTES: &str = "Original Bytes";
    /// Current bytes column.
    pub const CURRENT_BYTES: &str = "Current Bytes";
    /// Name column.
    pub const NAME: &str = "Name";
}

/// Detailed table model for displaying relocation entries with row objects.
///
/// Ported from `ghidra.app.plugin.core.reloc.RelocationRowTableModel` (the
/// full row-based variant used by the fixup handler).
#[derive(Debug)]
pub struct RelocationRowTableModel {
    /// Row objects sorted by address.
    rows: Vec<RelocationRowObject>,
    /// Whether the model is loaded.
    loaded: bool,
    /// The program name.
    program_name: String,
}

impl RelocationRowTableModel {
    /// Create a new empty relocation table model.
    pub fn new(program_name: impl Into<String>) -> Self {
        Self {
            rows: Vec::new(),
            loaded: false,
            program_name: program_name.into(),
        }
    }

    /// Load relocations into the model.
    pub fn load(&mut self, relocations: Vec<Relocation>) {
        self.rows.clear();
        for (i, reloc) in relocations.into_iter().enumerate() {
            self.rows
                .push(RelocationRowObject::new(reloc, i as u32));
        }
        self.rows.sort();
        self.loaded = true;
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get a row by index.
    pub fn get_row(&self, index: usize) -> Option<&RelocationRowObject> {
        self.rows.get(index)
    }

    /// Get a mutable row by index.
    pub fn get_row_mut(&mut self, index: usize) -> Option<&mut RelocationRowObject> {
        self.rows.get_mut(index)
    }

    /// Get all rows.
    pub fn rows(&self) -> &[RelocationRowObject] {
        &self.rows
    }

    /// Whether the model has been loaded.
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Get the program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Get a column value for a given row.
    pub fn get_column_value(&self, row: usize, col: &str) -> Option<String> {
        let r = self.get_row(row)?;
        Some(match col {
            columns::STATUS => r.status.clone(),
            columns::TYPE => r.type_hex(),
            columns::VALUES => r.values_display(),
            columns::ORIGINAL_BYTES => r.original_bytes_hex(),
            columns::CURRENT_BYTES => String::new(), // Requires memory access
            columns::NAME => r
                .relocation
                .symbol_name
                .clone()
                .unwrap_or_default(),
            _ => String::new(),
        })
    }

    /// Find rows at a given address.
    pub fn find_by_address(&self, addr: Address) -> Vec<usize> {
        self.rows
            .iter()
            .enumerate()
            .filter(|(_, r)| r.relocation.address == addr)
            .map(|(i, _)| i)
            .collect()
    }

    /// Clear all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
        self.loaded = false;
    }
}

impl Default for RelocationRowTableModel {
    fn default() -> Self {
        Self::new("")
    }
}

// ---------------------------------------------------------------------------
// ELF Relocation Fixup Handler
// ---------------------------------------------------------------------------

/// Relocation fixup handler for ELF binaries.
///
/// Ported from `ElfRelocationFixupHandler`.
#[derive(Debug)]
pub struct ElfRelocationFixupHandler {
    /// Whether to use RELA (with explicit addend) vs REL.
    pub use_rela: bool,
}

impl ElfRelocationFixupHandler {
    /// Create a new ELF relocation handler.
    pub fn new() -> Self {
        Self { use_rela: true }
    }
}

impl Default for ElfRelocationFixupHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl RelocationFixupHandler for ElfRelocationFixupHandler {
    fn name(&self) -> &str {
        "ELF Relocation Fixup Handler"
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
                let new_val = (relocation.original_value as i64 + delta) as u64;
                RelocationResult::success(relocation.address, new_val)
            }
            RelocationType::Relative => {
                // PC-relative relocations don't need adjustment for base change
                RelocationResult::success(relocation.address, relocation.original_value)
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
// PE32 Relocation Fixup Handler
// ---------------------------------------------------------------------------

/// Relocation fixup handler for PE32 binaries.
///
/// Ported from `Pe32RelocationFixupHandler`.
#[derive(Debug)]
pub struct Pe32RelocationFixupHandler;

impl Pe32RelocationFixupHandler {
    /// Create a new PE32 relocation handler.
    pub fn new() -> Self {
        Self
    }
}

impl Default for Pe32RelocationFixupHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl RelocationFixupHandler for Pe32RelocationFixupHandler {
    fn name(&self) -> &str {
        "PE32 Relocation Fixup Handler"
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
        let new_val = (relocation.original_value as i64 + delta) as u64;
        RelocationResult::success(relocation.address, new_val & 0xFFFF_FFFF)
    }

    fn format(&self) -> &str {
        "PE32"
    }
}

// ---------------------------------------------------------------------------
// PE64 Relocation Fixup Handler
// ---------------------------------------------------------------------------

/// Relocation fixup handler for PE64 (PE32+) binaries.
///
/// Ported from `Pe64RelocationFixupHandler`.
#[derive(Debug)]
pub struct Pe64RelocationFixupHandler;

impl Pe64RelocationFixupHandler {
    /// Create a new PE64 relocation handler.
    pub fn new() -> Self {
        Self
    }
}

impl Default for Pe64RelocationFixupHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl RelocationFixupHandler for Pe64RelocationFixupHandler {
    fn name(&self) -> &str {
        "PE64 Relocation Fixup Handler"
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
        let new_val = (relocation.original_value as i64 + delta) as u64;
        RelocationResult::success(relocation.address, new_val)
    }

    fn format(&self) -> &str {
        "PE64"
    }
}

// ---------------------------------------------------------------------------
// Generic Reference Base Relocation Fixup Handler
// ---------------------------------------------------------------------------

/// Generic relocation handler for programs with base-relative references.
///
/// Ported from `GenericRefernenceBaseRelocationFixupHandler`.
#[derive(Debug)]
pub struct GenericRelocationFixupHandler;

impl GenericRelocationFixupHandler {
    /// Create a new generic relocation handler.
    pub fn new() -> Self {
        Self
    }
}

impl Default for GenericRelocationFixupHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl RelocationFixupHandler for GenericRelocationFixupHandler {
    fn name(&self) -> &str {
        "Generic Reference Base Relocation Fixup Handler"
    }

    fn can_handle(&self, _format: &str) -> bool {
        true // Catch-all handler
    }

    fn apply_relocation(
        &self,
        relocation: &Relocation,
        _image_base: u64,
        delta: i64,
    ) -> RelocationResult {
        if relocation.reloc_type.is_absolute() {
            let new_val = (relocation.original_value as i64 + delta) as u64;
            RelocationResult::success(relocation.address, new_val)
        } else {
            RelocationResult::failure(
                relocation.address,
                "Non-absolute relocation in generic handler",
            )
        }
    }

    fn format(&self) -> &str {
        "Generic"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reloc::RelocationType;

    #[test]
    fn test_relocation_row_object() {
        let reloc = Relocation::new(Address::new(0x1000), RelocationType::Absolute, 0x401000);
        let row = RelocationRowObject::new(reloc, 0);
        assert_eq!(row.address().offset, 0x1000);
        assert_eq!(row.status, "Pending");
        assert!(row.values_display().contains("401000"));
    }

    #[test]
    fn test_relocation_row_ordering() {
        let r1 = RelocationRowObject::new(
            Relocation::new(Address::new(0x1000), RelocationType::Absolute, 0),
            0,
        );
        let r2 = RelocationRowObject::new(
            Relocation::new(Address::new(0x2000), RelocationType::Absolute, 0),
            0,
        );
        assert!(r1 < r2);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0xDEADBEEF, 4), "ef be ad de");
        assert_eq!(format_bytes(0x41, 1), "41");
    }

    #[test]
    fn test_instruction_stasher() {
        let mut stash = InstructionStasher::new(Address::new(0x1000));
        assert!(!stash.is_valid());
        stash.stash("MOV", 3);
        assert!(stash.is_valid());
        assert_eq!(stash.mnemonic, "MOV");
        assert_eq!(stash.length, 3);
        stash.clear();
        assert!(!stash.is_valid());
    }

    #[test]
    fn test_relocation_to_address_mapper() {
        let reloc = Relocation::new(Address::new(0x1000), RelocationType::Absolute, 0);
        let row = RelocationRowObject::new(reloc, 0);
        let addr = RelocationToAddressMapper::map(&row);
        assert_eq!(addr.offset, 0x1000);
    }

    #[test]
    fn test_relocation_table_model() {
        let mut model = RelocationRowTableModel::new("test.exe");
        assert_eq!(model.row_count(), 0);
        assert!(!model.is_loaded());

        let relocs = vec![
            Relocation::new(Address::new(0x2000), RelocationType::Absolute, 0x402000),
            Relocation::new(Address::new(0x1000), RelocationType::Absolute, 0x401000),
            Relocation::new(Address::new(0x1004), RelocationType::Relative, 0x403000),
        ];
        model.load(relocs);
        assert_eq!(model.row_count(), 3);
        assert!(model.is_loaded());

        // Should be sorted by address
        assert_eq!(model.get_row(0).unwrap().address().offset, 0x1000);
        assert_eq!(model.get_row(1).unwrap().address().offset, 0x1004);
        assert_eq!(model.get_row(2).unwrap().address().offset, 0x2000);
    }

    #[test]
    fn test_relocation_table_model_column_values() {
        let mut model = RelocationRowTableModel::new("test.exe");
        model.load(vec![Relocation::new(
            Address::new(0x1000),
            RelocationType::Absolute,
            0x401000,
        )
        .with_symbol("main")]);

        assert_eq!(
            model.get_column_value(0, columns::NAME).unwrap(),
            "main"
        );
        assert_eq!(
            model.get_column_value(0, columns::STATUS).unwrap(),
            "Pending"
        );
    }

    #[test]
    fn test_relocation_table_model_find_by_address() {
        let mut model = RelocationRowTableModel::new("test.exe");
        model.load(vec![
            Relocation::new(Address::new(0x1000), RelocationType::Absolute, 0),
            Relocation::new(Address::new(0x1000), RelocationType::Absolute, 0),
            Relocation::new(Address::new(0x2000), RelocationType::Absolute, 0),
        ]);
        let indices = model.find_by_address(Address::new(0x1000));
        assert_eq!(indices.len(), 2);
    }

    #[test]
    fn test_elf_handler() {
        let handler = ElfRelocationFixupHandler::new();
        assert!(handler.can_handle("ELF"));
        assert!(handler.can_handle("elf"));
        assert!(!handler.can_handle("PE"));

        let reloc = Relocation::new(Address::new(0x1000), RelocationType::Absolute, 0x401000);
        let result = handler.apply_relocation(&reloc, 0x400000, 0x100000);
        assert!(result.applied);
        assert_eq!(result.new_value, Some(0x501000));
    }

    #[test]
    fn test_pe32_handler() {
        let handler = Pe32RelocationFixupHandler::new();
        assert!(handler.can_handle("PE"));
        assert!(handler.can_handle("PE32"));

        let reloc = Relocation::new(Address::new(0x1000), RelocationType::Absolute, 0x401000);
        let result = handler.apply_relocation(&reloc, 0x400000, 0x100000);
        assert!(result.applied);
        assert_eq!(result.new_value, Some(0x501000));
    }

    #[test]
    fn test_pe64_handler() {
        let handler = Pe64RelocationFixupHandler::new();
        assert!(handler.can_handle("PE64"));

        let reloc = Relocation::new(Address::new(0x1000), RelocationType::Absolute, 0x401000);
        let result = handler.apply_relocation(&reloc, 0x400000, 0x100000);
        assert!(result.applied);
    }

    #[test]
    fn test_generic_handler() {
        let handler = GenericRelocationFixupHandler::new();
        assert!(handler.can_handle("anything"));

        let reloc = Relocation::new(Address::new(0x1000), RelocationType::Absolute, 0x401000);
        let result = handler.apply_relocation(&reloc, 0x400000, 0x100000);
        assert!(result.applied);
    }

    #[test]
    fn test_generic_handler_non_absolute() {
        let handler = GenericRelocationFixupHandler::new();
        let reloc = Relocation::new(Address::new(0x1000), RelocationType::Unknown, 0x401000);
        let result = handler.apply_relocation(&reloc, 0x400000, 0x100000);
        assert!(!result.applied);
    }

    #[test]
    fn test_relocation_result() {
        let ok = RelocationResult::success(Address::new(0x1000), 0x42);
        assert!(ok.applied);
        assert_eq!(ok.new_value, Some(0x42));

        let fail = RelocationResult::failure(Address::new(0x1000), "bad reloc");
        assert!(!fail.applied);
        assert_eq!(fail.error.as_deref(), Some("bad reloc"));
    }

    #[test]
    fn test_flow_override() {
        assert_ne!(FlowOverride::Call, FlowOverride::Jump);
        assert_eq!(FlowOverride::None, FlowOverride::None);
    }
}

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

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod original_tests {
    use super::*;

    fn sample_reloc(addr: u64, rtype: RelocationType) -> Relocation {
        Relocation::new(Address::new(addr), rtype, 0x1000)
    }

    #[test]
    fn test_elf_handler_original() {
        let handler = ElfRelocationFixupHandler::new();
        assert_eq!(handler.name(), "ELF Relocation Fixup Handler");
        assert!(handler.can_handle("ELF"));
        assert!(!handler.can_handle("PE"));

        let reloc = sample_reloc(0x400000, RelocationType::Absolute);
        let result = handler.apply_relocation(&reloc, 0x400000, 0x1000);
        assert!(result.applied);
    }

    #[test]
    fn test_pe32_handler_original() {
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
        let handler = GenericRelocationFixupHandler::new();
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
        let mut stasher = InstructionStasher::new(Address::new(0x1000));
        assert!(!stasher.is_valid());

        stasher.stash("MOV", 3);
        assert!(stasher.is_valid());
        assert_eq!(stasher.mnemonic, "MOV");
        assert_eq!(stasher.length, 3);

        stasher.clear();
        assert!(!stasher.is_valid());
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
        let mut model = RelocationRowTableModel::new("test");
        assert_eq!(model.row_count(), 0);

        model.load(vec![
            sample_reloc(0x3000, RelocationType::Absolute),
            sample_reloc(0x1000, RelocationType::Relative),
            sample_reloc(0x2000, RelocationType::Pointer),
        ]);
        assert_eq!(model.row_count(), 3);
        assert!(model.is_loaded());

        // Test column values
        assert!(model.get_column_value(0, columns::STATUS).is_some());
        assert_eq!(model.get_column_value(99, columns::STATUS), None);
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
