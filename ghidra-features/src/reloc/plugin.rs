//! Relocation table plugin, fixup handler, and table model.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.reloc` Java package:
//! `RelocationTablePlugin`, `RelocationFixupPlugin`,
//! `RelocationFixupHandler`, `RelocationFixupCommand`,
//! `RelocationProvider`, `RelocationTableModel`,
//! `RelocationToAddressTableRowMapper`,
//! `ElfRelocationFixupHandler`, `Pe32RelocationFixupHandler`,
//! `Pe64RelocationFixupHandler`, `GenericRefernenceBaseRelocationFixupHandler`,
//! `InstructionStasher`.

use ghidra_core::Address;

// ============================================================================
// RelocationType -- the type of relocation
// ============================================================================

/// The type of relocation applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelocationType {
    /// Absolute address relocation.
    Absolute,
    /// Relative (PC-relative) relocation.
    Relative,
    /// High 16 bits.
    High16,
    /// Low 16 bits.
    Low16,
    /// High + low split.
    HighLow,
    /// 64-bit absolute.
    Absolute64,
    /// Base-relative.
    BaseRelative,
    /// Thumb call.
    ThumbCall,
    /// ARM call.
    ArmCall,
    /// Other/unknown type.
    Other(u32),
}

impl RelocationType {
    /// Display name for this relocation type.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Absolute => "ABSOLUTE",
            Self::Relative => "RELATIVE",
            Self::High16 => "HIGH16",
            Self::Low16 => "LOW16",
            Self::HighLow => "HIGHLOW",
            Self::Absolute64 => "ABSOLUTE64",
            Self::BaseRelative => "BASE_RELATIVE",
            Self::ThumbCall => "THUMB_CALL",
            Self::ArmCall => "ARM_CALL",
            Self::Other(_) => "OTHER",
        }
    }
}

// ============================================================================
// RelocationEntry -- a single relocation
// ============================================================================

/// A single relocation entry in the program.
///
/// Ported from relocation data in `RelocationTableModel`.
#[derive(Debug, Clone)]
pub struct RelocationEntry {
    /// The address being relocated.
    pub address: Address,
    /// The relocation type.
    pub relocation_type: RelocationType,
    /// The symbol name (if associated with a symbol).
    pub symbol_name: Option<String>,
    /// The original value at the address (before relocation).
    pub original_value: u64,
    /// The addend added to the relocation.
    pub addend: i64,
    /// The relocation status.
    pub status: RelocationStatus,
}

/// Status of a relocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationStatus {
    /// Relocation has been applied.
    Applied,
    /// Relocation is pending.
    Pending,
    /// Relocation failed.
    Failed,
    /// Relocation was skipped.
    Skipped,
}

impl RelocationEntry {
    /// Create a new relocation entry.
    pub fn new(
        address: Address,
        relocation_type: RelocationType,
        original_value: u64,
    ) -> Self {
        Self {
            address,
            relocation_type,
            symbol_name: None,
            original_value,
            addend: 0,
            status: RelocationStatus::Pending,
        }
    }

    /// Create a relocation with a symbol name.
    pub fn with_symbol(
        address: Address,
        relocation_type: RelocationType,
        original_value: u64,
        symbol_name: impl Into<String>,
    ) -> Self {
        Self {
            address,
            relocation_type,
            symbol_name: Some(symbol_name.into()),
            original_value,
            addend: 0,
            status: RelocationStatus::Pending,
        }
    }
}

// ============================================================================
// RelocationTableModel -- table model for relocations
// ============================================================================

/// Column definitions for the relocation table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelocationColumn {
    /// Address column.
    Address,
    /// Type column.
    Type,
    /// Symbol column.
    Symbol,
    /// Original value column.
    OriginalValue,
    /// Status column.
    Status,
}

impl RelocationColumn {
    /// All columns in display order.
    pub fn all() -> &'static [RelocationColumn] {
        &[
            Self::Address,
            Self::Type,
            Self::Symbol,
            Self::OriginalValue,
            Self::Status,
        ]
    }

    /// Column header.
    pub fn header(&self) -> &'static str {
        match self {
            Self::Address => "Address",
            Self::Type => "Type",
            Self::Symbol => "Symbol",
            Self::OriginalValue => "Original Value",
            Self::Status => "Status",
        }
    }
}

/// Table model for displaying relocation entries.
///
/// Ported from `ghidra.app.plugin.core.reloc.RelocationTableModel`.
#[derive(Debug, Default)]
pub struct RelocationTableModel {
    /// All relocation entries.
    entries: Vec<RelocationEntry>,
}

impl RelocationTableModel {
    /// Create a new empty model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a relocation entry.
    pub fn add_entry(&mut self, entry: RelocationEntry) {
        self.entries.push(entry);
    }

    /// Entry count.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get an entry by index.
    pub fn get_entry(&self, index: usize) -> Option<&RelocationEntry> {
        self.entries.get(index)
    }

    /// Get all entries.
    pub fn all_entries(&self) -> &[RelocationEntry] {
        &self.entries
    }

    /// Get entries by status.
    pub fn entries_by_status(&self, status: RelocationStatus) -> Vec<&RelocationEntry> {
        self.entries.iter().filter(|e| e.status == status).collect()
    }

    /// Get entries by type.
    pub fn entries_by_type(&self, reloc_type: RelocationType) -> Vec<&RelocationEntry> {
        self.entries.iter().filter(|e| e.relocation_type == reloc_type).collect()
    }

    /// Sort by column.
    pub fn sort_by(&mut self, column: RelocationColumn, ascending: bool) {
        match column {
            RelocationColumn::Address => {
                self.entries.sort_by_key(|e| e.address.offset);
            }
            RelocationColumn::Type => {
                self.entries.sort_by(|a, b| {
                    a.relocation_type.display_name().cmp(b.relocation_type.display_name())
                });
            }
            RelocationColumn::Symbol => {
                self.entries.sort_by(|a, b| {
                    a.symbol_name
                        .as_deref()
                        .unwrap_or("")
                        .cmp(b.symbol_name.as_deref().unwrap_or(""))
                });
            }
            RelocationColumn::OriginalValue => {
                self.entries.sort_by_key(|e| e.original_value);
            }
            RelocationColumn::Status => {
                self.entries.sort_by(|a, b| format!("{:?}", a.status).cmp(&format!("{:?}", b.status)));
            }
        }
        if !ascending {
            self.entries.reverse();
        }
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ============================================================================
// Address mapper
// ============================================================================

/// Maps a relocation entry to its address.
///
/// Ported from
/// `ghidra.app.plugin.core.reloc.RelocationToAddressTableRowMapper`.
pub struct RelocationToAddressMapper;

impl RelocationToAddressMapper {
    /// Map a relocation entry to its address.
    pub fn map(entry: &RelocationEntry) -> Address {
        entry.address
    }
}

// ============================================================================
// RelocationFixupHandler -- trait for format-specific fixup handlers
// ============================================================================

/// Trait for applying relocations to a program.
///
/// Ported from `ghidra.app.plugin.core.reloc.RelocationFixupHandler`.
pub trait RelocationFixupHandler: Send + Sync {
    /// The name of this handler.
    fn name(&self) -> &str;

    /// Whether this handler can process the given relocation type.
    fn can_handle(&self, reloc_type: RelocationType) -> bool;

    /// Apply a relocation fixup.
    fn apply_fixup(
        &self,
        entry: &RelocationEntry,
        program_data: &mut [u8],
        base_address: u64,
    ) -> Result<(), String>;
}

// ============================================================================
// ELF Relocation Fixup Handler
// ============================================================================

/// ELF relocation fixup handler.
///
/// Ported from `ghidra.app.plugin.core.reloc.ElfRelocationFixupHandler`.
#[derive(Debug)]
pub struct ElfRelocationFixupHandler;

impl RelocationFixupHandler for ElfRelocationFixupHandler {
    fn name(&self) -> &str {
        "ELF Relocation Fixup"
    }

    fn can_handle(&self, reloc_type: RelocationType) -> bool {
        matches!(
            reloc_type,
            RelocationType::Absolute
                | RelocationType::Relative
                | RelocationType::Absolute64
        )
    }

    fn apply_fixup(
        &self,
        entry: &RelocationEntry,
        program_data: &mut [u8],
        base_address: u64,
    ) -> Result<(), String> {
        let offset = (entry.address.offset.saturating_sub(base_address)) as usize;
        let value = (entry.original_value as i64 + entry.addend) as u64;

        match entry.relocation_type {
            RelocationType::Absolute | RelocationType::Relative => {
                if offset + 4 > program_data.len() {
                    return Err("Relocation offset out of bounds".into());
                }
                let bytes = (value as u32).to_le_bytes();
                program_data[offset..offset + 4].copy_from_slice(&bytes);
            }
            RelocationType::Absolute64 => {
                if offset + 8 > program_data.len() {
                    return Err("Relocation offset out of bounds".into());
                }
                let bytes = value.to_le_bytes();
                program_data[offset..offset + 8].copy_from_slice(&bytes);
            }
            _ => return Err(format!("Unsupported ELF relocation: {:?}", entry.relocation_type)),
        }
        Ok(())
    }
}

// ============================================================================
// PE32 Relocation Fixup Handler
// ============================================================================

/// PE32 relocation fixup handler.
///
/// Ported from `ghidra.app.plugin.core.reloc.Pe32RelocationFixupHandler`.
#[derive(Debug)]
pub struct Pe32RelocationFixupHandler;

impl RelocationFixupHandler for Pe32RelocationFixupHandler {
    fn name(&self) -> &str {
        "PE32 Relocation Fixup"
    }

    fn can_handle(&self, reloc_type: RelocationType) -> bool {
        matches!(
            reloc_type,
            RelocationType::HighLow | RelocationType::Absolute
        )
    }

    fn apply_fixup(
        &self,
        entry: &RelocationEntry,
        program_data: &mut [u8],
        base_address: u64,
    ) -> Result<(), String> {
        let offset = (entry.address.offset.saturating_sub(base_address)) as usize;
        if offset + 4 > program_data.len() {
            return Err("Relocation offset out of bounds".into());
        }
        let value = (entry.original_value as u32).wrapping_add(entry.addend as u32);
        let bytes = value.to_le_bytes();
        program_data[offset..offset + 4].copy_from_slice(&bytes);
        Ok(())
    }
}

// ============================================================================
// PE64 Relocation Fixup Handler
// ============================================================================

/// PE64 relocation fixup handler.
///
/// Ported from `ghidra.app.plugin.core.reloc.Pe64RelocationFixupHandler`.
#[derive(Debug)]
pub struct Pe64RelocationFixupHandler;

impl RelocationFixupHandler for Pe64RelocationFixupHandler {
    fn name(&self) -> &str {
        "PE64 Relocation Fixup"
    }

    fn can_handle(&self, reloc_type: RelocationType) -> bool {
        matches!(
            reloc_type,
            RelocationType::Absolute64 | RelocationType::HighLow | RelocationType::Absolute
        )
    }

    fn apply_fixup(
        &self,
        entry: &RelocationEntry,
        program_data: &mut [u8],
        base_address: u64,
    ) -> Result<(), String> {
        let offset = (entry.address.offset.saturating_sub(base_address)) as usize;
        match entry.relocation_type {
            RelocationType::Absolute64 => {
                if offset + 8 > program_data.len() {
                    return Err("Relocation offset out of bounds".into());
                }
                let value = (entry.original_value).wrapping_add(entry.addend as u64);
                let bytes = value.to_le_bytes();
                program_data[offset..offset + 8].copy_from_slice(&bytes);
            }
            RelocationType::HighLow | RelocationType::Absolute => {
                if offset + 4 > program_data.len() {
                    return Err("Relocation offset out of bounds".into());
                }
                let value = (entry.original_value as u32).wrapping_add(entry.addend as u32);
                let bytes = value.to_le_bytes();
                program_data[offset..offset + 4].copy_from_slice(&bytes);
            }
            _ => return Err(format!("Unsupported PE64 relocation: {:?}", entry.relocation_type)),
        }
        Ok(())
    }
}

// ============================================================================
// RelocationFixupCommand -- command to apply relocations
// ============================================================================

/// Command to apply a relocation fixup.
///
/// Ported from `ghidra.app.plugin.core.reloc.RelocationFixupCommand`.
#[derive(Debug)]
pub struct RelocationFixupCommand {
    /// The relocation entry.
    pub entry: RelocationEntry,
    /// The handler name to use.
    pub handler_name: String,
}

impl RelocationFixupCommand {
    /// Create a new fixup command.
    pub fn new(entry: RelocationEntry, handler_name: impl Into<String>) -> Self {
        Self {
            entry,
            handler_name: handler_name.into(),
        }
    }
}

// ============================================================================
// RelocationTablePlugin -- plugin for the relocation table view
// ============================================================================

/// Plugin for the relocation table view.
///
/// Ported from `ghidra.app.plugin.core.reloc.RelocationTablePlugin`.
#[derive(Debug)]
pub struct RelocationTablePlugin {
    /// The relocation table model.
    pub model: RelocationTableModel,
    /// Registered fixup handlers.
    handlers: Vec<String>,
    /// Whether the plugin is disposed.
    disposed: bool,
}

impl RelocationTablePlugin {
    /// Create a new relocation table plugin.
    pub fn new() -> Self {
        Self {
            model: RelocationTableModel::new(),
            handlers: Vec::new(),
            disposed: false,
        }
    }

    /// Add a relocation entry.
    pub fn add_relocation(&mut self, entry: RelocationEntry) {
        self.model.add_entry(entry);
    }

    /// Register a fixup handler by name.
    pub fn register_handler(&mut self, name: impl Into<String>) {
        self.handlers.push(name.into());
    }

    /// Get registered handler names.
    pub fn handler_names(&self) -> &[String] {
        &self.handlers
    }

    /// Get the total number of relocations.
    pub fn relocation_count(&self) -> usize {
        self.model.entry_count()
    }

    /// Get the count of pending relocations.
    pub fn pending_count(&self) -> usize {
        self.model
            .entries_by_status(RelocationStatus::Pending)
            .len()
    }

    /// Dispose the plugin.
    pub fn dispose(&mut self) {
        self.disposed = true;
    }

    /// Whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }
}

impl Default for RelocationTablePlugin {
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

    #[test]
    fn test_relocation_type_display() {
        assert_eq!(RelocationType::Absolute.display_name(), "ABSOLUTE");
        assert_eq!(RelocationType::Relative.display_name(), "RELATIVE");
        assert_eq!(RelocationType::High16.display_name(), "HIGH16");
        assert_eq!(RelocationType::Other(99).display_name(), "OTHER");
    }

    #[test]
    fn test_relocation_entry() {
        let entry = RelocationEntry::new(
            Address::new(0x1000),
            RelocationType::Absolute,
            0xDEADBEEF,
        );
        assert_eq!(entry.address, Address::new(0x1000));
        assert_eq!(entry.status, RelocationStatus::Pending);
        assert!(entry.symbol_name.is_none());
    }

    #[test]
    fn test_relocation_entry_with_symbol() {
        let entry = RelocationEntry::with_symbol(
            Address::new(0x1000),
            RelocationType::Relative,
            0x100,
            "printf",
        );
        assert_eq!(entry.symbol_name.as_deref(), Some("printf"));
    }

    #[test]
    fn test_relocation_table_model() {
        let mut model = RelocationTableModel::new();
        model.add_entry(RelocationEntry::new(
            Address::new(0x1000),
            RelocationType::Absolute,
            0x100,
        ));
        model.add_entry(RelocationEntry::new(
            Address::new(0x2000),
            RelocationType::Relative,
            0x200,
        ));
        assert_eq!(model.entry_count(), 2);
    }

    #[test]
    fn test_relocation_table_model_by_status() {
        let mut model = RelocationTableModel::new();
        let mut e1 = RelocationEntry::new(Address::new(0x1000), RelocationType::Absolute, 0);
        e1.status = RelocationStatus::Applied;
        model.add_entry(e1);
        model.add_entry(RelocationEntry::new(
            Address::new(0x2000),
            RelocationType::Relative,
            0,
        ));

        assert_eq!(
            model.entries_by_status(RelocationStatus::Applied).len(),
            1
        );
        assert_eq!(
            model.entries_by_status(RelocationStatus::Pending).len(),
            1
        );
    }

    #[test]
    fn test_relocation_table_model_by_type() {
        let mut model = RelocationTableModel::new();
        model.add_entry(RelocationEntry::new(
            Address::new(0x1000),
            RelocationType::Absolute,
            0,
        ));
        model.add_entry(RelocationEntry::new(
            Address::new(0x2000),
            RelocationType::Absolute,
            0,
        ));
        model.add_entry(RelocationEntry::new(
            Address::new(0x3000),
            RelocationType::Relative,
            0,
        ));
        assert_eq!(
            model.entries_by_type(RelocationType::Absolute).len(),
            2
        );
        assert_eq!(
            model.entries_by_type(RelocationType::Relative).len(),
            1
        );
    }

    #[test]
    fn test_relocation_table_model_sort() {
        let mut model = RelocationTableModel::new();
        model.add_entry(RelocationEntry::new(
            Address::new(0x3000),
            RelocationType::Absolute,
            0x100,
        ));
        model.add_entry(RelocationEntry::new(
            Address::new(0x1000),
            RelocationType::Relative,
            0x200,
        ));

        model.sort_by(RelocationColumn::Address, true);
        assert_eq!(model.get_entry(0).unwrap().address, Address::new(0x1000));

        model.sort_by(RelocationColumn::OriginalValue, true);
        assert_eq!(model.get_entry(0).unwrap().original_value, 0x100);
    }

    #[test]
    fn test_relocation_table_model_clear() {
        let mut model = RelocationTableModel::new();
        model.add_entry(RelocationEntry::new(
            Address::new(0x1000),
            RelocationType::Absolute,
            0,
        ));
        model.clear();
        assert_eq!(model.entry_count(), 0);
    }

    #[test]
    fn test_relocation_address_mapper() {
        let entry = RelocationEntry::new(
            Address::new(0x4000),
            RelocationType::Absolute,
            0,
        );
        assert_eq!(RelocationToAddressMapper::map(&entry), Address::new(0x4000));
    }

    #[test]
    fn test_elf_fixup_handler() {
        let handler = ElfRelocationFixupHandler;
        assert_eq!(handler.name(), "ELF Relocation Fixup");
        assert!(handler.can_handle(RelocationType::Absolute));
        assert!(handler.can_handle(RelocationType::Relative));
        assert!(handler.can_handle(RelocationType::Absolute64));
        assert!(!handler.can_handle(RelocationType::HighLow));
    }

    #[test]
    fn test_elf_fixup_apply_32bit() {
        let handler = ElfRelocationFixupHandler;
        let entry = RelocationEntry::new(
            Address::new(0x1000),
            RelocationType::Absolute,
            0x1000,
        );
        let mut data = vec![0u8; 0x2000];
        let result = handler.apply_fixup(&entry, &mut data, 0);
        assert!(result.is_ok());
        let offset = 0x1000usize;
        let value = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
        assert_eq!(value, 0x1000);
    }

    #[test]
    fn test_elf_fixup_apply_64bit() {
        let handler = ElfRelocationFixupHandler;
        let entry = RelocationEntry::new(
            Address::new(0x1000),
            RelocationType::Absolute64,
            0x0000_0040_0000_1000,
        );
        let mut data = vec![0u8; 0x2000];
        let result = handler.apply_fixup(&entry, &mut data, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pe32_fixup_handler() {
        let handler = Pe32RelocationFixupHandler;
        assert!(handler.can_handle(RelocationType::HighLow));
        assert!(handler.can_handle(RelocationType::Absolute));
        assert!(!handler.can_handle(RelocationType::Absolute64));
    }

    #[test]
    fn test_pe64_fixup_handler() {
        let handler = Pe64RelocationFixupHandler;
        assert!(handler.can_handle(RelocationType::Absolute64));
        assert!(handler.can_handle(RelocationType::HighLow));
        assert!(!handler.can_handle(RelocationType::ThumbCall));
    }

    #[test]
    fn test_relocation_table_plugin() {
        let mut plugin = RelocationTablePlugin::new();
        assert!(!plugin.is_disposed());
        assert_eq!(plugin.relocation_count(), 0);

        plugin.add_relocation(RelocationEntry::new(
            Address::new(0x1000),
            RelocationType::Absolute,
            0,
        ));
        assert_eq!(plugin.relocation_count(), 1);
        assert_eq!(plugin.pending_count(), 1);

        plugin.register_handler("ELF");
        assert_eq!(plugin.handler_names(), &["ELF"]);

        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_relocation_column_headers() {
        assert_eq!(RelocationColumn::Address.header(), "Address");
        assert_eq!(RelocationColumn::Type.header(), "Type");
        assert_eq!(RelocationColumn::Symbol.header(), "Symbol");
        assert_eq!(RelocationColumn::OriginalValue.header(), "Original Value");
        assert_eq!(RelocationColumn::Status.header(), "Status");
        assert_eq!(RelocationColumn::all().len(), 5);
    }

    #[test]
    fn test_elf_fixup_with_addend() {
        let handler = ElfRelocationFixupHandler;
        let mut entry = RelocationEntry::new(
            Address::new(0x1000),
            RelocationType::Absolute,
            0x1000,
        );
        entry.addend = 0x50;
        let mut data = vec![0u8; 0x2000];
        handler.apply_fixup(&entry, &mut data, 0).unwrap();
        let offset = 0x1000usize;
        let value = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
        assert_eq!(value, 0x1050);
    }

    #[test]
    fn test_fixup_out_of_bounds() {
        let handler = ElfRelocationFixupHandler;
        let entry = RelocationEntry::new(
            Address::new(0x5000),
            RelocationType::Absolute,
            0x100,
        );
        let mut data = vec![0u8; 0x100];
        let result = handler.apply_fixup(&entry, &mut data, 0);
        assert!(result.is_err());
    }
}
