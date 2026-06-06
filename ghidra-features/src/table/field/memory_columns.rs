//! Memory section table columns.
//!
//! Ported from `ghidra.util.table.field`:
//! - `MemorySectionProgramLocationBasedTableColumn` -- displays the memory
//!   block/section name containing an address.
//! - `MemorySourceProgramLocationBasedTableColumn` -- displays the source
//!   file section for an address.
//! - `MemoryTypeProgramLocationBasedTableColumn` -- displays the memory
//!   block type (ram, ro, etc.).

use ghidra_core::addr::Address;

use super::traits::{ProgramBasedDynamicTableColumn, ProgramInfo, ProgramLocationTableColumn,
                    ProgramLocationTableColumnExt, ServiceProvider, Settings};
use super::super::mapper::ProgramLocation;

// ---------------------------------------------------------------------------
// MemoryBlockType
// ---------------------------------------------------------------------------

/// Type of memory block in a program.
///
/// Ported from properties of `ghidra.program.model.mem.MemoryBlock`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryBlockType {
    /// Initialized memory block.
    Initialized,
    /// Uninitialized (BSS) memory block.
    Uninitialized,
    /// Memory-mapped I/O block.
    MappedIO,
    /// Overlay memory block.
    Overlay,
    /// External memory block.
    External,
    /// Volatile memory block.
    Volatile,
}

impl std::fmt::Display for MemoryBlockType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryBlockType::Initialized => f.write_str("Initialized"),
            MemoryBlockType::Uninitialized => f.write_str("Uninitialized"),
            MemoryBlockType::MappedIO => f.write_str("Memory-Mapped I/O"),
            MemoryBlockType::Overlay => f.write_str("Overlay"),
            MemoryBlockType::External => f.write_str("External"),
            MemoryBlockType::Volatile => f.write_str("Volatile"),
        }
    }
}

// ---------------------------------------------------------------------------
// MemoryBlockInfo
// ---------------------------------------------------------------------------

/// Lightweight memory block information for table column use.
#[derive(Debug, Clone)]
pub struct MemoryBlockInfo {
    /// Block name (e.g., ".text", ".data").
    pub name: String,
    /// Block type.
    pub block_type: MemoryBlockType,
    /// Start address.
    pub start: Address,
    /// End address.
    pub end: Address,
    /// Whether the block is readable.
    pub read: bool,
    /// Whether the block is writable.
    pub write: bool,
    /// Whether the block is executable.
    pub execute: bool,
}

impl MemoryBlockInfo {
    /// Create new memory block info.
    pub fn new(name: impl Into<String>, block_type: MemoryBlockType,
               start: Address, end: Address) -> Self {
        Self {
            name: name.into(),
            block_type,
            start,
            end,
            read: true,
            write: false,
            execute: true,
        }
    }

    /// Returns the size of the block in bytes.
    pub fn size(&self) -> u64 {
        self.end.offset.saturating_sub(self.start.offset) + 1
    }
}

// ---------------------------------------------------------------------------
// MemorySectionProgramLocationBasedTableColumn
// ---------------------------------------------------------------------------

/// Displays the memory section name for an address.
///
/// Ported from `ghidra.util.table.field.MemorySectionProgramLocationBasedTableColumn`.
#[derive(Debug)]
pub struct MemorySectionProgramLocationBasedTableColumn;

impl ProgramBasedDynamicTableColumn<Address> for MemorySectionProgramLocationBasedTableColumn {
    fn column_name(&self) -> &str { "Memory Section" }

    fn get_value(&self, _row: &Address, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        // In a real implementation, look up the memory block for the address.
        None
    }

    fn preferred_width(&self) -> usize { 120 }
}

impl ProgramLocationTableColumn<Address> for MemorySectionProgramLocationBasedTableColumn {
    fn get_program_location(&self, row: &Address, _settings: &Settings,
                            _program: &ProgramInfo, _sp: &ServiceProvider)
        -> Option<ProgramLocation> {
        Some(ProgramLocation::new(*row))
    }
}

impl ProgramLocationTableColumnExt<Address> for MemorySectionProgramLocationBasedTableColumn {}

// ---------------------------------------------------------------------------
// MemorySourceProgramLocationBasedTableColumn
// ---------------------------------------------------------------------------

/// Displays the source file section for an address.
///
/// Ported from `ghidra.util.table.field.MemorySourceProgramLocationBasedTableColumn`.
#[derive(Debug)]
pub struct MemorySourceProgramLocationBasedTableColumn;

impl ProgramBasedDynamicTableColumn<Address> for MemorySourceProgramLocationBasedTableColumn {
    fn column_name(&self) -> &str { "Source Section" }

    fn get_value(&self, _row: &Address, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        None
    }
}

impl ProgramLocationTableColumn<Address> for MemorySourceProgramLocationBasedTableColumn {
    fn get_program_location(&self, row: &Address, _settings: &Settings,
                            _program: &ProgramInfo, _sp: &ServiceProvider)
        -> Option<ProgramLocation> {
        Some(ProgramLocation::new(*row))
    }
}

impl ProgramLocationTableColumnExt<Address> for MemorySourceProgramLocationBasedTableColumn {}

// ---------------------------------------------------------------------------
// MemoryTypeProgramLocationBasedTableColumn
// ---------------------------------------------------------------------------

/// Displays the memory block type for an address.
///
/// Ported from `ghidra.util.table.field.MemoryTypeProgramLocationBasedTableColumn`.
#[derive(Debug)]
pub struct MemoryTypeProgramLocationBasedTableColumn;

impl ProgramBasedDynamicTableColumn<Address> for MemoryTypeProgramLocationBasedTableColumn {
    fn column_name(&self) -> &str { "Memory Type" }

    fn get_value(&self, _row: &Address, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        None
    }
}

impl ProgramLocationTableColumn<Address> for MemoryTypeProgramLocationBasedTableColumn {
    fn get_program_location(&self, row: &Address, _settings: &Settings,
                            _program: &ProgramInfo, _sp: &ServiceProvider)
        -> Option<ProgramLocation> {
        Some(ProgramLocation::new(*row))
    }
}

impl ProgramLocationTableColumnExt<Address> for MemoryTypeProgramLocationBasedTableColumn {}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_program() -> ProgramInfo {
        ProgramInfo::new("test", "x86:LE:64:default")
    }

    fn test_sp() -> ServiceProvider {
        ServiceProvider::new("TestTool")
    }

    #[test]
    fn test_memory_block_type_display() {
        assert_eq!(MemoryBlockType::Initialized.to_string(), "Initialized");
        assert_eq!(MemoryBlockType::Uninitialized.to_string(), "Uninitialized");
        assert_eq!(MemoryBlockType::MappedIO.to_string(), "Memory-Mapped I/O");
        assert_eq!(MemoryBlockType::Overlay.to_string(), "Overlay");
    }

    #[test]
    fn test_memory_block_info_size() {
        let block = MemoryBlockInfo::new(
            ".text", MemoryBlockType::Initialized,
            Address::new(0x1000), Address::new(0x1FFF));
        assert_eq!(block.size(), 0x1000);
    }

    #[test]
    fn test_memory_section_column() {
        let col = MemorySectionProgramLocationBasedTableColumn;
        assert_eq!(col.column_name(), "Memory Section");
        assert_eq!(col.preferred_width(), 120);
        let addr = Address::new(0x1000);
        let loc = col.get_program_location(&addr, &Settings::new(), &test_program(), &test_sp());
        assert!(loc.is_some());
    }

    #[test]
    fn test_memory_source_column() {
        let col = MemorySourceProgramLocationBasedTableColumn;
        assert_eq!(col.column_name(), "Source Section");
    }

    #[test]
    fn test_memory_type_column() {
        let col = MemoryTypeProgramLocationBasedTableColumn;
        assert_eq!(col.column_name(), "Memory Type");
    }
}
