//! Memory map table model — provides a table-model view of memory blocks.
//!
//! Ported from `MemoryMapModel` in Ghidra's `ghidra.app.plugin.core.memory`.
//!
//! This module provides a data-oriented table model representing the memory
//! blocks in a program, with column definitions for display and sorting.

use ghidra_core::addr::Address;
use ghidra_core::mem::{MemoryBlock, MemoryBlockType};
use ghidra_core::program::program::Program;
use std::cmp::Ordering;

// ============================================================================
// MemoryColumn — column identifiers for the memory map table
// ============================================================================

/// Column identifiers for the memory map table model.
///
/// Mirrors the column constants in `MemoryMapModel` from Java.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MemoryColumn {
    /// Block name.
    Name = 0,
    /// Start address.
    Start = 1,
    /// End address.
    End = 2,
    /// Block size.
    Length = 3,
    /// Read permission.
    Read = 4,
    /// Write permission.
    Write = 5,
    /// Execute permission.
    Execute = 6,
    /// Volatile attribute.
    Volatile = 7,
    /// Artificial attribute.
    Artificial = 8,
    /// Whether the block is in an overlay space.
    Overlay = 9,
    /// Block type (Default, BitMapped, ByteMapped).
    BlockType = 10,
    /// Whether the block is initialized.
    Init = 11,
    /// Byte source descriptions.
    ByteSource = 12,
    /// Source name.
    Source = 13,
    /// Block comment.
    Comment = 14,
}

impl MemoryColumn {
    /// All columns in display order.
    pub const ALL: [MemoryColumn; 15] = [
        Self::Name,
        Self::Start,
        Self::End,
        Self::Length,
        Self::Read,
        Self::Write,
        Self::Execute,
        Self::Volatile,
        Self::Artificial,
        Self::Overlay,
        Self::BlockType,
        Self::Init,
        Self::ByteSource,
        Self::Source,
        Self::Comment,
    ];

    /// Human-readable column name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Start => "Start",
            Self::End => "End",
            Self::Length => "Length",
            Self::Read => "R",
            Self::Write => "W",
            Self::Execute => "X",
            Self::Volatile => "Volatile",
            Self::Artificial => "Artificial",
            Self::Overlay => "Overlayed Space",
            Self::BlockType => "Type",
            Self::Init => "Initialized",
            Self::ByteSource => "Byte Source",
            Self::Source => "Source",
            Self::Comment => "Comment",
        }
    }

    /// Whether this column is sortable.
    pub fn is_sortable(&self) -> bool {
        !matches!(
            self,
            Self::Read | Self::Write | Self::Execute | Self::Volatile | Self::Artificial | Self::Init
        )
    }

    /// Whether the cells in this column are editable.
    pub fn is_editable(&self) -> bool {
        matches!(
            self,
            Self::Name | Self::Read | Self::Write | Self::Execute | Self::Volatile | Self::Artificial | Self::Comment
        )
    }

    /// Index of this column.
    pub fn index(&self) -> usize {
        *self as usize
    }

    /// Look up a column by index.
    pub fn from_index(index: usize) -> Option<MemoryColumn> {
        Self::ALL.get(index).copied()
    }

    /// Look up a column by name.
    pub fn from_name(name: &str) -> Option<MemoryColumn> {
        Self::ALL.iter().find(|c| c.name() == name).copied()
    }
}

// ============================================================================
// MemoryMapModel
// ============================================================================

/// Table model representing the memory blocks of a program.
///
/// Ported from `MemoryMapModel` in Java. Provides a data-oriented view
/// of the program's memory blocks with support for column-based access
/// and sorting.
#[derive(Debug)]
pub struct MemoryMapModel {
    /// Ordered list of memory blocks.
    blocks: Vec<MemoryBlock>,
    /// The sort column (default: Start).
    sort_column: MemoryColumn,
    /// Whether sort is ascending.
    sort_ascending: bool,
}

impl MemoryMapModel {
    /// Create a new memory map model populated from the given program.
    pub fn new(program: &Program) -> Self {
        let mut blocks: Vec<MemoryBlock> = program
            .memory
            .get_blocks()
            .into_iter()
            .cloned()
            .collect();
        blocks.sort_by_key(|b| b.start().offset);

        Self {
            blocks,
            sort_column: MemoryColumn::Start,
            sort_ascending: true,
        }
    }

    /// Repopulate the model from the given program.
    pub fn set_program(&mut self, program: &Program) {
        self.blocks = program
            .memory
            .get_blocks()
            .into_iter()
            .cloned()
            .collect();
        self.resort();
    }

    /// Get the number of rows (memory blocks).
    pub fn row_count(&self) -> usize {
        self.blocks.len()
    }

    /// Get the number of columns.
    pub fn column_count(&self) -> usize {
        MemoryColumn::ALL.len()
    }

    /// Get the memory block at the given row index.
    pub fn get_block(&self, row: usize) -> Option<&MemoryBlock> {
        self.blocks.get(row)
    }

    /// Get all blocks as a slice.
    pub fn blocks(&self) -> &[MemoryBlock] {
        &self.blocks
    }

    /// Get the column value for a given block and column index.
    ///
    /// Returns a displayable string for the given cell.
    pub fn get_cell_value(&self, row: usize, col: MemoryColumn) -> Option<String> {
        let block = self.blocks.get(row)?;
        Some(match col {
            MemoryColumn::Name => block.name.clone(),
            MemoryColumn::Start => format!("0x{:x}", block.start().offset),
            MemoryColumn::End => format!("0x{:x}", block.end().offset),
            MemoryColumn::Length => format!("0x{:x}", block.size()),
            MemoryColumn::Read => block.is_read().to_string(),
            MemoryColumn::Write => block.is_write().to_string(),
            MemoryColumn::Execute => block.is_execute().to_string(),
            MemoryColumn::Volatile => block.is_volatile().to_string(),
            MemoryColumn::Artificial => block.is_artificial().to_string(),
            MemoryColumn::Overlay => block.is_overlay().to_string(),
            MemoryColumn::BlockType => block.block_type.name().to_string(),
            MemoryColumn::Init => block.is_initialized().to_string(),
            MemoryColumn::ByteSource => {
                let descs: Vec<&str> = block
                    .source_infos
                    .iter()
                    .take(4)
                    .map(|info| info.get_description())
                    .collect();
                let mut s = descs.join(" | ");
                if block.source_infos.len() > 4 {
                    s.push_str("...");
                }
                s
            }
            MemoryColumn::Source => block.source_name.clone(),
            MemoryColumn::Comment => block.comment.clone(),
        })
    }

    /// Sort the model by the given column.
    pub fn sort_by(&mut self, column: MemoryColumn) {
        if self.sort_column == column {
            self.sort_ascending = !self.sort_ascending;
        } else {
            self.sort_column = column;
            self.sort_ascending = true;
        }
        self.resort();
    }

    /// Get the current sort column.
    pub fn sort_column(&self) -> MemoryColumn {
        self.sort_column
    }

    /// Whether the current sort is ascending.
    pub fn is_sort_ascending(&self) -> bool {
        self.sort_ascending
    }

    fn resort(&mut self) {
        let col = self.sort_column;
        let asc = self.sort_ascending;
        self.blocks.sort_by(|a, b| {
            let ord = Self::compare_blocks(a, b, col);
            if asc {
                ord
            } else {
                ord.reverse()
            }
        });
    }

    fn compare_blocks(a: &MemoryBlock, b: &MemoryBlock, col: MemoryColumn) -> Ordering {
        match col {
            MemoryColumn::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            MemoryColumn::Start => a.start().offset.cmp(&b.start().offset),
            MemoryColumn::End => a.end().offset.cmp(&b.end().offset),
            MemoryColumn::Length => a.size().cmp(&b.size()),
            MemoryColumn::Read => a.is_read().cmp(&b.is_read()),
            MemoryColumn::Write => a.is_write().cmp(&b.is_write()),
            MemoryColumn::Execute => a.is_execute().cmp(&b.is_execute()),
            MemoryColumn::Volatile => a.is_volatile().cmp(&b.is_volatile()),
            MemoryColumn::Artificial => a.is_artificial().cmp(&b.is_artificial()),
            MemoryColumn::Overlay => a.is_overlay().cmp(&b.is_overlay()),
            MemoryColumn::Init => a.is_initialized().cmp(&b.is_initialized()),
            MemoryColumn::BlockType => a.block_type.name().cmp(b.block_type.name()),
            MemoryColumn::Source => a.source_name.to_lowercase().cmp(&b.source_name.to_lowercase()),
            MemoryColumn::Comment => a.comment.to_lowercase().cmp(&b.comment.to_lowercase()),
            MemoryColumn::ByteSource => Ordering::Equal,
        }
    }

    /// Get the address range for a set of row indices.
    ///
    /// Returns the combined address set as a list of (start, end) pairs.
    pub fn get_address_ranges(&self, rows: &[usize]) -> Vec<(Address, Address)> {
        rows.iter()
            .filter_map(|&row| self.blocks.get(row))
            .map(|b| (b.start(), b.end()))
            .collect()
    }
}

impl Default for MemoryMapModel {
    fn default() -> Self {
        Self {
            blocks: Vec::new(),
            sort_column: MemoryColumn::Start,
            sort_ascending: true,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;
    use ghidra_core::mem::MemoryMap;

    fn make_program() -> Program {
        let memory = MemoryMap::new(false);
        let mut p = Program::with_memory("test", Address::new(0), Box::new(memory));
        let _ = p.memory.create_initialized_block(
            ".data",
            Address::new(0x2000),
            vec![0u8; 0x800],
            false,
        );
        let _ = p.memory.create_initialized_block(
            ".text",
            Address::new(0x1000),
            vec![0u8; 0x1000],
            false,
        );
        let _ = p.memory.create_uninitialized_block(
            ".bss",
            Address::new(0x2800),
            0x400,
            false,
        );
        p
    }

    #[test]
    fn test_model_from_program() {
        let program = make_program();
        let model = MemoryMapModel::new(&program);
        assert_eq!(model.row_count(), 3);
        assert_eq!(model.column_count(), 15);
    }

    #[test]
    fn test_default_sort_by_start() {
        let program = make_program();
        let model = MemoryMapModel::new(&program);
        // Sorted by start address
        let b0 = model.get_block(0).unwrap();
        let b1 = model.get_block(1).unwrap();
        let b2 = model.get_block(2).unwrap();
        assert_eq!(b0.name, ".text");
        assert_eq!(b1.name, ".data");
        assert_eq!(b2.name, ".bss");
    }

    #[test]
    fn test_sort_by_name() {
        let program = make_program();
        let mut model = MemoryMapModel::new(&program);
        model.sort_by(MemoryColumn::Name);
        let b0 = model.get_block(0).unwrap();
        let b1 = model.get_block(1).unwrap();
        let b2 = model.get_block(2).unwrap();
        assert_eq!(b0.name, ".bss");
        assert_eq!(b1.name, ".data");
        assert_eq!(b2.name, ".text");
    }

    #[test]
    fn test_get_cell_value_name() {
        let program = make_program();
        let model = MemoryMapModel::new(&program);
        assert_eq!(
            model.get_cell_value(0, MemoryColumn::Name),
            Some(".text".into())
        );
    }

    #[test]
    fn test_get_cell_value_length() {
        let program = make_program();
        let model = MemoryMapModel::new(&program);
        assert_eq!(
            model.get_cell_value(0, MemoryColumn::Length),
            Some("0x1000".into())
        );
    }

    #[test]
    fn test_get_cell_value_init() {
        let program = make_program();
        let model = MemoryMapModel::new(&program);
        // .text is initialized
        assert_eq!(
            model.get_cell_value(0, MemoryColumn::Init),
            Some("true".into())
        );
        // .bss is uninitialized — it's at index 2
        assert_eq!(
            model.get_cell_value(2, MemoryColumn::Init),
            Some("false".into())
        );
    }

    #[test]
    fn test_column_name_lookup() {
        assert_eq!(MemoryColumn::from_name("Name"), Some(MemoryColumn::Name));
        assert_eq!(MemoryColumn::from_name("R"), Some(MemoryColumn::Read));
        assert_eq!(MemoryColumn::from_name("nonexistent"), None);
    }

    #[test]
    fn test_column_index_roundtrip() {
        for col in &MemoryColumn::ALL {
            assert_eq!(MemoryColumn::from_index(col.index()), Some(*col));
        }
    }

    #[test]
    fn test_sortable_columns() {
        assert!(MemoryColumn::Name.is_sortable());
        assert!(MemoryColumn::Start.is_sortable());
        assert!(!MemoryColumn::Read.is_sortable());
        assert!(!MemoryColumn::Execute.is_sortable());
    }

    #[test]
    fn test_editable_columns() {
        assert!(MemoryColumn::Name.is_editable());
        assert!(MemoryColumn::Comment.is_editable());
        assert!(!MemoryColumn::Start.is_editable());
        assert!(!MemoryColumn::Length.is_editable());
    }

    #[test]
    fn test_get_address_ranges() {
        let program = make_program();
        let model = MemoryMapModel::new(&program);
        let ranges = model.get_address_ranges(&[0, 2]);
        assert_eq!(ranges.len(), 2);
        // Row 0 is .text (0x1000), Row 2 is .bss (0x2800)
        assert_eq!(ranges[0].0, Address::new(0x1000));
        assert_eq!(ranges[1].0, Address::new(0x2800));
    }

    #[test]
    fn test_out_of_range_returns_none() {
        let program = make_program();
        let model = MemoryMapModel::new(&program);
        assert!(model.get_block(100).is_none());
        assert!(model.get_cell_value(100, MemoryColumn::Name).is_none());
    }
}
