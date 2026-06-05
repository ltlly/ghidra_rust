//! Source files table model, row objects, and plugin.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.sourcefilestable` Java package:
//! `SourceFilesTableModel`, `SourceFileRowObject`, `SourceFilesTablePlugin`,
//! `SourceFilesTableProvider`, `SourceMapEntryRowObject`,
//! `SourceMapEntryTableModel`, `SourceMapEntryToAddressTableRowMapper`,
//! `SourceMapEntryToProgramLocationRowMapper`, `TransformerTableModel`.

use ghidra_core::Address;

// ============================================================================
// SourceFileRowObject -- a row in the source files table
// ============================================================================

/// A row in the source files table.
///
/// Ported from `ghidra.app.plugin.core.sourcefilestable.SourceFileRowObject`.
#[derive(Debug, Clone)]
pub struct SourceFileRowObject {
    /// The source file path.
    pub path: String,
    /// The source language.
    pub language: String,
    /// The number of source lines mapped.
    pub line_count: usize,
    /// The number of mapped address ranges.
    pub range_count: usize,
}

impl SourceFileRowObject {
    /// Create a new source file row object.
    pub fn new(
        path: impl Into<String>,
        language: impl Into<String>,
        line_count: usize,
        range_count: usize,
    ) -> Self {
        Self {
            path: path.into(),
            language: language.into(),
            line_count,
            range_count,
        }
    }
}

// ============================================================================
// SourceMapEntryRowObject -- a source map entry
// ============================================================================

/// A source map entry mapping an address range to a source file line.
///
/// Ported from `ghidra.app.plugin.core.sourcefilestable.SourceMapEntryRowObject`.
#[derive(Debug, Clone)]
pub struct SourceMapEntryRowObject {
    /// The start address.
    pub start_address: Address,
    /// The end address.
    pub end_address: Address,
    /// The source file path.
    pub source_file: String,
    /// The source line number.
    pub line_number: u32,
    /// The column number (0 = unknown).
    pub column_number: u32,
}

impl SourceMapEntryRowObject {
    /// Create a new source map entry row.
    pub fn new(
        start: Address,
        end: Address,
        source_file: impl Into<String>,
        line_number: u32,
    ) -> Self {
        Self {
            start_address: start,
            end_address: end,
            source_file: source_file.into(),
            line_number,
            column_number: 0,
        }
    }

    /// The size of the mapped range.
    pub fn range_size(&self) -> u64 {
        self.end_address.offset.saturating_sub(self.start_address.offset) + 1
    }
}

// ============================================================================
// SourceFilesTableModel -- table model for source files
// ============================================================================

/// Column definitions for the source files table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceFileColumn {
    /// Source file path.
    Path,
    /// Language.
    Language,
    /// Number of source lines.
    LineCount,
    /// Number of mapped ranges.
    RangeCount,
}

impl SourceFileColumn {
    /// All columns in display order.
    pub fn all() -> &'static [SourceFileColumn] {
        &[
            Self::Path,
            Self::Language,
            Self::LineCount,
            Self::RangeCount,
        ]
    }

    /// Column header.
    pub fn header(&self) -> &'static str {
        match self {
            Self::Path => "Source File",
            Self::Language => "Language",
            Self::LineCount => "Lines",
            Self::RangeCount => "Ranges",
        }
    }
}

/// Table model for displaying source files.
///
/// Ported from `ghidra.app.plugin.core.sourcefilestable.SourceFilesTableModel`.
#[derive(Debug, Default)]
pub struct SourceFilesTableModel {
    /// Rows.
    rows: Vec<SourceFileRowObject>,
}

impl SourceFilesTableModel {
    /// Create a new empty model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a row.
    pub fn add_row(&mut self, row: SourceFileRowObject) {
        self.rows.push(row);
    }

    /// Get the row count.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get a row by index.
    pub fn get_row(&self, index: usize) -> Option<&SourceFileRowObject> {
        self.rows.get(index)
    }

    /// Get all rows.
    pub fn all_rows(&self) -> &[SourceFileRowObject] {
        &self.rows
    }

    /// Sort by column.
    pub fn sort_by(&mut self, column: SourceFileColumn, ascending: bool) {
        match column {
            SourceFileColumn::Path => {
                self.rows.sort_by(|a, b| a.path.cmp(&b.path));
            }
            SourceFileColumn::Language => {
                self.rows.sort_by(|a, b| a.language.cmp(&b.language));
            }
            SourceFileColumn::LineCount => {
                self.rows.sort_by_key(|r| r.line_count);
            }
            SourceFileColumn::RangeCount => {
                self.rows.sort_by_key(|r| r.range_count);
            }
        }
        if !ascending {
            self.rows.reverse();
        }
    }

    /// Clear all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
    }
}

// ============================================================================
// SourceMapEntryTableModel -- table model for source map entries
// ============================================================================

/// Table model for source map entries.
///
/// Ported from `ghidra.app.plugin.core.sourcefilestable.SourceMapEntryTableModel`.
#[derive(Debug, Default)]
pub struct SourceMapEntryTableModel {
    /// Entries.
    entries: Vec<SourceMapEntryRowObject>,
}

impl SourceMapEntryTableModel {
    /// Create a new empty model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry.
    pub fn add_entry(&mut self, entry: SourceMapEntryRowObject) {
        self.entries.push(entry);
    }

    /// Entry count.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get an entry by index.
    pub fn get_entry(&self, index: usize) -> Option<&SourceMapEntryRowObject> {
        self.entries.get(index)
    }

    /// Filter entries for a specific source file.
    pub fn filter_by_source(&self, source_file: &str) -> Vec<&SourceMapEntryRowObject> {
        self.entries
            .iter()
            .filter(|e| e.source_file == source_file)
            .collect()
    }

    /// Sort by start address.
    pub fn sort_by_address(&mut self, ascending: bool) {
        self.entries.sort_by_key(|e| e.start_address.offset);
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
// Address mapper for source map entries
// ============================================================================

/// Maps a source map entry row to an address.
///
/// Ported from
/// `ghidra.app.plugin.core.sourcefilestable.SourceMapEntryToAddressTableRowMapper`.
#[derive(Debug)]
pub struct SourceMapEntryToAddressMapper;

impl SourceMapEntryToAddressMapper {
    /// Map a source map entry to its start address.
    pub fn map(entry: &SourceMapEntryRowObject) -> Address {
        entry.start_address
    }
}

/// Maps a source map entry to a program location.
///
/// Ported from
/// `ghidra.app.plugin.core.sourcefilestable.SourceMapEntryToProgramLocationRowMapper`.
#[derive(Debug)]
pub struct SourceMapEntryToProgramLocationMapper;

impl SourceMapEntryToProgramLocationMapper {
    /// Map a source map entry to a (address, source_file, line) tuple.
    pub fn map(entry: &SourceMapEntryRowObject) -> (Address, &str, u32) {
        (entry.start_address, &entry.source_file, entry.line_number)
    }
}

// ============================================================================
// SourceFilesTablePlugin -- plugin for source files table
// ============================================================================

/// Plugin for the source files table view.
///
/// Ported from `ghidra.app.plugin.core.sourcefilestable.SourceFilesTablePlugin`.
#[derive(Debug)]
pub struct SourceFilesTablePlugin {
    /// The source files table model.
    pub model: SourceFilesTableModel,
    /// The source map entry model.
    pub entry_model: SourceMapEntryTableModel,
    /// Whether the plugin is disposed.
    disposed: bool,
}

impl SourceFilesTablePlugin {
    /// Create a new plugin.
    pub fn new() -> Self {
        Self {
            model: SourceFilesTableModel::new(),
            entry_model: SourceMapEntryTableModel::new(),
            disposed: false,
        }
    }

    /// Add a source file.
    pub fn add_source_file(&mut self, row: SourceFileRowObject) {
        self.model.add_row(row);
    }

    /// Add a source map entry.
    pub fn add_source_map_entry(&mut self, entry: SourceMapEntryRowObject) {
        self.entry_model.add_entry(entry);
    }

    /// Get the total number of source files.
    pub fn source_file_count(&self) -> usize {
        self.model.row_count()
    }

    /// Get the total number of source map entries.
    pub fn source_map_entry_count(&self) -> usize {
        self.entry_model.entry_count()
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

impl Default for SourceFilesTablePlugin {
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
    fn test_source_file_row_object() {
        let row = SourceFileRowObject::new("main.c", "C", 150, 5);
        assert_eq!(row.path, "main.c");
        assert_eq!(row.language, "C");
        assert_eq!(row.line_count, 150);
        assert_eq!(row.range_count, 5);
    }

    #[test]
    fn test_source_map_entry() {
        let entry = SourceMapEntryRowObject::new(
            Address::new(0x1000),
            Address::new(0x1FFF),
            "main.c",
            42,
        );
        assert_eq!(entry.range_size(), 0x1000);
        assert_eq!(entry.line_number, 42);
    }

    #[test]
    fn test_source_files_table_model() {
        let mut model = SourceFilesTableModel::new();
        model.add_row(SourceFileRowObject::new("a.c", "C", 100, 3));
        model.add_row(SourceFileRowObject::new("b.c", "C", 200, 5));
        assert_eq!(model.row_count(), 2);

        model.sort_by(SourceFileColumn::LineCount, true);
        assert_eq!(model.get_row(0).unwrap().line_count, 100);
        assert_eq!(model.get_row(1).unwrap().line_count, 200);

        model.sort_by(SourceFileColumn::LineCount, false);
        assert_eq!(model.get_row(0).unwrap().line_count, 200);
    }

    #[test]
    fn test_source_files_table_model_sort_by_path() {
        let mut model = SourceFilesTableModel::new();
        model.add_row(SourceFileRowObject::new("z.c", "C", 10, 1));
        model.add_row(SourceFileRowObject::new("a.c", "C", 20, 2));
        model.sort_by(SourceFileColumn::Path, true);
        assert_eq!(model.get_row(0).unwrap().path, "a.c");
    }

    #[test]
    fn test_source_map_entry_table_model() {
        let mut model = SourceMapEntryTableModel::new();
        model.add_entry(SourceMapEntryRowObject::new(
            Address::new(0x1000),
            Address::new(0x1FFF),
            "a.c",
            10,
        ));
        model.add_entry(SourceMapEntryRowObject::new(
            Address::new(0x2000),
            Address::new(0x2FFF),
            "b.c",
            20,
        ));
        assert_eq!(model.entry_count(), 2);

        let filtered = model.filter_by_source("a.c");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].source_file, "a.c");
    }

    #[test]
    fn test_source_map_entry_sort_by_address() {
        let mut model = SourceMapEntryTableModel::new();
        model.add_entry(SourceMapEntryRowObject::new(
            Address::new(0x3000),
            Address::new(0x3FFF),
            "a.c",
            10,
        ));
        model.add_entry(SourceMapEntryRowObject::new(
            Address::new(0x1000),
            Address::new(0x1FFF),
            "b.c",
            20,
        ));
        model.sort_by_address(true);
        assert_eq!(model.get_entry(0).unwrap().start_address, Address::new(0x1000));
    }

    #[test]
    fn test_source_map_entry_mappers() {
        let entry = SourceMapEntryRowObject::new(
            Address::new(0x4000),
            Address::new(0x4FFF),
            "test.c",
            50,
        );
        assert_eq!(
            SourceMapEntryToAddressMapper::map(&entry),
            Address::new(0x4000)
        );
        let (addr, file, line) = SourceMapEntryToProgramLocationMapper::map(&entry);
        assert_eq!(addr, Address::new(0x4000));
        assert_eq!(file, "test.c");
        assert_eq!(line, 50);
    }

    #[test]
    fn test_source_files_table_plugin() {
        let mut plugin = SourceFilesTablePlugin::new();
        assert!(!plugin.is_disposed());
        assert_eq!(plugin.source_file_count(), 0);
        assert_eq!(plugin.source_map_entry_count(), 0);

        plugin.add_source_file(SourceFileRowObject::new("main.c", "C", 100, 3));
        plugin.add_source_map_entry(SourceMapEntryRowObject::new(
            Address::new(0x1000),
            Address::new(0x1FFF),
            "main.c",
            10,
        ));
        assert_eq!(plugin.source_file_count(), 1);
        assert_eq!(plugin.source_map_entry_count(), 1);

        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_source_file_column_headers() {
        assert_eq!(SourceFileColumn::Path.header(), "Source File");
        assert_eq!(SourceFileColumn::Language.header(), "Language");
        assert_eq!(SourceFileColumn::LineCount.header(), "Lines");
        assert_eq!(SourceFileColumn::RangeCount.header(), "Ranges");
        assert_eq!(SourceFileColumn::all().len(), 4);
    }

    #[test]
    fn test_source_files_table_model_clear() {
        let mut model = SourceFilesTableModel::new();
        model.add_row(SourceFileRowObject::new("a.c", "C", 10, 1));
        assert_eq!(model.row_count(), 1);
        model.clear();
        assert_eq!(model.row_count(), 0);
    }

    #[test]
    fn test_source_map_entry_table_model_clear() {
        let mut model = SourceMapEntryTableModel::new();
        model.add_entry(SourceMapEntryRowObject::new(
            Address::new(0x1000),
            Address::new(0x1FFF),
            "a.c",
            10,
        ));
        model.clear();
        assert_eq!(model.entry_count(), 0);
    }
}
