//! Source files table plugin, provider, and row objects.
//!
//! Ported from `ghidra.app.plugin.core.sourcefilestable.SourceFilesTablePlugin`,
//! `SourceFilesTableProvider`, `SourceFileRowObject`, `SourceFilesTableModel`,
//! `SourceMapEntryRowObject`, `SourceMapEntryTableModel`, and mapper types.

use ghidra_core::Address;

// ---------------------------------------------------------------------------
// SourceFileRowObject
// ---------------------------------------------------------------------------

/// A row object representing a source file.
///
/// Ported from `ghidra.app.plugin.core.sourcefilestable.SourceFileRowObject`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFileRowObject {
    /// The source file path.
    pub path: String,
    /// The number of lines mapped in the program.
    pub line_count: usize,
    /// The number of functions containing lines from this file.
    pub function_count: usize,
    /// The language/compiler that produced this file.
    pub language: Option<String>,
}

impl SourceFileRowObject {
    /// Create a new source file row object.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            line_count: 0,
            function_count: 0,
            language: None,
        }
    }
}

// ---------------------------------------------------------------------------
// SourceMapEntryRowObject
// ---------------------------------------------------------------------------

/// A row object representing a source map entry (address-to-source-line mapping).
///
/// Ported from `ghidra.app.plugin.core.sourcefilestable.SourceMapEntryRowObject`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMapEntryRowObject {
    /// The program address.
    pub address: Address,
    /// The source file path.
    pub source_path: String,
    /// The source line number (1-based).
    pub line_number: u32,
    /// The column number (0 = unknown).
    pub column: u32,
}

impl SourceMapEntryRowObject {
    /// Create a new source map entry row.
    pub fn new(address: Address, source_path: impl Into<String>, line_number: u32) -> Self {
        Self {
            address,
            source_path: source_path.into(),
            line_number,
            column: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// SourceFilesTableModel
// ---------------------------------------------------------------------------

/// Table model for displaying source files.
///
/// Ported from `ghidra.app.plugin.core.sourcefilestable.SourceFilesTableModel`.
#[derive(Debug)]
pub struct SourceFilesTableModel {
    /// All source file rows.
    rows: Vec<SourceFileRowObject>,
    /// Sort column index.
    sort_column: usize,
    /// Sort ascending.
    sort_ascending: bool,
}

impl SourceFilesTableModel {
    /// Column: path.
    pub const COL_PATH: usize = 0;
    /// Column: line count.
    pub const COL_LINES: usize = 1;
    /// Column: function count.
    pub const COL_FUNCTIONS: usize = 2;
    /// Column: language.
    pub const COL_LANGUAGE: usize = 3;

    /// Create a new model.
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            sort_column: 0,
            sort_ascending: true,
        }
    }

    /// Add a row.
    pub fn add(&mut self, row: SourceFileRowObject) {
        self.rows.push(row);
    }

    /// Get the number of rows.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the model is empty.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Get a row by index.
    pub fn get(&self, index: usize) -> Option<&SourceFileRowObject> {
        self.rows.get(index)
    }

    /// Get all rows.
    pub fn rows(&self) -> &[SourceFileRowObject] {
        &self.rows
    }

    /// Sort by path.
    pub fn sort_by_path(&mut self) {
        self.rows.sort_by(|a, b| a.path.cmp(&b.path));
    }

    /// Sort by line count (descending).
    pub fn sort_by_lines(&mut self) {
        self.rows.sort_by(|a, b| b.line_count.cmp(&a.line_count));
    }

    /// Sort by function count (descending).
    pub fn sort_by_functions(&mut self) {
        self.rows
            .sort_by(|a, b| b.function_count.cmp(&a.function_count));
    }

    /// Get a cell value for display.
    pub fn cell_value(&self, row: usize, col: usize) -> Option<String> {
        let r = self.rows.get(row)?;
        Some(match col {
            Self::COL_PATH => r.path.clone(),
            Self::COL_LINES => r.line_count.to_string(),
            Self::COL_FUNCTIONS => r.function_count.to_string(),
            Self::COL_LANGUAGE => r.language.clone().unwrap_or_else(|| "-".to_string()),
            _ => return None,
        })
    }

    /// Get column names.
    pub fn column_names() -> &'static [&'static str] {
        &["Source File", "Lines", "Functions", "Language"]
    }

    /// Clear all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
    }
}

impl Default for SourceFilesTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SourceMapEntryTableModel
// ---------------------------------------------------------------------------

/// Table model for displaying source map entries.
///
/// Ported from `ghidra.app.plugin.core.sourcefilestable.SourceMapEntryTableModel`.
#[derive(Debug)]
pub struct SourceMapEntryTableModel {
    rows: Vec<SourceMapEntryRowObject>,
}

impl SourceMapEntryTableModel {
    /// Column: address.
    pub const COL_ADDRESS: usize = 0;
    /// Column: source path.
    pub const COL_SOURCE: usize = 1;
    /// Column: line number.
    pub const COL_LINE: usize = 2;

    /// Create a new model.
    pub fn new() -> Self {
        Self { rows: Vec::new() }
    }

    /// Add a row.
    pub fn add(&mut self, row: SourceMapEntryRowObject) {
        self.rows.push(row);
    }

    /// Get the number of rows.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the model is empty.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Get a row by index.
    pub fn get(&self, index: usize) -> Option<&SourceMapEntryRowObject> {
        self.rows.get(index)
    }

    /// Sort by address.
    pub fn sort_by_address(&mut self) {
        self.rows.sort_by_key(|r| r.address.offset);
    }

    /// Sort by source path then line.
    pub fn sort_by_source(&mut self) {
        self.rows
            .sort_by(|a, b| a.source_path.cmp(&b.source_path).then(a.line_number.cmp(&b.line_number)));
    }

    /// Get a cell value for display.
    pub fn cell_value(&self, row: usize, col: usize) -> Option<String> {
        let r = self.rows.get(row)?;
        Some(match col {
            Self::COL_ADDRESS => format!("0x{:08X}", r.address.offset),
            Self::COL_SOURCE => r.source_path.clone(),
            Self::COL_LINE => r.line_number.to_string(),
            _ => return None,
        })
    }

    /// Get column names.
    pub fn column_names() -> &'static [&'static str] {
        &["Address", "Source File", "Line"]
    }

    /// Clear all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
    }
}

impl Default for SourceMapEntryTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TransformerTableModel
// ---------------------------------------------------------------------------

/// Table model that transforms source map entries to address table rows.
///
/// Ported from `ghidra.app.plugin.core.sourcefilestable.TransformerTableModel`.
#[derive(Debug)]
pub struct TransformerTableModel {
    entries: Vec<SourceMapEntryRowObject>,
}

impl TransformerTableModel {
    /// Create a new transformer model.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add an entry.
    pub fn add(&mut self, entry: SourceMapEntryRowObject) {
        self.entries.push(entry);
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the model is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the address for an entry (for address table mapping).
    pub fn address_for_row(&self, row: usize) -> Option<Address> {
        self.entries.get(row).map(|e| e.address)
    }

    /// Get all addresses.
    pub fn addresses(&self) -> Vec<Address> {
        self.entries.iter().map(|e| e.address).collect()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl Default for TransformerTableModel {
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
        let mut row = SourceFileRowObject::new("/src/main.c");
        assert_eq!(row.path, "/src/main.c");
        assert_eq!(row.line_count, 0);

        row.line_count = 150;
        row.function_count = 10;
        row.language = Some("C".to_string());
        assert_eq!(row.language.as_deref(), Some("C"));
    }

    #[test]
    fn test_source_map_entry_row_object() {
        let entry = SourceMapEntryRowObject::new(Address::new(0x400000), "main.c", 42);
        assert_eq!(entry.address.offset, 0x400000);
        assert_eq!(entry.source_path, "main.c");
        assert_eq!(entry.line_number, 42);
        assert_eq!(entry.column, 0);
    }

    #[test]
    fn test_source_files_table_model() {
        let mut model = SourceFilesTableModel::new();
        assert!(model.is_empty());

        let mut r1 = SourceFileRowObject::new("b.c");
        r1.line_count = 20;
        r1.function_count = 5;
        let mut r2 = SourceFileRowObject::new("a.c");
        r2.line_count = 50;
        r2.function_count = 15;

        model.add(r1);
        model.add(r2);
        assert_eq!(model.len(), 2);

        model.sort_by_path();
        assert_eq!(model.get(0).unwrap().path, "a.c");

        model.sort_by_lines();
        assert_eq!(model.get(0).unwrap().line_count, 50);

        model.sort_by_functions();
        assert_eq!(model.get(0).unwrap().function_count, 15);
    }

    #[test]
    fn test_source_files_table_cell_values() {
        let mut model = SourceFilesTableModel::new();
        let mut row = SourceFileRowObject::new("test.c");
        row.line_count = 42;
        row.function_count = 7;
        row.language = Some("C99".to_string());
        model.add(row);

        assert_eq!(
            model.cell_value(0, SourceFilesTableModel::COL_PATH),
            Some("test.c".to_string())
        );
        assert_eq!(
            model.cell_value(0, SourceFilesTableModel::COL_LINES),
            Some("42".to_string())
        );
        assert_eq!(
            model.cell_value(0, SourceFilesTableModel::COL_LANGUAGE),
            Some("C99".to_string())
        );
        assert_eq!(model.cell_value(99, 0), None);
    }

    #[test]
    fn test_source_map_entry_table_model() {
        let mut model = SourceMapEntryTableModel::new();
        model.add(SourceMapEntryRowObject::new(Address::new(0x3000), "b.c", 10));
        model.add(SourceMapEntryRowObject::new(Address::new(0x1000), "a.c", 5));
        assert_eq!(model.len(), 2);

        model.sort_by_address();
        assert_eq!(model.get(0).unwrap().address.offset, 0x1000);

        model.sort_by_source();
        assert_eq!(model.get(0).unwrap().source_path, "a.c");
    }

    #[test]
    fn test_source_map_entry_cell_values() {
        let mut model = SourceMapEntryTableModel::new();
        model.add(SourceMapEntryRowObject::new(Address::new(0x400000), "main.c", 100));

        assert_eq!(
            model.cell_value(0, SourceMapEntryTableModel::COL_ADDRESS),
            Some("0x00400000".to_string())
        );
        assert_eq!(
            model.cell_value(0, SourceMapEntryTableModel::COL_LINE),
            Some("100".to_string())
        );
    }

    #[test]
    fn test_transformer_table_model() {
        let mut model = TransformerTableModel::new();
        model.add(SourceMapEntryRowObject::new(Address::new(0x1000), "a.c", 1));
        model.add(SourceMapEntryRowObject::new(Address::new(0x2000), "b.c", 5));
        assert_eq!(model.len(), 2);

        assert_eq!(model.address_for_row(0), Some(Address::new(0x1000)));
        assert_eq!(model.address_for_row(99), None);

        let addrs = model.addresses();
        assert_eq!(addrs, vec![Address::new(0x1000), Address::new(0x2000)]);
    }

    #[test]
    fn test_column_names() {
        assert_eq!(SourceFilesTableModel::column_names().len(), 4);
        assert_eq!(SourceMapEntryTableModel::column_names().len(), 3);
    }

    #[test]
    fn test_clear() {
        let mut model = SourceFilesTableModel::new();
        model.add(SourceFileRowObject::new("test.c"));
        model.clear();
        assert!(model.is_empty());
    }
}
