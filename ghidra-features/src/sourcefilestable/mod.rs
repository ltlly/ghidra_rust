//! Source Files Table -- display source file information.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.sourcefilestable` Java package.
//!
//! Provides model-level logic for displaying and querying source file
//! information associated with a program's debug info.

/// Source files table model, row objects, and plugin.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.sourcefilestable` Java package.
pub mod model;

/// Source files table plugin, provider, row objects, and table models.
///
/// Ported from `ghidra.app.plugin.core.sourcefilestable.SourceFilesTablePlugin`,
/// `SourceFilesTableProvider`, `SourceFileRowObject`, `SourceFilesTableModel`,
/// `SourceMapEntryRowObject`, `SourceMapEntryTableModel`, and
/// `TransformerTableModel`.
pub mod plugin;

use ghidra_core::Address;
use std::collections::HashMap;

/// A source file entry from debug information.
#[derive(Debug, Clone)]
pub struct SourceFileEntry {
    /// The source file path.
    pub path: String,
    /// The source language (e.g. "C", "C++", "Rust").
    pub language: String,
    /// The number of code units associated with this file.
    pub code_unit_count: u32,
    /// Line count if known.
    pub line_count: Option<u32>,
    /// Whether this file was found on disk.
    pub found_on_disk: bool,
}

impl SourceFileEntry {
    /// Create a new source file entry.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            language: String::new(),
            code_unit_count: 0,
            line_count: None,
            found_on_disk: false,
        }
    }
}

/// Model for the source files table.
#[derive(Debug, Default)]
pub struct SourceFilesTableModel {
    entries: Vec<SourceFileEntry>,
    by_language: HashMap<String, Vec<usize>>,
}

impl SourceFilesTableModel {
    /// Create a new model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a source file entry.
    pub fn add_entry(&mut self, entry: SourceFileEntry) {
        let idx = self.entries.len();
        self.by_language
            .entry(entry.language.clone())
            .or_default()
            .push(idx);
        self.entries.push(entry);
    }

    /// Get all entries.
    pub fn get_all_entries(&self) -> &[SourceFileEntry] {
        &self.entries
    }

    /// Get entries for a specific language.
    pub fn get_entries_for_language(&self, language: &str) -> Vec<&SourceFileEntry> {
        self.by_language
            .get(language)
            .map(|indices| {
                indices
                    .iter()
                    .filter_map(|&i| self.entries.get(i))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return the total number of source files.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get a list of unique languages in the model.
    pub fn unique_languages(&self) -> Vec<String> {
        self.by_language.keys().cloned().collect()
    }

    /// Get the total code unit count across all source files.
    pub fn total_code_units(&self) -> u32 {
        self.entries.iter().map(|e| e.code_unit_count).sum()
    }

    /// Get source files that were found on disk.
    pub fn files_found_on_disk(&self) -> Vec<&SourceFileEntry> {
        self.entries.iter().filter(|e| e.found_on_disk).collect()
    }

    /// Get source files that were NOT found on disk.
    pub fn files_not_found(&self) -> Vec<&SourceFileEntry> {
        self.entries.iter().filter(|e| !e.found_on_disk).collect()
    }

    /// Get entries sorted by code unit count.
    ///
    /// If `ascending` is true, sorts from smallest to largest.
    pub fn get_entries_sorted_by_code_units(&self, ascending: bool) -> Vec<&SourceFileEntry> {
        let mut sorted: Vec<&SourceFileEntry> = self.entries.iter().collect();
        if ascending {
            sorted.sort_by_key(|e| e.code_unit_count);
        } else {
            sorted.sort_by(|a, b| b.code_unit_count.cmp(&a.code_unit_count));
        }
        sorted
    }

    /// Get entries filtered by file extension.
    pub fn get_entries_by_extension(&self, ext: &str) -> Vec<&SourceFileEntry> {
        self.entries
            .iter()
            .filter(|e| {
                e.path
                    .rsplit('.')
                    .next()
                    .map_or(false, |file_ext| file_ext.eq_ignore_ascii_case(ext))
            })
            .collect()
    }
}

// ============================================================================
// SourceFileIdType -- how a source file is identified
// ============================================================================

/// How a source file is identified in the source map.
///
/// Ported from `ghidra.program.database.sourcemap.SourceFileIdType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceFileIdType {
    /// Identified by absolute path on disk.
    AbsolutePath,
    /// Identified by relative path.
    RelativePath,
    /// Identified by a unique identifier (e.g., build ID, UUID).
    UniqueId,
    /// Identified by a content hash.
    ContentHash,
    /// Unknown identification method.
    Unknown,
}

impl SourceFileIdType {
    /// Display name for this ID type.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::AbsolutePath => "Absolute Path",
            Self::RelativePath => "Relative Path",
            Self::UniqueId => "Unique ID",
            Self::ContentHash => "Content Hash",
            Self::Unknown => "Unknown",
        }
    }
}

impl std::fmt::Display for SourceFileIdType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ============================================================================
// SourceFileRowObject -- row object for source file table
// ============================================================================

/// A row in the source files table.
///
/// Ported from `ghidra.app.plugin.core.sourcefilestable.SourceFileRowObject`.
#[derive(Debug, Clone)]
pub struct SourceFileRowObject {
    /// The source file name (basename).
    pub file_name: String,
    /// The full path of the source file.
    pub path: String,
    /// How this source file is identified.
    pub id_type: SourceFileIdType,
    /// The identifier string (path, UUID, hash, etc.).
    pub identifier: String,
    /// The transformed path (after applying path transformers).
    pub transformed_path: Option<String>,
    /// The number of source map entries associated with this file.
    pub num_entries: usize,
}

impl SourceFileRowObject {
    /// Create a new source file row object.
    pub fn new(
        file_name: impl Into<String>,
        path: impl Into<String>,
        id_type: SourceFileIdType,
    ) -> Self {
        let p = path.into();
        Self {
            file_name: file_name.into(),
            path: p.clone(),
            id_type,
            identifier: String::new(),
            transformed_path: None,
            num_entries: 0,
        }
    }

    /// Get the file name.
    pub fn get_file_name(&self) -> &str {
        &self.file_name
    }

    /// Get the path.
    pub fn get_path(&self) -> &str {
        &self.path
    }

    /// Get the source file ID type.
    pub fn get_id_type(&self) -> SourceFileIdType {
        self.id_type
    }

    /// Get the identifier.
    pub fn get_identifier(&self) -> &str {
        &self.identifier
    }

    /// Get the transformed path.
    pub fn get_transformed_path(&self) -> Option<&str> {
        self.transformed_path.as_deref()
    }

    /// Get the number of source map entries.
    pub fn get_num_entries(&self) -> usize {
        self.num_entries
    }
}

// ============================================================================
// SourceMapEntryRowObject -- row object for source map entries
// ============================================================================

/// A row in the source map entries table.
///
/// Ported from `ghidra.app.plugin.core.sourcefilestable.SourceMapEntryRowObject`.
#[derive(Debug, Clone)]
pub struct SourceMapEntryRowObject {
    /// The source file path.
    pub source_file_path: String,
    /// The line number in the source file.
    pub line_number: u32,
    /// The address in the program.
    pub address: Address,
    /// The length of the mapping (number of bytes).
    pub length: usize,
    /// Optional column number.
    pub column_number: Option<u32>,
}

impl SourceMapEntryRowObject {
    /// Create a new source map entry row.
    pub fn new(
        source_file_path: impl Into<String>,
        line_number: u32,
        address: Address,
        length: usize,
    ) -> Self {
        Self {
            source_file_path: source_file_path.into(),
            line_number,
            address,
            length,
            column_number: None,
        }
    }

    /// Get the end address of this mapping.
    pub fn end_address(&self) -> u64 {
        self.address.offset + self.length as u64
    }

    /// Get a display string for the line/column.
    pub fn location_display(&self) -> String {
        match self.column_number {
            Some(col) => format!("{}:{}", self.line_number, col),
            None => format!("{}", self.line_number),
        }
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
    entries: Vec<SourceMapEntryRowObject>,
    by_address: HashMap<u64, Vec<usize>>,
    by_source_file: HashMap<String, Vec<usize>>,
}

impl SourceMapEntryTableModel {
    /// Create a new model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a source map entry.
    pub fn add_entry(&mut self, entry: SourceMapEntryRowObject) {
        let idx = self.entries.len();
        self.by_address
            .entry(entry.address.offset)
            .or_default()
            .push(idx);
        self.by_source_file
            .entry(entry.source_file_path.clone())
            .or_default()
            .push(idx);
        self.entries.push(entry);
    }

    /// Get the entry count.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get entries at a given address.
    pub fn get_entries_at_address(&self, addr: Address) -> Vec<&SourceMapEntryRowObject> {
        self.by_address
            .get(&addr.offset)
            .map(|indices| {
                indices
                    .iter()
                    .filter_map(|&i| self.entries.get(i))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get entries for a source file.
    pub fn get_entries_for_file(&self, path: &str) -> Vec<&SourceMapEntryRowObject> {
        self.by_source_file
            .get(path)
            .map(|indices| {
                indices
                    .iter()
                    .filter_map(|&i| self.entries.get(i))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all entries.
    pub fn all_entries(&self) -> &[SourceMapEntryRowObject] {
        &self.entries
    }

    /// Get unique source file paths.
    pub fn unique_source_files(&self) -> Vec<&str> {
        self.by_source_file.keys().map(|s| s.as_str()).collect()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.by_address.clear();
        self.by_source_file.clear();
    }
}

// ============================================================================
// TransformerTableModel -- table model for path transformers
// ============================================================================

/// A path transformation entry.
///
/// Ported from `ghidra.app.plugin.core.sourcefilestable.TransformerTableModel`.
#[derive(Debug, Clone)]
pub struct PathTransformerEntry {
    /// The original path.
    pub original_path: String,
    /// The transformed path.
    pub transformed_path: String,
    /// The transformer name.
    pub transformer_name: String,
    /// Whether the transformation was applied successfully.
    pub applied: bool,
}

impl PathTransformerEntry {
    /// Create a new path transformer entry.
    pub fn new(
        original_path: impl Into<String>,
        transformed_path: impl Into<String>,
        transformer_name: impl Into<String>,
    ) -> Self {
        Self {
            original_path: original_path.into(),
            transformed_path: transformed_path.into(),
            transformer_name: transformer_name.into(),
            applied: true,
        }
    }
}

/// Table model for path transformer entries.
#[derive(Debug, Default)]
pub struct TransformerTableModel {
    entries: Vec<PathTransformerEntry>,
}

impl TransformerTableModel {
    /// Create a new model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry.
    pub fn add_entry(&mut self, entry: PathTransformerEntry) {
        self.entries.push(entry);
    }

    /// Get the entry count.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get an entry by index.
    pub fn get_entry(&self, index: usize) -> Option<&PathTransformerEntry> {
        self.entries.get(index)
    }

    /// Get all entries.
    pub fn all_entries(&self) -> &[PathTransformerEntry] {
        &self.entries
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ============================================================================
// SourceFilesTablePlugin -- plugin for source files table
// ============================================================================

/// Plugin providing the source files table.
///
/// Ported from `ghidra.app.plugin.core.sourcefilestable.SourceFilesTablePlugin`.
#[derive(Debug)]
pub struct SourceFilesTablePlugin {
    /// Plugin name.
    pub name: String,
    /// Current program name.
    current_program: Option<String>,
    /// Source file table model.
    pub source_file_model: SourceFilesTableModel,
    /// Source map entry table model.
    pub entry_model: SourceMapEntryTableModel,
    /// Transformer table model.
    pub transformer_model: TransformerTableModel,
    /// Whether the plugin is disposed.
    disposed: bool,
}

impl SourceFilesTablePlugin {
    /// Create a new plugin.
    pub fn new() -> Self {
        Self {
            name: "SourceFilesTable".into(),
            current_program: None,
            source_file_model: SourceFilesTableModel::new(),
            entry_model: SourceMapEntryTableModel::new(),
            transformer_model: TransformerTableModel::new(),
            disposed: false,
        }
    }

    /// Set the current program.
    pub fn set_current_program(&mut self, program_name: Option<String>) {
        self.current_program = program_name;
    }

    /// Get the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Dispose the plugin.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.source_file_model = SourceFilesTableModel::new();
        self.entry_model.clear();
        self.transformer_model.clear();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get_entries() {
        let mut model = SourceFilesTableModel::new();
        let mut e = SourceFileEntry::new("/src/main.c");
        e.language = "C".into();
        e.code_unit_count = 100;
        model.add_entry(e);
        assert_eq!(model.entry_count(), 1);
        assert_eq!(model.get_all_entries()[0].path, "/src/main.c");
    }

    #[test]
    fn test_get_by_language() {
        let mut model = SourceFilesTableModel::new();
        let mut e1 = SourceFileEntry::new("/src/main.c");
        e1.language = "C".into();
        let mut e2 = SourceFileEntry::new("/src/main.rs");
        e2.language = "Rust".into();
        let mut e3 = SourceFileEntry::new("/src/util.c");
        e3.language = "C".into();
        model.add_entry(e1);
        model.add_entry(e2);
        model.add_entry(e3);
        assert_eq!(model.get_entries_for_language("C").len(), 2);
        assert_eq!(model.get_entries_for_language("Rust").len(), 1);
    }

    #[test]
    fn test_unique_languages() {
        let mut model = SourceFilesTableModel::new();
        let mut e1 = SourceFileEntry::new("a.c");
        e1.language = "C".into();
        let mut e2 = SourceFileEntry::new("b.rs");
        e2.language = "Rust".into();
        let mut e3 = SourceFileEntry::new("c.c");
        e3.language = "C".into();
        model.add_entry(e1);
        model.add_entry(e2);
        model.add_entry(e3);
        let langs = model.unique_languages();
        assert_eq!(langs.len(), 2);
        assert!(langs.contains(&"C".to_string()));
        assert!(langs.contains(&"Rust".to_string()));
    }

    #[test]
    fn test_total_code_units() {
        let mut model = SourceFilesTableModel::new();
        let mut e1 = SourceFileEntry::new("a.c");
        e1.code_unit_count = 100;
        let mut e2 = SourceFileEntry::new("b.c");
        e2.code_unit_count = 200;
        model.add_entry(e1);
        model.add_entry(e2);
        assert_eq!(model.total_code_units(), 300);
    }

    #[test]
    fn test_files_on_disk() {
        let mut model = SourceFilesTableModel::new();
        let mut e1 = SourceFileEntry::new("found.c");
        e1.found_on_disk = true;
        let mut e2 = SourceFileEntry::new("missing.c");
        e2.found_on_disk = false;
        model.add_entry(e1);
        model.add_entry(e2);
        assert_eq!(model.files_found_on_disk().len(), 1);
        assert_eq!(model.files_not_found().len(), 1);
    }

    #[test]
    fn test_sorted_by_code_units() {
        let mut model = SourceFilesTableModel::new();
        let mut e1 = SourceFileEntry::new("small.c");
        e1.code_unit_count = 10;
        let mut e2 = SourceFileEntry::new("large.c");
        e2.code_unit_count = 1000;
        let mut e3 = SourceFileEntry::new("medium.c");
        e3.code_unit_count = 100;
        model.add_entry(e1);
        model.add_entry(e2);
        model.add_entry(e3);
        let sorted = model.get_entries_sorted_by_code_units(false);
        assert_eq!(sorted[0].path, "large.c");
        assert_eq!(sorted[1].path, "medium.c");
        assert_eq!(sorted[2].path, "small.c");
    }

    #[test]
    fn test_file_extension_filter() {
        let mut model = SourceFilesTableModel::new();
        model.add_entry(SourceFileEntry::new("main.c"));
        model.add_entry(SourceFileEntry::new("util.h"));
        model.add_entry(SourceFileEntry::new("lib.rs"));
        let c_files = model.get_entries_by_extension("c");
        assert_eq!(c_files.len(), 1);
        assert_eq!(c_files[0].path, "main.c");
    }

    // --- SourceFileIdType tests ---

    #[test]
    fn test_source_file_id_type_display() {
        assert_eq!(SourceFileIdType::AbsolutePath.display_name(), "Absolute Path");
        assert_eq!(SourceFileIdType::UniqueId.to_string(), "Unique ID");
    }

    // --- SourceFileRowObject tests ---

    #[test]
    fn test_source_file_row_object() {
        let row = SourceFileRowObject::new("main.c", "/src/main.c", SourceFileIdType::AbsolutePath);
        assert_eq!(row.get_file_name(), "main.c");
        assert_eq!(row.get_path(), "/src/main.c");
        assert_eq!(row.get_id_type(), SourceFileIdType::AbsolutePath);
        assert_eq!(row.get_num_entries(), 0);
    }

    // --- SourceMapEntryRowObject tests ---

    #[test]
    fn test_source_map_entry_row_object() {
        let entry = SourceMapEntryRowObject::new("main.c", 42, Address::new(0x1000), 10);
        assert_eq!(entry.source_file_path, "main.c");
        assert_eq!(entry.line_number, 42);
        assert_eq!(entry.address.offset, 0x1000);
        assert_eq!(entry.length, 10);
        assert_eq!(entry.end_address(), 0x100A);
        assert_eq!(entry.location_display(), "42");
    }

    #[test]
    fn test_source_map_entry_with_column() {
        let mut entry = SourceMapEntryRowObject::new("main.c", 10, Address::new(0x1000), 5);
        entry.column_number = Some(5);
        assert_eq!(entry.location_display(), "10:5");
    }

    // --- SourceMapEntryTableModel tests ---

    #[test]
    fn test_source_map_entry_table_model() {
        let mut model = SourceMapEntryTableModel::new();
        model.add_entry(SourceMapEntryRowObject::new("main.c", 10, Address::new(0x1000), 5));
        model.add_entry(SourceMapEntryRowObject::new("main.c", 20, Address::new(0x2000), 5));
        model.add_entry(SourceMapEntryRowObject::new("util.c", 5, Address::new(0x1000), 3));
        assert_eq!(model.entry_count(), 3);
    }

    #[test]
    fn test_source_map_entry_by_address() {
        let mut model = SourceMapEntryTableModel::new();
        model.add_entry(SourceMapEntryRowObject::new("main.c", 10, Address::new(0x1000), 5));
        model.add_entry(SourceMapEntryRowObject::new("util.c", 5, Address::new(0x1000), 3));
        let entries = model.get_entries_at_address(Address::new(0x1000));
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_source_map_entry_by_file() {
        let mut model = SourceMapEntryTableModel::new();
        model.add_entry(SourceMapEntryRowObject::new("main.c", 10, Address::new(0x1000), 5));
        model.add_entry(SourceMapEntryRowObject::new("main.c", 20, Address::new(0x2000), 5));
        model.add_entry(SourceMapEntryRowObject::new("util.c", 5, Address::new(0x3000), 3));
        assert_eq!(model.get_entries_for_file("main.c").len(), 2);
        assert_eq!(model.get_entries_for_file("util.c").len(), 1);
    }

    #[test]
    fn test_source_map_entry_unique_files() {
        let mut model = SourceMapEntryTableModel::new();
        model.add_entry(SourceMapEntryRowObject::new("a.c", 1, Address::new(0x1000), 1));
        model.add_entry(SourceMapEntryRowObject::new("b.c", 1, Address::new(0x2000), 1));
        let files = model.unique_source_files();
        assert_eq!(files.len(), 2);
    }

    // --- TransformerTableModel tests ---

    #[test]
    fn test_transformer_table_model() {
        let mut model = TransformerTableModel::new();
        model.add_entry(PathTransformerEntry::new("/old/path", "/new/path", "UserPath"));
        assert_eq!(model.entry_count(), 1);
        let entry = model.get_entry(0).unwrap();
        assert_eq!(entry.original_path, "/old/path");
        assert_eq!(entry.transformed_path, "/new/path");
    }

    // --- SourceFilesTablePlugin tests ---

    #[test]
    fn test_source_files_table_plugin() {
        let mut plugin = SourceFilesTablePlugin::new();
        assert!(!plugin.is_disposed());
        assert!(plugin.current_program().is_none());

        plugin.set_current_program(Some("test.exe".into()));
        assert_eq!(plugin.current_program(), Some("test.exe"));

        plugin.dispose();
        assert!(plugin.is_disposed());
    }
}
