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
}
