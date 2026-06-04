//! Source Files Table -- display source file information.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.sourcefilestable` Java package.
//!
//! Provides model-level logic for displaying and querying source file
//! information associated with a program's debug info.

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
}
