//! Enum table model for editing enum data type entries.
//!
//! Ported from `ghidra.app.plugin.core.datamgr.EnumTableModel`,
//! `EnumEditorPanel`, and `EnumEntry`.

use serde::{Deserialize, Serialize};

/// A single entry in an enum data type.
///
/// Ported from `ghidra.app.plugin.core.datamgr.EnumEntry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumEntry {
    /// The name of the enum entry.
    pub name: String,
    /// The numeric value.
    pub value: u64,
    /// Optional comment.
    pub comment: Option<String>,
    /// Whether this entry was explicitly assigned a value.
    pub explicit_value: bool,
}

impl EnumEntry {
    /// Create a new enum entry.
    pub fn new(name: impl Into<String>, value: u64) -> Self {
        Self {
            name: name.into(),
            value,
            comment: None,
            explicit_value: true,
        }
    }

    /// Create an enum entry with a comment.
    pub fn with_comment(
        name: impl Into<String>,
        value: u64,
        comment: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value,
            comment: Some(comment.into()),
            explicit_value: true,
        }
    }

    /// Create an auto-numbered entry (value is implicit).
    pub fn auto_numbered(name: impl Into<String>, value: u64) -> Self {
        Self {
            name: name.into(),
            value,
            comment: None,
            explicit_value: false,
        }
    }
}

// ---------------------------------------------------------------------------
// EnumTableModel
// ---------------------------------------------------------------------------

/// Table model for editing enum data type entries.
///
/// Ported from `ghidra.app.plugin.core.datamgr.EnumTableModel`.
#[derive(Debug)]
pub struct EnumTableModel {
    /// The enum name.
    pub enum_name: String,
    /// The enum entries.
    entries: Vec<EnumEntry>,
    /// The bit size of the enum (8, 16, 32, 64).
    pub bit_size: u32,
    /// Whether the enum is signed.
    pub signed: bool,
    /// Undo stack.
    undo_stack: Vec<Vec<EnumEntry>>,
    /// Redo stack.
    redo_stack: Vec<Vec<EnumEntry>>,
    /// Whether the model has unsaved changes.
    dirty: bool,
}

impl EnumTableModel {
    /// Create a new enum table model.
    pub fn new(enum_name: impl Into<String>, bit_size: u32, signed: bool) -> Self {
        Self {
            enum_name: enum_name.into(),
            entries: Vec::new(),
            bit_size,
            signed,
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            dirty: false,
        }
    }

    /// Get the entries.
    pub fn entries(&self) -> &[EnumEntry] {
        &self.entries
    }

    /// Number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Add an entry.
    pub fn add_entry(&mut self, entry: EnumEntry) {
        self.save_undo();
        self.entries.push(entry);
        self.dirty = true;
    }

    /// Remove an entry by index.
    pub fn remove_entry(&mut self, index: usize) -> Option<EnumEntry> {
        if index < self.entries.len() {
            self.save_undo();
            let removed = self.entries.remove(index);
            self.dirty = true;
            Some(removed)
        } else {
            None
        }
    }

    /// Update the name of an entry.
    pub fn set_entry_name(&mut self, index: usize, name: impl Into<String>) -> bool {
        if index < self.entries.len() {
            self.save_undo();
            self.entries[index].name = name.into();
            self.dirty = true;
            true
        } else {
            false
        }
    }

    /// Update the value of an entry.
    pub fn set_entry_value(&mut self, index: usize, value: u64) -> bool {
        if index < self.entries.len() {
            self.save_undo();
            self.entries[index].value = value;
            self.entries[index].explicit_value = true;
            self.dirty = true;
            true
        } else {
            false
        }
    }

    /// Update the comment of an entry.
    pub fn set_entry_comment(&mut self, index: usize, comment: Option<String>) -> bool {
        if index < self.entries.len() {
            self.save_undo();
            self.entries[index].comment = comment;
            self.dirty = true;
            true
        } else {
            false
        }
    }

    /// Get the maximum value that fits in this enum's bit size.
    pub fn max_value(&self) -> u64 {
        if self.bit_size >= 64 {
            u64::MAX
        } else {
            (1u64 << self.bit_size) - 1
        }
    }

    /// Whether an entry name is already used.
    pub fn is_name_taken(&self, name: &str, exclude_index: Option<usize>) -> bool {
        self.entries
            .iter()
            .enumerate()
            .any(|(i, e)| Some(i) != exclude_index && e.name == name)
    }

    /// Whether an entry value is already used.
    pub fn is_value_taken(&self, value: u64, exclude_index: Option<usize>) -> bool {
        self.entries
            .iter()
            .enumerate()
            .any(|(i, e)| Some(i) != exclude_index && e.value == value)
    }

    /// Get the next auto-increment value.
    pub fn next_value(&self) -> u64 {
        self.entries
            .iter()
            .map(|e| e.value)
            .max()
            .map_or(0, |v| v + 1)
    }

    /// Whether the model has unsaved changes.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark as clean.
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Whether undo is available.
    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    /// Whether redo is available.
    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    /// Undo the last change.
    pub fn undo(&mut self) -> bool {
        if let Some(prev) = self.undo_stack.pop() {
            self.redo_stack.push(std::mem::replace(&mut self.entries, prev));
            self.dirty = true;
            true
        } else {
            false
        }
    }

    /// Redo the last undone change.
    pub fn redo(&mut self) -> bool {
        if let Some(next) = self.redo_stack.pop() {
            self.undo_stack.push(std::mem::replace(&mut self.entries, next));
            self.dirty = true;
            true
        } else {
            false
        }
    }

    /// Sort entries by value.
    pub fn sort_by_value(&mut self) {
        self.save_undo();
        self.entries.sort_by_key(|e| e.value);
        self.dirty = true;
    }

    /// Sort entries by name.
    pub fn sort_by_name(&mut self) {
        self.save_undo();
        self.entries.sort_by(|a, b| a.name.cmp(&b.name));
        self.dirty = true;
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.save_undo();
        self.entries.clear();
        self.dirty = true;
    }

    fn save_undo(&mut self) {
        self.undo_stack.push(self.entries.clone());
        self.redo_stack.clear();
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enum_entry_new() {
        let entry = EnumEntry::new("VALUE_A", 0);
        assert_eq!(entry.name, "VALUE_A");
        assert_eq!(entry.value, 0);
        assert!(entry.explicit_value);
        assert!(entry.comment.is_none());
    }

    #[test]
    fn test_enum_entry_with_comment() {
        let entry = EnumEntry::with_comment("VAL", 1, "first value");
        assert_eq!(entry.comment, Some("first value".into()));
    }

    #[test]
    fn test_enum_table_model_creation() {
        let model = EnumTableModel::new("MyEnum", 32, false);
        assert_eq!(model.enum_name, "MyEnum");
        assert_eq!(model.entry_count(), 0);
        assert_eq!(model.bit_size, 32);
    }

    #[test]
    fn test_enum_table_model_add_remove() {
        let mut model = EnumTableModel::new("E", 32, false);
        model.add_entry(EnumEntry::new("A", 0));
        model.add_entry(EnumEntry::new("B", 1));
        assert_eq!(model.entry_count(), 2);

        model.remove_entry(0);
        assert_eq!(model.entry_count(), 1);
        assert_eq!(model.entries()[0].name, "B");
    }

    #[test]
    fn test_enum_table_model_setters() {
        let mut model = EnumTableModel::new("E", 32, false);
        model.add_entry(EnumEntry::new("A", 0));

        model.set_entry_name(0, "NEW_A");
        assert_eq!(model.entries()[0].name, "NEW_A");

        model.set_entry_value(0, 42);
        assert_eq!(model.entries()[0].value, 42);

        model.set_entry_comment(0, Some("my comment".into()));
        assert_eq!(model.entries()[0].comment, Some("my comment".into()));
    }

    #[test]
    fn test_enum_table_model_max_value() {
        let m8 = EnumTableModel::new("E8", 8, false);
        assert_eq!(m8.max_value(), 255);

        let m16 = EnumTableModel::new("E16", 16, false);
        assert_eq!(m16.max_value(), 65535);

        let m64 = EnumTableModel::new("E64", 64, false);
        assert_eq!(m64.max_value(), u64::MAX);
    }

    #[test]
    fn test_enum_table_model_name_taken() {
        let mut model = EnumTableModel::new("E", 32, false);
        model.add_entry(EnumEntry::new("A", 0));
        model.add_entry(EnumEntry::new("B", 1));

        assert!(model.is_name_taken("A", None));
        assert!(model.is_name_taken("A", Some(1)));
        assert!(!model.is_name_taken("A", Some(0)));
        assert!(!model.is_name_taken("C", None));
    }

    #[test]
    fn test_enum_table_model_value_taken() {
        let mut model = EnumTableModel::new("E", 32, false);
        model.add_entry(EnumEntry::new("A", 0));
        model.add_entry(EnumEntry::new("B", 1));

        assert!(model.is_value_taken(0, None));
        assert!(!model.is_value_taken(0, Some(0))); // excluded index 0, value 0 not taken by others
        assert!(!model.is_value_taken(2, None));
    }

    #[test]
    fn test_enum_table_model_next_value() {
        let mut model = EnumTableModel::new("E", 32, false);
        assert_eq!(model.next_value(), 0);

        model.add_entry(EnumEntry::new("A", 5));
        model.add_entry(EnumEntry::new("B", 10));
        assert_eq!(model.next_value(), 11);
    }

    #[test]
    fn test_enum_table_model_undo_redo() {
        let mut model = EnumTableModel::new("E", 32, false);
        model.add_entry(EnumEntry::new("A", 0));
        model.add_entry(EnumEntry::new("B", 1));
        assert!(model.can_undo());
        assert!(!model.can_redo());

        model.undo();
        assert_eq!(model.entry_count(), 1);
        assert!(model.can_redo());

        model.redo();
        assert_eq!(model.entry_count(), 2);
    }

    #[test]
    fn test_enum_table_model_sort_by_value() {
        let mut model = EnumTableModel::new("E", 32, false);
        model.add_entry(EnumEntry::new("B", 2));
        model.add_entry(EnumEntry::new("A", 0));
        model.add_entry(EnumEntry::new("C", 1));

        model.sort_by_value();
        assert_eq!(model.entries()[0].name, "A");
        assert_eq!(model.entries()[1].name, "C");
        assert_eq!(model.entries()[2].name, "B");
    }

    #[test]
    fn test_enum_table_model_sort_by_name() {
        let mut model = EnumTableModel::new("E", 32, false);
        model.add_entry(EnumEntry::new("C", 2));
        model.add_entry(EnumEntry::new("A", 0));
        model.add_entry(EnumEntry::new("B", 1));

        model.sort_by_name();
        assert_eq!(model.entries()[0].name, "A");
        assert_eq!(model.entries()[1].name, "B");
        assert_eq!(model.entries()[2].name, "C");
    }

    #[test]
    fn test_enum_table_model_dirty() {
        let mut model = EnumTableModel::new("E", 32, false);
        assert!(!model.is_dirty());

        model.add_entry(EnumEntry::new("A", 0));
        assert!(model.is_dirty());

        model.mark_clean();
        assert!(!model.is_dirty());
    }

    #[test]
    fn test_enum_table_model_clear() {
        let mut model = EnumTableModel::new("E", 32, false);
        model.add_entry(EnumEntry::new("A", 0));
        model.add_entry(EnumEntry::new("B", 1));
        model.clear();
        assert_eq!(model.entry_count(), 0);
        assert!(model.is_dirty());
    }
}
