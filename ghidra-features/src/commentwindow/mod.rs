//! Comment Window -- display and edit comments in a table view.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.commentwindow` Java package.
//!
//! Provides model-level logic for a table view of all comments in a program.
//! Supports filtering by comment type and sorting.
//!
//! # Architecture
//!
//! - [`CommentType`] -- the kind of comment (EOL, Pre, Post, Plate, Repeatable).
//! - [`CommentEntry`] -- a single comment at an address.
//! - [`CommentTableModel`] -- sortable/filterable table model.
//! - [`CommentWindowModel`] -- high-level model with CRUD operations.
//! - [`CommentSortField`] -- columns by which comments can be sorted.

use ghidra_core::Address;
use std::collections::BTreeMap;

// ============================================================================
// CommentType
// ============================================================================

/// The type of a comment in Ghidra.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CommentType {
    /// End-of-line comment (appears after the code unit).
    Eol = 0,
    /// Pre-comment (appears before the code unit).
    Pre = 1,
    /// Post-comment (appears after the code unit, separate line).
    Post = 2,
    /// Plate comment (appears above as a banner).
    Plate = 3,
    /// Repeatable comment (shown at references to this address).
    Repeatable = 4,
}

impl CommentType {
    /// Return the comment type from an integer code.
    pub fn from_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Eol),
            1 => Some(Self::Pre),
            2 => Some(Self::Post),
            3 => Some(Self::Plate),
            4 => Some(Self::Repeatable),
            _ => None,
        }
    }

    /// Return the integer code.
    pub fn to_code(&self) -> i32 {
        *self as i32
    }

    /// The display name of the comment type.
    pub fn display_name(&self) -> &str {
        match self {
            Self::Eol => "EOL",
            Self::Pre => "Pre",
            Self::Post => "Post",
            Self::Plate => "Plate",
            Self::Repeatable => "Repeatable",
        }
    }
}

impl std::fmt::Display for CommentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_name())
    }
}

// ============================================================================
// CommentEntry
// ============================================================================

/// A comment entry for the comment window.
#[derive(Debug, Clone)]
pub struct CommentEntry {
    /// The address of the comment.
    pub address: Address,
    /// The comment type.
    pub comment_type: CommentType,
    /// The comment text.
    pub text: String,
}

impl CommentEntry {
    /// Create a new comment entry.
    pub fn new(address: Address, comment_type: CommentType, text: impl Into<String>) -> Self {
        Self {
            address,
            comment_type,
            text: text.into(),
        }
    }

    /// Get the human-readable type name.
    pub fn type_name(&self) -> &str {
        self.comment_type.display_name()
    }
}

// ============================================================================
// CommentSortField
// ============================================================================

/// Fields by which comments can be sorted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentSortField {
    /// Sort by address (ascending).
    Address,
    /// Sort by comment type.
    Type,
    /// Sort by comment text.
    Text,
}

/// Sort direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDirection {
    /// Ascending (A-Z, low-high).
    Ascending,
    /// Descending (Z-A, high-low).
    Descending,
}

// ============================================================================
// CommentTableModel -- sortable/filterable table
// ============================================================================

/// Sortable, filterable table model for comments.
///
/// Ported from `ghidra.app.plugin.core.commentwindow.CommentTableModel`.
#[derive(Debug)]
pub struct CommentTableModel {
    /// All comment entries.
    entries: Vec<CommentEntry>,
    /// Filtered indices into `entries`.
    filtered_indices: Vec<usize>,
    /// Current sort field.
    sort_field: CommentSortField,
    /// Current sort direction.
    sort_direction: SortDirection,
    /// Filter: which comment types to show (empty = show all).
    type_filter: Vec<CommentType>,
    /// Filter: text substring (empty = show all).
    text_filter: String,
    /// Dirty flag.
    dirty: bool,
}

impl CommentTableModel {
    /// Create a new empty table model.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            filtered_indices: Vec::new(),
            sort_field: CommentSortField::Address,
            sort_direction: SortDirection::Ascending,
            type_filter: Vec::new(),
            text_filter: String::new(),
            dirty: true,
        }
    }

    /// Add a comment entry.
    pub fn add_entry(&mut self, entry: CommentEntry) {
        self.entries.push(entry);
        self.dirty = true;
    }

    /// Remove entries at the given address.
    pub fn remove_entries_at(&mut self, address: Address) {
        self.entries.retain(|e| e.address != address);
        self.dirty = true;
    }

    /// Set the type filter.
    pub fn set_type_filter(&mut self, types: Vec<CommentType>) {
        self.type_filter = types;
        self.dirty = true;
    }

    /// Set the text filter (substring match).
    pub fn set_text_filter(&mut self, filter: impl Into<String>) {
        self.text_filter = filter.into();
        self.dirty = true;
    }

    /// Set the sort field and direction.
    pub fn set_sort(&mut self, field: CommentSortField, direction: SortDirection) {
        self.sort_field = field;
        self.sort_direction = direction;
        self.dirty = true;
    }

    /// Rebuild the filtered/sorted view.
    fn rebuild(&mut self) {
        if !self.dirty {
            return;
        }

        let mut indices: Vec<usize> = (0..self.entries.len()).collect();

        // Apply type filter
        if !self.type_filter.is_empty() {
            indices.retain(|&i| self.type_filter.contains(&self.entries[i].comment_type));
        }

        // Apply text filter
        if !self.text_filter.is_empty() {
            let lower = self.text_filter.to_lowercase();
            indices.retain(|&i| self.entries[i].text.to_lowercase().contains(&lower));
        }

        // Sort
        let entries = &self.entries;
        let ascending = self.sort_direction == SortDirection::Ascending;
        match self.sort_field {
            CommentSortField::Address => {
                indices.sort_by(|&a, &b| {
                    let ord = entries[a].address.offset.cmp(&entries[b].address.offset);
                    if ascending { ord } else { ord.reverse() }
                });
            }
            CommentSortField::Type => {
                indices.sort_by(|&a, &b| {
                    let ord = entries[a].comment_type.cmp(&entries[b].comment_type);
                    if ascending { ord } else { ord.reverse() }
                });
            }
            CommentSortField::Text => {
                indices.sort_by(|&a, &b| {
                    let ord = entries[a].text.cmp(&entries[b].text);
                    if ascending { ord } else { ord.reverse() }
                });
            }
        }

        self.filtered_indices = indices;
        self.dirty = false;
    }

    /// Get the total number of entries (before filtering).
    pub fn total_count(&self) -> usize {
        self.entries.len()
    }

    /// Get the filtered entry count.
    pub fn filtered_count(&mut self) -> usize {
        self.rebuild();
        self.filtered_indices.len()
    }

    /// Get a reference to a filtered entry by row index.
    pub fn get_filtered(&mut self, row: usize) -> Option<&CommentEntry> {
        self.rebuild();
        self.filtered_indices
            .get(row)
            .map(|&i| &self.entries[i])
    }

    /// Get all entries (unfiltered).
    pub fn all_entries(&self) -> &[CommentEntry] {
        &self.entries
    }
}

impl Default for CommentTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// CommentWindowModel -- high-level CRUD
// ============================================================================

/// Model for the comment window table.
#[derive(Debug, Default)]
pub struct CommentWindowModel {
    entries: BTreeMap<u64, Vec<CommentEntry>>,
    table_model: CommentTableModel,
}

impl CommentWindowModel {
    /// Create a new model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a comment entry.
    pub fn add_entry(&mut self, entry: CommentEntry) {
        self.entries
            .entry(entry.address.offset)
            .or_default()
            .push(CommentEntry::new(
                entry.address,
                entry.comment_type,
                &entry.text,
            ));
        self.table_model.add_entry(entry);
    }

    /// Get all entries at an address.
    pub fn get_entries_at(&self, address: Address) -> Vec<&CommentEntry> {
        self.entries
            .get(&address.offset)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Get all entries as a flat list.
    pub fn get_all_entries(&self) -> Vec<&CommentEntry> {
        self.entries.values().flat_map(|v| v.iter()).collect()
    }

    /// Return the total number of comment entries.
    pub fn entry_count(&self) -> usize {
        self.entries.values().map(|v| v.len()).sum()
    }

    /// Return the number of addresses with comments.
    pub fn address_count(&self) -> usize {
        self.entries.len()
    }

    /// Remove all entries at an address.
    pub fn remove_entries_at(&mut self, address: Address) {
        self.entries.remove(&address.offset);
        self.table_model.remove_entries_at(address);
    }

    /// Get the table model for filtered/sorted viewing.
    pub fn table_model(&self) -> &CommentTableModel {
        &self.table_model
    }

    /// Get mutable access to the table model.
    pub fn table_model_mut(&mut self) -> &mut CommentTableModel {
        &mut self.table_model
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comment_type_from_code() {
        assert_eq!(CommentType::from_code(0), Some(CommentType::Eol));
        assert_eq!(CommentType::from_code(3), Some(CommentType::Plate));
        assert_eq!(CommentType::from_code(4), Some(CommentType::Repeatable));
        assert_eq!(CommentType::from_code(99), None);
    }

    #[test]
    fn test_comment_type_display() {
        assert_eq!(CommentType::Eol.to_string(), "EOL");
        assert_eq!(CommentType::Pre.to_string(), "Pre");
        assert_eq!(CommentType::Plate.to_string(), "Plate");
    }

    #[test]
    fn test_comment_type_code_roundtrip() {
        for t in [
            CommentType::Eol,
            CommentType::Pre,
            CommentType::Post,
            CommentType::Plate,
            CommentType::Repeatable,
        ] {
            assert_eq!(CommentType::from_code(t.to_code()), Some(t));
        }
    }

    #[test]
    fn test_comment_entry_new() {
        let entry = CommentEntry::new(Address::new(0x1000), CommentType::Eol, "test");
        assert_eq!(entry.address.offset, 0x1000);
        assert_eq!(entry.comment_type, CommentType::Eol);
        assert_eq!(entry.text, "test");
        assert_eq!(entry.type_name(), "EOL");
    }

    #[test]
    fn test_add_and_get_entries() {
        let mut model = CommentWindowModel::new();
        model.add_entry(CommentEntry::new(Address::new(0x1000), CommentType::Eol, "EOL comment"));
        model.add_entry(CommentEntry::new(Address::new(0x1000), CommentType::Pre, "Pre comment"));
        assert_eq!(model.entry_count(), 2);
        assert_eq!(model.address_count(), 1);
        let entries = model.get_entries_at(Address::new(0x1000));
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_type_name() {
        let entry = CommentEntry::new(Address::new(0x1000), CommentType::Plate, "Plate");
        assert_eq!(entry.type_name(), "Plate");
    }

    #[test]
    fn test_comment_table_model_filter() {
        let mut model = CommentTableModel::new();
        model.add_entry(CommentEntry::new(Address::new(0x1000), CommentType::Eol, "first"));
        model.add_entry(CommentEntry::new(Address::new(0x2000), CommentType::Pre, "second"));
        model.add_entry(CommentEntry::new(Address::new(0x3000), CommentType::Eol, "third"));

        // No filter
        assert_eq!(model.filtered_count(), 3);

        // Filter by type
        model.set_type_filter(vec![CommentType::Pre]);
        assert_eq!(model.filtered_count(), 1);
        assert_eq!(model.get_filtered(0).unwrap().text, "second");

        // Clear filter
        model.set_type_filter(vec![]);
        assert_eq!(model.filtered_count(), 3);
    }

    #[test]
    fn test_comment_table_model_text_filter() {
        let mut model = CommentTableModel::new();
        model.add_entry(CommentEntry::new(Address::new(0x1000), CommentType::Eol, "hello world"));
        model.add_entry(CommentEntry::new(Address::new(0x2000), CommentType::Pre, "foo bar"));
        model.add_entry(CommentEntry::new(Address::new(0x3000), CommentType::Post, "hello there"));

        model.set_text_filter("hello");
        assert_eq!(model.filtered_count(), 2);
        assert_eq!(model.get_filtered(0).unwrap().address.offset, 0x1000);
    }

    #[test]
    fn test_comment_table_model_sort() {
        let mut model = CommentTableModel::new();
        model.add_entry(CommentEntry::new(Address::new(0x3000), CommentType::Eol, "C"));
        model.add_entry(CommentEntry::new(Address::new(0x1000), CommentType::Pre, "A"));
        model.add_entry(CommentEntry::new(Address::new(0x2000), CommentType::Post, "B"));

        // Default sort: address ascending
        assert_eq!(model.get_filtered(0).unwrap().address.offset, 0x1000);
        assert_eq!(model.get_filtered(1).unwrap().address.offset, 0x2000);
        assert_eq!(model.get_filtered(2).unwrap().address.offset, 0x3000);

        // Sort by address descending
        model.set_sort(CommentSortField::Address, SortDirection::Descending);
        assert_eq!(model.get_filtered(0).unwrap().address.offset, 0x3000);
        assert_eq!(model.get_filtered(2).unwrap().address.offset, 0x1000);

        // Sort by text ascending
        model.set_sort(CommentSortField::Text, SortDirection::Ascending);
        assert_eq!(model.get_filtered(0).unwrap().text, "A");
        assert_eq!(model.get_filtered(2).unwrap().text, "C");
    }

    #[test]
    fn test_comment_table_model_combined_filter() {
        let mut model = CommentTableModel::new();
        model.add_entry(CommentEntry::new(Address::new(0x1000), CommentType::Eol, "alpha"));
        model.add_entry(CommentEntry::new(Address::new(0x2000), CommentType::Pre, "beta"));
        model.add_entry(CommentEntry::new(Address::new(0x3000), CommentType::Eol, "gamma"));

        model.set_type_filter(vec![CommentType::Eol]);
        model.set_text_filter("alp");
        assert_eq!(model.filtered_count(), 1);
        assert_eq!(model.get_filtered(0).unwrap().text, "alpha");
    }

    #[test]
    fn test_comment_window_model_remove() {
        let mut model = CommentWindowModel::new();
        model.add_entry(CommentEntry::new(Address::new(0x1000), CommentType::Eol, "test"));
        model.add_entry(CommentEntry::new(Address::new(0x1000), CommentType::Pre, "test2"));
        assert_eq!(model.entry_count(), 2);
        model.remove_entries_at(Address::new(0x1000));
        assert_eq!(model.entry_count(), 0);
        assert_eq!(model.address_count(), 0);
    }
}
