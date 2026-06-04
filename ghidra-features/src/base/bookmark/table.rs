//! Bookmark table model for displaying bookmarks in a tabular view.
//!
//! This module provides the Rust analogue of Ghidra's `BookmarkTableModel`,
//! supporting column definitions, row data access, type filtering, and
//! sorted iteration.

use std::collections::HashSet;

use ghidra_core::addr::Address;

use super::model::{BookmarkManager, BookmarkRowObject, FilterState};

// ---------------------------------------------------------------------------
// BookmarkColumn
// ---------------------------------------------------------------------------

/// Column identifiers for the bookmark table.
///
/// Corresponds to the column indices in Ghidra's `BookmarkTableModel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BookmarkColumn {
    /// Bookmark type (e.g. "Note", "Warning").
    Type = 0,
    /// Bookmark category.
    Category = 1,
    /// Bookmark comment/description.
    Comment = 2,
    /// Address where the bookmark is located.
    Location = 3,
    /// Label/symbol name at the bookmark address.
    Label = 4,
    /// Code unit preview at the bookmark address.
    Preview = 5,
}

impl BookmarkColumn {
    /// All columns in display order.
    pub const ALL: [BookmarkColumn; 6] = [
        BookmarkColumn::Type,
        BookmarkColumn::Category,
        BookmarkColumn::Comment,
        BookmarkColumn::Location,
        BookmarkColumn::Label,
        BookmarkColumn::Preview,
    ];

    /// Returns the column header display name.
    pub fn display_name(self) -> &'static str {
        match self {
            BookmarkColumn::Type => "Type",
            BookmarkColumn::Category => "Category",
            BookmarkColumn::Comment => "Description",
            BookmarkColumn::Location => "Location",
            BookmarkColumn::Label => "Label",
            BookmarkColumn::Preview => "Preview",
        }
    }

    /// Returns the column index (0-based).
    pub fn index(self) -> usize {
        self as usize
    }

    /// Returns true if this column is editable.
    pub fn is_editable(self) -> bool {
        matches!(self, BookmarkColumn::Category | BookmarkColumn::Comment)
    }
}

// ---------------------------------------------------------------------------
// BookmarkTableEntry
// ---------------------------------------------------------------------------

/// A single row in the bookmark table, containing all column values.
///
/// This is a pre-fetched view of a bookmark for display, analogous to how
/// Ghidra's table model queries the BookmarkManager per column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookmarkTableEntry {
    /// Bookmark ID (internal key).
    pub id: u64,
    /// Bookmark type string.
    pub type_string: String,
    /// Bookmark category.
    pub category: String,
    /// Bookmark comment/description.
    pub comment: String,
    /// Address offset (as display string).
    pub address_str: String,
    /// The raw address.
    pub address: Address,
    /// Label name at this address (empty if no label).
    pub label: String,
    /// Code unit preview (empty if not available).
    pub preview: String,
}

// ---------------------------------------------------------------------------
// BookmarkTableModel
// ---------------------------------------------------------------------------

/// Table model for displaying bookmarks.
///
/// This corresponds to Ghidra's `BookmarkTableModel` and manages:
/// - Type-based filtering (show/hide specific bookmark types)
/// - Loading rows from a BookmarkManager
/// - In-place editing of category and comment columns
/// - Snapshot of filter state for persistence
pub struct BookmarkTableModel {
    /// Current rows (ordered).
    rows: Vec<BookmarkTableEntry>,
    /// Row objects (keys) in the same order.
    row_objects: Vec<BookmarkRowObject>,
    /// The set of enabled bookmark type strings.
    active_types: HashSet<String>,
    /// Whether the model has been initialized with a manager.
    initialized: bool,
}

impl BookmarkTableModel {
    /// Creates a new empty BookmarkTableModel.
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            row_objects: Vec::new(),
            active_types: HashSet::new(),
            initialized: false,
        }
    }

    /// Initializes the model with types from the given BookmarkManager.
    ///
    /// If no types have been previously set, all types from the manager
    /// become active. If types have been set (e.g., from a FilterState
    /// restore), only those types that exist in the manager are kept.
    pub fn initialize(&mut self, mgr: &BookmarkManager) {
        let default_types: HashSet<String> = mgr
            .get_bookmark_type_strings()
            .iter()
            .map(|s| s.to_string())
            .collect();

        if self.active_types.is_empty() {
            // First initialization: use all types.
            self.active_types = default_types;
        } else {
            // Keep only types that still exist in the program.
            self.active_types = self
                .active_types
                .intersection(&default_types)
                .cloned()
                .collect();
        }
        self.initialized = true;
    }

    /// Loads all bookmarks from the manager, respecting type filters.
    pub fn load(&mut self, mgr: &BookmarkManager) {
        self.rows.clear();
        self.row_objects.clear();

        for type_string in &self.active_types {
            for bm in mgr.get_bookmarks_iterator(type_string) {
                let entry = BookmarkTableEntry {
                    id: bm.id(),
                    type_string: bm.type_string().to_string(),
                    category: bm.category().to_string(),
                    comment: bm.comment().to_string(),
                    address_str: format!("0x{:X}", bm.address().offset),
                    address: *bm.address(),
                    label: String::new(),  // Would be populated from SymbolTable.
                    preview: String::new(), // Would be populated from Listing.
                };
                self.rows.push(entry);
                self.row_objects.push(BookmarkRowObject::new(bm.id()));
            }
        }

        // Sort by address then type.
        self.sort_rows();
    }

    fn sort_rows(&mut self) {
        let mut indices: Vec<usize> = (0..self.rows.len()).collect();
        indices.sort_by(|&a, &b| {
            self.rows[a]
                .address
                .offset
                .cmp(&self.rows[b].address.offset)
                .then_with(|| self.rows[a].type_string.cmp(&self.rows[b].type_string))
        });

        let sorted_rows: Vec<_> = indices.iter().map(|&i| self.rows[i].clone()).collect();
        let sorted_objects: Vec<_> = indices.iter().map(|&i| self.row_objects[i]).collect();
        self.rows = sorted_rows;
        self.row_objects = sorted_objects;
    }

    /// Returns the number of visible rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Returns a reference to the entry at the given row index.
    pub fn get_entry(&self, row: usize) -> Option<&BookmarkTableEntry> {
        self.rows.get(row)
    }

    /// Returns the row object at the given index.
    pub fn get_row_object(&self, row: usize) -> Option<BookmarkRowObject> {
        self.row_objects.get(row).copied()
    }

    /// Returns the address for the given row.
    pub fn get_address(&self, row: usize) -> Option<Address> {
        self.rows.get(row).map(|e| e.address)
    }

    /// Returns the total number of bookmarks in the manager (ignoring filters).
    pub fn total_count(&self, mgr: &BookmarkManager) -> usize {
        mgr.get_bookmark_count()
    }

    /// Returns true if a type filter is active (not all types are shown).
    pub fn has_type_filter_applied(&self, mgr: &BookmarkManager) -> bool {
        let all_types = mgr.get_bookmark_type_strings();
        !self.active_types.is_empty() && self.active_types.len() != all_types.len()
    }

    /// Returns the current filter state (for serialization).
    pub fn get_filter_state(&self) -> FilterState {
        FilterState::new(self.active_types.clone())
    }

    /// Restores the filter state from a serialized snapshot.
    pub fn restore_filter_state(&mut self, state: &FilterState) {
        self.active_types = state.bookmark_types().clone();
    }

    /// Shows the given bookmark type.
    pub fn show_type(&mut self, type_string: &str) {
        self.active_types.insert(type_string.to_string());
    }

    /// Hides the given bookmark type.
    pub fn hide_type(&mut self, type_string: &str) {
        self.active_types.remove(type_string);
    }

    /// Returns true if the given type is currently shown.
    pub fn is_showing_type(&self, type_string: &str) -> bool {
        self.active_types.contains(type_string)
    }

    /// Hides all bookmark types.
    pub fn hide_all_types(&mut self) {
        self.active_types.clear();
    }

    /// Returns all currently active types.
    pub fn get_active_types(&self) -> &HashSet<String> {
        &self.active_types
    }

    /// Notifies the model that a new type was added to the program.
    pub fn type_added(&mut self, type_string: &str) {
        self.active_types.insert(type_string.to_string());
    }

    /// Notifies the model that a bookmark was added.
    pub fn bookmark_added(&mut self, mgr: &BookmarkManager, bookmark_id: u64) {
        if let Some(bm) = mgr.get_bookmark(bookmark_id) {
            if self.is_showing_type(bm.type_string()) {
                // Reload to keep ordering.
                self.load(mgr);
            }
        }
    }

    /// Notifies the model that a bookmark was changed.
    pub fn bookmark_changed(&mut self, mgr: &BookmarkManager, bookmark_id: u64) {
        if let Some(bm) = mgr.get_bookmark(bookmark_id) {
            if self.is_showing_type(bm.type_string()) {
                self.load(mgr);
            }
        }
    }

    /// Notifies the model that a bookmark was removed.
    pub fn bookmark_removed(&mut self, mgr: &BookmarkManager, bookmark_id: u64) {
        if let Some(idx) = self.row_objects.iter().position(|ro| ro.key() == bookmark_id) {
            self.rows.remove(idx);
            self.row_objects.remove(idx);
        }
        // Also check by type if we have the info.
        let _ = mgr; // May need full reload for index consistency.
    }

    /// Returns true if the model has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for BookmarkTableModel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::model::BookmarkManager;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn setup_model() -> (BookmarkTableModel, BookmarkManager) {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "Cat", "First");
        mgr.set_bookmark(&addr(0x2000), "Warning", "", "Second");
        mgr.set_bookmark(&addr(0x1500), "Note", "Cat2", "Third");
        mgr.set_bookmark(&addr(0x3000), "Error", "Bug", "Crash");

        let mut model = BookmarkTableModel::new();
        model.initialize(&mgr);
        model.load(&mgr);
        (model, mgr)
    }

    #[test]
    fn test_model_loads_all_types() {
        let (model, _) = setup_model();
        assert_eq!(model.row_count(), 4);
    }

    #[test]
    fn test_model_sorted_by_address() {
        let (model, _) = setup_model();
        assert_eq!(model.get_entry(0).unwrap().address.offset, 0x1000);
        assert_eq!(model.get_entry(1).unwrap().address.offset, 0x1500);
        assert_eq!(model.get_entry(2).unwrap().address.offset, 0x2000);
        assert_eq!(model.get_entry(3).unwrap().address.offset, 0x3000);
    }

    #[test]
    fn test_model_filter_hides_types() {
        let (mut model, mgr) = setup_model();
        model.hide_type("Warning");
        model.hide_type("Error");
        model.load(&mgr);
        assert_eq!(model.row_count(), 2);
        assert!(model.get_entry(0).unwrap().type_string == "Note");
    }

    #[test]
    fn test_model_filter_state_roundtrip() {
        let (mut model, _mgr) = setup_model();
        let state = model.get_filter_state();
        model.hide_all_types();
        model.load(&_mgr);
        assert_eq!(model.row_count(), 0);

        model.restore_filter_state(&state);
        model.load(&_mgr);
        assert_eq!(model.row_count(), 4);
    }

    #[test]
    fn test_model_show_type() {
        let (mut model, _mgr) = setup_model();
        model.hide_all_types();
        model.show_type("Note");
        model.load(&_mgr);
        assert_eq!(model.row_count(), 2);
    }

    #[test]
    fn test_model_is_showing_type() {
        let (model, _) = setup_model();
        assert!(model.is_showing_type("Note"));
        assert!(model.is_showing_type("Warning"));
    }

    #[test]
    fn test_model_has_type_filter_applied() {
        let (mut model, mgr) = setup_model();
        assert!(!model.has_type_filter_applied(&mgr));
        model.hide_type("Error");
        assert!(model.has_type_filter_applied(&mgr));
    }

    #[test]
    fn test_model_get_address() {
        let (model, _) = setup_model();
        assert_eq!(model.get_address(0).unwrap().offset, 0x1000);
        assert!(model.get_address(99).is_none());
    }

    #[test]
    fn test_model_get_row_object() {
        let (model, _) = setup_model();
        let ro = model.get_row_object(0).unwrap();
        assert!(ro.key() > 0);
    }

    #[test]
    fn test_model_bookmark_added() {
        let (mut model, mut mgr) = setup_model();
        let id = mgr.set_bookmark(&addr(0x5000), "Note", "", "New").id();
        model.bookmark_added(&mgr, id);
        assert_eq!(model.row_count(), 5);
    }

    #[test]
    fn test_model_bookmark_removed() {
        let (mut model, mut mgr) = setup_model();
        let id = mgr.set_bookmark(&addr(0x5000), "Note", "", "Temp").id();
        model.bookmark_added(&mgr, id);
        assert_eq!(model.row_count(), 5);

        model.bookmark_removed(&mgr, id);
        // The row should be gone.
        assert!(model.rows.iter().all(|r| r.id != id));
    }

    #[test]
    fn test_model_type_added() {
        let (mut model, _mgr) = setup_model();
        assert!(!model.is_showing_type("CustomType"));
        model.type_added("CustomType");
        assert!(model.is_showing_type("CustomType"));
    }

    #[test]
    fn test_column_properties() {
        assert_eq!(BookmarkColumn::Type.display_name(), "Type");
        assert_eq!(BookmarkColumn::Type.index(), 0);
        assert!(!BookmarkColumn::Type.is_editable());
        assert!(BookmarkColumn::Category.is_editable());
        assert!(BookmarkColumn::Comment.is_editable());
        assert!(!BookmarkColumn::Location.is_editable());
    }

    #[test]
    fn test_model_empty() {
        let model = BookmarkTableModel::new();
        assert_eq!(model.row_count(), 0);
        assert!(!model.is_initialized());
    }
}
