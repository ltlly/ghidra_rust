//! Bookmark provider -- table data model for the bookmarks panel.
//!
//! Ported from Ghidra's `BookmarkProvider`, which displays a filtered,
//! sortable table of all bookmarks in the current program.
//!
//! Provides:
//! - [`BookmarkProviderModel`] -- the data model behind the bookmarks panel
//! - [`BookmarkFilterState`] -- which bookmark types are visible
//! - Sorting by any column
//! - Address-to-row mapping for navigation

use std::collections::HashSet;

use ghidra_core::addr::Address;

use super::model::{Bookmark, BookmarkManager, FilterState};
use super::table::BookmarkColumn;

// ---------------------------------------------------------------------------
// BookmarkFilterState -- which types are visible in the panel
// ---------------------------------------------------------------------------

/// Tracks which bookmark types are currently visible in the provider panel.
///
/// This is the Rust equivalent of Ghidra's `FilterState` plus the
/// `FilterDialog` state management.
#[derive(Debug, Clone)]
pub struct BookmarkFilterState {
    /// The set of visible bookmark type strings.
    /// If empty, all types are visible.
    visible_types: HashSet<String>,
    /// Whether all types are currently shown.
    show_all: bool,
}

impl BookmarkFilterState {
    /// Creates a new filter state with all types visible.
    pub fn new() -> Self {
        Self {
            visible_types: HashSet::new(),
            show_all: true,
        }
    }

    /// Creates a filter state with only the given types visible.
    pub fn with_types(types: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            visible_types: types.into_iter().map(|s| s.into()).collect(),
            show_all: false,
        }
    }

    /// Returns true if the given type is visible.
    pub fn is_visible(&self, type_string: &str) -> bool {
        self.show_all || self.visible_types.contains(type_string)
    }

    /// Shows only the given type.
    pub fn show_only(&mut self, type_string: impl Into<String>) {
        self.visible_types.clear();
        self.visible_types.insert(type_string.into());
        self.show_all = false;
    }

    /// Toggles the visibility of a specific type.
    pub fn toggle_type(&mut self, type_string: &str) {
        if self.show_all {
            // Switch to show-all-off, then remove the toggled type
            self.show_all = false;
            // Add all types except the toggled one -- but we don't know
            // all types here. Instead, just toggle the specific type.
            self.visible_types.insert(type_string.to_string());
        } else if self.visible_types.contains(type_string) {
            self.visible_types.remove(type_string);
        } else {
            self.visible_types.insert(type_string.to_string());
        }
    }

    /// Shows all types.
    pub fn show_all(&mut self) {
        self.visible_types.clear();
        self.show_all = true;
    }

    /// Returns true if all types are shown.
    pub fn is_showing_all(&self) -> bool {
        self.show_all
    }

    /// Returns the set of visible type strings (empty if showing all).
    pub fn visible_types(&self) -> &HashSet<String> {
        &self.visible_types
    }

    /// Converts to a `FilterState` for serialization.
    pub fn to_filter_state(&self) -> FilterState {
        FilterState::new(self.visible_types.clone())
    }

    /// Restores from a `FilterState`.
    pub fn from_filter_state(state: &FilterState) -> Self {
        let types = state.bookmark_types().clone();
        Self {
            show_all: types.is_empty(),
            visible_types: types,
        }
    }
}

impl Default for BookmarkFilterState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BookmarkProviderModel -- data model for the bookmarks panel
// ---------------------------------------------------------------------------

/// Data model for the bookmarks provider panel.
///
/// This is the Rust equivalent of the table model behind Ghidra's
/// `BookmarkProvider`. It provides a filtered, sortable view of all
/// bookmarks in the program.
#[derive(Debug)]
pub struct BookmarkProviderModel {
    /// All bookmarks (snapshot from BookmarkManager).
    entries: Vec<BookmarkProviderEntry>,
    /// The current filter state.
    filter: BookmarkFilterState,
    /// The current sort column.
    sort_column: BookmarkColumn,
    /// Whether sort is ascending.
    sort_ascending: bool,
    /// Cached filtered entries.
    filtered_indices: Vec<usize>,
    /// Whether the cache is dirty.
    dirty: bool,
}

/// A row entry in the bookmark provider table.
#[derive(Debug, Clone)]
pub struct BookmarkProviderEntry {
    /// The bookmark data.
    pub bookmark: Bookmark,
    /// The bookmark type's display icon ID.
    pub icon_id: Option<String>,
    /// The bookmark type's marker color.
    pub color: Option<String>,
}

impl BookmarkProviderEntry {
    /// Creates a new provider entry from a bookmark.
    pub fn new(bookmark: Bookmark, icon_id: Option<String>, color: Option<String>) -> Self {
        Self {
            bookmark,
            icon_id,
            color,
        }
    }
}

impl BookmarkProviderModel {
    /// Creates a new empty model.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            filter: BookmarkFilterState::new(),
            sort_column: BookmarkColumn::Type,
            sort_ascending: true,
            filtered_indices: Vec::new(),
            dirty: true,
        }
    }

    /// Populates the model from a BookmarkManager.
    pub fn populate(&mut self, mgr: &BookmarkManager) {
        self.entries.clear();
        let ids: Vec<u64> = mgr.bookmark_ids().collect();
        for id in ids {
            if let Some(bm) = mgr.get_bookmark(id) {
                let bmt = mgr.get_bookmark_type(bm.type_string());
                let icon_id = bmt.and_then(|bt| bt.icon_id().map(|s| s.to_string()));
                let color = bmt.and_then(|bt| bt.marker_color().map(|s| s.to_string()));
                self.entries.push(BookmarkProviderEntry::new(
                    bm.clone(),
                    icon_id,
                    color,
                ));
            }
        }
        self.dirty = true;
    }

    /// Rebuilds the filter cache if dirty.
    fn rebuild_cache(&mut self) {
        if !self.dirty {
            return;
        }
        self.filtered_indices = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| self.filter.is_visible(e.bookmark.type_string()))
            .map(|(i, _)| i)
            .collect();

        // Sort
        let entries = &self.entries;
        let col = self.sort_column;
        let asc = self.sort_ascending;
        self.filtered_indices.sort_by(|&a, &b| {
            let ea = &entries[a].bookmark;
            let eb = &entries[b].bookmark;
            let ord = match col {
                BookmarkColumn::Location => ea.address().offset.cmp(&eb.address().offset),
                BookmarkColumn::Type => ea.type_string().cmp(eb.type_string()),
                BookmarkColumn::Category => ea.category().cmp(eb.category()),
                BookmarkColumn::Comment => ea.comment().cmp(eb.comment()),
                BookmarkColumn::Label => {
                    entries[a]
                        .icon_id
                        .as_deref()
                        .unwrap_or("")
                        .cmp(entries[b].icon_id.as_deref().unwrap_or(""))
                }
                BookmarkColumn::Preview => {
                    entries[a]
                        .icon_id
                        .as_deref()
                        .unwrap_or("")
                        .cmp(entries[b].icon_id.as_deref().unwrap_or(""))
                }
            };
            if asc { ord } else { ord.reverse() }
        });

        self.dirty = false;
    }

    /// Returns the number of visible (filtered) rows.
    pub fn row_count(&mut self) -> usize {
        self.rebuild_cache();
        self.filtered_indices.len()
    }

    /// Returns the total number of entries (before filtering).
    pub fn total_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns the bookmark at the given visible row index.
    pub fn get_bookmark(&mut self, row: usize) -> Option<&Bookmark> {
        self.rebuild_cache();
        let idx = *self.filtered_indices.get(row)?;
        self.entries.get(idx).map(|e| &e.bookmark)
    }

    /// Returns the provider entry at the given visible row index.
    pub fn get_entry(&mut self, row: usize) -> Option<&BookmarkProviderEntry> {
        self.rebuild_cache();
        let idx = *self.filtered_indices.get(row)?;
        self.entries.get(idx)
    }

    /// Returns the cell value for a visible row and column.
    pub fn get_value(&mut self, row: usize, col: BookmarkColumn) -> Option<String> {
        self.rebuild_cache();
        let idx = *self.filtered_indices.get(row)?;
        let entry = self.entries.get(idx)?;
        Some(match col {
            BookmarkColumn::Location => format!("0x{:X}", entry.bookmark.address().offset),
            BookmarkColumn::Type => entry.bookmark.type_string().to_string(),
            BookmarkColumn::Category => entry.bookmark.category().to_string(),
            BookmarkColumn::Comment => entry.bookmark.comment().to_string(),
            BookmarkColumn::Label | BookmarkColumn::Preview => {
                entry.icon_id.clone().unwrap_or_default()
            }
        })
    }

    /// Sorts by the given column. Toggles direction if same column.
    pub fn sort_by(&mut self, col: BookmarkColumn) {
        if self.sort_column == col {
            self.sort_ascending = !self.sort_ascending;
        } else {
            self.sort_column = col;
            self.sort_ascending = true;
        }
        self.dirty = true;
    }

    /// Sets the filter state and marks the cache dirty.
    pub fn set_filter(&mut self, filter: BookmarkFilterState) {
        self.filter = filter;
        self.dirty = true;
    }

    /// Returns a reference to the current filter state.
    pub fn filter(&self) -> &BookmarkFilterState {
        &self.filter
    }

    /// Returns a mutable reference to the filter state.
    pub fn filter_mut(&mut self) -> &mut BookmarkFilterState {
        self.dirty = true;
        &mut self.filter
    }

    /// Finds the visible row index for a bookmark with the given address.
    ///
    /// Returns the first matching row, or None if no bookmark at that address
    /// is visible.
    pub fn find_row_by_address(&mut self, addr: &Address) -> Option<usize> {
        self.rebuild_cache();
        self.filtered_indices
            .iter()
            .position(|&idx| self.entries[idx].bookmark.address().offset == addr.offset)
    }

    /// Returns all visible bookmark addresses (for marker set updates).
    pub fn visible_addresses(&mut self) -> Vec<Address> {
        self.rebuild_cache();
        self.filtered_indices
            .iter()
            .map(|&idx| *self.entries[idx].bookmark.address())
            .collect()
    }

    /// Returns the set of bookmark type strings present in the model.
    pub fn type_strings(&self) -> HashSet<String> {
        self.entries
            .iter()
            .map(|e| e.bookmark.type_string().to_string())
            .collect()
    }
}

impl Default for BookmarkProviderModel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::BookmarkType;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn make_mgr_with_bookmarks() -> BookmarkManager {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "Cat1", "First note");
        mgr.set_bookmark(&addr(0x2000), "Warning", "", "Watch out");
        mgr.set_bookmark(&addr(0x3000), "Note", "Cat2", "Another note");
        mgr.set_bookmark(&addr(0x4000), "Analysis", "", "Needs review");
        mgr
    }

    // ====================================================================
    // BookmarkFilterState
    // ====================================================================

    #[test]
    fn test_filter_state_new() {
        let filter = BookmarkFilterState::new();
        assert!(filter.is_showing_all());
        assert!(filter.is_visible("Note"));
        assert!(filter.is_visible("Warning"));
    }

    #[test]
    fn test_filter_state_with_types() {
        let filter = BookmarkFilterState::with_types(["Note", "Warning"]);
        assert!(!filter.is_showing_all());
        assert!(filter.is_visible("Note"));
        assert!(filter.is_visible("Warning"));
        assert!(!filter.is_visible("Analysis"));
    }

    #[test]
    fn test_filter_state_show_only() {
        let mut filter = BookmarkFilterState::new();
        filter.show_only("Note");
        assert!(!filter.is_showing_all());
        assert!(filter.is_visible("Note"));
        assert!(!filter.is_visible("Warning"));
    }

    #[test]
    fn test_filter_state_toggle() {
        let mut filter = BookmarkFilterState::new();
        // First toggle: adds to visible set (since show_all was true)
        filter.toggle_type("Note");
        // Now show_all is false, "Note" is in the visible set
        assert!(!filter.is_showing_all());
        assert!(filter.is_visible("Note"));
    }

    #[test]
    fn test_filter_state_show_all() {
        let mut filter = BookmarkFilterState::with_types(["Note"]);
        filter.show_all();
        assert!(filter.is_showing_all());
        assert!(filter.is_visible("Warning"));
    }

    #[test]
    fn test_filter_state_roundtrip() {
        let filter = BookmarkFilterState::with_types(["Note", "Warning"]);
        let fs = filter.to_filter_state();
        let restored = BookmarkFilterState::from_filter_state(&fs);
        assert!(restored.is_visible("Note"));
        assert!(restored.is_visible("Warning"));
        assert!(!restored.is_visible("Analysis"));
    }

    // ====================================================================
    // BookmarkProviderModel
    // ====================================================================

    #[test]
    fn test_model_new_empty() {
        let mut model = BookmarkProviderModel::new();
        assert_eq!(model.row_count(), 0);
        assert_eq!(model.total_count(), 0);
    }

    #[test]
    fn test_model_populate() {
        let mgr = make_mgr_with_bookmarks();
        let mut model = BookmarkProviderModel::new();
        model.populate(&mgr);
        assert_eq!(model.total_count(), 4);
        assert_eq!(model.row_count(), 4); // no filter
    }

    #[test]
    fn test_model_get_value() {
        let mgr = make_mgr_with_bookmarks();
        let mut model = BookmarkProviderModel::new();
        model.populate(&mgr);

        // Sort by address for predictable order
        model.sort_by(BookmarkColumn::Location);
        let addr_val = model.get_value(0, BookmarkColumn::Location);
        assert_eq!(addr_val, Some("0x1000".to_string()));
        let type_val = model.get_value(0, BookmarkColumn::Type);
        assert_eq!(type_val, Some("Note".to_string()));
    }

    #[test]
    fn test_model_get_bookmark() {
        let mgr = make_mgr_with_bookmarks();
        let mut model = BookmarkProviderModel::new();
        model.populate(&mgr);
        model.sort_by(BookmarkColumn::Location);

        let bm = model.get_bookmark(0).unwrap();
        assert_eq!(*bm.address(), addr(0x1000));
    }

    #[test]
    fn test_model_filter() {
        let mgr = make_mgr_with_bookmarks();
        let mut model = BookmarkProviderModel::new();
        model.populate(&mgr);

        model.set_filter(BookmarkFilterState::with_types(["Note"]));
        assert_eq!(model.row_count(), 2);
        assert_eq!(model.total_count(), 4); // total unchanged
    }

    #[test]
    fn test_model_sort_by_type() {
        let mgr = make_mgr_with_bookmarks();
        let mut model = BookmarkProviderModel::new();
        model.populate(&mgr);
        // Default sort_column is Type, so sort_by(Type) toggles to descending.
        // Use a different column first, then sort by Type for ascending.
        model.sort_by(BookmarkColumn::Location);
        model.sort_by(BookmarkColumn::Type);

        // Analysis comes first alphabetically (ascending)
        let type_val = model.get_value(0, BookmarkColumn::Type);
        assert_eq!(type_val, Some("Analysis".to_string()));
    }

    #[test]
    fn test_model_sort_toggle() {
        let mgr = make_mgr_with_bookmarks();
        let mut model = BookmarkProviderModel::new();
        model.populate(&mgr);
        model.sort_by(BookmarkColumn::Location); // ascending
        model.sort_by(BookmarkColumn::Location); // toggle to descending

        let addr_val = model.get_value(0, BookmarkColumn::Location);
        assert_eq!(addr_val, Some("0x4000".to_string()));
    }

    #[test]
    fn test_model_find_row_by_address() {
        let mgr = make_mgr_with_bookmarks();
        let mut model = BookmarkProviderModel::new();
        model.populate(&mgr);
        model.sort_by(BookmarkColumn::Location);

        assert_eq!(model.find_row_by_address(&addr(0x1000)), Some(0));
        assert_eq!(model.find_row_by_address(&addr(0x3000)), Some(2));
        assert_eq!(model.find_row_by_address(&addr(0x9999)), None);
    }

    #[test]
    fn test_model_visible_addresses() {
        let mgr = make_mgr_with_bookmarks();
        let mut model = BookmarkProviderModel::new();
        model.populate(&mgr);
        model.sort_by(BookmarkColumn::Location);

        let addrs = model.visible_addresses();
        assert_eq!(addrs.len(), 4);
        assert_eq!(addrs[0], addr(0x1000));
        assert_eq!(addrs[3], addr(0x4000));
    }

    #[test]
    fn test_model_type_strings() {
        let mgr = make_mgr_with_bookmarks();
        let mut model = BookmarkProviderModel::new();
        model.populate(&mgr);

        let types = model.type_strings();
        assert!(types.contains("Note"));
        assert!(types.contains("Warning"));
        assert!(types.contains("Analysis"));
    }

    #[test]
    fn test_model_out_of_bounds() {
        let mgr = make_mgr_with_bookmarks();
        let mut model = BookmarkProviderModel::new();
        model.populate(&mgr);

        assert!(model.get_bookmark(99).is_none());
        assert!(model.get_value(99, BookmarkColumn::Location).is_none());
        assert!(model.get_entry(99).is_none());
    }

    #[test]
    fn test_model_empty_after_filter() {
        let mgr = make_mgr_with_bookmarks();
        let mut model = BookmarkProviderModel::new();
        model.populate(&mgr);

        model.set_filter(BookmarkFilterState::with_types(["Nonexistent"]));
        assert_eq!(model.row_count(), 0);
        assert_eq!(model.total_count(), 4);
    }

    #[test]
    fn test_filter_state_toggle_remove() {
        let mut filter = BookmarkFilterState::with_types(["Note", "Warning"]);
        filter.toggle_type("Note");
        assert!(!filter.is_visible("Note"));
        assert!(filter.is_visible("Warning"));
    }
}
