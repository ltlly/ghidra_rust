//! BookmarkView Provider -- view-specific extension of the bookmark provider.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.bookmark.BookmarkProvider`
//! view-related functionality.
//!
//! This module extends the bookmark provider with view-specific behavior
//! including:
//! - Managing the bookmark table display
//! - Handling filter state persistence
//! - Coordinating with GoTo service for navigation
//! - Managing category cell editing
//! - Providing selection-based operations
//!
//! # Architecture
//!
//! The BookmarkView provider acts as the presentation layer:
//! - Displays bookmarks in a filterable, sortable table
//! - Manages column sizing and layout
//! - Handles user interactions (selection, editing, deletion)
//! - Coordinates with external services (GoTo, navigation)
//!
//! In the Rust port, Swing-specific UI components are replaced with
//! pure-data representations and callback-based patterns.

use std::collections::HashSet;
use std::fmt;

use ghidra_core::addr::Address;

use super::commands::{AddressSet, BookmarkDeleteCmd};
use super::model::{Bookmark, BookmarkManager, BookmarkRowObject, FilterState};
use super::provider::{BookmarkFilterState, BookmarkProviderEntry, BookmarkProviderModel};
use super::table::{BookmarkColumn, BookmarkTableEntry, BookmarkTableModel};

// ---------------------------------------------------------------------------
// BookmarkViewProvider
// ---------------------------------------------------------------------------

/// View-specific extension of the bookmark provider.
///
/// This struct manages the bookmark table display and user interactions.
/// It corresponds to the view-related portions of Ghidra's `BookmarkProvider`.
///
/// # Features
///
/// - Filterable, sortable table of bookmarks
/// - Column sizing and layout management
/// - Selection tracking for batch operations
/// - Category editing with auto-complete from existing categories
/// - Config state persistence for filter settings
#[derive(Debug)]
pub struct BookmarkViewProvider {
    /// The provider name (used for display and identification).
    name: String,
    /// The underlying data model.
    model: BookmarkTableModel,
    /// The provider data model for filtering and sorting.
    provider_model: BookmarkProviderModel,
    /// Whether the provider is currently visible.
    visible: bool,
    /// The current program (if any).
    program: Option<String>,
    /// Selected row indices.
    selected_rows: Vec<usize>,
    /// Column widths (column index -> width in pixels).
    column_widths: Vec<(BookmarkColumn, usize)>,
    /// Whether the provider has been disposed.
    disposed: bool,
}

impl BookmarkViewProvider {
    /// Creates a new BookmarkViewProvider.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            model: BookmarkTableModel::new(),
            provider_model: BookmarkProviderModel::new(),
            visible: false,
            program: None,
            selected_rows: Vec::new(),
            column_widths: Self::default_column_widths(),
            disposed: false,
        }
    }

    /// Returns the default column widths.
    fn default_column_widths() -> Vec<(BookmarkColumn, usize)> {
        vec![
            (BookmarkColumn::Location, 90),
            (BookmarkColumn::Type, 80),
            (BookmarkColumn::Category, 90),
            (BookmarkColumn::Comment, 200),
            (BookmarkColumn::Label, 100),
            (BookmarkColumn::Preview, 150),
        ]
    }

    /// Returns the provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    // -- Lifecycle ----------------------------------------------------------

    /// Disposes the provider.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.model = BookmarkTableModel::new();
        self.provider_model = BookmarkProviderModel::new();
        self.program = None;
        self.selected_rows.clear();
    }

    /// Returns whether the provider has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    // -- Visibility ---------------------------------------------------------

    /// Returns whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Sets the provider visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    // -- Program lifecycle --------------------------------------------------

    /// Sets the current program.
    pub fn set_program(&mut self, program: Option<String>) {
        self.program = program;
        if self.program.is_none() {
            self.selected_rows.clear();
        }
    }

    /// Returns the current program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program.as_deref()
    }

    /// Reloads the model from the given program.
    pub fn reload(&mut self, mgr: Option<&BookmarkManager>) {
        if let Some(mgr) = mgr {
            self.model.initialize(mgr);
            self.model.load(mgr);
            self.provider_model.populate(mgr);
        } else {
            self.model = BookmarkTableModel::new();
            self.provider_model = BookmarkProviderModel::new();
        }
        self.selected_rows.clear();
    }

    // -- Bookmark events ----------------------------------------------------

    /// Notifies the provider that a bookmark was added.
    pub fn bookmark_added(&mut self, mgr: &BookmarkManager, bookmark_id: u64) {
        if self.visible {
            self.model.bookmark_added(mgr, bookmark_id);
            self.provider_model.populate(mgr);
        }
    }

    /// Notifies the provider that a bookmark was changed.
    pub fn bookmark_changed(&mut self, mgr: &BookmarkManager, bookmark_id: u64) {
        if self.visible {
            self.model.bookmark_changed(mgr, bookmark_id);
            self.provider_model.populate(mgr);
        }
    }

    /// Notifies the provider that a bookmark was removed.
    pub fn bookmark_removed(&mut self, mgr: &BookmarkManager, bookmark_id: u64) {
        if self.visible {
            self.model.bookmark_removed(mgr, bookmark_id);
            self.provider_model.populate(mgr);
        }
    }

    /// Notifies the provider that a new bookmark type was added.
    pub fn type_added(&mut self, type_string: &str) {
        if self.visible {
            self.model.type_added(type_string);
        }
    }

    // -- Selection ----------------------------------------------------------

    /// Returns the currently selected row indices.
    pub fn selected_rows(&self) -> &[usize] {
        &self.selected_rows
    }

    /// Sets the selected row indices.
    pub fn set_selected_rows(&mut self, rows: Vec<usize>) {
        self.selected_rows = rows;
    }

    /// Clears the selection.
    pub fn clear_selection(&mut self) {
        self.selected_rows.clear();
    }

    /// Returns the bookmark IDs for the selected rows.
    pub fn get_selected_bookmark_ids(&self) -> Vec<u64> {
        self.selected_rows
            .iter()
            .filter_map(|&row| self.model.get_row_object(row).map(|ro| ro.key()))
            .collect()
    }

    /// Returns the addresses of the selected bookmarks.
    pub fn get_selected_addresses(&self) -> Vec<Address> {
        self.selected_rows
            .iter()
            .filter_map(|&row| self.model.get_address(row))
            .collect()
    }

    // -- Deletion -----------------------------------------------------------

    /// Creates delete commands for the selected bookmarks.
    pub fn delete_selected(&self) -> Vec<BookmarkDeleteCmd> {
        self.get_selected_bookmark_ids()
            .iter()
            .map(|&id| BookmarkDeleteCmd::by_id(id))
            .collect()
    }

    // -- Filter state -------------------------------------------------------

    /// Returns the current filter state.
    pub fn get_filter_state(&self) -> FilterState {
        self.model.get_filter_state()
    }

    /// Restores the filter state.
    pub fn restore_filter_state(&mut self, state: &FilterState) {
        self.model.restore_filter_state(state);
    }

    /// Shows the given bookmark type.
    pub fn show_type(&mut self, type_string: &str) {
        self.model.show_type(type_string);
    }

    /// Hides all bookmark types.
    pub fn hide_all_types(&mut self) {
        self.model.hide_all_types();
    }

    /// Returns true if the given type is currently shown.
    pub fn is_showing_type(&self, type_string: &str) -> bool {
        self.model.is_showing_type(type_string)
    }

    /// Returns true if a type filter is applied.
    pub fn has_type_filter_applied(&self, mgr: &BookmarkManager) -> bool {
        self.model.has_type_filter_applied(mgr)
    }

    /// Sets the filter types (hides all, then shows the given types).
    pub fn set_filter_types(&mut self, types: &[String], mgr: &BookmarkManager) {
        self.model.hide_all_types();
        for t in types {
            self.model.show_type(t);
        }
        self.model.load(mgr);
    }

    /// Returns all currently active types.
    pub fn get_active_types(&self) -> &HashSet<String> {
        self.model.get_active_types()
    }

    // -- Column management --------------------------------------------------

    /// Returns the column width for the given column.
    pub fn column_width(&self, col: BookmarkColumn) -> usize {
        self.column_widths
            .iter()
            .find(|(c, _)| *c == col)
            .map(|(_, w)| *w)
            .unwrap_or(80)
    }

    /// Sets the column width for the given column.
    pub fn set_column_width(&mut self, col: BookmarkColumn, width: usize) {
        if let Some(entry) = self.column_widths.iter_mut().find(|(c, _)| *c == col) {
            entry.1 = width;
        } else {
            self.column_widths.push((col, width));
        }
    }

    // -- Table access -------------------------------------------------------

    /// Returns a reference to the table model.
    pub fn table_model(&self) -> &BookmarkTableModel {
        &self.model
    }

    /// Returns a mutable reference to the table model.
    pub fn table_model_mut(&mut self) -> &mut BookmarkTableModel {
        &mut self.model
    }

    /// Returns a reference to the provider model.
    pub fn provider_model(&self) -> &BookmarkProviderModel {
        &self.provider_model
    }

    /// Returns a mutable reference to the provider model.
    pub fn provider_model_mut(&mut self) -> &mut BookmarkProviderModel {
        &mut self.provider_model
    }

    /// Returns the row count.
    pub fn row_count(&self) -> usize {
        self.model.row_count()
    }

    /// Returns the total bookmark count.
    pub fn total_count(&self, mgr: &BookmarkManager) -> usize {
        self.model.total_count(mgr)
    }

    /// Returns the entry at the given row.
    pub fn get_entry(&self, row: usize) -> Option<&BookmarkTableEntry> {
        self.model.get_entry(row)
    }

    /// Returns the address at the given row.
    pub fn get_address(&self, row: usize) -> Option<Address> {
        self.model.get_address(row)
    }

    // -- Display subtitle ---------------------------------------------------

    /// Returns the display subtitle showing filter status.
    pub fn display_subtitle(&self, mgr: &BookmarkManager) -> String {
        let row_count = self.model.row_count();
        let total = self.model.total_count(mgr);

        if self.model.has_type_filter_applied(mgr) {
            format!("(filter matched {} of {})", row_count, total)
        } else {
            format!("({} bookmarks)", row_count)
        }
    }
}

impl Default for BookmarkViewProvider {
    fn default() -> Self {
        Self::new("Bookmarks")
    }
}

impl fmt::Display for BookmarkViewProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BookmarkViewProvider({}, visible={}, rows={})",
            self.name,
            self.visible,
            self.model.row_count()
        )
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

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

    fn make_provider_with_data() -> (BookmarkViewProvider, BookmarkManager) {
        let mut provider = BookmarkViewProvider::new("TestBookmarks");
        let mgr = make_mgr_with_bookmarks();
        provider.model.initialize(&mgr);
        provider.model.load(&mgr);
        provider.provider_model.populate(&mgr);
        (provider, mgr)
    }

    // ====================================================================
    // BookmarkViewProvider creation
    // ====================================================================

    #[test]
    fn test_provider_new() {
        let provider = BookmarkViewProvider::new("TestBookmarks");
        assert_eq!(provider.name(), "TestBookmarks");
        assert!(!provider.is_visible());
        assert!(!provider.is_disposed());
        assert!(provider.program_name().is_none());
        assert_eq!(provider.row_count(), 0);
    }

    #[test]
    fn test_provider_default() {
        let provider = BookmarkViewProvider::default();
        assert_eq!(provider.name(), "Bookmarks");
    }

    #[test]
    fn test_provider_display() {
        let provider = BookmarkViewProvider::new("Test");
        let s = format!("{}", provider);
        assert!(s.contains("Test"));
        assert!(s.contains("visible="));
        assert!(s.contains("rows="));
    }

    // ====================================================================
    // Lifecycle
    // ====================================================================

    #[test]
    fn test_provider_dispose() {
        let (mut provider, _) = make_provider_with_data();
        assert!(!provider.is_disposed());
        provider.dispose();
        assert!(provider.is_disposed());
        assert_eq!(provider.row_count(), 0);
    }

    // ====================================================================
    // Visibility
    // ====================================================================

    #[test]
    fn test_provider_visibility() {
        let mut provider = BookmarkViewProvider::new("Test");
        assert!(!provider.is_visible());
        provider.set_visible(true);
        assert!(provider.is_visible());
        provider.set_visible(false);
        assert!(!provider.is_visible());
    }

    // ====================================================================
    // Program lifecycle
    // ====================================================================

    #[test]
    fn test_program_name() {
        let mut provider = BookmarkViewProvider::new("Test");
        assert!(provider.program_name().is_none());
        provider.set_program(Some("test.exe".to_string()));
        assert_eq!(provider.program_name(), Some("test.exe"));
    }

    #[test]
    fn test_program_cleared_on_none() {
        let mut provider = BookmarkViewProvider::new("Test");
        provider.set_program(Some("test.exe".to_string()));
        provider.set_selected_rows(vec![0, 1]);
        provider.set_program(None);
        assert!(provider.program_name().is_none());
        assert!(provider.selected_rows().is_empty());
    }

    // ====================================================================
    // Reload
    // ====================================================================

    #[test]
    fn test_reload_with_program() {
        let mut provider = BookmarkViewProvider::new("Test");
        let mgr = make_mgr_with_bookmarks();
        provider.reload(Some(&mgr));
        assert_eq!(provider.row_count(), 4);
    }

    #[test]
    fn test_reload_without_program() {
        let (mut provider, _) = make_provider_with_data();
        assert_eq!(provider.row_count(), 4);
        provider.reload(None);
        assert_eq!(provider.row_count(), 0);
    }

    // ====================================================================
    // Bookmark events
    // ====================================================================

    #[test]
    fn test_bookmark_added() {
        let (mut provider, mut mgr) = make_provider_with_data();
        provider.set_visible(true);
        let id = mgr.set_bookmark(&addr(0x5000), "Note", "", "New").id();
        provider.bookmark_added(&mgr, id);
        assert_eq!(provider.row_count(), 5);
    }

    #[test]
    fn test_bookmark_changed() {
        let (mut provider, mut mgr) = make_provider_with_data();
        provider.set_visible(true);
        let id = mgr.set_bookmark(&addr(0x1000), "Note", "Cat1", "Updated").id();
        provider.bookmark_changed(&mgr, id);
    }

    #[test]
    fn test_bookmark_removed() {
        let (mut provider, mut mgr) = make_provider_with_data();
        provider.set_visible(true);
        let id = mgr.set_bookmark(&addr(0x5000), "Note", "", "Temp").id();
        provider.bookmark_added(&mgr, id);
        assert_eq!(provider.row_count(), 5);
        provider.bookmark_removed(&mgr, id);
        assert_eq!(provider.row_count(), 4);
    }

    #[test]
    fn test_type_added() {
        let (mut provider, _mgr) = make_provider_with_data();
        provider.set_visible(true);
        assert!(!provider.is_showing_type("CustomType"));
        provider.type_added("CustomType");
        assert!(provider.is_showing_type("CustomType"));
    }

    // ====================================================================
    // Selection
    // ====================================================================

    #[test]
    fn test_selected_rows() {
        let (mut provider, _) = make_provider_with_data();
        assert!(provider.selected_rows().is_empty());
        provider.set_selected_rows(vec![0, 2]);
        assert_eq!(provider.selected_rows(), &[0, 2]);
    }

    #[test]
    fn test_clear_selection() {
        let (mut provider, _) = make_provider_with_data();
        provider.set_selected_rows(vec![0, 1, 2]);
        provider.clear_selection();
        assert!(provider.selected_rows().is_empty());
    }

    #[test]
    fn test_get_selected_bookmark_ids() {
        let (mut provider, _) = make_provider_with_data();
        provider.set_selected_rows(vec![0, 1]);
        let ids = provider.get_selected_bookmark_ids();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn test_get_selected_addresses() {
        let (mut provider, _) = make_provider_with_data();
        provider.set_selected_rows(vec![0]);
        let addrs = provider.get_selected_addresses();
        assert_eq!(addrs.len(), 1);
    }

    // ====================================================================
    // Deletion
    // ====================================================================

    #[test]
    fn test_delete_selected() {
        let (mut provider, _) = make_provider_with_data();
        provider.set_selected_rows(vec![0, 1]);
        let cmds = provider.delete_selected();
        assert_eq!(cmds.len(), 2);
    }

    // ====================================================================
    // Filter state
    // ====================================================================

    #[test]
    fn test_filter_state_roundtrip() {
        let (mut provider, _mgr) = make_provider_with_data();
        let state = provider.get_filter_state();
        provider.hide_all_types();
        provider.model.load(&_mgr);
        assert_eq!(provider.row_count(), 0);

        provider.restore_filter_state(&state);
        provider.model.initialize(&_mgr);
        provider.model.load(&_mgr);
        assert_eq!(provider.row_count(), 4);
    }

    #[test]
    fn test_show_type() {
        let (mut provider, _mgr) = make_provider_with_data();
        provider.hide_all_types();
        provider.show_type("Note");
        provider.model.load(&_mgr);
        assert_eq!(provider.row_count(), 2);
    }

    #[test]
    fn test_is_showing_type() {
        let (provider, _) = make_provider_with_data();
        assert!(provider.is_showing_type("Note"));
        assert!(provider.is_showing_type("Warning"));
    }

    #[test]
    fn test_has_type_filter_applied() {
        let (mut provider, mgr) = make_provider_with_data();
        assert!(!provider.has_type_filter_applied(&mgr));
        provider.model.hide_type("Error");
        assert!(provider.has_type_filter_applied(&mgr));
    }

    #[test]
    fn test_set_filter_types() {
        let (mut provider, mgr) = make_provider_with_data();
        provider.set_filter_types(&["Note".to_string()], &mgr);
        assert_eq!(provider.row_count(), 2);
    }

    // ====================================================================
    // Column management
    // ====================================================================

    #[test]
    fn test_column_widths() {
        let provider = BookmarkViewProvider::new("Test");
        assert_eq!(provider.column_width(BookmarkColumn::Comment), 200);
        assert_eq!(provider.column_width(BookmarkColumn::Location), 90);
    }

    #[test]
    fn test_set_column_width() {
        let mut provider = BookmarkViewProvider::new("Test");
        provider.set_column_width(BookmarkColumn::Comment, 300);
        assert_eq!(provider.column_width(BookmarkColumn::Comment), 300);
    }

    // ====================================================================
    // Display subtitle
    // ====================================================================

    #[test]
    fn test_display_subtitle_no_filter() {
        let (provider, mgr) = make_provider_with_data();
        let subtitle = provider.display_subtitle(&mgr);
        assert_eq!(subtitle, "(4 bookmarks)");
    }

    #[test]
    fn test_display_subtitle_with_filter() {
        let (mut provider, mgr) = make_provider_with_data();
        provider.model.hide_type("Warning");
        provider.model.hide_type("Analysis");
        provider.model.load(&mgr);
        let subtitle = provider.display_subtitle(&mgr);
        assert!(subtitle.contains("filter matched"));
        assert!(subtitle.contains("2 of 4"));
    }

    // ====================================================================
    // Table access
    // ====================================================================

    #[test]
    fn test_table_model_access() {
        let (provider, _) = make_provider_with_data();
        assert_eq!(provider.table_model().row_count(), 4);
    }

    #[test]
    fn test_provider_model_access() {
        let (mut provider, _) = make_provider_with_data();
        assert_eq!(provider.provider_model().total_count(), 4);
    }

    #[test]
    fn test_get_entry() {
        let (provider, _) = make_provider_with_data();
        assert!(provider.get_entry(0).is_some());
        assert!(provider.get_entry(99).is_none());
    }

    #[test]
    fn test_get_address() {
        let (provider, _) = make_provider_with_data();
        assert!(provider.get_address(0).is_some());
        assert!(provider.get_address(99).is_none());
    }
}
