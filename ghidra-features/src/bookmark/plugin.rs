//! Bookmark plugin, provider, table model, and filtering logic.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.bookmark` Java package
//! (BookmarkPlugin, BookmarkProvider, BookmarkTableModel, FilterState,
//! BookmarkRowObject, BookmarkNavigator, BookmarkDeleteCmd, BookmarkEditCmd,
//! CreateBookmarkDialog, AddBookmarkAction, DeleteBookmarkAction,
//! BookmarkRowObjectToAddressTableRowMapper,
//! BookmarkRowObjectToProgramLocationTableRowMapper).

use super::{BookmarkData, BookmarkManager, BookmarkType};
use ghidra_core::Address;
use std::collections::HashSet;

// ============================================================================
// FilterState -- bookmark type filter
// ============================================================================

/// Tracks which bookmark types are visible.
///
/// Ported from `ghidra.app.plugin.core.bookmark.FilterState`.
#[derive(Debug, Clone)]
pub struct FilterState {
    /// The set of bookmark type strings that are enabled.
    enabled_types: HashSet<String>,
}

impl FilterState {
    /// Create a new filter state with all types enabled.
    pub fn all_enabled(types: &[String]) -> Self {
        Self {
            enabled_types: types.iter().cloned().collect(),
        }
    }

    /// Create a filter state with no types enabled.
    pub fn none_enabled() -> Self {
        Self {
            enabled_types: HashSet::new(),
        }
    }

    /// Check whether a bookmark type is enabled.
    pub fn is_enabled(&self, type_string: &str) -> bool {
        self.enabled_types.contains(type_string)
    }

    /// Enable a bookmark type.
    pub fn enable(&mut self, type_string: impl Into<String>) {
        self.enabled_types.insert(type_string.into());
    }

    /// Disable a bookmark type.
    pub fn disable(&mut self, type_string: &str) {
        self.enabled_types.remove(type_string);
    }

    /// Toggle a bookmark type.
    pub fn toggle(&mut self, type_string: &str) {
        if self.enabled_types.contains(type_string) {
            self.enabled_types.remove(type_string);
        } else {
            self.enabled_types.insert(type_string.to_string());
        }
    }

    /// Get all enabled types.
    pub fn enabled_types(&self) -> &HashSet<String> {
        &self.enabled_types
    }

    /// The number of enabled types.
    pub fn enabled_count(&self) -> usize {
        self.enabled_types.len()
    }

    /// Whether all given types are enabled.
    pub fn are_all_enabled(&self, types: &[String]) -> bool {
        types.iter().all(|t| self.enabled_types.contains(t))
    }
}

impl Default for FilterState {
    fn default() -> Self {
        Self::all_enabled(&[
            "Info".to_string(),
            "Warning".to_string(),
            "Error".to_string(),
            "Note".to_string(),
        ])
    }
}

// ============================================================================
// BookmarkRowObject -- a row in the bookmark table
// ============================================================================

/// Represents a single row in the bookmark table.
///
/// Ported from `ghidra.app.plugin.core.bookmark.BookmarkRowObject`.
#[derive(Debug, Clone)]
pub struct BookmarkRowObject {
    /// The bookmark ID.
    pub id: u64,
    /// The address.
    pub address: Address,
    /// The bookmark type string.
    pub type_string: String,
    /// The category string.
    pub category: String,
    /// The comment text.
    pub comment: String,
}

impl BookmarkRowObject {
    /// Create a row object from bookmark data.
    pub fn from_bookmark(bm: &BookmarkData) -> Self {
        Self {
            id: bm.id,
            address: bm.address,
            type_string: bm.bookmark_type.type_string().to_string(),
            category: bm.bookmark_type.category().to_string(),
            comment: bm.comment.clone(),
        }
    }
}

// ============================================================================
// BookmarkTableModel -- a table model for displaying bookmarks
// ============================================================================

/// Column definitions for the bookmark table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BookmarkColumn {
    /// Address column.
    Address,
    /// Type column.
    Type,
    /// Category column.
    Category,
    /// Comment column.
    Comment,
}

impl BookmarkColumn {
    /// All columns in display order.
    pub fn all() -> &'static [BookmarkColumn] {
        &[
            BookmarkColumn::Address,
            BookmarkColumn::Type,
            BookmarkColumn::Category,
            BookmarkColumn::Comment,
        ]
    }

    /// Column header name.
    pub fn header(&self) -> &'static str {
        match self {
            Self::Address => "Address",
            Self::Type => "Type",
            Self::Category => "Category",
            Self::Comment => "Comment",
        }
    }
}

/// Table model for displaying bookmarks.
///
/// Ported from `ghidra.app.plugin.core.bookmark.BookmarkTableModel`.
#[derive(Debug)]
pub struct BookmarkTableModel {
    /// All bookmark rows.
    rows: Vec<BookmarkRowObject>,
    /// Current filter state.
    filter: FilterState,
    /// Sort column.
    sort_column: BookmarkColumn,
    /// Whether sort is ascending.
    sort_ascending: bool,
}

impl BookmarkTableModel {
    /// Create a new table model from a bookmark manager.
    pub fn new(manager: &BookmarkManager) -> Self {
        let rows: Vec<BookmarkRowObject> = manager
            .get_all_bookmarks()
            .iter()
            .map(|bm| BookmarkRowObject::from_bookmark(bm))
            .collect();
        Self {
            rows,
            filter: FilterState::default(),
            sort_column: BookmarkColumn::Address,
            sort_ascending: true,
        }
    }

    /// Get the total number of rows (before filtering).
    pub fn total_row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get the number of visible rows (after filtering).
    pub fn visible_row_count(&self) -> usize {
        self.rows
            .iter()
            .filter(|r| self.filter.is_enabled(&r.type_string))
            .count()
    }

    /// Get a row by index (unfiltered).
    pub fn get_row(&self, index: usize) -> Option<&BookmarkRowObject> {
        self.rows.get(index)
    }

    /// Get all visible rows.
    pub fn visible_rows(&self) -> Vec<&BookmarkRowObject> {
        self.rows
            .iter()
            .filter(|r| self.filter.is_enabled(&r.type_string))
            .collect()
    }

    /// Set the filter state.
    pub fn set_filter(&mut self, filter: FilterState) {
        self.filter = filter;
    }

    /// Get the filter state.
    pub fn filter(&self) -> &FilterState {
        &self.filter
    }

    /// Sort the table by column.
    pub fn sort_by(&mut self, column: BookmarkColumn, ascending: bool) {
        self.sort_column = column;
        self.sort_ascending = ascending;
        match column {
            BookmarkColumn::Address => {
                self.rows.sort_by_key(|r| r.address.offset);
            }
            BookmarkColumn::Type => {
                self.rows.sort_by(|a, b| a.type_string.cmp(&b.type_string));
            }
            BookmarkColumn::Category => {
                self.rows.sort_by(|a, b| a.category.cmp(&b.category));
            }
            BookmarkColumn::Comment => {
                self.rows.sort_by(|a, b| a.comment.cmp(&b.comment));
            }
        }
        if !ascending {
            self.rows.reverse();
        }
    }

    /// Refresh the model from the bookmark manager.
    pub fn refresh(&mut self, manager: &BookmarkManager) {
        self.rows = manager
            .get_all_bookmarks()
            .iter()
            .map(|bm| BookmarkRowObject::from_bookmark(bm))
            .collect();
        self.sort_by(self.sort_column, self.sort_ascending);
    }
}

// ============================================================================
// BookmarkDeleteCmd -- command for deleting bookmarks
// ============================================================================

/// Command to delete bookmarks.
///
/// Ported from `ghidra.app.plugin.core.bookmark.BookmarkDeleteCmd`.
#[derive(Debug)]
pub struct BookmarkDeleteCmd {
    /// The IDs to delete.
    pub bookmark_ids: Vec<u64>,
    /// Error message if the command failed.
    error_message: Option<String>,
}

impl BookmarkDeleteCmd {
    /// Create a new delete command for a single bookmark.
    pub fn new(id: u64) -> Self {
        Self {
            bookmark_ids: vec![id],
            error_message: None,
        }
    }

    /// Create a delete command for multiple bookmarks.
    pub fn new_multiple(ids: Vec<u64>) -> Self {
        Self {
            bookmark_ids: ids,
            error_message: None,
        }
    }

    /// Execute the delete command.
    pub fn execute(&mut self, manager: &mut BookmarkManager) -> bool {
        for id in &self.bookmark_ids {
            if manager.remove_bookmark(*id).is_none() {
                self.error_message = Some(format!("Bookmark {} not found", id));
                return false;
            }
        }
        true
    }

    /// Get the error message, if any.
    pub fn status_msg(&self) -> Option<&str> {
        self.error_message.as_deref()
    }
}

// ============================================================================
// BookmarkEditCmd -- command for editing bookmark comments
// ============================================================================

/// Command to edit a bookmark's comment.
///
/// Ported from `ghidra.app.plugin.core.bookmark.BookmarkEditCmd`.
#[derive(Debug)]
pub struct BookmarkEditCmd {
    /// The bookmark ID to edit.
    pub bookmark_id: u64,
    /// The new comment text.
    pub new_comment: String,
}

impl BookmarkEditCmd {
    /// Create a new edit command.
    pub fn new(bookmark_id: u64, new_comment: impl Into<String>) -> Self {
        Self {
            bookmark_id,
            new_comment: new_comment.into(),
        }
    }

    /// Execute the edit command.
    pub fn execute(&self, manager: &mut BookmarkManager) -> Result<(), String> {
        if let Some(bm) = manager.get_bookmark_mut(self.bookmark_id) {
            bm.comment = self.new_comment.clone();
            Ok(())
        } else {
            Err(format!("Bookmark {} not found", self.bookmark_id))
        }
    }
}

// ============================================================================
// BookmarkProvider -- the bookmark provider / view model
// ============================================================================

/// The bookmark provider manages the bookmark view state.
///
/// Ported from `ghidra.app.plugin.core.bookmark.BookmarkProvider`.
#[derive(Debug)]
pub struct BookmarkProvider {
    /// The table model.
    pub table_model: BookmarkTableModel,
    /// Whether the provider is visible.
    pub visible: bool,
    /// The currently selected bookmark IDs.
    selected_ids: Vec<u64>,
}

impl BookmarkProvider {
    /// Create a new bookmark provider.
    pub fn new(manager: &BookmarkManager) -> Self {
        Self {
            table_model: BookmarkTableModel::new(manager),
            visible: false,
            selected_ids: Vec::new(),
        }
    }

    /// Set the selection.
    pub fn set_selection(&mut self, ids: Vec<u64>) {
        self.selected_ids = ids;
    }

    /// Get the selected bookmark IDs.
    pub fn selected_ids(&self) -> &[u64] {
        &self.selected_ids
    }

    /// Whether there is a selection.
    pub fn has_selection(&self) -> bool {
        !self.selected_ids.is_empty()
    }

    /// Refresh the table from the manager.
    pub fn refresh(&mut self, manager: &BookmarkManager) {
        self.table_model.refresh(manager);
    }

    /// Show the provider.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Hide the provider.
    pub fn hide(&mut self) {
        self.visible = false;
    }
}

// ============================================================================
// BookmarkPlugin -- the main bookmark plugin
// ============================================================================

/// The bookmark plugin orchestrates bookmark operations.
///
/// Ported from `ghidra.app.plugin.core.bookmark.BookmarkPlugin`.
#[derive(Debug)]
pub struct BookmarkPlugin {
    /// The bookmark manager.
    pub manager: BookmarkManager,
    /// The bookmark provider.
    pub provider: BookmarkProvider,
    /// Timer delay for repainting markers (ms).
    pub timer_delay: u32,
    /// Minimum timeout (ms).
    pub min_timeout: u32,
    /// Maximum timeout (ms).
    pub max_timeout: u32,
    /// Whether the plugin is disposed.
    disposed: bool,
}

impl BookmarkPlugin {
    /// Create a new bookmark plugin.
    pub fn new() -> Self {
        let manager = BookmarkManager::new();
        let provider = BookmarkProvider::new(&manager);
        Self {
            manager,
            provider,
            timer_delay: 500,
            min_timeout: 1000,
            max_timeout: 1_200_000, // 20 minutes
            disposed: false,
        }
    }

    /// Add a bookmark.
    pub fn add_bookmark(
        &mut self,
        address: Address,
        bookmark_type: BookmarkType,
        comment: &str,
    ) -> u64 {
        let id = self.manager.set_bookmark(address, &bookmark_type, comment);
        self.provider.refresh(&self.manager);
        id
    }

    /// Delete bookmarks by IDs.
    pub fn delete_bookmarks(&mut self, ids: &[u64]) {
        for &id in ids {
            self.manager.remove_bookmark(id);
        }
        self.provider.refresh(&self.manager);
    }

    /// Edit a bookmark's comment.
    pub fn edit_bookmark(&mut self, id: u64, new_comment: &str) -> Result<(), String> {
        BookmarkEditCmd::new(id, new_comment).execute(&mut self.manager)?;
        self.provider.refresh(&self.manager);
        Ok(())
    }

    /// Get bookmark count by type.
    pub fn bookmark_count_by_type(&self, type_string: &str) -> usize {
        self.manager.bookmark_count_by_type(type_string)
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

impl Default for BookmarkPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// BookmarkNavigator -- navigates between bookmarks
// ============================================================================

/// Address mapper for bookmark table rows.
///
/// Ported from
/// `ghidra.app.plugin.core.bookmark.BookmarkRowObjectToAddressTableRowMapper`.
#[derive(Debug)]
pub struct BookmarkRowObjectToAddressMapper;

impl BookmarkRowObjectToAddressMapper {
    /// Map a bookmark row to an address.
    pub fn map(row: &BookmarkRowObject) -> Address {
        row.address
    }
}

/// Program location mapper for bookmark table rows.
///
/// Ported from
/// `ghidra.app.plugin.core.bookmark.BookmarkRowObjectToProgramLocationTableRowMapper`.
#[derive(Debug)]
pub struct BookmarkRowObjectToProgramLocationMapper;

impl BookmarkRowObjectToProgramLocationMapper {
    /// Map a bookmark row to a program location (address + type info).
    pub fn map(row: &BookmarkRowObject) -> (Address, &str, &str) {
        (row.address, &row.type_string, &row.category)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_state_default() {
        let filter = FilterState::default();
        assert!(filter.is_enabled("Info"));
        assert!(filter.is_enabled("Warning"));
        assert!(filter.is_enabled("Error"));
        assert!(filter.is_enabled("Note"));
        assert_eq!(filter.enabled_count(), 4);
    }

    #[test]
    fn test_filter_state_toggle() {
        let mut filter = FilterState::default();
        assert!(filter.is_enabled("Info"));
        filter.toggle("Info");
        assert!(!filter.is_enabled("Info"));
        filter.toggle("Info");
        assert!(filter.is_enabled("Info"));
    }

    #[test]
    fn test_filter_state_enable_disable() {
        let mut filter = FilterState::none_enabled();
        assert_eq!(filter.enabled_count(), 0);
        filter.enable("Info");
        assert_eq!(filter.enabled_count(), 1);
        filter.disable("Info");
        assert_eq!(filter.enabled_count(), 0);
    }

    #[test]
    fn test_filter_state_all_enabled() {
        let types = vec!["A".to_string(), "B".to_string()];
        let filter = FilterState::all_enabled(&types);
        assert!(filter.are_all_enabled(&types));

        let mut filter2 = FilterState::all_enabled(&types);
        filter2.disable("A");
        assert!(!filter2.are_all_enabled(&types));
    }

    #[test]
    fn test_bookmark_row_object() {
        let bm = BookmarkData::new(
            Address::new(0x1000),
            BookmarkType::info(),
            "test comment",
            1,
        );
        let row = BookmarkRowObject::from_bookmark(&bm);
        assert_eq!(row.id, 1);
        assert_eq!(row.address, Address::new(0x1000));
        assert_eq!(row.type_string, "Info");
        assert_eq!(row.category, "Analysis");
        assert_eq!(row.comment, "test comment");
    }

    #[test]
    fn test_bookmark_table_model() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(Address::new(0x1000), &BookmarkType::info(), "c1");
        mgr.set_bookmark(Address::new(0x2000), &BookmarkType::warning(), "c2");
        mgr.set_bookmark(Address::new(0x3000), &BookmarkType::note(), "c3");

        let model = BookmarkTableModel::new(&mgr);
        assert_eq!(model.total_row_count(), 3);
        assert_eq!(model.visible_row_count(), 3); // all enabled by default
    }

    #[test]
    fn test_bookmark_table_model_filter() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(Address::new(0x1000), &BookmarkType::info(), "c1");
        mgr.set_bookmark(Address::new(0x2000), &BookmarkType::warning(), "c2");

        let mut model = BookmarkTableModel::new(&mgr);
        let mut filter = FilterState::default();
        filter.disable("Info");
        model.set_filter(filter);

        assert_eq!(model.total_row_count(), 2);
        assert_eq!(model.visible_row_count(), 1);
    }

    #[test]
    fn test_bookmark_table_model_sort() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(Address::new(0x3000), &BookmarkType::info(), "c");
        mgr.set_bookmark(Address::new(0x1000), &BookmarkType::warning(), "a");
        mgr.set_bookmark(Address::new(0x2000), &BookmarkType::note(), "b");

        let mut model = BookmarkTableModel::new(&mgr);
        model.sort_by(BookmarkColumn::Address, true);
        let rows = model.visible_rows();
        assert_eq!(rows[0].address, Address::new(0x1000));
        assert_eq!(rows[1].address, Address::new(0x2000));
        assert_eq!(rows[2].address, Address::new(0x3000));

        model.sort_by(BookmarkColumn::Address, false);
        let rows = model.visible_rows();
        assert_eq!(rows[0].address, Address::new(0x3000));
    }

    #[test]
    fn test_bookmark_table_model_sort_by_comment() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(Address::new(0x1000), &BookmarkType::info(), "zebra");
        mgr.set_bookmark(Address::new(0x2000), &BookmarkType::info(), "alpha");

        let mut model = BookmarkTableModel::new(&mgr);
        model.sort_by(BookmarkColumn::Comment, true);
        let rows = model.visible_rows();
        assert_eq!(rows[0].comment, "alpha");
        assert_eq!(rows[1].comment, "zebra");
    }

    #[test]
    fn test_bookmark_delete_cmd() {
        let mut mgr = BookmarkManager::new();
        let id = mgr.set_bookmark(Address::new(0x1000), &BookmarkType::info(), "test");
        let mut cmd = BookmarkDeleteCmd::new(id);
        assert!(cmd.execute(&mut mgr));
        assert!(mgr.get_bookmark(id).is_none());
    }

    #[test]
    fn test_bookmark_delete_cmd_not_found() {
        let mut mgr = BookmarkManager::new();
        let mut cmd = BookmarkDeleteCmd::new(999);
        assert!(!cmd.execute(&mut mgr));
        assert!(cmd.status_msg().is_some());
    }

    #[test]
    fn test_bookmark_delete_multiple() {
        let mut mgr = BookmarkManager::new();
        let id1 = mgr.set_bookmark(Address::new(0x1000), &BookmarkType::info(), "a");
        let id2 = mgr.set_bookmark(Address::new(0x2000), &BookmarkType::info(), "b");
        let mut cmd = BookmarkDeleteCmd::new_multiple(vec![id1, id2]);
        assert!(cmd.execute(&mut mgr));
        assert_eq!(mgr.bookmark_count(), 0);
    }

    #[test]
    fn test_bookmark_edit_cmd() {
        let mut mgr = BookmarkManager::new();
        let id = mgr.set_bookmark(Address::new(0x1000), &BookmarkType::info(), "old");
        let cmd = BookmarkEditCmd::new(id, "new comment");
        cmd.execute(&mut mgr).unwrap();
        assert_eq!(mgr.get_bookmark(id).unwrap().comment, "new comment");
    }

    #[test]
    fn test_bookmark_edit_cmd_not_found() {
        let mut mgr = BookmarkManager::new();
        let cmd = BookmarkEditCmd::new(999, "new");
        assert!(cmd.execute(&mut mgr).is_err());
    }

    #[test]
    fn test_bookmark_provider() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(Address::new(0x1000), &BookmarkType::info(), "c1");
        let mut provider = BookmarkProvider::new(&mgr);
        assert!(!provider.visible);
        provider.show();
        assert!(provider.visible);
        assert!(!provider.has_selection());
        provider.set_selection(vec![1]);
        assert!(provider.has_selection());
    }

    #[test]
    fn test_bookmark_plugin() {
        let mut plugin = BookmarkPlugin::new();
        assert_eq!(plugin.manager.bookmark_count(), 0); // no bookmarks initially
        assert_eq!(plugin.manager.get_bookmark_types().len(), 4); // 4 default types registered

        plugin.add_bookmark(Address::new(0x1000), BookmarkType::info(), "test");
        assert_eq!(plugin.bookmark_count_by_type("Info"), 1);

        plugin.edit_bookmark(0, "updated").unwrap();
        let bm = plugin.manager.get_bookmark(0).unwrap();
        assert_eq!(bm.comment, "updated");

        plugin.delete_bookmarks(&[0]);
        assert_eq!(plugin.bookmark_count_by_type("Info"), 0);
    }

    #[test]
    fn test_bookmark_plugin_dispose() {
        let mut plugin = BookmarkPlugin::new();
        assert!(!plugin.is_disposed());
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_bookmark_column_headers() {
        assert_eq!(BookmarkColumn::Address.header(), "Address");
        assert_eq!(BookmarkColumn::Type.header(), "Type");
        assert_eq!(BookmarkColumn::Category.header(), "Category");
        assert_eq!(BookmarkColumn::Comment.header(), "Comment");
        assert_eq!(BookmarkColumn::all().len(), 4);
    }

    #[test]
    fn test_address_mapper() {
        let row = BookmarkRowObject {
            id: 1,
            address: Address::new(0x4000),
            type_string: "Info".into(),
            category: "Analysis".into(),
            comment: "test".into(),
        };
        assert_eq!(BookmarkRowObjectToAddressMapper::map(&row), Address::new(0x4000));
    }

    #[test]
    fn test_program_location_mapper() {
        let row = BookmarkRowObject {
            id: 1,
            address: Address::new(0x4000),
            type_string: "Warning".into(),
            category: "Analysis".into(),
            comment: "test".into(),
        };
        let (addr, typ, cat) = BookmarkRowObjectToProgramLocationMapper::map(&row);
        assert_eq!(addr, Address::new(0x4000));
        assert_eq!(typ, "Warning");
        assert_eq!(cat, "Analysis");
    }

    #[test]
    fn test_bookmark_table_model_refresh() {
        let mut mgr = BookmarkManager::new();
        let mut model = BookmarkTableModel::new(&mgr);
        assert_eq!(model.total_row_count(), 0);

        mgr.set_bookmark(Address::new(0x1000), &BookmarkType::info(), "new");
        model.refresh(&mgr);
        assert_eq!(model.total_row_count(), 1);
    }
}
