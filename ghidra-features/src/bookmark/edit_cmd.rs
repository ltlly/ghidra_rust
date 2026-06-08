//! Bookmark edit command and table row mappers.
//!
//! Ported from `ghidra.app.plugin.core.bookmark.BookmarkEditCmd`,
//! `ghidra.app.plugin.core.bookmark.BookmarkRowObject`,
//! `ghidra.app.plugin.core.bookmark.BookmarkRowObjectToAddressTableRowMapper`,
//! and `ghidra.app.plugin.core.bookmark.BookmarkRowObjectToProgramLocationTableRowMapper`.

use serde::{Deserialize, Serialize};

use super::BookmarkData;

/// Command to set bookmarks at a location or range of locations.
///
/// Ported from `ghidra.app.plugin.core.bookmark.BookmarkEditCmd`.
///
/// The location to create bookmarks can be set by:
/// 1. By address set where the bookmark is placed at the first address in each range
/// 2. At a given single address
/// 3. By the information contained in an existing bookmark
#[derive(Debug, Clone)]
pub struct BookmarkEditCmd {
    /// The bookmark type string.
    pub type_string: String,
    /// The bookmark category.
    pub category: String,
    /// The bookmark comment.
    pub comment: String,
    /// Addresses to add bookmarks to (for address-set mode).
    addresses: Vec<u64>,
    /// Single address (for single-address mode).
    single_address: Option<u64>,
    /// Whether to edit an existing bookmark.
    edit_existing: Option<u64>,
    /// Presentation name.
    presentation_name: String,
    /// Whether the command was applied.
    applied: bool,
}

impl BookmarkEditCmd {
    /// Create a command to add bookmarks at addresses in a set.
    pub fn new_for_address_set(
        addresses: Vec<u64>,
        type_string: impl Into<String>,
        category: impl Into<String>,
        comment: impl Into<String>,
    ) -> Self {
        let ts = type_string.into();
        let presentation = format!("Add {} Bookmark(s)", ts);
        Self {
            type_string: ts,
            category: category.into(),
            comment: comment.into(),
            addresses,
            single_address: None,
            edit_existing: None,
            presentation_name: presentation,
            applied: false,
        }
    }

    /// Create a command to add a bookmark at a single address.
    pub fn new_for_address(
        address: u64,
        type_string: impl Into<String>,
        category: impl Into<String>,
        comment: impl Into<String>,
    ) -> Self {
        let ts = type_string.into();
        let presentation = format!("Add {} Bookmark", ts);
        Self {
            type_string: ts,
            category: category.into(),
            comment: comment.into(),
            addresses: Vec::new(),
            single_address: Some(address),
            edit_existing: None,
            presentation_name: presentation,
            applied: false,
        }
    }

    /// Create a command to edit an existing bookmark.
    pub fn new_for_edit(
        bookmark_id: u64,
        type_string: impl Into<String>,
        category: impl Into<String>,
        comment: impl Into<String>,
    ) -> Self {
        let ts = type_string.into();
        let presentation = format!("Edit {} Bookmark", ts);
        Self {
            type_string: ts,
            category: category.into(),
            comment: comment.into(),
            addresses: Vec::new(),
            single_address: None,
            edit_existing: Some(bookmark_id),
            presentation_name: presentation,
            applied: false,
        }
    }

    /// Get the presentation name.
    pub fn presentation_name(&self) -> &str {
        &self.presentation_name
    }

    /// Get the command name.
    pub fn name(&self) -> &str {
        &self.presentation_name
    }

    /// Apply the command (simulated).
    pub fn apply(&mut self) -> bool {
        self.applied = true;
        true
    }

    /// Whether the command was applied.
    pub fn was_applied(&self) -> bool {
        self.applied
    }

    /// Get the status message (always None on success).
    pub fn status_msg(&self) -> Option<&str> {
        None
    }

    /// Get all target addresses this command will create bookmarks at.
    pub fn target_addresses(&self) -> Vec<u64> {
        if let Some(addr) = self.single_address {
            vec![addr]
        } else {
            self.addresses.clone()
        }
    }
}

// ---------------------------------------------------------------------------
// BookmarkDeleteCmd
// ---------------------------------------------------------------------------

/// Command to delete bookmarks.
///
/// Ported from `ghidra.app.plugin.core.bookmark.BookmarkDeleteCmd`.
#[derive(Debug, Clone)]
pub struct BookmarkDeleteCmd {
    /// Bookmark IDs to delete.
    pub bookmark_ids: Vec<u64>,
    /// The bookmark type to delete (None = all types).
    pub type_filter: Option<String>,
    /// Whether the command was applied.
    applied: bool,
}

impl BookmarkDeleteCmd {
    /// Create a new delete command for specific bookmark IDs.
    pub fn new(bookmark_ids: Vec<u64>) -> Self {
        Self {
            bookmark_ids,
            type_filter: None,
            applied: false,
        }
    }

    /// Create a new delete command for bookmarks of a specific type.
    pub fn new_typed(bookmark_ids: Vec<u64>, type_string: impl Into<String>) -> Self {
        Self {
            bookmark_ids,
            type_filter: Some(type_string.into()),
            applied: false,
        }
    }

    /// Apply the command.
    pub fn apply(&mut self) -> bool {
        self.applied = true;
        true
    }

    /// Whether the command was applied.
    pub fn was_applied(&self) -> bool {
        self.applied
    }

    /// Get the command name.
    pub fn name(&self) -> &str {
        "Delete Bookmark"
    }
}

// ---------------------------------------------------------------------------
// BookmarkRowObject
// ---------------------------------------------------------------------------

/// Row object for displaying a bookmark in a table.
///
/// Ported from `ghidra.app.plugin.core.bookmark.BookmarkRowObject`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkRowObject {
    /// The bookmark type string.
    pub type_string: String,
    /// The bookmark category.
    pub category: String,
    /// The bookmark comment.
    pub comment: String,
    /// The address of the bookmark.
    pub address: u64,
    /// The bookmark ID.
    pub id: u64,
    /// Primary key for table sorting.
    pub primary_key: u64,
}

impl BookmarkRowObject {
    /// Create a new bookmark row object.
    pub fn new(
        type_string: impl Into<String>,
        category: impl Into<String>,
        comment: impl Into<String>,
        address: u64,
        id: u64,
    ) -> Self {
        Self {
            type_string: type_string.into(),
            category: category.into(),
            comment: comment.into(),
            address,
            id,
            primary_key: id,
        }
    }

    /// Create from BookmarkData.
    pub fn from_bookmark_data(bm: &BookmarkData) -> Self {
        Self {
            type_string: bm.bookmark_type.type_string().to_string(),
            category: bm.bookmark_type.category().to_string(),
            comment: bm.comment.clone(),
            address: bm.address.offset,
            id: bm.id,
            primary_key: bm.id,
        }
    }

    /// Get the address as a u64.
    pub fn get_address(&self) -> u64 {
        self.address
    }

    /// Get the type string.
    pub fn get_type_string(&self) -> &str {
        &self.type_string
    }

    /// Get the category.
    pub fn get_category(&self) -> &str {
        &self.category
    }

    /// Get the comment.
    pub fn get_comment(&self) -> &str {
        &self.comment
    }
}

// ---------------------------------------------------------------------------
// BookmarkTableModel
// ---------------------------------------------------------------------------

/// Table model for displaying bookmarks in a table.
///
/// Ported from `ghidra.app.plugin.core.bookmark.BookmarkTableModel`.
#[derive(Debug, Clone)]
pub struct BookmarkTableModel {
    /// Column names for the bookmark table.
    pub columns: Vec<String>,
    /// Row objects in the table.
    rows: Vec<BookmarkRowObject>,
    /// Current filter type (None = show all).
    pub filter_type: Option<String>,
    /// Current filter category (None = show all).
    pub filter_category: Option<String>,
}

impl BookmarkTableModel {
    /// Column index for bookmark type.
    pub const COL_TYPE: usize = 0;
    /// Column index for bookmark category.
    pub const COL_CATEGORY: usize = 1;
    /// Column index for bookmark address.
    pub const COL_ADDRESS: usize = 2;
    /// Column index for bookmark comment.
    pub const COL_COMMENT: usize = 3;

    /// Create a new bookmark table model.
    pub fn new() -> Self {
        Self {
            columns: vec![
                "Type".to_string(),
                "Category".to_string(),
                "Address".to_string(),
                "Comment".to_string(),
            ],
            rows: Vec::new(),
            filter_type: None,
            filter_category: None,
        }
    }

    /// Get the number of columns.
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Get the column name.
    pub fn column_name(&self, index: usize) -> Option<&str> {
        self.columns.get(index).map(|s| s.as_str())
    }

    /// Get the number of rows (after filtering).
    pub fn row_count(&self) -> usize {
        self.filtered_rows().len()
    }

    /// Get all row objects (unfiltered).
    pub fn all_rows(&self) -> &[BookmarkRowObject] {
        &self.rows
    }

    /// Get filtered row objects.
    pub fn filtered_rows(&self) -> Vec<&BookmarkRowObject> {
        self.rows
            .iter()
            .filter(|row| {
                if let Some(ref ft) = self.filter_type {
                    if row.type_string != *ft {
                        return false;
                    }
                }
                if let Some(ref fc) = self.filter_category {
                    if row.category != *fc {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    /// Set the data for the table.
    pub fn set_data(&mut self, rows: Vec<BookmarkRowObject>) {
        self.rows = rows;
    }

    /// Add a row.
    pub fn add_row(&mut self, row: BookmarkRowObject) {
        self.rows.push(row);
    }

    /// Remove a row by bookmark ID.
    pub fn remove_row(&mut self, bookmark_id: u64) -> Option<BookmarkRowObject> {
        if let Some(idx) = self.rows.iter().position(|r| r.id == bookmark_id) {
            Some(self.rows.remove(idx))
        } else {
            None
        }
    }

    /// Set a type filter.
    pub fn set_filter_type(&mut self, type_string: Option<String>) {
        self.filter_type = type_string;
    }

    /// Set a category filter.
    pub fn set_filter_category(&mut self, category: Option<String>) {
        self.filter_category = category;
    }

    /// Clear all filters.
    pub fn clear_filters(&mut self) {
        self.filter_type = None;
        self.filter_category = None;
    }

    /// Get a row by index (filtered).
    pub fn get_row(&self, index: usize) -> Option<&BookmarkRowObject> {
        self.filtered_rows().into_iter().nth(index)
    }

    /// Get the cell value for a given row and column.
    pub fn get_cell_value(&self, row: usize, col: usize) -> Option<String> {
        let r = self.get_row(row)?;
        match col {
            Self::COL_TYPE => Some(r.type_string.clone()),
            Self::COL_CATEGORY => Some(r.category.clone()),
            Self::COL_ADDRESS => Some(format!("0x{:X}", r.address)),
            Self::COL_COMMENT => Some(r.comment.clone()),
            _ => None,
        }
    }
}

impl Default for BookmarkTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BookmarkRowObjectToAddressTableRowMapper
// ---------------------------------------------------------------------------

/// Maps a `BookmarkRowObject` to an address (for table navigation).
///
/// Ported from `ghidra.app.plugin.core.bookmark.BookmarkRowObjectToAddressTableRowMapper`.
#[derive(Debug, Clone)]
pub struct BookmarkRowObjectToAddressTableRowMapper;

impl BookmarkRowObjectToAddressTableRowMapper {
    /// Map a bookmark row object to an address.
    pub fn map(row: &BookmarkRowObject) -> u64 {
        row.address
    }
}

// ---------------------------------------------------------------------------
// BookmarkRowObjectToProgramLocationTableRowMapper
// ---------------------------------------------------------------------------

/// Maps a `BookmarkRowObject` to a program location (for table navigation).
///
/// Ported from `ghidra.app.plugin.core.bookmark.BookmarkRowObjectToProgramLocationTableRowMapper`.
#[derive(Debug, Clone)]
pub struct BookmarkRowObjectToProgramLocationTableRowMapper;

/// A program location row reference, combining address and bookmark metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkProgramLocation {
    /// The address.
    pub address: u64,
    /// The bookmark type.
    pub type_string: String,
    /// The bookmark ID.
    pub bookmark_id: u64,
}

impl BookmarkRowObjectToProgramLocationTableRowMapper {
    /// Map a bookmark row object to a program location.
    pub fn map(row: &BookmarkRowObject) -> BookmarkProgramLocation {
        BookmarkProgramLocation {
            address: row.address,
            type_string: row.type_string.clone(),
            bookmark_id: row.id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bookmark::BookmarkType;

    #[test]
    fn test_bookmark_edit_cmd_for_address() {
        let cmd = BookmarkEditCmd::new_for_address(
            0x400000,
            "Info",
            "Analysis",
            "Test comment",
        );
        assert_eq!(cmd.name(), "Add Info Bookmark");
        assert_eq!(cmd.target_addresses(), vec![0x400000]);
        assert!(!cmd.was_applied());
    }

    #[test]
    fn test_bookmark_edit_cmd_for_address_set() {
        let cmd = BookmarkEditCmd::new_for_address_set(
            vec![0x1000, 0x2000, 0x3000],
            "Warning",
            "Analysis",
            "Batch add",
        );
        assert_eq!(cmd.name(), "Add Warning Bookmark(s)");
        assert_eq!(cmd.target_addresses().len(), 3);
    }

    #[test]
    fn test_bookmark_edit_cmd_for_edit() {
        let cmd = BookmarkEditCmd::new_for_edit(
            42,
            "Note",
            "User",
            "Updated comment",
        );
        assert_eq!(cmd.name(), "Edit Note Bookmark");
    }

    #[test]
    fn test_bookmark_edit_cmd_apply() {
        let mut cmd = BookmarkEditCmd::new_for_address(0x1000, "Info", "Analysis", "test");
        assert!(!cmd.was_applied());
        assert!(cmd.apply());
        assert!(cmd.was_applied());
        assert!(cmd.status_msg().is_none());
    }

    #[test]
    fn test_bookmark_delete_cmd() {
        let mut cmd = BookmarkDeleteCmd::new(vec![1, 2, 3]);
        assert_eq!(cmd.bookmark_ids.len(), 3);
        assert!(!cmd.was_applied());
        assert!(cmd.apply());
        assert!(cmd.was_applied());
    }

    #[test]
    fn test_bookmark_delete_cmd_typed() {
        let cmd = BookmarkDeleteCmd::new_typed(vec![1], "Info");
        assert_eq!(cmd.type_filter, Some("Info".to_string()));
    }

    #[test]
    fn test_bookmark_row_object() {
        let row = BookmarkRowObject::new("Info", "Analysis", "test", 0x400000, 1);
        assert_eq!(row.get_type_string(), "Info");
        assert_eq!(row.get_category(), "Analysis");
        assert_eq!(row.get_address(), 0x400000);
    }

    #[test]
    fn test_bookmark_row_object_from_data() {
        use ghidra_core::Address;
        let bm = BookmarkData::new(
            Address::new(0x1000),
            BookmarkType::warning(),
            "careful",
            99,
        );
        let row = BookmarkRowObject::from_bookmark_data(&bm);
        assert_eq!(row.type_string, "Warning");
        assert_eq!(row.category, "Analysis");
        assert_eq!(row.comment, "careful");
        assert_eq!(row.address, 0x1000);
    }

    #[test]
    fn test_bookmark_table_model_basic() {
        let model = BookmarkTableModel::new();
        assert_eq!(model.column_count(), 4);
        assert_eq!(model.column_name(0), Some("Type"));
        assert_eq!(model.row_count(), 0);
    }

    #[test]
    fn test_bookmark_table_model_add_rows() {
        let mut model = BookmarkTableModel::new();
        model.add_row(BookmarkRowObject::new("Info", "Analysis", "a", 0x1000, 1));
        model.add_row(BookmarkRowObject::new("Warning", "Analysis", "b", 0x2000, 2));
        model.add_row(BookmarkRowObject::new("Note", "User", "c", 0x3000, 3));
        assert_eq!(model.row_count(), 3);
    }

    #[test]
    fn test_bookmark_table_model_filter_type() {
        let mut model = BookmarkTableModel::new();
        model.add_row(BookmarkRowObject::new("Info", "Analysis", "a", 0x1000, 1));
        model.add_row(BookmarkRowObject::new("Warning", "Analysis", "b", 0x2000, 2));
        model.add_row(BookmarkRowObject::new("Info", "User", "c", 0x3000, 3));

        model.set_filter_type(Some("Info".to_string()));
        assert_eq!(model.row_count(), 2);

        model.set_filter_type(Some("Warning".to_string()));
        assert_eq!(model.row_count(), 1);
    }

    #[test]
    fn test_bookmark_table_model_filter_category() {
        let mut model = BookmarkTableModel::new();
        model.add_row(BookmarkRowObject::new("Info", "Analysis", "a", 0x1000, 1));
        model.add_row(BookmarkRowObject::new("Info", "User", "b", 0x2000, 2));

        model.set_filter_category(Some("User".to_string()));
        assert_eq!(model.row_count(), 1);
    }

    #[test]
    fn test_bookmark_table_model_clear_filters() {
        let mut model = BookmarkTableModel::new();
        model.add_row(BookmarkRowObject::new("Info", "Analysis", "a", 0x1000, 1));
        model.set_filter_type(Some("Info".to_string()));
        assert_eq!(model.row_count(), 1);
        model.clear_filters();
        assert_eq!(model.row_count(), 1);
    }

    #[test]
    fn test_bookmark_table_model_remove() {
        let mut model = BookmarkTableModel::new();
        model.add_row(BookmarkRowObject::new("Info", "Analysis", "a", 0x1000, 1));
        model.add_row(BookmarkRowObject::new("Info", "Analysis", "b", 0x2000, 2));
        assert_eq!(model.row_count(), 2);

        let removed = model.remove_row(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().comment, "a");
        assert_eq!(model.row_count(), 1);
    }

    #[test]
    fn test_bookmark_table_model_get_cell_value() {
        let mut model = BookmarkTableModel::new();
        model.add_row(BookmarkRowObject::new("Info", "Analysis", "test", 0x400000, 1));

        assert_eq!(model.get_cell_value(0, 0), Some("Info".to_string()));
        assert_eq!(model.get_cell_value(0, 1), Some("Analysis".to_string()));
        assert_eq!(model.get_cell_value(0, 2), Some("0x400000".to_string()));
        assert_eq!(model.get_cell_value(0, 3), Some("test".to_string()));
        assert_eq!(model.get_cell_value(0, 4), None); // invalid column
        assert_eq!(model.get_cell_value(1, 0), None); // invalid row
    }

    #[test]
    fn test_address_table_row_mapper() {
        let row = BookmarkRowObject::new("Info", "Analysis", "test", 0x400000, 1);
        assert_eq!(BookmarkRowObjectToAddressTableRowMapper::map(&row), 0x400000);
    }

    #[test]
    fn test_program_location_table_row_mapper() {
        let row = BookmarkRowObject::new("Warning", "Analysis", "careful", 0x1000, 42);
        let loc = BookmarkRowObjectToProgramLocationTableRowMapper::map(&row);
        assert_eq!(loc.address, 0x1000);
        assert_eq!(loc.type_string, "Warning");
        assert_eq!(loc.bookmark_id, 42);
    }
}
