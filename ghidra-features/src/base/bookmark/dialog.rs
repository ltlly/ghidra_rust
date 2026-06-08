//! Bookmark dialog models for creating and filtering bookmarks.
//!
//! Ported from Ghidra's:
//! - `CreateBookmarkDialog` -- dialog for adding a Note bookmark at an address
//! - `FilterDialog` -- dialog for selecting which bookmark types to display
//!
//! These are data-model representations of the dialogs; actual GUI
//! rendering is handled by the host framework.

use std::collections::HashSet;

use ghidra_core::addr::Address;

use super::model::{Bookmark, BookmarkManager};
use super::types::BookmarkType;

// ---------------------------------------------------------------------------
// CreateBookmarkDialog -- data model for the "Add Bookmark" dialog
// ---------------------------------------------------------------------------

/// Data model for the create-bookmark dialog.
///
/// Corresponds to Ghidra's `CreateBookmarkDialog`. The dialog allows the
/// user to set a category and description for a Note bookmark at a given
/// address. It pre-populates from an existing bookmark at that address
/// (if any) or from the code unit's EOL comment.
///
/// # Lifecycle
///
/// 1. Create via [`CreateBookmarkDialog::new()`]
/// 2. Populate initial state via [`initialize()`](Self::initialize)
/// 3. The user modifies category/description fields
/// 4. On OK, call [`ok_callback()`](Self::ok_callback) to produce the
///    bookmark command data
#[derive(Debug, Clone)]
pub struct CreateBookmarkDialog {
    /// The address to bookmark.
    address: Address,
    /// Whether there is a current program selection.
    has_selection: bool,
    /// The current category text (editable).
    category: String,
    /// The current description text (editable).
    description: String,
    /// Available categories from the BookmarkManager (for combo box).
    available_categories: Vec<String>,
    /// Whether to apply to all selection ranges.
    apply_to_selection: bool,
    /// The number of address ranges in the selection.
    selection_range_count: usize,
    /// Pre-populated category from an existing bookmark at this address.
    existing_category: Option<String>,
    /// Pre-populated description from an existing bookmark at this address.
    existing_description: Option<String>,
    /// The address display string (e.g. "0x401000 (plus 2 more)").
    address_display: String,
}

impl CreateBookmarkDialog {
    /// Creates a new create-bookmark dialog for the given address.
    ///
    /// Corresponds to `CreateBookmarkDialog(BookmarkPlugin, CodeUnit, boolean)`.
    pub fn new(address: Address, has_selection: bool) -> Self {
        Self {
            address,
            has_selection,
            category: String::new(),
            description: String::new(),
            available_categories: Vec::new(),
            apply_to_selection: false,
            selection_range_count: 0,
            existing_category: None,
            existing_description: None,
            address_display: format!("0x{:X}", address.offset),
        }
    }

    /// Initializes the dialog from the BookmarkManager.
    ///
    /// Loads available categories and pre-populates fields from any
    /// existing Note bookmark at this address.
    ///
    /// Corresponds to the initialization logic in the Java constructor.
    pub fn initialize(&mut self, mgr: &BookmarkManager, eol_comment: Option<&str>) {
        // Load available categories for Note type.
        self.available_categories = self.load_categories(mgr);
        self.available_categories.sort();

        // Check for existing Note bookmark at this address.
        let existing = mgr.get_bookmarks_by_type(&self.address, BookmarkType::NOTE);
        if let Some(bm) = existing.first() {
            self.existing_category = Some(bm.category().to_string());
            self.existing_description = Some(bm.comment().to_string());
            self.category = bm.category().to_string();
            self.description = bm.comment().to_string();
        } else {
            // Use EOL comment as default description.
            let comment = eol_comment.unwrap_or("").replace('\n', " ");
            self.description = comment;
        }
    }

    /// Loads available categories for the Note bookmark type.
    fn load_categories(&self, mgr: &BookmarkManager) -> Vec<String> {
        // Collect unique categories from existing Note bookmarks.
        let mut categories: HashSet<String> = HashSet::new();
        categories.insert(String::new()); // empty category always available
        for bm in mgr.get_bookmarks_iterator(BookmarkType::NOTE) {
            let cat = bm.category().to_string();
            if !cat.is_empty() {
                categories.insert(cat);
            }
        }
        categories.into_iter().collect()
    }

    /// Sets the selection range count (for multi-selection mode).
    pub fn set_selection_range_count(&mut self, count: usize) {
        self.selection_range_count = count;
        if count <= 1 {
            self.apply_to_selection = false;
        }
    }

    /// Returns the address display string.
    pub fn address_display(&self) -> &str {
        &self.address_display
    }

    /// Returns the current category text.
    pub fn category(&self) -> &str {
        &self.category
    }

    /// Sets the category text.
    pub fn set_category(&mut self, category: impl Into<String>) {
        self.category = category.into();
    }

    /// Returns the current description text.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Sets the description text.
    pub fn set_description(&mut self, description: impl Into<String>) {
        self.description = description.into();
    }

    /// Returns the available categories.
    pub fn available_categories(&self) -> &[String] {
        &self.available_categories
    }

    /// Returns whether to apply to the selection.
    pub fn apply_to_selection(&self) -> bool {
        self.apply_to_selection
    }

    /// Sets whether to apply to the selection.
    pub fn set_apply_to_selection(&mut self, apply: bool) {
        if self.selection_range_count > 1 {
            self.apply_to_selection = apply;
        }
    }

    /// Returns whether the dialog has a selection with multiple ranges.
    pub fn has_multi_selection(&self) -> bool {
        self.has_selection && self.selection_range_count > 1
    }

    /// Returns the address to bookmark.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Returns whether there is an existing bookmark at this address.
    pub fn has_existing_bookmark(&self) -> bool {
        self.existing_category.is_some()
    }

    /// Executes the OK callback, returning the bookmark command data.
    ///
    /// Corresponds to `CreateBookmarkDialog.okCallback()`.
    pub fn ok_callback(&self) -> CreateBookmarkResult {
        CreateBookmarkResult {
            address: self.address,
            category: self.category.clone(),
            description: self.description.clone(),
            apply_to_selection: self.apply_to_selection && self.has_selection,
        }
    }
}

/// Result of the create-bookmark dialog.
///
/// Contains the data needed to execute a bookmark creation command.
#[derive(Debug, Clone)]
pub struct CreateBookmarkResult {
    /// The address to bookmark.
    pub address: Address,
    /// The bookmark category.
    pub category: String,
    /// The bookmark description.
    pub description: String,
    /// Whether to apply to all selection ranges.
    pub apply_to_selection: bool,
}

// ---------------------------------------------------------------------------
// FilterDialog -- data model for the bookmark type filter dialog
// ---------------------------------------------------------------------------

/// Data model for the bookmark type filter dialog.
///
/// Corresponds to Ghidra's `FilterDialog`. The dialog allows the user
/// to select which bookmark types are visible in the bookmarks panel.
///
/// # Lifecycle
///
/// 1. Create via [`FilterDialog::new()`]
/// 2. User toggles type checkboxes
/// 3. On OK, call [`ok_callback()`](Self::ok_callback) to get the list
///    of visible types
#[derive(Debug, Clone)]
pub struct FilterDialog {
    /// All known bookmark types with their current visibility state.
    type_entries: Vec<FilterTypeEntry>,
}

/// A single entry in the filter dialog's type list.
#[derive(Debug, Clone)]
pub struct FilterTypeEntry {
    /// The bookmark type string.
    pub type_string: String,
    /// Whether this type is currently selected (visible).
    pub selected: bool,
    /// The icon identifier for this type.
    pub icon_id: Option<String>,
}

impl FilterDialog {
    /// Creates a new filter dialog from the BookmarkManager and current visibility.
    ///
    /// Corresponds to `FilterDialog(BookmarkProvider, Program)`.
    pub fn new(mgr: &BookmarkManager, visible_types: &HashSet<String>) -> Self {
        let type_entries: Vec<FilterTypeEntry> = mgr
            .get_bookmark_types()
            .into_iter()
            .map(|bmt| {
                let ts = bmt.type_string().to_string();
                let selected = visible_types.is_empty() || visible_types.contains(&ts);
                FilterTypeEntry {
                    type_string: ts,
                    selected,
                    icon_id: bmt.icon_id().map(|s| s.to_string()),
                }
            })
            .collect();

        Self { type_entries }
    }

    /// Returns a reference to all type entries.
    pub fn type_entries(&self) -> &[FilterTypeEntry] {
        &self.type_entries
    }

    /// Returns the number of types.
    pub fn type_count(&self) -> usize {
        self.type_entries.len()
    }

    /// Toggles the selection state of a specific type.
    pub fn toggle_type(&mut self, type_string: &str) {
        if let Some(entry) = self
            .type_entries
            .iter_mut()
            .find(|e| e.type_string == type_string)
        {
            entry.selected = !entry.selected;
        }
    }

    /// Sets the selection state of a specific type.
    pub fn set_type_selected(&mut self, type_string: &str, selected: bool) {
        if let Some(entry) = self
            .type_entries
            .iter_mut()
            .find(|e| e.type_string == type_string)
        {
            entry.selected = selected;
        }
    }

    /// Returns true if the given type is selected.
    pub fn is_type_selected(&self, type_string: &str) -> bool {
        self.type_entries
            .iter()
            .find(|e| e.type_string == type_string)
            .map_or(false, |e| e.selected)
    }

    /// Selects all types.
    pub fn select_all(&mut self) {
        for entry in &mut self.type_entries {
            entry.selected = true;
        }
    }

    /// Deselects all types.
    pub fn deselect_all(&mut self) {
        for entry in &mut self.type_entries {
            entry.selected = false;
        }
    }

    /// Executes the OK callback, returning the list of selected type strings.
    ///
    /// Corresponds to `FilterDialog.okCallback()`.
    pub fn ok_callback(&self) -> Vec<String> {
        self.type_entries
            .iter()
            .filter(|e| e.selected)
            .map(|e| e.type_string.clone())
            .collect()
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

    fn make_mgr() -> BookmarkManager {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "Todo", "Fix this");
        mgr.set_bookmark(&addr(0x2000), "Warning", "", "Watch out");
        mgr.set_bookmark(&addr(0x3000), "Note", "Security", "Check auth");
        mgr.set_bookmark(&addr(0x4000), "Error", "Bug", "Crash");
        mgr
    }

    // ====================================================================
    // CreateBookmarkDialog
    // ====================================================================

    #[test]
    fn test_create_dialog_new() {
        let dialog = CreateBookmarkDialog::new(addr(0x1000), false);
        assert_eq!(dialog.address(), addr(0x1000));
        assert!(!dialog.has_selection);
        assert!(dialog.category().is_empty());
        assert!(dialog.description().is_empty());
    }

    #[test]
    fn test_create_dialog_initialize_existing() {
        let mgr = make_mgr();
        let mut dialog = CreateBookmarkDialog::new(addr(0x1000), false);
        dialog.initialize(&mgr, None);

        // Should pre-populate from the existing Note bookmark.
        assert_eq!(dialog.category(), "Todo");
        assert_eq!(dialog.description(), "Fix this");
        assert!(dialog.has_existing_bookmark());
    }

    #[test]
    fn test_create_dialog_initialize_no_existing() {
        let mgr = make_mgr();
        let mut dialog = CreateBookmarkDialog::new(addr(0x9000), false);
        dialog.initialize(&mgr, Some("EOL comment here"));

        assert!(!dialog.has_existing_bookmark());
        assert_eq!(dialog.description(), "EOL comment here");
    }

    #[test]
    fn test_create_dialog_initialize_eol_comment_newlines() {
        let mgr = make_mgr();
        let mut dialog = CreateBookmarkDialog::new(addr(0x9000), false);
        dialog.initialize(&mgr, Some("line1\nline2"));

        assert_eq!(dialog.description(), "line1 line2");
    }

    #[test]
    fn test_create_dialog_categories() {
        let mgr = make_mgr();
        let mut dialog = CreateBookmarkDialog::new(addr(0x1000), false);
        dialog.initialize(&mgr, None);

        // Should include empty, "Todo", "Security" categories.
        let cats = dialog.available_categories();
        assert!(cats.contains(&String::new()));
        assert!(cats.iter().any(|c| c == "Todo"));
        assert!(cats.iter().any(|c| c == "Security"));
    }

    #[test]
    fn test_create_dialog_set_fields() {
        let mut dialog = CreateBookmarkDialog::new(addr(0x1000), false);
        dialog.set_category("NewCat");
        dialog.set_description("NewDesc");
        assert_eq!(dialog.category(), "NewCat");
        assert_eq!(dialog.description(), "NewDesc");
    }

    #[test]
    fn test_create_dialog_selection() {
        let mut dialog = CreateBookmarkDialog::new(addr(0x1000), true);
        dialog.set_selection_range_count(5);
        assert!(dialog.has_multi_selection());
        dialog.set_apply_to_selection(true);
        assert!(dialog.apply_to_selection());
    }

    #[test]
    fn test_create_dialog_single_range_no_selection() {
        let mut dialog = CreateBookmarkDialog::new(addr(0x1000), true);
        dialog.set_selection_range_count(1);
        assert!(!dialog.has_multi_selection());
        dialog.set_apply_to_selection(true);
        assert!(!dialog.apply_to_selection()); // Can't apply to selection with <=1 range
    }

    #[test]
    fn test_create_dialog_ok_callback() {
        let mut dialog = CreateBookmarkDialog::new(addr(0x1000), false);
        dialog.set_category("Cat");
        dialog.set_description("Desc");
        let result = dialog.ok_callback();
        assert_eq!(result.address, addr(0x1000));
        assert_eq!(result.category, "Cat");
        assert_eq!(result.description, "Desc");
        assert!(!result.apply_to_selection);
    }

    #[test]
    fn test_create_dialog_address_display() {
        let dialog = CreateBookmarkDialog::new(addr(0x401000), false);
        assert_eq!(dialog.address_display(), "0x401000");
    }

    // ====================================================================
    // FilterDialog
    // ====================================================================

    #[test]
    fn test_filter_dialog_new() {
        let mgr = make_mgr();
        let visible: HashSet<String> = HashSet::new(); // empty = show all
        let dialog = FilterDialog::new(&mgr, &visible);

        // Should have entries for all registered types.
        assert!(dialog.type_count() >= 5); // Note, Info, Warning, Error, Analysis
    }

    #[test]
    fn test_filter_dialog_all_selected_by_default() {
        let mgr = make_mgr();
        let visible: HashSet<String> = HashSet::new();
        let dialog = FilterDialog::new(&mgr, &visible);

        // All should be selected when visible set is empty.
        for entry in dialog.type_entries() {
            assert!(entry.selected, "{} should be selected", entry.type_string);
        }
    }

    #[test]
    fn test_filter_dialog_subset_selected() {
        let mgr = make_mgr();
        let mut visible = HashSet::new();
        visible.insert("Note".to_string());
        visible.insert("Warning".to_string());
        let dialog = FilterDialog::new(&mgr, &visible);

        assert!(dialog.is_type_selected("Note"));
        assert!(dialog.is_type_selected("Warning"));
        assert!(!dialog.is_type_selected("Error"));
    }

    #[test]
    fn test_filter_dialog_toggle_type() {
        let mgr = make_mgr();
        let visible: HashSet<String> = HashSet::new();
        let mut dialog = FilterDialog::new(&mgr, &visible);

        assert!(dialog.is_type_selected("Note"));
        dialog.toggle_type("Note");
        assert!(!dialog.is_type_selected("Note"));
        dialog.toggle_type("Note");
        assert!(dialog.is_type_selected("Note"));
    }

    #[test]
    fn test_filter_dialog_set_type_selected() {
        let mgr = make_mgr();
        let visible: HashSet<String> = HashSet::new();
        let mut dialog = FilterDialog::new(&mgr, &visible);

        dialog.set_type_selected("Note", false);
        assert!(!dialog.is_type_selected("Note"));
        dialog.set_type_selected("Note", true);
        assert!(dialog.is_type_selected("Note"));
    }

    #[test]
    fn test_filter_dialog_select_all() {
        let mgr = make_mgr();
        let mut visible = HashSet::new();
        visible.insert("Note".to_string());
        let mut dialog = FilterDialog::new(&mgr, &visible);

        dialog.select_all();
        for entry in dialog.type_entries() {
            assert!(entry.selected);
        }
    }

    #[test]
    fn test_filter_dialog_deselect_all() {
        let mgr = make_mgr();
        let visible: HashSet<String> = HashSet::new();
        let mut dialog = FilterDialog::new(&mgr, &visible);

        dialog.deselect_all();
        for entry in dialog.type_entries() {
            assert!(!entry.selected);
        }
    }

    #[test]
    fn test_filter_dialog_ok_callback() {
        let mgr = make_mgr();
        let mut visible = HashSet::new();
        visible.insert("Note".to_string());
        visible.insert("Warning".to_string());
        let dialog = FilterDialog::new(&mgr, &visible);

        let selected = dialog.ok_callback();
        assert!(selected.contains(&"Note".to_string()));
        assert!(selected.contains(&"Warning".to_string()));
        assert!(!selected.contains(&"Error".to_string()));
    }

    #[test]
    fn test_filter_dialog_ok_callback_after_toggle() {
        let mgr = make_mgr();
        let visible: HashSet<String> = HashSet::new();
        let mut dialog = FilterDialog::new(&mgr, &visible);

        dialog.toggle_type("Note"); // deselect
        let selected = dialog.ok_callback();
        assert!(!selected.contains(&"Note".to_string()));
    }

    #[test]
    fn test_filter_dialog_type_entries_have_icon() {
        let mgr = make_mgr();
        let visible: HashSet<String> = HashSet::new();
        let dialog = FilterDialog::new(&mgr, &visible);

        // Built-in types should have icons.
        let note_entry = dialog
            .type_entries()
            .iter()
            .find(|e| e.type_string == "Note")
            .unwrap();
        assert!(note_entry.icon_id.is_some());
    }

    // ====================================================================
    // CreateBookmarkResult
    // ====================================================================

    #[test]
    fn test_create_result_clone() {
        let result = CreateBookmarkResult {
            address: addr(0x1000),
            category: "Cat".to_string(),
            description: "Desc".to_string(),
            apply_to_selection: false,
        };
        let cloned = result.clone();
        assert_eq!(result.address, cloned.address);
        assert_eq!(result.category, cloned.category);
    }
}
