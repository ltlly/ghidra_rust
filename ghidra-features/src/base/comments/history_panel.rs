//! Comment history panel model and location-based popup resolution.
//!
//! Ported from Ghidra's `CommentHistoryPanel` and `CommentHistoryDialog`,
//! plus the popup path resolution logic from `CommentsPlugin`.
//!
//! Provides:
//! - [`CommentHistoryPanelModel`] -- data model for the comment history dialog
//! - [`CommentLocationType`] -- classifies what kind of comment location
//!   the cursor is on
//! - `resolve_popup_path` -- maps a location to a popup menu path

use ghidra_core::addr::Address;
use ghidra_core::program::listing::CommentType;
use std::fmt;

// ---------------------------------------------------------------------------
// CommentLocationType -- classifies cursor position for popup resolution
// ---------------------------------------------------------------------------

/// Describes the type of comment field the cursor is on.
///
/// Used by `resolve_popup_path()` to determine the correct popup menu text.
/// Corresponds to the Java `instanceof` checks in
/// `CommentsPlugin.updatePopupPath()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentLocationType {
    /// Cursor is on an EOL comment field.
    EolComment,
    /// Cursor is on a pre-comment field.
    PreComment,
    /// Cursor is on a post-comment field.
    PostComment,
    /// Cursor is on a plate comment field.
    PlateComment,
    /// Cursor is on a repeatable comment field (function level).
    RepeatableComment,
    /// Cursor is not on any comment field.
    None,
}

impl CommentLocationType {
    /// Returns the corresponding `CommentType`, if applicable.
    pub fn to_comment_type(self) -> Option<CommentType> {
        match self {
            CommentLocationType::EolComment => Some(CommentType::Eol),
            CommentLocationType::PreComment => Some(CommentType::Pre),
            CommentLocationType::PostComment => Some(CommentType::Post),
            CommentLocationType::PlateComment => Some(CommentType::Plate),
            CommentLocationType::RepeatableComment => Some(CommentType::Repeatable),
            CommentLocationType::None => None,
        }
    }

    /// Returns the human-readable suffix for popup menus.
    ///
    /// E.g., "EOL Comment", "Pre-Comment", "Plate Comment".
    pub fn display_suffix(self) -> &'static str {
        match self {
            CommentLocationType::EolComment => "EOL Comment",
            CommentLocationType::PreComment => "Pre-Comment",
            CommentLocationType::PostComment => "Post-Comment",
            CommentLocationType::PlateComment => "Plate Comment",
            CommentLocationType::RepeatableComment => "Repeatable Comment",
            CommentLocationType::None => "",
        }
    }

    /// Returns true if this is a recognized comment location.
    pub fn is_comment_location(self) -> bool {
        self != CommentLocationType::None
    }
}

impl fmt::Display for CommentLocationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_suffix())
    }
}

// ---------------------------------------------------------------------------
// Popup path resolution
// ---------------------------------------------------------------------------

/// Resolves the popup menu path for a comment action.
///
/// This is the Rust equivalent of `CommentsPlugin.updatePopupPath()`.
///
/// Parameters:
/// - `action_verb`: The action name prefix (e.g., "Set", "Delete", "Show History for")
/// - `location_type`: The type of comment field under the cursor
/// - `append_ellipsis`: Whether to append "..." to the suffix (for history dialogs)
///
/// Returns the full popup menu path as a vector of strings, e.g.
/// `["Comments", "Set EOL Comment"]`.
pub fn resolve_popup_path(
    action_verb: &str,
    location_type: CommentLocationType,
    append_ellipsis: bool,
) -> Vec<String> {
    let suffix = match location_type {
        CommentLocationType::None => return vec!["Comments".to_string(), action_verb.to_string()],
        _ => location_type.display_suffix(),
    };

    let mut end = String::new();
    if append_ellipsis {
        end.push_str("...");
    }

    vec![
        "Comments".to_string(),
        format!("{} {}{}", action_verb, suffix, end),
    ]
}

/// Resolves the popup menu path for the "Delete" action at a given location.
///
/// Convenience wrapper around `resolve_popup_path`.
pub fn delete_popup_path(location_type: CommentLocationType) -> Vec<String> {
    resolve_popup_path("Delete", location_type, false)
}

/// Resolves the popup menu path for the "Show History" action at a given location.
///
/// Convenience wrapper around `resolve_popup_path`.
pub fn history_popup_path(location_type: CommentLocationType) -> Vec<String> {
    resolve_popup_path("Show History for", location_type, true)
}

// ---------------------------------------------------------------------------
// CommentHistoryPanelModel -- data model for the history display dialog
// ---------------------------------------------------------------------------

/// A single entry in the comment history panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentHistoryPanelEntry {
    /// The address of the comment.
    pub address: Address,
    /// The type of comment.
    pub comment_type: CommentType,
    /// The user who made the change.
    pub user: String,
    /// The timestamp of the change.
    pub timestamp: String,
    /// The comment text after the change.
    pub text: String,
}

impl CommentHistoryPanelEntry {
    /// Creates a new panel entry.
    pub fn new(
        address: Address,
        comment_type: CommentType,
        user: impl Into<String>,
        timestamp: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        Self {
            address,
            comment_type,
            user: user.into(),
            timestamp: timestamp.into(),
            text: text.into(),
        }
    }
}

/// Column identifiers for the comment history panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentHistoryColumn {
    /// Address column.
    Address,
    /// Comment type column.
    CommentType,
    /// User column.
    User,
    /// Timestamp column.
    Timestamp,
    /// Comment text column.
    Text,
}

impl CommentHistoryColumn {
    /// All columns in display order.
    pub const ALL: [CommentHistoryColumn; 5] = [
        CommentHistoryColumn::Address,
        CommentHistoryColumn::CommentType,
        CommentHistoryColumn::User,
        CommentHistoryColumn::Timestamp,
        CommentHistoryColumn::Text,
    ];

    /// Returns the column header name.
    pub fn display_name(self) -> &'static str {
        match self {
            CommentHistoryColumn::Address => "Address",
            CommentHistoryColumn::CommentType => "Type",
            CommentHistoryColumn::User => "User",
            CommentHistoryColumn::Timestamp => "Date",
            CommentHistoryColumn::Text => "Comment",
        }
    }
}

/// Data model for the comment history dialog.
///
/// Corresponds to Ghidra's `CommentHistoryPanel`, which displays
/// the change history of comments at an address.
#[derive(Debug)]
pub struct CommentHistoryPanelModel {
    /// The entries to display.
    entries: Vec<CommentHistoryPanelEntry>,
    /// Whether to show the address column (only when showing all history).
    show_address: bool,
    /// Whether to show the comment type column.
    show_type: bool,
}

impl CommentHistoryPanelModel {
    /// Creates a new empty model.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            show_address: false,
            show_type: false,
        }
    }

    /// Creates a model for history at a single address (no address column).
    pub fn for_address(entries: Vec<CommentHistoryPanelEntry>) -> Self {
        Self {
            entries,
            show_address: false,
            show_type: false,
        }
    }

    /// Creates a model for all history across the program (with address column).
    pub fn for_all(entries: Vec<CommentHistoryPanelEntry>) -> Self {
        Self {
            entries,
            show_address: true,
            show_type: true,
        }
    }

    /// Returns the number of rows.
    pub fn row_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns the number of visible columns.
    pub fn column_count(&self) -> usize {
        let mut count = 2; // User + Timestamp are always shown
        if self.show_address {
            count += 1;
        }
        if self.show_type {
            count += 1;
        }
        count += 1; // Text is always shown
        count
    }

    /// Returns the column header name for the given visible column index.
    pub fn column_name(&self, col: usize) -> Option<&'static str> {
        let cols = self.visible_columns();
        cols.get(col).map(|c| c.display_name())
    }

    /// Returns the list of visible columns.
    pub fn visible_columns(&self) -> Vec<CommentHistoryColumn> {
        let mut cols = Vec::new();
        if self.show_address {
            cols.push(CommentHistoryColumn::Address);
        }
        if self.show_type {
            cols.push(CommentHistoryColumn::CommentType);
        }
        cols.push(CommentHistoryColumn::User);
        cols.push(CommentHistoryColumn::Timestamp);
        cols.push(CommentHistoryColumn::Text);
        cols
    }

    /// Returns the cell value at (row, visible_column).
    pub fn get_value(&self, row: usize, col: usize) -> Option<String> {
        let entry = self.entries.get(row)?;
        let cols = self.visible_columns();
        let column = cols.get(col)?;

        Some(match column {
            CommentHistoryColumn::Address => format!("0x{:X}", entry.address.offset),
            CommentHistoryColumn::CommentType => format!("{}", entry.comment_type),
            CommentHistoryColumn::User => entry.user.clone(),
            CommentHistoryColumn::Timestamp => entry.timestamp.clone(),
            CommentHistoryColumn::Text => entry.text.clone(),
        })
    }

    /// Returns a reference to the entry at the given row.
    pub fn get_entry(&self, row: usize) -> Option<&CommentHistoryPanelEntry> {
        self.entries.get(row)
    }

    /// Returns true if the model is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Adds an entry.
    pub fn add_entry(&mut self, entry: CommentHistoryPanelEntry) {
        self.entries.push(entry);
    }

    /// Clears all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Returns all entries.
    pub fn entries(&self) -> &[CommentHistoryPanelEntry] {
        &self.entries
    }
}

impl Default for CommentHistoryPanelModel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    // ====================================================================
    // CommentLocationType
    // ====================================================================

    #[test]
    fn test_location_type_to_comment_type() {
        assert_eq!(
            CommentLocationType::EolComment.to_comment_type(),
            Some(CommentType::Eol)
        );
        assert_eq!(
            CommentLocationType::PlateComment.to_comment_type(),
            Some(CommentType::Plate)
        );
        assert_eq!(CommentLocationType::None.to_comment_type(), None);
    }

    #[test]
    fn test_location_type_display_suffix() {
        assert_eq!(CommentLocationType::EolComment.display_suffix(), "EOL Comment");
        assert_eq!(
            CommentLocationType::PreComment.display_suffix(),
            "Pre-Comment"
        );
        assert_eq!(
            CommentLocationType::PostComment.display_suffix(),
            "Post-Comment"
        );
        assert_eq!(
            CommentLocationType::PlateComment.display_suffix(),
            "Plate Comment"
        );
        assert_eq!(
            CommentLocationType::RepeatableComment.display_suffix(),
            "Repeatable Comment"
        );
        assert_eq!(CommentLocationType::None.display_suffix(), "");
    }

    #[test]
    fn test_location_type_is_comment_location() {
        assert!(CommentLocationType::EolComment.is_comment_location());
        assert!(!CommentLocationType::None.is_comment_location());
    }

    // ====================================================================
    // resolve_popup_path
    // ====================================================================

    #[test]
    fn test_resolve_popup_path_eol() {
        let path = resolve_popup_path("Set", CommentLocationType::EolComment, false);
        assert_eq!(path, vec!["Comments", "Set EOL Comment"]);
    }

    #[test]
    fn test_resolve_popup_path_with_ellipsis() {
        let path = resolve_popup_path("Delete", CommentLocationType::PreComment, true);
        assert_eq!(path, vec!["Comments", "Delete Pre-Comment..."]);
    }

    #[test]
    fn test_resolve_popup_path_none_location() {
        let path = resolve_popup_path("Set...", CommentLocationType::None, false);
        assert_eq!(path, vec!["Comments", "Set..."]);
    }

    #[test]
    fn test_delete_popup_path() {
        let path = delete_popup_path(CommentLocationType::PlateComment);
        assert_eq!(path, vec!["Comments", "Delete Plate Comment"]);
    }

    #[test]
    fn test_history_popup_path() {
        let path = history_popup_path(CommentLocationType::RepeatableComment);
        assert_eq!(
            path,
            vec!["Comments", "Show History for Repeatable Comment..."]
        );
    }

    #[test]
    fn test_resolve_popup_path_all_types() {
        for loc_type in [
            CommentLocationType::EolComment,
            CommentLocationType::PreComment,
            CommentLocationType::PostComment,
            CommentLocationType::PlateComment,
            CommentLocationType::RepeatableComment,
        ] {
            let path = resolve_popup_path("Set", loc_type, false);
            assert_eq!(path.len(), 2);
            assert_eq!(path[0], "Comments");
            assert!(path[1].starts_with("Set "));
        }
    }

    // ====================================================================
    // CommentHistoryPanelModel
    // ====================================================================

    fn sample_entries() -> Vec<CommentHistoryPanelEntry> {
        vec![
            CommentHistoryPanelEntry::new(
                addr(0x1000),
                CommentType::Eol,
                "user1",
                "2024-01-01",
                "first comment",
            ),
            CommentHistoryPanelEntry::new(
                addr(0x1000),
                CommentType::Eol,
                "user1",
                "2024-01-02",
                "updated comment",
            ),
            CommentHistoryPanelEntry::new(
                addr(0x2000),
                CommentType::Plate,
                "user2",
                "2024-01-03",
                "Main function",
            ),
        ]
    }

    #[test]
    fn test_panel_model_new_empty() {
        let model = CommentHistoryPanelModel::new();
        assert_eq!(model.row_count(), 0);
        assert!(model.is_empty());
    }

    #[test]
    fn test_panel_model_for_address() {
        let model = CommentHistoryPanelModel::for_address(sample_entries());
        assert_eq!(model.row_count(), 3);
        // No address column, no type column = User, Timestamp, Text = 3
        assert_eq!(model.column_count(), 3);
        assert_eq!(model.column_name(0), Some("User"));
        assert_eq!(model.column_name(1), Some("Date"));
        assert_eq!(model.column_name(2), Some("Comment"));
    }

    #[test]
    fn test_panel_model_for_all() {
        let model = CommentHistoryPanelModel::for_all(sample_entries());
        assert_eq!(model.row_count(), 3);
        // Address, Type, User, Timestamp, Text = 5
        assert_eq!(model.column_count(), 5);
        assert_eq!(model.column_name(0), Some("Address"));
        assert_eq!(model.column_name(1), Some("Type"));
    }

    #[test]
    fn test_panel_model_get_value_single_address() {
        let model = CommentHistoryPanelModel::for_address(sample_entries());
        assert_eq!(model.get_value(0, 0), Some("user1".to_string()));
        assert_eq!(model.get_value(0, 1), Some("2024-01-01".to_string()));
        assert_eq!(model.get_value(0, 2), Some("first comment".to_string()));
    }

    #[test]
    fn test_panel_model_get_value_all() {
        let model = CommentHistoryPanelModel::for_all(sample_entries());
        assert_eq!(model.get_value(0, 0), Some("0x1000".to_string()));
        assert_eq!(model.get_value(0, 1), Some("EOL".to_string()));
        assert_eq!(model.get_value(0, 2), Some("user1".to_string()));
        assert_eq!(model.get_value(0, 3), Some("2024-01-01".to_string()));
        assert_eq!(model.get_value(0, 4), Some("first comment".to_string()));
    }

    #[test]
    fn test_panel_model_get_value_out_of_bounds() {
        let model = CommentHistoryPanelModel::for_address(sample_entries());
        assert!(model.get_value(99, 0).is_none());
        assert!(model.get_value(0, 99).is_none());
    }

    #[test]
    fn test_panel_model_get_entry() {
        let model = CommentHistoryPanelModel::for_address(sample_entries());
        let entry = model.get_entry(0).unwrap();
        assert_eq!(entry.user, "user1");
        assert_eq!(entry.text, "first comment");
        assert!(model.get_entry(99).is_none());
    }

    #[test]
    fn test_panel_model_add_and_clear() {
        let mut model = CommentHistoryPanelModel::new();
        model.add_entry(CommentHistoryPanelEntry::new(
            addr(0x1000),
            CommentType::Eol,
            "user",
            "now",
            "text",
        ));
        assert_eq!(model.row_count(), 1);
        model.clear();
        assert!(model.is_empty());
    }

    #[test]
    fn test_panel_entry_new() {
        let entry = CommentHistoryPanelEntry::new(
            addr(0x4000),
            CommentType::Pre,
            "analyst",
            "2024-06-01T12:00:00Z",
            "setup code",
        );
        assert_eq!(entry.address, addr(0x4000));
        assert_eq!(entry.comment_type, CommentType::Pre);
        assert_eq!(entry.user, "analyst");
        assert_eq!(entry.text, "setup code");
    }

    #[test]
    fn test_visible_columns_for_address() {
        let model = CommentHistoryPanelModel::for_address(vec![]);
        let cols = model.visible_columns();
        assert_eq!(cols.len(), 3);
        assert_eq!(cols[0], CommentHistoryColumn::User);
        assert_eq!(cols[1], CommentHistoryColumn::Timestamp);
        assert_eq!(cols[2], CommentHistoryColumn::Text);
    }

    #[test]
    fn test_visible_columns_for_all() {
        let model = CommentHistoryPanelModel::for_all(vec![]);
        let cols = model.visible_columns();
        assert_eq!(cols.len(), 5);
        assert_eq!(cols[0], CommentHistoryColumn::Address);
    }

    #[test]
    fn test_comment_history_column_display() {
        assert_eq!(CommentHistoryColumn::Address.display_name(), "Address");
        assert_eq!(CommentHistoryColumn::CommentType.display_name(), "Type");
        assert_eq!(CommentHistoryColumn::User.display_name(), "User");
        assert_eq!(CommentHistoryColumn::Timestamp.display_name(), "Date");
        assert_eq!(CommentHistoryColumn::Text.display_name(), "Comment");
    }
}
