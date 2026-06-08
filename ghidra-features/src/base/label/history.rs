//! Label history types and table model.
//!
//! Ported from Ghidra's `LabelHistoryTableModel` and related types.
//! Label history records track every change made to labels at addresses
//! (additions, removals, and renames).

use std::fmt;

use ghidra_core::addr::Address;
use ghidra_core::symbol::LabelHistory;

// ---------------------------------------------------------------------------
// LabelHistoryAction
// ---------------------------------------------------------------------------

/// The kind of label history action.
///
/// Corresponds to Ghidra's label history action IDs used in `LabelHistory`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LabelHistoryAction {
    /// A label was added at an address.
    Add = 0,
    /// A label was removed from an address.
    Remove = 1,
    /// A label was renamed at an address.
    Rename = 2,
}

impl LabelHistoryAction {
    /// All action types.
    pub const ALL: [LabelHistoryAction; 3] = [
        LabelHistoryAction::Add,
        LabelHistoryAction::Remove,
        LabelHistoryAction::Rename,
    ];

    /// Returns the human-readable display name.
    pub fn display_name(self) -> &'static str {
        match self {
            LabelHistoryAction::Add => "Add",
            LabelHistoryAction::Remove => "Remove",
            LabelHistoryAction::Rename => "Rename",
        }
    }

    /// Returns the action from an integer ID.
    pub fn from_id(id: usize) -> Option<Self> {
        match id {
            0 => Some(LabelHistoryAction::Add),
            1 => Some(LabelHistoryAction::Remove),
            2 => Some(LabelHistoryAction::Rename),
            _ => None,
        }
    }
}

impl fmt::Display for LabelHistoryAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// LabelHistoryEntry
// ---------------------------------------------------------------------------

/// A single label history entry for table display.
///
/// This is the Rust equivalent of what Ghidra's `LabelHistoryTableModel`
/// displays, containing the address, action, label, user, and date.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelHistoryEntry {
    /// The address where the label change occurred.
    pub address: Address,
    /// The kind of action (Add/Remove/Rename).
    pub action: LabelHistoryAction,
    /// The label name involved in the change.
    pub label: String,
    /// The user who made the change.
    pub user: String,
    /// The modification timestamp (ISO 8601 or similar string).
    pub date: String,
}

impl LabelHistoryEntry {
    /// Creates a new label history entry.
    pub fn new(
        address: Address,
        action: LabelHistoryAction,
        label: impl Into<String>,
        user: impl Into<String>,
        date: impl Into<String>,
    ) -> Self {
        Self {
            address,
            action,
            label: label.into(),
            user: user.into(),
            date: date.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// LabelHistoryColumn
// ---------------------------------------------------------------------------

/// Column identifiers for the label history table.
///
/// Corresponds to the column indices in Ghidra's `LabelHistoryTableModel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LabelHistoryColumn {
    /// The address where the change occurred.
    Address = 0,
    /// The action type (Add/Remove/Rename).
    Action = 1,
    /// The label name.
    Label = 2,
    /// The user who made the change.
    User = 3,
    /// The modification date.
    ModificationDate = 4,
}

impl LabelHistoryColumn {
    /// All columns in order.
    pub const ALL: [LabelHistoryColumn; 5] = [
        LabelHistoryColumn::Address,
        LabelHistoryColumn::Action,
        LabelHistoryColumn::Label,
        LabelHistoryColumn::User,
        LabelHistoryColumn::ModificationDate,
    ];

    /// Returns the column header display name.
    pub fn display_name(self) -> &'static str {
        match self {
            LabelHistoryColumn::Address => "Address",
            LabelHistoryColumn::Action => "Action",
            LabelHistoryColumn::Label => "Label",
            LabelHistoryColumn::User => "User",
            LabelHistoryColumn::ModificationDate => "Modification Date",
        }
    }

    /// Returns the column index.
    pub fn index(self) -> usize {
        self as usize
    }
}

// ---------------------------------------------------------------------------
// LabelHistoryTableModel
// ---------------------------------------------------------------------------

/// Table model for label history display.
///
/// Corresponds to Ghidra's `LabelHistoryTableModel` which supports two modes:
/// - **With address column**: shows all label history across the program
/// - **Without address column**: shows history for a single address
pub struct LabelHistoryTableModel {
    /// The history entries.
    entries: Vec<LabelHistoryEntry>,
    /// Whether to show the address column.
    show_address: bool,
}

impl LabelHistoryTableModel {
    /// Creates a new model with the given entries.
    ///
    /// If `show_address` is true, the Address column is included.
    pub fn new(entries: Vec<LabelHistoryEntry>, show_address: bool) -> Self {
        Self {
            entries,
            show_address,
        }
    }

    /// Creates a model from Ghidra `LabelHistory` records.
    pub fn from_label_histories(histories: &[LabelHistory], show_address: bool) -> Self {
        let entries = histories
            .iter()
            .map(|h| LabelHistoryEntry {
                address: h.address.clone(),
                action: LabelHistoryAction::Add, // Default; actual action depends on context.
                label: h.label.clone(),
                user: String::new(), // Would be populated from full LabelHistory.
                date: h.timestamp.clone(),
            })
            .collect();

        Self {
            entries,
            show_address,
        }
    }

    /// Returns the number of rows.
    pub fn row_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns the number of visible columns.
    pub fn column_count(&self) -> usize {
        if self.show_address {
            5
        } else {
            4
        }
    }

    /// Returns the column header name for the given column index.
    pub fn column_name(&self, col: usize) -> Option<&'static str> {
        let columns = self.visible_columns();
        columns.get(col).map(|c| c.display_name())
    }

    /// Returns the list of visible columns.
    pub fn visible_columns(&self) -> Vec<LabelHistoryColumn> {
        if self.show_address {
            LabelHistoryColumn::ALL.to_vec()
        } else {
            vec![
                LabelHistoryColumn::Action,
                LabelHistoryColumn::Label,
                LabelHistoryColumn::User,
                LabelHistoryColumn::ModificationDate,
            ]
        }
    }

    /// Returns the entry at the given row index.
    pub fn get_entry(&self, row: usize) -> Option<&LabelHistoryEntry> {
        self.entries.get(row)
    }

    /// Returns the value for a specific cell (row, col).
    pub fn get_value(&self, row: usize, col: usize) -> Option<String> {
        let entry = self.entries.get(row)?;
        let columns = self.visible_columns();
        let column = columns.get(col)?;

        Some(match column {
            LabelHistoryColumn::Address => format!("0x{:X}", entry.address.offset),
            LabelHistoryColumn::Action => entry.action.display_name().to_string(),
            LabelHistoryColumn::Label => entry.label.clone(),
            LabelHistoryColumn::User => entry.user.clone(),
            LabelHistoryColumn::ModificationDate => entry.date.clone(),
        })
    }

    /// Returns the default sort column index.
    pub fn default_sort_column(&self) -> usize {
        if self.show_address {
            LabelHistoryColumn::Address.index()
        } else {
            // Sort by date (last column) when address is hidden.
            self.column_count() - 1
        }
    }

    /// Returns the label column index.
    pub fn label_column_index(&self) -> usize {
        // Label is always 2 columns from the end.
        self.column_count() - 3
    }

    /// Returns all entries.
    pub fn entries(&self) -> &[LabelHistoryEntry] {
        &self.entries
    }

    /// Returns whether the address column is shown.
    pub fn shows_address(&self) -> bool {
        self.show_address
    }
}

// ---------------------------------------------------------------------------
// LabelHistoryListener
// ---------------------------------------------------------------------------

/// Trait for components that want to be notified when a label history
/// entry is selected (for address navigation).
///
/// Corresponds to Ghidra's `LabelHistoryListener` interface.
pub trait LabelHistoryListener: fmt::Debug {
    /// Called when the user selects a label history entry.
    fn address_selected(&self, address: &Address);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn sample_entries() -> Vec<LabelHistoryEntry> {
        vec![
            LabelHistoryEntry::new(
                addr(0x1000),
                LabelHistoryAction::Add,
                "main",
                "user1",
                "2024-01-01",
            ),
            LabelHistoryEntry::new(
                addr(0x1000),
                LabelHistoryAction::Rename,
                "main_old",
                "user1",
                "2024-01-02",
            ),
            LabelHistoryEntry::new(
                addr(0x2000),
                LabelHistoryAction::Add,
                "helper",
                "user2",
                "2024-01-03",
            ),
            LabelHistoryEntry::new(
                addr(0x2000),
                LabelHistoryAction::Remove,
                "helper",
                "user2",
                "2024-01-04",
            ),
        ]
    }

    #[test]
    fn test_action_display() {
        assert_eq!(LabelHistoryAction::Add.display_name(), "Add");
        assert_eq!(LabelHistoryAction::Remove.display_name(), "Remove");
        assert_eq!(LabelHistoryAction::Rename.display_name(), "Rename");
    }

    #[test]
    fn test_action_from_id() {
        assert_eq!(
            LabelHistoryAction::from_id(0),
            Some(LabelHistoryAction::Add)
        );
        assert_eq!(
            LabelHistoryAction::from_id(1),
            Some(LabelHistoryAction::Remove)
        );
        assert_eq!(
            LabelHistoryAction::from_id(2),
            Some(LabelHistoryAction::Rename)
        );
        assert_eq!(LabelHistoryAction::from_id(99), None);
    }

    #[test]
    fn test_table_model_with_address() {
        let model = LabelHistoryTableModel::new(sample_entries(), true);
        assert_eq!(model.row_count(), 4);
        assert_eq!(model.column_count(), 5);
        assert_eq!(model.column_name(0), Some("Address"));
        assert_eq!(model.column_name(1), Some("Action"));
        assert_eq!(model.column_name(2), Some("Label"));
    }

    #[test]
    fn test_table_model_without_address() {
        let model = LabelHistoryTableModel::new(sample_entries(), false);
        assert_eq!(model.row_count(), 4);
        assert_eq!(model.column_count(), 4);
        assert_eq!(model.column_name(0), Some("Action"));
        assert_eq!(model.column_name(1), Some("Label"));
    }

    #[test]
    fn test_table_model_get_value() {
        let model = LabelHistoryTableModel::new(sample_entries(), true);
        assert_eq!(model.get_value(0, 0), Some("0x1000".to_string()));
        assert_eq!(model.get_value(0, 1), Some("Add".to_string()));
        assert_eq!(model.get_value(0, 2), Some("main".to_string()));
        assert_eq!(model.get_value(0, 3), Some("user1".to_string()));
        assert_eq!(model.get_value(0, 4), Some("2024-01-01".to_string()));
    }

    #[test]
    fn test_table_model_get_value_no_address() {
        let model = LabelHistoryTableModel::new(sample_entries(), false);
        // First column is Action when address is hidden.
        assert_eq!(model.get_value(0, 0), Some("Add".to_string()));
        assert_eq!(model.get_value(0, 1), Some("main".to_string()));
    }

    #[test]
    fn test_table_model_default_sort_column() {
        let model_with = LabelHistoryTableModel::new(sample_entries(), true);
        assert_eq!(model_with.default_sort_column(), 0); // Address

        let model_without = LabelHistoryTableModel::new(sample_entries(), false);
        assert_eq!(model_without.default_sort_column(), 3); // Date (last)
    }

    #[test]
    fn test_table_model_label_column_index() {
        let model_with = LabelHistoryTableModel::new(sample_entries(), true);
        assert_eq!(model_with.label_column_index(), 2);

        let model_without = LabelHistoryTableModel::new(sample_entries(), false);
        assert_eq!(model_without.label_column_index(), 1);
    }

    #[test]
    fn test_table_model_out_of_bounds() {
        let model = LabelHistoryTableModel::new(sample_entries(), true);
        assert!(model.get_entry(99).is_none());
        assert!(model.get_value(99, 0).is_none());
        assert!(model.get_value(0, 99).is_none());
    }

    #[test]
    fn test_table_model_empty() {
        let model = LabelHistoryTableModel::new(vec![], true);
        assert_eq!(model.row_count(), 0);
        assert_eq!(model.column_count(), 5);
    }

    #[test]
    fn test_entry_new() {
        let entry = LabelHistoryEntry::new(
            addr(0x1000),
            LabelHistoryAction::Add,
            "test_label",
            "admin",
            "2024-06-01T00:00:00Z",
        );
        assert_eq!(entry.address.offset, 0x1000);
        assert_eq!(entry.action, LabelHistoryAction::Add);
        assert_eq!(entry.label, "test_label");
        assert_eq!(entry.user, "admin");
        assert_eq!(entry.date, "2024-06-01T00:00:00Z");
    }

    #[test]
    fn test_column_properties() {
        assert_eq!(LabelHistoryColumn::Address.display_name(), "Address");
        assert_eq!(
            LabelHistoryColumn::ModificationDate.display_name(),
            "Modification Date"
        );
        assert_eq!(LabelHistoryColumn::Label.index(), 2);
    }

    #[test]
    fn test_visible_columns() {
        let model = LabelHistoryTableModel::new(vec![], true);
        let cols = model.visible_columns();
        assert_eq!(cols.len(), 5);
        assert_eq!(cols[0], LabelHistoryColumn::Address);

        let model = LabelHistoryTableModel::new(vec![], false);
        let cols = model.visible_columns();
        assert_eq!(cols.len(), 4);
        assert_eq!(cols[0], LabelHistoryColumn::Action);
    }
}
