//! Comment history dialog -- ported from Ghidra's comments plugin.
//!
//! Provides the comment history panel and dialog for viewing
//! the history of comment changes at addresses.
//!
//! Ported from:
//! - `ghidra.app.plugin.core.comments.CommentHistoryDialog`
//! - `ghidra.app.plugin.core.comments.CommentHistoryPanel`

use std::collections::BTreeMap;

use ghidra_core::Address;

use super::{CommentEntry, CommentType};

// ---------------------------------------------------------------------------
// CommentHistoryEntry -- a single history record
// ---------------------------------------------------------------------------

/// A single entry in the comment change history.
///
/// Records who changed a comment, when, and what it was changed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentHistoryEntry {
    /// The address where the comment was changed.
    pub address: Address,
    /// The comment type.
    pub comment_type: CommentType,
    /// The old comment text (empty if newly created).
    pub old_text: String,
    /// The new comment text (empty if deleted).
    pub new_text: String,
    /// The user who made the change.
    pub user: String,
    /// The timestamp (epoch millis).
    pub timestamp: u64,
}

impl CommentHistoryEntry {
    /// Create a new history entry.
    pub fn new(
        address: Address,
        comment_type: CommentType,
        old_text: impl Into<String>,
        new_text: impl Into<String>,
        user: impl Into<String>,
        timestamp: u64,
    ) -> Self {
        Self {
            address,
            comment_type,
            old_text: old_text.into(),
            new_text: new_text.into(),
            user: user.into(),
            timestamp,
        }
    }

    /// Whether this was a creation (old text is empty).
    pub fn is_creation(&self) -> bool {
        self.old_text.is_empty()
    }

    /// Whether this was a deletion (new text is empty).
    pub fn is_deletion(&self) -> bool {
        self.new_text.is_empty()
    }

    /// Whether this was an edit (both old and new are non-empty).
    pub fn is_edit(&self) -> bool {
        !self.old_text.is_empty() && !self.new_text.is_empty()
    }

    /// Summary description of this change.
    pub fn summary(&self) -> String {
        let name = self.comment_type.display_name();
        if self.is_creation() {
            format!("Created {}", name)
        } else if self.is_deletion() {
            format!("Deleted {}", name)
        } else {
            format!("Edited {}", name)
        }
    }
}

// ---------------------------------------------------------------------------
// CommentHistoryPanel -- panel model for displaying history
// ---------------------------------------------------------------------------

/// Panel model for displaying comment history at an address.
///
/// Ported from `ghidra.app.plugin.core.comments.CommentHistoryPanel`.
///
/// Displays a list of all comment changes that have occurred at
/// a specific address, grouped by comment type.
#[derive(Debug, Clone)]
pub struct CommentHistoryPanel {
    /// The address being viewed.
    pub address: Address,
    /// All history entries for this address.
    entries: Vec<CommentHistoryEntry>,
    /// The currently selected index.
    selected_index: Option<usize>,
    /// Filter by comment type (None = show all).
    pub filter_type: Option<CommentType>,
}

impl CommentHistoryPanel {
    /// Create a new history panel for an address.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            entries: Vec::new(),
            selected_index: None,
            filter_type: None,
        }
    }

    /// Add a history entry.
    pub fn add_entry(&mut self, entry: CommentHistoryEntry) {
        self.entries.push(entry);
        // Keep sorted by timestamp
        self.entries.sort_by_key(|e| e.timestamp);
    }

    /// Get all visible entries (applying filter).
    pub fn visible_entries(&self) -> Vec<&CommentHistoryEntry> {
        self.entries
            .iter()
            .filter(|e| {
                self.filter_type
                    .map_or(true, |ct| e.comment_type == ct)
            })
            .collect()
    }

    /// Get the total number of entries (unfiltered).
    pub fn total_entries(&self) -> usize {
        self.entries.len()
    }

    /// Get an entry by index.
    pub fn get_entry(&self, index: usize) -> Option<&CommentHistoryEntry> {
        self.entries.get(index)
    }

    /// Set the selected entry.
    pub fn set_selected(&mut self, index: Option<usize>) {
        self.selected_index = index;
    }

    /// Get the selected entry.
    pub fn selected_entry(&self) -> Option<&CommentHistoryEntry> {
        self.selected_index.and_then(|i| self.entries.get(i))
    }

    /// Clear all history entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.selected_index = None;
    }

    /// Get entries for a specific comment type.
    pub fn entries_for_type(&self, ct: CommentType) -> Vec<&CommentHistoryEntry> {
        self.entries
            .iter()
            .filter(|e| e.comment_type == ct)
            .collect()
    }

    /// The most recent entry.
    pub fn most_recent(&self) -> Option<&CommentHistoryEntry> {
        self.entries.last()
    }
}

// ---------------------------------------------------------------------------
// CommentHistoryDialog -- dialog model
// ---------------------------------------------------------------------------

/// Dialog model for viewing comment history.
///
/// Ported from `ghidra.app.plugin.core.comments.CommentHistoryDialog`.
///
/// Wraps a `CommentHistoryPanel` and adds dialog-level state
/// like title and visibility.
#[derive(Debug, Clone)]
pub struct CommentHistoryDialog {
    /// The panel displaying history.
    pub panel: CommentHistoryPanel,
    /// Whether the dialog is visible.
    pub visible: bool,
}

impl CommentHistoryDialog {
    /// Create a new dialog for an address.
    pub fn new(address: Address) -> Self {
        Self {
            panel: CommentHistoryPanel::new(address),
            visible: false,
        }
    }

    /// Show the dialog.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Hide the dialog.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Get the dialog title.
    pub fn title(&self) -> String {
        format!("Comment History at {}", self.panel.address)
    }

    /// Add an entry to the history.
    pub fn add_entry(&mut self, entry: CommentHistoryEntry) {
        self.panel.add_entry(entry);
    }
}

// ---------------------------------------------------------------------------
// CommentHistoryStore -- global comment history storage
// ---------------------------------------------------------------------------

/// Persistent store for comment history across the program.
///
/// Tracks all comment changes for undo-history display.
#[derive(Debug, Default)]
pub struct CommentHistoryStore {
    /// History entries keyed by address offset.
    history: BTreeMap<u64, Vec<CommentHistoryEntry>>,
}

impl CommentHistoryStore {
    /// Create a new empty history store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a comment change.
    pub fn record(&mut self, entry: CommentHistoryEntry) {
        let offset = entry.address.offset;
        self.history.entry(offset).or_default().push(entry);
    }

    /// Get all history entries for an address.
    pub fn get_history(&self, address: &Address) -> Vec<&CommentHistoryEntry> {
        self.history
            .get(&address.offset)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Get a panel populated with history for an address.
    pub fn get_panel(&self, address: Address) -> CommentHistoryPanel {
        let mut panel = CommentHistoryPanel::new(address);
        if let Some(entries) = self.history.get(&address.offset) {
            for entry in entries {
                panel.add_entry(entry.clone());
            }
        }
        panel
    }

    /// Total number of tracked addresses.
    pub fn tracked_addresses(&self) -> usize {
        self.history.len()
    }

    /// Total number of history entries.
    pub fn total_entries(&self) -> usize {
        self.history.values().map(|v| v.len()).sum()
    }

    /// Clear all history.
    pub fn clear(&mut self) {
        self.history.clear();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(addr: u64, ct: CommentType, old: &str, new: &str) -> CommentHistoryEntry {
        CommentHistoryEntry::new(
            Address::new(addr),
            ct,
            old,
            new,
            "user",
            1000,
        )
    }

    #[test]
    fn test_history_entry_types() {
        let creation = make_entry(0x1000, CommentType::Eol, "", "new comment");
        assert!(creation.is_creation());
        assert!(!creation.is_deletion());
        assert!(!creation.is_edit());

        let deletion = make_entry(0x1000, CommentType::Eol, "old comment", "");
        assert!(!deletion.is_creation());
        assert!(deletion.is_deletion());

        let edit = make_entry(0x1000, CommentType::Eol, "old", "new");
        assert!(edit.is_edit());
    }

    #[test]
    fn test_history_panel_filter() {
        let mut panel = CommentHistoryPanel::new(Address::new(0x1000));
        panel.add_entry(make_entry(0x1000, CommentType::Eol, "", "eol"));
        panel.add_entry(make_entry(0x1000, CommentType::Pre, "", "pre"));
        panel.add_entry(make_entry(0x1000, CommentType::Eol, "eol", "eol2"));

        assert_eq!(panel.visible_entries().len(), 3);

        panel.filter_type = Some(CommentType::Eol);
        assert_eq!(panel.visible_entries().len(), 2);
        assert_eq!(panel.entries_for_type(CommentType::Pre).len(), 1);
    }

    #[test]
    fn test_history_panel_selection() {
        let mut panel = CommentHistoryPanel::new(Address::new(0x1000));
        panel.add_entry(make_entry(0x1000, CommentType::Eol, "", "first"));
        panel.add_entry(make_entry(0x1000, CommentType::Eol, "first", "second"));

        assert!(panel.selected_entry().is_none());
        panel.set_selected(Some(1));
        let selected = panel.selected_entry().unwrap();
        assert_eq!(selected.new_text, "second");
    }

    #[test]
    fn test_history_dialog() {
        let mut dialog = CommentHistoryDialog::new(Address::new(0x2000));
        assert!(!dialog.visible);
        assert!(dialog.title().contains("2000"));

        dialog.show();
        assert!(dialog.visible);

        dialog.add_entry(make_entry(0x2000, CommentType::Plate, "", "plate text"));
        assert_eq!(dialog.panel.total_entries(), 1);
    }

    #[test]
    fn test_history_store() {
        let mut store = CommentHistoryStore::new();
        store.record(make_entry(0x1000, CommentType::Eol, "", "first"));
        store.record(make_entry(0x1000, CommentType::Eol, "first", "second"));
        store.record(make_entry(0x2000, CommentType::Pre, "", "pre"));

        assert_eq!(store.tracked_addresses(), 2);
        assert_eq!(store.total_entries(), 3);

        let h = store.get_history(&Address::new(0x1000));
        assert_eq!(h.len(), 2);

        let panel = store.get_panel(Address::new(0x2000));
        assert_eq!(panel.total_entries(), 1);
    }

    #[test]
    fn test_most_recent() {
        let mut panel = CommentHistoryPanel::new(Address::new(0x1000));
        assert!(panel.most_recent().is_none());

        panel.add_entry(make_entry(0x1000, CommentType::Eol, "", "first"));
        panel.add_entry(make_entry(0x1000, CommentType::Eol, "first", "latest"));
        let most = panel.most_recent().unwrap();
        assert_eq!(most.new_text, "latest");
    }

    #[test]
    fn test_history_entry_summary() {
        let c = make_entry(0x1000, CommentType::Eol, "", "new");
        assert_eq!(c.summary(), "Created EOL Comment");

        let d = make_entry(0x1000, CommentType::Pre, "old", "");
        assert_eq!(d.summary(), "Deleted Pre-Comment");

        let e = make_entry(0x1000, CommentType::Plate, "old", "new");
        assert_eq!(e.summary(), "Edited Plate Comment");
    }
}
