//! Comment Window -- display and edit comments in a table view.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.commentwindow` Java package.

use ghidra_core::Address;
use std::collections::BTreeMap;

/// A comment entry for the comment window.
#[derive(Debug, Clone)]
pub struct CommentEntry {
    /// The address of the comment.
    pub address: Address,
    /// Comment type (0=EOL, 1=PRE, 2=POST, 3=PLATE, 4=REPEATABLE).
    pub comment_type: i32,
    /// The comment text.
    pub text: String,
}

/// A type name for display.
impl CommentEntry {
    /// Get the human-readable type name.
    pub fn type_name(&self) -> &str {
        match self.comment_type {
            0 => "EOL",
            1 => "Pre",
            2 => "Post",
            3 => "Plate",
            4 => "Repeatable",
            _ => "Unknown",
        }
    }
}

/// Model for the comment window table.
#[derive(Debug, Default)]
pub struct CommentWindowModel {
    entries: BTreeMap<u64, Vec<CommentEntry>>,
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
            .push(entry);
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get_entries() {
        let mut model = CommentWindowModel::new();
        model.add_entry(CommentEntry {
            address: Address::new(0x1000),
            comment_type: 0,
            text: "EOL comment".into(),
        });
        model.add_entry(CommentEntry {
            address: Address::new(0x1000),
            comment_type: 1,
            text: "Pre comment".into(),
        });
        assert_eq!(model.entry_count(), 2);
        assert_eq!(model.address_count(), 1);
        let entries = model.get_entries_at(Address::new(0x1000));
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_type_name() {
        let entry = CommentEntry {
            address: Address::new(0x1000),
            comment_type: 3,
            text: "Plate".into(),
        };
        assert_eq!(entry.type_name(), "Plate");
    }
}
