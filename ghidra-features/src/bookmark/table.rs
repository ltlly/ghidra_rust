//! Bookmark table model.
//!
//! Ported from Ghidra's BookmarkTableModel.

use serde::{Deserialize, Serialize};

/// A single bookmark entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkEntry {
    /// Address of the bookmark.
    pub address: String,
    /// Category (e.g., "Info", "Warning", "Error", "Note").
    pub category: String,
    /// Bookmark comment text.
    pub comment: String,
    /// The bookmark type identifier.
    pub bookmark_type: String,
}

impl BookmarkEntry {
    /// Create a new bookmark entry.
    pub fn new(address: &str, category: &str, comment: &str) -> Self {
        Self {
            address: address.to_string(),
            category: category.to_string(),
            comment: comment.to_string(),
            bookmark_type: "Note".to_string(),
        }
    }
    /// Set the bookmark type.
    pub fn with_type(mut self, btype: &str) -> Self {
        self.bookmark_type = btype.to_string();
        self
    }
}

/// Table model for displaying bookmarks.
#[derive(Debug, Default)]
pub struct BookmarkTableModel {
    entries: Vec<BookmarkEntry>,
}

impl BookmarkTableModel {
    pub fn new() -> Self { Self::default() }
    pub fn add(&mut self, entry: BookmarkEntry) { self.entries.push(entry); }
    pub fn remove(&mut self, address: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.address != address);
        self.entries.len() < before
    }
    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
    pub fn entries(&self) -> &[BookmarkEntry] { &self.entries }
    pub fn find_by_address(&self, address: &str) -> Vec<&BookmarkEntry> {
        self.entries.iter().filter(|e| e.address == address).collect()
    }
    pub fn find_by_category(&self, category: &str) -> Vec<&BookmarkEntry> {
        self.entries.iter().filter(|e| e.category == category).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bookmark_entry() {
        let entry = BookmarkEntry::new("0x401000", "Info", "Main entry point").with_type("Note");
        assert_eq!(entry.address, "0x401000");
        assert_eq!(entry.bookmark_type, "Note");
    }

    #[test]
    fn test_bookmark_table_model() {
        let mut model = BookmarkTableModel::new();
        assert!(model.is_empty());
        model.add(BookmarkEntry::new("0x401000", "Info", "entry"));
        model.add(BookmarkEntry::new("0x402000", "Warning", "todo"));
        model.add(BookmarkEntry::new("0x401000", "Error", "bug"));
        assert_eq!(model.len(), 3);
        assert_eq!(model.find_by_address("0x401000").len(), 2);
        assert_eq!(model.find_by_category("Warning").len(), 1);
        assert!(model.remove("0x402000"));
        assert_eq!(model.len(), 2);
    }
}
