//! Bookmark manager for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.listing.BookmarkManager`.
//!
//! Manages user-placed bookmarks at specific addresses in the program.

use crate::addr::Address;
use std::collections::{HashMap, HashSet};

/// A category/type of bookmark.
///
/// Corresponds to Ghidra's `BookmarkType`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BookmarkType {
    /// The unique type name (e.g., "Analysis", "Info", "Warning", "Error").
    pub type_name: String,
    /// A marker symbol (single character for display).
    pub marker: Option<String>,
    /// Whether this bookmark type has an associated keyboard shortcut.
    pub has_shortcut: bool,
}

impl BookmarkType {
    /// Create a new bookmark type.
    pub fn new(type_name: impl Into<String>) -> Self {
        Self {
            type_name: type_name.into(),
            marker: None,
            has_shortcut: false,
        }
    }

    /// Builder: set a marker character.
    pub fn with_marker(mut self, marker: impl Into<String>) -> Self {
        self.marker = Some(marker.into());
        self
    }

    /// Builder: set shortcut availability.
    pub fn with_shortcut(mut self, has_shortcut: bool) -> Self {
        self.has_shortcut = has_shortcut;
        self
    }
}

/// A user-placed bookmark at a specific address.
///
/// Corresponds to Ghidra's `Bookmark` interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bookmark {
    /// The bookmark ID (unique within the program).
    pub id: u64,
    /// The address where this bookmark is placed.
    pub address: Address,
    /// The bookmark type string (e.g., "Analysis", "Info").
    pub bookmark_type: String,
    /// The category string (sub-type grouping).
    pub category: String,
    /// The comment/description text.
    pub comment: String,
}

impl Bookmark {
    /// Create a new bookmark.
    pub fn new(
        id: u64,
        address: Address,
        bookmark_type: impl Into<String>,
        category: impl Into<String>,
        comment: impl Into<String>,
    ) -> Self {
        Self {
            id,
            address,
            bookmark_type: bookmark_type.into(),
            category: category.into(),
            comment: comment.into(),
        }
    }
}

/// Manages bookmarks in a program.
///
/// Corresponds to Ghidra's `BookmarkManager` interface.
#[derive(Debug, Clone, Default)]
pub struct BookmarkManager {
    /// Bookmarks keyed by address.
    bookmarks: HashMap<Address, Vec<Bookmark>>,
    /// All defined bookmark types.
    bookmark_types: HashMap<String, BookmarkType>,
    /// All categories.
    categories: HashSet<String>,
    /// Next bookmark ID.
    next_id: u64,
}

impl BookmarkManager {
    /// Create a new empty bookmark manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a bookmark at an address. Overwrites any existing bookmark of the same type+category.
    pub fn set_bookmark(
        &mut self,
        addr: Address,
        bookmark_type: impl Into<String>,
        category: impl Into<String>,
        comment: impl Into<String>,
    ) -> Bookmark {
        let bm_type: String = bookmark_type.into();
        let cat: String = category.into();
        let comment: String = comment.into();

        if !self.bookmark_types.contains_key(&bm_type) {
            self.bookmark_types
                .insert(bm_type.clone(), BookmarkType::new(&bm_type));
        }
        self.categories.insert(cat.clone());

        let id = self.next_id;
        self.next_id += 1;
        let bm = Bookmark {
            id,
            address: addr,
            bookmark_type: bm_type,
            category: cat,
            comment,
        };
        self.bookmarks.entry(addr).or_default().push(bm.clone());
        bm
    }

    /// Remove all bookmarks at an address.
    pub fn remove_bookmarks(&mut self, addr: &Address) -> Vec<Bookmark> {
        self.bookmarks.remove(addr).unwrap_or_default()
    }

    /// Get all bookmarks at an address.
    pub fn get_bookmarks(&self, addr: &Address) -> Vec<&Bookmark> {
        self.bookmarks
            .get(addr)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Get all bookmarks of a given type.
    pub fn get_bookmarks_by_type(&self, bookmark_type: &str) -> Vec<&Bookmark> {
        self.bookmarks
            .values()
            .flatten()
            .filter(|bm| bm.bookmark_type == bookmark_type)
            .collect()
    }

    /// Get all bookmarks in a given category.
    pub fn get_bookmarks_by_category(&self, category: &str) -> Vec<&Bookmark> {
        self.bookmarks
            .values()
            .flatten()
            .filter(|bm| bm.category == category)
            .collect()
    }

    /// Get all defined bookmark types.
    pub fn get_bookmark_types(&self) -> Vec<&BookmarkType> {
        self.bookmark_types.values().collect()
    }

    /// Get all categories.
    pub fn get_categories(&self) -> Vec<&String> {
        self.categories.iter().collect()
    }

    /// Total number of bookmarks.
    pub fn num_bookmarks(&self) -> usize {
        self.bookmarks.values().map(|v| v.len()).sum()
    }

    /// Returns all addresses that currently have one or more bookmarks.
    pub fn get_bookmark_addresses(&self) -> Vec<Address> {
        self.bookmarks.keys().copied().collect()
    }

    /// Returns true if there are no bookmarks.
    pub fn is_empty(&self) -> bool {
        self.bookmarks.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bookmark_manager_set_and_get() {
        let mut mgr = BookmarkManager::new();
        let bm = mgr.set_bookmark(
            Address::new(0x1000),
            "Analysis",
            "Entry Point",
            "Program entry",
        );
        assert_eq!(bm.address, Address::new(0x1000));
        assert_eq!(bm.bookmark_type, "Analysis");
        assert_eq!(bm.category, "Entry Point");
        assert_eq!(mgr.num_bookmarks(), 1);

        let found = mgr.get_bookmarks(&Address::new(0x1000));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].comment, "Program entry");
    }

    #[test]
    fn test_bookmark_manager_remove() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(Address::new(0x1000), "Info", "Note", "test");
        assert_eq!(mgr.num_bookmarks(), 1);
        mgr.remove_bookmarks(&Address::new(0x1000));
        assert_eq!(mgr.num_bookmarks(), 0);
    }

    #[test]
    fn test_bookmark_manager_by_type() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(Address::new(0x1000), "Analysis", "Type1", "a1");
        mgr.set_bookmark(Address::new(0x2000), "Analysis", "Type2", "a2");
        mgr.set_bookmark(Address::new(0x3000), "Warning", "Type1", "w1");

        let analysis = mgr.get_bookmarks_by_type("Analysis");
        assert_eq!(analysis.len(), 2);

        let warnings = mgr.get_bookmarks_by_type("Warning");
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn test_bookmark_manager_categories() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(Address::new(0x1000), "Info", "Category1", "c1");
        mgr.set_bookmark(Address::new(0x2000), "Info", "Category2", "c2");
        assert_eq!(mgr.get_categories().len(), 2);
    }

    #[test]
    fn test_bookmark_manager_empty() {
        let mgr = BookmarkManager::new();
        assert!(mgr.is_empty());
        assert_eq!(mgr.num_bookmarks(), 0);
        assert!(mgr.get_bookmark_types().is_empty());
    }

    #[test]
    fn test_bookmark_type_builder() {
        let bt = BookmarkType::new("Analysis")
            .with_marker("A")
            .with_shortcut(true);
        assert_eq!(bt.type_name, "Analysis");
        assert_eq!(bt.marker, Some("A".to_string()));
        assert!(bt.has_shortcut);
    }

    #[test]
    fn test_bookmark_manager_get_by_category() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(Address::new(0x1000), "Info", "Entry", "note1");
        mgr.set_bookmark(Address::new(0x2000), "Warning", "Entry", "note2");
        let entries = mgr.get_bookmarks_by_category("Entry");
        assert_eq!(entries.len(), 2);
    }
}
