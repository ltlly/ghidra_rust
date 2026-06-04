//! Bookmark management -- types, manager, and plugin logic.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.bookmark` Java package.
//!
//! Bookmarks are user-created annotations attached to addresses in a program.
//! Each bookmark has a type (e.g. `"Info"`, `"Warning"`, `"Note"`), a category,
//! and a comment string.
//!
//! # Architecture
//!
//! - [`BookmarkType`] -- a named bookmark category (string type + category).
//! - [`BookmarkData`] -- a single bookmark instance at an address.
//! - [`BookmarkManager`] -- manages bookmark CRUD operations on a program.
//! - [`BookmarkNavigator`] -- navigates between bookmarks of a given type.
//! - [`BookmarkPlugin`] -- orchestrates bookmark creation/removal actions.

use ghidra_core::Address;
use std::collections::{BTreeMap, HashMap};
use std::fmt;

// ============================================================================
// BookmarkType -- bookmark category
// ============================================================================

/// A bookmark type defines the category of a bookmark (e.g. `"Info"`, `"Warning"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BookmarkType {
    /// The type string (e.g. `"Info"`, `"Note"`, `"Warning"`, `"Error"`).
    type_string: String,
    /// The category string (e.g. `"Analysis"`, `"User"`).
    category: String,
}

impl BookmarkType {
    /// Create a new bookmark type.
    pub fn new(type_string: impl Into<String>, category: impl Into<String>) -> Self {
        Self {
            type_string: type_string.into(),
            category: category.into(),
        }
    }

    /// Return the type string.
    pub fn type_string(&self) -> &str {
        &self.type_string
    }

    /// Return the category string.
    pub fn category(&self) -> &str {
        &self.category
    }
}

impl fmt::Display for BookmarkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.type_string, self.category)
    }
}

// Standard bookmark types
impl BookmarkType {
    /// Informational bookmark.
    pub fn info() -> Self {
        Self::new("Info", "Analysis")
    }

    /// Warning bookmark.
    pub fn warning() -> Self {
        Self::new("Warning", "Analysis")
    }

    /// Error bookmark.
    pub fn error() -> Self {
        Self::new("Error", "Analysis")
    }

    /// User-created note bookmark.
    pub fn note() -> Self {
        Self::new("Note", "User")
    }
}

// ============================================================================
// BookmarkData -- a single bookmark instance
// ============================================================================

/// A bookmark at a specific address.
#[derive(Debug, Clone)]
pub struct BookmarkData {
    /// The address this bookmark applies to.
    pub address: Address,
    /// The bookmark type.
    pub bookmark_type: BookmarkType,
    /// The comment text.
    pub comment: String,
    /// Unique ID for this bookmark.
    pub id: u64,
}

impl BookmarkData {
    /// Create a new bookmark.
    pub fn new(
        address: Address,
        bookmark_type: BookmarkType,
        comment: impl Into<String>,
        id: u64,
    ) -> Self {
        Self {
            address,
            bookmark_type,
            comment: comment.into(),
            id,
        }
    }
}

// ============================================================================
// BookmarkManager -- manages bookmarks in a program
// ============================================================================

/// Manages bookmarks for a program.
///
/// Supports CRUD operations and queries by type, address, and range.
#[derive(Debug, Default)]
pub struct BookmarkManager {
    /// All bookmarks, keyed by ID.
    bookmarks: HashMap<u64, BookmarkData>,
    /// Index by address: address -> list of bookmark IDs.
    by_address: BTreeMap<u64, Vec<u64>>,
    /// Index by type string: type_string -> list of bookmark IDs.
    by_type: HashMap<String, Vec<u64>>,
    /// Next bookmark ID.
    next_id: u64,
    /// Registered bookmark types.
    types: HashMap<String, BookmarkType>,
}

impl BookmarkManager {
    /// Create a new empty bookmark manager.
    pub fn new() -> Self {
        let mut mgr = Self::default();
        // Register default types
        mgr.define_type(BookmarkType::info());
        mgr.define_type(BookmarkType::warning());
        mgr.define_type(BookmarkType::error());
        mgr.define_type(BookmarkType::note());
        mgr
    }

    /// Register a bookmark type.
    pub fn define_type(&mut self, btype: BookmarkType) {
        self.types
            .entry(btype.type_string().to_string())
            .or_insert(btype);
    }

    /// Get all registered bookmark types.
    pub fn get_bookmark_types(&self) -> Vec<&BookmarkType> {
        self.types.values().collect()
    }

    /// Set (create or update) a bookmark at the given address.
    pub fn set_bookmark(
        &mut self,
        address: Address,
        bookmark_type: &BookmarkType,
        comment: &str,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;

        let bm = BookmarkData::new(address, bookmark_type.clone(), comment, id);

        // Index by address
        self.by_address
            .entry(address.offset)
            .or_default()
            .push(id);
        // Index by type
        self.by_type
            .entry(bookmark_type.type_string().to_string())
            .or_default()
            .push(id);

        self.bookmarks.insert(id, bm);
        id
    }

    /// Remove a bookmark by ID.
    pub fn remove_bookmark(&mut self, id: u64) -> Option<BookmarkData> {
        if let Some(bm) = self.bookmarks.remove(&id) {
            // Remove from address index
            if let Some(ids) = self.by_address.get_mut(&bm.address.offset) {
                ids.retain(|&x| x != id);
                if ids.is_empty() {
                    self.by_address.remove(&bm.address.offset);
                }
            }
            // Remove from type index
            if let Some(ids) = self.by_type.get_mut(bm.bookmark_type.type_string()) {
                ids.retain(|&x| x != id);
                if ids.is_empty() {
                    self.by_type.remove(bm.bookmark_type.type_string());
                }
            }
            Some(bm)
        } else {
            None
        }
    }

    /// Get a bookmark by ID.
    pub fn get_bookmark(&self, id: u64) -> Option<&BookmarkData> {
        self.bookmarks.get(&id)
    }

    /// Get all bookmarks at the given address.
    pub fn get_bookmarks_at(&self, address: Address) -> Vec<&BookmarkData> {
        self.by_address
            .get(&address.offset)
            .map(|ids| ids.iter().filter_map(|id| self.bookmarks.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get all bookmarks of a given type.
    pub fn get_bookmarks_by_type(&self, type_string: &str) -> Vec<&BookmarkData> {
        self.by_type
            .get(type_string)
            .map(|ids| ids.iter().filter_map(|id| self.bookmarks.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get all bookmarks.
    pub fn get_all_bookmarks(&self) -> Vec<&BookmarkData> {
        self.bookmarks.values().collect()
    }

    /// Return the total number of bookmarks.
    pub fn bookmark_count(&self) -> usize {
        self.bookmarks.len()
    }

    /// Return the number of bookmarks of a given type.
    pub fn bookmark_count_by_type(&self, type_string: &str) -> usize {
        self.by_type
            .get(type_string)
            .map(|v| v.len())
            .unwrap_or(0)
    }
}

// ============================================================================
// BookmarkNavigator -- next/previous navigation for bookmarks
// ============================================================================

/// Navigates between bookmarks of a specific type.
#[derive(Debug)]
pub struct BookmarkNavigator {
    /// The type this navigator operates on.
    pub bookmark_type: BookmarkType,
    /// Sorted addresses with bookmarks of this type.
    addresses: Vec<Address>,
}

impl BookmarkNavigator {
    /// Create a navigator from a bookmark manager and type.
    pub fn new(bookmark_type: BookmarkType, manager: &BookmarkManager) -> Self {
        let bookmarks = manager.get_bookmarks_by_type(bookmark_type.type_string());
        let mut addresses: Vec<Address> = bookmarks.iter().map(|b| b.address).collect();
        addresses.sort();
        addresses.dedup();
        Self {
            bookmark_type,
            addresses,
        }
    }

    /// Find the next bookmark address after `current`.
    pub fn get_next(&self, current: Address) -> Option<Address> {
        self.addresses
            .iter()
            .find(|&&addr| addr > current)
            .copied()
    }

    /// Find the previous bookmark address before `current`.
    pub fn get_previous(&self, current: Address) -> Option<Address> {
        self.addresses
            .iter()
            .rev()
            .find(|&&addr| addr < current)
            .copied()
    }

    /// The number of bookmarks this navigator tracks.
    pub fn count(&self) -> usize {
        self.addresses.len()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bookmark_type_display() {
        let bt = BookmarkType::info();
        assert_eq!(bt.to_string(), "Info (Analysis)");
    }

    #[test]
    fn test_bookmark_manager_set_and_get() {
        let mut mgr = BookmarkManager::new();
        let addr = Address::new(0x1000);
        let id = mgr.set_bookmark(addr, &BookmarkType::note(), "Test bookmark");
        let bm = mgr.get_bookmark(id).unwrap();
        assert_eq!(bm.address, addr);
        assert_eq!(bm.comment, "Test bookmark");
        assert_eq!(bm.bookmark_type.type_string(), "Note");
    }

    #[test]
    fn test_bookmark_manager_remove() {
        let mut mgr = BookmarkManager::new();
        let id = mgr.set_bookmark(Address::new(0x1000), &BookmarkType::info(), "test");
        assert!(mgr.remove_bookmark(id).is_some());
        assert!(mgr.get_bookmark(id).is_none());
    }

    #[test]
    fn test_bookmarks_at_address() {
        let mut mgr = BookmarkManager::new();
        let addr = Address::new(0x2000);
        mgr.set_bookmark(addr, &BookmarkType::info(), "first");
        mgr.set_bookmark(addr, &BookmarkType::warning(), "second");
        let at_addr = mgr.get_bookmarks_at(addr);
        assert_eq!(at_addr.len(), 2);
    }

    #[test]
    fn test_bookmarks_by_type() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(Address::new(0x1000), &BookmarkType::info(), "i1");
        mgr.set_bookmark(Address::new(0x2000), &BookmarkType::info(), "i2");
        mgr.set_bookmark(Address::new(0x3000), &BookmarkType::warning(), "w1");
        assert_eq!(mgr.bookmark_count_by_type("Info"), 2);
        assert_eq!(mgr.bookmark_count_by_type("Warning"), 1);
    }

    #[test]
    fn test_bookmark_manager_total_count() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(Address::new(0x1000), &BookmarkType::info(), "a");
        mgr.set_bookmark(Address::new(0x2000), &BookmarkType::note(), "b");
        assert_eq!(mgr.bookmark_count(), 2);
    }

    #[test]
    fn test_define_custom_type() {
        let mut mgr = BookmarkManager::new();
        let custom = BookmarkType::new("Custom", "MyCategory");
        mgr.define_type(custom.clone());
        assert!(mgr.get_bookmark_types().iter().any(|t| t.type_string() == "Custom"));
    }

    #[test]
    fn test_bookmark_navigator_next_previous() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(Address::new(0x1000), &BookmarkType::info(), "a");
        mgr.set_bookmark(Address::new(0x3000), &BookmarkType::info(), "b");
        mgr.set_bookmark(Address::new(0x5000), &BookmarkType::info(), "c");

        let nav = BookmarkNavigator::new(BookmarkType::info(), &mgr);
        assert_eq!(nav.count(), 3);
        assert_eq!(nav.get_next(Address::new(0x1000)), Some(Address::new(0x3000)));
        assert_eq!(nav.get_next(Address::new(0x5000)), None);
        assert_eq!(nav.get_previous(Address::new(0x5000)), Some(Address::new(0x3000)));
        assert_eq!(nav.get_previous(Address::new(0x1000)), None);
    }
}
