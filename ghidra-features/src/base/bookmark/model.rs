//! Bookmark data model, row objects, and filter state.
//!
//! This module provides the core bookmark data types ported from
//! Ghidra's `ghidra.app.plugin.core.bookmark` Java package:
//!
//! - [`Bookmark`] -- a single bookmark at an address with type/category/comment
//! - [`BookmarkRowObject`] -- a lightweight row key for table models
//! - [`FilterState`] -- serializable state of which bookmark types are visible
//! - [`BookmarkManager`] -- manages all bookmarks in a program

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use ghidra_core::addr::Address;

use super::types::BookmarkType;

// ---------------------------------------------------------------------------
// Bookmark
// ---------------------------------------------------------------------------

/// A bookmark annotation attached to an address in a program.
///
/// Bookmarks are user- or analysis-created annotations with:
/// - A unique ID (assigned by the manager)
/// - An address
/// - A type string (e.g. "Note", "Warning")
/// - An optional category (e.g. "Security", "Todo")
/// - A comment/description string
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bookmark {
    /// Unique bookmark ID.
    id: u64,
    /// Address where the bookmark is located.
    address: Address,
    /// Bookmark type string (e.g. "Note", "Warning").
    type_string: String,
    /// Optional category.
    category: String,
    /// Comment/description text.
    comment: String,
}

impl Bookmark {
    /// Creates a new Bookmark.
    pub fn new(
        id: u64,
        address: Address,
        type_string: impl Into<String>,
        category: impl Into<String>,
        comment: impl Into<String>,
    ) -> Self {
        Self {
            id,
            address,
            type_string: type_string.into(),
            category: category.into(),
            comment: comment.into(),
        }
    }

    /// Returns the unique bookmark ID.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Returns the address of this bookmark.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the type string (e.g. "Note", "Warning").
    pub fn type_string(&self) -> &str {
        &self.type_string
    }

    /// Returns the category string.
    pub fn category(&self) -> &str {
        &self.category
    }

    /// Returns the comment/description.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Updates the category and comment of this bookmark.
    pub fn set(&mut self, category: impl Into<String>, comment: impl Into<String>) {
        self.category = category.into();
        self.comment = comment.into();
    }
}

impl PartialOrd for Bookmark {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Bookmark {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl fmt::Display for Bookmark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Bookmark[id={}, addr={}, type={}, cat={}, comment={}]",
            self.id, self.address, self.type_string, self.category, self.comment
        )
    }
}

// ---------------------------------------------------------------------------
// BookmarkRowObject
// ---------------------------------------------------------------------------

/// A lightweight table row key that identifies a bookmark by its ID.
///
/// This corresponds to Ghidra's `BookmarkRowObject` which wraps a `long key`
/// and is used as the row identifier in bookmark table models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BookmarkRowObject {
    key: u64,
}

impl BookmarkRowObject {
    /// Creates a new row object wrapping the given bookmark key.
    pub fn new(key: u64) -> Self {
        Self { key }
    }

    /// Returns the bookmark key/ID.
    pub fn key(&self) -> u64 {
        self.key
    }
}

impl PartialOrd for BookmarkRowObject {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BookmarkRowObject {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key.cmp(&other.key)
    }
}

impl fmt::Display for BookmarkRowObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BookmarkRowObject[key={}]", self.key)
    }
}

// ---------------------------------------------------------------------------
// FilterState
// ---------------------------------------------------------------------------

/// Serializable snapshot of which bookmark types are currently visible.
///
/// Corresponds to Ghidra's `FilterState` which stores the set of
/// enabled bookmark type strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterState {
    /// The set of enabled bookmark type strings.
    bookmark_types: HashSet<String>,
}

impl FilterState {
    /// Creates a new FilterState with the given enabled types.
    pub fn new(bookmark_types: HashSet<String>) -> Self {
        Self { bookmark_types }
    }

    /// Returns a reference to the set of enabled bookmark type strings.
    pub fn bookmark_types(&self) -> &HashSet<String> {
        &self.bookmark_types
    }

    /// Returns true if the given type is enabled.
    pub fn is_type_enabled(&self, type_string: &str) -> bool {
        self.bookmark_types.contains(type_string)
    }

    /// Returns the number of enabled types.
    pub fn len(&self) -> usize {
        self.bookmark_types.len()
    }

    /// Returns true if no types are enabled.
    pub fn is_empty(&self) -> bool {
        self.bookmark_types.is_empty()
    }
}

// ---------------------------------------------------------------------------
// BookmarkManager
// ---------------------------------------------------------------------------

/// Manages all bookmarks in a program.
///
/// This is the Rust equivalent of Ghidra's `BookmarkManager`. It stores
/// bookmarks indexed by ID and provides lookup, iteration, and mutation
/// operations. Bookmark types can be registered via [`define_type`].
///
/// # Thread Safety
///
/// This implementation is not internally synchronized. Callers are
/// responsible for external locking if used from multiple threads.
#[derive(Debug)]
pub struct BookmarkManager {
    /// All bookmarks by ID.
    bookmarks: BTreeMap<u64, Bookmark>,
    /// Next available bookmark ID.
    next_id: u64,
    /// Registered bookmark types (type_string -> BookmarkType).
    types: HashMap<String, BookmarkType>,
    /// Index: type_string -> set of bookmark IDs.
    by_type: HashMap<String, HashSet<u64>>,
    /// Index: (type_string, category) -> set of bookmark IDs.
    by_type_category: HashMap<(String, String), HashSet<u64>>,
    /// Index: address -> set of bookmark IDs.
    by_address: HashMap<Address, HashSet<u64>>,
}

impl BookmarkManager {
    /// Creates a new empty BookmarkManager.
    pub fn new() -> Self {
        let mut mgr = Self {
            bookmarks: BTreeMap::new(),
            next_id: 1,
            types: HashMap::new(),
            by_type: HashMap::new(),
            by_type_category: HashMap::new(),
            by_address: HashMap::new(),
        };
        // Register built-in types with default properties.
        for bt in BookmarkType::builtin_types() {
            mgr.define_type_from(bt);
        }
        mgr
    }

    // -- Type registration ------------------------------------------------

    /// Registers or updates a bookmark type with icon, color, and priority.
    ///
    /// Corresponds to Ghidra's `BookmarkManager.defineType(String, Icon, Color, int)`.
    pub fn define_type(
        &mut self,
        type_string: &str,
        icon_id: Option<String>,
        color: Option<String>,
        priority: i32,
    ) {
        let bt = BookmarkType::new(type_string, priority, color, icon_id);
        self.types.insert(type_string.to_string(), bt);
    }

    /// Registers a pre-built BookmarkType.
    fn define_type_from(&mut self, bt: BookmarkType) {
        self.types.insert(bt.type_string().to_string(), bt);
    }

    /// Returns the registered BookmarkType for the given type string, if any.
    pub fn get_bookmark_type(&self, type_string: &str) -> Option<&BookmarkType> {
        self.types.get(type_string)
    }

    /// Returns all registered bookmark types.
    pub fn get_bookmark_types(&self) -> Vec<&BookmarkType> {
        self.types.values().collect()
    }

    /// Returns all registered bookmark type strings.
    pub fn get_bookmark_type_strings(&self) -> Vec<&str> {
        self.types.keys().map(|s| s.as_str()).collect()
    }

    // -- Bookmark creation ------------------------------------------------

    /// Sets (creates or updates) a bookmark at the given address.
    ///
    /// If a bookmark with the same type and category already exists at the
    /// address, it is updated; otherwise a new bookmark is created.
    ///
    /// Corresponds to `BookmarkManager.setBookmark(Address, String, String, String)`.
    pub fn set_bookmark(
        &mut self,
        address: &Address,
        type_string: &str,
        category: &str,
        comment: &str,
    ) -> &Bookmark {
        // Check for existing bookmark with same type + category at this address.
        if let Some(ids) = self.by_address.get(address) {
            let existing_id = ids.iter().find(|id| {
                if let Some(bm) = self.bookmarks.get(id) {
                    bm.type_string() == type_string && bm.category() == category
                } else {
                    false
                }
            }).copied();

            if let Some(id) = existing_id {
                let bm = self.bookmarks.get_mut(&id).unwrap();
                bm.set(category, comment);
                return self.bookmarks.get(&id).unwrap();
            }
        }

        let id = self.next_id;
        self.next_id += 1;
        let bm = Bookmark::new(id, address.clone(), type_string, category, comment);
        self.insert_bookmark(bm);
        self.bookmarks.get(&id).unwrap()
    }

    /// Inserts a bookmark directly, assigning a new ID.
    pub fn add_bookmark(&mut self, mut bookmark: Bookmark) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        bookmark.id = id;
        self.insert_bookmark(bookmark);
        id
    }

    /// Internal helper to insert a bookmark into all indices.
    fn insert_bookmark(&mut self, bookmark: Bookmark) {
        let id = bookmark.id;
        let type_string = bookmark.type_string().to_string();
        let category = bookmark.category().to_string();
        let address = bookmark.address().clone();

        self.bookmarks.insert(id, bookmark);
        self.by_type
            .entry(type_string.clone())
            .or_default()
            .insert(id);
        self.by_type_category
            .entry((type_string, category))
            .or_default()
            .insert(id);
        self.by_address
            .entry(address)
            .or_default()
            .insert(id);
    }

    // -- Bookmark queries -------------------------------------------------

    /// Returns a reference to the bookmark with the given ID.
    pub fn get_bookmark(&self, id: u64) -> Option<&Bookmark> {
        self.bookmarks.get(&id)
    }

    /// Returns a mutable reference to the bookmark with the given ID.
    pub fn get_bookmark_mut(&mut self, id: u64) -> Option<&mut Bookmark> {
        self.bookmarks.get_mut(&id)
    }

    /// Returns the total number of bookmarks.
    pub fn get_bookmark_count(&self) -> usize {
        self.bookmarks.len()
    }

    /// Returns the number of bookmarks of the given type.
    pub fn get_bookmark_count_by_type(&self, type_string: &str) -> usize {
        self.by_type
            .get(type_string)
            .map_or(0, |s| s.len())
    }

    /// Returns all bookmarks at the given address.
    pub fn get_bookmarks(&self, address: &Address) -> Vec<&Bookmark> {
        self.by_address
            .get(address)
            .map_or_else(Vec::new, |ids| {
                ids.iter()
                    .filter_map(|id| self.bookmarks.get(id))
                    .collect()
            })
    }

    /// Returns bookmarks at the given address filtered by type.
    pub fn get_bookmarks_by_type(&self, address: &Address, type_string: &str) -> Vec<&Bookmark> {
        self.get_bookmarks(address)
            .into_iter()
            .filter(|bm| bm.type_string() == type_string)
            .collect()
    }

    /// Returns an iterator over all bookmark IDs.
    pub fn bookmark_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.bookmarks.keys().copied()
    }

    /// Returns an iterator over all bookmarks of the given type.
    pub fn get_bookmarks_iterator(&self, type_string: &str) -> Box<dyn Iterator<Item = &Bookmark> + '_> {
        match self.by_type.get(type_string) {
            Some(ids) => {
                let ids_vec: Vec<u64> = ids.iter().copied().collect();
                Box::new(ids_vec.into_iter().filter_map(move |id| self.bookmarks.get(&id)))
            }
            None => Box::new(std::iter::empty()),
        }
    }

    // -- Bookmark removal -------------------------------------------------

    /// Removes the bookmark with the given ID. Returns the removed bookmark.
    pub fn remove_bookmark_by_id(&mut self, id: u64) -> Option<Bookmark> {
        let bm = self.bookmarks.remove(&id)?;
        self.remove_from_indices(&bm);
        Some(bm)
    }

    /// Removes the given bookmark (matched by ID).
    pub fn remove_bookmark(&mut self, bookmark: &Bookmark) -> bool {
        self.remove_bookmark_by_id(bookmark.id()).is_some()
    }

    /// Removes all bookmarks of the given type.
    pub fn remove_bookmarks_by_type(&mut self, type_string: &str) {
        if let Some(ids) = self.by_type.remove(type_string) {
            for id in &ids {
                if let Some(bm) = self.bookmarks.remove(id) {
                    self.by_type_category
                        .remove(&(bm.type_string().to_string(), bm.category().to_string()));
                    self.by_address.remove(bm.address());
                }
            }
        }
    }

    /// Removes all bookmarks of the given type and category.
    pub fn remove_bookmarks_by_type_and_category(&mut self, type_string: &str, category: &str) {
        let key = (type_string.to_string(), category.to_string());
        if let Some(ids) = self.by_type_category.remove(&key) {
            for id in &ids {
                if let Some(bm) = self.bookmarks.remove(id) {
                    if let Some(type_set) = self.by_type.get_mut(type_string) {
                        type_set.remove(id);
                    }
                    self.by_address.remove(bm.address());
                }
            }
        }
    }

    /// Removes all bookmarks at the given address(es).
    pub fn remove_bookmarks_at_addresses(&mut self, addresses: &[Address]) {
        for addr in addresses {
            if let Some(ids) = self.by_address.remove(addr) {
                for id in &ids {
                    if let Some(bm) = self.bookmarks.remove(id) {
                        if let Some(type_set) = self.by_type.get_mut(bm.type_string()) {
                            type_set.remove(id);
                        }
                        let key = (bm.type_string().to_string(), bm.category().to_string());
                        if let Some(tc_set) = self.by_type_category.get_mut(&key) {
                            tc_set.remove(id);
                        }
                    }
                }
            }
        }
    }

    /// Removes all bookmarks at the given address(es) with the given type.
    pub fn remove_bookmarks_at_addresses_by_type(
        &mut self,
        addresses: &[Address],
        type_string: &str,
    ) {
        for addr in addresses {
            let ids_to_remove: Vec<u64> = self
                .by_address
                .get(addr)
                .map_or_else(Vec::new, |ids| {
                    ids.iter()
                        .filter(|id| {
                            self.bookmarks
                                .get(id)
                                .map_or(false, |bm| bm.type_string() == type_string)
                        })
                        .copied()
                        .collect()
                });

            for id in ids_to_remove {
                if let Some(bm) = self.bookmarks.remove(&id) {
                    self.remove_from_indices(&bm);
                }
            }
        }
    }

    /// Removes all bookmarks.
    pub fn clear(&mut self) {
        self.bookmarks.clear();
        self.by_type.clear();
        self.by_type_category.clear();
        self.by_address.clear();
    }

    /// Removes a bookmark from all secondary indices.
    fn remove_from_indices(&mut self, bm: &Bookmark) {
        let id = bm.id();
        if let Some(type_set) = self.by_type.get_mut(bm.type_string()) {
            type_set.remove(&id);
        }
        let key = (bm.type_string().to_string(), bm.category().to_string());
        if let Some(tc_set) = self.by_type_category.get_mut(&key) {
            tc_set.remove(&id);
        }
        if let Some(addr_set) = self.by_address.get_mut(bm.address()) {
            addr_set.remove(&id);
        }
    }
}

impl Default for BookmarkManager {
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

    #[test]
    fn test_bookmark_creation() {
        let bm = Bookmark::new(1, addr(0x1000), "Note", "Todo", "Check this");
        assert_eq!(bm.id(), 1);
        assert_eq!(bm.address().offset, 0x1000);
        assert_eq!(bm.type_string(), "Note");
        assert_eq!(bm.category(), "Todo");
        assert_eq!(bm.comment(), "Check this");
    }

    #[test]
    fn test_bookmark_set_updates_category_and_comment() {
        let mut bm = Bookmark::new(1, addr(0x1000), "Note", "", "");
        bm.set("NewCat", "NewComment");
        assert_eq!(bm.category(), "NewCat");
        assert_eq!(bm.comment(), "NewComment");
    }

    #[test]
    fn test_bookmark_row_object_ordering() {
        let row1 = BookmarkRowObject::new(10);
        let row2 = BookmarkRowObject::new(20);
        assert!(row1 < row2);
        assert_eq!(row1.key(), 10);
    }

    #[test]
    fn test_bookmark_row_object_display() {
        let row = BookmarkRowObject::new(42);
        assert_eq!(format!("{}", row), "BookmarkRowObject[key=42]");
    }

    #[test]
    fn test_filter_state() {
        let mut types = HashSet::new();
        types.insert("Note".into());
        types.insert("Warning".into());
        let state = FilterState::new(types);

        assert!(state.is_type_enabled("Note"));
        assert!(state.is_type_enabled("Warning"));
        assert!(!state.is_type_enabled("Error"));
        assert_eq!(state.len(), 2);
    }

    #[test]
    fn test_manager_create_and_get() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "Cat1", "Hello");

        let bm = mgr.get_bookmark(1).unwrap();
        assert_eq!(bm.type_string(), "Note");
        assert_eq!(bm.category(), "Cat1");
        assert_eq!(bm.comment(), "Hello");
    }

    #[test]
    fn test_manager_set_updates_existing() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "Cat1", "v1");
        mgr.set_bookmark(&addr(0x1000), "Note", "Cat1", "v2");

        // Should still be one bookmark.
        assert_eq!(mgr.get_bookmark_count(), 1);
        let bm = mgr.get_bookmark(1).unwrap();
        assert_eq!(bm.comment(), "v2");
    }

    #[test]
    fn test_manager_different_types_same_address() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "", "note");
        mgr.set_bookmark(&addr(0x1000), "Warning", "", "warn");

        assert_eq!(mgr.get_bookmark_count(), 2);
        assert_eq!(mgr.get_bookmarks(&addr(0x1000)).len(), 2);
    }

    #[test]
    fn test_manager_remove_by_id() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "", "test");
        assert_eq!(mgr.get_bookmark_count(), 1);

        let removed = mgr.remove_bookmark_by_id(1);
        assert!(removed.is_some());
        assert_eq!(mgr.get_bookmark_count(), 0);
    }

    #[test]
    fn test_manager_remove_by_type() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "", "a");
        mgr.set_bookmark(&addr(0x2000), "Note", "", "b");
        mgr.set_bookmark(&addr(0x3000), "Warning", "", "c");

        mgr.remove_bookmarks_by_type("Note");
        assert_eq!(mgr.get_bookmark_count(), 1);
        assert_eq!(mgr.get_bookmark_count_by_type("Warning"), 1);
    }

    #[test]
    fn test_manager_remove_by_type_and_category() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "A", "a");
        mgr.set_bookmark(&addr(0x2000), "Note", "B", "b");
        mgr.set_bookmark(&addr(0x3000), "Note", "A", "c");

        mgr.remove_bookmarks_by_type_and_category("Note", "A");
        assert_eq!(mgr.get_bookmark_count(), 1);
        assert_eq!(mgr.get_bookmark_count_by_type("Note"), 1);
    }

    #[test]
    fn test_manager_remove_at_addresses() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "", "a");
        mgr.set_bookmark(&addr(0x2000), "Warning", "", "b");

        mgr.remove_bookmarks_at_addresses(&[addr(0x1000)]);
        assert_eq!(mgr.get_bookmark_count(), 1);
        assert!(mgr.get_bookmark(1).is_none());
        assert!(mgr.get_bookmark(2).is_some());
    }

    #[test]
    fn test_manager_clear() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "", "a");
        mgr.set_bookmark(&addr(0x2000), "Warning", "", "b");
        mgr.clear();
        assert_eq!(mgr.get_bookmark_count(), 0);
    }

    #[test]
    fn test_manager_iterator_by_type() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "", "a");
        mgr.set_bookmark(&addr(0x2000), "Note", "", "b");
        mgr.set_bookmark(&addr(0x3000), "Warning", "", "c");

        let notes: Vec<_> = mgr.get_bookmarks_iterator("Note").collect();
        assert_eq!(notes.len(), 2);
    }

    #[test]
    fn test_manager_bookmark_ids() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "", "a");
        mgr.set_bookmark(&addr(0x2000), "Warning", "", "b");

        let ids: Vec<u64> = mgr.bookmark_ids().collect();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn test_manager_builtin_types_registered() {
        let mgr = BookmarkManager::new();
        assert!(mgr.get_bookmark_type("Note").is_some());
        assert!(mgr.get_bookmark_type("Warning").is_some());
        assert!(mgr.get_bookmark_type("Error").is_some());
        assert!(mgr.get_bookmark_type("Info").is_some());
        assert!(mgr.get_bookmark_type("Analysis").is_some());
        assert!(mgr.get_bookmark_type("Nonexistent").is_none());
    }

    #[test]
    fn test_manager_define_custom_type() {
        let mut mgr = BookmarkManager::new();
        mgr.define_type("Custom", Some("icon.custom".into()), Some("#FF00FF".into()), 99);
        let bt = mgr.get_bookmark_type("Custom").unwrap();
        assert_eq!(bt.type_string(), "Custom");
        assert_eq!(bt.marker_priority(), 99);
    }

    #[test]
    fn test_manager_get_bookmarks_by_type_at_address() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "", "n");
        mgr.set_bookmark(&addr(0x1000), "Warning", "", "w");

        let notes = mgr.get_bookmarks_by_type(&addr(0x1000), "Note");
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].type_string(), "Note");
    }

    #[test]
    fn test_manager_remove_bookmarks_at_addresses_by_type() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "", "n");
        mgr.set_bookmark(&addr(0x1000), "Warning", "", "w");

        mgr.remove_bookmarks_at_addresses_by_type(&[addr(0x1000)], "Note");
        assert_eq!(mgr.get_bookmark_count(), 1);
        assert_eq!(mgr.get_bookmark_count_by_type("Warning"), 1);
    }
}
