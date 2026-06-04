//! Bookmark model for the Debug framework.
//!
//! Ported from `ghidra.trace.model.bookmark` — includes [`TraceBookmarkType`],
//! [`TraceBookmark`], and [`TraceBookmarkManager`].

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use super::core_types::Lifespan;

// ---------------------------------------------------------------------------
// TraceBookmarkType
// ---------------------------------------------------------------------------

/// A type of bookmark (e.g., Note, Warning, Analysis).
///
/// Ported from `ghidra.trace.model.bookmark.TraceBookmarkType`.
#[derive(Debug, Clone)]
pub struct TraceBookmarkType {
    /// Unique type name (e.g., "Note", "Warning").
    name: String,
    /// Display priority (lower = higher priority when multiple bookmarks at same address).
    priority: i32,
}

impl TraceBookmarkType {
    /// Create a new bookmark type.
    pub fn new(name: impl Into<String>, priority: i32) -> Self {
        Self {
            name: name.into(),
            priority,
        }
    }

    /// Returns the type name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the display priority.
    pub fn priority(&self) -> i32 {
        self.priority
    }
}

impl fmt::Display for TraceBookmarkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ---------------------------------------------------------------------------
// TraceBookmark
// ---------------------------------------------------------------------------

/// A bookmark placed at a specific address and snap in a trace.
///
/// Ported from `ghidra.trace.model.bookmark.TraceBookmark`. Bookmarks are
/// annotations at specific (address, snap) points. They have a type, category,
/// comment, and a lifespan.
#[derive(Debug, Clone)]
pub struct TraceBookmark {
    /// Unique key for this bookmark.
    key: u64,
    /// The type name (key into `TraceBookmarkType` registry).
    type_name: String,
    /// The address space name (e.g., "ram", "register").
    space_name: String,
    /// The offset within the address space.
    offset: u64,
    /// The category string (optional grouping).
    category: String,
    /// The comment text.
    comment: String,
    /// The lifespan of this bookmark.
    pub lifespan: Lifespan,
    /// Whether the bookmark has been deleted.
    deleted: bool,
}

impl TraceBookmark {
    /// Create a new bookmark.
    pub fn new(
        key: u64,
        type_name: impl Into<String>,
        space_name: impl Into<String>,
        offset: u64,
        category: impl Into<String>,
        comment: impl Into<String>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            key,
            type_name: type_name.into(),
            space_name: space_name.into(),
            offset,
            category: category.into(),
            comment: comment.into(),
            lifespan,
            deleted: false,
        }
    }

    /// Returns the unique key.
    pub fn key(&self) -> u64 {
        self.key
    }

    /// Returns the type name.
    pub fn type_name(&self) -> &str {
        &self.type_name
    }

    /// Returns the address space name.
    pub fn space_name(&self) -> &str {
        &self.space_name
    }

    /// Returns the offset.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the category.
    pub fn category(&self) -> &str {
        &self.category
    }

    /// Returns the comment.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Set the comment.
    pub fn set_comment(&mut self, comment: impl Into<String>) {
        self.comment = comment.into();
    }

    /// Set the lifespan.
    pub fn set_lifespan(&mut self, lifespan: Lifespan) {
        self.lifespan = lifespan;
    }

    /// Delete this bookmark.
    pub fn delete(&mut self) {
        self.deleted = true;
    }

    /// Check if valid at the given snapshot.
    pub fn is_valid(&self, snap: i64) -> bool {
        !self.deleted && self.lifespan.contains(snap)
    }

    /// Check if this bookmark overlaps the given address and snap.
    pub fn matches(&self, address: u64, snap: i64) -> bool {
        self.offset == address && self.is_valid(snap)
    }
}

impl fmt::Display for TraceBookmark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] 0x{:x}: {}",
            self.type_name, self.offset, self.comment
        )
    }
}

// ---------------------------------------------------------------------------
// TraceBookmarkManager
// ---------------------------------------------------------------------------

/// Manages bookmarks within a trace.
///
/// Ported from `ghidra.trace.model.bookmark.TraceBookmarkManager`.
#[derive(Debug)]
pub struct TraceBookmarkManager {
    next_key: AtomicU64,
    bookmarks: BTreeMap<u64, TraceBookmark>,
    types: BTreeMap<String, TraceBookmarkType>,
}

impl TraceBookmarkManager {
    /// Create a new empty bookmark manager.
    pub fn new() -> Self {
        let mut types = BTreeMap::new();
        // Register the standard bookmark types
        types.insert(
            "Note".to_string(),
            TraceBookmarkType::new("Note", 0),
        );
        types.insert(
            "Warning".to_string(),
            TraceBookmarkType::new("Warning", 1),
        );
        types.insert(
            "Analysis".to_string(),
            TraceBookmarkType::new("Analysis", 2),
        );
        types.insert(
            "Error".to_string(),
            TraceBookmarkType::new("Error", 3),
        );
        Self {
            next_key: AtomicU64::new(1),
            bookmarks: BTreeMap::new(),
            types,
        }
    }

    fn alloc_key(&self) -> u64 {
        self.next_key.fetch_add(1, Ordering::Relaxed)
    }

    /// Define (or redefine) a bookmark type.
    pub fn define_bookmark_type(
        &mut self,
        name: impl Into<String>,
        priority: i32,
    ) -> &TraceBookmarkType {
        let name_str = name.into();
        self.types
            .insert(name_str.clone(), TraceBookmarkType::new(&name_str, priority));
        self.types.get(&name_str).unwrap()
    }

    /// Get a bookmark type by name.
    pub fn get_bookmark_type(&self, name: &str) -> Option<&TraceBookmarkType> {
        self.types.get(name)
    }

    /// Get all defined bookmark types.
    pub fn get_defined_types(&self) -> Vec<&TraceBookmarkType> {
        self.types.values().collect()
    }

    /// Add a bookmark.
    pub fn set_bookmark(
        &mut self,
        type_name: impl Into<String>,
        space_name: impl Into<String>,
        offset: u64,
        lifespan: Lifespan,
        category: impl Into<String>,
        comment: impl Into<String>,
    ) -> u64 {
        let key = self.alloc_key();
        self.bookmarks.insert(
            key,
            TraceBookmark::new(key, type_name, space_name, offset, category, comment, lifespan),
        );
        key
    }

    /// Get a bookmark by key.
    pub fn get_bookmark(&self, key: u64) -> Option<&TraceBookmark> {
        self.bookmarks.get(&key)
    }

    /// Get a mutable bookmark by key.
    pub fn get_bookmark_mut(&mut self, key: u64) -> Option<&mut TraceBookmark> {
        self.bookmarks.get_mut(&key)
    }

    /// Get all bookmarks at a given address and snapshot.
    pub fn get_bookmarks_at(&self, address: u64, snap: i64) -> Vec<&TraceBookmark> {
        self.bookmarks
            .values()
            .filter(|b| b.matches(address, snap))
            .collect()
    }

    /// Get all bookmarks of a given type at a given address.
    pub fn get_bookmarks_with_type_at(
        &self,
        type_name: &str,
        address: u64,
        snap: i64,
    ) -> Vec<&TraceBookmark> {
        self.bookmarks
            .values()
            .filter(|b| b.type_name == type_name && b.matches(address, snap))
            .collect()
    }

    /// Get all bookmarks valid at the given snapshot.
    pub fn get_bookmarks_at_snap(&self, snap: i64) -> Vec<&TraceBookmark> {
        self.bookmarks
            .values()
            .filter(|b| b.is_valid(snap))
            .collect()
    }

    /// Get bookmarks added between two snapshots.
    pub fn get_bookmarks_added(&self, from: i64, to: i64) -> Vec<&TraceBookmark> {
        self.bookmarks
            .values()
            .filter(|b| !b.deleted && b.lifespan.min() >= from && b.lifespan.min() <= to)
            .collect()
    }

    /// Get bookmarks removed between two snapshots.
    pub fn get_bookmarks_removed(&self, from: i64, to: i64) -> Vec<&TraceBookmark> {
        self.bookmarks
            .values()
            .filter(|b| !b.deleted && b.lifespan.max() >= from && b.lifespan.max() <= to)
            .collect()
    }

    /// Iterate over all bookmarks.
    pub fn bookmarks(&self) -> impl Iterator<Item = &TraceBookmark> {
        self.bookmarks.values()
    }

    /// Remove a bookmark by key.
    pub fn remove_bookmark(&mut self, key: u64) -> Option<TraceBookmark> {
        self.bookmarks.remove(&key)
    }
}

impl Default for TraceBookmarkManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bookmark_type() {
        let bt = TraceBookmarkType::new("Note", 0);
        assert_eq!(bt.name(), "Note");
        assert_eq!(bt.priority(), 0);
        assert_eq!(format!("{bt}"), "Note");
    }

    #[test]
    fn test_bookmark_basic() {
        let bm = TraceBookmark::new(
            1,
            "Note",
            "ram",
            0x400000,
            "",
            "Important location",
            Lifespan::span(0, 100),
        );
        assert_eq!(bm.key(), 1);
        assert_eq!(bm.type_name(), "Note");
        assert_eq!(bm.space_name(), "ram");
        assert_eq!(bm.offset(), 0x400000);
        assert_eq!(bm.comment(), "Important location");
        assert!(bm.is_valid(0));
        assert!(bm.is_valid(50));
        assert!(bm.is_valid(100));
        assert!(!bm.is_valid(101));
    }

    #[test]
    fn test_bookmark_matches() {
        let bm = TraceBookmark::new(
            1,
            "Note",
            "ram",
            0x400000,
            "",
            "test",
            Lifespan::span(0, 10),
        );
        assert!(bm.matches(0x400000, 5));
        assert!(!bm.matches(0x400001, 5));
        assert!(!bm.matches(0x400000, 11));
    }

    #[test]
    fn test_bookmark_delete() {
        let mut bm = TraceBookmark::new(
            1,
            "Note",
            "ram",
            0x400000,
            "",
            "test",
            Lifespan::now_on(0),
        );
        assert!(bm.is_valid(0));
        bm.delete();
        assert!(!bm.is_valid(0));
    }

    #[test]
    fn test_bookmark_manager_types() {
        let mgr = TraceBookmarkManager::new();
        assert!(mgr.get_bookmark_type("Note").is_some());
        assert!(mgr.get_bookmark_type("Warning").is_some());
        assert!(mgr.get_bookmark_type("Analysis").is_some());
        assert!(mgr.get_bookmark_type("Error").is_some());
        assert!(mgr.get_bookmark_type("Nonexistent").is_none());
        assert_eq!(mgr.get_defined_types().len(), 4);
    }

    #[test]
    fn test_bookmark_manager_set_and_get() {
        let mut mgr = TraceBookmarkManager::new();
        let key = mgr.set_bookmark(
            "Note",
            "ram",
            0x400000,
            Lifespan::now_on(0),
            "",
            "test bookmark",
        );

        let bm = mgr.get_bookmark(key).unwrap();
        assert_eq!(bm.type_name(), "Note");
        assert_eq!(bm.offset(), 0x400000);
        assert_eq!(bm.comment(), "test bookmark");
    }

    #[test]
    fn test_bookmark_manager_query() {
        let mut mgr = TraceBookmarkManager::new();
        mgr.set_bookmark(
            "Note",
            "ram",
            0x400000,
            Lifespan::now_on(0),
            "",
            "note",
        );
        mgr.set_bookmark(
            "Warning",
            "ram",
            0x400000,
            Lifespan::now_on(5),
            "",
            "warning",
        );
        mgr.set_bookmark(
            "Note",
            "ram",
            0x500000,
            Lifespan::now_on(0),
            "",
            "other",
        );

        // At snap 0, only the first and third bookmarks are valid
        let at_snap_0 = mgr.get_bookmarks_at_snap(0);
        assert_eq!(at_snap_0.len(), 2);

        // At snap 10, all three are valid
        let at_snap_10 = mgr.get_bookmarks_at_snap(10);
        assert_eq!(at_snap_10.len(), 3);

        // At address 0x400000, snap 10
        let at_addr = mgr.get_bookmarks_at(0x400000, 10);
        assert_eq!(at_addr.len(), 2);

        // Only notes at 0x400000
        let notes = mgr.get_bookmarks_with_type_at("Note", 0x400000, 10);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].comment(), "note");
    }

    #[test]
    fn test_bookmark_manager_remove() {
        let mut mgr = TraceBookmarkManager::new();
        let key = mgr.set_bookmark(
            "Note",
            "ram",
            0x400000,
            Lifespan::now_on(0),
            "",
            "temporary",
        );
        assert_eq!(mgr.bookmarks().count(), 1);
        mgr.remove_bookmark(key);
        assert_eq!(mgr.bookmarks().count(), 0);
    }

    #[test]
    fn test_bookmark_manager_define_type() {
        let mut mgr = TraceBookmarkManager::new();
        mgr.define_bookmark_type("CustomType", 10);
        assert!(mgr.get_bookmark_type("CustomType").is_some());
    }

    #[test]
    fn test_bookmark_display() {
        let bm = TraceBookmark::new(
            1,
            "Note",
            "ram",
            0x400000,
            "",
            "hello",
            Lifespan::now_on(0),
        );
        assert_eq!(format!("{bm}"), "[Note] 0x400000: hello");
    }
}
