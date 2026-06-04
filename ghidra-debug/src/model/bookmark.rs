//! TraceBookmark - bookmarks in a trace (notes, warnings, errors, types).
//!
//! Ported from Ghidra's `ghidra.trace.model.bookmark` package.
//! Bookmarks annotate addresses in a trace with typed comments across a lifespan.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::Lifespan;

/// The type of a trace bookmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TraceBookmarkType {
    /// A user-defined note.
    Note,
    /// A warning bookmark.
    Warning,
    /// An error bookmark.
    Error,
    /// An analysis bookmark.
    Analysis,
    /// A type bookmark.
    Type,
}

impl TraceBookmarkType {
    /// The display name for this bookmark type.
    pub fn display_name(&self) -> &str {
        match self {
            Self::Note => "Note",
            Self::Warning => "Warning",
            Self::Error => "Error",
            Self::Analysis => "Analysis",
            Self::Type => "Type",
        }
    }
}

impl fmt::Display for TraceBookmarkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// A bookmark in a trace at a specific address and lifespan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceBookmark {
    /// Unique key for this bookmark.
    pub key: i64,
    /// The address offset.
    pub address: u64,
    /// The lifespan of this bookmark.
    pub lifespan: Lifespan,
    /// The type of this bookmark.
    pub bookmark_type: TraceBookmarkType,
    /// The category string (sub-type).
    pub category: String,
    /// The comment string.
    pub comment: String,
    /// Optional thread key (for register-space bookmarks).
    pub thread_key: Option<i64>,
}

impl TraceBookmark {
    /// Create a new bookmark.
    pub fn new(
        key: i64,
        address: u64,
        lifespan: Lifespan,
        bookmark_type: TraceBookmarkType,
        category: impl Into<String>,
        comment: impl Into<String>,
    ) -> Self {
        Self {
            key,
            address,
            lifespan,
            bookmark_type,
            category: category.into(),
            comment: comment.into(),
            thread_key: None,
        }
    }

    /// Set the thread key for a register-space bookmark.
    pub fn with_thread(mut self, thread_key: i64) -> Self {
        self.thread_key = Some(thread_key);
        self
    }

    /// Whether this bookmark is active at the given snap.
    pub fn is_active_at(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }
}

/// Manages bookmarks for a trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceBookmarkManager {
    next_key: i64,
    bookmarks: Vec<TraceBookmark>,
}

impl TraceBookmarkManager {
    /// Create a new bookmark manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a bookmark.
    pub fn add_bookmark(
        &mut self,
        address: u64,
        lifespan: Lifespan,
        bookmark_type: TraceBookmarkType,
        category: impl Into<String>,
        comment: impl Into<String>,
    ) -> &mut TraceBookmark {
        let key = self.next_key;
        self.next_key += 1;
        self.bookmarks.push(TraceBookmark::new(
            key,
            address,
            lifespan,
            bookmark_type,
            category,
            comment,
        ));
        self.bookmarks.last_mut().unwrap()
    }

    /// Add a bookmark with a specific key (used when loading from database).
    pub fn add_bookmark_with_key(&mut self, bookmark: TraceBookmark) {
        if bookmark.key >= self.next_key {
            self.next_key = bookmark.key + 1;
        }
        self.bookmarks.push(bookmark);
    }

    /// Delete a bookmark by key.
    pub fn delete(&mut self, key: i64) -> bool {
        let before = self.bookmarks.len();
        self.bookmarks.retain(|b| b.key != key);
        self.bookmarks.len() < before
    }

    /// Get all bookmarks.
    pub fn all_bookmarks(&self) -> &[TraceBookmark] {
        &self.bookmarks
    }

    /// Get bookmarks at a given snap and address.
    pub fn bookmarks_at(&self, snap: i64, address: u64) -> Vec<&TraceBookmark> {
        self.bookmarks
            .iter()
            .filter(|b| b.address == address && b.lifespan.contains(snap))
            .collect()
    }

    /// Get all bookmarks at a given snap.
    pub fn bookmarks_at_snap(&self, snap: i64) -> Vec<&TraceBookmark> {
        self.bookmarks
            .iter()
            .filter(|b| b.lifespan.contains(snap))
            .collect()
    }

    /// Get all categories for a given type.
    pub fn categories_for_type(&self, bookmark_type: TraceBookmarkType) -> BTreeSet<String> {
        self.bookmarks
            .iter()
            .filter(|b| b.bookmark_type == bookmark_type)
            .map(|b| b.category.clone())
            .collect()
    }

    /// Get bookmarks by type.
    pub fn bookmarks_by_type(&self, bookmark_type: TraceBookmarkType) -> Vec<&TraceBookmark> {
        self.bookmarks
            .iter()
            .filter(|b| b.bookmark_type == bookmark_type)
            .collect()
    }

    /// Number of bookmarks.
    pub fn len(&self) -> usize {
        self.bookmarks.len()
    }

    /// Whether there are no bookmarks.
    pub fn is_empty(&self) -> bool {
        self.bookmarks.is_empty()
    }

    /// Get a bookmark by key.
    pub fn get(&self, key: i64) -> Option<&TraceBookmark> {
        self.bookmarks.iter().find(|b| b.key == key)
    }

    /// Get a mutable reference to a bookmark by key.
    pub fn get_mut(&mut self, key: i64) -> Option<&mut TraceBookmark> {
        self.bookmarks.iter_mut().find(|b| b.key == key)
    }
}

/// A map from bookmark type to the set of bookmarks of that type.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceBookmarkTypeMap {
    map: BTreeMap<TraceBookmarkType, Vec<i64>>,
}

impl TraceBookmarkTypeMap {
    /// Create a new empty type map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a bookmark key to the given type.
    pub fn insert(&mut self, bookmark_type: TraceBookmarkType, key: i64) {
        self.map.entry(bookmark_type).or_default().push(key);
    }

    /// Get keys for a type.
    pub fn get(&self, bookmark_type: &TraceBookmarkType) -> Option<&Vec<i64>> {
        self.map.get(bookmark_type)
    }

    /// Remove a bookmark key.
    pub fn remove(&mut self, bookmark_type: &TraceBookmarkType, key: i64) -> bool {
        if let Some(keys) = self.map.get_mut(bookmark_type) {
            let before = keys.len();
            keys.retain(|k| *k != key);
            keys.len() < before
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bookmark_type_display() {
        assert_eq!(TraceBookmarkType::Note.to_string(), "Note");
        assert_eq!(TraceBookmarkType::Warning.to_string(), "Warning");
        assert_eq!(TraceBookmarkType::Error.to_string(), "Error");
    }

    #[test]
    fn test_bookmark_creation() {
        let bm = TraceBookmark::new(1, 0x400000, Lifespan::at(5), TraceBookmarkType::Note, "cat1", "hello");
        assert_eq!(bm.key, 1);
        assert_eq!(bm.address, 0x400000);
        assert!(bm.is_active_at(5));
        assert!(!bm.is_active_at(6));
    }

    #[test]
    fn test_bookmark_with_thread() {
        let bm = TraceBookmark::new(1, 0, Lifespan::ALL, TraceBookmarkType::Note, "", "")
            .with_thread(42);
        assert_eq!(bm.thread_key, Some(42));
    }

    #[test]
    fn test_bookmark_manager_add_and_query() {
        let mut mgr = TraceBookmarkManager::new();
        mgr.add_bookmark(0x400000, Lifespan::at(0), TraceBookmarkType::Note, "ui", "first note");
        mgr.add_bookmark(0x400000, Lifespan::at(0), TraceBookmarkType::Warning, "analysis", "warn");
        mgr.add_bookmark(0x500000, Lifespan::now_on(1), TraceBookmarkType::Error, "runtime", "oops");

        assert_eq!(mgr.len(), 3);

        let at_400 = mgr.bookmarks_at(0, 0x400000);
        assert_eq!(at_400.len(), 2);

        let at_snap0 = mgr.bookmarks_at_snap(0);
        assert_eq!(at_snap0.len(), 2);

        let errors = mgr.bookmarks_by_type(TraceBookmarkType::Error);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].address, 0x500000);
    }

    #[test]
    fn test_bookmark_delete() {
        let mut mgr = TraceBookmarkManager::new();
        mgr.add_bookmark(0x100, Lifespan::ALL, TraceBookmarkType::Note, "", "");
        let key = mgr.all_bookmarks()[0].key;
        assert!(mgr.delete(key));
        assert!(mgr.is_empty());
        assert!(!mgr.delete(key));
    }

    #[test]
    fn test_categories_for_type() {
        let mut mgr = TraceBookmarkManager::new();
        mgr.add_bookmark(0x100, Lifespan::ALL, TraceBookmarkType::Analysis, "decompile", "");
        mgr.add_bookmark(0x200, Lifespan::ALL, TraceBookmarkType::Analysis, "propagate", "");
        mgr.add_bookmark(0x300, Lifespan::ALL, TraceBookmarkType::Note, "user", "");

        let cats = mgr.categories_for_type(TraceBookmarkType::Analysis);
        assert_eq!(cats.len(), 2);
        assert!(cats.contains("decompile"));
        assert!(cats.contains("propagate"));
    }

    #[test]
    fn test_bookmark_type_map() {
        let mut map = TraceBookmarkTypeMap::new();
        map.insert(TraceBookmarkType::Note, 1);
        map.insert(TraceBookmarkType::Note, 2);
        map.insert(TraceBookmarkType::Error, 3);

        assert_eq!(map.get(&TraceBookmarkType::Note).unwrap().len(), 2);
        assert!(map.remove(&TraceBookmarkType::Note, 1));
        assert_eq!(map.get(&TraceBookmarkType::Note).unwrap().len(), 1);
    }

    #[test]
    fn test_bookmark_serde() {
        let bm = TraceBookmark::new(1, 0x400, Lifespan::at(0), TraceBookmarkType::Note, "c", "m");
        let json = serde_json::to_string(&bm).unwrap();
        let back: TraceBookmark = serde_json::from_str(&json).unwrap();
        assert_eq!(back.key, 1);
        assert_eq!(back.address, 0x400);
    }
}
