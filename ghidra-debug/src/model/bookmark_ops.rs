//! Bookmark operations for trace bookmarks.
//!
//! Ported from Ghidra's `ghidra.trace.model.bookmark.TraceBookmarkOperations`
//! and `TraceBookmarkSpace`.
//!
//! Provides the interface for operating on bookmarks in a trace through
//! typed queries.

use serde::{Deserialize, Serialize};

use super::bookmark::{TraceBookmark, TraceBookmarkType};
use super::Lifespan;

/// Operations for adding and retrieving bookmarks in a trace.
///
/// Ported from Ghidra's `TraceBookmarkOperations` interface.
pub trait TraceBookmarkOperations {
    /// Get all the categories used for a given type.
    fn get_categories_for_type(&self, bookmark_type: TraceBookmarkType) -> Vec<String>;

    /// Add a bookmark at the given location.
    fn add_bookmark(
        &mut self,
        lifespan: Lifespan,
        address: u64,
        bookmark_type: TraceBookmarkType,
        category: &str,
        comment: &str,
    ) -> i64;

    /// Get all bookmarks.
    fn get_all_bookmarks(&self) -> Vec<&TraceBookmark>;

    /// Get bookmarks at a specific snap and address.
    fn get_bookmarks_at(&self, snap: i64, address: u64) -> Vec<&TraceBookmark>;

    /// Get bookmarks enclosed within the given lifespan and address range.
    fn get_bookmarks_enclosed(
        &self,
        span: &Lifespan,
        min_address: u64,
        max_address: u64,
    ) -> Vec<&TraceBookmark>;

    /// Get bookmarks intersecting the given lifespan and address range.
    fn get_bookmarks_intersecting(
        &self,
        span: &Lifespan,
        min_address: u64,
        max_address: u64,
    ) -> Vec<&TraceBookmark>;
}

/// A bookmark space that ties bookmark operations to a specific address space.
///
/// Ported from Ghidra's `TraceBookmarkSpace` interface.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceBookmarkSpace {
    /// The address space this bookmark space operates on.
    pub address_space: String,
    /// The bookmarks in this space.
    pub bookmarks: Vec<TraceBookmark>,
    /// Next available bookmark key.
    pub next_key: i64,
}

impl TraceBookmarkSpace {
    /// Create a new bookmark space for the given address space.
    pub fn new(address_space: impl Into<String>) -> Self {
        Self {
            address_space: address_space.into(),
            bookmarks: Vec::new(),
            next_key: 1,
        }
    }

    /// Get the address space name.
    pub fn address_space(&self) -> &str {
        &self.address_space
    }

    /// Get the number of bookmarks.
    pub fn len(&self) -> usize {
        self.bookmarks.len()
    }

    /// Whether this space has no bookmarks.
    pub fn is_empty(&self) -> bool {
        self.bookmarks.is_empty()
    }

    /// Add a bookmark and return its key.
    pub fn insert_bookmark(&mut self, mut bookmark: TraceBookmark) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        bookmark.key = key;
        self.bookmarks.push(bookmark);
        key
    }

    /// Remove a bookmark by key.
    pub fn remove_bookmark(&mut self, key: i64) -> Option<TraceBookmark> {
        if let Some(pos) = self.bookmarks.iter().position(|b| b.key == key) {
            Some(self.bookmarks.remove(pos))
        } else {
            None
        }
    }

    /// Get a bookmark by key.
    pub fn get_bookmark(&self, key: i64) -> Option<&TraceBookmark> {
        self.bookmarks.iter().find(|b| b.key == key)
    }
}

impl TraceBookmarkOperations for TraceBookmarkSpace {
    fn get_categories_for_type(&self, bookmark_type: TraceBookmarkType) -> Vec<String> {
        let mut categories: Vec<String> = self
            .bookmarks
            .iter()
            .filter(|b| b.bookmark_type == bookmark_type)
            .map(|b| b.category.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        categories.sort();
        categories
    }

    fn add_bookmark(
        &mut self,
        lifespan: Lifespan,
        address: u64,
        bookmark_type: TraceBookmarkType,
        category: &str,
        comment: &str,
    ) -> i64 {
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
        key
    }

    fn get_all_bookmarks(&self) -> Vec<&TraceBookmark> {
        self.bookmarks.iter().collect()
    }

    fn get_bookmarks_at(&self, snap: i64, address: u64) -> Vec<&TraceBookmark> {
        self.bookmarks
            .iter()
            .filter(|b| b.address == address && b.lifespan.contains(snap))
            .collect()
    }

    fn get_bookmarks_enclosed(
        &self,
        span: &Lifespan,
        min_address: u64,
        max_address: u64,
    ) -> Vec<&TraceBookmark> {
        self.bookmarks
            .iter()
            .filter(|b| {
                b.lifespan.encloses(span)
                    && b.address >= min_address
                    && b.address <= max_address
            })
            .collect()
    }

    fn get_bookmarks_intersecting(
        &self,
        span: &Lifespan,
        min_address: u64,
        max_address: u64,
    ) -> Vec<&TraceBookmark> {
        self.bookmarks
            .iter()
            .filter(|b| {
                b.lifespan.intersects(span)
                    && b.address >= min_address
                    && b.address <= max_address
            })
            .collect()
    }
}

/// A bookmark manager that holds multiple bookmark spaces.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceBookmarkSpaceManager {
    /// The bookmark spaces by address space name.
    pub spaces: std::collections::HashMap<String, TraceBookmarkSpace>,
}

impl TraceBookmarkSpaceManager {
    /// Create a new bookmark space manager.
    pub fn new() -> Self {
        Self {
            spaces: std::collections::HashMap::new(),
        }
    }

    /// Get or create a bookmark space.
    pub fn get_or_create_space(&mut self, space: &str) -> &mut TraceBookmarkSpace {
        self.spaces
            .entry(space.to_string())
            .or_insert_with(|| TraceBookmarkSpace::new(space))
    }

    /// Get a bookmark space.
    pub fn get_space(&self, space: &str) -> Option<&TraceBookmarkSpace> {
        self.spaces.get(space)
    }

    /// Add a bookmark to the appropriate space.
    pub fn add_bookmark(
        &mut self,
        address_space: &str,
        lifespan: Lifespan,
        address: u64,
        bookmark_type: TraceBookmarkType,
        category: &str,
        comment: &str,
    ) -> i64 {
        self.get_or_create_space(address_space)
            .add_bookmark(lifespan, address, bookmark_type, category, comment)
    }

    /// Get all bookmarks across all spaces.
    pub fn get_all_bookmarks(&self) -> Vec<&TraceBookmark> {
        self.spaces.values().flat_map(|s| s.bookmarks.iter()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bookmark_space_basic() {
        let space = TraceBookmarkSpace::new("ram");
        assert_eq!(space.address_space(), "ram");
        assert!(space.is_empty());
    }

    #[test]
    fn test_bookmark_space_add_remove() {
        let mut space = TraceBookmarkSpace::new("ram");
        let key = space.add_bookmark(
            Lifespan::span(0, 10),
            0x1000,
            TraceBookmarkType::Note,
            "test",
            "A test bookmark",
        );
        assert_eq!(key, 1);
        assert_eq!(space.len(), 1);

        let removed = space.remove_bookmark(key);
        assert!(removed.is_some());
        assert!(space.is_empty());
    }

    #[test]
    fn test_bookmark_space_queries() {
        let mut space = TraceBookmarkSpace::new("ram");
        space.add_bookmark(
            Lifespan::span(0, 10),
            0x1000,
            TraceBookmarkType::Note,
            "notes",
            "First",
        );
        space.add_bookmark(
            Lifespan::span(0, 10),
            0x2000,
            TraceBookmarkType::Warning,
            "warnings",
            "Second",
        );
        space.add_bookmark(
            Lifespan::span(5, 15),
            0x1000,
            TraceBookmarkType::Error,
            "errors",
            "Third",
        );

        assert_eq!(space.get_bookmarks_at(5, 0x1000).len(), 2);
        assert_eq!(space.get_bookmarks_at(12, 0x1000).len(), 1);
        assert_eq!(space.get_bookmarks_at(0, 0x2000).len(), 1);
    }

    #[test]
    fn test_bookmark_categories() {
        let mut space = TraceBookmarkSpace::new("ram");
        space.add_bookmark(
            Lifespan::span(0, 10),
            0x1000,
            TraceBookmarkType::Note,
            "cat_a",
            "First",
        );
        space.add_bookmark(
            Lifespan::span(0, 10),
            0x2000,
            TraceBookmarkType::Note,
            "cat_b",
            "Second",
        );
        space.add_bookmark(
            Lifespan::span(0, 10),
            0x3000,
            TraceBookmarkType::Warning,
            "cat_c",
            "Third",
        );

        let mut note_cats = space.get_categories_for_type(TraceBookmarkType::Note);
        note_cats.sort();
        assert_eq!(note_cats, vec!["cat_a", "cat_b"]);
    }

    #[test]
    fn test_bookmark_intersecting() {
        let mut space = TraceBookmarkSpace::new("ram");
        space.add_bookmark(
            Lifespan::span(0, 10),
            0x1000,
            TraceBookmarkType::Note,
            "c",
            "msg",
        );
        space.add_bookmark(
            Lifespan::span(0, 10),
            0x3000,
            TraceBookmarkType::Note,
            "c",
            "msg",
        );

        let result = space.get_bookmarks_intersecting(&Lifespan::span(5, 15), 0x500, 0x2000);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_bookmark_space_manager() {
        let mut mgr = TraceBookmarkSpaceManager::new();
        mgr.add_bookmark(
            "ram",
            Lifespan::span(0, 10),
            0x1000,
            TraceBookmarkType::Note,
            "cat",
            "msg",
        );
        mgr.add_bookmark(
            "register",
            Lifespan::span(0, 10),
            0,
            TraceBookmarkType::Warning,
            "cat",
            "msg",
        );

        assert_eq!(mgr.get_all_bookmarks().len(), 2);
        assert!(mgr.get_space("ram").is_some());
        assert!(mgr.get_space("register").is_some());
    }
}
