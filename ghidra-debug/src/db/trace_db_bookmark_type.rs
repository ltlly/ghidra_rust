//! Database-backed bookmark type implementation.
//!
//! Ported from Ghidra's `ghidra.trace.database.bookmark.DBTraceBookmarkType`.
//! Represents a bookmark category with visual properties (color, priority, icon).


/// A bookmark type in the database-backed trace.
///
/// Corresponds to Java's `DBTraceBookmarkType`. Each bookmark type
/// defines a category (e.g., "Analysis", "Warning", "Error") with
/// visual properties for rendering in the UI.
#[derive(Debug, Clone)]
pub struct DbTraceBookmarkType {
    /// Unique type identifier.
    pub type_id: u32,
    /// The type string (category name).
    pub type_string: String,
    /// Marker color as ARGB value.
    pub marker_color: u32,
    /// Marker priority for overlapping markers (higher = on top).
    pub marker_priority: i32,
    /// Categories this bookmark type belongs to.
    pub categories: Vec<String>,
    /// Internal bookmark IDs belonging to this type.
    bookmark_ids: Vec<u64>,
}

impl DbTraceBookmarkType {
    /// Create a new bookmark type.
    pub fn new(type_id: u32, type_string: impl Into<String>) -> Self {
        Self {
            type_id,
            type_string: type_string.into(),
            marker_color: 0xFF000000, // Black default
            marker_priority: 0,
            categories: Vec::new(),
            bookmark_ids: Vec::new(),
        }
    }

    /// Create a new bookmark type with full configuration.
    pub fn with_config(
        type_id: u32,
        type_string: impl Into<String>,
        marker_color: u32,
        marker_priority: i32,
        categories: Vec<String>,
    ) -> Self {
        Self {
            type_id,
            type_string: type_string.into(),
            marker_color,
            marker_priority,
            categories,
            bookmark_ids: Vec::new(),
        }
    }

    /// Get the type string (category name).
    pub fn get_type_string(&self) -> &str {
        &self.type_string
    }

    /// Get the type identifier.
    pub fn get_type_id(&self) -> u32 {
        self.type_id
    }

    /// Get the marker color.
    pub fn get_marker_color(&self) -> u32 {
        self.marker_color
    }

    /// Set the marker color.
    pub fn set_marker_color(&mut self, color: u32) {
        self.marker_color = color;
    }

    /// Get the marker priority.
    pub fn get_marker_priority(&self) -> i32 {
        self.marker_priority
    }

    /// Set the marker priority.
    pub fn set_marker_priority(&mut self, priority: i32) {
        self.marker_priority = priority;
    }

    /// Get the categories.
    pub fn get_categories(&self) -> &[String] {
        &self.categories
    }

    /// Add a category.
    pub fn add_category(&mut self, category: impl Into<String>) {
        let c = category.into();
        if !self.categories.contains(&c) {
            self.categories.push(c);
        }
    }

    /// Check if this type has any bookmarks.
    pub fn has_bookmarks(&self) -> bool {
        !self.bookmark_ids.is_empty()
    }

    /// Get the number of bookmarks of this type.
    pub fn count_bookmarks(&self) -> usize {
        self.bookmark_ids.len()
    }

    /// Register a bookmark ID with this type.
    pub fn add_bookmark_id(&mut self, id: u64) {
        if !self.bookmark_ids.contains(&id) {
            self.bookmark_ids.push(id);
        }
    }

    /// Remove a bookmark ID from this type.
    pub fn remove_bookmark_id(&mut self, id: u64) {
        self.bookmark_ids.retain(|&x| x != id);
    }

    /// Get the list of bookmark IDs.
    pub fn bookmark_ids(&self) -> &[u64] {
        &self.bookmark_ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bookmark_type_new() {
        let bt = DbTraceBookmarkType::new(1, "Analysis");
        assert_eq!(bt.get_type_id(), 1);
        assert_eq!(bt.get_type_string(), "Analysis");
        assert_eq!(bt.get_marker_color(), 0xFF000000);
        assert_eq!(bt.get_marker_priority(), 0);
        assert!(bt.categories.is_empty());
    }

    #[test]
    fn test_bookmark_type_with_config() {
        let bt = DbTraceBookmarkType::with_config(
            2,
            "Warning",
            0xFFFF0000,
            10,
            vec!["Alerts".to_string()],
        );
        assert_eq!(bt.get_marker_color(), 0xFFFF0000);
        assert_eq!(bt.get_marker_priority(), 10);
        assert_eq!(bt.get_categories(), &["Alerts"]);
    }

    #[test]
    fn test_bookmark_type_set_color() {
        let mut bt = DbTraceBookmarkType::new(1, "Test");
        bt.set_marker_color(0xFF00FF00);
        assert_eq!(bt.get_marker_color(), 0xFF00FF00);
    }

    #[test]
    fn test_bookmark_type_set_priority() {
        let mut bt = DbTraceBookmarkType::new(1, "Test");
        bt.set_marker_priority(5);
        assert_eq!(bt.get_marker_priority(), 5);
    }

    #[test]
    fn test_bookmark_type_categories() {
        let mut bt = DbTraceBookmarkType::new(1, "Test");
        bt.add_category("cat1");
        bt.add_category("cat2");
        bt.add_category("cat1"); // Duplicate
        assert_eq!(bt.get_categories().len(), 2);
    }

    #[test]
    fn test_bookmark_type_bookmark_counting() {
        let mut bt = DbTraceBookmarkType::new(1, "Test");
        assert!(!bt.has_bookmarks());
        assert_eq!(bt.count_bookmarks(), 0);

        bt.add_bookmark_id(100);
        bt.add_bookmark_id(200);
        assert!(bt.has_bookmarks());
        assert_eq!(bt.count_bookmarks(), 2);
    }

    #[test]
    fn test_bookmark_type_remove_bookmark() {
        let mut bt = DbTraceBookmarkType::new(1, "Test");
        bt.add_bookmark_id(100);
        bt.add_bookmark_id(200);
        bt.remove_bookmark_id(100);
        assert_eq!(bt.count_bookmarks(), 1);
        assert_eq!(bt.bookmark_ids(), &[200]);
    }

    #[test]
    fn test_bookmark_type_no_duplicate_ids() {
        let mut bt = DbTraceBookmarkType::new(1, "Test");
        bt.add_bookmark_id(100);
        bt.add_bookmark_id(100);
        assert_eq!(bt.count_bookmarks(), 1);
    }
}
