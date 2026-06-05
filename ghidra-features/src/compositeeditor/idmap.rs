//! ID mapping database for composite editor view/program data type correspondence.
//!
//! Ported from `ghidra.app.plugin.core.compositeeditor.IDMapDB`.
//!
//! Provides a bidirectional map for tracking view-to-from original data type ID
//! correspondence and facilitating recovery across undo/redo of the view's
//! data type manager.

use std::collections::HashMap;

/// A bidirectional map for tracking data type ID correspondence between
/// the composite editor view and the original data type manager.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.IDMapDB`.
///
/// When a composite type is opened for editing, a copy of it is placed
/// in a temporary "view" data type manager. The IDs in the view differ
/// from those in the original program's data type manager. This map
/// tracks the correspondence so changes in the view can be applied back.
#[derive(Debug, Clone)]
pub struct IdMapDb {
    /// Forward map: view data type ID -> original data type ID.
    view_to_original: HashMap<i64, i64>,
    /// Reverse map: original data type ID -> view data type ID.
    original_to_view: HashMap<i64, i64>,
}

impl IdMapDb {
    /// Create a new empty ID map.
    pub fn new() -> Self {
        Self {
            view_to_original: HashMap::new(),
            original_to_view: HashMap::new(),
        }
    }

    /// Insert a mapping between a view ID and an original ID.
    ///
    /// If the view_id was previously mapped to a different original_id,
    /// the old reverse mapping is removed. Similarly, if the original_id
    /// was previously mapped to a different view_id, the old forward
    /// mapping is removed.
    pub fn put(&mut self, view_id: i64, original_id: i64) {
        // Remove old reverse mapping if view_id was previously mapped
        if let Some(old_original) = self.view_to_original.get(&view_id).copied() {
            if old_original != original_id {
                self.original_to_view.remove(&old_original);
            }
        }
        // Remove old forward mapping if original_id was previously mapped
        if let Some(old_view) = self.original_to_view.get(&original_id).copied() {
            if old_view != view_id {
                self.view_to_original.remove(&old_view);
            }
        }
        self.view_to_original.insert(view_id, original_id);
        self.original_to_view.insert(original_id, view_id);
    }

    /// Get the original data type ID given a view data type ID.
    pub fn get_original_id(&self, view_id: i64) -> Option<i64> {
        self.view_to_original.get(&view_id).copied()
    }

    /// Get the view data type ID given an original data type ID.
    pub fn get_view_id(&self, original_id: i64) -> Option<i64> {
        self.original_to_view.get(&original_id).copied()
    }

    /// Remove a mapping by view ID.
    pub fn remove_by_view_id(&mut self, view_id: i64) {
        if let Some(orig) = self.view_to_original.remove(&view_id) {
            self.original_to_view.remove(&orig);
        }
    }

    /// Remove a mapping by original ID.
    pub fn remove_by_original_id(&mut self, original_id: i64) {
        if let Some(view) = self.original_to_view.remove(&original_id) {
            self.view_to_original.remove(&view);
        }
    }

    /// Whether the map contains a mapping for the given view ID.
    pub fn contains_view_id(&self, view_id: i64) -> bool {
        self.view_to_original.contains_key(&view_id)
    }

    /// Whether the map contains a mapping for the given original ID.
    pub fn contains_original_id(&self, original_id: i64) -> bool {
        self.original_to_view.contains_key(&original_id)
    }

    /// Number of mappings.
    pub fn len(&self) -> usize {
        self.view_to_original.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.view_to_original.is_empty()
    }

    /// Clear all mappings.
    pub fn clear(&mut self) {
        self.view_to_original.clear();
        self.original_to_view.clear();
    }

    /// Get all view IDs.
    pub fn view_ids(&self) -> Vec<i64> {
        self.view_to_original.keys().copied().collect()
    }

    /// Get all original IDs.
    pub fn original_ids(&self) -> Vec<i64> {
        self.original_to_view.keys().copied().collect()
    }
}

impl Default for IdMapDb {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idmap_basic() {
        let mut map = IdMapDb::new();
        assert!(map.is_empty());

        map.put(100, 200);
        assert_eq!(map.len(), 1);
        assert!(!map.is_empty());
    }

    #[test]
    fn test_idmap_bidirectional() {
        let mut map = IdMapDb::new();
        map.put(100, 200);
        map.put(101, 201);

        assert_eq!(map.get_original_id(100), Some(200));
        assert_eq!(map.get_original_id(101), Some(201));
        assert_eq!(map.get_view_id(200), Some(100));
        assert_eq!(map.get_view_id(201), Some(101));
    }

    #[test]
    fn test_idmap_not_found() {
        let map = IdMapDb::new();
        assert_eq!(map.get_original_id(999), None);
        assert_eq!(map.get_view_id(999), None);
    }

    #[test]
    fn test_idmap_remove_by_view_id() {
        let mut map = IdMapDb::new();
        map.put(100, 200);
        map.remove_by_view_id(100);

        assert!(map.is_empty());
        assert_eq!(map.get_original_id(100), None);
        assert_eq!(map.get_view_id(200), None);
    }

    #[test]
    fn test_idmap_remove_by_original_id() {
        let mut map = IdMapDb::new();
        map.put(100, 200);
        map.remove_by_original_id(200);

        assert!(map.is_empty());
        assert_eq!(map.get_original_id(100), None);
        assert_eq!(map.get_view_id(200), None);
    }

    #[test]
    fn test_idmap_contains() {
        let mut map = IdMapDb::new();
        map.put(100, 200);

        assert!(map.contains_view_id(100));
        assert!(map.contains_original_id(200));
        assert!(!map.contains_view_id(999));
        assert!(!map.contains_original_id(999));
    }

    #[test]
    fn test_idmap_clear() {
        let mut map = IdMapDb::new();
        map.put(1, 2);
        map.put(3, 4);
        assert_eq!(map.len(), 2);

        map.clear();
        assert!(map.is_empty());
    }

    #[test]
    fn test_idmap_overwrite() {
        let mut map = IdMapDb::new();
        map.put(100, 200);
        map.put(100, 300); // overwrite view_id 100

        assert_eq!(map.get_original_id(100), Some(300));
        assert_eq!(map.get_view_id(300), Some(100));
        // Old reverse mapping should be gone
        assert_eq!(map.get_view_id(200), None);
    }

    #[test]
    fn test_idmap_view_and_original_ids() {
        let mut map = IdMapDb::new();
        map.put(10, 20);
        map.put(30, 40);

        let mut vids = map.view_ids();
        vids.sort();
        assert_eq!(vids, vec![10, 30]);

        let mut oids = map.original_ids();
        oids.sort();
        assert_eq!(oids, vec![20, 40]);
    }
}
