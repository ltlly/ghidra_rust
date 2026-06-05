//! R*-tree spatial indexing for trace objects.
//!
//! Ported from Ghidra's `DBTraceObjectValueRStarTree`.
//!
//! Provides a simplified R*-tree implementation for spatial indexing
//! of trace objects that have both address and time (snap) dimensions.

use serde::{Deserialize, Serialize};

/// A rectangle in the (address, snap) 2D space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpatialRect {
    /// Minimum address (x-axis lower bound).
    pub min_addr: u64,
    /// Maximum address (x-axis upper bound).
    pub max_addr: u64,
    /// Minimum snap (y-axis lower bound).
    pub min_snap: i64,
    /// Maximum snap (y-axis upper bound).
    pub max_snap: i64,
}

impl SpatialRect {
    /// Create a new spatial rectangle.
    pub fn new(min_addr: u64, max_addr: u64, min_snap: i64, max_snap: i64) -> Self {
        Self {
            min_addr,
            max_addr,
            min_snap,
            max_snap,
        }
    }

    /// Create a point rectangle.
    pub fn point(addr: u64, snap: i64) -> Self {
        Self {
            min_addr: addr,
            max_addr: addr,
            min_snap: snap,
            max_snap: snap,
        }
    }

    /// Compute the area of this rectangle (as a product of side lengths).
    pub fn area(&self) -> u128 {
        let dx = (self.max_addr as u128) - (self.min_addr as u128);
        let dy = (self.max_snap as u128) - (self.min_snap as u128);
        dx * dy
    }

    /// Check if this rectangle contains a point.
    pub fn contains_point(&self, addr: u64, snap: i64) -> bool {
        addr >= self.min_addr && addr <= self.max_addr && snap >= self.min_snap && snap <= self.max_snap
    }

    /// Check if this rectangle intersects another rectangle.
    pub fn intersects(&self, other: &SpatialRect) -> bool {
        self.min_addr <= other.max_addr
            && self.max_addr >= other.min_addr
            && self.min_snap <= other.max_snap
            && self.max_snap >= other.min_snap
    }

    /// Compute the minimum bounding rectangle that contains both rectangles.
    pub fn merge(&self, other: &SpatialRect) -> SpatialRect {
        SpatialRect {
            min_addr: self.min_addr.min(other.min_addr),
            max_addr: self.max_addr.max(other.max_addr),
            min_snap: self.min_snap.min(other.min_snap),
            max_snap: self.max_snap.max(other.max_snap),
        }
    }

    /// Compute the intersection with another rectangle, if any.
    pub fn intersection(&self, other: &SpatialRect) -> Option<SpatialRect> {
        if !self.intersects(other) {
            return None;
        }
        Some(SpatialRect {
            min_addr: self.min_addr.max(other.min_addr),
            max_addr: self.max_addr.min(other.max_addr),
            min_snap: self.min_snap.max(other.min_snap),
            max_snap: self.max_snap.min(other.max_snap),
        })
    }

    /// Compute how much area would be added if this rectangle were merged with another.
    pub fn enlargement_area(&self, other: &SpatialRect) -> u128 {
        self.merge(other).area() - self.area()
    }
}

/// An entry in the R*-tree: a bounding box paired with an object key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RStarEntry<K> {
    /// The bounding rectangle.
    pub bounds: SpatialRect,
    /// The key identifying the stored object.
    pub key: K,
}

impl<K> RStarEntry<K> {
    /// Create a new R*-tree entry.
    pub fn new(bounds: SpatialRect, key: K) -> Self {
        Self { bounds, key }
    }
}

/// A simple R*-tree for spatial querying of trace objects.
///
/// This is a simplified implementation that stores entries in a flat list
/// and uses brute-force search. For production use, a proper R*-tree
/// with node splitting would be needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RStarTree<K> {
    entries: Vec<RStarEntry<K>>,
    max_entries: usize,
}

impl<K: Clone + std::fmt::Debug> RStarTree<K> {
    /// Create a new empty R*-tree.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            max_entries: 64,
        }
    }

    /// Create a new R*-tree with a specified max entries per node.
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
        }
    }

    /// Insert an entry into the tree.
    pub fn insert(&mut self, entry: RStarEntry<K>) {
        self.entries.push(entry);
    }

    /// Remove an entry matching the given key.
    pub fn remove(&mut self, key: &K) -> bool
    where
        K: PartialEq,
    {
        let before = self.entries.len();
        self.entries.retain(|e| &e.key != key);
        self.entries.len() < before
    }

    /// Get the number of entries in the tree.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Find all entries whose bounds intersect the given rectangle.
    pub fn query_intersecting(&self, rect: &SpatialRect) -> Vec<&RStarEntry<K>> {
        self.entries
            .iter()
            .filter(|e| e.bounds.intersects(rect))
            .collect()
    }

    /// Find all entries whose bounds contain the given point.
    pub fn query_containing_point(&self, addr: u64, snap: i64) -> Vec<&RStarEntry<K>> {
        self.entries
            .iter()
            .filter(|e| e.bounds.contains_point(addr, snap))
            .collect()
    }

    /// Find the entry whose bounds contain the given point and has the smallest area.
    ///
    /// This is useful for finding the most specific match.
    pub fn query_smallest_containing(&self, addr: u64, snap: i64) -> Option<&RStarEntry<K>> {
        self.entries
            .iter()
            .filter(|e| e.bounds.contains_point(addr, snap))
            .min_by_key(|e| e.bounds.area())
    }

    /// Compute the minimum bounding rectangle of all entries.
    pub fn bounds(&self) -> Option<SpatialRect> {
        self.entries
            .first()
            .map(|first| {
                self.entries
                    .iter()
                    .fold(first.bounds.clone(), |acc, e| acc.merge(&e.bounds))
            })
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = &RStarEntry<K>> {
        self.entries.iter()
    }
}

impl<K: Clone + std::fmt::Debug> Default for RStarTree<K> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spatial_rect_creation() {
        let rect = SpatialRect::new(0x1000, 0x2000, 0, 100);
        assert_eq!(rect.min_addr, 0x1000);
        assert_eq!(rect.max_addr, 0x2000);
        assert_eq!(rect.min_snap, 0);
        assert_eq!(rect.max_snap, 100);
    }

    #[test]
    fn test_spatial_rect_point() {
        let point = SpatialRect::point(0x4000, 5);
        assert!(point.contains_point(0x4000, 5));
        assert!(!point.contains_point(0x4001, 5));
        assert_eq!(point.area(), 0);
    }

    #[test]
    fn test_spatial_rect_area() {
        let rect = SpatialRect::new(0, 100, 0, 50);
        assert_eq!(rect.area(), 5000);
    }

    #[test]
    fn test_spatial_rect_intersection() {
        let r1 = SpatialRect::new(0, 100, 0, 50);
        let r2 = SpatialRect::new(50, 150, 25, 75);
        let r3 = SpatialRect::new(200, 300, 0, 50);

        assert!(r1.intersects(&r2));
        assert!(!r1.intersects(&r3));

        let inter = r1.intersection(&r2).unwrap();
        assert_eq!(inter.min_addr, 50);
        assert_eq!(inter.max_addr, 100);
        assert_eq!(inter.min_snap, 25);
        assert_eq!(inter.max_snap, 50);

        assert!(r1.intersection(&r3).is_none());
    }

    #[test]
    fn test_spatial_rect_merge() {
        let r1 = SpatialRect::new(0, 100, 0, 50);
        let r2 = SpatialRect::new(50, 200, 25, 75);

        let merged = r1.merge(&r2);
        assert_eq!(merged.min_addr, 0);
        assert_eq!(merged.max_addr, 200);
        assert_eq!(merged.min_snap, 0);
        assert_eq!(merged.max_snap, 75);
    }

    #[test]
    fn test_spatial_rect_enlargement() {
        let r1 = SpatialRect::new(0, 100, 0, 100);
        let r2 = SpatialRect::new(50, 150, 50, 150);

        let enlargement = r1.enlargement_area(&r2);
        assert!(enlargement > 0);
    }

    #[test]
    fn test_rstar_tree_insert_and_query() {
        let mut tree = RStarTree::<i32>::new();
        tree.insert(RStarEntry::new(
            SpatialRect::new(0x1000, 0x2000, 0, 100),
            1,
        ));
        tree.insert(RStarEntry::new(
            SpatialRect::new(0x3000, 0x4000, 0, 100),
            2,
        ));
        tree.insert(RStarEntry::new(
            SpatialRect::new(0x1500, 0x2500, 50, 150),
            3,
        ));

        assert_eq!(tree.len(), 3);

        // Query intersecting the first two rectangles
        let query_rect = SpatialRect::new(0x1800, 0x1900, 0, 100);
        let results = tree.query_intersecting(&query_rect);
        assert_eq!(results.len(), 2); // entries 1 and 3

        // Query containing a point
        let point_results = tree.query_containing_point(0x1800, 50);
        assert_eq!(point_results.len(), 2); // entries 1 and 3
    }

    #[test]
    fn test_rstar_tree_smallest_containing() {
        let mut tree = RStarTree::<i32>::new();
        tree.insert(RStarEntry::new(
            SpatialRect::new(0, 1000, 0, 1000),
            1,
        ));
        tree.insert(RStarEntry::new(
            SpatialRect::new(100, 200, 10, 20),
            2,
        ));

        let smallest = tree.query_smallest_containing(150, 15);
        assert!(smallest.is_some());
        assert_eq!(smallest.unwrap().key, 2);
    }

    #[test]
    fn test_rstar_tree_remove() {
        let mut tree = RStarTree::<i32>::new();
        tree.insert(RStarEntry::new(
            SpatialRect::new(0, 100, 0, 100),
            1,
        ));
        tree.insert(RStarEntry::new(
            SpatialRect::new(200, 300, 0, 100),
            2,
        ));

        assert!(tree.remove(&1));
        assert_eq!(tree.len(), 1);
        assert!(!tree.remove(&1)); // already removed
        assert!(!tree.remove(&3)); // never existed
    }

    #[test]
    fn test_rstar_tree_bounds() {
        let mut tree = RStarTree::<i32>::new();
        assert!(tree.bounds().is_none());

        tree.insert(RStarEntry::new(
            SpatialRect::new(0x1000, 0x2000, 0, 50),
            1,
        ));
        tree.insert(RStarEntry::new(
            SpatialRect::new(0x3000, 0x4000, 25, 75),
            2,
        ));

        let bounds = tree.bounds().unwrap();
        assert_eq!(bounds.min_addr, 0x1000);
        assert_eq!(bounds.max_addr, 0x4000);
        assert_eq!(bounds.min_snap, 0);
        assert_eq!(bounds.max_snap, 75);
    }

    #[test]
    fn test_rstar_tree_clear() {
        let mut tree = RStarTree::<i32>::new();
        tree.insert(RStarEntry::new(
            SpatialRect::new(0, 100, 0, 100),
            1,
        ));
        assert_eq!(tree.len(), 1);

        tree.clear();
        assert!(tree.is_empty());
    }

    #[test]
    fn test_rstar_tree_iter() {
        let mut tree = RStarTree::<i32>::new();
        tree.insert(RStarEntry::new(
            SpatialRect::new(0, 100, 0, 100),
            1,
        ));
        tree.insert(RStarEntry::new(
            SpatialRect::new(200, 300, 0, 100),
            2,
        ));

        let keys: Vec<i32> = tree.iter().map(|e| e.key).collect();
        assert_eq!(keys, vec![1, 2]);
    }

    #[test]
    fn test_rstar_tree_default() {
        let tree = RStarTree::<String>::default();
        assert!(tree.is_empty());
    }

    #[test]
    fn test_rstar_tree_with_max_entries() {
        let tree = RStarTree::<i32>::with_max_entries(128);
        assert_eq!(tree.max_entries, 128);
    }

    #[test]
    fn test_spatial_rect_serialization() {
        let rect = SpatialRect::new(0x1000, 0x2000, 0, 100);
        let json = serde_json::to_string(&rect).unwrap();
        let deserialized: SpatialRect = serde_json::from_str(&json).unwrap();
        assert_eq!(rect, deserialized);
    }

    #[test]
    fn test_rstar_entry_serialization() {
        let entry = RStarEntry::new(SpatialRect::point(0x4000, 5), "test-key".to_string());
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: RStarEntry<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(entry.key, deserialized.key);
        assert_eq!(entry.bounds, deserialized.bounds);
    }

    #[test]
    fn test_empty_query() {
        let tree = RStarTree::<i32>::new();
        let results = tree.query_intersecting(&SpatialRect::new(0, 100, 0, 100));
        assert!(results.is_empty());

        let point_results = tree.query_containing_point(50, 50);
        assert!(point_results.is_empty());
    }

    #[test]
    fn test_rstar_tree_string_keys() {
        let mut tree = RStarTree::<String>::new();
        tree.insert(RStarEntry::new(
            SpatialRect::new(0x1000, 0x2000, 0, 100),
            "libc.text".to_string(),
        ));
        tree.insert(RStarEntry::new(
            SpatialRect::new(0x3000, 0x4000, 0, 100),
            "libc.data".to_string(),
        ));

        let results = tree.query_containing_point(0x1500, 50);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key, "libc.text");

        assert!(tree.remove(&"libc.text".to_string()));
        assert_eq!(tree.len(), 1);
    }
}
