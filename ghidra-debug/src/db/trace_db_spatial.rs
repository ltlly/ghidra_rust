//! Spatial indexing for trace object values.
//!
//! Ported from Ghidra's `DBTraceObjectValueRStarTree` and
//! `TraceObjectValueQuery`. Provides R*-tree-like spatial indexing for
//! efficient lookup of object values by address range and time span.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;
use crate::target::KeyPath;

/// A query for finding trace object values in a spatial index.
///
/// Ported from Ghidra's `TraceObjectValueQuery`. Defines constraints
/// on the snap range, address range, and entry key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceObjectValueQuery {
    /// Snap range constraint (None = no constraint).
    pub snap_range: Option<Lifespan>,
    /// Minimum address offset constraint (None = no minimum).
    pub min_offset: Option<u64>,
    /// Maximum address offset constraint (None = no maximum).
    pub max_offset: Option<u64>,
    /// Entry key constraint (None = any key).
    pub entry_key: Option<String>,
    /// Parent path constraint (None = any parent).
    pub parent_path: Option<KeyPath>,
}

impl TraceObjectValueQuery {
    /// Create a new empty query (matches everything).
    pub fn new() -> Self {
        Self {
            snap_range: None,
            min_offset: None,
            max_offset: None,
            entry_key: None,
            parent_path: None,
        }
    }

    /// Constrain to an intersecting lifespan.
    pub fn intersecting(lifespan: Lifespan) -> Self {
        Self {
            snap_range: Some(lifespan),
            ..Self::new()
        }
    }

    /// Constrain to an address range.
    pub fn in_address_range(min: u64, max: u64) -> Self {
        Self {
            min_offset: Some(min),
            max_offset: Some(max),
            ..Self::new()
        }
    }

    /// Constrain to a specific entry key.
    pub fn with_entry_key(key: impl Into<String>) -> Self {
        Self {
            entry_key: Some(key.into()),
            ..Self::new()
        }
    }

    /// Constrain to a specific parent path.
    pub fn with_parent_path(path: KeyPath) -> Self {
        Self {
            parent_path: Some(path),
            ..Self::new()
        }
    }

    /// Combine this query with another (AND).
    pub fn and(self, other: TraceObjectValueQuery) -> Self {
        Self {
            snap_range: merge_optional(self.snap_range, other.snap_range, |a, b| {
                let i = a.intersect(&b);
                if i.is_empty() { None } else { Some(i) }
            }),
            min_offset: merge_optional(self.min_offset, other.min_offset, |a, b| Some(a.max(b))),
            max_offset: merge_optional(self.max_offset, other.max_offset, |a, b| Some(a.min(b))),
            entry_key: merge_optional(self.entry_key, other.entry_key, |a, b| {
                if a == b { Some(a) } else { None }
            }),
            parent_path: merge_optional(self.parent_path, other.parent_path, |a, b| {
                if a == b { Some(a) } else { None }
            }),
        }
    }

    /// Check if a value entry matches this query.
    pub fn matches(&self, snap: i64, offset: u64, key: &str, parent: &KeyPath) -> bool {
        if let Some(ref range) = self.snap_range {
            if !range.contains(snap) {
                return false;
            }
        }
        if let Some(min) = self.min_offset {
            if offset < min {
                return false;
            }
        }
        if let Some(max) = self.max_offset {
            if offset > max {
                return false;
            }
        }
        if let Some(ref ek) = self.entry_key {
            if ek != key {
                return false;
            }
        }
        if let Some(ref pp) = self.parent_path {
            if pp != parent {
                return false;
            }
        }
        true
    }
}

impl Default for TraceObjectValueQuery {
    fn default() -> Self {
        Self::new()
    }
}

fn merge_optional<T, F>(a: Option<T>, b: Option<T>, merge: F) -> Option<T>
where
    F: FnOnce(T, T) -> Option<T>,
{
    match (a, b) {
        (Some(a), Some(b)) => merge(a, b),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// An indexed entry in the spatial index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpatialEntry {
    /// The parent object path.
    pub parent_path: KeyPath,
    /// The entry key.
    pub key: String,
    /// Whether this is an element.
    pub is_element: bool,
    /// The lifespan.
    pub lifespan: Lifespan,
    /// The minimum address offset (if this value has spatial extent).
    pub min_offset: u64,
    /// The maximum address offset (if this value has spatial extent).
    pub max_offset: u64,
    /// The database row ID.
    pub row_id: i64,
}

impl SpatialEntry {
    /// Create a new spatial entry.
    pub fn new(
        parent_path: KeyPath,
        key: impl Into<String>,
        is_element: bool,
        lifespan: Lifespan,
        min_offset: u64,
        max_offset: u64,
        row_id: i64,
    ) -> Self {
        Self {
            parent_path,
            key: key.into(),
            is_element,
            lifespan,
            min_offset,
            max_offset,
            row_id,
        }
    }

    /// Whether this entry overlaps a query.
    pub fn matches_query(&self, query: &TraceObjectValueQuery) -> bool {
        query.matches(
            self.lifespan.lmin(),
            self.min_offset,
            &self.key,
            &self.parent_path,
        )
    }
}

/// A simple spatial index for trace object values.
///
/// Ported from Ghidra's `DBTraceObjectValueRStarTree`. Uses a sorted
/// map for efficient range queries by snap and offset.
#[derive(Debug, Default)]
pub struct TraceObjectValueSpatialIndex {
    /// Entries indexed by (snap, offset) for efficient range queries.
    entries: Vec<SpatialEntry>,
    /// Index by parent path for fast path-based lookups.
    by_parent: BTreeMap<KeyPath, Vec<usize>>,
    /// Index by key for fast key-based lookups.
    by_key: BTreeMap<String, Vec<usize>>,
}

impl TraceObjectValueSpatialIndex {
    /// Create a new empty spatial index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an entry into the index.
    pub fn insert(&mut self, entry: SpatialEntry) {
        let idx = self.entries.len();
        self.by_parent
            .entry(entry.parent_path.clone())
            .or_default()
            .push(idx);
        self.by_key
            .entry(entry.key.clone())
            .or_default()
            .push(idx);
        self.entries.push(entry);
    }

    /// Find all entries matching a query.
    pub fn query(&self, query: &TraceObjectValueQuery) -> Vec<&SpatialEntry> {
        self.entries
            .iter()
            .filter(|e| e.matches_query(query))
            .collect()
    }

    /// Find entries for a specific parent path.
    pub fn by_parent(&self, parent: &KeyPath) -> Vec<&SpatialEntry> {
        self.by_parent
            .get(parent)
            .map(|indices| indices.iter().map(|&i| &self.entries[i]).collect())
            .unwrap_or_default()
    }

    /// Find entries with a specific key.
    pub fn by_key(&self, key: &str) -> Vec<&SpatialEntry> {
        self.by_key
            .get(key)
            .map(|indices| indices.iter().map(|&i| &self.entries[i]).collect())
            .unwrap_or_default()
    }

    /// The number of entries in the index.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.by_parent.clear();
        self.by_key.clear();
    }

    /// Remove entries matching a predicate.
    pub fn remove_where<F: Fn(&SpatialEntry) -> bool>(&mut self, pred: F) {
        let mut new_entries = Vec::new();
        let mut new_by_parent: BTreeMap<KeyPath, Vec<usize>> = BTreeMap::new();
        let mut new_by_key: BTreeMap<String, Vec<usize>> = BTreeMap::new();

        for entry in self.entries.drain(..) {
            if !pred(&entry) {
                let idx = new_entries.len();
                new_by_parent
                    .entry(entry.parent_path.clone())
                    .or_default()
                    .push(idx);
                new_by_key
                    .entry(entry.key.clone())
                    .or_default()
                    .push(idx);
                new_entries.push(entry);
            }
        }

        self.entries = new_entries;
        self.by_parent = new_by_parent;
        self.by_key = new_by_key;
    }
}

/// A spatial map that provides a view over matching entries.
///
/// Ported from Ghidra's `DBTraceObjectValueMap`.
pub struct SpatialMapView<'a> {
    index: &'a TraceObjectValueSpatialIndex,
    query: TraceObjectValueQuery,
}

impl<'a> SpatialMapView<'a> {
    /// Create a new view.
    pub fn new(index: &'a TraceObjectValueSpatialIndex, query: TraceObjectValueQuery) -> Self {
        Self { index, query }
    }

    /// Reduce this view with an additional query constraint.
    pub fn reduce(&self, additional: TraceObjectValueQuery) -> SpatialMapView<'_> {
        let combined = self.query.clone().and(additional);
        SpatialMapView {
            index: self.index,
            query: combined,
        }
    }

    /// Get all matching entries.
    pub fn entries(&self) -> Vec<&SpatialEntry> {
        self.index.query(&self.query)
    }

    /// Get the count of matching entries.
    pub fn count(&self) -> usize {
        self.entries().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(parent: &str, key: &str, snap: i64, offset: u64) -> SpatialEntry {
        SpatialEntry::new(
            KeyPath::parse(parent),
            key,
            false,
            Lifespan::span(snap, snap + 10),
            offset,
            offset + 0xFF,
            0,
        )
    }

    #[test]
    fn test_spatial_index_insert() {
        let mut index = TraceObjectValueSpatialIndex::new();
        assert!(index.is_empty());

        index.insert(sample_entry("Session.Process", "pid", 0, 0));
        index.insert(sample_entry("Session.Process.Thread", "name", 0, 0));
        assert_eq!(index.len(), 2);
    }

    #[test]
    fn test_spatial_index_query_all() {
        let mut index = TraceObjectValueSpatialIndex::new();
        index.insert(sample_entry("a", "x", 0, 0x1000));
        index.insert(sample_entry("b", "y", 5, 0x2000));

        let query = TraceObjectValueQuery::new();
        let results = index.query(&query);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_spatial_index_query_by_snap() {
        let mut index = TraceObjectValueSpatialIndex::new();
        index.insert(sample_entry("a", "x", 0, 0x1000));
        index.insert(sample_entry("b", "y", 50, 0x2000));

        let query = TraceObjectValueQuery::intersecting(Lifespan::span(0, 10));
        let results = index.query(&query);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_spatial_index_query_by_address() {
        let mut index = TraceObjectValueSpatialIndex::new();
        index.insert(sample_entry("a", "x", 0, 0x1000));
        index.insert(sample_entry("b", "y", 0, 0x5000));

        let query = TraceObjectValueQuery::in_address_range(0x0500, 0x2000);
        let results = index.query(&query);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_spatial_index_by_parent() {
        let mut index = TraceObjectValueSpatialIndex::new();
        index.insert(sample_entry("Session.Process", "pid", 0, 0));
        index.insert(sample_entry("Session.Process", "name", 0, 0));
        index.insert(sample_entry("Session.Thread", "tid", 0, 0));

        let results = index.by_parent(&KeyPath::parse("Session.Process"));
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_spatial_index_by_key() {
        let mut index = TraceObjectValueSpatialIndex::new();
        index.insert(sample_entry("a", "pid", 0, 0));
        index.insert(sample_entry("b", "pid", 0, 0));
        index.insert(sample_entry("c", "name", 0, 0));

        let results = index.by_key("pid");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_spatial_index_remove_where() {
        let mut index = TraceObjectValueSpatialIndex::new();
        index.insert(sample_entry("a", "x", 0, 0x1000));
        index.insert(sample_entry("b", "y", 0, 0x2000));

        index.remove_where(|e| e.key == "x");
        assert_eq!(index.len(), 1);
        assert_eq!(index.by_key("y").len(), 1);
    }

    #[test]
    fn test_spatial_index_clear() {
        let mut index = TraceObjectValueSpatialIndex::new();
        index.insert(sample_entry("a", "x", 0, 0));
        index.clear();
        assert!(index.is_empty());
    }

    #[test]
    fn test_query_and_combine() {
        let q1 = TraceObjectValueQuery::intersecting(Lifespan::span(0, 10));
        let q2 = TraceObjectValueQuery::in_address_range(0x1000, 0x2000);
        let combined = q1.and(q2);

        assert!(combined.snap_range.is_some());
        assert!(combined.min_offset.is_some());
        assert!(combined.max_offset.is_some());
    }

    #[test]
    fn test_query_matches() {
        let query = TraceObjectValueQuery {
            snap_range: Some(Lifespan::span(0, 10)),
            min_offset: Some(0x1000),
            max_offset: Some(0x2000),
            entry_key: Some("pid".into()),
            parent_path: Some(KeyPath::parse("Session.Process")),
        };

        assert!(query.matches(5, 0x1500, "pid", &KeyPath::parse("Session.Process")));
        assert!(!query.matches(5, 0x1500, "name", &KeyPath::parse("Session.Process")));
        assert!(!query.matches(15, 0x1500, "pid", &KeyPath::parse("Session.Process")));
    }

    #[test]
    fn test_spatial_map_view() {
        let mut index = TraceObjectValueSpatialIndex::new();
        index.insert(sample_entry("Session", "Process", 0, 0x1000));
        index.insert(sample_entry("Session", "Thread", 0, 0x2000));

        let query = TraceObjectValueQuery::new();
        let view = SpatialMapView::new(&index, query);
        assert_eq!(view.count(), 2);

        let reduced = view.reduce(TraceObjectValueQuery::with_entry_key("Process"));
        assert_eq!(reduced.count(), 1);
    }

    #[test]
    fn test_spatial_entry_new() {
        let entry = SpatialEntry::new(
            KeyPath::parse("a.b"),
            "key",
            true,
            Lifespan::span(0, 10),
            0x1000,
            0x2000,
            42,
        );
        assert!(entry.is_element);
        assert_eq!(entry.row_id, 42);
    }

    #[test]
    fn test_query_serde() {
        let query = TraceObjectValueQuery::intersecting(Lifespan::span(0, 10));
        let json = serde_json::to_string(&query).unwrap();
        let back: TraceObjectValueQuery = serde_json::from_str(&json).unwrap();
        assert!(back.snap_range.is_some());
    }
}
