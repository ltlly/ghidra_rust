//! Extended target object storage types.
//!
//! Ported from Ghidra's `ghidra.trace.database.target` package.
//! Provides the `TraceObjectValueStorage` interface, write-behind cache,
//! and address set view for spatial queries on target object values.

use std::collections::BTreeMap;

use crate::model::lifespan::Lifespan;

/// Interface for storage backends of trace object values.
///
/// Corresponds to Java's `TraceObjectValueStorage`. Provides the contract for
/// how object values are stored, retrieved, and managed in the trace database.
pub trait TraceObjectValueStorage {
    /// Get the parent object of this value entry.
    fn parent_id(&self) -> Option<u64>;

    /// Get the entry key (property name or index).
    fn entry_key(&self) -> &str;

    /// Get the lifespan of this value entry.
    fn lifespan(&self) -> &Lifespan;

    /// Set the lifespan without triggering notifications.
    fn set_lifespan(&mut self, lifespan: Lifespan);

    /// Get the child object ID if this is a relation entry, or `None` for attributes.
    fn child_id(&self) -> Option<u64>;

    /// Whether this entry has been logically deleted.
    fn is_deleted(&self) -> bool;

    /// Mark this entry as deleted.
    fn mark_deleted(&mut self);
}

/// Cached value entry in the write-behind cache.
#[derive(Debug, Clone)]
pub struct CachedValueEntry {
    /// Parent object identifier.
    pub parent_id: u64,
    /// The entry key (property name).
    pub key: String,
    /// The lifespan of this cached entry.
    pub lifespan: Lifespan,
    /// The value stored (as JSON).
    pub value: serde_json::Value,
    /// Whether this is a child relation (true) or attribute (false).
    pub is_relation: bool,
    /// Child object ID if this is a relation.
    pub child_id: Option<u64>,
    /// Whether this entry has been written to the database.
    pub persisted: bool,
}

impl CachedValueEntry {
    /// Mark this entry as persisted.
    pub fn mark_persisted(&mut self) {
        self.persisted = true;
    }

    /// Check if this entry needs to be written.
    pub fn needs_flush(&self) -> bool {
        !self.persisted
    }
}

/// Write-behind cache for trace object values.
///
/// Corresponds to Java's `DBTraceObjectValueWriteBehindCache`. Caches recently
/// written values and batches them for efficient database writes.
#[derive(Debug)]
pub struct ObjectValueWriteBehindCache {
    /// The cache entries indexed by (parent_id, key, snap).
    entries: BTreeMap<(u64, String, i64), CachedValueEntry>,
    /// Maximum number of entries before forced flush.
    max_entries: usize,
    /// Number of entries that need flushing.
    dirty_count: usize,
}

impl ObjectValueWriteBehindCache {
    /// Create a new write-behind cache with the given capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            max_entries,
            dirty_count: 0,
        }
    }

    /// Insert or update a cached value.
    pub fn put(
        &mut self,
        parent_id: u64,
        key: String,
        snap: i64,
        value: serde_json::Value,
        lifespan: Lifespan,
        is_relation: bool,
        child_id: Option<u64>,
    ) {
        let entry = CachedValueEntry {
            parent_id,
            key: key.clone(),
            lifespan,
            value,
            is_relation,
            child_id,
            persisted: false,
        };
        let k = (parent_id, key, snap);
        if !self.entries.contains_key(&k) {
            self.dirty_count += 1;
        }
        self.entries.insert(k, entry);
    }

    /// Get a cached value if present.
    pub fn get(&self, parent_id: u64, key: &str, snap: i64) -> Option<&CachedValueEntry> {
        self.entries.get(&(parent_id, key.to_string(), snap))
    }

    /// Remove a cached entry.
    pub fn remove(&mut self, parent_id: u64, key: &str, snap: i64) -> Option<CachedValueEntry> {
        let k = (parent_id, key.to_string(), snap);
        let entry = self.entries.remove(&k);
        if entry.is_some() {
            self.dirty_count = self.dirty_count.saturating_sub(1);
        }
        entry
    }

    /// Flush all dirty entries: marks them as persisted and returns the count.
    pub fn flush(&mut self) -> usize {
        let mut count = 0;
        for entry in self.entries.values_mut() {
            if entry.needs_flush() {
                entry.mark_persisted();
                count += 1;
            }
        }
        self.dirty_count = 0;
        count
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.dirty_count = 0;
    }

    /// Get the number of dirty (un-persisted) entries.
    pub fn dirty_count(&self) -> usize {
        self.dirty_count
    }

    /// Get the total number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Check if the cache needs flushing.
    pub fn needs_flush(&self) -> bool {
        self.dirty_count > 0
    }

    /// Check if the cache has exceeded its maximum capacity.
    pub fn is_over_capacity(&self) -> bool {
        self.entries.len() > self.max_entries
    }

    /// Get all entries for a given parent object.
    pub fn entries_for_parent(&self, parent_id: u64) -> Vec<&CachedValueEntry> {
        self.entries
            .range(
                (parent_id, String::new(), i64::MIN)
                    ..=(parent_id, String::from("\u{10FFFF}"), i64::MAX),
            )
            .map(|(_, v)| v)
            .collect()
    }
}

/// A simple address range represented as (start, end) offset pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AddressRange {
    /// Start offset (inclusive).
    pub min_offset: u64,
    /// End offset (inclusive).
    pub max_offset: u64,
}

impl AddressRange {
    /// Create a new address range.
    pub fn new(min_offset: u64, max_offset: u64) -> Self {
        Self {
            min_offset,
            max_offset,
        }
    }

    /// Create a single-address range.
    pub fn single(offset: u64) -> Self {
        Self {
            min_offset: offset,
            max_offset: offset,
        }
    }

    /// Check if an offset is contained in this range.
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.min_offset && offset <= self.max_offset
    }

    /// Check if this range intersects with another.
    pub fn intersects(&self, other: &AddressRange) -> bool {
        self.min_offset <= other.max_offset && other.min_offset <= self.max_offset
    }

    /// Get the number of addresses in this range.
    pub fn num_addresses(&self) -> u64 {
        self.max_offset - self.min_offset + 1
    }
}

/// Address set view for trace object values with spatial queries.
///
/// Corresponds to Java's `DBTraceObjectValueMapAddressSetView`.
/// Provides efficient containment and intersection queries for
/// address ranges associated with trace object values.
#[derive(Debug, Clone)]
pub struct ObjectValueMapAddressSetView {
    /// The ranges in this set, kept sorted and non-overlapping.
    ranges: Vec<AddressRange>,
}

impl ObjectValueMapAddressSetView {
    /// Create an empty address set view.
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Create from a pre-sorted, non-overlapping list of ranges.
    pub fn from_ranges(ranges: Vec<AddressRange>) -> Self {
        Self { ranges }
    }

    /// Check if the set contains an address.
    pub fn contains(&self, offset: u64) -> bool {
        self.ranges
            .binary_search_by(|r| {
                if offset < r.min_offset {
                    std::cmp::Ordering::Greater
                } else if offset > r.max_offset {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Get the number of address ranges.
    pub fn num_address_ranges(&self) -> usize {
        self.ranges.len()
    }

    /// Get the total number of addresses across all ranges.
    pub fn num_addresses(&self) -> u64 {
        self.ranges.iter().map(|r| r.num_addresses()).sum()
    }

    /// Get the first (lowest) address range.
    pub fn first_range(&self) -> Option<&AddressRange> {
        self.ranges.first()
    }

    /// Get the last (highest) address range.
    pub fn last_range(&self) -> Option<&AddressRange> {
        self.ranges.last()
    }

    /// Check if any range in this set intersects with the given range.
    pub fn intersects_range(&self, range: &AddressRange) -> bool {
        self.ranges.iter().any(|r| r.intersects(range))
    }

    /// Add a range to the set, merging overlapping ranges.
    pub fn add_range(&mut self, new_range: AddressRange) {
        let mut merged = Vec::new();
        let mut inserted = false;

        for existing in &self.ranges {
            if new_range.intersects(existing) || new_range.max_offset + 1 == existing.min_offset || existing.max_offset + 1 == new_range.min_offset {
                if !inserted {
                    merged.push(AddressRange::new(
                        new_range.min_offset.min(existing.min_offset),
                        new_range.max_offset.max(existing.max_offset),
                    ));
                    inserted = true;
                } else {
                    // Merge with the last element
                    let last = merged.last_mut().unwrap();
                    last.max_offset = last.max_offset.max(existing.max_offset);
                }
            } else if existing.max_offset < new_range.min_offset {
                merged.push(*existing);
            } else {
                if !inserted {
                    merged.push(new_range);
                    inserted = true;
                }
                merged.push(*existing);
            }
        }

        if !inserted {
            merged.push(new_range);
        }

        self.ranges = merged;
    }

    /// Iterate over all ranges.
    pub fn iter(&self) -> impl Iterator<Item = &AddressRange> {
        self.ranges.iter()
    }
}

impl Default for ObjectValueMapAddressSetView {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_value_entry() {
        let mut entry = CachedValueEntry {
            parent_id: 1,
            key: "name".to_string(),
            lifespan: Lifespan::span(0, 100),
            value: serde_json::json!("test"),
            is_relation: false,
            child_id: None,
            persisted: false,
        };
        assert!(entry.needs_flush());
        entry.mark_persisted();
        assert!(!entry.needs_flush());
    }

    #[test]
    fn test_write_behind_cache_basic() {
        let mut cache = ObjectValueWriteBehindCache::new(1000);
        assert!(cache.is_empty());

        cache.put(
            1, "key".to_string(), 0,
            serde_json::json!("value"),
            Lifespan::span(0, 100),
            false, None,
        );
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.dirty_count(), 1);
        assert!(cache.needs_flush());
    }

    #[test]
    fn test_write_behind_cache_get() {
        let mut cache = ObjectValueWriteBehindCache::new(1000);
        cache.put(
            1, "name".to_string(), 5,
            serde_json::json!("hello"),
            Lifespan::span(0, 100),
            false, None,
        );

        let entry = cache.get(1, "name", 5);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().value, serde_json::json!("hello"));

        assert!(cache.get(1, "name", 6).is_none());
        assert!(cache.get(2, "name", 5).is_none());
    }

    #[test]
    fn test_write_behind_cache_flush() {
        let mut cache = ObjectValueWriteBehindCache::new(1000);
        cache.put(
            1, "a".to_string(), 0,
            serde_json::json!(1),
            Lifespan::span(0, 100),
            false, None,
        );
        cache.put(
            1, "b".to_string(), 0,
            serde_json::json!(2),
            Lifespan::span(0, 100),
            false, None,
        );
        assert_eq!(cache.dirty_count(), 2);

        let flushed = cache.flush();
        assert_eq!(flushed, 2);
        assert_eq!(cache.dirty_count(), 0);
        assert!(!cache.needs_flush());
    }

    #[test]
    fn test_write_behind_cache_remove() {
        let mut cache = ObjectValueWriteBehindCache::new(1000);
        cache.put(
            1, "key".to_string(), 0,
            serde_json::json!("val"),
            Lifespan::span(0, 100),
            false, None,
        );
        assert_eq!(cache.len(), 1);

        let removed = cache.remove(1, "key", 0);
        assert!(removed.is_some());
        assert!(cache.is_empty());
    }

    #[test]
    fn test_write_behind_cache_entries_for_parent() {
        let mut cache = ObjectValueWriteBehindCache::new(1000);
        cache.put(1, "a".to_string(), 0, serde_json::json!(1), Lifespan::span(0, 10), false, None);
        cache.put(1, "b".to_string(), 0, serde_json::json!(2), Lifespan::span(0, 10), false, None);
        cache.put(2, "c".to_string(), 0, serde_json::json!(3), Lifespan::span(0, 10), false, None);

        let entries = cache.entries_for_parent(1);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_write_behind_cache_over_capacity() {
        let mut cache = ObjectValueWriteBehindCache::new(2);
        cache.put(1, "a".to_string(), 0, serde_json::json!(1), Lifespan::span(0, 10), false, None);
        cache.put(2, "b".to_string(), 0, serde_json::json!(2), Lifespan::span(0, 10), false, None);
        assert!(!cache.is_over_capacity());
        cache.put(3, "c".to_string(), 0, serde_json::json!(3), Lifespan::span(0, 10), false, None);
        assert!(cache.is_over_capacity());
    }

    #[test]
    fn test_address_range() {
        let r = AddressRange::new(0x1000, 0x1FFF);
        assert!(r.contains(0x1500));
        assert!(!r.contains(0x2000));
        assert_eq!(r.num_addresses(), 0x1000);
    }

    #[test]
    fn test_address_range_single() {
        let r = AddressRange::single(0x400000);
        assert!(r.contains(0x400000));
        assert!(!r.contains(0x400001));
        assert_eq!(r.num_addresses(), 1);
    }

    #[test]
    fn test_address_range_intersects() {
        let a = AddressRange::new(0, 100);
        let b = AddressRange::new(50, 150);
        let c = AddressRange::new(200, 300);
        assert!(a.intersects(&b));
        assert!(b.intersects(&a));
        assert!(!a.intersects(&c));
    }

    #[test]
    fn test_address_set_view_empty() {
        let view = ObjectValueMapAddressSetView::new();
        assert!(view.is_empty());
        assert!(!view.contains(0));
    }

    #[test]
    fn test_address_set_view_contains() {
        let view = ObjectValueMapAddressSetView::from_ranges(vec![
            AddressRange::new(0x1000, 0x1FFF),
            AddressRange::new(0x3000, 0x3FFF),
        ]);
        assert!(view.contains(0x1000));
        assert!(view.contains(0x1FFF));
        assert!(!view.contains(0x2000));
        assert!(view.contains(0x3500));
        assert_eq!(view.num_address_ranges(), 2);
        assert_eq!(view.num_addresses(), 0x2000);
    }

    #[test]
    fn test_address_set_view_intersects_range() {
        let view = ObjectValueMapAddressSetView::from_ranges(vec![
            AddressRange::new(0x1000, 0x1FFF),
        ]);
        assert!(view.intersects_range(&AddressRange::new(0x1500, 0x2500)));
        assert!(!view.intersects_range(&AddressRange::new(0x2000, 0x3000)));
    }

    #[test]
    fn test_address_set_view_add_range_merge() {
        let mut view = ObjectValueMapAddressSetView::new();
        view.add_range(AddressRange::new(0, 100));
        view.add_range(AddressRange::new(50, 200));
        assert_eq!(view.num_address_ranges(), 1);
        assert_eq!(view.num_addresses(), 201);
    }

    #[test]
    fn test_address_set_view_add_range_adjacent() {
        let mut view = ObjectValueMapAddressSetView::new();
        view.add_range(AddressRange::new(0, 100));
        view.add_range(AddressRange::new(101, 200));
        assert_eq!(view.num_address_ranges(), 1);
    }

    #[test]
    fn test_address_set_view_add_range_disjoint() {
        let mut view = ObjectValueMapAddressSetView::new();
        view.add_range(AddressRange::new(0, 100));
        view.add_range(AddressRange::new(200, 300));
        assert_eq!(view.num_address_ranges(), 2);
    }

    #[test]
    fn test_address_set_view_first_last_range() {
        let view = ObjectValueMapAddressSetView::from_ranges(vec![
            AddressRange::new(0x1000, 0x1FFF),
            AddressRange::new(0x5000, 0x5FFF),
        ]);
        assert_eq!(view.first_range().unwrap().min_offset, 0x1000);
        assert_eq!(view.last_range().unwrap().max_offset, 0x5FFF);
    }
}
