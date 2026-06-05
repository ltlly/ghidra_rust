//! Cache for "containing" queries on address-snap ranges.
//!
//! Ported from Ghidra's `DBTraceCacheForContainingQueries`.
//!
//! Provides a bounded cache with range-based and point-based lookup
//! for efficiently answering "what contains this (address, snap)?" queries.

use std::collections::HashMap;
use std::hash::Hash;

use crate::model::{Lifespan, TraceAddressSnapRange};

/// A key for a "containing" query: a (snap, offset) point.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContainingQueryKey {
    /// The snapshot time.
    pub snap: i64,
    /// The address offset.
    pub offset: u64,
}

impl ContainingQueryKey {
    /// Create a new containing query key.
    pub fn new(snap: i64, offset: u64) -> Self {
        Self { snap, offset }
    }
}

/// Cache configuration for containing queries.
#[derive(Debug, Clone)]
pub struct ContainingCacheConfig {
    /// How many snapshots to include in the cached range.
    pub snap_breadth: i64,
    /// How many addresses to include in the cached range.
    pub address_breadth: u64,
    /// Maximum number of point cache entries.
    pub max_points: usize,
}

impl Default for ContainingCacheConfig {
    fn default() -> Self {
        Self {
            snap_breadth: 32,
            address_breadth: 0x1000,
            max_points: 1024,
        }
    }
}

/// A bounded-size LRU-like cache for point lookups.
#[derive(Debug)]
pub struct BoundedPointCache<K: Eq + Hash, V> {
    entries: HashMap<K, V>,
    max_size: usize,
    insertion_order: Vec<K>,
}

impl<K: Eq + Hash + Clone, V> BoundedPointCache<K, V> {
    /// Create a new bounded point cache.
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(max_size.min(1024)),
            max_size,
            insertion_order: Vec::new(),
        }
    }

    /// Get a value from the cache.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }

    /// Insert a value into the cache, evicting the oldest entry if full.
    pub fn insert(&mut self, key: K, value: V) {
        if self.entries.len() >= self.max_size && !self.entries.contains_key(&key) {
            // Evict oldest
            if let Some(oldest) = self.insertion_order.first().cloned() {
                self.entries.remove(&oldest);
                self.insertion_order.remove(0);
            }
        }
        if !self.entries.contains_key(&key) {
            self.insertion_order.push(key.clone());
        }
        self.entries.insert(key, value);
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.insertion_order.clear();
    }

    /// Get the current size.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Cache for "containing" queries over address-snap ranges.
///
/// Maintains a two-level cache: a range cache for broad spatial queries
/// and a point cache for exact (snap, offset) lookups.
///
/// Ported from Ghidra's `DBTraceCacheForContainingQueries`.
pub struct ContainingQueryCache<T: Clone> {
    config: ContainingCacheConfig,
    point_cache: BoundedPointCache<ContainingQueryKey, Option<T>>,
    range_cache: Vec<(TraceAddressSnapRange, T)>,
    cached_range: Option<TraceAddressSnapRange>,
}

impl<T: Clone> ContainingQueryCache<T> {
    /// Create a new cache with the given configuration.
    pub fn new(config: ContainingCacheConfig) -> Self {
        let max_points = config.max_points;
        Self {
            config,
            point_cache: BoundedPointCache::new(max_points),
            range_cache: Vec::new(),
            cached_range: None,
        }
    }

    /// Create a cache with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(ContainingCacheConfig::default())
    }

    /// Check if a point is within the currently cached range.
    pub fn is_in_cached_range(&self, snap: i64, offset: u64) -> bool {
        if let Some(ref range) = self.cached_range {
            range.contains(offset, snap)
        } else {
            false
        }
    }

    /// Compute a new cached range centered on the given point.
    pub fn compute_cached_range(&self, snap: i64, offset: u64) -> TraceAddressSnapRange {
        let snap_half = self.config.snap_breadth / 2;
        let addr_half = self.config.address_breadth / 2;

        let snap_min = snap.saturating_sub(snap_half);
        let snap_max = snap.saturating_add(snap_half);
        let min_offset = offset.saturating_sub(addr_half);
        let max_offset = offset.saturating_add(addr_half);

        TraceAddressSnapRange::new(min_offset, max_offset, Lifespan::span(snap_min, snap_max))
    }

    /// Ensure the cached range covers the given point.
    /// If not, clears and recomputes.
    pub fn ensure_cached_range(&mut self, snap: i64, offset: u64) {
        if !self.is_in_cached_range(snap, offset) {
            self.range_cache.clear();
            self.cached_range = Some(self.compute_cached_range(snap, offset));
        }
    }

    /// Get all entries in the range cache that contain the given key.
    pub fn get_all_in_range_containing(&self, key: &ContainingQueryKey) -> Vec<&T> {
        self.range_cache
            .iter()
            .filter(|(range, _)| range.contains(key.offset, key.snap))
            .map(|(_, item)| item)
            .collect()
    }

    /// Get the first entry in the range cache that contains the given key.
    pub fn get_first_in_range_containing(&self, key: &ContainingQueryKey) -> Option<&T> {
        self.range_cache.iter().find_map(|(range, item)| {
            if range.contains(key.offset, key.snap) {
                Some(item)
            } else {
                None
            }
        })
    }

    /// Get a value from the point cache.
    pub fn get_cached_point(&self, key: &ContainingQueryKey) -> Option<Option<&T>> {
        self.point_cache.get(key).map(|v| v.as_ref())
    }

    /// Insert a value into the point cache.
    pub fn cache_point(&mut self, key: ContainingQueryKey, value: Option<T>) {
        self.point_cache.insert(key, value);
    }

    /// Add an entry to the range cache if it intersects the cached range.
    pub fn notify_new_entry(&mut self, range: TraceAddressSnapRange, item: T) {
        if let Some(ref cached) = self.cached_range {
            let ranges_overlap = cached.min_offset <= range.max_offset
                && range.min_offset <= cached.max_offset;
            if cached.lifespan.intersects(&range.lifespan) && ranges_overlap {
                self.range_cache.push((range, item));
            }
        }
        // Always clear point cache on mutation
        self.point_cache.clear();
    }

    /// Remove an entry from the range cache.
    pub fn notify_entry_removed(&mut self, _range: &TraceAddressSnapRange, _item_ref: &T) {
        // Conservative: invalidate everything
        self.invalidate();
    }

    /// Invalidate the entire cache.
    pub fn invalidate(&mut self) {
        self.point_cache.clear();
        self.range_cache.clear();
        self.cached_range = None;
    }

    /// Get the number of entries in the range cache.
    pub fn range_cache_len(&self) -> usize {
        self.range_cache.len()
    }

    /// Get the number of entries in the point cache.
    pub fn point_cache_len(&self) -> usize {
        self.point_cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_range(min_offset: u64, max_offset: u64, snap_min: i64, snap_max: i64) -> TraceAddressSnapRange {
        TraceAddressSnapRange::new(min_offset, max_offset, Lifespan::span(snap_min, snap_max))
    }

    #[test]
    fn test_bounded_point_cache() {
        let mut cache = BoundedPointCache::new(2);
        cache.insert("a", 1);
        cache.insert("b", 2);
        assert_eq!(cache.get(&"a"), Some(&1));
        assert_eq!(cache.get(&"b"), Some(&2));

        // Inserting a third should evict the oldest
        cache.insert("c", 3);
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&"a").is_none() || cache.get(&"b").is_none());
    }

    #[test]
    fn test_containing_cache_range() {
        let mut cache = ContainingQueryCache::<i32>::with_defaults();
        assert!(!cache.is_in_cached_range(0, 0x1000));

        cache.ensure_cached_range(10, 0x1000);
        assert!(cache.is_in_cached_range(10, 0x1000));
        assert!(cache.is_in_cached_range(5, 0x0800));
    }

    #[test]
    fn test_range_cache_query() {
        let mut cache = ContainingQueryCache::<String>::new(ContainingCacheConfig {
            snap_breadth: 100,
            address_breadth: 0x10000,
            max_points: 100,
        });

        cache.ensure_cached_range(50, 0x5000);
        cache.notify_new_entry(
            make_range(0x4000, 0x6000, 40, 60),
            "region1".to_string(),
        );
        cache.notify_new_entry(
            make_range(0x8000, 0x9000, 40, 60),
            "region2".to_string(),
        );

        let key = ContainingQueryKey::new(50, 0x5000);
        let results = cache.get_all_in_range_containing(&key);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "region1");

        let first = cache.get_first_in_range_containing(&key);
        assert!(first.is_some());
    }

    #[test]
    fn test_invalidation() {
        let mut cache = ContainingQueryCache::<i32>::with_defaults();
        cache.ensure_cached_range(10, 0x1000);
        cache.notify_new_entry(make_range(0, 0x2000, 0, 20), 42);
        cache.cache_point(ContainingQueryKey::new(10, 0x1000), Some(42));

        cache.invalidate();
        assert!(cache.cached_range.is_none());
        assert!(cache.range_cache.is_empty());
        assert!(cache.point_cache.is_empty());
    }
}
