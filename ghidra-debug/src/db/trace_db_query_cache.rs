//! Query cache implementations for trace database.
//!
//! Ported from Ghidra's `DBTraceCacheForContainingQueries` and
//! `DBTraceCacheForSequenceQueries`. These provide LRU-style caches
//! for efficient spatial and temporal queries against the trace database.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

use crate::model::Lifespan;

/// Key for point queries (snap + offset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CachePointKey {
    /// The snapshot/time key.
    pub snap: i64,
    /// The address offset.
    pub offset: u64,
}

impl CachePointKey {
    /// Create a new cache point key.
    pub fn new(snap: i64, offset: u64) -> Self {
        Self { snap, offset }
    }
}

/// A cached range entry in the containing-queries cache.
#[derive(Debug, Clone)]
pub struct CachedRangeEntry<T> {
    /// Start offset of the range.
    pub min_offset: u64,
    /// End offset of the range.
    pub max_offset: u64,
    /// Lifespan of this entry.
    pub lifespan: Lifespan,
    /// The cached value.
    pub value: T,
}

impl<T> CachedRangeEntry<T> {
    /// Check if a point key is contained within this range entry.
    pub fn contains(&self, key: &CachePointKey) -> bool {
        self.lifespan.contains(key.snap) && key.offset >= self.min_offset && key.offset <= self.max_offset
    }
}

/// Cache for containing-point queries.
///
/// When looking up which entry contains a given (snap, address) pair,
/// this cache avoids repeated full scans by maintaining a bounded
/// cache of recently-accessed ranges and a point cache for fast lookups.
///
/// Ported from `DBTraceCacheForContainingQueries`.
#[derive(Debug)]
pub struct ContainingQueryCache<T: Clone + std::fmt::Debug> {
    /// Breadth of snap range to cache around queries.
    snap_breadth: i64,
    /// Breadth of address range to cache around queries.
    address_breadth: u64,
    /// Maximum number of point entries to cache.
    max_points: usize,
    /// Point cache: maps (snap, offset) to the value found there.
    point_cache: HashMap<CachePointKey, Option<T>>,
    /// Range cache: entries loaded for the current query window.
    range_cache: Vec<CachedRangeEntry<T>>,
    /// The snap range currently covered by the range cache.
    cached_snap_range: Option<(i64, i64)>,
    /// The address range currently covered by the range cache.
    cached_addr_range: Option<(u64, u64)>,
}

impl<T: Clone + std::fmt::Debug> ContainingQueryCache<T> {
    /// Create a new containing query cache.
    pub fn new(snap_breadth: i64, address_breadth: u64, max_points: usize) -> Self {
        Self {
            snap_breadth,
            address_breadth,
            max_points,
            point_cache: HashMap::new(),
            range_cache: Vec::new(),
            cached_snap_range: None,
            cached_addr_range: None,
        }
    }

    /// Check whether the given key falls within the cached range.
    pub fn is_in_cached_range(&self, key: &CachePointKey) -> bool {
        if let (Some((smin, smax)), Some((amin, amax))) = (&self.cached_snap_range, &self.cached_addr_range) {
            key.snap >= *smin && key.snap <= *smax && key.offset >= *amin && key.offset <= *amax
        } else {
            false
        }
    }

    /// Invalidate all cached data.
    pub fn invalidate(&mut self) {
        self.point_cache.clear();
        self.range_cache.clear();
        self.cached_snap_range = None;
        self.cached_addr_range = None;
    }

    /// Add a range entry to the cache.
    pub fn add_entry(&mut self, entry: CachedRangeEntry<T>) {
        self.range_cache.push(entry);
        // Invalidate point cache when new entries are added
        self.point_cache.clear();
    }

    /// Find all range entries containing the given key.
    pub fn get_all_containing(&self, key: &CachePointKey) -> Vec<&T> {
        self.range_cache
            .iter()
            .filter(|e| e.contains(key))
            .map(|e| &e.value)
            .collect()
    }

    /// Find the first range entry containing the given key.
    pub fn get_first_containing(&self, key: &CachePointKey) -> Option<&T> {
        self.range_cache
            .iter()
            .find(|e| e.contains(key))
            .map(|e| &e.value)
    }

    /// Notify the cache of a new entry being added to the database.
    pub fn notify_new_entry(&mut self, _lifespan: Lifespan, _min_offset: u64, _max_offset: u64, _item: T) {
        // Can be smarter, but for now invalidate point cache
        self.point_cache.clear();
    }

    /// Notify the cache that an entry was removed.
    pub fn notify_entry_removed(&mut self) {
        self.invalidate();
    }

    /// Notify the cache that an entry's shape changed.
    pub fn notify_shape_changed(&mut self) {
        self.invalidate();
    }

    /// Compute the snap range that should be cached around a given snap.
    pub fn compute_snap_range(&self, snap: i64) -> (i64, i64) {
        (snap - self.snap_breadth, snap + self.snap_breadth)
    }

    /// Compute the address range that should be cached around a given offset.
    pub fn compute_addr_range(&self, offset: u64) -> (u64, u64) {
        let min = offset.saturating_sub(self.address_breadth);
        let max = offset.saturating_add(self.address_breadth);
        (min, max)
    }

    /// Get the number of cached entries.
    pub fn len(&self) -> usize {
        self.range_cache.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.range_cache.is_empty()
    }

    /// Get the number of point cache entries.
    pub fn point_cache_len(&self) -> usize {
        self.point_cache.len()
    }
}

/// A cached region for sequence queries.
#[derive(Debug)]
pub struct CachedSequenceRegion<T: Clone> {
    /// The snap for this region.
    pub snap: i64,
    /// Navigable map of address -> value for ordered access.
    entries: BTreeMap<u64, T>,
    /// Minimum cached address.
    pub min_offset: u64,
    /// Maximum cached address.
    pub max_offset: u64,
}

impl<T: Clone> CachedSequenceRegion<T> {
    /// Create a new cached sequence region.
    pub fn new(snap: i64, min_offset: u64, max_offset: u64) -> Self {
        Self {
            snap,
            entries: BTreeMap::new(),
            min_offset,
            max_offset,
        }
    }

    /// Get the floor entry (greatest entry <= address).
    pub fn get_floor(&self, offset: u64) -> Option<&T> {
        self.entries.range(..=offset).next_back().map(|(_, v)| v)
    }

    /// Get the ceiling entry (least entry >= address).
    pub fn get_ceiling(&self, offset: u64) -> Option<&T> {
        self.entries.range(offset..).next().map(|(_, v)| v)
    }

    /// Load entries from an iterator.
    pub fn load<I: IntoIterator<Item = (u64, T)>>(&mut self, entries: I) {
        for (addr, value) in entries {
            self.entries.insert(addr, value);
        }
        if let Some((&min, _)) = self.entries.iter().next() {
            self.min_offset = min;
        }
        if let Some((&max, _)) = self.entries.iter().next_back() {
            self.max_offset = max;
        }
    }

    /// Check if this region contains the given offset.
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.min_offset && offset <= self.max_offset
    }

    /// Re-initialize the region with new bounds.
    pub fn re_init(&mut self, snap: i64, min_offset: u64, max_offset: u64) {
        self.snap = snap;
        self.min_offset = min_offset;
        self.max_offset = max_offset;
        self.entries.clear();
    }

    /// Get the number of entries in this region.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Cache for sequence (floor/ceiling) queries.
///
/// Provides LRU-cached access to floor and ceiling queries within
/// address ranges at given snapshots. This avoids repeated database
/// lookups when iterating through instruction/data sequences.
///
/// Ported from `DBTraceCacheForSequenceQueries`.
#[derive(Debug)]
pub struct SequenceQueryCache<T: Clone + std::fmt::Debug> {
    /// Maximum number of cached regions.
    max_regions: usize,
    /// Breadth of the address range to cache.
    address_breadth: u64,
    /// Cached regions (most recently used at front).
    regions: Vec<CachedSequenceRegion<T>>,
}

impl<T: Clone + std::fmt::Debug> SequenceQueryCache<T> {
    /// Create a new sequence query cache.
    pub fn new(max_regions: usize, address_breadth: u64) -> Self {
        Self {
            max_regions,
            address_breadth,
            regions: Vec::with_capacity(max_regions),
        }
    }

    /// Find or create the cached region for the given (snap, offset).
    pub fn ensure_in_cache(&mut self, snap: i64, offset: u64) -> &mut CachedSequenceRegion<T> {
        // Check if any existing region covers this (snap, offset)
        let found_idx = self.regions.iter().position(|r| r.snap == snap && r.contains(offset));
        if let Some(idx) = found_idx {
            // Move to front (MRU)
            if idx > 0 {
                let region = self.regions.remove(idx);
                self.regions.insert(0, region);
            }
            return &mut self.regions[0];
        }

        // Cache miss: create or reuse a region
        let min = offset.saturating_sub(self.address_breadth);
        let max = offset.saturating_add(self.address_breadth);
        if self.regions.len() >= self.max_regions {
            // Reuse the LRU (last) entry
            let last = self.regions.last_mut().unwrap();
            last.re_init(snap, min, max);
            let region = self.regions.pop().unwrap();
            self.regions.insert(0, region);
        } else {
            self.regions.insert(0, CachedSequenceRegion::new(snap, min, max));
        }
        &mut self.regions[0]
    }

    /// Get the floor entry for (snap, offset).
    pub fn get_floor(&mut self, snap: i64, offset: u64) -> Option<&T> {
        let region = self.ensure_in_cache(snap, offset);
        region.get_floor(offset)
    }

    /// Get the ceiling entry for (snap, offset).
    pub fn get_ceiling(&mut self, snap: i64, offset: u64) -> Option<&T> {
        let region = self.ensure_in_cache(snap, offset);
        region.get_ceiling(offset)
    }

    /// Invalidate all cached data.
    pub fn invalidate(&mut self) {
        self.regions.clear();
    }

    /// Get the number of cached regions.
    pub fn region_count(&self) -> usize {
        self.regions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_point_key_equality() {
        let k1 = CachePointKey::new(10, 0x1000);
        let k2 = CachePointKey::new(10, 0x1000);
        let k3 = CachePointKey::new(20, 0x1000);
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
    }

    #[test]
    fn test_cached_range_entry_contains() {
        let entry = CachedRangeEntry {
            min_offset: 0x1000,
            max_offset: 0x2000,
            lifespan: Lifespan::span(5, 15),
            value: "test",
        };
        assert!(entry.contains(&CachePointKey::new(10, 0x1500)));
        assert!(!entry.contains(&CachePointKey::new(20, 0x1500))); // out of lifespan
        assert!(!entry.contains(&CachePointKey::new(10, 0x3000))); // out of range
    }

    #[test]
    fn test_containing_query_cache_basic() {
        let mut cache = ContainingQueryCache::<String>::new(10, 0x1000, 100);
        assert!(cache.is_empty());

        cache.add_entry(CachedRangeEntry {
            min_offset: 0x1000,
            max_offset: 0x2000,
            lifespan: Lifespan::span(0, 100),
            value: "region1".to_string(),
        });
        assert_eq!(cache.len(), 1);

        let results = cache.get_all_containing(&CachePointKey::new(50, 0x1500));
        assert_eq!(results.len(), 1);
        assert_eq!(*results[0], "region1");
    }

    #[test]
    fn test_containing_query_cache_no_match() {
        let mut cache = ContainingQueryCache::<String>::new(10, 0x1000, 100);
        cache.add_entry(CachedRangeEntry {
            min_offset: 0x1000,
            max_offset: 0x2000,
            lifespan: Lifespan::span(0, 100),
            value: "region1".to_string(),
        });

        let results = cache.get_all_containing(&CachePointKey::new(200, 0x1500));
        assert!(results.is_empty());
    }

    #[test]
    fn test_containing_query_cache_invalidate() {
        let mut cache = ContainingQueryCache::<String>::new(10, 0x1000, 100);
        cache.add_entry(CachedRangeEntry {
            min_offset: 0x1000,
            max_offset: 0x2000,
            lifespan: Lifespan::span(0, 100),
            value: "test".to_string(),
        });
        cache.invalidate();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_containing_query_cache_compute_ranges() {
        let cache = ContainingQueryCache::<String>::new(10, 0x1000, 100);
        let (smin, smax) = cache.compute_snap_range(50);
        assert_eq!(smin, 40);
        assert_eq!(smax, 60);

        let (amin, amax) = cache.compute_addr_range(0x5000);
        assert_eq!(amin, 0x4000);
        assert_eq!(amax, 0x6000);
    }

    #[test]
    fn test_sequence_region_floor_ceiling() {
        let mut region = CachedSequenceRegion::<String>::new(10, 0, 0xFFFF);
        region.load(vec![
            (0x1000, "inst1".to_string()),
            (0x1004, "inst2".to_string()),
            (0x1008, "inst3".to_string()),
        ]);

        assert_eq!(region.get_floor(0x1003).map(|s| s.as_str()), Some("inst1"));
        assert_eq!(region.get_floor(0x1004).map(|s| s.as_str()), Some("inst2"));
        assert_eq!(region.get_ceiling(0x1003).map(|s| s.as_str()), Some("inst2"));
        assert_eq!(region.get_ceiling(0x1008).map(|s| s.as_str()), Some("inst3"));
        assert_eq!(region.get_ceiling(0x1009), None);
    }

    #[test]
    fn test_sequence_query_cache_lru() {
        let mut cache = SequenceQueryCache::<String>::new(2, 0x1000);

        // First query creates region 1
        {
            let region = cache.ensure_in_cache(0, 0x1000);
            region.load(vec![(0x1000, "a".to_string())]);
        }
        assert_eq!(cache.region_count(), 1);

        // Second query creates region 2
        {
            let region = cache.ensure_in_cache(0, 0x5000);
            region.load(vec![(0x5000, "b".to_string())]);
        }
        assert_eq!(cache.region_count(), 2);

        // Third query evicts region 1 (LRU)
        {
            let region = cache.ensure_in_cache(0, 0x9000);
            region.load(vec![(0x9000, "c".to_string())]);
        }
        assert_eq!(cache.region_count(), 2);
    }

    #[test]
    fn test_sequence_query_cache_floor_ceiling() {
        let mut cache = SequenceQueryCache::<String>::new(5, 0x1000);

        // Load some data
        {
            let region = cache.ensure_in_cache(0, 0x1004);
            region.load(vec![
                (0x1000, "inst1".to_string()),
                (0x1004, "inst2".to_string()),
                (0x1008, "inst3".to_string()),
            ]);
        }

        assert_eq!(cache.get_floor(0, 0x1005).map(|s| s.as_str()), Some("inst2"));
        assert_eq!(cache.get_ceiling(0, 0x1005).map(|s| s.as_str()), Some("inst3"));
    }

    #[test]
    fn test_sequence_query_cache_invalidate() {
        let mut cache = SequenceQueryCache::<String>::new(5, 0x1000);
        {
            let region = cache.ensure_in_cache(0, 0x1000);
            region.load(vec![(0x1000, "test".to_string())]);
        }
        assert_eq!(cache.region_count(), 1);
        cache.invalidate();
        assert_eq!(cache.region_count(), 0);
    }

    #[test]
    fn test_containing_query_cache_first_match() {
        let mut cache = ContainingQueryCache::<i32>::new(10, 0x1000, 100);
        cache.add_entry(CachedRangeEntry {
            min_offset: 0x1000,
            max_offset: 0x1FFF,
            lifespan: Lifespan::span(0, 50),
            value: 1,
        });
        cache.add_entry(CachedRangeEntry {
            min_offset: 0x1000,
            max_offset: 0x1FFF,
            lifespan: Lifespan::span(0, 50),
            value: 2,
        });

        assert_eq!(cache.get_first_containing(&CachePointKey::new(10, 0x1500)), Some(&1));
        let all = cache.get_all_containing(&CachePointKey::new(10, 0x1500));
        assert_eq!(all.len(), 2);
    }
}
