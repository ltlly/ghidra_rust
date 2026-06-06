//! Database query caching for trace data.
//!
//! Ported from Ghidra's `DBTraceCacheForContainingQueries` and
//! `DBTraceCacheForSequenceQueries` in `ghidra.trace.database`. These
//! caches avoid repeated database round-trips for common access patterns:
//! "get the entry containing a given (snap, address)" and "get the
//! floor/ceiling entry near a given (snap, address)."

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::sync::{Arc, RwLock};

use crate::model::{Lifespan, TraceAddressSnapRange};

// ── Containing Query Cache ───────────────────────────────────────────────

/// Cache key for a point query at a specific (snap, address).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContainingCacheKey {
    /// The snapshot (time) of the query.
    pub snap: i64,
    /// The address offset of the query.
    pub offset: u64,
}

impl ContainingCacheKey {
    /// Create a new containing cache key.
    pub fn new(snap: i64, offset: u64) -> Self {
        Self { snap, offset }
    }
}

/// An LRU-style cache for "containing" queries: given (snap, address),
/// find the entry whose (lifespan, address_range) contains that point.
///
/// Ported from Ghidra's `DBTraceCacheForContainingQueries`.
#[derive(Debug)]
pub struct ContainingQueryCache<T: Clone + std::fmt::Debug> {
    /// Breadth in snapshots for the range cache.
    snap_breadth: i64,
    /// Breadth in addresses for the range cache.
    address_breadth: u64,
    /// Maximum number of point cache entries.
    #[allow(dead_code)]
    max_points: usize,
    /// Point cache: exact (snap, offset) -> result.
    point_cache: HashMap<ContainingCacheKey, Option<T>>,
    /// Range cache: entries loaded for a surrounding range.
    range_cache: Vec<(TraceAddressSnapRange, T)>,
    /// The range currently cached, if any.
    range_cache_range: Option<TraceAddressSnapRange>,
}

impl<T: Clone + std::fmt::Debug> ContainingQueryCache<T> {
    /// Create a new cache with the given breadth parameters.
    pub fn new(snap_breadth: i64, address_breadth: u64, max_points: usize) -> Self {
        Self {
            snap_breadth,
            address_breadth,
            max_points,
            point_cache: HashMap::new(),
            range_cache: Vec::new(),
            range_cache_range: None,
        }
    }

    /// Check if a point is within the currently cached range.
    pub fn is_in_cached_range(&self, snap: i64, offset: u64) -> bool {
        if let Some(ref range) = self.range_cache_range {
            range.lifespan.contains(snap)
                && offset >= range.min_offset
                && offset <= range.max_offset
        } else {
            false
        }
    }

    /// Compute a new cache range centered on the given point.
    pub fn compute_new_cached_range(&self, snap: i64, offset: u64) -> TraceAddressSnapRange {
        let half_addr = self.address_breadth / 2;
        let half_snap = self.snap_breadth / 2;
        TraceAddressSnapRange {
            min_offset: offset.saturating_sub(half_addr),
            max_offset: offset.saturating_add(half_addr),
            lifespan: Lifespan::span(
                snap.saturating_sub(half_snap),
                snap.saturating_add(half_snap),
            ),
        }
    }

    /// Get the range cache entries containing the given point.
    pub fn get_all_in_range_cache_containing(&self, snap: i64, offset: u64) -> Vec<T> {
        self.range_cache
            .iter()
            .filter(|(range, _)| {
                range.lifespan.contains(snap)
                    && offset >= range.min_offset
                    && offset <= range.max_offset
            })
            .map(|(_, item)| item.clone())
            .collect()
    }

    /// Get the first range cache entry containing the given point.
    pub fn get_first_in_range_cache_containing(&self, snap: i64, offset: u64) -> Option<T> {
        self.range_cache.iter().find_map(|(range, item)| {
            if range.lifespan.contains(snap)
                && offset >= range.min_offset
                && offset <= range.max_offset
            {
                Some(item.clone())
            } else {
                None
            }
        })
    }

    /// Notify the cache that a new entry was added.
    pub fn notify_new_entry(&mut self, range: &TraceAddressSnapRange, item: T) {
        // Invalidate point cache on structural change
        self.point_cache.clear();
        if let Some(ref cached_range) = self.range_cache_range {
            if !cached_range.lifespan.intersect(&range.lifespan).is_empty()
                && Self::ranges_intersect(cached_range, range)
            {
                self.range_cache.push((range.clone(), item));
            }
        }
    }

    /// Notify the cache that an entry was removed.
    pub fn notify_entry_removed(&mut self) {
        self.invalidate();
    }

    /// Notify the cache that an entry's shape changed.
    pub fn notify_entry_shape_changed(&mut self) {
        self.invalidate();
    }

    /// Clear the entire cache.
    pub fn invalidate(&mut self) {
        self.point_cache.clear();
        self.range_cache.clear();
        self.range_cache_range = None;
    }

    /// Check whether two ranges' address ranges intersect.
    fn ranges_intersect(a: &TraceAddressSnapRange, b: &TraceAddressSnapRange) -> bool {
        a.min_offset <= b.max_offset && b.min_offset <= a.max_offset
    }

    /// Get a mutable reference to the point cache.
    pub fn point_cache_mut(&mut self) -> &mut HashMap<ContainingCacheKey, Option<T>> {
        &mut self.point_cache
    }

    /// Get a reference to the point cache.
    pub fn point_cache(&self) -> &HashMap<ContainingCacheKey, Option<T>> {
        &self.point_cache
    }

    /// Get the range cache.
    pub fn range_cache(&self) -> &[(TraceAddressSnapRange, T)] {
        &self.range_cache
    }

    /// Get the currently cached range.
    pub fn cached_range(&self) -> Option<&TraceAddressSnapRange> {
        self.range_cache_range.as_ref()
    }

    /// Load entries into the range cache.
    pub fn load_range_cache(&mut self, entries: Vec<(TraceAddressSnapRange, T)>) {
        self.range_cache = entries;
    }

    /// Set the cached range.
    pub fn set_cached_range(&mut self, range: Option<TraceAddressSnapRange>) {
        self.range_cache_range = range;
    }
}

// ── Sequence Query Cache ─────────────────────────────────────────────────

/// A cached region for sequence queries (floor/ceiling operations).
#[derive(Debug)]
pub struct CachedSequenceRegion<T: Clone + std::fmt::Debug> {
    /// The snap this region is for.
    pub snap: i64,
    /// The navigable map of address -> item within this region.
    entries: BTreeMap<u64, T>,
    /// Minimum address in the region.
    pub min_addr: u64,
    /// Maximum address in the region.
    pub max_addr: u64,
}

impl<T: Clone + std::fmt::Debug> CachedSequenceRegion<T> {
    /// Create a new cached region.
    pub fn new(snap: i64, min_addr: u64, max_addr: u64) -> Self {
        Self {
            snap,
            entries: BTreeMap::new(),
            min_addr,
            max_addr,
        }
    }

    /// Whether this region contains the given address.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.min_addr && address <= self.max_addr
    }

    /// Get the floor entry (entry at or just below the given address).
    pub fn get_floor(&self, address: u64) -> Option<&T> {
        self.entries
            .range(..=address)
            .next_back()
            .map(|(_, v)| v)
    }

    /// Get the ceiling entry (entry at or just above the given address).
    pub fn get_ceiling(&self, address: u64) -> Option<&T> {
        self.entries.range(address..).next().map(|(_, v)| v)
    }

    /// Load entries into this region.
    pub fn load(&mut self, entries: impl IntoIterator<Item = (u64, T)>) {
        for (addr, item) in entries {
            self.entries.insert(addr, item);
        }
    }

    /// Re-initialize the region for a new snap and range.
    pub fn re_init(&mut self, snap: i64, min_addr: u64, max_addr: u64) {
        self.snap = snap;
        self.entries.clear();
        self.min_addr = min_addr;
        self.max_addr = max_addr;
    }
}

/// Cache for sequence queries (floor/ceiling).
///
/// Ported from Ghidra's `DBTraceCacheForSequenceQueries`.
#[derive(Debug)]
pub struct SequenceQueryCache<T: Clone + std::fmt::Debug> {
    /// Maximum number of cached regions.
    max_regions: usize,
    /// Address breadth for cache regions.
    address_breadth: u64,
    /// Cached regions (MRU order: last is most recently used).
    regions: Vec<CachedSequenceRegion<T>>,
}

impl<T: Clone + std::fmt::Debug> SequenceQueryCache<T> {
    /// Create a new sequence query cache.
    pub fn new(max_regions: usize, address_breadth: u64) -> Self {
        Self {
            max_regions,
            address_breadth,
            regions: Vec::new(),
        }
    }

    /// Compute a new cached range centered on the given address.
    fn compute_cached_range(&self, address: u64) -> (u64, u64) {
        let half = self.address_breadth / 2;
        (address.saturating_sub(half), address.saturating_add(half))
    }

    /// Ensure the given (snap, address) is within a cached region,
    /// returning the index of the region.
    fn ensure_in_cache(&mut self, snap: i64, address: u64) -> usize {
        // Check existing regions
        for i in 0..self.regions.len() {
            if self.regions[i].snap == snap && self.regions[i].contains(address) {
                // Move to end (MRU)
                let region = self.regions.remove(i);
                self.regions.push(region);
                return self.regions.len() - 1;
            }
        }
        // Evict oldest if at capacity
        let (min_addr, max_addr) = self.compute_cached_range(address);
        if self.regions.len() >= self.max_regions {
            self.regions[0].re_init(snap, min_addr, max_addr);
            let region = self.regions.remove(0);
            self.regions.push(region);
        } else {
            self.regions
                .push(CachedSequenceRegion::new(snap, min_addr, max_addr));
        }
        self.regions.len() - 1
    }

    /// Get the floor entry at (snap, address).
    pub fn get_floor(&mut self, snap: i64, address: u64) -> Option<T> {
        let idx = self.ensure_in_cache(snap, address);
        self.regions[idx].get_floor(address).cloned()
    }

    /// Get the ceiling entry at (snap, address).
    pub fn get_ceiling(&mut self, snap: i64, address: u64) -> Option<T> {
        let idx = self.ensure_in_cache(snap, address);
        self.regions[idx].get_ceiling(address).cloned()
    }

    /// Notify the cache that a new entry was added.
    pub fn notify_new_entry(&mut self) {
        self.invalidate();
    }

    /// Notify the cache that an entry was removed.
    pub fn notify_entry_removed(&mut self) {
        self.invalidate();
    }

    /// Clear the entire cache.
    pub fn invalidate(&mut self) {
        self.regions.clear();
    }

    /// Get the number of cached regions.
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Get a reference to the regions (for testing).
    pub fn regions(&self) -> &[CachedSequenceRegion<T>] {
        &self.regions
    }

    /// Load entries into the most recent region (for testing/setup).
    pub fn load_into_current_region(&mut self, entries: impl IntoIterator<Item = (u64, T)>) {
        if let Some(region) = self.regions.last_mut() {
            region.load(entries);
        }
    }
}

// ── Thread-safe wrappers ─────────────────────────────────────────────────

/// A thread-safe wrapper around `ContainingQueryCache`.
pub type SharedContainingCache<T> = Arc<RwLock<ContainingQueryCache<T>>>;

/// A thread-safe wrapper around `SequenceQueryCache`.
pub type SharedSequenceCache<T> = Arc<RwLock<SequenceQueryCache<T>>>;

/// Create a shared containing cache.
pub fn shared_containing_cache<T: Clone + std::fmt::Debug>(
    snap_breadth: i64,
    address_breadth: u64,
    max_points: usize,
) -> SharedContainingCache<T> {
    Arc::new(RwLock::new(ContainingQueryCache::new(
        snap_breadth,
        address_breadth,
        max_points,
    )))
}

/// Create a shared sequence cache.
pub fn shared_sequence_cache<T: Clone + std::fmt::Debug>(
    max_regions: usize,
    address_breadth: u64,
) -> SharedSequenceCache<T> {
    Arc::new(RwLock::new(SequenceQueryCache::new(
        max_regions,
        address_breadth,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_containing_cache_basic() {
        let mut cache = ContainingQueryCache::<String>::new(10, 0x1000, 100);
        assert!(cache.point_cache().is_empty());

        let range = TraceAddressSnapRange {
            min_offset: 0x400000,
            max_offset: 0x400FFF,
            lifespan: Lifespan::span(0, 10),
        };
        cache.notify_new_entry(&range, "test_entry".to_string());
        assert!(cache.point_cache().is_empty()); // cleared on notify
    }

    #[test]
    fn test_containing_cache_range_computation() {
        let cache = ContainingQueryCache::<String>::new(10, 0x2000, 100);
        let range = cache.compute_new_cached_range(5, 0x400100);
        assert_eq!(range.lifespan.lmin(), 0);
        assert_eq!(range.lifespan.lmax(), 10);
        assert_eq!(range.min_offset, 0x400100 - 0x1000);
        assert_eq!(range.max_offset, 0x400100 + 0x1000);
    }

    #[test]
    fn test_containing_cache_invalidate() {
        let mut cache = ContainingQueryCache::<String>::new(10, 0x1000, 100);
        cache.point_cache_mut().insert(
            ContainingCacheKey::new(0, 0),
            Some("x".to_string()),
        );
        cache.invalidate();
        assert!(cache.point_cache().is_empty());
    }

    #[test]
    fn test_sequence_cache_basic() {
        let mut cache = SequenceQueryCache::<String>::new(5, 0x1000);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_sequence_cache_floor_ceiling() {
        let mut cache = SequenceQueryCache::<String>::new(5, 0x1000);
        cache.get_floor(0, 0x400050); // creates a region
        assert_eq!(cache.len(), 1);

        // Load some data
        cache.load_into_current_region(vec![
            (0x400010, "a".to_string()),
            (0x400020, "b".to_string()),
            (0x400050, "c".to_string()),
            (0x400080, "d".to_string()),
        ]);

        // Floor of 0x400050 should be "c"
        assert_eq!(cache.get_floor(0, 0x400050), Some("c".to_string()));
        // Floor of 0x400055 should be "c"
        assert_eq!(cache.get_floor(0, 0x400055), Some("c".to_string()));
        // Ceiling of 0x400050 should be "c"
        assert_eq!(cache.get_ceiling(0, 0x400050), Some("c".to_string()));
        // Ceiling of 0x400051 should be "d"
        assert_eq!(cache.get_ceiling(0, 0x400051), Some("d".to_string()));
    }

    #[test]
    fn test_cached_sequence_region() {
        let mut region = CachedSequenceRegion::<i32>::new(0, 0x1000, 0x2000);
        assert!(region.contains(0x1500));
        assert!(!region.contains(0x0500));
        assert!(!region.contains(0x3000));

        region.load(vec![(0x1100, 1), (0x1200, 2), (0x1500, 3)]);
        assert_eq!(region.get_floor(0x1200), Some(&2));
        assert_eq!(region.get_floor(0x1300), Some(&2));
        assert_eq!(region.get_ceiling(0x1200), Some(&2));
        assert_eq!(region.get_ceiling(0x1201), Some(&3));
    }

    #[test]
    fn test_containing_cache_range_intersect() {
        let a = TraceAddressSnapRange {
            min_offset: 0,
            max_offset: 100,
            lifespan: Lifespan::span(0, 10),
        };
        let b = TraceAddressSnapRange {
            min_offset: 50,
            max_offset: 150,
            lifespan: Lifespan::span(5, 15),
        };
        assert!(ContainingQueryCache::<()>::ranges_intersect(&a, &b));

        let c = TraceAddressSnapRange {
            min_offset: 200,
            max_offset: 300,
            lifespan: Lifespan::span(0, 10),
        };
        assert!(!ContainingQueryCache::<()>::ranges_intersect(&a, &c));
    }

    #[test]
    fn test_shared_caches() {
        let c = shared_containing_cache::<i32>(10, 0x100, 50);
        {
            let mut guard = c.write().unwrap();
            guard.invalidate();
        }
        let s = shared_sequence_cache::<i32>(5, 0x100);
        {
            let mut guard = s.write().unwrap();
            assert!(guard.is_empty());
        }
    }

    #[test]
    fn test_sequence_cache_eviction() {
        let mut cache = SequenceQueryCache::<i32>::new(2, 0x1000);
        // Fill to capacity
        cache.get_floor(0, 0x1000);
        cache.get_floor(0, 0x5000);
        assert_eq!(cache.len(), 2);
        // Trigger eviction
        cache.get_floor(0, 0x9000);
        assert_eq!(cache.len(), 2); // still 2, one was evicted
    }
}
