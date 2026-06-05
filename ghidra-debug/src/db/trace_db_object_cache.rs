//! Per-object value cache for the target object system.
//!
//! Ported from Ghidra's `CachePerDBTraceObject` in
//! `ghidra.trace.database.target`. Provides LRU-bounded caching of
//! object values indexed by snap and entry key, with expand-on-query
//! semantics to exploit temporal locality.

use std::collections::{BTreeMap, HashMap};

use crate::model::Lifespan;

/// Maximum number of per-key cache entries before LRU eviction.
const MAX_CACHE_KEYS: usize = 200;

/// Temporal expansion window for locality exploitation.
const EXPANSION: i64 = 10;

/// A composite key for sorting cached values by (snap, entry_key).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SnapKey {
    /// The snap (time) component.
    pub snap: i64,
    /// The entry key (attribute or element name).
    pub key: Option<String>,
}

impl SnapKey {
    /// Create a new snap key.
    pub fn new(snap: i64, key: Option<String>) -> Self {
        Self { snap, key }
    }
}

impl PartialOrd for SnapKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SnapKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.snap
            .cmp(&other.snap)
            .then_with(|| match (&self.key, &other.key) {
                (Some(a), Some(b)) => a.cmp(b),
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, None) => std::cmp::Ordering::Equal,
            })
    }
}

/// A cache result that may be a hit or miss.
#[derive(Debug, Clone)]
pub enum Cached<T> {
    /// The value was not found in cache.
    Miss,
    /// The value was found in cache.
    Hit(T),
}

impl<T> Cached<T> {
    /// Returns true if this is a cache miss.
    pub fn is_miss(&self) -> bool {
        matches!(self, Cached::Miss)
    }

    /// Returns the hit value, or None.
    pub fn value(&self) -> Option<&T> {
        match self {
            Cached::Hit(v) => Some(v),
            Cached::Miss => None,
        }
    }

    /// Unwrap the hit value or panic.
    pub fn unwrap(self) -> T {
        match self {
            Cached::Hit(v) => v,
            Cached::Miss => panic!("unwrap on Cached::Miss"),
        }
    }
}

/// Cached lifespan-bounded values keyed by snap.
#[derive(Debug, Clone)]
pub struct CachedLifespanValues<K: Ord> {
    /// The lifespan this cache covers.
    pub span: Lifespan,
    /// The cached values indexed by snap key.
    pub values: BTreeMap<K, usize>, // usize is a placeholder for object value ID
}

impl<K: Ord> CachedLifespanValues<K> {
    /// Create new cached lifespan values.
    pub fn new(span: Lifespan) -> Self {
        Self {
            span,
            values: BTreeMap::new(),
        }
    }

    /// Whether this cache covers the given snap.
    pub fn contains_snap(&self, snap: i64) -> bool {
        self.span.contains(snap)
    }

    /// Whether this cache encloses the given lifespan.
    pub fn encloses(&self, lifespan: &Lifespan) -> bool {
        self.span.encloses(lifespan)
    }
}

/// Per-object value cache, ported from Ghidra's `CachePerDBTraceObject`.
///
/// Provides LRU-bounded per-key and all-key caches for efficient
/// temporal queries against a trace object's values.
#[derive(Debug)]
pub struct CachePerDbTraceObject {
    /// Per-key cache with LRU eviction.
    per_key_cache: HashMap<String, CachedLifespanValues<i64>>,
    /// All-keys cache for cross-key queries.
    any_key_cache: Option<CachedLifespanValues<SnapKey>>,
    /// LRU ordering for per-key cache eviction.
    lru_order: Vec<String>,
}

impl CachePerDbTraceObject {
    /// Create a new per-object cache.
    pub fn new() -> Self {
        Self {
            per_key_cache: HashMap::new(),
            any_key_cache: None,
            lru_order: Vec::new(),
        }
    }

    /// Look up a value by snap and entry key.
    pub fn get_value(&mut self, snap: i64, key: &str) -> Cached<usize> {
        // First, check and extract the result without holding borrows
        let result = if let Some(cached) = self.per_key_cache.get(key) {
            if cached.contains_snap(snap) {
                // Find the floor entry (greatest snap <= requested snap)
                cached.values.range(..=snap).next_back().map(|(_, id)| *id)
            } else {
                None
            }
        } else {
            None
        };
        // Touch LRU after the immutable borrow is released
        if result.is_some() {
            self.touch_lru(key);
        }
        match result {
            Some(id) => Cached::Hit(id),
            None => Cached::Miss,
        }
    }

    /// Look up values for any key in the given lifespan.
    pub fn stream_values(&self, lifespan: &Lifespan) -> Cached<Vec<usize>> {
        if let Some(ref cached) = self.any_key_cache {
            if cached.encloses(lifespan) {
                let results: Vec<usize> = cached
                    .values
                    .range(..)
                    .filter(|(k, _)| lifespan.contains(k.snap))
                    .map(|(_, id)| *id)
                    .collect();
                return Cached::Hit(results);
            }
        }
        Cached::Miss
    }

    /// Look up values for a specific key in the given lifespan.
    pub fn stream_values_for_key(&self, lifespan: &Lifespan, key: &str, forward: bool) -> Cached<Vec<usize>> {
        if let Some(cached) = self.per_key_cache.get(key) {
            if cached.encloses(lifespan) {
                let results: Vec<usize> = if forward {
                    cached
                        .values
                        .range(lifespan.lmin()..=lifespan.lmax())
                        .map(|(_, id)| *id)
                        .collect()
                } else {
                    cached
                        .values
                        .range(lifespan.lmin()..=lifespan.lmax())
                        .rev()
                        .map(|(_, id)| *id)
                        .collect()
                };
                return Cached::Hit(results);
            }
        }
        Cached::Miss
    }

    /// Expand a lifespan query to take advantage of temporal locality.
    pub fn expand_lifespan(&self, lifespan: &Lifespan) -> Lifespan {
        let min = lifespan.lmin().saturating_sub(EXPANSION);
        let max = lifespan.lmax().saturating_add(EXPANSION);
        Lifespan::span(min.max(Lifespan::ALL.lmin()), max.min(Lifespan::ALL.lmax()))
    }

    /// Notify the cache that a value was created.
    pub fn notify_value_created(&mut self, snap: i64, key: &str, value_id: usize) {
        if let Some(ref mut cached) = self.any_key_cache {
            if cached.span.contains(snap) {
                cached.values.insert(SnapKey::new(snap, Some(key.to_string())), value_id);
            }
        }
        if let Some(cached) = self.per_key_cache.get_mut(key) {
            if cached.span.contains(snap) {
                cached.values.insert(snap, value_id);
            }
        }
    }

    /// Notify the cache that a value was deleted.
    pub fn notify_value_deleted(&mut self, snap: i64, key: &str) {
        if let Some(ref mut cached) = self.any_key_cache {
            cached.values.remove(&SnapKey::new(snap, Some(key.to_string())));
        }
        if let Some(cached) = self.per_key_cache.get_mut(key) {
            cached.values.remove(&snap);
        }
    }

    /// Populate the per-key cache for a given key and lifespan.
    pub fn populate_key(&mut self, key: String, span: Lifespan) {
        self.evict_if_needed();
        self.per_key_cache
            .insert(key.clone(), CachedLifespanValues::new(span));
        self.lru_order.push(key);
    }

    /// Populate the all-key cache for a given lifespan.
    pub fn populate_any_key(&mut self, span: Lifespan) {
        self.any_key_cache = Some(CachedLifespanValues::new(span));
    }

    /// Invalidate the entire cache.
    pub fn invalidate(&mut self) {
        self.per_key_cache.clear();
        self.any_key_cache = None;
        self.lru_order.clear();
    }

    /// Whether the per-key cache has an entry for the given key.
    pub fn has_key(&self, key: &str) -> bool {
        self.per_key_cache.contains_key(key)
    }

    /// Whether the all-key cache is populated.
    pub fn has_any_key_cache(&self) -> bool {
        self.any_key_cache.is_some()
    }

    fn touch_lru(&mut self, key: &str) {
        if let Some(pos) = self.lru_order.iter().position(|k| k == key) {
            let entry = self.lru_order.remove(pos);
            self.lru_order.push(entry);
        }
    }

    fn evict_if_needed(&mut self) {
        while self.per_key_cache.len() >= MAX_CACHE_KEYS {
            if let Some(oldest) = self.lru_order.first().cloned() {
                self.per_key_cache.remove(&oldest);
                self.lru_order.remove(0);
            } else {
                break;
            }
        }
    }
}

impl Default for CachePerDbTraceObject {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snap_key_ordering() {
        let k1 = SnapKey::new(5, Some("a".to_string()));
        let k2 = SnapKey::new(10, Some("a".to_string()));
        let k3 = SnapKey::new(10, Some("b".to_string()));
        let k4 = SnapKey::new(10, None);
        assert!(k1 < k2);
        assert!(k2 < k3);
        assert!(k3 < k4);
    }

    #[test]
    fn test_snap_key_same_snap_different_key() {
        let k1 = SnapKey::new(5, Some("alpha".to_string()));
        let k2 = SnapKey::new(5, Some("beta".to_string()));
        assert!(k1 < k2);
    }

    #[test]
    fn test_cached_hit_miss() {
        let miss: Cached<i32> = Cached::Miss;
        assert!(miss.is_miss());
        assert!(miss.value().is_none());

        let hit: Cached<i32> = Cached::Hit(42);
        assert!(!hit.is_miss());
        assert_eq!(hit.value(), Some(&42));
        assert_eq!(hit.unwrap(), 42);
    }

    #[test]
    fn test_cache_populate_and_get() {
        let mut cache = CachePerDbTraceObject::new();
        cache.populate_key("mykey".to_string(), Lifespan::span(0, 100));
        assert!(cache.has_key("mykey"));
        assert!(!cache.has_key("other"));

        // Cache miss (nothing populated with values yet)
        let result = cache.get_value(50, "mykey");
        assert!(result.is_miss());
    }

    #[test]
    fn test_cache_notify_created_and_get() {
        let mut cache = CachePerDbTraceObject::new();
        cache.populate_key("attr".to_string(), Lifespan::span(0, 100));
        cache.notify_value_created(5, "attr", 42);
        let result = cache.get_value(5, "attr");
        assert!(!result.is_miss());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_cache_notify_deleted() {
        let mut cache = CachePerDbTraceObject::new();
        cache.populate_key("attr".to_string(), Lifespan::span(0, 100));
        cache.notify_value_created(5, "attr", 42);
        cache.notify_value_deleted(5, "attr");
        let result = cache.get_value(5, "attr");
        assert!(result.is_miss());
    }

    #[test]
    fn test_cache_expand_lifespan() {
        let cache = CachePerDbTraceObject::new();
        let ls = Lifespan::span(20, 30);
        let expanded = cache.expand_lifespan(&ls);
        assert!(expanded.lmin() <= 20);
        assert!(expanded.lmax() >= 30);
    }

    #[test]
    fn test_cache_invalidate() {
        let mut cache = CachePerDbTraceObject::new();
        cache.populate_key("k".to_string(), Lifespan::span(0, 100));
        cache.populate_any_key(Lifespan::span(0, 100));
        assert!(cache.has_key("k"));
        assert!(cache.has_any_key_cache());
        cache.invalidate();
        assert!(!cache.has_key("k"));
        assert!(!cache.has_any_key_cache());
    }

    #[test]
    fn test_cache_lru_eviction() {
        let mut cache = CachePerDbTraceObject::new();
        for i in 0..MAX_CACHE_KEYS + 10 {
            cache.populate_key(format!("key_{}", i), Lifespan::span(0, 100));
        }
        // Should have evicted the oldest entries
        assert!(cache.per_key_cache.len() <= MAX_CACHE_KEYS);
    }

    #[test]
    fn test_cached_lifespan_values_encloses() {
        let cached = CachedLifespanValues::<i64>::new(Lifespan::span(10, 100));
        assert!(cached.encloses(&Lifespan::span(20, 50)));
        assert!(!cached.encloses(&Lifespan::span(5, 50)));
        assert!(!cached.encloses(&Lifespan::span(50, 150)));
    }
}
