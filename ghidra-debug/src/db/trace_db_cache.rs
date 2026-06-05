//! Database trace caching layer.
//!
//! Ported from Ghidra's `ghidra.trace.database.DBTraceCacheForContainingQueries`
//! and `ghidra.trace.database.DBTraceCacheForSequenceQueries`.
//! Provides caching mechanisms for frequently accessed trace data
//! to avoid repeated database queries.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A cache entry for containing queries.
///
/// When the UI queries "what objects contain address X?", the result
/// is cached here to avoid repeated lookups.
#[derive(Debug, Clone)]
pub struct ContainingQueryCache<T: Clone> {
    /// The cache entries keyed by (space, offset).
    entries: HashMap<u64, CachedEntry<T>>,
    /// Maximum number of entries.
    max_size: usize,
    /// Cache hit count.
    hits: u64,
    /// Cache miss count.
    misses: u64,
}

impl<T: Clone> ContainingQueryCache<T> {
    /// Create a new cache with the given maximum size.
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(max_size.min(1024)),
            max_size,
            hits: 0,
            misses: 0,
        }
    }

    /// Look up a cached entry by key.
    pub fn get(&mut self, key: u64) -> Option<&CachedEntry<T>> {
        if let Some(entry) = self.entries.get(&key) {
            self.hits += 1;
            Some(entry)
        } else {
            self.misses += 1;
            None
        }
    }

    /// Insert a cache entry.
    pub fn insert(&mut self, key: u64, value: T) {
        if self.entries.len() >= self.max_size {
            self.evict_one();
        }
        self.entries.insert(key, CachedEntry { value });
    }

    /// Invalidate entries matching a predicate.
    pub fn invalidate_where<F: Fn(&T) -> bool>(&mut self, predicate: F) {
        self.entries.retain(|_, entry| !predicate(&entry.value));
    }

    /// Clear the entire cache.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the cache hit rate (hits / (hits + misses)).
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }

    /// Get the number of cache hits.
    pub fn hits(&self) -> u64 {
        self.hits
    }

    /// Get the number of cache misses.
    pub fn misses(&self) -> u64 {
        self.misses
    }

    /// Simple eviction: remove the first entry.
    fn evict_one(&mut self) {
        if let Some(first_key) = self.entries.keys().next().copied() {
            self.entries.remove(&first_key);
        }
    }
}

/// A cached entry wrapping a value.
#[derive(Debug, Clone)]
pub struct CachedEntry<T: Clone> {
    /// The cached value.
    pub value: T,
}

/// A cache for sequence queries.
///
/// When the UI queries "what is the next object after address X?",
/// the result is cached to speed up sequential traversal.
#[derive(Debug, Clone)]
pub struct SequenceQueryCache<T: Clone> {
    /// Entries keyed by (start_key).
    entries: HashMap<u64, SequenceCacheEntry<T>>,
    /// Maximum entries.
    max_size: usize,
}

#[derive(Debug, Clone)]
struct SequenceCacheEntry<T: Clone> {
    /// The result for this sequence query.
    result: Vec<T>,
}

impl<T: Clone> SequenceQueryCache<T> {
    /// Create a new sequence query cache.
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_size,
        }
    }

    /// Look up a cached sequence starting at the given key.
    pub fn get(&self, key: u64) -> Option<&[T]> {
        self.entries.get(&key).map(|e| e.result.as_slice())
    }

    /// Insert a sequence query result.
    pub fn insert(&mut self, key: u64, result: Vec<T>) {
        if self.entries.len() >= self.max_size {
            if let Some(first_key) = self.entries.keys().next().copied() {
                self.entries.remove(&first_key);
            }
        }
        self.entries.insert(key, SequenceCacheEntry { result });
    }

    /// Invalidate all entries that contain a value matching the predicate.
    pub fn invalidate_where<F: Fn(&T) -> bool>(&mut self, predicate: F) {
        self.entries.retain(|_, entry| {
            !entry.result.iter().any(|v| predicate(v))
        });
    }

    /// Clear the cache.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Configuration for trace database caching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCacheConfig {
    /// Maximum entries in the containing query cache.
    pub containing_cache_size: usize,
    /// Maximum entries in the sequence query cache.
    pub sequence_cache_size: usize,
    /// Whether caching is enabled.
    pub enabled: bool,
}

impl Default for TraceCacheConfig {
    fn default() -> Self {
        Self {
            containing_cache_size: 4096,
            sequence_cache_size: 256,
            enabled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_containing_cache_basic() {
        let mut cache = ContainingQueryCache::new(100);
        assert!(cache.is_empty());

        cache.insert(1, "item1".to_string());
        cache.insert(2, "item2".to_string());
        assert_eq!(cache.len(), 2);

        let entry = cache.get(1);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().value, "item1");

        assert_eq!(cache.hits(), 1);
        assert_eq!(cache.misses(), 0);
    }

    #[test]
    fn test_containing_cache_miss() {
        let mut cache = ContainingQueryCache::<String>::new(100);
        let entry = cache.get(999);
        assert!(entry.is_none());
        assert_eq!(cache.misses(), 1);
    }

    #[test]
    fn test_containing_cache_eviction() {
        let mut cache = ContainingQueryCache::new(2);
        cache.insert(1, "a");
        cache.insert(2, "b");
        cache.insert(3, "c"); // should evict one
        assert!(cache.len() <= 2);
    }

    #[test]
    fn test_containing_cache_invalidate() {
        let mut cache = ContainingQueryCache::new(100);
        cache.insert(1, "remove_me".to_string());
        cache.insert(2, "keep".to_string());
        cache.invalidate_where(|v| v == "remove_me");
        assert_eq!(cache.len(), 1);
        assert!(cache.get(1).is_none());
        assert!(cache.get(2).is_some());
    }

    #[test]
    fn test_containing_cache_hit_rate() {
        let mut cache = ContainingQueryCache::new(100);
        cache.insert(1, "a");
        cache.get(1); // hit
        cache.get(2); // miss
        let rate = cache.hit_rate();
        assert!((rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_containing_cache_clear() {
        let mut cache = ContainingQueryCache::new(100);
        cache.insert(1, "a");
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_sequence_cache() {
        let mut cache = SequenceQueryCache::new(100);
        cache.insert(1, vec!["a".to_string(), "b".to_string()]);

        let result = cache.get(1).unwrap();
        assert_eq!(result, &["a", "b"]);
        assert!(cache.get(99).is_none());
    }

    #[test]
    fn test_sequence_cache_invalidate() {
        let mut cache = SequenceQueryCache::new(100);
        cache.insert(1, vec!["a".to_string(), "remove".to_string()]);
        cache.insert(2, vec!["keep".to_string()]);
        cache.invalidate_where(|v| v == "remove");
        assert!(cache.get(1).is_none());
        assert!(cache.get(2).is_some());
    }

    #[test]
    fn test_cache_config_default() {
        let config = TraceCacheConfig::default();
        assert_eq!(config.containing_cache_size, 4096);
        assert!(config.enabled);
    }
}
