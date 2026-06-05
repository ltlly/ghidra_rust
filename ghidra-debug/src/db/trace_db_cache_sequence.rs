//! Cache for "sequence" queries on address-snap ranges.
//!
//! Ported from Ghidra's `DBTraceCacheForSequenceQueries`.
//!
//! Provides caching for queries that fetch ordered sequences of entries
//! along a snap timeline, e.g., "give me the entry at address X that was
//! active at snap S."

use std::collections::HashMap;

use crate::db::trace_db_cache_containing::BoundedPointCache;
use crate::model::Lifespan;

/// A key for a sequence query: (snap, address_offset, thread_id).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SequenceQueryKey {
    /// The snapshot time.
    pub snap: i64,
    /// The address offset.
    pub offset: u64,
    /// The thread ID (0 for global).
    pub thread_id: u64,
}

impl SequenceQueryKey {
    /// Create a new sequence query key.
    pub fn new(snap: i64, offset: u64, thread_id: u64) -> Self {
        Self {
            snap,
            offset,
            thread_id,
        }
    }
}

/// An entry in the sequence cache with its lifespan.
#[derive(Debug, Clone)]
pub struct SequenceEntry<T> {
    /// The lifespan during which this entry is active.
    pub lifespan: Lifespan,
    /// The cached value.
    pub value: T,
}

/// Cache for "sequence" queries on address-snap ranges.
///
/// Caches the results of sequence queries that walk along the time axis
/// for a particular address to find the entry active at a given snap.
///
/// Ported from Ghidra's `DBTraceCacheForSequenceQueries`.
pub struct SequenceQueryCache<T: Clone> {
    /// The cached entries indexed by (offset, thread_id).
    entries: HashMap<(u64, u64), Vec<SequenceEntry<T>>>,
    /// Point cache for quick lookups.
    point_cache: BoundedPointCache<SequenceQueryKey, Option<T>>,
    max_entries_per_key: usize,
}

impl<T: Clone> SequenceQueryCache<T> {
    /// Create a new sequence query cache.
    pub fn new(max_point_cache: usize, max_entries_per_key: usize) -> Self {
        Self {
            entries: HashMap::new(),
            point_cache: BoundedPointCache::new(max_point_cache),
            max_entries_per_key,
        }
    }

    /// Create with default settings.
    pub fn with_defaults() -> Self {
        Self::new(1024, 64)
    }

    /// Get the sequence entries for a given (offset, thread_id) pair.
    pub fn get_entries(&self, offset: u64, thread_id: u64) -> Option<&Vec<SequenceEntry<T>>> {
        self.entries.get(&(offset, thread_id))
    }

    /// Find the entry active at the given snap within a sequence.
    pub fn find_active_at(&self, offset: u64, thread_id: u64, snap: i64) -> Option<&T> {
        self.entries.get(&(offset, thread_id)).and_then(|entries| {
            entries
                .iter()
                .find(|e| e.lifespan.contains(snap))
                .map(|e| &e.value)
        })
    }

    /// Cache the sequence for a given (offset, thread_id) pair.
    pub fn cache_entries(&mut self, offset: u64, thread_id: u64, entries: Vec<SequenceEntry<T>>) {
        self.point_cache.clear();
        self.entries.insert((offset, thread_id), entries);
    }

    /// Insert a single entry into the sequence for a given (offset, thread_id).
    pub fn insert_entry(&mut self, offset: u64, thread_id: u64, entry: SequenceEntry<T>) {
        self.point_cache.clear();
        let seq = self.entries.entry((offset, thread_id)).or_default();
        if seq.len() >= self.max_entries_per_key {
            // Remove the oldest entry
            seq.remove(0);
        }
        seq.push(entry);
    }

    /// Get a cached point result.
    pub fn get_cached_point(&self, key: &SequenceQueryKey) -> Option<Option<&T>> {
        self.point_cache.get(key).map(|v| v.as_ref())
    }

    /// Cache a point result.
    pub fn cache_point(&mut self, key: SequenceQueryKey, value: Option<T>) {
        self.point_cache.insert(key, value);
    }

    /// Invalidate all cached data for a given (offset, thread_id).
    pub fn invalidate_key(&mut self, offset: u64, thread_id: u64) {
        self.point_cache.clear();
        self.entries.remove(&(offset, thread_id));
    }

    /// Invalidate all caches.
    pub fn invalidate(&mut self) {
        self.point_cache.clear();
        self.entries.clear();
    }

    /// Get the number of cached sequences.
    pub fn key_count(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequence_query_find() {
        let mut cache = SequenceQueryCache::with_defaults();

        let entries = vec![
            SequenceEntry {
                lifespan: Lifespan::span(0, 9),
                value: "first".to_string(),
            },
            SequenceEntry {
                lifespan: Lifespan::span(10, 19),
                value: "second".to_string(),
            },
            SequenceEntry {
                lifespan: Lifespan::span(20, i64::MAX),
                value: "third".to_string(),
            },
        ];

        cache.cache_entries(0x1000, 0, entries);

        assert_eq!(
            cache.find_active_at(0x1000, 0, 5).map(|s| s.as_str()),
            Some("first")
        );
        assert_eq!(
            cache.find_active_at(0x1000, 0, 15).map(|s| s.as_str()),
            Some("second")
        );
        assert_eq!(
            cache.find_active_at(0x1000, 0, 25).map(|s| s.as_str()),
            Some("third")
        );
        assert!(cache.find_active_at(0x2000, 0, 5).is_none());
    }

    #[test]
    fn test_sequence_invalidation() {
        let mut cache = SequenceQueryCache::with_defaults();
        cache.insert_entry(
            0x1000,
            0,
            SequenceEntry {
                lifespan: Lifespan::span(0, 10),
                value: 42,
            },
        );

        assert_eq!(cache.key_count(), 1);
        cache.invalidate_key(0x1000, 0);
        assert_eq!(cache.key_count(), 0);
    }
}
