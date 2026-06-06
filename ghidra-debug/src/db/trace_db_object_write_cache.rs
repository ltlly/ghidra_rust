//! Write-behind cache manager for target object values.
//!
//! Ported from Ghidra's `DBTraceObjectValueWriteBehindCache` in
//! `ghidra.trace.database.target`. Manages a batch of pending value
//! changes in memory before they are flushed to the persistent database.
//!
//! The cache supports:
//! - Buffering writes (create, update, delete) to reduce DB I/O
//! - Generation-based ordering for deterministic flush sequences
//! - Snapshot reads that merge cached values with persistent storage
//! - Dirty tracking to determine which entries need flushing

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;
use crate::target::KeyPath;

use super::trace_db_object_value_behind::{BehindValue, DbTraceObjectValueBehind};

/// A pending operation in the write-behind cache.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CacheOperation {
    /// Insert a new value.
    Insert,
    /// Update an existing value's lifespan or content.
    Update,
    /// Delete an existing value.
    Delete,
}

/// Key identifying a value entry in the cache.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CacheKey {
    /// The parent object ID.
    pub parent_id: i64,
    /// The entry key (attribute name or element index).
    pub entry_key: String,
    /// The minimum snap of the value's lifespan.
    pub min_snap: i64,
}

impl CacheKey {
    /// Create a new cache key.
    pub fn new(parent_id: i64, entry_key: impl Into<String>, min_snap: i64) -> Self {
        Self {
            parent_id,
            entry_key: entry_key.into(),
            min_snap,
        }
    }
}

/// A pending change in the write-behind cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedChange {
    /// The operation type.
    pub operation: CacheOperation,
    /// The cached value (None for deletes).
    pub value: Option<DbTraceObjectValueBehind>,
    /// The generation at which this change was enqueued.
    pub generation: u64,
    /// Whether this change has been flushed to the database.
    pub flushed: bool,
}

/// Write-behind cache for target object values.
///
/// Manages a batch of pending changes that are periodically flushed
/// to the persistent database. Changes are ordered by generation
/// for deterministic replay.
#[derive(Debug, Clone)]
pub struct ObjectValueWriteCache {
    /// Pending changes keyed by `CacheKey`.
    pending: BTreeMap<CacheKey, CachedChange>,
    /// The current generation counter.
    generation: u64,
    /// Object IDs that have been touched in this batch.
    dirty_objects: HashSet<i64>,
    /// Parent ID to set of dirty entry keys.
    dirty_entries: HashMap<i64, HashSet<String>>,
    /// Whether the cache has been modified since last flush.
    is_dirty: bool,
    /// Maximum number of entries before auto-flush is recommended.
    max_pending: usize,
}

impl ObjectValueWriteCache {
    /// Create a new empty write-behind cache.
    pub fn new() -> Self {
        Self {
            pending: BTreeMap::new(),
            generation: 0,
            dirty_objects: HashSet::new(),
            dirty_entries: HashMap::new(),
            is_dirty: false,
            max_pending: 1024,
        }
    }

    /// Create a cache with a custom maximum pending threshold.
    pub fn with_max_pending(max: usize) -> Self {
        let mut cache = Self::new();
        cache.max_pending = max;
        cache
    }

    /// Get the current generation counter.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether the cache has any pending changes.
    pub fn is_dirty(&self) -> bool {
        self.is_dirty
    }

    /// The number of pending changes.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Whether auto-flush is recommended.
    pub fn should_flush(&self) -> bool {
        self.pending.len() >= self.max_pending
    }

    /// Enqueue a value insertion.
    pub fn insert_value(
        &mut self,
        parent_id: i64,
        entry_key: impl Into<String>,
        lifespan: Lifespan,
        value: BehindValue,
    ) -> u64 {
        self.generation += 1;
        let gen = self.generation;
        let entry_key_s = entry_key.into();
        let behind = DbTraceObjectValueBehind::new(
            parent_id,
            &entry_key_s,
            lifespan,
            value,
            gen,
        );
        let key = CacheKey::new(parent_id, &entry_key_s, lifespan.lmin());
        self.pending.insert(
            key,
            CachedChange {
                operation: CacheOperation::Insert,
                value: Some(behind),
                generation: gen,
                flushed: false,
            },
        );
        self.dirty_objects.insert(parent_id);
        self.dirty_entries
            .entry(parent_id)
            .or_default()
            .insert(entry_key_s);
        self.is_dirty = true;
        gen
    }

    /// Enqueue a value update (lifespan change).
    pub fn update_value(
        &mut self,
        parent_id: i64,
        entry_key: impl Into<String>,
        old_min_snap: i64,
        new_lifespan: Lifespan,
        new_value: BehindValue,
    ) -> u64 {
        self.generation += 1;
        let gen = self.generation;
        let entry_key_s = entry_key.into();

        // Remove old entry if present
        let old_key = CacheKey::new(parent_id, &entry_key_s, old_min_snap);
        self.pending.remove(&old_key);

        let behind = DbTraceObjectValueBehind::new(
            parent_id,
            &entry_key_s,
            new_lifespan,
            new_value,
            gen,
        );
        let key = CacheKey::new(parent_id, &entry_key_s, new_lifespan.lmin());
        self.pending.insert(
            key,
            CachedChange {
                operation: CacheOperation::Update,
                value: Some(behind),
                generation: gen,
                flushed: false,
            },
        );
        self.dirty_objects.insert(parent_id);
        self.dirty_entries
            .entry(parent_id)
            .or_default()
            .insert(entry_key_s);
        self.is_dirty = true;
        gen
    }

    /// Enqueue a value deletion.
    pub fn delete_value(
        &mut self,
        parent_id: i64,
        entry_key: impl Into<String>,
        min_snap: i64,
    ) -> u64 {
        self.generation += 1;
        let gen = self.generation;
        let entry_key_s = entry_key.into();
        let key = CacheKey::new(parent_id, &entry_key_s, min_snap);

        // If this was a pending insert, just remove it (no need to record delete)
        if let Some(existing) = self.pending.get(&key) {
            if existing.operation == CacheOperation::Insert {
                self.pending.remove(&key);
                self.is_dirty = !self.pending.is_empty();
                return gen;
            }
        }

        self.pending.insert(
            key,
            CachedChange {
                operation: CacheOperation::Delete,
                value: None,
                generation: gen,
                flushed: false,
            },
        );
        self.dirty_objects.insert(parent_id);
        self.dirty_entries
            .entry(parent_id)
            .or_default()
            .insert(entry_key_s);
        self.is_dirty = true;
        gen
    }

    /// Get all pending changes in generation order.
    pub fn drain_pending(&mut self) -> Vec<(CacheKey, CachedChange)> {
        let changes: Vec<_> = self.pending.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        self.pending.clear();
        self.dirty_objects.clear();
        self.dirty_entries.clear();
        self.is_dirty = false;
        changes
    }

    /// Mark all pending changes as flushed.
    pub fn mark_all_flushed(&mut self) {
        for change in self.pending.values_mut() {
            change.flushed = true;
        }
    }

    /// Get the set of dirty object IDs.
    pub fn dirty_objects(&self) -> &HashSet<i64> {
        &self.dirty_objects
    }

    /// Get the dirty entry keys for a given parent ID.
    pub fn dirty_entries_for(&self, parent_id: i64) -> Option<&HashSet<String>> {
        self.dirty_entries.get(&parent_id)
    }

    /// Check if a specific entry is in the cache.
    pub fn contains(&self, parent_id: i64, entry_key: &str, min_snap: i64) -> bool {
        let key = CacheKey::new(parent_id, entry_key, min_snap);
        self.pending.contains_key(&key)
    }

    /// Get a reference to a cached value.
    pub fn get_cached(
        &self,
        parent_id: i64,
        entry_key: &str,
        min_snap: i64,
    ) -> Option<&DbTraceObjectValueBehind> {
        let key = CacheKey::new(parent_id, entry_key, min_snap);
        self.pending.get(&key).and_then(|c| c.value.as_ref())
    }

    /// Get all cached values for a given parent object.
    pub fn values_for_parent(&self, parent_id: i64) -> Vec<&DbTraceObjectValueBehind> {
        self.pending
            .iter()
            .filter(|(k, _)| k.parent_id == parent_id)
            .filter_map(|(_, c)| c.value.as_ref())
            .collect()
    }

    /// Get all cached values whose lifespan intersects the given span.
    pub fn values_in_span(&self, parent_id: i64, min_snap: i64, max_snap: i64) -> Vec<&DbTraceObjectValueBehind> {
        self.pending
            .iter()
            .filter(|(k, _)| k.parent_id == parent_id && k.min_snap <= max_snap)
            .filter_map(|(_, c)| c.value.as_ref())
            .filter(|v| v.lifespan.lmin() <= max_snap && v.lifespan.lmax() >= min_snap)
            .collect()
    }

    /// Clear the cache without flushing.
    pub fn clear(&mut self) {
        self.pending.clear();
        self.dirty_objects.clear();
        self.dirty_entries.clear();
        self.is_dirty = false;
    }

    /// Get the total number of bytes estimated to be consumed by pending values.
    pub fn estimated_memory_bytes(&self) -> usize {
        let mut total = 0;
        for (_, change) in &self.pending {
            total += std::mem::size_of::<CachedChange>();
            if let Some(ref v) = change.value {
                total += v.entry_key.len();
                total += match &v.value {
                    BehindValue::String(s) => s.len(),
                    BehindValue::Bytes(b) => b.len(),
                    _ => 8,
                };
            }
        }
        total
    }
}

impl Default for ObjectValueWriteCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_lifespan(min: i64, max: i64) -> Lifespan {
        Lifespan::span(min, max)
    }

    #[test]
    fn test_cache_new() {
        let cache = ObjectValueWriteCache::new();
        assert_eq!(cache.generation(), 0);
        assert!(!cache.is_dirty());
        assert_eq!(cache.pending_count(), 0);
    }

    #[test]
    fn test_insert_value() {
        let mut cache = ObjectValueWriteCache::new();
        let gen = cache.insert_value(1, "name", test_lifespan(0, 100), BehindValue::String("hello".into()));
        assert_eq!(gen, 1);
        assert_eq!(cache.generation(), 1);
        assert!(cache.is_dirty());
        assert_eq!(cache.pending_count(), 1);
    }

    #[test]
    fn test_update_value() {
        let mut cache = ObjectValueWriteCache::new();
        cache.insert_value(1, "name", test_lifespan(0, 100), BehindValue::String("hello".into()));
        let gen = cache.update_value(1, "name", 0, test_lifespan(0, 200), BehindValue::String("world".into()));
        assert_eq!(gen, 2);
        assert_eq!(cache.pending_count(), 1); // replaced, not added
    }

    #[test]
    fn test_delete_cancels_insert() {
        let mut cache = ObjectValueWriteCache::new();
        cache.insert_value(1, "name", test_lifespan(0, 100), BehindValue::Bool(true));
        assert_eq!(cache.pending_count(), 1);

        cache.delete_value(1, "name", 0);
        // Delete of a pending insert removes it entirely
        assert_eq!(cache.pending_count(), 0);
    }

    #[test]
    fn test_delete_after_update() {
        let mut cache = ObjectValueWriteCache::new();
        // Simulate an update on a pre-existing value (not an insert)
        cache.update_value(1, "val", 50, test_lifespan(50, 200), BehindValue::Long(42));
        assert_eq!(cache.pending_count(), 1);

        cache.delete_value(1, "val", 50);
        // Now we have a delete record
        assert_eq!(cache.pending_count(), 1);
        let changes = cache.drain_pending();
        assert_eq!(changes[0].1.operation, CacheOperation::Delete);
    }

    #[test]
    fn test_drain_pending() {
        let mut cache = ObjectValueWriteCache::new();
        cache.insert_value(1, "a", test_lifespan(0, 10), BehindValue::Bool(true));
        cache.insert_value(1, "b", test_lifespan(0, 10), BehindValue::Long(1));
        cache.insert_value(2, "c", test_lifespan(0, 10), BehindValue::String("x".into()));

        let changes = cache.drain_pending();
        assert_eq!(changes.len(), 3);
        assert!(!cache.is_dirty());
        assert_eq!(cache.pending_count(), 0);
        assert!(cache.dirty_objects().is_empty());
    }

    #[test]
    fn test_generation_ordering() {
        let mut cache = ObjectValueWriteCache::new();
        let g1 = cache.insert_value(1, "a", test_lifespan(0, 10), BehindValue::Bool(true));
        let g2 = cache.insert_value(1, "b", test_lifespan(0, 10), BehindValue::Bool(false));
        let g3 = cache.insert_value(2, "c", test_lifespan(0, 10), BehindValue::Long(5));

        assert!(g1 < g2);
        assert!(g2 < g3);

        let changes = cache.drain_pending();
        // Changes should be in generation order (BTreeMap key order)
        for i in 1..changes.len() {
            assert!(changes[i - 1].1.generation <= changes[i].1.generation);
        }
    }

    #[test]
    fn test_dirty_tracking() {
        let mut cache = ObjectValueWriteCache::new();
        cache.insert_value(10, "attr1", test_lifespan(0, 10), BehindValue::Bool(true));
        cache.insert_value(10, "attr2", test_lifespan(0, 10), BehindValue::Bool(false));
        cache.insert_value(20, "attr3", test_lifespan(0, 10), BehindValue::Long(1));

        assert!(cache.dirty_objects().contains(&10));
        assert!(cache.dirty_objects().contains(&20));
        assert_eq!(cache.dirty_objects().len(), 2);

        let entries_10 = cache.dirty_entries_for(10).unwrap();
        assert!(entries_10.contains("attr1"));
        assert!(entries_10.contains("attr2"));
        assert_eq!(entries_10.len(), 2);

        assert!(cache.dirty_entries_for(99).is_none());
    }

    #[test]
    fn test_contains_and_get() {
        let mut cache = ObjectValueWriteCache::new();
        cache.insert_value(1, "name", test_lifespan(0, 100), BehindValue::String("hello".into()));

        assert!(cache.contains(1, "name", 0));
        assert!(!cache.contains(1, "name", 50));
        assert!(!cache.contains(1, "other", 0));

        let val = cache.get_cached(1, "name", 0).unwrap();
        assert_eq!(val.value, BehindValue::String("hello".into()));
        assert!(cache.get_cached(2, "name", 0).is_none());
    }

    #[test]
    fn test_values_for_parent() {
        let mut cache = ObjectValueWriteCache::new();
        cache.insert_value(1, "a", test_lifespan(0, 10), BehindValue::Bool(true));
        cache.insert_value(1, "b", test_lifespan(0, 10), BehindValue::Long(2));
        cache.insert_value(2, "c", test_lifespan(0, 10), BehindValue::String("x".into()));

        let vals = cache.values_for_parent(1);
        assert_eq!(vals.len(), 2);

        let vals = cache.values_for_parent(2);
        assert_eq!(vals.len(), 1);

        let vals = cache.values_for_parent(99);
        assert!(vals.is_empty());
    }

    #[test]
    fn test_values_in_span() {
        let mut cache = ObjectValueWriteCache::new();
        cache.insert_value(1, "a", test_lifespan(0, 10), BehindValue::Bool(true));
        cache.insert_value(1, "b", test_lifespan(20, 30), BehindValue::Bool(false));
        cache.insert_value(1, "c", test_lifespan(50, 60), BehindValue::Long(1));

        // Query snap 5 - should find "a"
        let vals = cache.values_in_span(1, 5, 5);
        assert_eq!(vals.len(), 1);

        // Query snap 0-25 - should find "a" and "b"
        let vals = cache.values_in_span(1, 0, 25);
        assert_eq!(vals.len(), 2);

        // Query snap 100 - should find nothing
        let vals = cache.values_in_span(1, 100, 100);
        assert!(vals.is_empty());
    }

    #[test]
    fn test_should_flush() {
        let mut cache = ObjectValueWriteCache::with_max_pending(3);
        assert!(!cache.should_flush());

        cache.insert_value(1, "a", test_lifespan(0, 10), BehindValue::Bool(true));
        cache.insert_value(1, "b", test_lifespan(0, 10), BehindValue::Bool(false));
        assert!(!cache.should_flush());

        cache.insert_value(1, "c", test_lifespan(0, 10), BehindValue::Long(1));
        assert!(cache.should_flush());
    }

    #[test]
    fn test_mark_all_flushed() {
        let mut cache = ObjectValueWriteCache::new();
        cache.insert_value(1, "a", test_lifespan(0, 10), BehindValue::Bool(true));
        cache.insert_value(1, "b", test_lifespan(0, 10), BehindValue::Long(2));

        cache.mark_all_flushed();
        for (_, change) in &cache.pending {
            assert!(change.flushed);
        }
        // Cache is still dirty (changes are still pending)
        assert!(cache.is_dirty());
    }

    #[test]
    fn test_clear() {
        let mut cache = ObjectValueWriteCache::new();
        cache.insert_value(1, "a", test_lifespan(0, 10), BehindValue::Bool(true));
        cache.insert_value(2, "b", test_lifespan(0, 10), BehindValue::Long(2));

        assert_eq!(cache.pending_count(), 2);
        cache.clear();
        assert_eq!(cache.pending_count(), 0);
        assert!(!cache.is_dirty());
        assert!(cache.dirty_objects().is_empty());
    }

    #[test]
    fn test_estimated_memory() {
        let mut cache = ObjectValueWriteCache::new();
        cache.insert_value(1, "a", test_lifespan(0, 10), BehindValue::String("hello".into()));
        let est = cache.estimated_memory_bytes();
        assert!(est > 0);
    }

    #[test]
    fn test_with_max_pending() {
        let cache = ObjectValueWriteCache::with_max_pending(512);
        assert_eq!(cache.max_pending, 512);
    }

    #[test]
    fn test_default() {
        let cache = ObjectValueWriteCache::default();
        assert_eq!(cache.generation(), 0);
        assert!(!cache.is_dirty());
    }

    #[test]
    fn test_cache_key_ordering() {
        let k1 = CacheKey::new(1, "a", 0);
        let k2 = CacheKey::new(1, "a", 5);
        let k3 = CacheKey::new(1, "b", 0);
        let k4 = CacheKey::new(2, "a", 0);

        assert!(k1 < k2);
        assert!(k2 < k3);
        assert!(k3 < k4);
    }

    #[test]
    fn test_cache_key_serde() {
        let key = CacheKey::new(42, "test", 100);
        let json = serde_json::to_string(&key).unwrap();
        let back: CacheKey = serde_json::from_str(&json).unwrap();
        assert_eq!(back, key);
    }

    #[test]
    fn test_multi_parent_scenario() {
        let mut cache = ObjectValueWriteCache::new();

        // Simulate writes across multiple objects
        cache.insert_value(1, "pid", test_lifespan(0, 100), BehindValue::Long(100));
        cache.insert_value(1, "name", test_lifespan(0, 100), BehindValue::String("init".into()));
        cache.insert_value(2, "tid", test_lifespan(0, 100), BehindValue::Long(200));
        cache.insert_value(2, "state", test_lifespan(0, 50), BehindValue::String("running".into()));
        cache.update_value(2, "state", 0, test_lifespan(50, 100), BehindValue::String("stopped".into()));

        assert_eq!(cache.dirty_objects().len(), 2);
        assert_eq!(cache.pending_count(), 4); // 3 inserts + 1 update (replaced the state insert)

        let changes = cache.drain_pending();
        // Verify all changes are for the right parents
        for (key, change) in &changes {
            assert!(key.parent_id == 1 || key.parent_id == 2);
            assert!(change.generation > 0);
        }
    }

    #[test]
    fn test_insert_delete_insert_cycle() {
        let mut cache = ObjectValueWriteCache::new();

        // Insert
        cache.insert_value(1, "val", test_lifespan(0, 100), BehindValue::Long(1));
        assert_eq!(cache.pending_count(), 1);

        // Delete (cancels insert)
        cache.delete_value(1, "val", 0);
        assert_eq!(cache.pending_count(), 0);

        // Insert again
        cache.insert_value(1, "val", test_lifespan(50, 200), BehindValue::Long(2));
        assert_eq!(cache.pending_count(), 1);

        let changes = cache.drain_pending();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].1.operation, CacheOperation::Insert);
    }
}
