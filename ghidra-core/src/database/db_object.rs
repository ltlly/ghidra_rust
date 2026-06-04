//! Database object base types ported from Java's `DbObject` and `DbCache`.
//!
//! Provides the foundational caching and invalidation primitives used by every
//! database-backed manager (symbols, functions, references, etc.).
//!
//! - [`DbObject`]: base trait for objects stored in the database with a unique
//!   key, cache membership, and dirty/valid tracking.
//! - [`DbCache`]: generic LRU cache that ties object identity to a primary key
//!   and supports bulk invalidation via a modification counter.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, RwLock};

// ============================================================================
// DbObject trait (port of Java abstract DbObject)
// ============================================================================

/// Trait for database-backed objects that participate in the [`DbCache`].
///
/// Every concrete database object (FunctionDB, SymbolDB, etc.) stores its
/// primary key, tracks validity against a modification counter, and can be
/// refreshed from the underlying database.
pub trait DbObject: fmt::Debug + Send + Sync {
    /// Return the primary key of this object.
    fn key(&self) -> i64;

    /// Return true if this object has been deleted from the database.
    fn is_deleted(&self) -> bool;

    /// Mark this object as deleted.
    fn set_deleted(&mut self, deleted: bool);

    /// Return true if this object needs to be refreshed from the database.
    fn needs_refresh(&self, current_mod_count: i64) -> bool;

    /// Refresh this object from the given record data.
    ///
    /// Called when the cache detects a stale entry.  Implementations should
    /// re-read their backing record and update all cached fields.
    fn refresh(&mut self) -> Result<(), String>;

    /// Set the modification counter snapshot that was last applied to this
    /// object.
    fn set_mod_count(&mut self, count: i64);

    /// Mark this object as valid without re-reading from the database.
    fn set_valid(&mut self);
}

// ============================================================================
// DbCache<T> (port of Java DbCache<T extends DbObject>)
// ============================================================================

/// A keyed cache of [`DbObject`]s, backed by an `RwLock<HashMap>`.
///
/// Maintains a global modification counter; when the counter changes all
/// cached entries become stale and will be refreshed on next access.
pub struct DbCache<T: DbObject> {
    /// Map from primary key to cached object.
    entries: RwLock<HashMap<i64, Arc<RwLock<T>>>>,
    /// Monotonically increasing modification counter.
    mod_count: AtomicI64,
    /// Maximum number of entries (0 = unbounded).
    capacity: usize,
}

impl<T: DbObject> DbCache<T> {
    /// Create a new empty cache with the given capacity (0 = unbounded).
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            mod_count: AtomicI64::new(0),
            capacity,
        }
    }

    /// Return the current modification counter.
    pub fn get_modification_count(&self) -> i64 {
        self.mod_count.load(Ordering::Relaxed)
    }

    /// Increment the modification counter, marking all cached entries as stale.
    ///
    /// Mirrors Java `DbCache.invalidate()`.
    pub fn invalidate(&self) {
        self.mod_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Insert or replace an object in the cache.
    ///
    /// If the cache is at capacity the oldest entry is evicted.
    pub fn put(&self, obj: T) {
        let key = obj.key();
        let count = self.get_modification_count();
        let mut wrapped = obj;
        wrapped.set_mod_count(count);
        let arc = Arc::new(RwLock::new(wrapped));
        let mut entries = self.entries.write().unwrap();
        if self.capacity > 0 && entries.len() >= self.capacity && !entries.contains_key(&key) {
            // Evict a random entry (not LRU, but good enough).
            if let Some((&evict_key, _)) = entries.iter().next() {
                let evict_key = evict_key;
                entries.remove(&evict_key);
            }
        }
        entries.insert(key, arc);
    }

    /// Look up an object by key.
    ///
    /// Returns `None` if the key is not in the cache.
    pub fn get(&self, key: i64) -> Option<Arc<RwLock<T>>> {
        let entries = self.entries.read().unwrap();
        entries.get(&key).cloned()
    }

    /// Look up an object by key, refreshing it if the cache has been
    /// invalidated since the object was last read.
    pub fn get_validated(&self, key: i64) -> Option<Arc<RwLock<T>>> {
        let current = self.get_modification_count();
        let arc = self.get(key)?;
        {
            let mut obj = arc.write().unwrap();
            if obj.needs_refresh(current) {
                if obj.refresh().is_err() {
                    obj.set_deleted(true);
                    return None;
                }
                obj.set_mod_count(current);
            }
            if obj.is_deleted() {
                return None;
            }
        }
        Some(arc)
    }

    /// Remove an entry by key.
    pub fn remove(&self, key: i64) -> Option<Arc<RwLock<T>>> {
        let mut entries = self.entries.write().unwrap();
        entries.remove(&key)
    }

    /// Return the number of entries currently cached.
    pub fn len(&self) -> usize {
        let entries = self.entries.read().unwrap();
        entries.len()
    }

    /// Return true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        let entries = self.entries.read().unwrap();
        entries.is_empty()
    }

    /// Remove all entries.
    pub fn clear(&self) {
        let mut entries = self.entries.write().unwrap();
        entries.clear();
    }

    /// Iterate over all cached keys.
    pub fn keys(&self) -> Vec<i64> {
        let entries = self.entries.read().unwrap();
        entries.keys().copied().collect()
    }

    /// Iterate over all cached values (cloned Arc references).
    pub fn values(&self) -> Vec<Arc<RwLock<T>>> {
        let entries = self.entries.read().unwrap();
        entries.values().cloned().collect()
    }
}

impl<T: DbObject + fmt::Debug> fmt::Debug for DbCache<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self.entries.read().unwrap();
        f.debug_struct("DbCache")
            .field("len", &entries.len())
            .field("capacity", &self.capacity)
            .field("mod_count", &self.mod_count.load(Ordering::Relaxed))
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestObject {
        key_val: i64,
        deleted: bool,
        mod_count_val: i64,
        data: String,
    }

    impl TestObject {
        fn new(key: i64, data: &str) -> Self {
            Self {
                key_val: key,
                deleted: false,
                mod_count_val: -1,
                data: data.to_string(),
            }
        }
    }

    impl DbObject for TestObject {
        fn key(&self) -> i64 { self.key_val }
        fn is_deleted(&self) -> bool { self.deleted }
        fn set_deleted(&mut self, deleted: bool) { self.deleted = deleted; }
        fn needs_refresh(&self, current_mod_count: i64) -> bool {
            current_mod_count != self.mod_count_val
        }
        fn refresh(&mut self) -> Result<(), String> { Ok(()) }
        fn set_mod_count(&mut self, count: i64) { self.mod_count_val = count; }
        fn set_valid(&mut self) { self.mod_count_val = 0; }
    }

    #[test]
    fn test_cache_put_get() {
        let cache = DbCache::<TestObject>::new(10);
        cache.put(TestObject::new(1, "hello"));
        cache.put(TestObject::new(2, "world"));

        assert_eq!(cache.len(), 2);
        let obj = cache.get(1).unwrap();
        assert_eq!(obj.read().unwrap().data, "hello");
    }

    #[test]
    fn test_cache_remove() {
        let cache = DbCache::<TestObject>::new(10);
        cache.put(TestObject::new(1, "a"));
        assert_eq!(cache.len(), 1);
        cache.remove(1);
        assert_eq!(cache.len(), 0);
        assert!(cache.get(1).is_none());
    }

    #[test]
    fn test_cache_invalidate() {
        let cache = DbCache::<TestObject>::new(10);
        assert_eq!(cache.get_modification_count(), 0);
        cache.invalidate();
        assert_eq!(cache.get_modification_count(), 1);
        cache.invalidate();
        assert_eq!(cache.get_modification_count(), 2);
    }

    #[test]
    fn test_cache_validated_refresh() {
        let cache = DbCache::<TestObject>::new(10);
        cache.put(TestObject::new(1, "before"));

        // Invalidate so the next get_validated triggers a refresh.
        cache.invalidate();
        let obj = cache.get_validated(1).unwrap();
        assert_eq!(obj.read().unwrap().data, "before"); // refresh() is a no-op here
    }

    #[test]
    fn test_cache_validated_deleted() {
        let cache = DbCache::<TestObject>::new(10);
        cache.put(TestObject::new(1, "gone"));
        // Mark the entry as deleted.
        {
            let obj = cache.get(1).unwrap();
            obj.write().unwrap().set_deleted(true);
        }
        cache.invalidate();
        assert!(cache.get_validated(1).is_none());
    }

    #[test]
    fn test_cache_eviction() {
        let cache = DbCache::<TestObject>::new(2);
        cache.put(TestObject::new(1, "a"));
        cache.put(TestObject::new(2, "b"));
        cache.put(TestObject::new(3, "c")); // should evict one
        assert!(cache.len() <= 2);
    }

    #[test]
    fn test_cache_keys_values() {
        let cache = DbCache::<TestObject>::new(10);
        cache.put(TestObject::new(10, "a"));
        cache.put(TestObject::new(20, "b"));
        let mut keys = cache.keys();
        keys.sort();
        assert_eq!(keys, vec![10, 20]);
        assert_eq!(cache.values().len(), 2);
    }

    #[test]
    fn test_cache_clear() {
        let cache = DbCache::<TestObject>::new(10);
        cache.put(TestObject::new(1, "a"));
        cache.put(TestObject::new(2, "b"));
        cache.clear();
        assert!(cache.is_empty());
    }
}
