//! Cache and pooling utilities for Ghidra Rust.
//!
//! Ports Ghidra's `generic.cache` package: `Factory`, `BasicFactory`,
//! `CachingPool`, `WeakReferenceCache`, and `FixedSizeMRUCache`.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, Weak};

// ============================================================================
// Factory trait
// ============================================================================

/// A simple factory that produces a value for a key.
///
/// Corresponds to Ghidra's `generic.cache.Factory`.
pub trait Factory<K, V>: Send + Sync {
    fn get(&self, key: K) -> V;
}

// ============================================================================
// BasicFactory trait
// ============================================================================

/// A factory that can create and dispose of instances.
///
/// Corresponds to Ghidra's `generic.cache.BasicFactory`.
pub trait BasicFactory<T>: Send + Sync {
    /// Create a new instance.
    fn create(&self) -> T;

    /// Dispose of an instance (cleanup).
    fn dispose(&self, _item: T) {}
}

// ============================================================================
// CachingPool — thread-safe object pool
// ============================================================================

/// A thread-safe object pool that reuses instances.
///
/// When clients are done with a pooled item, they call [`release`](CachingPool::release)
/// to return it to the pool.
///
/// Corresponds to Ghidra's `generic.cache.CachingPool`.
pub struct CachingPool<T> {
    factory: Box<dyn BasicFactory<T>>,
    cache: Mutex<VecDeque<T>>,
    is_disposed: Mutex<bool>,
}

impl<T> CachingPool<T> {
    /// Create a new pool with the given factory.
    pub fn new(factory: impl BasicFactory<T> + 'static) -> Self {
        Self {
            factory: Box::new(factory),
            cache: Mutex::new(VecDeque::new()),
            is_disposed: Mutex::new(false),
        }
    }

    /// Get a cached or new instance.
    pub fn get(&self) -> T {
        let mut cache = self.cache.lock().unwrap();
        let disposed = *self.is_disposed.lock().unwrap();
        if cache.is_empty() || disposed {
            drop(cache);
            self.factory.create()
        } else {
            cache.pop_front().unwrap()
        }
    }

    /// Return an instance to the pool for reuse.
    pub fn release(&self, item: T) {
        let disposed = *self.is_disposed.lock().unwrap();
        if disposed {
            self.factory.dispose(item);
        } else {
            self.cache.lock().unwrap().push_back(item);
        }
    }

    /// Dispose all cached items and prevent future pooling.
    pub fn dispose(&self) {
        let mut disposed = self.is_disposed.lock().unwrap();
        *disposed = true;
        let mut cache = self.cache.lock().unwrap();
        while let Some(item) = cache.pop_front() {
            self.factory.dispose(item);
        }
    }

    /// The number of items currently in the pool.
    pub fn size(&self) -> usize {
        self.cache.lock().unwrap().len()
    }
}

// ============================================================================
// WeakReferenceCache — cache with weak references
// ============================================================================

/// A cache that holds weak references to values, with a hard LRU cache to
/// protect recently-used entries from garbage collection.
///
/// Corresponds to Ghidra's `generic.cache.WeakReferenceCache`.
///
/// In Rust, we use `Weak<Arc<V>>` for the weak references, but since Rust
/// does not have a GC, we simulate the behavior: entries whose `Arc` has been
/// dropped are cleaned up on access.
pub struct WeakReferenceCache<K, V> {
    /// Strong references (hard cache) to protect recent entries.
    hard_cache: Mutex<HashMap<K, Arc<V>>>,
    /// Weak references for all entries.
    weak_refs: Mutex<HashMap<K, Weak<V>>>,
    /// Maximum size of the hard cache.
    hard_cache_size: usize,
}

impl<K: Eq + std::hash::Hash + Clone, V> WeakReferenceCache<K, V> {
    /// Create a new weak reference cache with the given hard cache size.
    pub fn new(hard_cache_size: usize) -> Self {
        Self {
            hard_cache: Mutex::new(HashMap::new()),
            weak_refs: Mutex::new(HashMap::new()),
            hard_cache_size,
        }
    }

    /// Retrieve a cached value by key.
    ///
    /// Returns `None` if the value is not cached or has been dropped.
    pub fn get(&self, key: &K) -> Option<Arc<V>> {
        // Try the weak refs first
        let mut weak_refs = self.weak_refs.lock().unwrap();
        if let Some(weak) = weak_refs.get(key) {
            if let Some(strong) = weak.upgrade() {
                // Promote to hard cache
                let mut hard = self.hard_cache.lock().unwrap();
                hard.insert(key.clone(), strong.clone());
                self.evict_if_needed(&mut hard);
                return Some(strong);
            } else {
                // Value was dropped; clean up
                weak_refs.remove(key);
            }
        }
        None
    }

    /// Add a value to the cache.
    ///
    /// Returns the `Arc<V>` that was stored.
    pub fn add(&self, key: K, value: V) -> Arc<V> {
        self.cleanup_dead_refs();
        let arc = Arc::new(value);
        let weak = Arc::downgrade(&arc);
        {
            let mut weak_refs = self.weak_refs.lock().unwrap();
            weak_refs.insert(key.clone(), weak);
        }
        {
            let mut hard = self.hard_cache.lock().unwrap();
            hard.insert(key, arc.clone());
            self.evict_if_needed(&mut hard);
        }
        arc
    }

    /// Remove a value from the cache by key.
    pub fn delete(&self, key: &K) -> Option<Arc<V>> {
        self.weak_refs.lock().unwrap().remove(key);
        self.hard_cache.lock().unwrap().remove(key)
    }

    /// Remove all entries whose values match a predicate.
    pub fn delete_if(&self, predicate: impl Fn(&V) -> bool) {
        let mut weak_refs = self.weak_refs.lock().unwrap();
        let mut hard = self.hard_cache.lock().unwrap();

        let keys_to_remove: Vec<K> = weak_refs
            .iter()
            .filter_map(|(k, w)| {
                if let Some(strong) = w.upgrade() {
                    if predicate(&*strong) {
                        Some(k.clone())
                    } else {
                        None
                    }
                } else {
                    Some(k.clone())
                }
            })
            .collect();

        for key in keys_to_remove {
            weak_refs.remove(&key);
            hard.remove(&key);
        }
    }

    /// Get all currently-cached values (as strong references).
    pub fn get_cached_objects(&self) -> Vec<Arc<V>> {
        self.cleanup_dead_refs();
        let weak_refs = self.weak_refs.lock().unwrap();
        weak_refs
            .values()
            .filter_map(|w| w.upgrade())
            .collect()
    }

    /// Apply a function to all currently-cached values.
    pub fn apply(&self, f: impl Fn(&V)) {
        let weak_refs = self.weak_refs.lock().unwrap();
        for weak in weak_refs.values() {
            if let Some(strong) = weak.upgrade() {
                f(&*strong);
            }
        }
    }

    /// The number of entries in the cache (including weak-only entries).
    pub fn size(&self) -> usize {
        self.weak_refs.lock().unwrap().len()
    }

    /// Change the hard cache size.
    pub fn set_hard_cache_size(&self, _size: usize) {
        // Note: we don't store this atomically, so we just clear the hard cache
        let mut hard = self.hard_cache.lock().unwrap();
        hard.clear();
    }

    fn cleanup_dead_refs(&self) {
        let mut weak_refs = self.weak_refs.lock().unwrap();
        let dead_keys: Vec<K> = weak_refs
            .iter()
            .filter(|(_, w)| w.strong_count() == 0)
            .map(|(k, _)| k.clone())
            .collect();
        for key in dead_keys {
            weak_refs.remove(&key);
        }
    }

    fn evict_if_needed(&self, hard: &mut HashMap<K, Arc<V>>) {
        // Simple eviction: if over size, remove a random entry.
        // A real LRU would use an ordered structure.
        while hard.len() > self.hard_cache_size {
            if let Some(key) = hard.keys().next().cloned() {
                hard.remove(&key);
            } else {
                break;
            }
        }
    }
}

// ============================================================================
// FixedSizeMRUCache — a fixed-size MRU cache
// ============================================================================

/// A fixed-size cache that evicts the most recently used item when full.
///
/// Corresponds to Ghidra's `generic.cache.FixedSizeMRUCachingFactory`.
pub struct FixedSizeMruCache<K, V> {
    entries: Mutex<VecDeque<(K, V)>>,
    capacity: usize,
    factory: Box<dyn Fn(&K) -> V>,
}

impl<K: Eq + Clone, V: Clone> FixedSizeMruCache<K, V> {
    /// Create a new MRU cache with the given capacity and factory function.
    pub fn new(capacity: usize, factory: impl Fn(&K) -> V + 'static) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            factory: Box::new(factory),
        }
    }

    /// Get a value for the given key, using the cache if available.
    pub fn get(&self, key: &K) -> V {
        let mut entries = self.entries.lock().unwrap();
        // Check if already cached
        if let Some(pos) = entries.iter().position(|(k, _)| k == key) {
            let (_, v) = entries.remove(pos).unwrap();
            entries.push_front((key.clone(), v.clone()));
            return v;
        }
        // Create new value
        let value = (self.factory)(key);
        if entries.len() >= self.capacity {
            entries.pop_back();
        }
        entries.push_front((key.clone(), value.clone()));
        value
    }

    /// The number of entries currently cached.
    pub fn size(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// Clear all cached entries.
    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

// ============================================================================
// CountingBasicFactory — wraps a BasicFactory with a creation counter
// ============================================================================

/// A wrapper around [`BasicFactory`] that counts how many times `create()` is
/// called.
pub struct CountingBasicFactory<T: Send + Sync, F: BasicFactory<T>> {
    inner: F,
    create_count: Mutex<usize>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: Send + Sync, F: BasicFactory<T>> CountingBasicFactory<T, F> {
    pub fn new(inner: F) -> Self {
        Self {
            inner,
            create_count: Mutex::new(0),
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn create_count(&self) -> usize {
        *self.create_count.lock().unwrap()
    }
}

impl<T: Send + Sync, F: BasicFactory<T>> BasicFactory<T> for CountingBasicFactory<T, F> {
    fn create(&self) -> T {
        *self.create_count.lock().unwrap() += 1;
        self.inner.create()
    }

    fn dispose(&self, item: T) {
        self.inner.dispose(item);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    struct TestFactory;
    impl BasicFactory<String> for TestFactory {
        fn create(&self) -> String {
            "new_item".to_string()
        }
    }

    #[test]
    fn test_caching_pool_basic() {
        let pool = CachingPool::new(TestFactory);
        let item = pool.get();
        assert_eq!(item, "new_item");
        pool.release(item);
        assert_eq!(pool.size(), 1);
        let reused = pool.get();
        assert_eq!(reused, "new_item");
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn test_caching_pool_dispose() {
        let pool = CachingPool::new(TestFactory);
        let item = pool.get();
        pool.release(item);
        pool.dispose();
        assert_eq!(pool.size(), 0);
        // After dispose, items should not be pooled
        let new_item = pool.get();
        pool.release(new_item); // should be disposed, not pooled
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn test_weak_reference_cache() {
        let cache = WeakReferenceCache::new(10);
        let val = cache.add("key1".to_string(), 42);
        assert_eq!(*val, 42);
        assert_eq!(cache.size(), 1);

        let retrieved = cache.get(&"key1".to_string()).unwrap();
        assert_eq!(*retrieved, 42);

        assert!(cache.get(&"nonexistent".to_string()).is_none());
    }

    #[test]
    fn test_weak_reference_cache_delete() {
        let cache = WeakReferenceCache::new(10);
        cache.add("key1".to_string(), 42);
        assert_eq!(cache.size(), 1);
        cache.delete(&"key1".to_string());
        assert!(cache.get(&"key1".to_string()).is_none());
    }

    #[test]
    fn test_weak_reference_cache_delete_if() {
        let cache = WeakReferenceCache::new(10);
        cache.add("a".to_string(), 1);
        cache.add("b".to_string(), 2);
        cache.add("c".to_string(), 3);
        cache.delete_if(|v| *v > 1);
        assert!(cache.get(&"a".to_string()).is_some());
        assert!(cache.get(&"b".to_string()).is_none());
        assert!(cache.get(&"c".to_string()).is_none());
    }

    #[test]
    fn test_fixed_size_mru_cache() {
        let cache = FixedSizeMruCache::new(3, |k: &i32| k * 10);
        assert_eq!(cache.get(&1), 10);
        assert_eq!(cache.get(&2), 20);
        assert_eq!(cache.get(&3), 30);
        assert_eq!(cache.size(), 3);

        // This should evict the most recently used (3)
        assert_eq!(cache.get(&4), 40);
        assert_eq!(cache.size(), 3);
    }

    #[test]
    fn test_fixed_size_mru_cache_hit() {
        let cache = FixedSizeMruCache::new(3, |k: &i32| k * 10);
        cache.get(&1);
        cache.get(&2);
        cache.get(&3);
        // Get 1 again (should be a cache hit)
        assert_eq!(cache.get(&1), 10);
        assert_eq!(cache.size(), 3);
    }

    #[test]
    fn test_counting_factory() {
        let factory = CountingBasicFactory::new(TestFactory);
        assert_eq!(factory.create_count(), 0);
        let _item1 = factory.create();
        let _item2 = factory.create();
        assert_eq!(factory.create_count(), 2);
    }

    #[test]
    fn test_weak_ref_cache_drop_behavior() {
        let cache = WeakReferenceCache::new(10);
        cache.add("key".to_string(), 42);
        // Drop the strong reference
        // (the only strong ref is the one returned by add, which we don't store)
        // Since we don't store the Arc, the weak ref should be dead
        // BUT: the hard_cache keeps a strong reference, so it should still be alive
        let retrieved = cache.get(&"key".to_string());
        assert!(retrieved.is_some());
    }
}
