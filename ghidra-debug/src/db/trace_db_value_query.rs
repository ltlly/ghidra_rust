//! TraceObjectValueQuery and TraceObjectValueStorage - query and storage
//! interfaces for target object values in the trace database.
//!
//! Ported from Ghidra's `TraceObjectValueQuery` and `TraceObjectValueStorage`
//! in `ghidra.trace.database.target`.
//!
//! These provide the interface for querying and storing values in the
//! target object tree, including spatial (address-based) queries.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// Interface for querying values stored in the target object tree.
///
/// Ported from Ghidra's `TraceObjectValueQuery`. Provides methods
/// for finding values by entry key, address range, and lifespan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceObjectValueQuery {
    /// The parent object ID.
    pub parent_id: u64,
    /// Optional entry key filter.
    pub entry_key: Option<String>,
    /// Optional lifespan filter.
    pub lifespan: Option<Lifespan>,
    /// Optional address range filter (min, max).
    pub address_range: Option<(u64, u64)>,
    /// Maximum number of results (0 = unlimited).
    pub limit: usize,
    /// Whether to include values from child objects.
    pub include_children: bool,
}

impl TraceObjectValueQuery {
    /// Create a new query for all values of a parent object.
    pub fn new(parent_id: u64) -> Self {
        Self {
            parent_id,
            entry_key: None,
            lifespan: None,
            address_range: None,
            limit: 0,
            include_children: false,
        }
    }

    /// Filter by entry key.
    pub fn with_entry_key(mut self, key: impl Into<String>) -> Self {
        self.entry_key = Some(key.into());
        self
    }

    /// Filter by lifespan.
    pub fn with_lifespan(mut self, lifespan: Lifespan) -> Self {
        self.lifespan = Some(lifespan);
        self
    }

    /// Filter by address range.
    pub fn with_address_range(mut self, min: u64, max: u64) -> Self {
        self.address_range = Some((min, max));
        self
    }

    /// Set the maximum number of results.
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// Include values from child objects.
    pub fn with_children(mut self) -> Self {
        self.include_children = true;
        self
    }

    /// Check if this query matches a value with the given entry key.
    pub fn matches_entry_key(&self, key: &str) -> bool {
        match &self.entry_key {
            Some(filter) => filter == key,
            None => true,
        }
    }

    /// Check if this query matches a value with the given lifespan.
    pub fn matches_lifespan(&self, lifespan: &Lifespan) -> bool {
        match &self.lifespan {
            Some(filter) => filter.intersects(lifespan),
            None => true,
        }
    }

    /// Check if this query matches a value at the given address.
    pub fn matches_address(&self, address: u64) -> bool {
        match self.address_range {
            Some((min, max)) => address >= min && address <= max,
            None => true,
        }
    }
}

/// Interface for storing and retrieving values in the trace database.
///
/// Ported from Ghidra's `TraceObjectValueStorage`. Defines the
/// contract for persisting target object values.
pub trait TraceObjectValueStorage: std::fmt::Debug {
    /// Get the parent object ID.
    fn get_parent_id(&self) -> u64;

    /// Get the wrapper (value entry) ID.
    fn get_wrapper_id(&self) -> u64;

    /// Get the entry key.
    fn get_entry_key(&self) -> &str;

    /// Get the lifespan of this value.
    fn get_lifespan(&self) -> Lifespan;

    /// Set the lifespan (no notifications).
    fn do_set_lifespan(&mut self, lifespan: Lifespan);

    /// Get the child object ID, if this value references a child.
    fn get_child_id(&self) -> Option<u64>;

    /// Get the primitive value, if this is a primitive value entry.
    fn get_value(&self) -> Option<&serde_json::Value>;

    /// Check if this value has been deleted.
    fn is_deleted(&self) -> bool;

    /// Delete this value (mark for deletion).
    fn do_delete(&mut self);
}

/// A concrete implementation of value storage for database-backed traces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceValueStorage {
    parent_id: u64,
    wrapper_id: u64,
    entry_key: String,
    lifespan: Lifespan,
    child_id: Option<u64>,
    value: Option<serde_json::Value>,
    deleted: bool,
}

impl DbTraceValueStorage {
    /// Create a new value storage entry with a primitive value.
    pub fn new_primitive(
        parent_id: u64,
        wrapper_id: u64,
        entry_key: impl Into<String>,
        lifespan: Lifespan,
        value: serde_json::Value,
    ) -> Self {
        Self {
            parent_id,
            wrapper_id,
            entry_key: entry_key.into(),
            lifespan,
            child_id: None,
            value: Some(value),
            deleted: false,
        }
    }

    /// Create a new value storage entry with a child reference.
    pub fn new_child_ref(
        parent_id: u64,
        wrapper_id: u64,
        entry_key: impl Into<String>,
        lifespan: Lifespan,
        child_id: u64,
    ) -> Self {
        Self {
            parent_id,
            wrapper_id,
            entry_key: entry_key.into(),
            lifespan,
            child_id: Some(child_id),
            value: None,
            deleted: false,
        }
    }
}

impl TraceObjectValueStorage for DbTraceValueStorage {
    fn get_parent_id(&self) -> u64 {
        self.parent_id
    }

    fn get_wrapper_id(&self) -> u64 {
        self.wrapper_id
    }

    fn get_entry_key(&self) -> &str {
        &self.entry_key
    }

    fn get_lifespan(&self) -> Lifespan {
        self.lifespan.clone()
    }

    fn do_set_lifespan(&mut self, lifespan: Lifespan) {
        self.lifespan = lifespan;
    }

    fn get_child_id(&self) -> Option<u64> {
        self.child_id
    }

    fn get_value(&self) -> Option<&serde_json::Value> {
        self.value.as_ref()
    }

    fn is_deleted(&self) -> bool {
        self.deleted
    }

    fn do_delete(&mut self) {
        self.deleted = true;
    }
}

/// A per-object cache for database trace objects.
///
/// Ported from Ghidra's `CachePerDBTraceObject`. Provides an LRU-style
/// cache that is keyed per object, useful for caching computed values
/// that are expensive to recompute.
#[derive(Debug, Clone)]
pub struct CachePerDBTraceObject<V> {
    /// Cache entries by object ID.
    entries: std::collections::HashMap<u64, V>,
    /// Maximum number of entries.
    max_entries: usize,
    /// Access order for LRU eviction.
    access_order: Vec<u64>,
}

impl<V> CachePerDBTraceObject<V> {
    /// Create a new cache with the given capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            max_entries,
            access_order: Vec::new(),
        }
    }

    /// Get a value from the cache.
    pub fn get(&mut self, object_id: u64) -> Option<&V> {
        if self.entries.contains_key(&object_id) {
            // Move to back of access order
            self.access_order.retain(|&x| x != object_id);
            self.access_order.push(object_id);
            self.entries.get(&object_id)
        } else {
            None
        }
    }

    /// Insert a value into the cache.
    pub fn put(&mut self, object_id: u64, value: V) {
        if self.entries.len() >= self.max_entries && !self.entries.contains_key(&object_id) {
            // Evict LRU entry
            if let Some(lru_id) = self.access_order.first().copied() {
                self.entries.remove(&lru_id);
                self.access_order.remove(0);
            }
        }
        self.entries.insert(object_id, value);
        self.access_order.retain(|&x| x != object_id);
        self.access_order.push(object_id);
    }

    /// Remove an entry from the cache.
    pub fn remove(&mut self, object_id: u64) -> Option<V> {
        self.access_order.retain(|&x| x != object_id);
        self.entries.remove(&object_id)
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.access_order.clear();
    }

    /// Get the current number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_query_basic() {
        let q = TraceObjectValueQuery::new(1);
        assert_eq!(q.parent_id, 1);
        assert!(q.entry_key.is_none());
        assert!(q.matches_entry_key("anything"));
        assert!(q.matches_address(0x1000));
    }

    #[test]
    fn test_value_query_with_filters() {
        let q = TraceObjectValueQuery::new(1)
            .with_entry_key("key1")
            .with_address_range(0x1000, 0x2000)
            .with_limit(10);

        assert!(q.matches_entry_key("key1"));
        assert!(!q.matches_entry_key("key2"));
        assert!(q.matches_address(0x1500));
        assert!(!q.matches_address(0x3000));
        assert_eq!(q.limit, 10);
    }

    #[test]
    fn test_value_storage_primitive() {
        let mut storage = DbTraceValueStorage::new_primitive(
            1, 2, "key", Lifespan::span(0, 10), serde_json::json!(42),
        );
        assert_eq!(storage.get_parent_id(), 1);
        assert_eq!(storage.get_entry_key(), "key");
        assert!(storage.get_child_id().is_none());
        assert!(storage.get_value().is_some());
        assert!(!storage.is_deleted());

        storage.do_delete();
        assert!(storage.is_deleted());
    }

    #[test]
    fn test_value_storage_child_ref() {
        let storage = DbTraceValueStorage::new_child_ref(
            1, 2, "child_key", Lifespan::span(0, 5), 99,
        );
        assert_eq!(storage.get_child_id(), Some(99));
        assert!(storage.get_value().is_none());
    }

    #[test]
    fn test_cache_basic() {
        let mut cache = CachePerDBTraceObject::<String>::new(3);
        cache.put(1, "one".to_string());
        cache.put(2, "two".to_string());
        cache.put(3, "three".to_string());

        assert_eq!(cache.len(), 3);
        assert_eq!(cache.get(1), Some(&"one".to_string()));
    }

    #[test]
    fn test_cache_eviction() {
        let mut cache = CachePerDBTraceObject::<i32>::new(2);
        cache.put(1, 10);
        cache.put(2, 20);
        cache.put(3, 30); // Should evict object 1

        assert_eq!(cache.len(), 2);
        assert!(cache.get(1).is_none());
        assert_eq!(cache.get(2), Some(&20));
        assert_eq!(cache.get(3), Some(&30));
    }

    #[test]
    fn test_cache_remove() {
        let mut cache = CachePerDBTraceObject::<i32>::new(5);
        cache.put(1, 10);
        let removed = cache.remove(1);
        assert_eq!(removed, Some(10));
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_access_order_update() {
        let mut cache = CachePerDBTraceObject::<i32>::new(2);
        cache.put(1, 10);
        cache.put(2, 20);
        cache.get(1); // Access 1 to move it to back
        cache.put(3, 30); // Should evict 2, not 1

        assert!(cache.get(1).is_some());
        assert!(cache.get(2).is_none());
        assert!(cache.get(3).is_some());
    }
}
