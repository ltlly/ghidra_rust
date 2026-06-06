//! Record management for trace database entries.
//!
//! Ported from Ghidra's Framework-TraceModeling record manager infrastructure.
//! Provides a generic record manager for trace database tables, supporting
//! record lifecycle (create, read, update, delete), caching, and iteration.

use std::collections::BTreeMap;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};

/// A unique record key within a trace database table.
pub type RecordKey = u64;

/// Metadata about a managed record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordInfo {
    /// The unique key.
    pub key: RecordKey,
    /// The table name this record belongs to.
    pub table: String,
    /// Whether this record has been modified since last save.
    pub dirty: bool,
    /// Version counter for optimistic concurrency.
    pub version: u64,
}

impl RecordInfo {
    /// Create new record info.
    pub fn new(key: RecordKey, table: impl Into<String>) -> Self {
        Self {
            key,
            table: table.into(),
            dirty: false,
            version: 0,
        }
    }

    /// Mark this record as dirty (modified).
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
        self.version += 1;
    }

    /// Mark this record as clean (saved).
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }
}

/// A record manager for a trace database table.
///
/// Manages records of type `T` indexed by `RecordKey`. Provides
/// CRUD operations with change tracking.
#[derive(Debug)]
pub struct TraceRecordManager<T: Debug + Clone> {
    /// The table name.
    table_name: String,
    /// The stored records.
    records: BTreeMap<RecordKey, T>,
    /// Record metadata.
    infos: BTreeMap<RecordKey, RecordInfo>,
    /// The next key to allocate.
    next_key: RecordKey,
    /// The set of keys modified since the last save checkpoint.
    dirty_keys: Vec<RecordKey>,
}

impl<T: Debug + Clone> TraceRecordManager<T> {
    /// Create a new record manager for the given table.
    pub fn new(table_name: impl Into<String>) -> Self {
        Self {
            table_name: table_name.into(),
            records: BTreeMap::new(),
            infos: BTreeMap::new(),
            next_key: 1,
            dirty_keys: Vec::new(),
        }
    }

    /// Get the table name.
    pub fn table_name(&self) -> &str {
        &self.table_name
    }

    /// Insert a new record and return its key.
    pub fn insert(&mut self, record: T) -> RecordKey {
        let key = self.next_key;
        self.next_key += 1;
        let mut info = RecordInfo::new(key, &self.table_name);
        info.mark_dirty();
        self.dirty_keys.push(key);
        self.infos.insert(key, info);
        self.records.insert(key, record);
        key
    }

    /// Get a reference to a record by key.
    pub fn get(&self, key: RecordKey) -> Option<&T> {
        self.records.get(&key)
    }

    /// Get a mutable reference to a record by key, marking it dirty.
    pub fn get_mut(&mut self, key: RecordKey) -> Option<&mut T> {
        if let Some(info) = self.infos.get_mut(&key) {
            info.mark_dirty();
            self.dirty_keys.push(key);
        }
        self.records.get_mut(&key)
    }

    /// Remove a record by key, returning it if it existed.
    pub fn remove(&mut self, key: RecordKey) -> Option<T> {
        self.infos.remove(&key);
        self.records.remove(&key)
    }

    /// Check if a record with the given key exists.
    pub fn contains_key(&self, key: RecordKey) -> bool {
        self.records.contains_key(&key)
    }

    /// Get the number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Check if the manager is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Iterate over all (key, record) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (RecordKey, &T)> {
        self.records.iter().map(|(&k, v)| (k, v))
    }

    /// Get all keys.
    pub fn keys(&self) -> impl Iterator<Item = RecordKey> + '_ {
        self.records.keys().copied()
    }

    /// Get all record info for dirty records.
    pub fn dirty_records(&self) -> Vec<&RecordInfo> {
        self.infos.values().filter(|i| i.dirty).collect()
    }

    /// Mark all records as clean.
    pub fn clear_dirty(&mut self) {
        self.dirty_keys.clear();
        for info in self.infos.values_mut() {
            info.mark_clean();
        }
    }

    /// Get the set of keys that have been modified since last clean.
    pub fn dirty_keys(&self) -> &[RecordKey] {
        &self.dirty_keys
    }

    /// Get the total record count.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Get record info for a key.
    pub fn info(&self, key: RecordKey) -> Option<&RecordInfo> {
        self.infos.get(&key)
    }

    /// Clear all records.
    pub fn clear(&mut self) {
        self.records.clear();
        self.infos.clear();
        self.dirty_keys.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_manager_insert_get() {
        let mut mgr = TraceRecordManager::<String>::new("test_table");
        let key = mgr.insert("hello".to_string());
        assert_eq!(mgr.get(key), Some(&"hello".to_string()));
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn test_record_manager_remove() {
        let mut mgr = TraceRecordManager::<i32>::new("numbers");
        let key = mgr.insert(42);
        assert!(mgr.contains_key(key));
        let removed = mgr.remove(key);
        assert_eq!(removed, Some(42));
        assert!(!mgr.contains_key(key));
        assert_eq!(mgr.len(), 0);
    }

    #[test]
    fn test_record_manager_get_mut_marks_dirty() {
        let mut mgr = TraceRecordManager::<String>::new("test");
        let key = mgr.insert("original".to_string());
        // insert already marks dirty (version=1)
        {
            let val = mgr.get_mut(key).unwrap();
            val.push_str("_modified");
        }
        let info = mgr.info(key).unwrap();
        assert!(info.dirty);
        assert_eq!(info.version, 2); // insert=1, get_mut=2
        assert_eq!(mgr.get(key).unwrap(), "original_modified");
    }

    #[test]
    fn test_record_manager_dirty_tracking() {
        let mut mgr = TraceRecordManager::<i32>::new("tracked");
        let k1 = mgr.insert(1);
        let _k2 = mgr.insert(2);
        let _k3 = mgr.insert(3);

        assert_eq!(mgr.dirty_records().len(), 3);

        mgr.clear_dirty();
        assert!(mgr.dirty_records().is_empty());

        mgr.get_mut(k1);
        assert_eq!(mgr.dirty_records().len(), 1);
    }

    #[test]
    fn test_record_manager_iter() {
        let mut mgr = TraceRecordManager::<i32>::new("iter_test");
        mgr.insert(10);
        mgr.insert(20);
        mgr.insert(30);

        let keys: Vec<RecordKey> = mgr.keys().collect();
        assert_eq!(keys.len(), 3);
    }
}
