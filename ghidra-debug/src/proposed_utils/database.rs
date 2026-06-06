//! Database utility types.
//!
//! Ported from Ghidra's `ghidra.util.database` package.
//!
//! Provides key spans, field spans, directed iterators, and
//! the annotated object framework.

use serde::{Deserialize, Serialize};

/// The direction of iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IterDirection {
    /// Forward (ascending).
    Forward,
    /// Backward (descending).
    Backward,
}

/// A span of contiguous long keys.
///
/// Ported from Ghidra's `KeySpan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySpan {
    /// The minimum key (inclusive).
    pub min: i64,
    /// The maximum key (inclusive).
    pub max: i64,
}

impl KeySpan {
    /// Create a new key span.
    pub fn new(min: i64, max: i64) -> Self {
        assert!(min <= max, "KeySpan: min ({}) > max ({})", min, max);
        Self { min, max }
    }

    /// The number of keys in the span.
    pub fn len(&self) -> i64 {
        self.max - self.min + 1
    }

    /// Whether the span is empty (degenerate).
    pub fn is_empty(&self) -> bool {
        false // A valid span always has at least one key
    }

    /// Whether the span contains the given key.
    pub fn contains(&self, key: i64) -> bool {
        key >= self.min && key <= self.max
    }

    /// Whether this span overlaps with another.
    pub fn overlaps(&self, other: &KeySpan) -> bool {
        self.min <= other.max && other.min <= self.max
    }
}

/// A span of contiguous field indices.
///
/// Ported from Ghidra's `FieldSpan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldSpan {
    /// The column/field index.
    pub column: usize,
    /// Start row (inclusive).
    pub start_row: i64,
    /// End row (inclusive).
    pub end_row: i64,
}

impl FieldSpan {
    /// Create a new field span.
    pub fn new(column: usize, start_row: i64, end_row: i64) -> Self {
        Self {
            column,
            start_row,
            end_row,
        }
    }

    /// Number of rows.
    pub fn num_rows(&self) -> i64 {
        self.end_row - self.start_row + 1
    }
}

/// An annotated column definition for database objects.
///
/// Ported from Ghidra's `DBAnnotatedColumn`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotatedColumn {
    /// Column name.
    pub name: String,
    /// Column type name.
    pub type_name: String,
    /// Whether the column is a primary key.
    pub is_primary_key: bool,
    /// Whether the column is indexed.
    pub is_indexed: bool,
}

impl AnnotatedColumn {
    /// Create a new annotated column.
    pub fn new(name: impl Into<String>, type_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            type_name: type_name.into(),
            is_primary_key: false,
            is_indexed: false,
        }
    }

    /// Set as primary key.
    pub fn primary_key(mut self) -> Self {
        self.is_primary_key = true;
        self
    }

    /// Set as indexed.
    pub fn indexed(mut self) -> Self {
        self.is_indexed = true;
        self
    }
}

/// An annotated field definition for database objects.
///
/// Ported from Ghidra's `DBAnnotatedField`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotatedField {
    /// Field name.
    pub name: String,
    /// Column index.
    pub column_index: usize,
    /// Default value (JSON).
    pub default_value: Option<serde_json::Value>,
}

impl AnnotatedField {
    /// Create a new annotated field.
    pub fn new(name: impl Into<String>, column_index: usize) -> Self {
        Self {
            name: name.into(),
            column_index,
            default_value: None,
        }
    }

    /// Set the default value.
    pub fn with_default(mut self, value: serde_json::Value) -> Self {
        self.default_value = Some(value);
        self
    }
}

/// Object information for annotated database objects.
///
/// Ported from Ghidra's `DBAnnotatedObjectInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotatedObjectInfo {
    /// Table name.
    pub table_name: String,
    /// Columns.
    pub columns: Vec<AnnotatedColumn>,
    /// Fields.
    pub fields: Vec<AnnotatedField>,
}

impl AnnotatedObjectInfo {
    /// Create new object info.
    pub fn new(table_name: impl Into<String>) -> Self {
        Self {
            table_name: table_name.into(),
            columns: Vec::new(),
            fields: Vec::new(),
        }
    }

    /// Add a column.
    pub fn add_column(&mut self, column: AnnotatedColumn) {
        self.columns.push(column);
    }

    /// Add a field.
    pub fn add_field(&mut self, field: AnnotatedField) {
        self.fields.push(field);
    }
}

// ---------------------------------------------------------------------------
// Directed Record Iterator
// ---------------------------------------------------------------------------

/// A directed record iterator that traverses in a specified direction.
///
/// Ported from Ghidra's `DirectedRecordIterator`.
#[derive(Debug)]
pub struct DirectedRecordIterator<T: Clone> {
    records: Vec<T>,
    pos: usize,
    direction: IterDirection,
}

impl<T: Clone> DirectedRecordIterator<T> {
    /// Create a forward iterator over the given records.
    pub fn forward(records: Vec<T>) -> Self {
        Self {
            records,
            pos: 0,
            direction: IterDirection::Forward,
        }
    }

    /// Create a backward iterator over the given records.
    pub fn backward(records: Vec<T>) -> Self {
        let len = records.len();
        Self {
            records,
            pos: if len > 0 { len - 1 } else { 0 },
            direction: IterDirection::Backward,
        }
    }

    /// The direction of iteration.
    pub fn direction(&self) -> IterDirection {
        self.direction
    }

    /// Collect all remaining records.
    pub fn collect_remaining(&mut self) -> Vec<T> {
        let mut result = Vec::new();
        match self.direction {
            IterDirection::Forward => {
                while self.pos < self.records.len() {
                    result.push(self.records[self.pos].clone());
                    self.pos += 1;
                }
            }
            IterDirection::Backward => {
                loop {
                    result.push(self.records[self.pos].clone());
                    if self.pos == 0 {
                        break;
                    }
                    self.pos -= 1;
                }
            }
        }
        result
    }
}

/// A directed long-key iterator.
///
/// Ported from Ghidra's `DirectedLongKeyIterator`.
#[derive(Debug)]
pub struct DirectedLongKeyIterator {
    keys: Vec<i64>,
    pos: usize,
    direction: IterDirection,
}

impl DirectedLongKeyIterator {
    /// Create a forward key iterator.
    pub fn forward(keys: Vec<i64>) -> Self {
        Self {
            keys,
            pos: 0,
            direction: IterDirection::Forward,
        }
    }

    /// Create a backward key iterator.
    pub fn backward(keys: Vec<i64>) -> Self {
        let len = keys.len();
        Self {
            keys,
            pos: if len > 0 { len - 1 } else { 0 },
            direction: IterDirection::Backward,
        }
    }

    /// Collect all remaining keys.
    pub fn collect_remaining(&mut self) -> Vec<i64> {
        let mut result = Vec::new();
        match self.direction {
            IterDirection::Forward => {
                while self.pos < self.keys.len() {
                    result.push(self.keys[self.pos]);
                    self.pos += 1;
                }
            }
            IterDirection::Backward => {
                loop {
                    result.push(self.keys[self.pos]);
                    if self.pos == 0 {
                        break;
                    }
                    self.pos -= 1;
                }
            }
        }
        result
    }
}

/// A cached object store entry for the DB framework.
///
/// Ported from Ghidra's `DBCachedObjectStore` entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedObjectEntry<K: Clone, V: Clone> {
    /// The key.
    pub key: K,
    /// The value.
    pub value: V,
}

impl<K: Clone, V: Clone> CachedObjectEntry<K, V> {
    /// Create a new entry.
    pub fn new(key: K, value: V) -> Self {
        Self { key, value }
    }
}

/// A cached object store for the database framework.
///
/// Ported from Ghidra's `DBCachedObjectStore`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedObjectStore<K: Clone + Eq + std::hash::Hash, V: Clone> {
    entries: Vec<CachedObjectEntry<K, V>>,
    index: std::collections::HashMap<K, usize>,
}

impl<K: Clone + Eq + std::hash::Hash, V: Clone> CachedObjectStore<K, V> {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            index: std::collections::HashMap::new(),
        }
    }

    /// Insert a key-value pair.
    pub fn insert(&mut self, key: K, value: V) {
        let idx = self.entries.len();
        self.index.insert(key.clone(), idx);
        self.entries.push(CachedObjectEntry::new(key, value));
    }

    /// Get a value by key.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.index.get(key).map(|&idx| &self.entries[idx].value)
    }

    /// Remove a value by key.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        if let Some(idx) = self.index.remove(key) {
            Some(self.entries.remove(idx).value)
        } else {
            None
        }
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over entries.
    pub fn iter(&self) -> impl Iterator<Item = &CachedObjectEntry<K, V>> {
        self.entries.iter()
    }

    /// Get all keys.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.entries.iter().map(|e| &e.key)
    }

    /// Get all values.
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.iter().map(|e| &e.value)
    }

    /// Check if the store contains a key.
    pub fn contains_key(&self, key: &K) -> bool {
        self.index.contains_key(key)
    }
}

impl<K: Clone + Eq + std::hash::Hash, V: Clone> Default for CachedObjectStore<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

/// A database column definition.
///
/// Ported from Ghidra's `DBObjectColumn`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbObjectColumn {
    /// Column name.
    pub name: String,
    /// Column index.
    pub index: usize,
    /// Column type (as a string).
    pub column_type: String,
}

impl DbObjectColumn {
    /// Create a new column.
    pub fn new(name: impl Into<String>, index: usize, column_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            index,
            column_type: column_type.into(),
        }
    }
}

/// A cached object index for secondary lookups.
///
/// Ported from Ghidra's `DBCachedObjectIndex`.
#[derive(Debug, Clone)]
pub struct CachedObjectIndex<V: Clone> {
    index: std::collections::BTreeMap<String, Vec<V>>,
}

impl<V: Clone> Default for CachedObjectIndex<V> {
    fn default() -> Self {
        Self {
            index: std::collections::BTreeMap::new(),
        }
    }
}

impl<V: Clone> CachedObjectIndex<V> {
    /// Create a new empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry with the given key.
    pub fn insert(&mut self, key: impl Into<String>, value: V) {
        self.index.entry(key.into()).or_default().push(value);
    }

    /// Get all values for a given key.
    pub fn get(&self, key: &str) -> Option<&Vec<V>> {
        self.index.get(key)
    }

    /// Remove all entries for a key.
    pub fn remove(&mut self, key: &str) -> Option<Vec<V>> {
        self.index.remove(key)
    }

    /// The number of distinct keys.
    pub fn num_keys(&self) -> usize {
        self.index.len()
    }

    /// Iterate over all (key, values) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Vec<V>)> {
        self.index.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_span() {
        let span = KeySpan::new(0, 100);
        assert_eq!(span.len(), 101);
        assert!(span.contains(50));
        assert!(!span.contains(101));
    }

    #[test]
    fn test_key_span_overlaps() {
        let a = KeySpan::new(0, 50);
        let b = KeySpan::new(25, 75);
        let c = KeySpan::new(100, 200);

        assert!(a.overlaps(&b));
        assert!(b.overlaps(&a));
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn test_field_span() {
        let span = FieldSpan::new(0, 10, 20);
        assert_eq!(span.num_rows(), 11);
    }

    #[test]
    fn test_annotated_column() {
        let col = AnnotatedColumn::new("id", "long").primary_key().indexed();
        assert!(col.is_primary_key);
        assert!(col.is_indexed);
    }

    #[test]
    fn test_annotated_field() {
        let field = AnnotatedField::new("name", 1).with_default(serde_json::json!("unnamed"));
        assert_eq!(field.column_index, 1);
        assert!(field.default_value.is_some());
    }

    #[test]
    fn test_annotated_object_info() {
        let mut info = AnnotatedObjectInfo::new("threads");
        info.add_column(AnnotatedColumn::new("key", "long").primary_key());
        info.add_column(AnnotatedColumn::new("name", "string"));
        info.add_field(AnnotatedField::new("thread_name", 1));

        assert_eq!(info.columns.len(), 2);
        assert_eq!(info.fields.len(), 1);
    }

    #[test]
    fn test_directed_record_iterator_forward() {
        let mut iter = DirectedRecordIterator::forward(vec![10, 20, 30]);
        assert_eq!(iter.direction(), IterDirection::Forward);
        let result = iter.collect_remaining();
        assert_eq!(result, vec![10, 20, 30]);
    }

    #[test]
    fn test_directed_record_iterator_backward() {
        let mut iter = DirectedRecordIterator::backward(vec![10, 20, 30]);
        assert_eq!(iter.direction(), IterDirection::Backward);
        let result = iter.collect_remaining();
        assert_eq!(result, vec![30, 20, 10]);
    }

    #[test]
    fn test_directed_long_key_iterator_forward() {
        let mut iter = DirectedLongKeyIterator::forward(vec![1, 2, 3]);
        let result = iter.collect_remaining();
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn test_directed_long_key_iterator_backward() {
        let mut iter = DirectedLongKeyIterator::backward(vec![1, 2, 3]);
        let result = iter.collect_remaining();
        assert_eq!(result, vec![3, 2, 1]);
    }

    #[test]
    fn test_cached_object_store() {
        let mut store = CachedObjectStore::new();
        assert!(store.is_empty());

        store.insert("key1".to_string(), 100);
        store.insert("key2".to_string(), 200);
        assert_eq!(store.len(), 2);
        assert!(store.contains_key(&"key1".to_string()));
        assert_eq!(store.get(&"key1".to_string()), Some(&100));
        assert_eq!(store.get(&"key2".to_string()), Some(&200));
        assert_eq!(store.get(&"key3".to_string()), None);

        let removed = store.remove(&"key1".to_string());
        assert_eq!(removed, Some(100));
        assert_eq!(store.len(), 1);
        assert!(!store.contains_key(&"key1".to_string()));
    }

    #[test]
    fn test_cached_object_store_keys_values() {
        let mut store = CachedObjectStore::new();
        store.insert("a".to_string(), 1);
        store.insert("b".to_string(), 2);

        let keys: Vec<_> = store.keys().cloned().collect();
        assert!(keys.contains(&"a".to_string()));
        assert!(keys.contains(&"b".to_string()));

        let values: Vec<_> = store.values().cloned().collect();
        assert!(values.contains(&1));
        assert!(values.contains(&2));
    }

    #[test]
    fn test_db_object_column() {
        let col = DbObjectColumn::new("thread_id", 0, "long");
        assert_eq!(col.name, "thread_id");
        assert_eq!(col.index, 0);
        assert_eq!(col.column_type, "long");
    }

    #[test]
    fn test_cached_object_index() {
        let mut idx = CachedObjectIndex::new();
        idx.insert("thread", 1);
        idx.insert("thread", 2);
        idx.insert("process", 3);

        assert_eq!(idx.num_keys(), 2);
        assert_eq!(idx.get("thread"), Some(&vec![1, 2]));
        assert_eq!(idx.get("process"), Some(&vec![3]));
        assert_eq!(idx.get("missing"), None);

        let removed = idx.remove("thread");
        assert_eq!(removed, Some(vec![1, 2]));
        assert_eq!(idx.num_keys(), 1);
    }
}
