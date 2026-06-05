//! Additional target object database types.
//!
//! Ported from Ghidra's `ghidra.trace.database.target` package.
//! Provides concrete implementations for:
//! - `DBTraceObject`: The trace object entity.
//! - `DBTraceObjectManager`: Manager for trace objects.
//! - `DBTraceObjectDBFieldCodec`: Field codec for database storage.
//! - `DBTraceObjectValueMapAddressSetView`: Address set view for values.
//! - `DBTraceObjectValueRStarTree`: R*-tree spatial index for values.
//! - `DBTraceObjectValueWriteBehindCache`: Write-behind cache for values.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::model::Lifespan;

/// A trace object in the database.
///
/// Ported from `DBTraceObject`. Represents a single entity in the target
/// object model, with attributes, lifespans, and a path in the object tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceObject {
    /// Unique object ID.
    pub id: i64,
    /// The canonical path (key path segments).
    pub path: Vec<String>,
    /// The schema name for this object.
    pub schema_name: String,
    /// The lifespan of this object.
    pub lifespan: Lifespan,
    /// Attributes (key-value pairs).
    pub attributes: HashMap<String, ObjectValue>,
    /// Whether this object has been inserted into the tree.
    pub inserted: bool,
    /// The parent object ID, if any.
    pub parent_id: Option<i64>,
}

/// A value stored in a trace object attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObjectValue {
    /// A string value.
    String(String),
    /// A boolean value.
    Bool(bool),
    /// An integer value.
    Int(i64),
    /// A long integer value.
    Long(i64),
    /// A float value.
    Float(f64),
    /// A reference to another object by ID.
    ObjectRef(i64),
    /// A byte array value.
    Bytes(Vec<u8>),
    /// A null value.
    Null,
}

impl ObjectValue {
    /// Get the value as a string, if possible.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get the value as a boolean, if possible.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Get the value as an integer, if possible.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            Self::Long(l) => Some(*l),
            _ => None,
        }
    }

    /// Whether this is a null value.
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

impl DBTraceObject {
    /// Create a new trace object.
    pub fn new(id: i64, path: Vec<String>, schema_name: impl Into<String>) -> Self {
        Self {
            id,
            path,
            schema_name: schema_name.into(),
            lifespan: Lifespan::ALL,
            attributes: HashMap::new(),
            inserted: false,
            parent_id: None,
        }
    }

    /// Set an attribute.
    pub fn set_attribute(&mut self, key: impl Into<String>, value: ObjectValue) {
        self.attributes.insert(key.into(), value);
    }

    /// Get an attribute.
    pub fn get_attribute(&self, key: &str) -> Option<&ObjectValue> {
        self.attributes.get(key)
    }

    /// Remove an attribute.
    pub fn remove_attribute(&mut self, key: &str) -> Option<ObjectValue> {
        self.attributes.remove(key)
    }

    /// Get all attribute keys.
    pub fn attribute_keys(&self) -> Vec<&str> {
        self.attributes.keys().map(|s| s.as_str()).collect()
    }

    /// Get the number of attributes.
    pub fn attribute_count(&self) -> usize {
        self.attributes.len()
    }

    /// Get the canonical path as a string.
    pub fn canonical_path(&self) -> String {
        self.path.join(".")
    }

    /// Whether this object exists at the given snap.
    pub fn exists_at(&self, snap: i64) -> bool {
        self.inserted && self.lifespan.contains(snap)
    }
}

/// Manager for trace objects in the database.
///
/// Ported from `DBTraceObjectManager`.
#[derive(Debug)]
pub struct DBTraceObjectManager {
    objects: HashMap<i64, DBTraceObject>,
    path_index: BTreeMap<Vec<String>, i64>,
    next_id: i64,
}

impl Default for DBTraceObjectManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DBTraceObjectManager {
    /// Create a new object manager.
    pub fn new() -> Self {
        Self {
            objects: HashMap::new(),
            path_index: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Create a new object.
    pub fn create_object(
        &mut self,
        path: Vec<String>,
        schema_name: impl Into<String>,
    ) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        let obj = DBTraceObject::new(id, path.clone(), schema_name);
        self.objects.insert(id, obj);
        self.path_index.insert(path, id);
        id
    }

    /// Get an object by ID.
    pub fn get_object(&self, id: i64) -> Option<&DBTraceObject> {
        self.objects.get(&id)
    }

    /// Get a mutable reference to an object by ID.
    pub fn get_object_mut(&mut self, id: i64) -> Option<&mut DBTraceObject> {
        self.objects.get_mut(&id)
    }

    /// Get an object by path.
    pub fn get_object_by_path(&self, path: &[String]) -> Option<&DBTraceObject> {
        let id = self.path_index.get(path)?;
        self.objects.get(id)
    }

    /// Delete an object by ID.
    pub fn delete_object(&mut self, id: i64) -> Option<DBTraceObject> {
        let obj = self.objects.remove(&id)?;
        self.path_index.remove(&obj.path);
        Some(obj)
    }

    /// Get the total number of objects.
    pub fn count(&self) -> usize {
        self.objects.len()
    }

    /// Get all object IDs.
    pub fn all_ids(&self) -> Vec<i64> {
        self.objects.keys().copied().collect()
    }

    /// Insert an object (mark it as inserted).
    pub fn insert_object(&mut self, id: i64) -> bool {
        if let Some(obj) = self.objects.get_mut(&id) {
            obj.inserted = true;
            true
        } else {
            false
        }
    }

    /// Get children of an object (objects whose parent_id matches).
    pub fn get_children(&self, parent_id: i64) -> Vec<&DBTraceObject> {
        self.objects
            .values()
            .filter(|obj| obj.parent_id == Some(parent_id))
            .collect()
    }
}

/// Field codec for encoding/decoding trace object values in the database.
///
/// Ported from `DBTraceObjectDBFieldCodec`.
#[derive(Debug, Clone)]
pub struct DBTraceObjectFieldCodec {
    /// The field name.
    pub field_name: String,
    /// The value type.
    pub value_type: ObjectValueType,
    /// Whether this field is fixed (always present in schema).
    pub fixed: bool,
}

/// Value types for object fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectValueType {
    /// String type.
    String,
    /// Boolean type.
    Bool,
    /// Integer type.
    Int,
    /// Long integer type.
    Long,
    /// Float type.
    Float,
    /// Object reference type.
    ObjectRef,
    /// Byte array type.
    Bytes,
}

impl DBTraceObjectFieldCodec {
    /// Create a new field codec.
    pub fn new(
        field_name: impl Into<String>,
        value_type: ObjectValueType,
        fixed: bool,
    ) -> Self {
        Self {
            field_name: field_name.into(),
            value_type,
            fixed,
        }
    }

    /// Encode a value to bytes.
    pub fn encode(&self, value: &ObjectValue) -> Vec<u8> {
        match value {
            ObjectValue::String(s) => s.as_bytes().to_vec(),
            ObjectValue::Bool(b) => vec![if *b { 1 } else { 0 }],
            ObjectValue::Int(i) => i.to_le_bytes().to_vec(),
            ObjectValue::Long(l) => l.to_le_bytes().to_vec(),
            ObjectValue::Float(f) => f.to_le_bytes().to_vec(),
            ObjectValue::ObjectRef(id) => id.to_le_bytes().to_vec(),
            ObjectValue::Bytes(b) => b.clone(),
            ObjectValue::Null => Vec::new(),
        }
    }

    /// Decode a value from bytes.
    pub fn decode(&self, bytes: &[u8]) -> ObjectValue {
        match self.value_type {
            ObjectValueType::String => {
                ObjectValue::String(String::from_utf8_lossy(bytes).into_owned())
            }
            ObjectValueType::Bool => ObjectValue::Bool(bytes.first().map_or(false, |&b| b != 0)),
            ObjectValueType::Int => {
                let arr: [u8; 8] = bytes
                    .try_into()
                    .unwrap_or([0u8; 8]);
                ObjectValue::Int(i64::from_le_bytes(arr))
            }
            ObjectValueType::Long => {
                let arr: [u8; 8] = bytes
                    .try_into()
                    .unwrap_or([0u8; 8]);
                ObjectValue::Long(i64::from_le_bytes(arr))
            }
            ObjectValueType::Float => {
                let arr: [u8; 8] = bytes
                    .try_into()
                    .unwrap_or([0u8; 8]);
                ObjectValue::Float(f64::from_le_bytes(arr))
            }
            ObjectValueType::ObjectRef => {
                let arr: [u8; 8] = bytes
                    .try_into()
                    .unwrap_or([0u8; 8]);
                ObjectValue::ObjectRef(i64::from_le_bytes(arr))
            }
            ObjectValueType::Bytes => ObjectValue::Bytes(bytes.to_vec()),
        }
    }
}

/// A write-behind cache for trace object values.
///
/// Ported from `DBTraceObjectValueWriteBehindCache`. Caches recently
/// written values to reduce database writes.
#[derive(Debug)]
pub struct DBTraceObjectValueWriteBehindCache {
    /// Pending writes (key -> value).
    pending: HashMap<CacheKey, ObjectValue>,
    /// Dirty entries that need flushing.
    dirty: BTreeSet<CacheKey>,
    /// Maximum cache entries.
    max_entries: usize,
}

/// A cache key for object values.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CacheKey {
    /// The object ID.
    pub object_id: i64,
    /// The attribute name.
    pub attribute: String,
    /// The snap.
    pub snap: i64,
}

impl DBTraceObjectValueWriteBehindCache {
    /// Create a new write-behind cache.
    pub fn new(max_entries: usize) -> Self {
        Self {
            pending: HashMap::new(),
            dirty: BTreeSet::new(),
            max_entries,
        }
    }

    /// Put a value in the cache.
    pub fn put(&mut self, key: CacheKey, value: ObjectValue) {
        self.dirty.insert(key.clone());
        self.pending.insert(key, value);
        self.evict_if_needed();
    }

    /// Get a value from the cache.
    pub fn get(&self, key: &CacheKey) -> Option<&ObjectValue> {
        self.pending.get(key)
    }

    /// Get all dirty entries (entries that need flushing).
    pub fn dirty_entries(&self) -> Vec<(&CacheKey, &ObjectValue)> {
        self.dirty
            .iter()
            .filter_map(|k| self.pending.get_key_value(k).map(|(k, v)| (k, v)))
            .collect()
    }

    /// Flush all dirty entries (mark as clean).
    pub fn flush(&mut self) -> Vec<(CacheKey, ObjectValue)> {
        let result: Vec<_> = self
            .dirty
            .iter()
            .filter_map(|k| {
                self.pending
                    .get(k)
                    .map(|v| (k.clone(), v.clone()))
            })
            .collect();
        self.dirty.clear();
        result
    }

    /// Clear the cache entirely.
    pub fn clear(&mut self) {
        self.pending.clear();
        self.dirty.clear();
    }

    /// Number of entries in the cache.
    pub fn size(&self) -> usize {
        self.pending.len()
    }

    /// Number of dirty entries.
    pub fn dirty_count(&self) -> usize {
        self.dirty.len()
    }

    fn evict_if_needed(&mut self) {
        if self.pending.len() > self.max_entries {
            // Evict non-dirty entries first
            let keys_to_evict: Vec<_> = self
                .pending
                .keys()
                .filter(|k| !self.dirty.contains(k))
                .take(self.pending.len() - self.max_entries)
                .cloned()
                .collect();
            for key in keys_to_evict {
                self.pending.remove(&key);
            }
        }
    }
}

/// An address set view for object values.
///
/// Ported from `DBTraceObjectValueMapAddressSetView`. Provides a view of
/// addresses covered by object values.
#[derive(Debug, Default)]
pub struct DBTraceObjectValueAddressSetView {
    /// Ranges indexed by address space name.
    ranges: BTreeMap<String, Vec<(u64, u64)>>,
}

impl DBTraceObjectValueAddressSetView {
    /// Create a new address set view.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a range.
    pub fn add_range(&mut self, space: impl Into<String>, min: u64, max: u64) {
        self.ranges.entry(space.into()).or_default().push((min, max));
    }

    /// Check if an address is in the set.
    pub fn contains(&self, space: &str, address: u64) -> bool {
        self.ranges
            .get(space)
            .map_or(false, |ranges| {
                ranges.iter().any(|&(min, max)| address >= min && address <= max)
            })
    }

    /// Get all space names.
    pub fn spaces(&self) -> Vec<&str> {
        self.ranges.keys().map(|s| s.as_str()).collect()
    }

    /// Get ranges for a specific space.
    pub fn ranges_in(&self, space: &str) -> &[(u64, u64)] {
        self.ranges
            .get(space)
            .map_or(&[], |r| r.as_slice())
    }

    /// Get the total number of ranges.
    pub fn range_count(&self) -> usize {
        self.ranges.values().map(|r| r.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_value_types() {
        assert_eq!(ObjectValue::String("test".into()).as_str(), Some("test"));
        assert_eq!(ObjectValue::Bool(true).as_bool(), Some(true));
        assert_eq!(ObjectValue::Int(42).as_i64(), Some(42));
        assert!(ObjectValue::Null.is_null());
        assert_eq!(ObjectValue::Float(3.14).as_i64(), None);
    }

    #[test]
    fn test_db_trace_object() {
        let mut obj = DBTraceObject::new(1, vec!["Processes".into(), "1".into()], "Process");
        assert_eq!(obj.id, 1);
        assert_eq!(obj.canonical_path(), "Processes.1");
        assert!(!obj.exists_at(0)); // not inserted yet

        obj.inserted = true;
        assert!(obj.exists_at(0));

        obj.set_attribute("name", ObjectValue::String("test.exe".into()));
        assert_eq!(obj.attribute_count(), 1);
        assert_eq!(
            obj.get_attribute("name").unwrap().as_str(),
            Some("test.exe")
        );

        obj.remove_attribute("name");
        assert_eq!(obj.attribute_count(), 0);
    }

    #[test]
    fn test_db_trace_object_manager() {
        let mut mgr = DBTraceObjectManager::new();
        assert_eq!(mgr.count(), 0);

        let id = mgr.create_object(
            vec!["Processes".into(), "1".into()],
            "Process",
        );
        assert_eq!(mgr.count(), 1);

        let obj = mgr.get_object(id).unwrap();
        assert_eq!(obj.schema_name, "Process");

        let obj_by_path = mgr.get_object_by_path(&["Processes".into(), "1".into()]);
        assert!(obj_by_path.is_some());

        mgr.insert_object(id);
        assert!(mgr.get_object(id).unwrap().inserted);

        let deleted = mgr.delete_object(id);
        assert!(deleted.is_some());
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_field_codec() {
        let codec = DBTraceObjectFieldCodec::new("name", ObjectValueType::String, false);

        let encoded = codec.encode(&ObjectValue::String("hello".into()));
        let decoded = codec.decode(&encoded);
        assert_eq!(decoded.as_str(), Some("hello"));

        let codec = DBTraceObjectFieldCodec::new("count", ObjectValueType::Int, true);
        let encoded = codec.encode(&ObjectValue::Int(42));
        let decoded = codec.decode(&encoded);
        assert_eq!(decoded.as_i64(), Some(42));

        let codec = DBTraceObjectFieldCodec::new("flag", ObjectValueType::Bool, false);
        let encoded = codec.encode(&ObjectValue::Bool(true));
        let decoded = codec.decode(&encoded);
        assert_eq!(decoded.as_bool(), Some(true));
    }

    #[test]
    fn test_write_behind_cache() {
        let mut cache = DBTraceObjectValueWriteBehindCache::new(100);
        assert_eq!(cache.size(), 0);

        let key = CacheKey {
            object_id: 1,
            attribute: "name".into(),
            snap: 0,
        };

        cache.put(key.clone(), ObjectValue::String("test".into()));
        assert_eq!(cache.size(), 1);
        assert_eq!(cache.dirty_count(), 1);

        let val = cache.get(&key).unwrap();
        assert_eq!(val.as_str(), Some("test"));

        let dirty = cache.flush();
        assert_eq!(dirty.len(), 1);
        assert_eq!(cache.dirty_count(), 0);

        cache.clear();
        assert_eq!(cache.size(), 0);
    }

    #[test]
    fn test_address_set_view() {
        let mut view = DBTraceObjectValueAddressSetView::new();
        view.add_range("ram", 0x400000, 0x500000);
        view.add_range("ram", 0x600000, 0x700000);

        assert!(view.contains("ram", 0x450000));
        assert!(!view.contains("ram", 0x550000));
        assert!(!view.contains("other", 0x450000));
        assert_eq!(view.spaces(), vec!["ram"]);
        assert_eq!(view.range_count(), 2);
    }
}
