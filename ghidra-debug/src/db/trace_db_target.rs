//! Database-backed trace object (target) storage.
//!
//! Ported from Ghidra's `ghidra.trace.database.target` package in
//! Framework-TraceModeling. Provides SQLite-backed implementation of the
//! target object model.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::model::Lifespan;
use crate::target::{KeyPath, ObjectValue, TraceObject};

/// The interface name for an activatable object (e.g., process, thread).
pub const IFACE_ACTIVATABLE: &str = "Activatable";

/// The interface name for an aggregate object.
pub const IFACE_AGGREGATE: &str = "Aggregate";

/// The interface name for a container object.
pub const IFACE_CONTAINER: &str = "Container";

/// The interface name for a detachable object.
pub const IFACE_DETACHABLE: &str = "Detachable";

/// The interface name for a killable object.
pub const IFACE_KILLABLE: &str = "Killable";

/// The interface name for a launchable object.
pub const IFACE_LAUNCHABLE: &str = "Launchable";

/// The interface name for a connectable object.
pub const IFACE_CONNECTABLE: &str = "Connectable";

/// The interface name for a focusable object (thread selection).
pub const IFACE_FOCUSABLE: &str = "Focusable";

/// The interface name for a memory object.
pub const IFACE_MEMORY: &str = "Memory";

/// The interface name for a register bank.
pub const IFACE_REGISTER_BANK: &str = "RegisterBank";

/// The interface name for a stack frame.
pub const IFACE_STACK_FRAME: &str = "StackFrame";

/// The interface name for a module object.
pub const IFACE_MODULE: &str = "Module";

/// The interface name for a section object.
pub const IFACE_SECTION: &str = "Section";

/// The interface name for a breakpoint object.
pub const IFACE_BREAKPOINT: &str = "Breakpoint";

/// A database-backed trace object value.
///
/// Ported from Ghidra's `DBTraceObjectValue`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceObjectValue {
    /// The object path this value belongs to.
    pub object_path: KeyPath,
    /// The key (attribute name or element index).
    pub key: String,
    /// Whether this is an element (vs. attribute).
    pub is_element: bool,
    /// The stored value.
    pub value: ObjectValue,
    /// The lifespan of this value.
    pub lifespan: Lifespan,
    /// The database row ID.
    pub row_id: i64,
}

impl DBTraceObjectValue {
    /// Create a new value entry.
    pub fn new(
        object_path: KeyPath,
        key: impl Into<String>,
        is_element: bool,
        value: ObjectValue,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            object_path,
            key: key.into(),
            is_element,
            value,
            lifespan,
            row_id: 0,
        }
    }

    /// Set the database row ID.
    pub fn with_row_id(mut self, id: i64) -> Self {
        self.row_id = id;
        self
    }
}

/// A database-backed trace object value path.
///
/// Ported from Ghidra's `DBTraceObjectValPath`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceObjectValPath {
    /// The object path.
    pub object_path: KeyPath,
    /// The value key.
    pub key: String,
}

impl DBTraceObjectValPath {
    /// Create a new value path.
    pub fn new(object_path: KeyPath, key: impl Into<String>) -> Self {
        Self {
            object_path,
            key: key.into(),
        }
    }
}

/// A database-backed trace object value node for spatial indexing.
///
/// Ported from Ghidra's `DBTraceObjectValueNode`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceObjectValueNode {
    /// The value path.
    pub value_path: DBTraceObjectValPath,
    /// Minimum address in the R-tree entry.
    pub min_addr: u64,
    /// Maximum address in the R-tree entry.
    pub max_addr: u64,
    /// The snap range.
    pub lifespan: Lifespan,
}

impl DBTraceObjectValueNode {
    /// Create a new value node.
    pub fn new(
        value_path: DBTraceObjectValPath,
        min_addr: u64,
        max_addr: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            value_path,
            min_addr,
            max_addr,
            lifespan,
        }
    }

    /// Whether this node overlaps a given address at a given snap.
    pub fn overlaps(&self, addr: u64, snap: i64) -> bool {
        addr >= self.min_addr && addr <= self.max_addr && self.lifespan.contains(snap)
    }
}

/// A cache entry for a database-backed trace object.
///
/// Ported from Ghidra's `CachePerDBTraceObject`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DBTraceObjectCache {
    /// Cached objects by path.
    pub objects: IndexMap<KeyPath, TraceObject>,
    /// Dirty flag per object.
    pub dirty: IndexMap<KeyPath, bool>,
}

impl DBTraceObjectCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update a cached object.
    pub fn insert(&mut self, obj: TraceObject) {
        let path = obj.path.clone();
        self.objects.insert(path.clone(), obj);
        self.dirty.insert(path, false);
    }

    /// Get a cached object.
    pub fn get(&self, path: &KeyPath) -> Option<&TraceObject> {
        self.objects.get(path)
    }

    /// Mark an object as dirty.
    pub fn mark_dirty(&mut self, path: &KeyPath) {
        if let Some(d) = self.dirty.get_mut(path) {
            *d = true;
        }
    }

    /// Get all dirty paths.
    pub fn dirty_paths(&self) -> Vec<&KeyPath> {
        self.dirty
            .iter()
            .filter(|(_, &dirty)| dirty)
            .map(|(path, _)| path)
            .collect()
    }

    /// Clear dirty flags.
    pub fn clear_dirty(&mut self) {
        for d in self.dirty.values_mut() {
            *d = false;
        }
    }

    /// Remove an object from the cache.
    pub fn remove(&mut self, path: &KeyPath) -> Option<TraceObject> {
        self.dirty.shift_remove(path);
        self.objects.shift_remove(path)
    }

    /// The number of cached objects.
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}

/// Codec for serializing/deserializing DBTraceObjectValue to/from database fields.
///
/// Ported from Ghidra's `DBTraceObjectDBFieldCodec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceObjectFieldCodec {
    /// The schema name for the object type.
    pub schema_name: String,
}

impl DBTraceObjectFieldCodec {
    /// Create a new field codec.
    pub fn new(schema_name: impl Into<String>) -> Self {
        Self {
            schema_name: schema_name.into(),
        }
    }

    /// Encode a value to bytes for storage.
    pub fn encode(&self, value: &DBTraceObjectValue) -> Vec<u8> {
        // Simple JSON encoding for now
        serde_json::to_vec(value).unwrap_or_default()
    }

    /// Decode a value from stored bytes.
    pub fn decode(&self, data: &[u8]) -> Option<DBTraceObjectValue> {
        serde_json::from_slice(data).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_object(path: &str) -> TraceObject {
        TraceObject::new(KeyPath::parse(path), "TestType")
    }

    #[test]
    fn test_db_trace_object_value() {
        let val = DBTraceObjectValue::new(
            KeyPath::parse("Session.Process"),
            "pid",
            false,
            ObjectValue::Number(1234),
            Lifespan::now_on(0),
        )
        .with_row_id(42);
        assert_eq!(val.row_id, 42);
        assert_eq!(val.key, "pid");
        assert!(!val.is_element);
    }

    #[test]
    fn test_db_trace_object_val_path() {
        let path = DBTraceObjectValPath::new(KeyPath::parse("a.b"), "attr");
        assert_eq!(path.object_path, KeyPath::parse("a.b"));
        assert_eq!(path.key, "attr");
    }

    #[test]
    fn test_db_trace_object_value_node() {
        let node = DBTraceObjectValueNode::new(
            DBTraceObjectValPath::new(KeyPath::parse("a.b"), "range"),
            0x1000,
            0x2000,
            Lifespan::span(0, 5),
        );
        assert!(node.overlaps(0x1500, 5));
        assert!(!node.overlaps(0x3000, 5));
        assert!(!node.overlaps(0x1500, 10)); // beyond lifespan
    }

    #[test]
    fn test_db_trace_object_cache() {
        let mut cache = DBTraceObjectCache::new();
        assert!(cache.is_empty());

        cache.insert(sample_object("Session"));
        cache.insert(sample_object("Session.Process"));
        assert_eq!(cache.len(), 2);

        cache.mark_dirty(&KeyPath::parse("Session"));
        let dirty = cache.dirty_paths();
        assert_eq!(dirty.len(), 1);

        cache.clear_dirty();
        assert!(cache.dirty_paths().is_empty());

        let removed = cache.remove(&KeyPath::parse("Session"));
        assert!(removed.is_some());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_db_trace_object_field_codec() {
        let codec = DBTraceObjectFieldCodec::new("TestType");
        let val = DBTraceObjectValue::new(
            KeyPath::parse("a"),
            "x",
            false,
            ObjectValue::Number(42),
            Lifespan::now_on(0),
        );

        let encoded = codec.encode(&val);
        let decoded = codec.decode(&encoded).unwrap();
        assert_eq!(decoded.key, "x");
        assert_eq!(decoded.row_id, 0);
    }

    #[test]
    fn test_iface_constants() {
        assert_eq!(IFACE_ACTIVATABLE, "Activatable");
        assert_eq!(IFACE_CONTAINER, "Container");
        assert_eq!(IFACE_MEMORY, "Memory");
        assert_eq!(IFACE_BREAKPOINT, "Breakpoint");
    }

    #[test]
    fn test_db_value_serde() {
        let val = DBTraceObjectValue::new(
            KeyPath::parse("a.b"),
            "key",
            true,
            ObjectValue::String("hello".into()),
            Lifespan::span(0, 10),
        );
        let json = serde_json::to_string(&val).unwrap();
        let back: DBTraceObjectValue = serde_json::from_str(&json).unwrap();
        assert_eq!(back.key, "key");
        assert!(back.is_element);
    }
}
