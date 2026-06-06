//! Database-level trace object internals.
//!
//! Ported from Ghidra's `ghidra.trace.database.target` package.
//! Provides the internal data structures for storing trace object values
//! in the database, including value boxes, shapes, and space indexing.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;
use crate::target::ObjectValue;

/// A box holding a single value for a trace object entry.
///
/// Ported from Ghidra's `ValueBox`. Represents a stored value
/// that can be primitive, a reference to another object, or null.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueBox {
    /// The stored value.
    pub value: Option<ObjectValue>,
    /// The database row ID for this entry.
    pub row_id: i64,
}

impl ValueBox {
    /// Create a new value box.
    pub fn new(value: Option<ObjectValue>, row_id: i64) -> Self {
        Self { value, row_id }
    }

    /// Whether this box holds a null value.
    pub fn is_null(&self) -> bool {
        self.value.is_none()
    }

    /// Whether this box holds a reference to another object.
    pub fn is_object_ref(&self) -> bool {
        matches!(&self.value, Some(ObjectValue::ObjectRef(_)))
    }

    /// Whether this box holds a primitive value.
    pub fn is_primitive(&self) -> bool {
        matches!(
            &self.value,
            Some(ObjectValue::String(_) | ObjectValue::Number(_) | ObjectValue::Bool(_))
        )
    }
}

/// The shape (lifespan) of a value entry.
///
/// Ported from Ghidra's `ValueShape`. Represents the temporal extent
/// of a value in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueShape {
    /// The lifespan of this value.
    pub lifespan: Lifespan,
    /// The database row ID.
    pub row_id: i64,
}

impl ValueShape {
    /// Create a new value shape.
    pub fn new(lifespan: Lifespan, row_id: i64) -> Self {
        Self { lifespan, row_id }
    }

    /// Whether the lifespan contains the given snap.
    pub fn contains_snap(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }
}

/// A triple of (key, lifespan, value) for a trace object entry.
///
/// Ported from Ghidra's `ValueTriple`. Represents the complete
/// information about a single value assignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueTriple {
    /// The key (attribute name or element index).
    pub key: String,
    /// Whether this is an element.
    pub is_element: bool,
    /// The lifespan of this value.
    pub lifespan: Lifespan,
    /// The stored value.
    pub value: Option<ObjectValue>,
    /// The database row ID.
    pub row_id: i64,
}

impl ValueTriple {
    /// Create a new value triple.
    pub fn new(
        key: impl Into<String>,
        is_element: bool,
        lifespan: Lifespan,
        value: Option<ObjectValue>,
        row_id: i64,
    ) -> Self {
        Self {
            key: key.into(),
            is_element,
            lifespan,
            value,
            row_id,
        }
    }
}

/// An immutable value box that doesn't support mutation.
///
/// Ported from Ghidra's `ImmutableValueBox`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImmutableValueBox {
    inner: ValueBox,
}

impl ImmutableValueBox {
    /// Create a new immutable value box.
    pub fn new(value: Option<ObjectValue>, row_id: i64) -> Self {
        Self {
            inner: ValueBox::new(value, row_id),
        }
    }

    /// Get a reference to the inner value box.
    pub fn inner(&self) -> &ValueBox {
        &self.inner
    }
}

/// An immutable value shape that doesn't support mutation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImmutableValueShape {
    inner: ValueShape,
}

impl ImmutableValueShape {
    /// Create a new immutable value shape.
    pub fn new(lifespan: Lifespan, row_id: i64) -> Self {
        Self {
            inner: ValueShape::new(lifespan, row_id),
        }
    }

    /// Get a reference to the inner value shape.
    pub fn inner(&self) -> &ValueShape {
        &self.inner
    }
}

/// A dimension for snap-based indexing of object values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SnapDimension {
    /// The snap value.
    pub snap: i64,
}

impl SnapDimension {
    /// Create a new snap dimension.
    pub fn new(snap: i64) -> Self {
        Self { snap }
    }
}

/// A dimension for entry-key-based indexing of object values.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EntryKeyDimension {
    /// The key name.
    pub key: String,
    /// Whether this is an element.
    pub is_element: bool,
}

impl EntryKeyDimension {
    /// Create a new entry key dimension.
    pub fn new(key: impl Into<String>, is_element: bool) -> Self {
        Self {
            key: key.into(),
            is_element,
        }
    }
}

/// A cache entry for a single trace object.
///
/// Ported from Ghidra's `CachePerDBTraceObject`. Provides quick access
/// to an object's values without repeated database queries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CachePerDBObject {
    /// Cached values indexed by (key, is_element) -> list of (lifespan, value).
    values: BTreeMap<(String, bool), Vec<(Lifespan, Option<ObjectValue>)>>,
    /// Cached lifespan of the object itself.
    cached_life: Option<Lifespan>,
    /// Whether the cache is valid.
    dirty: bool,
}

impl CachePerDBObject {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the cache needs refreshing.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark the cache as dirty.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
        self.values.clear();
        self.cached_life = None;
    }

    /// Invalidate the cached lifespan.
    pub fn invalidate_life(&mut self) {
        self.cached_life = None;
    }

    /// Set the cached lifespan.
    pub fn set_cached_life(&mut self, life: Lifespan) {
        self.cached_life = Some(life);
    }

    /// Get the cached lifespan.
    pub fn cached_life(&self) -> Option<Lifespan> {
        self.cached_life
    }

    /// Get cached values for a given key.
    pub fn get_values(&self, key: &str, is_element: bool) -> Option<&[(Lifespan, Option<ObjectValue>)]> {
        self.values.get(&(key.to_string(), is_element)).map(|v| v.as_slice())
    }

    /// Set cached values for a given key.
    pub fn set_values(
        &mut self,
        key: impl Into<String>,
        is_element: bool,
        values: Vec<(Lifespan, Option<ObjectValue>)>,
    ) {
        self.values.insert((key.into(), is_element), values);
        self.dirty = false;
    }

    /// Clear all cached values.
    pub fn clear(&mut self) {
        self.values.clear();
        self.cached_life = None;
        self.dirty = false;
    }
}

/// The interface of a database-backed trace object.
///
/// Ported from Ghidra's `DBTraceObjectInterface`. Marker trait
/// for object interfaces that can be stored in the database.
pub trait DBTraceObjectInterface: std::fmt::Debug {
    /// The name of this interface.
    fn interface_name(&self) -> &str;

    /// The schema name associated with this interface.
    fn schema_name(&self) -> &str;

    /// The attributes expected by this interface.
    fn attributes(&self) -> &[&str];

    /// The fixed keys whose values don't change over the object's lifespan.
    fn fixed_keys(&self) -> &[&str];
}

/// Interface for togglable objects (e.g., enable/disable breakpoints).
#[derive(Debug)]
pub struct TogglableInterface;

impl DBTraceObjectInterface for TogglableInterface {
    fn interface_name(&self) -> &str {
        "Togglable"
    }

    fn schema_name(&self) -> &str {
        "trace.Togglable"
    }

    fn attributes(&self) -> &[&str] {
        &["enabled"]
    }

    fn fixed_keys(&self) -> &[&str] {
        &[]
    }
}

/// Interface for activatable objects (processes, threads).
#[derive(Debug)]
pub struct ActivatableInterface;

impl DBTraceObjectInterface for ActivatableInterface {
    fn interface_name(&self) -> &str {
        "Activatable"
    }

    fn schema_name(&self) -> &str {
        "trace.Activatable"
    }

    fn attributes(&self) -> &[&str] {
        &["active"]
    }

    fn fixed_keys(&self) -> &[&str] {
        &[]
    }
}

/// Interface for event scope objects (containers of events).
#[derive(Debug)]
pub struct EventScopeInterface;

impl DBTraceObjectInterface for EventScopeInterface {
    fn interface_name(&self) -> &str {
        "EventScope"
    }

    fn schema_name(&self) -> &str {
        "trace.EventScope"
    }

    fn attributes(&self) -> &[&str] {
        &["events"]
    }

    fn fixed_keys(&self) -> &[&str] {
        &[]
    }
}

/// Interface for execution stateful objects.
#[derive(Debug)]
pub struct ExecutionStatefulInterface;

impl DBTraceObjectInterface for ExecutionStatefulInterface {
    fn interface_name(&self) -> &str {
        "ExecutionStateful"
    }

    fn schema_name(&self) -> &str {
        "trace.ExecutionStateful"
    }

    fn attributes(&self) -> &[&str] {
        &["state"]
    }

    fn fixed_keys(&self) -> &[&str] {
        &[]
    }
}

/// Interface for focus scope objects (thread selection, etc.).
#[derive(Debug)]
pub struct FocusScopeInterface;

impl DBTraceObjectInterface for FocusScopeInterface {
    fn interface_name(&self) -> &str {
        "FocusScope"
    }

    fn schema_name(&self) -> &str {
        "trace.FocusScope"
    }

    fn attributes(&self) -> &[&str] {
        &["focus"]
    }

    fn fixed_keys(&self) -> &[&str] {
        &[]
    }
}

/// Interface for method objects (function entries, etc.).
#[derive(Debug)]
pub struct MethodInterface;

impl DBTraceObjectInterface for MethodInterface {
    fn interface_name(&self) -> &str {
        "Method"
    }

    fn schema_name(&self) -> &str {
        "trace.Method"
    }

    fn attributes(&self) -> &[&str] {
        &["name", "entry", "return_type"]
    }

    fn fixed_keys(&self) -> &[&str] {
        &["entry"]
    }
}

/// Interface for aggregate objects (collections of values).
#[derive(Debug)]
pub struct AggregateInterface;

impl DBTraceObjectInterface for AggregateInterface {
    fn interface_name(&self) -> &str {
        "Aggregate"
    }

    fn schema_name(&self) -> &str {
        "trace.Aggregate"
    }

    fn attributes(&self) -> &[&str] {
        &["components"]
    }

    fn fixed_keys(&self) -> &[&str] {
        &[]
    }
}

/// Interface for environment objects (process environment info).
#[derive(Debug)]
pub struct EnvironmentInterface;

impl DBTraceObjectInterface for EnvironmentInterface {
    fn interface_name(&self) -> &str {
        "Environment"
    }

    fn schema_name(&self) -> &str {
        "trace.Environment"
    }

    fn attributes(&self) -> &[&str] {
        &["pid", "command", "arguments"]
    }

    fn fixed_keys(&self) -> &[&str] {
        &["pid"]
    }
}

/// Get all built-in interface implementations.
pub fn builtin_interfaces() -> Vec<Box<dyn DBTraceObjectInterface>> {
    vec![
        Box::new(TogglableInterface),
        Box::new(ActivatableInterface),
        Box::new(EventScopeInterface),
        Box::new(ExecutionStatefulInterface),
        Box::new(FocusScopeInterface),
        Box::new(MethodInterface),
        Box::new(AggregateInterface),
        Box::new(EnvironmentInterface),
    ]
}

/// Get the interface with the given name.
pub fn interface_by_name(name: &str) -> Option<Box<dyn DBTraceObjectInterface>> {
    builtin_interfaces()
        .into_iter()
        .find(|i| i.interface_name() == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_box() {
        let box_null = ValueBox::new(None, 1);
        assert!(box_null.is_null());
        assert!(!box_null.is_object_ref());

        let box_ref = ValueBox::new(Some(ObjectValue::ObjectRef(crate::target::KeyPath::of(&["test"]))), 2);
        assert!(!box_ref.is_null());
        assert!(box_ref.is_object_ref());

        let box_prim = ValueBox::new(Some(ObjectValue::String("hello".into())), 3);
        assert!(!box_prim.is_null());
        assert!(box_prim.is_primitive());
    }

    #[test]
    fn test_value_shape() {
        let shape = ValueShape::new(Lifespan::span(0, 10), 1);
        assert!(shape.contains_snap(5));
        assert!(!shape.contains_snap(15));
    }

    #[test]
    fn test_value_triple() {
        let triple = ValueTriple::new("name", false, Lifespan::span(0, 10), Some(ObjectValue::String("test".into())), 1);
        assert_eq!(triple.key, "name");
        assert!(!triple.is_element);
    }

    #[test]
    fn test_cache_per_db_object() {
        let mut cache = CachePerDBObject::new();
        assert!(!cache.is_dirty());
        assert!(cache.cached_life().is_none());

        cache.set_cached_life(Lifespan::span(0, 100));
        assert_eq!(cache.cached_life(), Some(Lifespan::span(0, 100)));

        cache.mark_dirty();
        assert!(cache.is_dirty());
        assert!(cache.cached_life().is_none());
    }

    #[test]
    fn test_cache_per_db_object_values() {
        let mut cache = CachePerDBObject::new();
        cache.set_values("name", false, vec![
            (Lifespan::span(0, 10), Some(ObjectValue::String("foo".into()))),
        ]);
        let values = cache.get_values("name", false).unwrap();
        assert_eq!(values.len(), 1);
    }

    #[test]
    fn test_snap_dimension() {
        let dim = SnapDimension::new(42);
        assert_eq!(dim.snap, 42);
    }

    #[test]
    fn test_entry_key_dimension() {
        let dim = EntryKeyDimension::new("name", false);
        assert_eq!(dim.key, "name");
        assert!(!dim.is_element);
    }

    #[test]
    fn test_immutable_value_box() {
        let ibox = ImmutableValueBox::new(Some(ObjectValue::Number(42)), 1);
        assert!(!ibox.inner().is_null());
    }

    #[test]
    fn test_immutable_value_shape() {
        let ishape = ImmutableValueShape::new(Lifespan::span(0, 10), 1);
        assert!(ishape.inner().contains_snap(5));
    }

    #[test]
    fn test_builtin_interfaces() {
        let ifaces = builtin_interfaces();
        assert_eq!(ifaces.len(), 8);
        assert_eq!(ifaces[0].interface_name(), "Togglable");
    }

    #[test]
    fn test_interface_by_name() {
        let iface = interface_by_name("Activatable").unwrap();
        assert_eq!(iface.interface_name(), "Activatable");
        assert_eq!(iface.schema_name(), "trace.Activatable");
        assert!(interface_by_name("NonExistent").is_none());
    }

    #[test]
    fn test_interface_attributes() {
        let iface = interface_by_name("Method").unwrap();
        assert_eq!(iface.attributes().len(), 3);
        assert_eq!(iface.fixed_keys(), &["entry"]);
    }

    #[test]
    fn test_value_box_serde() {
        let v = ValueBox::new(Some(ObjectValue::Number(42)), 1);
        let json = serde_json::to_string(&v).unwrap();
        let back: ValueBox = serde_json::from_str(&json).unwrap();
        assert_eq!(back.row_id, 1);
    }
}
