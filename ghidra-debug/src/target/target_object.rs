//! TargetObject -- enhanced target-tree object with interface discovery.
//!
//! Ported from Ghidra's `Debugger/target/object/TargetObject.java`.
//!
//! A `TargetObject` is a node in the debug target tree that supports
//! interface-based behavior queries, parent/child navigation, and
//! method invocation. This is the *target-side* counterpart to the
//! model-level `TraceObject` (in `model::target_object`).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::key_path::KeyPath;
use crate::model::Lifespan;

// ---------------------------------------------------------------------------
// TargetObject value / entry
// ---------------------------------------------------------------------------

/// A value attached to a `TargetObject` child slot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TargetValue {
    /// A primitive string.
    String(String),
    /// A numeric value.
    Number(i64),
    /// A floating-point value.
    Float(f64),
    /// A reference to another `TargetObject` by path.
    ObjectRef(KeyPath),
    /// A boolean flag.
    Bool(bool),
    /// Byte buffer.
    Bytes(Vec<u8>),
    /// Null / absent.
    Null,
}

/// A child entry of a `TargetObject`, including its temporal lifespan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetEntry {
    /// The entry key (attribute name or element index).
    pub key: String,
    /// The value stored in this entry.
    pub value: TargetValue,
    /// The lifespan during which this entry is alive.
    pub lifespan: Lifespan,
}

impl TargetEntry {
    /// Create a new entry.
    pub fn new(key: impl Into<String>, value: TargetValue, lifespan: Lifespan) -> Self {
        Self {
            key: key.into(),
            value,
            lifespan,
        }
    }

    /// Whether this entry is valid at the given snap.
    pub fn is_valid(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }
}

// ---------------------------------------------------------------------------
// InterfaceSet
// ---------------------------------------------------------------------------

/// A set of interface names that a `TargetObject` implements.
///
/// Interfaces are plain strings (e.g. `"TargetProcess"`, `"TargetThread"`,
/// `"TargetExecutionStateful"`). An object may implement many interfaces
/// simultaneously.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceSet {
    names: Vec<String>,
}

impl InterfaceSet {
    /// Create an empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an interface.
    pub fn insert(&mut self, name: impl Into<String>) {
        let n = name.into();
        if !self.names.contains(&n) {
            self.names.push(n);
        }
    }

    /// Remove an interface.
    pub fn remove(&mut self, name: &str) -> bool {
        let len_before = self.names.len();
        self.names.retain(|n| n != name);
        self.names.len() < len_before
    }

    /// Whether the set contains the given interface.
    pub fn contains(&self, name: &str) -> bool {
        self.names.iter().any(|n| n == name)
    }

    /// Iterate over interface names.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.names.iter().map(|s| s.as_str())
    }

    /// Number of interfaces.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

impl fmt::Display for InterfaceSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.names.join(", "))
    }
}

// ---------------------------------------------------------------------------
// TargetObject
// ---------------------------------------------------------------------------

/// A node in the debug target tree.
///
/// Each object carries a canonical path, a set of interfaces it implements,
/// and a collection of child entries (attributes and indexed elements).
///
/// This is the target-tree API companion to `model::target_object::TraceObject`.
/// Use `TargetObject` when reasoning about the live debugger model;
/// use `model::target_object::TraceObject` when reasoning about the persisted
/// trace database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetObject {
    /// Unique key identifying this object.
    pub key: i64,
    /// The canonical path from root to this object.
    pub path: KeyPath,
    /// The schema name governing this object's structure.
    pub schema_name: String,
    /// Interfaces this object implements.
    pub interfaces: InterfaceSet,
    /// Named attribute entries.
    pub attributes: BTreeMap<String, Vec<TargetEntry>>,
    /// Indexed element entries.
    pub elements: BTreeMap<String, Vec<TargetEntry>>,
    /// The key of the parent object, if any.
    pub parent_key: Option<i64>,
    /// The snap at which this object was created.
    pub creation_snap: i64,
    /// Whether this object has been deleted.
    pub deleted: bool,
}

impl TargetObject {
    /// Create a new target object.
    pub fn new(
        key: i64,
        path: KeyPath,
        schema_name: impl Into<String>,
        creation_snap: i64,
    ) -> Self {
        Self {
            key,
            path,
            schema_name: schema_name.into(),
            interfaces: InterfaceSet::new(),
            attributes: BTreeMap::new(),
            elements: BTreeMap::new(),
            parent_key: None,
            creation_snap,
            deleted: false,
        }
    }

    /// Set the parent key.
    pub fn with_parent(mut self, parent_key: i64) -> Self {
        self.parent_key = Some(parent_key);
        self
    }

    /// Add an interface to this object.
    pub fn add_interface(&mut self, name: impl Into<String>) {
        self.interfaces.insert(name);
    }

    /// Remove an interface from this object.
    pub fn remove_interface(&mut self, name: &str) -> bool {
        self.interfaces.remove(name)
    }

    /// Whether this object implements the given interface.
    pub fn has_interface(&self, name: &str) -> bool {
        self.interfaces.contains(name)
    }

    /// Set an attribute entry for a given lifespan.
    pub fn set_attribute(
        &mut self,
        name: impl Into<String>,
        value: TargetValue,
        lifespan: Lifespan,
    ) {
        let name = name.into();
        self.attributes
            .entry(name.clone())
            .or_default()
            .push(TargetEntry::new(name, value, lifespan));
    }

    /// Get the most recent attribute value active at `snap`.
    pub fn get_attribute(&self, name: &str, snap: i64) -> Option<&TargetValue> {
        self.attributes.get(name).and_then(|entries| {
            entries
                .iter()
                .filter(|e| e.is_valid(snap))
                .max_by_key(|e| e.lifespan.lmin())
                .map(|e| &e.value)
        })
    }

    /// Remove all entries for an attribute.
    pub fn remove_attribute(&mut self, name: &str) -> bool {
        self.attributes.remove(name).is_some()
    }

    /// Get all attribute names active at `snap`.
    pub fn active_attribute_names(&self, snap: i64) -> Vec<&str> {
        self.attributes
            .iter()
            .filter(|(_, entries)| entries.iter().any(|e| e.is_valid(snap)))
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Set an element entry for a given lifespan.
    pub fn set_element(
        &mut self,
        index: impl Into<String>,
        value: TargetValue,
        lifespan: Lifespan,
    ) {
        let index = index.into();
        self.elements
            .entry(index.clone())
            .or_default()
            .push(TargetEntry::new(index, value, lifespan));
    }

    /// Get the most recent element value active at `snap`.
    pub fn get_element(&self, index: &str, snap: i64) -> Option<&TargetValue> {
        self.elements.get(index).and_then(|entries| {
            entries
                .iter()
                .filter(|e| e.is_valid(snap))
                .max_by_key(|e| e.lifespan.lmin())
                .map(|e| &e.value)
        })
    }

    /// Remove all entries for an element.
    pub fn remove_element(&mut self, index: &str) -> bool {
        self.elements.remove(index).is_some()
    }

    /// Get all element indices active at `snap`.
    pub fn active_element_indices(&self, snap: i64) -> Vec<&str> {
        self.elements
            .iter()
            .filter(|(_, entries)| entries.iter().any(|e| e.is_valid(snap)))
            .map(|(idx, _)| idx.as_str())
            .collect()
    }

    /// Mark this object as deleted.
    pub fn mark_deleted(&mut self) {
        self.deleted = true;
    }

    /// Whether this object is alive (not deleted and valid at `snap`).
    pub fn is_alive(&self, snap: i64) -> bool {
        !self.deleted && snap >= self.creation_snap
    }

    /// Collect all object-reference values from attributes and elements at `snap`.
    pub fn child_references(&self, snap: i64) -> Vec<&KeyPath> {
        let mut refs = Vec::new();
        for entries in self.attributes.values() {
            for e in entries.iter().filter(|e| e.is_valid(snap)) {
                if let TargetValue::ObjectRef(path) = &e.value {
                    refs.push(path);
                }
            }
        }
        for entries in self.elements.values() {
            for e in entries.iter().filter(|e| e.is_valid(snap)) {
                if let TargetValue::ObjectRef(path) = &e.value {
                    refs.push(path);
                }
            }
        }
        refs
    }
}

// ---------------------------------------------------------------------------
// TargetObjectManager
// ---------------------------------------------------------------------------

/// Manager for all `TargetObject` instances in a debug session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetObjectManager {
    objects: BTreeMap<i64, TargetObject>,
    path_index: BTreeMap<KeyPath, i64>,
}

impl TargetObjectManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an object to the manager.
    pub fn add_object(&mut self, object: TargetObject) {
        let key = object.key;
        let path = object.path.clone();
        self.path_index.insert(path, key);
        self.objects.insert(key, object);
    }

    /// Get an object by key.
    pub fn get_by_key(&self, key: i64) -> Option<&TargetObject> {
        self.objects.get(&key)
    }

    /// Get a mutable reference to an object by key.
    pub fn get_by_key_mut(&mut self, key: i64) -> Option<&mut TargetObject> {
        self.objects.get_mut(&key)
    }

    /// Get an object by path.
    pub fn get_by_path(&self, path: &KeyPath) -> Option<&TargetObject> {
        self.path_index.get(path).and_then(|k| self.objects.get(k))
    }

    /// Remove an object by key.
    pub fn remove_by_key(&mut self, key: i64) -> Option<TargetObject> {
        if let Some(obj) = self.objects.remove(&key) {
            self.path_index.remove(&obj.path);
            Some(obj)
        } else {
            None
        }
    }

    /// Mark an object as deleted (soft delete).
    pub fn soft_delete(&mut self, key: i64) -> bool {
        if let Some(obj) = self.objects.get_mut(&key) {
            obj.mark_deleted();
            true
        } else {
            false
        }
    }

    /// All objects that are alive at `snap`.
    pub fn alive_at(&self, snap: i64) -> Vec<&TargetObject> {
        self.objects.values().filter(|o| o.is_alive(snap)).collect()
    }

    /// Children of a parent key at `snap`.
    pub fn children_of(&self, parent_key: i64, snap: i64) -> Vec<&TargetObject> {
        self.objects
            .values()
            .filter(|o| o.parent_key == Some(parent_key) && o.is_alive(snap))
            .collect()
    }

    /// Find objects implementing a given interface at `snap`.
    pub fn objects_with_interface(&self, iface: &str, snap: i64) -> Vec<&TargetObject> {
        self.objects
            .values()
            .filter(|o| o.is_alive(snap) && o.has_interface(iface))
            .collect()
    }

    /// Number of managed objects (including deleted).
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Whether the manager is empty.
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// Iterate over all objects.
    pub fn iter(&self) -> impl Iterator<Item = &TargetObject> {
        self.objects.values()
    }
}

// ---------------------------------------------------------------------------
// Well-known interface names
// ---------------------------------------------------------------------------

/// Well-known target interface names used by the Ghidra debug framework.
pub mod interface_names {
    /// A process in the target.
    pub const TARGET_PROCESS: &str = "TargetProcess";
    /// A thread in the target.
    pub const TARGET_THREAD: &str = "TargetThread";
    /// An object with execution state (running/stopped/etc.).
    pub const TARGET_EXECUTION_STATEFUL: &str = "TargetExecutionStateful";
    /// An object that can be activated (focused).
    pub const TARGET_ACTIVATABLE: &str = "TargetActivatable";
    /// An object that can be toggled (breakpoints, etc.).
    pub const TARGET_TOGGLABLE: &str = "TargetTogglable";
    /// A focus scope.
    pub const TARGET_FOCUS_SCOPE: &str = "TargetFocusScope";
    /// A memory region.
    pub const TARGET_MEMORY_REGION: &str = "TargetMemoryRegion";
    /// A register container.
    pub const TARGET_REGISTER_CONTAINER: &str = "TargetRegisterContainer";
    /// A call stack.
    pub const TARGET_STACK: &str = "TargetStack";
    /// A stack frame.
    pub const TARGET_STACK_FRAME: &str = "TargetStackFrame";
    /// A method that can be invoked.
    pub const TARGET_METHOD: &str = "TargetMethod";
    /// A section within a module.
    pub const TARGET_SECTION: &str = "TargetSection";
    /// A loaded module.
    pub const TARGET_MODULE: &str = "TargetModule";
    /// A breakpoint.
    pub const TARGET_BREAKPOINT: &str = "TargetBreakpoint";
    /// An event in the target.
    pub const TARGET_EVENT: &str = "TargetEvent";
    /// An environment descriptor.
    pub const TARGET_ENVIRONMENT: &str = "TargetEnvironment";
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_object_creation() {
        let obj = TargetObject::new(
            1,
            KeyPath::parse("Session.Processes[0]"),
            "Process",
            0,
        );
        assert_eq!(obj.key, 1);
        assert_eq!(obj.schema_name, "Process");
        assert!(!obj.deleted);
        assert!(obj.is_alive(0));
        assert!(obj.is_alive(100));
    }

    #[test]
    fn test_target_object_with_parent() {
        let obj = TargetObject::new(
            5,
            KeyPath::parse("Session.Processes[0].Threads[1]"),
            "Thread",
            0,
        )
        .with_parent(1);
        assert_eq!(obj.parent_key, Some(1));
    }

    #[test]
    fn test_interface_set() {
        let mut obj = TargetObject::new(1, KeyPath::ROOT, "Session", 0);
        obj.add_interface("TargetProcess");
        obj.add_interface("TargetExecutionStateful");
        assert!(obj.has_interface("TargetProcess"));
        assert!(obj.has_interface("TargetExecutionStateful"));
        assert!(!obj.has_interface("TargetThread"));

        obj.remove_interface("TargetProcess");
        assert!(!obj.has_interface("TargetProcess"));
    }

    #[test]
    fn test_interface_set_display() {
        let mut iset = InterfaceSet::new();
        iset.insert("A");
        iset.insert("B");
        let s = format!("{iset}");
        assert!(s.contains("A"));
        assert!(s.contains("B"));
    }

    #[test]
    fn test_attributes() {
        let mut obj = TargetObject::new(1, KeyPath::parse("P"), "Test", 0);
        obj.set_attribute("name", TargetValue::String("main".into()), Lifespan::now_on(0));
        obj.set_attribute("pid", TargetValue::Number(1234), Lifespan::now_on(0));

        assert_eq!(
            obj.get_attribute("name", 5),
            Some(&TargetValue::String("main".into()))
        );
        assert_eq!(
            obj.get_attribute("pid", 5),
            Some(&TargetValue::Number(1234))
        );
        assert!(obj.get_attribute("missing", 5).is_none());

        let names = obj.active_attribute_names(5);
        assert!(names.contains(&"name"));
        assert!(names.contains(&"pid"));
    }

    #[test]
    fn test_elements() {
        let mut obj = TargetObject::new(1, KeyPath::parse("Threads"), "ThreadContainer", 0);
        obj.set_element(
            "0",
            TargetValue::ObjectRef(KeyPath::parse("Threads.0")),
            Lifespan::now_on(0),
        );
        assert!(obj.get_element("0", 5).is_some());
        assert!(obj.get_element("1", 5).is_none());
    }

    #[test]
    fn test_object_lifecycle() {
        let mut obj = TargetObject::new(1, KeyPath::parse("P"), "T", 10);
        assert!(!obj.is_alive(9));
        assert!(obj.is_alive(10));
        assert!(obj.is_alive(1000));

        obj.mark_deleted();
        assert!(!obj.is_alive(10));
    }

    #[test]
    fn test_child_references() {
        let mut obj = TargetObject::new(1, KeyPath::parse("P"), "T", 0);
        obj.set_attribute(
            "child",
            TargetValue::ObjectRef(KeyPath::parse("P.child")),
            Lifespan::now_on(0),
        );
        obj.set_element(
            "0",
            TargetValue::ObjectRef(KeyPath::parse("P.0")),
            Lifespan::now_on(0),
        );
        obj.set_attribute(
            "name",
            TargetValue::String("test".into()),
            Lifespan::now_on(0),
        );

        let refs = obj.child_references(5);
        assert_eq!(refs.len(), 2);
    }

    #[test]
    fn test_target_object_manager() {
        let mut mgr = TargetObjectManager::new();
        let obj = TargetObject::new(1, KeyPath::parse("Session"), "Session", 0);
        mgr.add_object(obj);
        let obj2 = TargetObject::new(
            2,
            KeyPath::parse("Session.Processes[0]"),
            "Process",
            0,
        )
        .with_parent(1);
        mgr.add_object(obj2);

        assert_eq!(mgr.len(), 2);
        assert!(mgr.get_by_key(1).is_some());
        assert!(mgr.get_by_path(&KeyPath::parse("Session.Processes[0]")).is_some());
    }

    #[test]
    fn test_manager_children_of() {
        let mut mgr = TargetObjectManager::new();
        mgr.add_object(TargetObject::new(1, KeyPath::parse("P"), "P", 0));
        mgr.add_object(
            TargetObject::new(2, KeyPath::parse("P.A"), "A", 0).with_parent(1),
        );
        mgr.add_object(
            TargetObject::new(3, KeyPath::parse("P.B"), "B", 0).with_parent(1),
        );
        mgr.add_object(
            TargetObject::new(4, KeyPath::parse("P.A.C"), "C", 0).with_parent(2),
        );

        let children = mgr.children_of(1, 0);
        assert_eq!(children.len(), 2);
    }

    #[test]
    fn test_manager_objects_with_interface() {
        let mut mgr = TargetObjectManager::new();
        let mut obj = TargetObject::new(1, KeyPath::parse("T0"), "Thread", 0);
        obj.add_interface("TargetThread");
        mgr.add_object(obj);

        let mut obj2 = TargetObject::new(2, KeyPath::parse("T1"), "Thread", 0);
        obj2.add_interface("TargetProcess");
        mgr.add_object(obj2);

        let threads = mgr.objects_with_interface("TargetThread", 0);
        assert_eq!(threads.len(), 1);
    }

    #[test]
    fn test_manager_soft_delete() {
        let mut mgr = TargetObjectManager::new();
        mgr.add_object(TargetObject::new(1, KeyPath::parse("P"), "P", 0));
        assert_eq!(mgr.alive_at(0).len(), 1);

        mgr.soft_delete(1);
        assert_eq!(mgr.alive_at(0).len(), 0);
        assert!(mgr.get_by_key(1).is_some()); // still in the map
    }

    #[test]
    fn test_manager_remove_by_key() {
        let mut mgr = TargetObjectManager::new();
        mgr.add_object(TargetObject::new(1, KeyPath::parse("P"), "P", 0));
        assert_eq!(mgr.len(), 1);

        let removed = mgr.remove_by_key(1);
        assert!(removed.is_some());
        assert_eq!(mgr.len(), 0);
        assert!(mgr.get_by_path(&KeyPath::parse("P")).is_none());
    }

    #[test]
    fn test_well_known_interfaces() {
        assert_eq!(interface_names::TARGET_PROCESS, "TargetProcess");
        assert_eq!(interface_names::TARGET_THREAD, "TargetThread");
        assert_eq!(
            interface_names::TARGET_EXECUTION_STATEFUL,
            "TargetExecutionStateful"
        );
    }

    #[test]
    fn test_target_entry_validity() {
        let entry = TargetEntry::new("x", TargetValue::Number(42), Lifespan::span(5, 10));
        assert!(!entry.is_valid(4));
        assert!(entry.is_valid(5));
        assert!(entry.is_valid(10));
        assert!(!entry.is_valid(11));
    }

    #[test]
    fn test_target_object_serde() {
        let obj = TargetObject::new(1, KeyPath::parse("S"), "Session", 0);
        let json = serde_json::to_string(&obj).unwrap();
        let back: TargetObject = serde_json::from_str(&json).unwrap();
        assert_eq!(back.key, 1);
        assert_eq!(back.schema_name, "Session");
    }

    #[test]
    fn test_target_value_equality() {
        assert_eq!(TargetValue::Number(1), TargetValue::Number(1));
        assert_ne!(TargetValue::Number(1), TargetValue::Number(2));
        assert_ne!(TargetValue::Bool(true), TargetValue::Null);
    }

    #[test]
    fn test_interface_set_contains_after_remove() {
        let mut iset = InterfaceSet::new();
        iset.insert("A");
        iset.insert("B");
        iset.insert("C");
        assert!(iset.contains("B"));
        iset.remove("B");
        assert!(!iset.contains("B"));
        assert_eq!(iset.len(), 2);
    }
}
