//! TraceObject - the focal point of the debug target model.
//!
//! A TraceObject supports querying for interfaces that define its behavior,
//! and may have children (attributes and elements). The debug model is a
//! directory-like tree rooted at a session object.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::key_path::KeyPath;
use crate::model::Lifespan;

/// A value that can be stored as an attribute or element of a TraceObject.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ObjectValue {
    /// A string value.
    String(String),
    /// A numeric value.
    Number(i64),
    /// A reference to another object by path.
    ObjectRef(KeyPath),
    /// A boolean.
    Bool(bool),
    /// Null/absent.
    Null,
}

/// An entry (attribute or element) of a TraceObject, including its temporal lifespan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectEntry {
    /// The value.
    pub value: ObjectValue,
    /// The lifespan during which this entry exists.
    pub lifespan: Lifespan,
}

/// A record of a target object in the debugger model.
///
/// Objects form a tree rooted at the session. Each object has attributes (named
/// children) and elements (indexed children). Objects may implement various
/// interfaces that define their behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceObject {
    /// The path from the root to this object.
    pub path: KeyPath,
    /// Named attributes, keyed by attribute name.
    pub attributes: IndexMap<String, Vec<ObjectEntry>>,
    /// Indexed elements, keyed by index string.
    pub elements: BTreeMap<String, Vec<ObjectEntry>>,
    /// The set of interface names this object implements.
    pub interfaces: Vec<String>,
    /// The schema name for this object.
    pub schema_name: String,
}

impl TraceObject {
    /// Create a new trace object at the given path.
    pub fn new(path: KeyPath, schema_name: impl Into<String>) -> Self {
        Self {
            path,
            attributes: IndexMap::new(),
            elements: BTreeMap::new(),
            interfaces: Vec::new(),
            schema_name: schema_name.into(),
        }
    }

    /// Add an interface to this object.
    pub fn add_interface(&mut self, iface: impl Into<String>) {
        let name = iface.into();
        if !self.interfaces.contains(&name) {
            self.interfaces.push(name);
        }
    }

    /// Whether this object implements a given interface.
    pub fn has_interface(&self, iface: &str) -> bool {
        self.interfaces.iter().any(|i| i == iface)
    }

    /// Set an attribute value for a given lifespan.
    pub fn set_attribute(
        &mut self,
        name: impl Into<String>,
        value: ObjectValue,
        lifespan: Lifespan,
    ) {
        let entry = ObjectEntry { value, lifespan };
        self.attributes
            .entry(name.into())
            .or_default()
            .push(entry);
    }

    /// Get the most recent attribute value at a given snap.
    pub fn get_attribute(&self, name: &str, snap: i64) -> Option<&ObjectValue> {
        self.attributes.get(name).and_then(|entries| {
            entries
                .iter()
                .filter(|e| e.lifespan.contains(snap))
                .max_by_key(|e| e.lifespan.lmin())
                .map(|e| &e.value)
        })
    }

    /// Set an element value for a given lifespan.
    pub fn set_element(
        &mut self,
        index: impl Into<String>,
        value: ObjectValue,
        lifespan: Lifespan,
    ) {
        let entry = ObjectEntry { value, lifespan };
        self.elements
            .entry(index.into())
            .or_default()
            .push(entry);
    }

    /// Get the most recent element value at a given snap.
    pub fn get_element(&self, index: &str, snap: i64) -> Option<&ObjectValue> {
        self.elements.get(index).and_then(|entries| {
            entries
                .iter()
                .filter(|e| e.lifespan.contains(snap))
                .max_by_key(|e| e.lifespan.lmin())
                .map(|e| &e.value)
        })
    }

    /// Get all attribute names active at the given snap.
    pub fn active_attribute_names(&self, snap: i64) -> Vec<&str> {
        self.attributes
            .iter()
            .filter(|(_, entries)| entries.iter().any(|e| e.lifespan.contains(snap)))
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Get all element indices active at the given snap.
    pub fn active_element_indices(&self, snap: i64) -> Vec<&str> {
        self.elements
            .iter()
            .filter(|(_, entries)| entries.iter().any(|e| e.lifespan.contains(snap)))
            .map(|(idx, _)| idx.as_str())
            .collect()
    }

    /// Remove an attribute.
    pub fn remove_attribute(&mut self, name: &str) -> bool {
        self.attributes.shift_remove(name).is_some()
    }

    /// Remove an element.
    pub fn remove_element(&mut self, index: &str) -> bool {
        self.elements.remove(index).is_some()
    }
}

/// Manager for all trace objects.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceObjectManager {
    objects: IndexMap<KeyPath, TraceObject>,
}

impl TraceObjectManager {
    /// Create a new object manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an object.
    pub fn add_object(&mut self, object: TraceObject) {
        self.objects.insert(object.path.clone(), object);
    }

    /// Get an object by path.
    pub fn get_object(&self, path: &KeyPath) -> Option<&TraceObject> {
        self.objects.get(path)
    }

    /// Get a mutable reference to an object by path.
    pub fn get_object_mut(&mut self, path: &KeyPath) -> Option<&mut TraceObject> {
        self.objects.get_mut(path)
    }

    /// Remove an object by path.
    pub fn remove_object(&mut self, path: &KeyPath) -> Option<TraceObject> {
        self.objects.shift_remove(path)
    }

    /// All objects.
    pub fn objects(&self) -> &IndexMap<KeyPath, TraceObject> {
        &self.objects
    }

    /// Number of objects.
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Whether there are no objects.
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// Get children of a given path (objects whose parent matches).
    pub fn children_of(&self, parent: &KeyPath) -> Vec<&TraceObject> {
        self.objects
            .values()
            .filter(|obj| obj.path.parent() == *parent)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_attributes() {
        let mut obj = TraceObject::new(KeyPath::parse("Session.Process"), "Process");
        obj.set_attribute(
            "pid",
            ObjectValue::Number(1234),
            Lifespan::now_on(0),
        );
        assert_eq!(
            obj.get_attribute("pid", 5),
            Some(&ObjectValue::Number(1234))
        );
        assert!(obj.get_attribute("missing", 5).is_none());
    }

    #[test]
    fn test_object_interfaces() {
        let mut obj = TraceObject::new(KeyPath::ROOT, "Session");
        obj.add_interface("TraceProcess");
        assert!(obj.has_interface("TraceProcess"));
        assert!(!obj.has_interface("TraceThread"));
    }

    #[test]
    fn test_object_elements() {
        let mut obj = TraceObject::new(KeyPath::parse("Threads"), "Threads");
        obj.set_element(
            "100",
            ObjectValue::ObjectRef(KeyPath::parse("Threads.100")),
            Lifespan::now_on(0),
        );
        assert!(obj.get_element("100", 5).is_some());
    }

    #[test]
    fn test_active_attributes() {
        let mut obj = TraceObject::new(KeyPath::ROOT, "Test");
        obj.set_attribute("name", ObjectValue::String("old".into()), Lifespan::span(0, 5));
        obj.set_attribute("name", ObjectValue::String("new".into()), Lifespan::now_on(6));

        let names = obj.active_attribute_names(3);
        assert!(names.contains(&"name"));
    }

    #[test]
    fn test_object_manager() {
        let mut mgr = TraceObjectManager::new();
        let obj = TraceObject::new(KeyPath::parse("Session"), "Session");
        mgr.add_object(obj);
        assert!(mgr.get_object(&KeyPath::parse("Session")).is_some());
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn test_children_of() {
        let mut mgr = TraceObjectManager::new();
        mgr.add_object(TraceObject::new(KeyPath::parse("a"), "A"));
        mgr.add_object(TraceObject::new(KeyPath::parse("a.b"), "B"));
        mgr.add_object(TraceObject::new(KeyPath::parse("a.c"), "C"));
        mgr.add_object(TraceObject::new(KeyPath::parse("a.b.d"), "D"));

        let children = mgr.children_of(&KeyPath::of(&["a"]));
        assert_eq!(children.len(), 2);
    }
}
