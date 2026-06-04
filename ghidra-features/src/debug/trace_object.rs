//! Target object model for the Debug framework.
//!
//! Ported from `ghidra.trace.model.target` — includes [`TraceObject`],
//! [`TraceObjectValue`], [`KeyPath`], [`TraceObjectSchema`],
//! [`SchemaContext`], and related types.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use super::core_types::Lifespan;

// ---------------------------------------------------------------------------
// KeyPath
// ---------------------------------------------------------------------------

/// A path of keys (indices and names) to an object in the target model.
///
/// Ported from `ghidra.trace.model.target.path.KeyPath`. A path is a sequence
/// of keys, each being either an index (numeric string in brackets) or a name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyPath {
    keys: Vec<String>,
}

/// Wildcard index that matches any index.
pub const WILDCARD_INDEX: &str = "[]";

impl KeyPath {
    /// The root (empty) path.
    pub const ROOT: KeyPath = KeyPath { keys: Vec::new() };

    /// Create a path from a vector of key strings.
    pub fn new(keys: Vec<String>) -> Self {
        Self { keys }
    }

    /// Create a root path.
    pub fn root() -> Self {
        Self { keys: Vec::new() }
    }

    /// Create a path with a single key.
    pub fn of(key: impl Into<String>) -> Self {
        Self {
            keys: vec![key.into()],
        }
    }

    /// Returns the number of keys in this path.
    pub fn size(&self) -> usize {
        self.keys.len()
    }

    /// Returns `true` if this is the root path.
    pub fn is_root(&self) -> bool {
        self.keys.is_empty()
    }

    /// Get the key at the given index.
    pub fn key_at(&self, index: usize) -> Option<&str> {
        self.keys.get(index).map(|s| s.as_str())
    }

    /// Get the last key in this path.
    pub fn key(&self) -> Option<&str> {
        self.keys.last().map(|s| s.as_str())
    }

    /// Returns the parent path (all keys except the last).
    pub fn parent(&self) -> Option<KeyPath> {
        if self.keys.is_empty() {
            return None;
        }
        Some(KeyPath {
            keys: self.keys[..self.keys.len() - 1].to_vec(),
        })
    }

    /// Extend this path with a key.
    pub fn key_extend(&self, key: impl Into<String>) -> KeyPath {
        let mut new_keys = self.keys.clone();
        new_keys.push(key.into());
        KeyPath { keys: new_keys }
    }

    /// Extend this path with an index.
    pub fn index_extend(&self, index: impl Into<String>) -> KeyPath {
        let idx = index.into();
        let key = format!("[{idx}]");
        self.key_extend(key)
    }

    /// Check if a string is an index (starts with `[` and ends with `]`).
    pub fn is_index(key: &str) -> bool {
        key.starts_with('[') && key.ends_with(']')
    }

    /// Parse the index from an index key (strip brackets).
    pub fn parse_index(key: &str) -> &str {
        if Self::is_index(key) {
            &key[1..key.len() - 1]
        } else {
            key
        }
    }

    /// Returns `true` if this path is an ancestor of (or equal to) the other.
    pub fn is_ancestor(&self, other: &KeyPath) -> bool {
        if self.keys.len() > other.keys.len() {
            return false;
        }
        self.keys.iter().zip(other.keys.iter()).all(|(a, b)| a == b)
    }

    /// Iterate over the keys.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.keys.iter().map(|s| s.as_str())
    }
}

impl fmt::Display for KeyPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.keys.is_empty() {
            return write!(f, "(root)");
        }
        write!(f, "{}", self.keys.join("."))
    }
}

// ---------------------------------------------------------------------------
// TraceObjectValue
// ---------------------------------------------------------------------------

/// A value stored in a trace object.
///
/// Ported from `ghidra.trace.model.target.TraceObjectValue`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceObjectValue {
    /// A primitive string value.
    String(String),
    /// A primitive integer value.
    Integer(i64),
    /// A primitive boolean value.
    Boolean(bool),
    /// A reference to another object by path.
    ObjectRef(KeyPath),
    /// An empty/null value.
    Null,
}

impl fmt::Display for TraceObjectValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraceObjectValue::String(s) => write!(f, "\"{s}\""),
            TraceObjectValue::Integer(i) => write!(f, "{i}"),
            TraceObjectValue::Boolean(b) => write!(f, "{b}"),
            TraceObjectValue::ObjectRef(path) => write!(f, "@{path}"),
            TraceObjectValue::Null => write!(f, "null"),
        }
    }
}

// ---------------------------------------------------------------------------
// TraceObject
// ---------------------------------------------------------------------------

/// An object in the trace target model.
///
/// Ported from `ghidra.trace.model.target.TraceObject`. Objects are organized
/// in a tree structure, each having a schema, attributes, and elements
/// (children).
#[derive(Debug, Clone)]
pub struct TraceObject {
    /// The path to this object.
    pub path: KeyPath,
    /// The schema name for this object.
    pub schema_name: String,
    /// Named attributes (key -> value).
    attributes: BTreeMap<String, TraceObjectValue>,
    /// Indexed elements (index -> object path reference).
    elements: BTreeMap<String, KeyPath>,
    /// The lifespan of this object.
    pub lifespan: Lifespan,
    /// Whether deleted.
    deleted: bool,
}

impl TraceObject {
    /// Create a new trace object.
    pub fn new(path: KeyPath, schema_name: impl Into<String>, lifespan: Lifespan) -> Self {
        Self {
            path,
            schema_name: schema_name.into(),
            attributes: BTreeMap::new(),
            elements: BTreeMap::new(),
            lifespan,
            deleted: false,
        }
    }

    /// Set an attribute.
    pub fn set_attribute(&mut self, key: impl Into<String>, value: TraceObjectValue) {
        self.attributes.insert(key.into(), value);
    }

    /// Get an attribute.
    pub fn get_attribute(&self, key: &str) -> Option<&TraceObjectValue> {
        self.attributes.get(key)
    }

    /// Get all attributes.
    pub fn attributes(&self) -> &BTreeMap<String, TraceObjectValue> {
        &self.attributes
    }

    /// Add an element (child reference by index).
    pub fn set_element(&mut self, index: impl Into<String>, child_path: KeyPath) {
        self.elements.insert(index.into(), child_path);
    }

    /// Get an element path by index.
    pub fn get_element(&self, index: &str) -> Option<&KeyPath> {
        self.elements.get(index)
    }

    /// Get all elements.
    pub fn elements(&self) -> &BTreeMap<String, KeyPath> {
        &self.elements
    }

    /// Delete this object.
    pub fn delete(&mut self) {
        self.deleted = true;
    }

    /// Check if valid at the given snapshot.
    pub fn is_valid(&self, snap: i64) -> bool {
        !self.deleted && self.lifespan.contains(snap)
    }
}

impl fmt::Display for TraceObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Object({}, {})", self.path, self.schema_name)
    }
}

// ---------------------------------------------------------------------------
// TraceObjectSchema
// ---------------------------------------------------------------------------

/// Schema descriptor for trace objects.
///
/// Ported from `ghidra.trace.model.target.schema.TraceObjectSchema`.
#[derive(Debug, Clone)]
pub struct TraceObjectSchema {
    /// The schema name.
    name: String,
    /// The required interfaces (names).
    interfaces: Vec<String>,
    /// Whether this schema is a canonical container.
    canonical_container: bool,
    /// Element schema mapping (index -> schema name).
    element_schemas: HashMap<String, String>,
    /// Default element schema name.
    default_element_schema: String,
    /// Attribute schema mapping (name -> attribute descriptor).
    attribute_schemas: HashMap<String, AttributeSchemaDesc>,
    /// Default attribute schema.
    default_attribute_schema: AttributeSchemaDesc,
}

/// Descriptor for an attribute schema.
#[derive(Debug, Clone)]
pub struct AttributeSchemaDesc {
    /// The attribute name.
    pub name: String,
    /// The schema name for this attribute's value.
    pub schema_name: String,
    /// Whether this attribute is required.
    pub required: bool,
    /// Whether this attribute is fixed (immutable).
    pub fixed: bool,
    /// Whether hidden by default.
    pub hidden: bool,
}

impl TraceObjectSchema {
    /// Create a new object schema.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            interfaces: Vec::new(),
            canonical_container: false,
            element_schemas: HashMap::new(),
            default_element_schema: "Object".to_string(),
            attribute_schemas: HashMap::new(),
            default_attribute_schema: AttributeSchemaDesc {
                name: String::new(),
                schema_name: "Any".to_string(),
                required: false,
                fixed: false,
                hidden: false,
            },
        }
    }

    /// Returns the schema name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Add a required interface.
    pub fn with_interface(mut self, iface: impl Into<String>) -> Self {
        self.interfaces.push(iface.into());
        self
    }

    /// Set whether this is a canonical container.
    pub fn with_canonical_container(mut self, canonical: bool) -> Self {
        self.canonical_container = canonical;
        self
    }

    /// Set the default element schema.
    pub fn with_default_element_schema(mut self, schema: impl Into<String>) -> Self {
        self.default_element_schema = schema.into();
        self
    }

    /// Add an attribute schema.
    pub fn with_attribute(
        mut self,
        name: impl Into<String>,
        schema_name: impl Into<String>,
        required: bool,
        fixed: bool,
    ) -> Self {
        let n = name.into();
        self.attribute_schemas.insert(
            n.clone(),
            AttributeSchemaDesc {
                name: n,
                schema_name: schema_name.into(),
                required,
                fixed,
                hidden: false,
            },
        );
        self
    }

    /// Get the interfaces.
    pub fn interfaces(&self) -> &[String] {
        &self.interfaces
    }

    /// Returns `true` if this is a canonical container.
    pub fn is_canonical_container(&self) -> bool {
        self.canonical_container
    }

    /// Get the attribute schema for a given name.
    pub fn get_attribute_schema(&self, name: &str) -> Option<&AttributeSchemaDesc> {
        self.attribute_schemas.get(name)
    }

    /// Get the child schema name for a given key.
    pub fn get_child_schema_name(&self, key: &str) -> &str {
        if KeyPath::is_index(key) {
            let index = KeyPath::parse_index(key);
            self.element_schemas
                .get(index)
                .map(|s| s.as_str())
                .unwrap_or(&self.default_element_schema)
        } else {
            self.attribute_schemas
                .get(key)
                .map(|a| a.schema_name.as_str())
                .unwrap_or(&self.default_attribute_schema.schema_name)
        }
    }

    /// Returns `true` if this schema implements the given interface.
    pub fn has_interface(&self, iface: &str) -> bool {
        self.interfaces.iter().any(|i| i == iface)
    }
}

impl fmt::Display for TraceObjectSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Schema({})", self.name)
    }
}

// ---------------------------------------------------------------------------
// SchemaContext
// ---------------------------------------------------------------------------

/// A context that holds and resolves schemas by name.
///
/// Ported from `ghidra.trace.model.target.schema.SchemaContext`.
#[derive(Debug)]
pub struct SchemaContext {
    schemas: HashMap<String, TraceObjectSchema>,
}

impl SchemaContext {
    /// Create a new empty schema context.
    pub fn new() -> Self {
        Self {
            schemas: HashMap::new(),
        }
    }

    /// Register a schema.
    pub fn register(&mut self, schema: TraceObjectSchema) {
        self.schemas.insert(schema.name.clone(), schema);
    }

    /// Get a schema by name.
    pub fn get_schema(&self, name: &str) -> Option<&TraceObjectSchema> {
        self.schemas.get(name)
    }

    /// Iterate over all schemas.
    pub fn schemas(&self) -> impl Iterator<Item = &TraceObjectSchema> {
        self.schemas.values()
    }
}

impl Default for SchemaContext {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PathFilter
// ---------------------------------------------------------------------------

/// A filter that matches object paths.
///
/// Ported from `ghidra.trace.model.target.path.PathFilter`.
#[derive(Debug, Clone)]
pub struct PathFilter {
    patterns: Vec<KeyPath>,
}

impl PathFilter {
    /// A filter that matches nothing.
    pub const NONE: PathFilter = PathFilter {
        patterns: Vec::new(),
    };

    /// Create a filter matching a single path.
    pub fn pattern(path: KeyPath) -> Self {
        Self {
            patterns: vec![path],
        }
    }

    /// Create a filter matching any of the given paths.
    pub fn any(patterns: Vec<KeyPath>) -> Self {
        Self { patterns }
    }

    /// Returns `true` if the given path matches any pattern in this filter.
    pub fn matches(&self, path: &KeyPath) -> bool {
        self.patterns.iter().any(|p| p.is_ancestor(path))
    }

    /// Returns `true` if this filter has no patterns.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

// ---------------------------------------------------------------------------
// TraceObjectManager
// ---------------------------------------------------------------------------

/// Manages trace objects.
///
/// Ported from `ghidra.trace.model.target.TraceObjectManager`.
#[derive(Debug)]
pub struct TraceObjectManager {
    objects: BTreeMap<String, TraceObject>,
    schema_context: SchemaContext,
}

impl TraceObjectManager {
    /// Create a new empty object manager.
    pub fn new() -> Self {
        Self {
            objects: BTreeMap::new(),
            schema_context: SchemaContext::new(),
        }
    }

    /// Get the schema context.
    pub fn schema_context(&self) -> &SchemaContext {
        &self.schema_context
    }

    /// Get a mutable reference to the schema context.
    pub fn schema_context_mut(&mut self) -> &mut SchemaContext {
        &mut self.schema_context
    }

    /// Add an object.
    pub fn add_object(&mut self, object: TraceObject) {
        let path_str = object.path.to_string();
        self.objects.insert(path_str, object);
    }

    /// Get an object by path.
    pub fn get_object(&self, path: &KeyPath) -> Option<&TraceObject> {
        self.objects.get(&path.to_string())
    }

    /// Get a mutable object by path.
    pub fn get_object_mut(&mut self, path: &KeyPath) -> Option<&mut TraceObject> {
        self.objects.get_mut(&path.to_string())
    }

    /// Remove an object by path.
    pub fn remove_object(&mut self, path: &KeyPath) -> Option<TraceObject> {
        self.objects.remove(&path.to_string())
    }

    /// Get all objects valid at the given snapshot.
    pub fn get_objects_at_snap(&self, snap: i64) -> Vec<&TraceObject> {
        self.objects.values().filter(|o| o.is_valid(snap)).collect()
    }

    /// Iterate over all objects.
    pub fn objects(&self) -> impl Iterator<Item = &TraceObject> {
        self.objects.values()
    }

    /// Returns the number of objects.
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Returns `true` if there are no objects.
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}

impl Default for TraceObjectManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_path_root() {
        let root = KeyPath::root();
        assert!(root.is_root());
        assert_eq!(root.size(), 0);
        assert!(root.key().is_none());
        assert!(root.parent().is_none());
    }

    #[test]
    fn test_key_path_extend() {
        let root = KeyPath::root();
        let p1 = root.key_extend("Threads");
        assert_eq!(p1.size(), 1);
        assert_eq!(p1.key(), Some("Threads"));

        let p2 = p1.index_extend("1");
        assert_eq!(p2.size(), 2);
        assert_eq!(p2.key_at(0), Some("Threads"));
        assert_eq!(p2.key_at(1), Some("[1]"));
    }

    #[test]
    fn test_key_path_parent() {
        let path = KeyPath::new(vec![
            "Threads".to_string(),
            "[1]".to_string(),
            "Stack".to_string(),
        ]);
        let parent = path.parent().unwrap();
        assert_eq!(parent.size(), 2);
        assert_eq!(parent.key(), Some("[1]"));
    }

    #[test]
    fn test_key_path_is_index() {
        assert!(KeyPath::is_index("[0]"));
        assert!(KeyPath::is_index("[42]"));
        assert!(!KeyPath::is_index("name"));
        assert!(!KeyPath::is_index(""));
    }

    #[test]
    fn test_key_path_is_ancestor() {
        let a = KeyPath::new(vec!["Threads".to_string(), "[1]".to_string()]);
        let b = KeyPath::new(vec![
            "Threads".to_string(),
            "[1]".to_string(),
            "Stack".to_string(),
        ]);
        assert!(a.is_ancestor(&b));
        assert!(!b.is_ancestor(&a));
        assert!(a.is_ancestor(&a)); // Equal paths are ancestors of each other
    }

    #[test]
    fn test_trace_object_value_display() {
        assert_eq!(format!("{}", TraceObjectValue::String("hello".into())), "\"hello\"");
        assert_eq!(format!("{}", TraceObjectValue::Integer(42)), "42");
        assert_eq!(format!("{}", TraceObjectValue::Boolean(true)), "true");
        assert_eq!(format!("{}", TraceObjectValue::Null), "null");
        assert_eq!(
            format!("{}", TraceObjectValue::ObjectRef(KeyPath::of("Threads"))),
            "@Threads"
        );
    }

    #[test]
    fn test_trace_object_basic() {
        let mut obj = TraceObject::new(
            KeyPath::of("Threads"),
            "ThreadContainer",
            Lifespan::now_on(0),
        );
        obj.set_attribute("name", TraceObjectValue::String("main".into()));
        obj.set_element("0", KeyPath::new(vec!["Threads".to_string(), "[0]".to_string()]));

        assert_eq!(
            obj.get_attribute("name"),
            Some(&TraceObjectValue::String("main".into()))
        );
        assert!(obj.get_attribute("missing").is_none());
        assert!(obj.get_element("0").is_some());
        assert!(obj.get_element("1").is_none());
        assert!(obj.is_valid(0));
    }

    #[test]
    fn test_trace_object_delete() {
        let mut obj = TraceObject::new(KeyPath::root(), "Root", Lifespan::now_on(0));
        assert!(obj.is_valid(0));
        obj.delete();
        assert!(!obj.is_valid(0));
    }

    #[test]
    fn test_trace_object_schema() {
        let schema = TraceObjectSchema::new("Process")
            .with_interface("Process")
            .with_canonical_container(true)
            .with_attribute("name", "String", true, false)
            .with_attribute("pid", "Integer", true, false);

        assert_eq!(schema.name(), "Process");
        assert!(schema.has_interface("Process"));
        assert!(!schema.has_interface("Thread"));
        assert!(schema.is_canonical_container());
        assert!(schema.get_attribute_schema("name").unwrap().required);
        assert!(!schema.get_attribute_schema("name").unwrap().fixed);
    }

    #[test]
    fn test_schema_context() {
        let mut ctx = SchemaContext::new();
        ctx.register(TraceObjectSchema::new("Process"));
        ctx.register(TraceObjectSchema::new("Thread"));

        assert!(ctx.get_schema("Process").is_some());
        assert!(ctx.get_schema("Thread").is_some());
        assert!(ctx.get_schema("Nonexistent").is_none());
    }

    #[test]
    fn test_path_filter() {
        let filter = PathFilter::NONE;
        assert!(filter.is_empty());
        assert!(!filter.matches(&KeyPath::of("test")));

        let filter2 = PathFilter::pattern(KeyPath::new(vec!["Threads".to_string(), "[1]".to_string()]));
        assert!(filter2.matches(&KeyPath::new(vec![
            "Threads".to_string(),
            "[1]".to_string(),
            "Stack".to_string(),
        ])));
        assert!(!filter2.matches(&KeyPath::of("Processes")));
    }

    #[test]
    fn test_object_manager() {
        let mut mgr = TraceObjectManager::new();
        let obj = TraceObject::new(KeyPath::of("root"), "Root", Lifespan::now_on(0));
        mgr.add_object(obj);

        assert_eq!(mgr.len(), 1);
        assert!(!mgr.is_empty());

        let found = mgr.get_object(&KeyPath::of("root"));
        assert!(found.is_some());
        assert_eq!(found.unwrap().schema_name, "Root");

        let not_found = mgr.get_object(&KeyPath::of("other"));
        assert!(not_found.is_none());
    }

    #[test]
    fn test_object_manager_remove() {
        let mut mgr = TraceObjectManager::new();
        mgr.add_object(TraceObject::new(KeyPath::of("temp"), "Temp", Lifespan::now_on(0)));
        assert_eq!(mgr.len(), 1);
        mgr.remove_object(&KeyPath::of("temp"));
        assert_eq!(mgr.len(), 0);
    }

    #[test]
    fn test_key_path_display() {
        let root = KeyPath::root();
        assert_eq!(format!("{root}"), "(root)");

        let path = KeyPath::new(vec!["Threads".to_string(), "[1]".to_string()]);
        assert_eq!(format!("{path}"), "Threads.[1]");
    }
}
