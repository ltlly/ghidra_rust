//! TraceObjectSchema - schema definitions for the debug target object model.
//!
//! Ported from Ghidra's `ghidra.trace.model.target.schema` package.
//! Defines the schema system that governs what types of objects can appear
//! in the target tree, their attributes, elements, and interface requirements.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};


/// A name identifying a schema within a schema context.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SchemaName {
    /// The schema name (e.g., "OBJECT", "THREAD", "PROCESS").
    pub name: String,
}

impl SchemaName {
    /// Create a new schema name.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// The name for the primitive object schema.
    pub fn object() -> Self {
        Self::new("OBJECT")
    }
}

impl std::fmt::Display for SchemaName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// Schema for an attribute (named child) of a TraceObject.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeSchema {
    /// The display name of the attribute.
    pub name: String,
    /// The schema name of values this attribute can hold.
    pub schema: SchemaName,
    /// Whether this attribute is hidden from the UI.
    pub hidden: bool,
    /// Whether this attribute is required.
    pub required: bool,
    /// An alias name for this attribute (alternative key that maps to it).
    pub alias_for: Option<String>,
}

impl AttributeSchema {
    /// Create a new attribute schema.
    pub fn new(name: impl Into<String>, schema: SchemaName) -> Self {
        Self {
            name: name.into(),
            schema,
            hidden: false,
            required: false,
            alias_for: None,
        }
    }

    /// Mark this attribute as hidden.
    pub fn hidden(mut self) -> Self {
        self.hidden = true;
        self
    }

    /// Mark this attribute as required.
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    /// Set this attribute as an alias for another.
    pub fn alias_for(mut self, target: impl Into<String>) -> Self {
        self.alias_for = Some(target.into());
        self
    }

    /// Check if this key is hidden (for a given key name).
    pub fn is_hidden(&self, _key: &str) -> bool {
        self.hidden
    }
}

/// A schema that defines the structure and constraints of a TraceObject.
///
/// Schemas define what interfaces an object implements, what attributes and
/// elements it can have, and what type of Java/Rust value it requires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceObjectSchemaDef {
    /// The name of this schema.
    pub name: SchemaName,
    /// The set of interface names this schema implements.
    pub interfaces: HashSet<String>,
    /// The required Rust type name (or Java class name).
    pub type_name: String,
    /// Named element schemas (indexed children).
    pub element_schemas: IndexMap<String, SchemaName>,
    /// Default element schema for elements not explicitly listed.
    pub default_element_schema: SchemaName,
    /// Named attribute schemas.
    pub attribute_schemas: IndexMap<String, AttributeSchema>,
    /// Default attribute schema for attributes not explicitly listed.
    pub default_attribute_schema: AttributeSchema,
    /// Whether this schema is a canonical container.
    pub canonical_container: bool,
    /// Whether this schema can be used as an alias source.
    pub aliases: HashMap<String, String>,
}

impl TraceObjectSchemaDef {
    /// Create a new schema definition.
    pub fn new(name: impl Into<String>, type_name: impl Into<String>) -> Self {
        let name = SchemaName::new(name);
        Self {
            name: name.clone(),
            interfaces: HashSet::new(),
            type_name: type_name.into(),
            element_schemas: IndexMap::new(),
            default_element_schema: SchemaName::object(),
            attribute_schemas: IndexMap::new(),
            default_attribute_schema: AttributeSchema::new("*", SchemaName::object()),
            canonical_container: false,
            aliases: HashMap::new(),
        }
    }

    /// Add an interface to this schema.
    pub fn with_interface(mut self, iface: impl Into<String>) -> Self {
        self.interfaces.insert(iface.into());
        self
    }

    /// Add a named element schema.
    pub fn with_element(mut self, key: impl Into<String>, schema: SchemaName) -> Self {
        self.element_schemas.insert(key.into(), schema);
        self
    }

    /// Set the default element schema.
    pub fn with_default_element(mut self, schema: SchemaName) -> Self {
        self.default_element_schema = schema;
        self
    }

    /// Add a named attribute schema.
    pub fn with_attribute(mut self, attr: AttributeSchema) -> Self {
        let key = attr.name.clone();
        self.attribute_schemas.insert(key, attr);
        self
    }

    /// Mark this schema as a canonical container.
    pub fn as_canonical_container(mut self) -> Self {
        self.canonical_container = true;
        self
    }

    /// Add an alias mapping.
    pub fn with_alias(mut self, alias: impl Into<String>, target: impl Into<String>) -> Self {
        self.aliases.insert(alias.into(), target.into());
        self
    }

    /// Check if this schema implements a given interface.
    pub fn implements(&self, iface: &str) -> bool {
        self.interfaces.contains(iface)
    }

    /// Get the schema for a child key.
    pub fn child_schema_name(&self, key: &str) -> &SchemaName {
        if let Some(idx) = key.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            self.element_schemas
                .get(idx)
                .unwrap_or(&self.default_element_schema)
        } else {
            self.attribute_schemas
                .get(key)
                .map(|a| &a.schema)
                .unwrap_or(&self.default_attribute_schema.schema)
        }
    }
}

/// The context that holds all known schemas.
///
/// A SchemaContext is the registry of all schema definitions. It allows
/// schemas to reference each other by name.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SchemaContext {
    schemas: HashMap<String, TraceObjectSchemaDef>,
}

impl SchemaContext {
    /// Create a new empty schema context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a schema in this context.
    pub fn register(&mut self, schema: TraceObjectSchemaDef) {
        self.schemas.insert(schema.name.name.clone(), schema);
    }

    /// Get a schema by name.
    pub fn get_schema(&self, name: &str) -> Option<&TraceObjectSchemaDef> {
        self.schemas.get(name)
    }

    /// Check if a schema is registered.
    pub fn has_schema(&self, name: &str) -> bool {
        self.schemas.contains_key(name)
    }

    /// Get all registered schema names.
    pub fn schema_names(&self) -> impl Iterator<Item = &str> {
        self.schemas.keys().map(|s| s.as_str())
    }

    /// Get the number of registered schemas.
    pub fn schema_count(&self) -> usize {
        self.schemas.len()
    }
}

/// Builder for constructing schemas fluently.
pub struct SchemaBuilder {
    schema: TraceObjectSchemaDef,
}

impl SchemaBuilder {
    /// Start building a schema with the given name.
    pub fn new(name: impl Into<String>, type_name: impl Into<String>) -> Self {
        Self {
            schema: TraceObjectSchemaDef::new(name, type_name),
        }
    }

    /// Add an interface.
    pub fn interface(mut self, iface: impl Into<String>) -> Self {
        self.schema.interfaces.insert(iface.into());
        self
    }

    /// Add a named attribute.
    pub fn attribute(mut self, attr: AttributeSchema) -> Self {
        let key = attr.name.clone();
        self.schema.attribute_schemas.insert(key, attr);
        self
    }

    /// Mark as canonical container.
    pub fn canonical_container(mut self) -> Self {
        self.schema.canonical_container = true;
        self
    }

    /// Build the final schema.
    pub fn build(self) -> TraceObjectSchemaDef {
        self.schema
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_creation() {
        let schema = TraceObjectSchemaDef::new("THREAD", "TraceObject")
            .with_interface("TraceThread")
            .with_interface("TraceObjectInterface");
        assert_eq!(schema.name.name, "THREAD");
        assert!(schema.implements("TraceThread"));
        assert!(schema.implements("TraceObjectInterface"));
        assert!(!schema.implements("TraceModule"));
    }

    #[test]
    fn test_schema_context() {
        let mut ctx = SchemaContext::new();
        let obj_schema = TraceObjectSchemaDef::new("OBJECT", "TraceObject");
        ctx.register(obj_schema);
        assert!(ctx.has_schema("OBJECT"));
        assert!(!ctx.has_schema("THREAD"));
        assert_eq!(ctx.schema_count(), 1);
    }

    #[test]
    fn test_attribute_schema() {
        let attr = AttributeSchema::new("name", SchemaName::object())
            .required()
            .hidden();
        assert!(attr.required);
        assert!(attr.hidden);
    }

    #[test]
    fn test_child_schema_lookup() {
        let mut schema = TraceObjectSchemaDef::new("PROCESS", "TraceObject");
        schema
            .attribute_schemas
            .insert("pid".into(), AttributeSchema::new("pid", SchemaName::new("VALUE")));
        schema.element_schemas.insert(
            "0".into(),
            SchemaName::new("THREAD"),
        );

        assert_eq!(schema.child_schema_name("pid").name, "VALUE");
        assert_eq!(schema.child_schema_name("[0]").name, "THREAD");
        assert_eq!(schema.child_schema_name("[99]").name, "OBJECT"); // default
        assert_eq!(schema.child_schema_name("unknown").name, "OBJECT"); // default attr
    }

    #[test]
    fn test_schema_builder() {
        let schema = SchemaBuilder::new("PROCESS", "TraceObject")
            .interface("TraceProcess")
            .canonical_container()
            .build();
        assert!(schema.implements("TraceProcess"));
        assert!(schema.canonical_container);
    }

    #[test]
    fn test_schema_name_display() {
        let name = SchemaName::new("THREAD");
        assert_eq!(format!("{}", name), "THREAD");
    }

    #[test]
    fn test_alias_attribute() {
        let attr = AttributeSchema::new("_display_name", SchemaName::object())
            .alias_for("display");
        assert_eq!(attr.alias_for.as_deref(), Some("display"));
    }
}
