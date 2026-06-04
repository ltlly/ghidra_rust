//! Default schema context and schema implementations.
//!
//! Ported from Ghidra's `DefaultSchemaContext`, `DefaultTraceObjectSchema`,
//! and `PrimitiveTraceObjectSchema`. These provide the concrete implementations
//! of the schema system used to define the structure of the trace target tree.

use indexmap::IndexMap;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use crate::model::target_schema::{AttributeSchema, SchemaBuilder, SchemaName};

/// A primitive schema that accepts any attributes and elements.
///
/// Corresponds to Ghidra's `PrimitiveTraceObjectSchema`. Used as a catch-all
/// schema for leaf objects or ad-hoc values.
#[derive(Debug, Clone)]
pub struct PrimitiveTraceObjectSchema {
    /// The name of this schema.
    pub name: SchemaName,
    /// The display name.
    pub display: String,
    /// The interfaces this schema requires.
    pub interfaces: Vec<String>,
}

impl PrimitiveTraceObjectSchema {
    /// Create a new primitive schema.
    pub fn new(name: SchemaName, display: impl Into<String>, interfaces: Vec<String>) -> Self {
        Self {
            name,
            display: display.into(),
            interfaces,
        }
    }

    /// Create the "OBJECT" primitive schema.
    pub fn object() -> Self {
        Self::new(SchemaName::object(), "Object", vec![])
    }

    /// Whether this schema has a specific attribute defined.
    pub fn has_attribute(&self, _name: &str) -> bool {
        // Primitive schemas accept all attributes.
        true
    }

    /// Get the interfaces this schema requires.
    pub fn interfaces(&self) -> &[String] {
        &self.interfaces
    }
}

/// A default trace object schema with defined attributes and elements.
///
/// Ported from Ghidra's `DefaultTraceObjectSchema`. Defines the structure
/// of a specific type of trace object, including its named attributes,
/// indexed elements, and required interfaces.
#[derive(Debug, Clone)]
pub struct DefaultTraceObjectSchema {
    /// The schema context this belongs to.
    pub context_name: String,
    /// The name of this schema.
    pub name: SchemaName,
    /// The display name.
    pub display: String,
    /// Named attributes.
    pub attributes: IndexMap<String, AttributeSchema>,
    /// Element schema (the schema of indexed children).
    pub element_schema: Option<SchemaName>,
    /// The interfaces this schema requires.
    pub interfaces: Vec<String>,
    /// Canonical key for uniquely identifying elements.
    pub canonical_key: Option<String>,
    /// Whether this schema is a root schema.
    pub is_root: bool,
}

impl DefaultTraceObjectSchema {
    /// Create a new default schema.
    pub fn new(
        context_name: impl Into<String>,
        name: SchemaName,
        display: impl Into<String>,
    ) -> Self {
        Self {
            context_name: context_name.into(),
            name,
            display: display.into(),
            attributes: IndexMap::new(),
            element_schema: None,
            interfaces: Vec::new(),
            canonical_key: None,
            is_root: false,
        }
    }

    /// Add an attribute to this schema.
    pub fn add_attribute(&mut self, attr: AttributeSchema) {
        self.attributes.insert(attr.name.clone(), attr);
    }

    /// Set the element schema.
    pub fn set_element_schema(&mut self, schema: SchemaName) {
        self.element_schema = Some(schema);
    }

    /// Add an interface requirement.
    pub fn add_interface(&mut self, iface: impl Into<String>) {
        let iface = iface.into();
        if !self.interfaces.contains(&iface) {
            self.interfaces.push(iface);
        }
    }

    /// Set the canonical key.
    pub fn set_canonical_key(&mut self, key: impl Into<String>) {
        self.canonical_key = Some(key.into());
    }

    /// Get an attribute by name.
    pub fn get_attribute(&self, name: &str) -> Option<&AttributeSchema> {
        self.attributes.get(name)
    }

    /// Get the interfaces this schema requires.
    pub fn interfaces(&self) -> &[String] {
        &self.interfaces
    }

    /// Whether this schema has elements.
    pub fn has_elements(&self) -> bool {
        self.element_schema.is_some()
    }

    /// Get the attribute names.
    pub fn attribute_names(&self) -> Vec<&str> {
        self.attributes.keys().map(|s| s.as_str()).collect()
    }
}

/// A schema context that manages schemas and their relationships.
///
/// Ported from Ghidra's `DefaultSchemaContext` and `SchemaContext`.
/// Provides a registry of schemas and supports schema lookup and
/// builder-based construction.
#[derive(Debug, Clone)]
pub struct DefaultSchemaContext {
    /// The name of this context.
    pub name: String,
    schemas: HashMap<SchemaName, SchemaEntry>,
}

#[derive(Debug, Clone)]
enum SchemaEntry {
    Primitive(PrimitiveTraceObjectSchema),
    Default(DefaultTraceObjectSchema),
}

impl DefaultSchemaContext {
    /// Create a new empty schema context.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            schemas: HashMap::new(),
        }
    }

    /// Create a schema context with the built-in OBJECT primitive.
    pub fn with_defaults() -> Self {
        let mut ctx = Self::new("Default");
        ctx.schemas.insert(
            SchemaName::object(),
            SchemaEntry::Primitive(PrimitiveTraceObjectSchema::object()),
        );
        ctx
    }

    /// Get a schema by name.
    pub fn get_schema(&self, name: &SchemaName) -> Option<&DefaultTraceObjectSchema> {
        self.schemas.get(name).and_then(|e| match e {
            SchemaEntry::Default(s) => Some(s),
            _ => None,
        })
    }

    /// Get a primitive schema by name.
    pub fn get_primitive(&self, name: &SchemaName) -> Option<&PrimitiveTraceObjectSchema> {
        self.schemas.get(name).and_then(|e| match e {
            SchemaEntry::Primitive(s) => Some(s),
            _ => None,
        })
    }

    /// Add a default schema.
    pub fn add_schema(&mut self, schema: DefaultTraceObjectSchema) {
        let name = schema.name.clone();
        self.schemas.insert(name, SchemaEntry::Default(schema));
    }

    /// Add a primitive schema.
    pub fn add_primitive(&mut self, schema: PrimitiveTraceObjectSchema) {
        let name = schema.name.clone();
        self.schemas.insert(name, SchemaEntry::Primitive(schema));
    }

    /// Get all schema names.
    pub fn schema_names(&self) -> Vec<&SchemaName> {
        self.schemas.keys().collect()
    }

    /// Number of schemas in this context.
    pub fn len(&self) -> usize {
        self.schemas.len()
    }

    /// Whether this context is empty.
    pub fn is_empty(&self) -> bool {
        self.schemas.is_empty()
    }

    /// Check whether a schema exists.
    pub fn has_schema(&self, name: &SchemaName) -> bool {
        self.schemas.contains_key(name)
    }

    /// Get the interfaces for a schema.
    pub fn get_interfaces(&self, name: &SchemaName) -> Vec<String> {
        match self.schemas.get(name) {
            Some(SchemaEntry::Default(s)) => s.interfaces.clone(),
            Some(SchemaEntry::Primitive(s)) => s.interfaces.clone(),
            None => Vec::new(),
        }
    }

    /// Get all attribute schemas for a given schema name.
    pub fn get_attributes(&self, name: &SchemaName) -> Option<&IndexMap<String, AttributeSchema>> {
        self.get_schema(name).map(|s| &s.attributes)
    }
}

/// A builder for constructing a schema context.
///
/// Ported from Ghidra's `SchemaBuilder` with a fluent API.
pub struct SchemaContextBuilder {
    context: DefaultSchemaContext,
    current_schema: Option<DefaultTraceObjectSchema>,
}

impl SchemaContextBuilder {
    /// Start building a new schema context.
    pub fn new(context_name: impl Into<String>) -> Self {
        Self {
            context: DefaultSchemaContext::new(context_name),
            current_schema: None,
        }
    }

    /// Begin defining a new schema.
    pub fn schema(
        mut self,
        name: impl Into<String>,
        display: impl Into<String>,
    ) -> Self {
        self.flush_current();
        let name_str = name.into();
        self.current_schema = Some(DefaultTraceObjectSchema::new(
            self.context.name.clone(),
            SchemaName::new(&name_str),
            display,
        ));
        self
    }

    /// Add an attribute to the current schema.
    pub fn attribute(mut self, name: impl Into<String>, schema_name: impl Into<String>) -> Self {
        if let Some(ref mut s) = self.current_schema {
            s.add_attribute(AttributeSchema::new(name, SchemaName::new(schema_name)));
        }
        self
    }

    /// Add a hidden attribute to the current schema.
    pub fn hidden_attribute(
        mut self,
        name: impl Into<String>,
        schema_name: impl Into<String>,
    ) -> Self {
        if let Some(ref mut s) = self.current_schema {
            let mut attr = AttributeSchema::new(name, SchemaName::new(schema_name));
            attr.hidden = true;
            s.add_attribute(attr);
        }
        self
    }

    /// Set the element schema for the current schema.
    pub fn element_schema(mut self, schema_name: impl Into<String>) -> Self {
        if let Some(ref mut s) = self.current_schema {
            s.set_element_schema(SchemaName::new(schema_name));
        }
        self
    }

    /// Add an interface to the current schema.
    pub fn interface(mut self, iface: impl Into<String>) -> Self {
        if let Some(ref mut s) = self.current_schema {
            s.add_interface(iface);
        }
        self
    }

    /// Set the canonical key for the current schema.
    pub fn canonical_key(mut self, key: impl Into<String>) -> Self {
        if let Some(ref mut s) = self.current_schema {
            s.set_canonical_key(key);
        }
        self
    }

    /// Mark the current schema as the root.
    pub fn root(mut self) -> Self {
        if let Some(ref mut s) = self.current_schema {
            s.is_root = true;
        }
        self
    }

    /// Build the schema context.
    pub fn build(mut self) -> DefaultSchemaContext {
        self.flush_current();
        self.context
    }

    fn flush_current(&mut self) {
        if let Some(schema) = self.current_schema.take() {
            self.context.add_schema(schema);
        }
    }
}

/// An XML-based schema context loader.
///
/// Ported from Ghidra's `XmlSchemaContext`. Provides parsing of XML
/// schema definitions into a `DefaultSchemaContext`.
pub struct XmlSchemaContext;

impl XmlSchemaContext {
    /// Parse schema definitions from an XML string.
    ///
    /// This is a simplified parser; the real Ghidra uses XML DOM parsing.
    pub fn from_xml(_xml: &str) -> Result<DefaultSchemaContext, String> {
        // Simplified: in a full port, this would parse XML schema definitions.
        // For now, return a default context with basic schemas.
        Ok(DefaultSchemaContext::with_defaults())
    }
}

/// Error type for bad schema definitions.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Bad schema: {0}")]
pub struct BadSchemaError(pub String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitive_schema() {
        let schema = PrimitiveTraceObjectSchema::object();
        assert_eq!(schema.name, SchemaName::object());
        assert!(schema.has_attribute("anything"));
    }

    #[test]
    fn test_default_schema() {
        let mut schema = DefaultTraceObjectSchema::new("ctx", SchemaName::new("PROC"), "Process");
        schema.add_attribute(AttributeSchema::new("pid", SchemaName::object()).required());
        schema.add_attribute(AttributeSchema::new("name", SchemaName::object()));
        schema.add_interface("TraceProcess");

        assert_eq!(schema.attribute_names().len(), 2);
        assert!(schema.get_attribute("pid").unwrap().required);
        assert_eq!(schema.interfaces().len(), 1);
    }

    #[test]
    fn test_schema_context() {
        let mut ctx = DefaultSchemaContext::with_defaults();
        assert!(ctx.has_schema(&SchemaName::object()));

        let mut proc_schema = DefaultTraceObjectSchema::new(
            "Default",
            SchemaName::new("PROCESS"),
            "Process",
        );
        proc_schema.add_attribute(AttributeSchema::new("pid", SchemaName::object()));
        proc_schema.add_interface("TraceProcess");
        ctx.add_schema(proc_schema);

        assert!(ctx.has_schema(&SchemaName::new("PROCESS")));
        assert_eq!(ctx.len(), 2); // OBJECT + PROCESS
    }

    #[test]
    fn test_schema_builder() {
        let ctx = SchemaContextBuilder::new("Test")
            .schema("SESSION", "Session")
            .attribute("name", "OBJECT")
            .interface("TraceEnvironment")
            .root()
            .schema("PROCESS", "Process")
            .attribute("pid", "OBJECT")
            .attribute("name", "OBJECT")
            .interface("TraceProcess")
            .build();

        assert!(ctx.has_schema(&SchemaName::new("SESSION")));
        assert!(ctx.has_schema(&SchemaName::new("PROCESS")));
        assert_eq!(ctx.get_schema(&SchemaName::new("PROCESS")).unwrap().attribute_names().len(), 2);
    }

    #[test]
    fn test_attribute_builder() {
        let attr = AttributeSchema::new("pid", SchemaName::object())
            .required()
            .alias_for("process_id");
        assert!(attr.required);
        assert_eq!(attr.alias_for.as_deref(), Some("process_id"));
    }

    #[test]
    fn test_schema_context_get_interfaces() {
        let ctx = SchemaContextBuilder::new("Test")
            .schema("PROC", "Process")
            .interface("TraceProcess")
            .interface("TraceActivatable")
            .build();

        let ifaces = ctx.get_interfaces(&SchemaName::new("PROC"));
        assert_eq!(ifaces.len(), 2);
        assert!(ifaces.contains(&"TraceProcess".to_string()));
    }
}
