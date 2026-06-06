//! Extended target schema types ported from DefaultTraceObjectSchema.java.
//!
//! Provides the mutable builder and default implementation of TraceObjectSchema.

use std::collections::{HashMap, HashSet};

/// The type of a schema element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaType {
    /// Primitive type.
    Primitive(String),
    /// Object type (has children and interfaces).
    Object,
}

/// An attribute schema describing a child slot.
#[derive(Debug, Clone)]
pub struct AttributeSchema {
    /// The key pattern for this attribute.
    pub key_pattern: String,
    /// The schema name for the child, if typed.
    pub schema_name: Option<String>,
    /// Whether this attribute is required.
    pub required: bool,
    /// Whether this attribute is fixed (always present).
    pub fixed: bool,
}

impl AttributeSchema {
    /// Create a new attribute schema.
    pub fn new(key_pattern: impl Into<String>, schema_name: Option<String>) -> Self {
        Self {
            key_pattern: key_pattern.into(),
            schema_name,
            required: false,
            fixed: false,
        }
    }

    /// Mark as required.
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    /// Mark as fixed (always present).
    pub fn fixed(mut self) -> Self {
        self.fixed = true;
        self
    }
}

/// Default mutable implementation of a trace object schema.
#[derive(Debug, Clone)]
pub struct DefaultTraceObjectSchema {
    /// Schema name.
    pub name: String,
    /// The type.
    pub schema_type: SchemaType,
    /// Interfaces this schema declares.
    pub interfaces: HashSet<String>,
    /// Attribute schemas.
    pub attributes: HashMap<String, AttributeSchema>,
    /// Aliases (from -> to).
    pub aliases: HashMap<String, String>,
}

impl DefaultTraceObjectSchema {
    /// Create a new object schema.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            schema_type: SchemaType::Object,
            interfaces: HashSet::new(),
            attributes: HashMap::new(),
            aliases: HashMap::new(),
        }
    }

    /// Add an interface.
    pub fn add_interface(&mut self, iface: impl Into<String>) {
        self.interfaces.insert(iface.into());
    }

    /// Add an attribute.
    pub fn add_attribute(&mut self, key: impl Into<String>, schema: AttributeSchema) {
        self.attributes.insert(key.into(), schema);
    }

    /// Add an alias.
    pub fn add_alias(&mut self, from: impl Into<String>, to: impl Into<String>) {
        self.aliases.insert(from.into(), to.into());
    }

    /// Get an attribute by key.
    pub fn get_attribute(&self, key: &str) -> Option<&AttributeSchema> {
        self.attributes.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_builder() {
        let mut schema = DefaultTraceObjectSchema::new("Thread");
        schema.add_interface("Object");
        schema.add_attribute("_name", AttributeSchema::new("_name", Some("String".to_string())).required());
        assert!(schema.get_attribute("_name").is_some());
        assert!(schema.interfaces.contains("Object"));
    }

    #[test]
    fn test_alias() {
        let mut schema = DefaultTraceObjectSchema::new("Test");
        schema.add_alias("short_name", "_display");
        assert_eq!(schema.aliases.get("short_name").unwrap(), "_display");
    }
}
