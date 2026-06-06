//! Default schema context and schema implementations.
//!
//! Ported from Ghidra's `DefaultSchemaContext`, `DefaultTraceObjectSchema`,
//! and `PrimitiveTraceObjectSchema`. These provide the concrete implementations
//! of the schema system used to define the structure of the trace target tree.

use indexmap::IndexMap;
use std::collections::HashMap;

use crate::model::target_schema::{AttributeSchema, SchemaName};

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
/// Ported from Ghidra's `XmlSchemaContext`. Parses XML schema definitions
/// into a `DefaultSchemaContext`. Supports the same XML elements and
/// attributes as Ghidra's implementation: `<context>`, `<schema>`,
/// `<interface>`, `<element>`, `<attribute>`, and `<attribute-alias>`.
pub struct XmlSchemaContext {
    context: DefaultSchemaContext,
    names: HashMap<String, SchemaName>,
}

impl XmlSchemaContext {
    /// Parse schema definitions from an XML string.
    ///
    /// Expects XML in the Ghidra schema format:
    /// ```xml
    /// <context>
    ///   <schema name="PROCESS">
    ///     <interface name="TraceProcess"/>
    ///     <element index="Threads" schema="OBJECT"/>
    ///     <attribute name="pid" schema="OBJECT" required="yes"/>
    ///     <attribute-alias from="process_id" to="pid"/>
    ///   </schema>
    /// </context>
    /// ```
    pub fn from_xml(xml: &str) -> Result<DefaultSchemaContext, String> {
        let mut parser = Self {
            context: DefaultSchemaContext::with_defaults(),
            names: HashMap::new(),
        };
        parser.parse(xml)?;
        Ok(parser.context)
    }

    fn parse(&mut self, xml: &str) -> Result<(), String> {
        let xml = xml.trim();
        // Find the <context> root element
        let context_start = xml.find("<context")
            .ok_or_else(|| "Missing <context> root element".to_string())?;
        let context_end_tag = xml[context_start..].find('>')
            .ok_or_else(|| "Unclosed <context> tag".to_string())?;
        let inner_start = context_start + context_end_tag + 1;
        let context_close = xml.rfind("</context>")
            .ok_or_else(|| "Missing </context> closing tag".to_string())?;
        let inner = &xml[inner_start..context_close];

        // Parse each <schema> element
        let mut remaining = inner;
        while let Some(start) = remaining.find("<schema") {
            remaining = &remaining[start..];
            let end = remaining.find("</schema>")
                .ok_or_else(|| "Unclosed <schema> tag".to_string())?;
            let schema_xml = &remaining[..end + "</schema>".len()];
            self.parse_schema(schema_xml)?;
            remaining = &remaining[end + "</schema>".len()..];
        }

        Ok(())
    }

    fn get_or_create_name(&mut self, name: &str) -> SchemaName {
        if let Some(sn) = self.names.get(name) {
            return sn.clone();
        }
        let sn = SchemaName::new(name);
        self.names.insert(name.to_string(), sn.clone());
        sn
    }

    fn parse_schema(&mut self, xml: &str) -> Result<(), String> {
        let tag_end = xml.find('>').ok_or("Unclosed schema tag")?;
        let tag_content = if xml.as_bytes().get(tag_end - 1) == Some(&b'/') {
            &xml[..tag_end - 1]
        } else {
            &xml[..tag_end]
        };

        let schema_name = Self::get_attr(tag_content, "name").unwrap_or_default();
        let is_canonical = Self::get_attr(tag_content, "canonical")
            .map(|v| Self::parse_bool(v))
            .unwrap_or(false);

        let sn = self.get_or_create_name(&schema_name);
        let mut schema = DefaultTraceObjectSchema::new("XmlLoaded", sn, schema_name.to_string());

        // Parse inner elements
        let inner_start = tag_end + 1;
        let inner_end = xml.rfind("</schema>").unwrap_or(xml.len());
        let inner = &xml[inner_start..inner_end];

        // Parse <interface> elements
        let mut remaining = inner;
        while let Some(start) = Self::find_element(remaining, "interface") {
            let (elem, rest) = Self::extract_element(remaining, start, "interface");
            if let Some(name) = Self::get_attr(&elem, "name") {
                schema.add_interface(name);
            }
            remaining = rest;
        }

        // Parse <element> elements
        remaining = inner;
        while let Some(start) = Self::find_element(remaining, "element") {
            let (elem, rest) = Self::extract_element(remaining, start, "element");
            if let Some(schema_ref) = Self::get_attr(&elem, "schema") {
                let _ = self.get_or_create_name(schema_ref);
                // Element schemas define what types of children are allowed
                if let Some(index) = Self::get_attr(&elem, "index") {
                    let attr = AttributeSchema::new(
                        format!("[{}]", index),
                        SchemaName::new(schema_ref),
                    );
                    schema.add_attribute(attr);
                }
            }
            remaining = rest;
        }

        // Parse <attribute> elements
        remaining = inner;
        while let Some(start) = Self::find_element(remaining, "attribute") {
            let (elem, rest) = Self::extract_element(remaining, start, "attribute");
            if let Some(schema_ref) = Self::get_attr(&elem, "schema") {
                let name = Self::get_attr(&elem, "name").unwrap_or("");
                let required = Self::get_attr(&elem, "required")
                    .map(Self::parse_bool)
                    .unwrap_or(false);
                let hidden = Self::get_attr(&elem, "hidden")
                    .map(Self::parse_bool)
                    .unwrap_or(false);

                let mut attr = AttributeSchema::new(name, SchemaName::new(schema_ref));
                if required {
                    attr = attr.required();
                }
                if hidden {
                    attr = attr.hidden();
                }
                schema.add_attribute(attr);
            }
            remaining = rest;
        }

        // Parse <attribute-alias> elements
        remaining = inner;
        while let Some(start) = Self::find_element(remaining, "attribute-alias") {
            let (elem, rest) = Self::extract_element(remaining, start, "attribute-alias");
            if let (Some(from), Some(to)) = (
                Self::get_attr(&elem, "from"),
                Self::get_attr(&elem, "to"),
            ) {
                let mut attr = AttributeSchema::new(from, SchemaName::object());
                attr = attr.alias_for(to);
                schema.add_attribute(attr);
            }
            remaining = rest;
        }

        if is_canonical {
            schema.set_canonical_key("key");
        }

        self.context.add_schema(schema);
        Ok(())
    }

    fn get_attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
        let pattern = format!("{}=\"", name);
        let start = tag.find(&pattern)? + pattern.len();
        let rest = &tag[start..];
        let end = rest.find('"')?;
        Some(&rest[..end])
    }

    fn parse_bool(value: &str) -> bool {
        matches!(
            value.to_lowercase().as_str(),
            "true" | "yes" | "y" | "1"
        )
    }

    fn find_element(haystack: &str, tag: &str) -> Option<usize> {
        let open = format!("<{}", tag);
        haystack.find(&open)
    }

    fn extract_element<'a>(haystack: &'a str, start: usize, tag: &str) -> (String, &'a str) {
        let close_tag = format!("</{}>", tag);
        let self_close = "/>";
        let rest = &haystack[start..];

        // Check if self-closing
        if let Some(end_pos) = rest.find(self_close) {
            let tag_end = rest.find('>').unwrap_or(end_pos);
            let elem = rest[..tag_end + 1].to_string();
            let after = &haystack[start + tag_end + 1..];
            return (elem, after);
        }

        if let Some(end_pos) = rest.find(&close_tag) {
            let elem = rest[..end_pos + close_tag.len()].to_string();
            let after = &haystack[start + end_pos + close_tag.len()..];
            return (elem, after);
        }

        // Fallback: take everything
        (rest.to_string(), "")
    }

    /// Serialize a schema context to an XML string.
    pub fn to_xml(context: &DefaultSchemaContext) -> String {
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<context>\n");
        for name in context.schema_names() {
            if let Some(schema) = context.get_schema(name) {
                xml.push_str(&format!("  <schema name=\"{}\">\n", schema.name));
                for iface in &schema.interfaces {
                    xml.push_str(&format!("    <interface name=\"{}\"/>\n", iface));
                }
                for (_, attr) in &schema.attributes {
                    xml.push_str(&format!(
                        "    <attribute name=\"{}\" schema=\"{}\"",
                        attr.name, attr.schema
                    ));
                    if attr.required {
                        xml.push_str(" required=\"yes\"");
                    }
                    if attr.hidden {
                        xml.push_str(" hidden=\"yes\"");
                    }
                    xml.push_str("/>\n");
                }
                xml.push_str("  </schema>\n");
            }
        }
        xml.push_str("</context>\n");
        xml
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

    #[test]
    fn test_xml_schema_context_parse() {
        let xml = r#"<context>
  <schema name="PROCESS">
    <interface name="TraceProcess"/>
    <interface name="TraceActivatable"/>
    <element index="Threads" schema="OBJECT"/>
    <attribute name="pid" schema="OBJECT" required="yes"/>
    <attribute name="name" schema="OBJECT"/>
    <attribute-alias from="process_id" to="pid"/>
  </schema>
</context>"#;

        let ctx = XmlSchemaContext::from_xml(xml).unwrap();
        assert!(ctx.has_schema(&SchemaName::new("PROCESS")));
        let schema = ctx.get_schema(&SchemaName::new("PROCESS")).unwrap();
        assert_eq!(schema.interfaces.len(), 2);
        assert!(schema.interfaces.contains(&"TraceProcess".to_string()));
    }

    #[test]
    fn test_xml_schema_context_roundtrip() {
        let ctx = SchemaContextBuilder::new("Test")
            .schema("PROC", "Process")
            .attribute("pid", "OBJECT")
            .interface("TraceProcess")
            .build();

        let xml = XmlSchemaContext::to_xml(&ctx);
        assert!(xml.contains("PROC"), "XML should contain PROC schema: {}", xml);
        assert!(xml.contains("TraceProcess"), "XML should contain TraceProcess: {}", xml);
        assert!(xml.contains("pid"), "XML should contain pid: {}", xml);
    }

    #[test]
    fn test_xml_schema_context_empty() {
        let xml = "<context></context>";
        let ctx = XmlSchemaContext::from_xml(xml).unwrap();
        // Should at least have the default OBJECT schema
        assert!(ctx.has_schema(&SchemaName::object()));
    }

    #[test]
    fn test_xml_schema_context_hidden_attribute() {
        let xml = r#"<context>
  <schema name="TEST">
    <attribute name="secret" schema="OBJECT" hidden="yes"/>
  </schema>
</context>"#;

        let ctx = XmlSchemaContext::from_xml(xml).unwrap();
        let schema = ctx.get_schema(&SchemaName::new("TEST")).unwrap();
        let attr = schema.get_attribute("secret").unwrap();
        assert!(attr.hidden);
    }

    #[test]
    fn test_xml_schema_context_self_closing() {
        let xml = r#"<context>
  <schema name="EMPTY">
  </schema>
</context>"#;
        let ctx = XmlSchemaContext::from_xml(xml).unwrap();
        assert!(ctx.has_schema(&SchemaName::new("EMPTY")));
    }

    #[test]
    fn test_xml_bad_schema_error() {
        let xml = "not xml at all";
        assert!(XmlSchemaContext::from_xml(xml).is_err());
    }
}
