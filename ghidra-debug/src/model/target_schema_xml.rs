//! XmlSchemaContext - XML-based schema deserialization for the target object model.
//!
//! Ported from Ghidra's `ghidra.trace.model.target.schema.XmlSchemaContext`.
//! Provides parsing of schema definitions from XML, including interfaces,
//! elements, attributes, and attribute aliases.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::target_schema::{AttributeSchema, SchemaBuilder, SchemaContext, SchemaName, TraceObjectSchemaDef};

/// XML element and attribute name constants.
pub mod xml_consts {
    /// Root context element name.
    pub const ELEM_CONTEXT: &str = "context";
    /// Schema element name.
    pub const ELEM_SCHEMA: &str = "schema";
    /// Interface element name.
    pub const ELEM_INTERFACE: &str = "interface";
    /// Element (child) element name.
    pub const ELEM_ELEMENT: &str = "element";
    /// Attribute element name.
    pub const ELEM_ATTRIBUTE: &str = "attribute";
    /// Alias element name.
    pub const ELEM_ATTRIBUTE_ALIAS: &str = "attribute-alias";
    /// Name attribute.
    pub const ATTR_NAME: &str = "name";
    /// Schema attribute.
    pub const ATTR_SCHEMA: &str = "schema";
    /// Canonical attribute.
    pub const ATTR_CANONICAL: &str = "canonical";
    /// Required attribute.
    pub const ATTR_REQUIRED: &str = "required";
    /// Fixed attribute.
    pub const ATTR_FIXED: &str = "fixed";
    /// Hidden attribute.
    pub const ATTR_HIDDEN: &str = "hidden";
    /// Index attribute.
    pub const ATTR_INDEX: &str = "index";
    /// From attribute (for aliases).
    pub const ATTR_FROM: &str = "from";
    /// To attribute (for aliases).
    pub const ATTR_TO: &str = "to";
}

/// Visibility level for schema attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HiddenLevel {
    /// Attribute is visible.
    No,
    /// Attribute is hidden from the default view.
    Yes,
    /// Attribute is hidden from the tree view.
    Tree,
}

impl Default for HiddenLevel {
    fn default() -> Self {
        Self::No
    }
}

/// A parsed XML element (simplified representation).
#[derive(Debug, Clone, Default)]
pub struct XmlElement {
    /// The element tag name.
    pub tag: String,
    /// The element's attributes.
    pub attributes: HashMap<String, String>,
    /// Child elements.
    pub children: Vec<XmlElement>,
    /// Text content, if any.
    pub text: Option<String>,
}

impl XmlElement {
    /// Create a new XML element.
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            attributes: HashMap::new(),
            children: Vec::new(),
            text: None,
        }
    }

    /// Get an attribute value.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes.get(name).map(|s| s.as_str())
    }

    /// Get an attribute value or a default.
    pub fn attr_or<'a>(&'a self, name: &str, default: &'a str) -> &'a str {
        self.attr(name).unwrap_or(default)
    }

    /// Get a required attribute value, returning an error if missing.
    pub fn require_attr(&self, name: &str) -> Result<&str, String> {
        self.attr(name).ok_or_else(|| {
            format!("Missing attribute '{}' in <{}>", name, self.tag)
        })
    }

    /// Get child elements with a given tag.
    pub fn children_with_tag(&self, tag: &str) -> Vec<&XmlElement> {
        self.children.iter().filter(|c| c.tag == tag).collect()
    }

    /// Parse a boolean attribute.
    pub fn parse_bool(&self, name: &str) -> bool {
        self.attr(name).map(|v| v == "true").unwrap_or(false)
    }
}

/// A schema context loaded from XML.
///
/// This extends the default schema context with the ability to parse
/// schema definitions from XML documents.
#[derive(Debug, Clone)]
pub struct XmlSchemaContext {
    /// The underlying default schema context.
    pub context: SchemaContext,
    /// Cached schema names.
    names: HashMap<String, SchemaName>,
}

impl XmlSchemaContext {
    /// Create a new empty XML schema context.
    pub fn new() -> Self {
        Self {
            context: SchemaContext::new(),
            names: HashMap::new(),
        }
    }

    /// Get or create a SchemaName.
    pub fn name(&mut self, name: &str) -> SchemaName {
        self.names
            .entry(name.to_string())
            .or_insert_with(|| SchemaName::new(name))
            .clone()
    }

    /// Parse a schema context from an XML element.
    pub fn context_from_xml(&mut self, context_elem: &XmlElement) -> Result<(), String> {
        if context_elem.tag != xml_consts::ELEM_CONTEXT {
            return Err(format!(
                "Expected <{}> root element, got <{}>",
                xml_consts::ELEM_CONTEXT,
                context_elem.tag
            ));
        }
        for schema_elem in context_elem.children_with_tag(xml_consts::ELEM_SCHEMA) {
            self.schema_from_xml(schema_elem)?;
        }
        Ok(())
    }

    /// Parse a single schema from an XML element.
    pub fn schema_from_xml(&mut self, schema_elem: &XmlElement) -> Result<TraceObjectSchemaDef, String> {
        let schema_name_str = schema_elem.attr_or(xml_consts::ATTR_NAME, "");
        let schema_name = self.name(schema_name_str);
        let mut builder = SchemaBuilder::new(schema_name.name.clone(), "TraceObject");

        // Parse interfaces
        for iface_elem in schema_elem.children_with_tag(xml_consts::ELEM_INTERFACE) {
            let iface_name = iface_elem.require_attr(xml_consts::ATTR_NAME)?;
            builder = builder.interface(iface_name.to_string());
        }

        // Parse canonical flag
        if schema_elem.parse_bool(xml_consts::ATTR_CANONICAL) {
            builder = builder.canonical_container();
        }

        // Parse elements (stored after build)
        let mut element_pairs: Vec<(String, SchemaName)> = Vec::new();
        for (i, elem_elem) in schema_elem.children_with_tag(xml_consts::ELEM_ELEMENT).into_iter().enumerate() {
            let child_schema_str = elem_elem.require_attr(xml_consts::ATTR_SCHEMA)?;
            let child_schema = self.name(child_schema_str);
            let index = elem_elem.attr_or(xml_consts::ATTR_INDEX, "");
            // Use explicit index if provided, otherwise use position-based index
            let key = if index.is_empty() {
                i.to_string()
            } else {
                index.to_string()
            };
            element_pairs.push((key, child_schema));
        }

        // Parse attributes
        for attr_elem in schema_elem.children_with_tag(xml_consts::ELEM_ATTRIBUTE) {
            let attr_name = attr_elem.attr_or(xml_consts::ATTR_NAME, "");
            let attr_schema_str = attr_elem.require_attr(xml_consts::ATTR_SCHEMA)?;
            let attr_schema = self.name(attr_schema_str);
            let required = attr_elem.parse_bool(xml_consts::ATTR_REQUIRED);
            let hidden = parse_hidden_level(attr_elem, xml_consts::ATTR_HIDDEN) != HiddenLevel::No;

            let mut attr = AttributeSchema::new(attr_name, attr_schema);
            if required {
                attr = attr.required();
            }
            if hidden {
                attr = attr.hidden();
            }
            builder = builder.attribute(attr);
        }

        // Parse attribute aliases
        for alias_elem in schema_elem.children_with_tag(xml_consts::ELEM_ATTRIBUTE_ALIAS) {
            let from = alias_elem.require_attr(xml_consts::ATTR_FROM)?;
            let to = alias_elem.require_attr(xml_consts::ATTR_TO)?;
            // Aliases are stored as attribute schemas with alias_for
            let attr = AttributeSchema::new(from, SchemaName::new("*")).alias_for(to);
            builder = builder.attribute(attr);
        }

        let mut schema = builder.build();
        // Add element schemas that were parsed
        for (index, child_schema) in element_pairs {
            schema.element_schemas.insert(index, child_schema);
        }
        self.context.register(schema.clone());
        Ok(schema)
    }

    /// Serialize a schema definition to an XML element.
    pub fn schema_to_xml(schema: &TraceObjectSchemaDef) -> XmlElement {
        let mut elem = XmlElement::new(xml_consts::ELEM_SCHEMA);
        elem.attributes
            .insert(xml_consts::ATTR_NAME.to_string(), schema.name.name.clone());

        if schema.canonical_container {
            elem.attributes
                .insert(xml_consts::ATTR_CANONICAL.to_string(), "true".to_string());
        }

        // Interfaces
        for iface in &schema.interfaces {
            let mut iface_elem = XmlElement::new(xml_consts::ELEM_INTERFACE);
            iface_elem
                .attributes
                .insert(xml_consts::ATTR_NAME.to_string(), iface.clone());
            elem.children.push(iface_elem);
        }

        // Elements
        for (index, child_schema) in &schema.element_schemas {
            let mut elem_elem = XmlElement::new(xml_consts::ELEM_ELEMENT);
            elem_elem
                .attributes
                .insert(xml_consts::ATTR_SCHEMA.to_string(), child_schema.name.clone());
            if !index.is_empty() {
                elem_elem
                    .attributes
                    .insert(xml_consts::ATTR_INDEX.to_string(), index.clone());
            }
            elem.children.push(elem_elem);
        }

        // Attributes
        for attr in schema.attribute_schemas.values() {
            let mut attr_elem = XmlElement::new(xml_consts::ELEM_ATTRIBUTE);
            attr_elem
                .attributes
                .insert(xml_consts::ATTR_NAME.to_string(), attr.name.clone());
            attr_elem
                .attributes
                .insert(xml_consts::ATTR_SCHEMA.to_string(), attr.schema.name.clone());
            if attr.required {
                attr_elem
                    .attributes
                    .insert(xml_consts::ATTR_REQUIRED.to_string(), "true".to_string());
            }
            if attr.hidden {
                attr_elem
                    .attributes
                    .insert(xml_consts::ATTR_HIDDEN.to_string(), "true".to_string());
            }
            elem.children.push(attr_elem);
        }

        // Attribute aliases
        for (from, to) in &schema.aliases {
            let mut alias_elem = XmlElement::new(xml_consts::ELEM_ATTRIBUTE_ALIAS);
            alias_elem
                .attributes
                .insert(xml_consts::ATTR_FROM.to_string(), from.clone());
            alias_elem
                .attributes
                .insert(xml_consts::ATTR_TO.to_string(), to.clone());
            elem.children.push(alias_elem);
        }

        elem
    }

    /// Serialize the entire context to an XML element.
    pub fn context_to_xml(&self) -> XmlElement {
        let mut root = XmlElement::new(xml_consts::ELEM_CONTEXT);
        for name in self.context.schema_names() {
            if let Some(schema) = self.context.get_schema(name) {
                root.children.push(Self::schema_to_xml(schema));
            }
        }
        root
    }

    /// Serialize the context to a simple XML string.
    pub fn to_xml_string(&self) -> String {
        let root = self.context_to_xml();
        element_to_string(&root, 0)
    }
}

impl Default for XmlSchemaContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a hidden level from an XML attribute.
fn parse_hidden_level(elem: &XmlElement, attr_name: &str) -> HiddenLevel {
    match elem.attr(attr_name) {
        Some("true") | Some("yes") => HiddenLevel::Yes,
        Some("tree") => HiddenLevel::Tree,
        _ => HiddenLevel::No,
    }
}

/// Convert an XML element to a simple string representation.
fn element_to_string(elem: &XmlElement, indent: usize) -> String {
    let pad = "  ".repeat(indent);
    let mut result = format!("{}<{}", pad, elem.tag);
    for (k, v) in &elem.attributes {
        result.push_str(&format!(" {}=\"{}\"", k, v));
    }
    if elem.children.is_empty() && elem.text.is_none() {
        result.push_str(" />\n");
        return result;
    }
    result.push_str(">\n");
    if let Some(ref text) = elem.text {
        result.push_str(&format!("{}  {}\n", pad, text));
    }
    for child in &elem.children {
        result.push_str(&element_to_string(child, indent + 1));
    }
    result.push_str(&format!("{}</{}>\n", pad, elem.tag));
    result
}

/// A simple XML parser for schema contexts.
///
/// This is a lightweight parser that handles the subset of XML needed for
/// schema context definitions. For full XML parsing, an external library
/// like `quick-xml` should be used.
pub struct XmlSchemaParser;

impl XmlSchemaParser {
    /// Parse an XML string into an XmlSchemaContext.
    pub fn parse(xml: &str) -> Result<XmlSchemaContext, String> {
        let root = Self::parse_element(xml)?;
        let mut ctx = XmlSchemaContext::new();
        ctx.context_from_xml(&root)?;
        Ok(ctx)
    }

    /// Parse a simple XML element from a string.
    fn parse_element(xml: &str) -> Result<XmlElement, String> {
        let trimmed = xml.trim();
        if !trimmed.starts_with('<') {
            return Err("Expected XML to start with '<'".to_string());
        }

        let end_of_open = trimmed.find('>').ok_or("Unclosed tag")?;
        let is_self_closing = trimmed.as_bytes().get(end_of_open - 1).map_or(false, |&b| b == b'/');
        let open_tag = if is_self_closing {
            &trimmed[1..end_of_open - 1]
        } else {
            &trimmed[1..end_of_open]
        };

        let parts: Vec<&str> = open_tag.splitn(2, |c: char| c.is_whitespace()).collect();
        let tag = parts[0].to_string();
        let mut elem = XmlElement::new(&tag);

        if parts.len() > 1 {
            elem.attributes = Self::parse_attributes(parts[1])?;
        }

        if is_self_closing {
            return Ok(elem);
        }

        let content_start = end_of_open + 1;
        let close_tag = format!("</{}>", tag);
        // Search for the matching close tag using depth counting
        let mut close_pos = None;
        let mut depth = 1i32;
        let mut pos = content_start;
        let open_prefix = format!("<{}", tag);
        while pos < trimmed.len() {
            if trimmed[pos..].starts_with(&close_tag) {
                depth -= 1;
                if depth == 0 {
                    close_pos = Some(pos);
                    break;
                }
                pos += close_tag.len();
            } else if trimmed[pos..].starts_with(&open_prefix) {
                let after = &trimmed[pos + open_prefix.len()..];
                if after.is_empty() || after.starts_with('>') || after.starts_with('/')
                    || after.starts_with(char::is_whitespace)
                {
                    depth += 1;
                }
                pos += 1;
            } else {
                pos += 1;
            }
        }
        let content_end = match close_pos {
            Some(pos) => pos,
            None => {
                return Err(format!(
                    "Missing closing tag {} (tag='{}', trimmed_len={})",
                    close_tag, tag, trimmed.len()
                ));
            }
        };
        let content = &trimmed[content_start..content_end];

        let mut remaining = content.trim();
        while !remaining.is_empty() {
            if remaining.starts_with("</") {
                // This is the parent's closing tag, stop parsing children
                break;
            } else if remaining.starts_with('<') {
                let child = Self::parse_element(remaining)?;
                let child_xml_len = Self::find_element_span(remaining)?;
                remaining = remaining[child_xml_len..].trim();
                elem.children.push(child);
            } else {
                let next_tag = remaining.find('<').unwrap_or(remaining.len());
                let text = remaining[..next_tag].trim();
                if !text.is_empty() {
                    elem.text = Some(text.to_string());
                }
                remaining = remaining[next_tag..].trim();
            }
        }

        Ok(elem)
    }

    /// Parse attributes from a string like `name="value" other="val"`.
    fn parse_attributes(s: &str) -> Result<HashMap<String, String>, String> {
        let mut attrs = HashMap::new();
        let mut remaining = s.trim();

        while !remaining.is_empty() {
            let eq_pos = remaining.find('=').ok_or("Expected '=' in attribute")?;
            let name = remaining[..eq_pos].trim().to_string();
            remaining = remaining[eq_pos + 1..].trim();

            if !remaining.starts_with('"') && !remaining.starts_with('\'') {
                return Err("Expected quoted attribute value".to_string());
            }
            let quote = remaining.as_bytes()[0] as char;
            remaining = &remaining[1..];
            let end_quote = remaining
                .find(quote)
                .ok_or("Unclosed attribute value")?;
            let value = remaining[..end_quote].to_string();
            remaining = remaining[end_quote + 1..].trim();

            attrs.insert(name, value);
        }

        Ok(attrs)
    }

    /// Find the span of an XML element starting at the beginning of `s`.
    fn find_element_span(s: &str) -> Result<usize, String> {
        if !s.starts_with('<') {
            return Err("Expected '<'".to_string());
        }

        // Find the end of the opening tag
        let mut end_of_open = 0;
        let mut in_quote = false;
        let mut quote_char = b'\0';
        for (i, &b) in s.as_bytes().iter().enumerate() {
            if i == 0 { continue; }
            if in_quote {
                if b == quote_char { in_quote = false; }
            } else if b == b'"' || b == b'\'' {
                in_quote = true;
                quote_char = b;
            } else if b == b'>' {
                end_of_open = i;
                break;
            }
        }
        if end_of_open == 0 {
            return Err("Unclosed tag".to_string());
        }

        let is_self_closing = s.as_bytes()[end_of_open - 1] == b'/';
        if is_self_closing {
            return Ok(end_of_open + 1);
        }

        let open_tag = &s[1..end_of_open];
        let tag = open_tag
            .split_whitespace()
            .next()
            .unwrap_or(open_tag);
        if tag.is_empty() || tag.starts_with('/') {
            return Err(format!("Invalid tag name: '{}'", tag));
        }
        let open_prefix = format!("<{} ", tag);
        let _open_prefix_exact = format!("<{}", tag);
        let close_tag = format!("</{}>", tag);

        let mut depth = 1;
        let mut pos = end_of_open + 1;
        while depth > 0 && pos < s.len() {
            if s[pos..].starts_with(&close_tag) {
                depth -= 1;
                if depth == 0 {
                    return Ok(pos + close_tag.len());
                }
                pos += close_tag.len();
            } else if s[pos..].starts_with('<') && !s[pos..].starts_with("</") {
                // Check if this is an opening tag for our element
                let rest = &s[pos..];
                if rest.starts_with(&open_prefix) || rest.starts_with(&format!("<{}>", tag))
                    || rest.starts_with(&format!("<{}/", tag))
                {
                    depth += 1;
                }
                pos += 1;
            } else {
                pos += 1;
            }
        }

        Err(format!("No matching closing tag for <{}>", tag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xml_element_basics() {
        let mut elem = XmlElement::new("test");
        elem.attributes.insert("name".to_string(), "value".to_string());
        assert_eq!(elem.attr("name"), Some("value"));
        assert_eq!(elem.attr("missing"), None);
        assert_eq!(elem.attr_or("missing", "default"), "default");
    }

    #[test]
    fn test_xml_element_children() {
        let mut parent = XmlElement::new("parent");
        let child1 = XmlElement::new("child");
        let mut child2 = XmlElement::new("child");
        child2.attributes.insert("id".to_string(), "2".to_string());
        let other = XmlElement::new("other");
        parent.children.push(child1);
        parent.children.push(child2);
        parent.children.push(other);

        assert_eq!(parent.children_with_tag("child").len(), 2);
        assert_eq!(parent.children_with_tag("other").len(), 1);
        assert_eq!(parent.children_with_tag("missing").len(), 0);
    }

    #[test]
    fn test_xml_schema_context_parse() {
        let xml = r#"<context>
  <schema name="OBJECT" canonical="true">
    <interface name="TraceObjectInterface"/>
    <attribute name="display" schema="string"/>
  </schema>
</context>"#;
        let ctx = XmlSchemaParser::parse(xml).unwrap();
        let schema = ctx.context.get_schema("OBJECT").unwrap();
        assert_eq!(schema.name.name, "OBJECT");
        assert!(schema.canonical_container);
        assert_eq!(schema.interfaces.len(), 1);
        assert_eq!(schema.attribute_schemas.len(), 1);
    }

    #[test]
    fn test_xml_schema_context_round_trip() {
        let mut ctx = XmlSchemaContext::new();
        let schema = SchemaBuilder::new("THREAD", "TraceObject")
            .interface("TraceThread")
            .build();
        ctx.context.register(schema);

        let xml_str = ctx.to_xml_string();
        assert!(xml_str.contains("THREAD"));
        assert!(xml_str.contains("TraceThread"));
    }

    #[test]
    fn test_hidden_level_parsing() {
        let elem = XmlElement::new("attr");
        assert_eq!(parse_hidden_level(&elem, "hidden"), HiddenLevel::No);

        let mut elem2 = XmlElement::new("attr");
        elem2.attributes.insert("hidden".to_string(), "true".to_string());
        assert_eq!(parse_hidden_level(&elem2, "hidden"), HiddenLevel::Yes);

        let mut elem3 = XmlElement::new("attr");
        elem3.attributes.insert("hidden".to_string(), "tree".to_string());
        assert_eq!(parse_hidden_level(&elem3, "hidden"), HiddenLevel::Tree);
    }

    #[test]
    fn test_xml_schema_with_multiple_schemas() {
        let xml = r#"<context>
  <schema name="PROCESS" canonical="true">
    <interface name="TraceProcess"/>
    <element schema="THREAD"/>
    <attribute name="pid" schema="long"/>
  </schema>
  <schema name="THREAD">
    <interface name="TraceThread"/>
  </schema>
</context>"#;
        let ctx = XmlSchemaParser::parse(xml).unwrap();
        assert!(ctx.context.has_schema("PROCESS"));
        assert!(ctx.context.has_schema("THREAD"));
        assert_eq!(ctx.context.schema_count(), 2);
    }

    #[test]
    fn test_xml_element_parse_bool() {
        let elem = XmlElement::new("test");
        assert!(!elem.parse_bool("flag"));

        let mut elem2 = XmlElement::new("test");
        elem2.attributes.insert("flag".to_string(), "true".to_string());
        assert!(elem2.parse_bool("flag"));

        let mut elem3 = XmlElement::new("test");
        elem3.attributes.insert("flag".to_string(), "false".to_string());
        assert!(!elem3.parse_bool("flag"));
    }

    #[test]
    fn test_schema_to_xml_and_back() {
        let schema = SchemaBuilder::new("MEMORY", "TraceObject")
            .interface("TraceMemory")
            .attribute(AttributeSchema::new("regions", SchemaName::new("REGION")).required())
            .build();

        let xml_elem = XmlSchemaContext::schema_to_xml(&schema);
        assert_eq!(xml_elem.tag, "schema");
        assert_eq!(xml_elem.attr("name"), Some("MEMORY"));
        assert_eq!(xml_elem.children_with_tag("interface").len(), 1);
        assert_eq!(xml_elem.children_with_tag("attribute").len(), 1);
    }

    #[test]
    fn test_xml_element_require_attr_error() {
        let elem = XmlElement::new("test");
        let result = elem.require_attr("missing");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing attribute"));
    }

    #[test]
    fn test_self_closing_element() {
        let xml = r#"<context>
  <schema name="EMPTY" />
</context>"#;
        let ctx = XmlSchemaParser::parse(xml).unwrap();
        assert!(ctx.context.has_schema("EMPTY"));
    }

    #[test]
    fn test_nested_elements() {
        let xml = r#"<context>
  <schema name="ROOT">
    <interface name="Root"/>
    <element schema="CHILD1"/>
    <element schema="CHILD2"/>
    <attribute name="a" schema="s1"/>
    <attribute name="b" schema="s2"/>
  </schema>
</context>"#;
        let ctx = XmlSchemaParser::parse(xml).unwrap();
        let schema = ctx.context.get_schema("ROOT").unwrap();
        assert_eq!(schema.element_schemas.len(), 2);
        assert_eq!(schema.attribute_schemas.len(), 2);
    }
}
