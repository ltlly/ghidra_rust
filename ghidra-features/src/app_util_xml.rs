//! XML utilities ported from Ghidra's `ghidra.app.util.xml` package.
//!
//! Provides XML parsing and serialization utilities for Ghidra:
//! - [`XmlPullParser`] -- lightweight XML pull parser
//! - [`XmlElement`] -- a parsed XML element
//! - [`XmlWriter`] -- XML serialization writer
//! - [`XmlAttributes`] -- XML attribute handling
//!
//! # Example
//!
//! ```rust
//! use ghidra_features::app_util_xml::*;
//!
//! let xml = r#"<program name="test.exe" arch="x86:LE:64:default">
//!     <memory_block name=".text" start="0x1000" length="4096"/>
//! </program>"#;
//!
//! let parser = XmlPullParser::new(xml);
//! let doc = parser.parse().unwrap();
//! assert_eq!(doc.tag_name, "program");
//! assert_eq!(doc.attr("name"), Some("test.exe"));
//! assert_eq!(doc.children.len(), 1);
//! ```

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// XmlElement
// ---------------------------------------------------------------------------

/// A parsed XML element with tag name, attributes, children, and optional text.
///
/// Ported from `ghidra.app.util.xml.XmlElement`.
#[derive(Debug, Clone, PartialEq)]
pub struct XmlElement {
    /// The element tag name.
    pub tag_name: String,
    /// The element attributes.
    pub attributes: HashMap<String, String>,
    /// Child elements.
    pub children: Vec<XmlElement>,
    /// Text content (if any).
    pub text: Option<String>,
}

impl XmlElement {
    /// Create a new element with the given tag name.
    pub fn new(tag_name: impl Into<String>) -> Self {
        Self {
            tag_name: tag_name.into(),
            attributes: HashMap::new(),
            children: Vec::new(),
            text: None,
        }
    }

    /// Get an attribute value by name.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes.get(name).map(|s| s.as_str())
    }

    /// Get an attribute value as a specific type.
    pub fn attr_as<T: std::str::FromStr>(&self, name: &str) -> Option<T> {
        self.attr(name).and_then(|v| v.parse().ok())
    }

    /// Get an attribute value as u64 (hex or decimal).
    pub fn attr_as_u64(&self, name: &str) -> Option<u64> {
        self.attr(name).and_then(|v| {
            if v.starts_with("0x") || v.starts_with("0X") {
                u64::from_str_radix(&v[2..], 16).ok()
            } else {
                v.parse().ok()
            }
        })
    }

    /// Get an attribute value as i64.
    pub fn attr_as_i64(&self, name: &str) -> Option<i64> {
        self.attr(name).and_then(|v| v.parse().ok())
    }

    /// Get an attribute value as bool.
    pub fn attr_as_bool(&self, name: &str) -> Option<bool> {
        self.attr(name).and_then(|v| match v.to_lowercase().as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        })
    }

    /// Set an attribute.
    pub fn set_attr(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.attributes.insert(name.into(), value.into());
    }

    /// Add a child element.
    pub fn add_child(&mut self, child: XmlElement) {
        self.children.push(child);
    }

    /// Find a direct child by tag name.
    pub fn child(&self, tag_name: &str) -> Option<&XmlElement> {
        self.children.iter().find(|c| c.tag_name == tag_name)
    }

    /// Find all direct children with the given tag name.
    pub fn children_with_tag(&self, tag_name: &str) -> Vec<&XmlElement> {
        self.children
            .iter()
            .filter(|c| c.tag_name == tag_name)
            .collect()
    }

    /// Get all child tag names.
    pub fn child_tag_names(&self) -> Vec<&str> {
        self.children.iter().map(|c| c.tag_name.as_str()).collect()
    }

    /// Check if this element has any children.
    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }

    /// Get the text content, trimming whitespace.
    pub fn text_content(&self) -> &str {
        self.text.as_deref().unwrap_or("").trim()
    }

    /// Check if the element is empty (no text, no children).
    pub fn is_empty(&self) -> bool {
        self.children.is_empty() && self.text.as_deref().unwrap_or("").trim().is_empty()
    }

    /// Serialize this element to XML string.
    pub fn to_xml(&self) -> String {
        let mut writer = XmlWriter::new();
        writer.write_element(self);
        writer.into_string()
    }

    /// Find an element by path (e.g., "parent/child/grandchild").
    pub fn find_by_path(&self, path: &str) -> Option<&XmlElement> {
        let parts: Vec<&str> = path.split('/').collect();
        let mut current = self;

        for part in &parts {
            match current.child(part) {
                Some(child) => current = child,
                None => return None,
            }
        }

        Some(current)
    }
}

impl fmt::Display for XmlElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_xml())
    }
}

// ---------------------------------------------------------------------------
// XmlPullParser
// ---------------------------------------------------------------------------

/// A lightweight XML pull parser.
///
/// Ported from `ghidra.app.util.xml.XmlPullParser`.
#[derive(Debug)]
pub struct XmlPullParser {
    input: Vec<char>,
    pos: usize,
}

impl XmlPullParser {
    /// Create a new parser from an XML string.
    pub fn new(input: &str) -> Self {
        Self {
            input: input.chars().collect(),
            pos: 0,
        }
    }

    /// Parse the XML input into a tree of elements.
    pub fn parse(mut self) -> Result<XmlElement, XmlParseError> {
        self.skip_whitespace();
        self.skip_xml_declaration();
        self.skip_whitespace();
        self.parse_element()
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() && self.input[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn skip_xml_declaration(&mut self) {
        if self.pos + 1 < self.input.len() && self.input[self.pos] == '<' && self.input[self.pos + 1] == '?' {
            // Skip <?xml ... ?>
            while self.pos < self.input.len() {
                if self.input[self.pos] == '?' && self.pos + 1 < self.input.len() && self.input[self.pos + 1] == '>' {
                    self.pos += 2;
                    return;
                }
                self.pos += 1;
            }
        }
    }

    fn parse_element(&mut self) -> Result<XmlElement, XmlParseError> {
        if self.pos >= self.input.len() || self.input[self.pos] != '<' {
            return Err(XmlParseError::UnexpectedEof);
        }

        self.pos += 1; // skip '<'

        // Skip comments and DOCTYPE
        if self.pos + 2 < self.input.len() && self.input[self.pos] == '!' && self.input[self.pos + 1] == '-' && self.input[self.pos + 2] == '-' {
            // Skip <!-- ... -->
            self.pos += 3;
            while self.pos + 2 < self.input.len() {
                if self.input[self.pos] == '-' && self.input[self.pos + 1] == '-' && self.input[self.pos + 2] == '>' {
                    self.pos += 3;
                    self.skip_whitespace();
                    return self.parse_element();
                }
                self.pos += 1;
            }
            return Err(XmlParseError::UnexpectedEof);
        }

        let tag_name = self.parse_name()?;
        let mut element = XmlElement::new(&tag_name);

        // Parse attributes
        loop {
            self.skip_whitespace();
            if self.pos >= self.input.len() {
                return Err(XmlParseError::UnexpectedEof);
            }

            if self.input[self.pos] == '>' {
                self.pos += 1;
                break;
            } else if self.input[self.pos] == '/' && self.pos + 1 < self.input.len() && self.input[self.pos + 1] == '>' {
                // Self-closing tag
                self.pos += 2;
                return Ok(element);
            } else {
                let (name, value) = self.parse_attribute()?;
                element.set_attr(name, value);
            }
        }

        // Parse children and text
        loop {
            self.skip_whitespace();
            if self.pos >= self.input.len() {
                return Err(XmlParseError::UnexpectedEof);
            }

            if self.input[self.pos] == '<' {
                if self.pos + 1 < self.input.len() && self.input[self.pos + 1] == '/' {
                    // Closing tag
                    self.pos += 2;
                    let closing_name = self.parse_name()?;
                    if closing_name != tag_name {
                        return Err(XmlParseError::MismatchedTag {
                            expected: tag_name,
                            found: closing_name,
                        });
                    }
                    self.skip_whitespace();
                    if self.pos < self.input.len() && self.input[self.pos] == '>' {
                        self.pos += 1;
                    }
                    return Ok(element);
                } else {
                    // Child element
                    let child = self.parse_element()?;
                    element.add_child(child);
                }
            } else {
                // Text content
                let text = self.parse_text()?;
                if !text.is_empty() {
                    element.text = Some(text);
                }
            }
        }
    }

    fn parse_name(&mut self) -> Result<String, XmlParseError> {
        let start = self.pos;
        while self.pos < self.input.len()
            && (self.input[self.pos].is_alphanumeric()
                || self.input[self.pos] == '_'
                || self.input[self.pos] == '-'
                || self.input[self.pos] == '.'
                || self.input[self.pos] == ':')
        {
            self.pos += 1;
        }
        if start == self.pos {
            return Err(XmlParseError::ExpectedName);
        }
        Ok(self.input[start..self.pos].iter().collect())
    }

    fn parse_attribute(&mut self) -> Result<(String, String), XmlParseError> {
        let name = self.parse_name()?;
        self.skip_whitespace();
        if self.pos >= self.input.len() || self.input[self.pos] != '=' {
            return Err(XmlParseError::ExpectedEquals);
        }
        self.pos += 1; // skip '='
        self.skip_whitespace();
        let value = self.parse_quoted_string()?;
        Ok((name, value))
    }

    fn parse_quoted_string(&mut self) -> Result<String, XmlParseError> {
        if self.pos >= self.input.len() {
            return Err(XmlParseError::UnexpectedEof);
        }
        let quote = self.input[self.pos];
        if quote != '"' && quote != '\'' {
            return Err(XmlParseError::ExpectedQuote);
        }
        self.pos += 1; // skip opening quote
        let start = self.pos;
        while self.pos < self.input.len() && self.input[self.pos] != quote {
            self.pos += 1;
        }
        if self.pos >= self.input.len() {
            return Err(XmlParseError::UnexpectedEof);
        }
        let value: String = self.input[start..self.pos].iter().collect();
        self.pos += 1; // skip closing quote
        Ok(value)
    }

    fn parse_text(&mut self) -> Result<String, XmlParseError> {
        let start = self.pos;
        while self.pos < self.input.len() && self.input[self.pos] != '<' {
            self.pos += 1;
        }
        let text: String = self.input[start..self.pos].iter().collect();
        Ok(text.trim().to_string())
    }
}

// ---------------------------------------------------------------------------
// XmlParseError
// ---------------------------------------------------------------------------

/// Error during XML parsing.
#[derive(Debug, Clone)]
pub enum XmlParseError {
    /// Unexpected end of input.
    UnexpectedEof,
    /// Expected an element or attribute name.
    ExpectedName,
    /// Expected '=' after attribute name.
    ExpectedEquals,
    /// Expected a quote character.
    ExpectedQuote,
    /// Mismatched closing tag.
    MismatchedTag { expected: String, found: String },
    /// Custom error message.
    Custom(String),
}

impl fmt::Display for XmlParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XmlParseError::UnexpectedEof => write!(f, "Unexpected end of XML input"),
            XmlParseError::ExpectedName => write!(f, "Expected element or attribute name"),
            XmlParseError::ExpectedEquals => write!(f, "Expected '=' after attribute name"),
            XmlParseError::ExpectedQuote => write!(f, "Expected quote character"),
            XmlParseError::MismatchedTag { expected, found } => {
                write!(f, "Mismatched tag: expected '{}', found '{}'", expected, found)
            }
            XmlParseError::Custom(msg) => write!(f, "XML parse error: {}", msg),
        }
    }
}

impl std::error::Error for XmlParseError {}

// ---------------------------------------------------------------------------
// XmlWriter
// ---------------------------------------------------------------------------

/// Serializes XML elements to strings.
///
/// Ported from `ghidra.app.util.xml.XmlWriter`.
#[derive(Debug)]
pub struct XmlWriter {
    output: String,
    indent: usize,
}

impl XmlWriter {
    pub fn new() -> Self {
        Self {
            output: String::new(),
            indent: 0,
        }
    }

    /// Write an element to the output.
    pub fn write_element(&mut self, element: &XmlElement) {
        self.write_indent();
        self.output.push('<');
        self.output.push_str(&element.tag_name);

        // Sort attributes for deterministic output
        let mut attrs: Vec<(&String, &String)> = element.attributes.iter().collect();
        attrs.sort_by_key(|(k, _)| k.as_str());
        for (name, value) in attrs {
            self.output.push(' ');
            self.output.push_str(name);
            self.output.push_str("=\"");
            self.write_escaped_attr(value);
            self.output.push('"');
        }

        if element.children.is_empty() && element.text.is_none() {
            self.output.push_str("/>\n");
        } else {
            self.output.push('>');
            if element.children.is_empty() {
                if let Some(text) = &element.text {
                    self.write_escaped_text(text);
                }
                self.output.push_str("</");
                self.output.push_str(&element.tag_name);
                self.output.push_str(">\n");
            } else {
                self.output.push('\n');
                self.indent += 1;
                for child in &element.children {
                    self.write_element(child);
                }
                if let Some(text) = &element.text {
                    self.write_indent();
                    self.write_escaped_text(text);
                    self.output.push('\n');
                }
                self.indent -= 1;
                self.write_indent();
                self.output.push_str("</");
                self.output.push_str(&element.tag_name);
                self.output.push_str(">\n");
            }
        }
    }

    fn write_indent(&mut self) {
        for _ in 0..self.indent {
            self.output.push_str("  ");
        }
    }

    fn write_escaped_attr(&mut self, s: &str) {
        for c in s.chars() {
            match c {
                '"' => self.output.push_str("&quot;"),
                '&' => self.output.push_str("&amp;"),
                '<' => self.output.push_str("&lt;"),
                '>' => self.output.push_str("&gt;"),
                _ => self.output.push(c),
            }
        }
    }

    fn write_escaped_text(&mut self, s: &str) {
        for c in s.chars() {
            match c {
                '&' => self.output.push_str("&amp;"),
                '<' => self.output.push_str("&lt;"),
                '>' => self.output.push_str("&gt;"),
                _ => self.output.push(c),
            }
        }
    }

    /// Get the output as a string.
    pub fn into_string(self) -> String {
        self.output
    }
}

impl Default for XmlWriter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// XmlAttributes helper
// ---------------------------------------------------------------------------

/// Utility for building XML attribute maps.
#[derive(Debug, Clone, Default)]
pub struct XmlAttributes {
    attrs: Vec<(String, String)>,
}

impl XmlAttributes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, name: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.attrs.push((name.into(), value.into()));
        self
    }

    pub fn add_u64(&mut self, name: impl Into<String>, value: u64) -> &mut Self {
        self.attrs.push((name.into(), format!("0x{:x}", value)));
        self
    }

    pub fn add_bool(&mut self, name: impl Into<String>, value: bool) -> &mut Self {
        self.attrs.push((name.into(), value.to_string()));
        self
    }

    pub fn to_map(&self) -> HashMap<String, String> {
        self.attrs.iter().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.attrs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.attrs.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_element() {
        let xml = "<root/>";
        let parser = XmlPullParser::new(xml);
        let doc = parser.parse().unwrap();
        assert_eq!(doc.tag_name, "root");
        assert!(doc.is_empty());
    }

    #[test]
    fn test_parse_element_with_attributes() {
        let xml = r#"<program name="test.exe" arch="x86:LE:64:default"/>"#;
        let parser = XmlPullParser::new(xml);
        let doc = parser.parse().unwrap();
        assert_eq!(doc.tag_name, "program");
        assert_eq!(doc.attr("name"), Some("test.exe"));
        assert_eq!(doc.attr("arch"), Some("x86:LE:64:default"));
    }

    #[test]
    fn test_parse_element_with_children() {
        let xml = r#"<program name="test.exe">
    <memory_block name=".text" start="0x1000" length="4096"/>
    <memory_block name=".data" start="0x5000" length="2048"/>
</program>"#;
        let parser = XmlPullParser::new(xml);
        let doc = parser.parse().unwrap();
        assert_eq!(doc.tag_name, "program");
        assert_eq!(doc.children.len(), 2);
        assert_eq!(doc.children[0].tag_name, "memory_block");
        assert_eq!(doc.children[0].attr("name"), Some(".text"));
        assert_eq!(doc.children[1].attr("name"), Some(".data"));
    }

    #[test]
    fn test_parse_with_xml_declaration() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<root><child/></root>"#;
        let parser = XmlPullParser::new(xml);
        let doc = parser.parse().unwrap();
        assert_eq!(doc.tag_name, "root");
        assert_eq!(doc.children.len(), 1);
    }

    #[test]
    fn test_parse_with_comments() {
        let xml = r#"<!-- This is a comment -->
<root>
    <!-- Another comment -->
    <child/>
</root>"#;
        let parser = XmlPullParser::new(xml);
        let doc = parser.parse().unwrap();
        assert_eq!(doc.tag_name, "root");
        assert_eq!(doc.children.len(), 1);
    }

    #[test]
    fn test_parse_text_content() {
        let xml = "<root>Hello World</root>";
        let parser = XmlPullParser::new(xml);
        let doc = parser.parse().unwrap();
        assert_eq!(doc.text_content(), "Hello World");
    }

    #[test]
    fn test_element_attr_as_u64() {
        let xml = r#"<item offset="0x1000" count="42"/>"#;
        let doc = XmlPullParser::new(xml).parse().unwrap();
        assert_eq!(doc.attr_as_u64("offset"), Some(0x1000));
        assert_eq!(doc.attr_as_u64("count"), Some(42));
        assert_eq!(doc.attr_as_u64("missing"), None);
    }

    #[test]
    fn test_element_attr_as_bool() {
        let xml = r#"<item enabled="true" verbose="false" flag="1"/>"#;
        let doc = XmlPullParser::new(xml).parse().unwrap();
        assert_eq!(doc.attr_as_bool("enabled"), Some(true));
        assert_eq!(doc.attr_as_bool("verbose"), Some(false));
        assert_eq!(doc.attr_as_bool("flag"), Some(true));
        assert_eq!(doc.attr_as_bool("missing"), None);
    }

    #[test]
    fn test_element_find_by_path() {
        let xml = r#"<root>
    <a>
        <b>
            <c value="found"/>
        </b>
    </a>
</root>"#;
        let doc = XmlPullParser::new(xml).parse().unwrap();
        let c = doc.find_by_path("a/b/c").unwrap();
        assert_eq!(c.attr("value"), Some("found"));

        assert!(doc.find_by_path("a/b/d").is_none());
        assert!(doc.find_by_path("x/y").is_none());
    }

    #[test]
    fn test_element_children_with_tag() {
        let xml = r#"<root>
    <item id="1"/>
    <item id="2"/>
    <other/>
    <item id="3"/>
</root>"#;
        let doc = XmlPullParser::new(xml).parse().unwrap();
        let items = doc.children_with_tag("item");
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].attr("id"), Some("1"));
        assert_eq!(items[2].attr("id"), Some("3"));
    }

    #[test]
    fn test_xml_writer() {
        let mut elem = XmlElement::new("program");
        elem.set_attr("name", "test.exe");

        let mut child = XmlElement::new("memory_block");
        child.set_attr("name", ".text");
        child.set_attr("start", "0x1000");
        elem.add_child(child);

        let xml = elem.to_xml();
        assert!(xml.contains("<program"));
        assert!(xml.contains("name=\"test.exe\""));
        assert!(xml.contains("<memory_block"));
        assert!(xml.contains("</program>"));
    }

    #[test]
    fn test_xml_writer_self_closing() {
        let elem = XmlElement::new("empty");
        let xml = elem.to_xml();
        assert!(xml.contains("<empty/>"));
    }

    #[test]
    fn test_xml_roundtrip() {
        let xml = r#"<root attr="value"><child id="1"/></root>"#;
        let doc = XmlPullParser::new(xml).parse().unwrap();
        let output = doc.to_xml();

        // Parse the output again
        let doc2 = XmlPullParser::new(&output).parse().unwrap();
        assert_eq!(doc2.tag_name, "root");
        assert_eq!(doc2.attr("attr"), Some("value"));
        assert_eq!(doc2.children.len(), 1);
        assert_eq!(doc2.children[0].tag_name, "child");
    }

    #[test]
    fn test_xml_attributes_helper() {
        let mut attrs = XmlAttributes::new();
        attrs.add("name", "test");
        attrs.add_u64("offset", 0x1000);
        attrs.add_bool("enabled", true);

        assert_eq!(attrs.len(), 3);
        let map = attrs.to_map();
        assert_eq!(map.get("name").unwrap(), "test");
        assert_eq!(map.get("offset").unwrap(), "0x1000");
        assert_eq!(map.get("enabled").unwrap(), "true");
    }

    #[test]
    fn test_parse_mismatched_tags() {
        let xml = "<a></b>";
        let result = XmlPullParser::new(xml).parse();
        assert!(result.is_err());
        match result.unwrap_err() {
            XmlParseError::MismatchedTag { expected, found } => {
                assert_eq!(expected, "a");
                assert_eq!(found, "b");
            }
            other => panic!("Expected MismatchedTag, got: {:?}", other),
        }
    }

    #[test]
    fn test_parse_empty_input() {
        let result = XmlPullParser::new("").parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_element_child_tag_names() {
        let xml = r#"<root><a/><b/><c/></root>"#;
        let doc = XmlPullParser::new(xml).parse().unwrap();
        assert_eq!(doc.child_tag_names(), vec!["a", "b", "c"]);
    }

    #[test]
    fn test_element_has_children() {
        let xml_leaf = "<leaf/>";
        let doc = XmlPullParser::new(xml_leaf).parse().unwrap();
        assert!(!doc.has_children());

        let xml_parent = "<parent><child/></parent>";
        let doc = XmlPullParser::new(xml_parent).parse().unwrap();
        assert!(doc.has_children());
    }

    #[test]
    fn test_parse_special_characters_in_attrs() {
        let xml = r#"<item name="foo &amp; bar" value="&lt;test&gt;"/>"#;
        let doc = XmlPullParser::new(xml).parse().unwrap();
        assert_eq!(doc.attr("name"), Some("foo &amp; bar"));
    }

    #[test]
    fn test_element_display() {
        let elem = XmlElement::new("test");
        let display = format!("{}", elem);
        assert!(display.contains("<test"));
    }

    #[test]
    fn test_xml_parse_error_display() {
        let err = XmlParseError::Custom("bad stuff".to_string());
        assert!(err.to_string().contains("bad stuff"));

        let err = XmlParseError::MismatchedTag {
            expected: "a".into(),
            found: "b".into(),
        };
        assert!(err.to_string().contains("a"));
        assert!(err.to_string().contains("b"));
    }
}
