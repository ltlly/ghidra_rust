//! XML parsing abstractions.
//!
//! Port of `ghidra.xml`: XmlPullParser, XmlElement, XmlException,
//! XmlElementImpl, and AbstractXmlPullParser.

use std::collections::HashMap;
use std::fmt;

/// Error during XML parsing.
///
/// Port of `ghidra.xml.XmlException`.
#[derive(Debug, Clone)]
pub struct XmlException {
    message: String,
    line: Option<usize>,
    column: Option<usize>,
}

impl XmlException {
    /// Create a new XML exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            line: None,
            column: None,
        }
    }

    /// Create with line/column information.
    pub fn with_location(message: impl Into<String>, line: usize, column: usize) -> Self {
        Self {
            message: message.into(),
            line: Some(line),
            column: Some(column),
        }
    }

    /// Get the line number, if available.
    pub fn line(&self) -> Option<usize> {
        self.line
    }

    /// Get the column number, if available.
    pub fn column(&self) -> Option<usize> {
        self.column
    }
}

impl fmt::Display for XmlException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.line, self.column) {
            (Some(l), Some(c)) => write!(f, "XML error at line {}, col {}: {}", l, c, self.message),
            (Some(l), None) => write!(f, "XML error at line {}: {}", l, self.message),
            _ => write!(f, "XML error: {}", self.message),
        }
    }
}

impl std::error::Error for XmlException {}

/// An XML element with name, attributes, and child content.
///
/// Port of `ghidra.xml.XmlElement` and `ghidra.xml.XmlElementImpl`.
#[derive(Debug, Clone)]
pub struct XmlElement {
    /// The element's tag name.
    pub name: String,
    /// The element's attributes.
    pub attributes: HashMap<String, String>,
    /// Text content of the element.
    pub content: Option<String>,
    /// Child elements.
    pub children: Vec<XmlElement>,
}

impl XmlElement {
    /// Create a new XML element.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            attributes: HashMap::new(),
            content: None,
            children: Vec::new(),
        }
    }

    /// Get the element name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get an attribute value by name.
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes.get(name).map(|s| s.as_str())
    }

    /// Get an attribute as a string, or return a default.
    pub fn attribute_or<'a>(&'a self, name: &str, default: &'a str) -> &'a str {
        self.attribute(name).unwrap_or(default)
    }

    /// Get an attribute parsed as a u64, or return a default.
    pub fn attribute_as_u64(&self, name: &str, default: u64) -> u64 {
        self.attribute(name)
            .and_then(|v| {
                let v = v.trim();
                if v.starts_with("0x") || v.starts_with("0X") {
                    u64::from_str_radix(&v[2..], 16).ok()
                } else {
                    v.parse().ok()
                }
            })
            .unwrap_or(default)
    }

    /// Set an attribute value.
    pub fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.attributes.insert(key.into(), value.into());
    }

    /// Get the text content.
    pub fn content(&self) -> Option<&str> {
        self.content.as_deref()
    }

    /// Set the text content.
    pub fn set_content(&mut self, content: impl Into<String>) {
        self.content = Some(content.into());
    }

    /// Add a child element.
    pub fn add_child(&mut self, child: XmlElement) {
        self.children.push(child);
    }

    /// Get child elements.
    pub fn children(&self) -> &[XmlElement] {
        &self.children
    }

    /// Find a child element by name.
    pub fn child(&self, name: &str) -> Option<&XmlElement> {
        self.children.iter().find(|c| c.name == name)
    }

    /// Find all child elements with the given name.
    pub fn children_named(&self, name: &str) -> Vec<&XmlElement> {
        self.children.iter().filter(|c| c.name == name).collect()
    }

    /// Whether this is a start element.
    pub fn is_start(&self) -> bool {
        !self.name.is_empty()
    }

    /// Whether this is an end-of-element marker.
    pub fn is_end(&self) -> bool {
        self.name.is_empty()
    }
}

impl fmt::Display for XmlElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}", self.name)?;
        for (key, value) in &self.attributes {
            write!(f, " {}=\"{}\"", key, value)?;
        }
        if self.children.is_empty() && self.content.is_none() {
            write!(f, " />")
        } else {
            write!(f, ">")?;
            if let Some(ref content) = self.content {
                write!(f, "{}", content)?;
            }
            for child in &self.children {
                write!(f, "{}", child)?;
            }
            write!(f, "</{}>", self.name)
        }
    }
}

/// Interface for XML pull parsers.
///
/// Port of `ghidra.xml.XmlPullParser`.
pub trait XmlPullParser {
    /// Returns the name of this parser.
    fn name(&self) -> &str;

    /// Returns the current line number.
    fn line_number(&self) -> usize;

    /// Returns the current column number.
    fn column_number(&self) -> usize;

    /// Returns whether the parser returns content elements.
    fn is_pulling_content(&self) -> bool;

    /// Set whether to return content elements.
    fn set_pulling_content(&mut self, pulling: bool);

    /// Parse the next XML event and return it as an XmlElement.
    fn next(&mut self) -> Result<Option<XmlElement>, XmlException>;

    /// Returns true if there are more events to parse.
    fn has_next(&self) -> bool;

    /// Get the value of a processing instruction attribute.
    fn processing_instruction(&self, name: &str, attribute: &str) -> Option<String>;
}

/// A simple SAX-like XML element for building parse trees.
///
/// This is a simpler representation than XmlElement, intended for
/// incremental building during pull-parsing.
#[derive(Debug, Clone)]
pub struct XmlEvent {
    /// The event type.
    pub event_type: XmlEventType,
    /// The element name (for start/end events).
    pub name: String,
    /// Attributes (for start events).
    pub attributes: HashMap<String, String>,
    /// Text content (for content events).
    pub text: String,
}

/// XML event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlEventType {
    /// Start of an element.
    StartElement,
    /// End of an element.
    EndElement,
    /// Text content.
    Content,
    /// Processing instruction.
    ProcessingInstruction,
    /// End of document.
    EndDocument,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xml_element_basic() {
        let elem = XmlElement::new("div");
        assert_eq!(elem.name(), "div");
        assert!(elem.is_start());
        assert!(!elem.is_end());
    }

    #[test]
    fn test_xml_element_attributes() {
        let mut elem = XmlElement::new("a");
        elem.set_attribute("href", "https://example.com");
        assert_eq!(elem.attribute("href"), Some("https://example.com"));
        assert_eq!(elem.attribute_or("class", "default"), "default");
    }

    #[test]
    fn test_xml_element_u64_attribute() {
        let mut elem = XmlElement::new("addr");
        elem.set_attribute("offset", "0xFF");
        assert_eq!(elem.attribute_as_u64("offset", 0), 0xFF);

        elem.set_attribute("size", "1024");
        assert_eq!(elem.attribute_as_u64("size", 0), 1024);
    }

    #[test]
    fn test_xml_element_children() {
        let mut parent = XmlElement::new("parent");
        parent.add_child(XmlElement::new("child1"));
        parent.add_child(XmlElement::new("child2"));
        assert_eq!(parent.children().len(), 2);
        assert!(parent.child("child1").is_some());
        assert!(parent.child("child2").is_some());
        assert!(parent.child("child3").is_none());
    }

    #[test]
    fn test_xml_element_display() {
        let elem = XmlElement::new("br");
        assert_eq!(format!("{}", elem), "<br />");

        let mut elem = XmlElement::new("p");
        elem.set_content("hello");
        assert_eq!(format!("{}", elem), "<p>hello</p>");
    }

    #[test]
    fn test_xml_exception() {
        let e = XmlException::new("unexpected tag");
        assert!(format!("{}", e).contains("unexpected tag"));

        let e = XmlException::with_location("bad syntax", 10, 5);
        assert!(format!("{}", e).contains("line 10"));
        assert_eq!(e.line(), Some(10));
    }
}
