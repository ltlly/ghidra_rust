//! XML parsing helpers (ported from `ghidra.app.util.xml`).
//!
//! Provides lightweight XML element types for Ghidra's XML-based
//! data formats (program XML, data type archives, etc.).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A parsed XML element.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XmlElement {
    /// Element tag name.
    pub tag: String,
    /// Element attributes.
    pub attributes: HashMap<String, String>,
    /// Child elements.
    pub children: Vec<XmlChild>,
}

/// A child node: either an element or text content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum XmlChild {
    /// A child element.
    Element(XmlElement),
    /// Text content.
    Text(String),
}

impl XmlElement {
    /// Create a new element.
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            attributes: HashMap::new(),
            children: Vec::new(),
        }
    }

    /// Add an attribute.
    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Add a text child.
    pub fn with_text(mut self, text: impl Into<String>) -> Self {
        self.children.push(XmlChild::Text(text.into()));
        self
    }

    /// Add a child element.
    pub fn with_child(mut self, child: XmlElement) -> Self {
        self.children.push(XmlChild::Element(child));
        self
    }

    /// Get an attribute value.
    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(|s| s.as_str())
    }

    /// Get the first child element with the given tag.
    pub fn child(&self, tag: &str) -> Option<&XmlElement> {
        self.children.iter().find_map(|c| match c {
            XmlChild::Element(e) if e.tag == tag => Some(e),
            _ => None,
        })
    }

    /// Get all child elements with the given tag.
    pub fn children_with_tag(&self, tag: &str) -> Vec<&XmlElement> {
        self.children
            .iter()
            .filter_map(|c| match c {
                XmlChild::Element(e) if e.tag == tag => Some(e),
                _ => None,
            })
            .collect()
    }

    /// Get the concatenated text content.
    pub fn text_content(&self) -> String {
        self.children
            .iter()
            .filter_map(|c| match c {
                XmlChild::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("")
    }

    /// Convert to a simple XML string.
    pub fn to_xml_string(&self) -> String {
        let mut s = format!("<{}", self.tag);
        for (k, v) in &self.attributes {
            s.push_str(&format!(" {}=\"{}\"", k, xml_escape_attr(v)));
        }
        if self.children.is_empty() {
            s.push_str(" />");
        } else {
            s.push('>');
            for child in &self.children {
                match child {
                    XmlChild::Element(e) => s.push_str(&e.to_xml_string()),
                    XmlChild::Text(t) => s.push_str(&xml_escape_text(t)),
                }
            }
            s.push_str(&format!("</{}>", self.tag));
        }
        s
    }
}

fn xml_escape_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn xml_escape_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_element_basic() {
        let e = XmlElement::new("root");
        assert_eq!(e.tag, "root");
        assert!(e.attributes.is_empty());
        assert!(e.children.is_empty());
        assert_eq!(e.to_xml_string(), "<root />");
    }

    #[test]
    fn xml_element_with_attrs() {
        let e = XmlElement::new("item").with_attr("id", "42").with_attr("name", "test");
        assert_eq!(e.attr("id"), Some("42"));
        assert_eq!(e.attr("name"), Some("test"));
        assert!(e.to_xml_string().contains("id=\"42\""));
    }

    #[test]
    fn xml_element_with_children() {
        let e = XmlElement::new("parent")
            .with_child(XmlElement::new("child").with_text("hello"))
            .with_child(XmlElement::new("child").with_text("world"));
        assert_eq!(e.children_with_tag("child").len(), 2);
        let xml = e.to_xml_string();
        assert!(xml.contains("<child>hello</child>"));
        assert!(xml.contains("<child>world</child>"));
    }

    #[test]
    fn xml_element_text_content() {
        let e = XmlElement::new("p")
            .with_text("Hello ")
            .with_text("World");
        assert_eq!(e.text_content(), "Hello World");
    }

    #[test]
    fn xml_element_nested() {
        let e = XmlElement::new("root").with_child(
            XmlElement::new("inner").with_attr("x", "1").with_text("content"),
        );
        let inner = e.child("inner").unwrap();
        assert_eq!(inner.text_content(), "content");
        assert_eq!(inner.attr("x"), Some("1"));
    }

    #[test]
    fn xml_escape_tests() {
        assert_eq!(xml_escape_attr("a\"b"), "a&quot;b");
        assert_eq!(xml_escape_text("<b>"), "&lt;b&gt;");
    }
}
