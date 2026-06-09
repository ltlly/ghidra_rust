//! XML utility functions for reading, writing, and transforming XML data.
//!
//! Port of `ghidra.util.XmlUtilities` and related XML helpers.
//!
//! Note: The lower-level XML parsing abstractions (XmlPullParser, XmlElement, etc.)
//! are in the [`xml_parser`] module. This module provides higher-level utility functions
//! for working with XML data.

use std::collections::HashMap;
use std::fmt;

/// XML utility functions.
///
/// Port of `ghidra.util.XmlUtilities`.
pub struct XmlUtilities;

impl XmlUtilities {
    /// Escape a string for safe inclusion in an XML text node or attribute value.
    ///
    /// Replaces `<`, `>`, `&`, `"`, and `'` with their XML entity equivalents.
    pub fn escape_xml(s: &str) -> String {
        let mut result = String::with_capacity(s.len() + s.len() / 4);
        for c in s.chars() {
            match c {
                '&' => result.push_str("&amp;"),
                '<' => result.push_str("&lt;"),
                '>' => result.push_str("&gt;"),
                '"' => result.push_str("&quot;"),
                '\'' => result.push_str("&apos;"),
                _ => result.push(c),
            }
        }
        result
    }

    /// Unescape XML entities in a string.
    ///
    /// Handles `&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`, and numeric character references.
    pub fn unescape_xml(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '&' {
                let mut entity = String::new();
                loop {
                    match chars.next() {
                        Some(';') => break,
                        Some(ch) => entity.push(ch),
                        None => {
                            result.push('&');
                            result.push_str(&entity);
                            return result;
                        }
                    }
                }
                match entity.as_str() {
                    "amp" => result.push('&'),
                    "lt" => result.push('<'),
                    "gt" => result.push('>'),
                    "quot" => result.push('"'),
                    "apos" => result.push('\''),
                    e if e.starts_with('#') => {
                        let num_str = &e[1..];
                        let codepoint = if num_str.starts_with('x') || num_str.starts_with('X') {
                            u32::from_str_radix(&num_str[1..], 16).ok()
                        } else {
                            num_str.parse::<u32>().ok()
                        };
                        if let Some(cp) = codepoint {
                            if let Some(ch) = char::from_u32(cp) {
                                result.push(ch);
                            } else {
                                result.push('&');
                                result.push_str(e);
                                result.push(';');
                            }
                        } else {
                            result.push('&');
                            result.push_str(e);
                            result.push(';');
                        }
                    }
                    _ => {
                        result.push('&');
                        result.push_str(&entity);
                        result.push(';');
                    }
                }
            } else {
                result.push(c);
            }
        }
        result
    }

    /// Build an XML element string from a tag name, attributes, and text content.
    ///
    /// Produces a self-contained element: `<tag attr="val">content</tag>`.
    pub fn element(tag: &str, attributes: &HashMap<String, String>, content: &str) -> String {
        let mut result = format!("<{}", Self::escape_xml(tag));
        for (key, value) in attributes {
            result.push_str(&format!(
                " {}=\"{}\"",
                Self::escape_xml(key),
                Self::escape_xml(value)
            ));
        }
        result.push('>');
        result.push_str(&Self::escape_xml(content));
        result.push_str(&format!("</{}>", Self::escape_xml(tag)));
        result
    }

    /// Build a self-closing XML element: `<tag attr="val" />`.
    pub fn empty_element(tag: &str, attributes: &HashMap<String, String>) -> String {
        let mut result = format!("<{}", Self::escape_xml(tag));
        for (key, value) in attributes {
            result.push_str(&format!(
                " {}=\"{}\"",
                Self::escape_xml(key),
                Self::escape_xml(value)
            ));
        }
        result.push_str(" />");
        result
    }

    /// Build an XML start tag: `<tag attr="val">`.
    pub fn start_tag(tag: &str, attributes: &HashMap<String, String>) -> String {
        let mut result = format!("<{}", Self::escape_xml(tag));
        for (key, value) in attributes {
            result.push_str(&format!(
                " {}=\"{}\"",
                Self::escape_xml(key),
                Self::escape_xml(value)
            ));
        }
        result.push('>');
        result
    }

    /// Build an XML end tag: `</tag>`.
    pub fn end_tag(tag: &str) -> String {
        format!("</{}>", Self::escape_xml(tag))
    }

    /// Indent XML text by the given number of levels (2 spaces per level).
    pub fn indent(xml: &str, levels: usize) -> String {
        let indent_str = "  ".repeat(levels);
        xml.lines()
            .map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    String::new()
                } else {
                    format!("{}{}", indent_str, trimmed)
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Pretty-print XML with indentation.
    ///
    /// Adds 2-space indentation based on nesting depth. This is a simple
    /// heuristic that indents after `>` and outdents before `</`.
    pub fn pretty_print(xml: &str) -> String {
        let mut result = String::with_capacity(xml.len() * 2);
        let mut depth: usize = 0;
        let mut chars = xml.chars().peekable();
        let mut current = String::new();

        while let Some(c) = chars.next() {
            current.push(c);
            if c == '>' {
                let trimmed = current.trim();
                if trimmed.is_empty() {
                    current.clear();
                    continue;
                }

                let is_closing = trimmed.starts_with("</");
                let is_self_closing = trimmed.ends_with("/>");
                let is_declaration = trimmed.starts_with("<?");
                let is_comment = trimmed.starts_with("<!--");

                if is_closing {
                    depth = depth.saturating_sub(1);
                }

                result.push_str(&"  ".repeat(depth));
                result.push_str(trimmed);
                result.push('\n');

                if !is_closing && !is_self_closing && !is_declaration && !is_comment {
                    depth += 1;
                }

                current.clear();
            }
        }

        if !current.trim().is_empty() {
            result.push_str(current.trim());
        }

        result
    }

    /// Validate that a string is well-formed XML (very basic check).
    ///
    /// Checks that tags are balanced. This is NOT a full XML validator;
    /// it performs a simple stack-based tag matching check.
    pub fn is_well_formed(xml: &str) -> bool {
        let mut tag_stack: Vec<String> = Vec::new();
        let mut chars = xml.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '<' {
                let mut tag = String::new();
                loop {
                    match chars.next() {
                        Some('>') => break,
                        Some(ch) => tag.push(ch),
                        None => return false, // unclosed tag
                    }
                }

                let tag = tag.trim();

                // Skip declarations, comments, CDATA
                if tag.starts_with('?') || tag.starts_with('!')
                    || tag.starts_with("![CDATA[")
                {
                    continue;
                }

                if tag.starts_with('/') {
                    // Closing tag
                    let name = tag[1..].trim().split_whitespace().next().unwrap_or("");
                    match tag_stack.pop() {
                        Some(open_name) if open_name == name => {}
                        _ => return false, // mismatched tags
                    }
                } else if !tag.ends_with('/') {
                    // Opening tag (not self-closing)
                    let name = tag.split_whitespace().next().unwrap_or("");
                    if !name.is_empty() {
                        tag_stack.push(name.to_string());
                    }
                }
                // Self-closing tags are ignored
            }
        }

        tag_stack.is_empty()
    }

    /// Extract the tag name from a start tag string (e.g., `"<foo bar='baz'>"` -> `"foo"`).
    pub fn tag_name(tag: &str) -> Option<&str> {
        let s = tag.trim();
        let s = s.strip_prefix('<')?;
        let s = s.strip_prefix('/').unwrap_or(s);
        let name = s.split_whitespace().next()?;
        let name = name.trim_end_matches('>').trim_end_matches('/');
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }

    /// Parse attributes from a tag string into a map.
    ///
    /// Given `<foo bar="baz" qux='1'>`, returns `{"bar": "baz", "qux": "1"}`.
    pub fn parse_attributes(tag: &str) -> HashMap<String, String> {
        let mut attrs = HashMap::new();
        let s = tag.trim();
        let s = match s.strip_prefix('<') {
            Some(s) => s,
            None => return attrs,
        };
        // Skip the tag name
        let rest = match s.find(|c: char| c.is_whitespace() || c == '>' || c == '/') {
            Some(pos) => &s[pos..],
            None => return attrs,
        };

        let mut chars = rest.chars().peekable();

        loop {
            // Skip whitespace
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() || c == '/' || c == '>' {
                    chars.next();
                    if c == '>' {
                        return attrs;
                    }
                } else {
                    break;
                }
            }

            // Read attribute name
            let mut name = String::new();
            while let Some(&c) = chars.peek() {
                if c == '=' || c.is_whitespace() || c == '>' || c == '/' {
                    break;
                }
                name.push(c);
                chars.next();
            }
            if name.is_empty() {
                continue;
            }

            // Skip whitespace and '='
            while let Some(&c) = chars.peek() {
                if c == '=' {
                    chars.next();
                    break;
                } else if c.is_whitespace() {
                    chars.next();
                } else {
                    break;
                }
            }

            // Skip whitespace
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    chars.next();
                } else {
                    break;
                }
            }

            // Read attribute value
            let mut value = String::new();
            if let Some(&quote) = chars.peek() {
                if quote == '"' || quote == '\'' {
                    chars.next(); // consume opening quote
                    while let Some(c) = chars.next() {
                        if c == quote {
                            break;
                        }
                        value.push(c);
                    }
                }
            }

            attrs.insert(name, value);
        }
    }
}

/// An XML writer that produces properly formatted XML output.
#[derive(Debug)]
pub struct XmlWriter {
    buf: String,
    depth: usize,
    indent_str: String,
}

impl XmlWriter {
    /// Create a new XML writer.
    pub fn new() -> Self {
        Self {
            buf: String::new(),
            depth: 0,
            indent_str: "  ".to_string(),
        }
    }

    /// Create a new XML writer with a custom indent string.
    pub fn with_indent(indent: &str) -> Self {
        Self {
            buf: String::new(),
            depth: 0,
            indent_str: indent.to_string(),
        }
    }

    /// Write the XML declaration.
    pub fn declaration(&mut self, version: &str, encoding: &str) -> &mut Self {
        self.buf.push_str(&format!(
            "<?xml version=\"{}\" encoding=\"{}\"?>\n",
            version, encoding
        ));
        self
    }

    /// Write a start tag with optional attributes.
    pub fn start_element(&mut self, tag: &str, attributes: &HashMap<String, String>) -> &mut Self {
        self.write_indent();
        self.buf.push_str(&XmlUtilities::start_tag(tag, attributes));
        self.buf.push('\n');
        self.depth += 1;
        self
    }

    /// Write an end tag.
    pub fn end_element(&mut self, tag: &str) -> &mut Self {
        self.depth = self.depth.saturating_sub(1);
        self.write_indent();
        self.buf.push_str(&XmlUtilities::end_tag(tag));
        self.buf.push('\n');
        self
    }

    /// Write a complete element with text content.
    pub fn element(&mut self, tag: &str, attributes: &HashMap<String, String>, content: &str) -> &mut Self {
        self.write_indent();
        self.buf.push_str(&XmlUtilities::element(tag, attributes, content));
        self.buf.push('\n');
        self
    }

    /// Write a self-closing element.
    pub fn empty_element(&mut self, tag: &str, attributes: &HashMap<String, String>) -> &mut Self {
        self.write_indent();
        self.buf.push_str(&XmlUtilities::empty_element(tag, attributes));
        self.buf.push('\n');
        self
    }

    /// Write a comment.
    pub fn comment(&mut self, text: &str) -> &mut Self {
        self.write_indent();
        self.buf.push_str(&format!("<!-- {} -->\n", text));
        self
    }

    /// Write raw XML content at the current indent level.
    pub fn raw(&mut self, xml: &str) -> &mut Self {
        let indented = XmlUtilities::indent(xml, self.depth);
        self.buf.push_str(&indented);
        self.buf.push('\n');
        self
    }

    fn write_indent(&mut self) {
        for _ in 0..self.depth {
            self.buf.push_str(&self.indent_str);
        }
    }

    /// Consume the writer and return the XML string.
    pub fn build(self) -> String {
        self.buf
    }
}

impl Default for XmlWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for XmlWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_xml() {
        assert_eq!(
            XmlUtilities::escape_xml("<foo>&\"bar\"</foo>"),
            "&lt;foo&gt;&amp;&quot;bar&quot;&lt;/foo&gt;"
        );
    }

    #[test]
    fn test_unescape_xml() {
        assert_eq!(
            XmlUtilities::unescape_xml("&lt;foo&gt;&amp;&quot;bar&quot;&lt;/foo&gt;"),
            "<foo>&\"bar\"</foo>"
        );
    }

    #[test]
    fn test_escape_unescape_roundtrip() {
        let original = "<tag attr=\"val\">text & 'more'</tag>";
        let escaped = XmlUtilities::escape_xml(original);
        let unescaped = XmlUtilities::unescape_xml(&escaped);
        assert_eq!(unescaped, original);
    }

    #[test]
    fn test_element() {
        let mut attrs = HashMap::new();
        attrs.insert("id".to_string(), "1".to_string());
        let elem = XmlUtilities::element("item", &attrs, "content");
        assert_eq!(elem, "<item id=\"1\">content</item>");
    }

    #[test]
    fn test_empty_element() {
        let mut attrs = HashMap::new();
        attrs.insert("href".to_string(), "test".to_string());
        let elem = XmlUtilities::empty_element("link", &attrs);
        assert_eq!(elem, "<link href=\"test\" />");
    }

    #[test]
    fn test_start_end_tag() {
        let attrs = HashMap::new();
        assert_eq!(XmlUtilities::start_tag("div", &attrs), "<div>");
        assert_eq!(XmlUtilities::end_tag("div"), "</div>");
    }

    #[test]
    fn test_is_well_formed() {
        assert!(XmlUtilities::is_well_formed("<root><child/></root>"));
        assert!(XmlUtilities::is_well_formed("<a><b>text</b></a>"));
        assert!(!XmlUtilities::is_well_formed("<a><b>text</a></b>"));
        assert!(!XmlUtilities::is_well_formed("<unclosed>"));
    }

    #[test]
    fn test_tag_name() {
        assert_eq!(XmlUtilities::tag_name("<foo>"), Some("foo"));
        assert_eq!(XmlUtilities::tag_name("</foo>"), Some("foo"));
        assert_eq!(XmlUtilities::tag_name("<foo bar='baz'>"), Some("foo"));
        assert_eq!(XmlUtilities::tag_name("<foo/>"), Some("foo"));
    }

    #[test]
    fn test_parse_attributes() {
        let attrs = XmlUtilities::parse_attributes("<foo bar=\"baz\" qux='1'>");
        assert_eq!(attrs.get("bar").map(|s| s.as_str()), Some("baz"));
        assert_eq!(attrs.get("qux").map(|s| s.as_str()), Some("1"));
    }

    #[test]
    fn test_pretty_print() {
        let xml = "<root><child>text</child></root>";
        let pretty = XmlUtilities::pretty_print(xml);
        assert!(pretty.contains("<root>"));
        assert!(pretty.contains("  <child>text</child>"));
    }

    #[test]
    fn test_indent() {
        let indented = XmlUtilities::indent("<p>hello</p>", 2);
        assert_eq!(indented, "    <p>hello</p>");
    }

    #[test]
    fn test_xml_writer() {
        let mut w = XmlWriter::new();
        w.declaration("1.0", "UTF-8");
        let mut attrs = HashMap::new();
        attrs.insert("version".to_string(), "1".to_string());
        w.start_element("root", &attrs);
        w.element("child", &HashMap::new(), "text");
        w.end_element("root");
        let xml = w.build();
        assert!(xml.contains("<?xml"));
        assert!(xml.contains("<root version=\"1\">"));
        assert!(xml.contains("<child>text</child>"));
        assert!(xml.contains("</root>"));
    }
}
