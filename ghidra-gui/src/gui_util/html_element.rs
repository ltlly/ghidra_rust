//! HTML element types for structured HTML construction.
//!
//! Ports Ghidra's `ghidra.util.html.HTMLElement`, `HtmlLineSplitter`,
//! `TrimmingWhitespaceHandler`, `PreservingWhitespaceHandler`, and
//! `WhitespaceHandler` from the `ghidra.util.html` package.

use std::fmt;

/// Trait for whitespace handling strategies when parsing HTML text.
///
/// Port of `ghidra.util.html.WhitespaceHandler`.
pub trait WhitespaceHandler: fmt::Debug {
    /// Process a text segment, handling whitespace according to the strategy.
    fn handle_text(&self, text: &str) -> String;

    /// Process a whitespace-only segment.
    fn handle_whitespace(&self, whitespace: &str) -> String;
}

/// Whitespace handler that trims leading and trailing whitespace from text
/// segments and collapses internal whitespace to single spaces.
///
/// Port of `ghidra.util.html.TrimmingWhitespaceHandler`.
#[derive(Debug, Clone, Copy, Default)]
pub struct TrimmingWhitespaceHandler;

impl WhitespaceHandler for TrimmingWhitespaceHandler {
    fn handle_text(&self, text: &str) -> String {
        let trimmed = text.trim();
        let mut result = String::with_capacity(trimmed.len());
        let mut prev_was_space = false;
        for ch in trimmed.chars() {
            if ch.is_whitespace() {
                if !prev_was_space {
                    result.push(' ');
                }
                prev_was_space = true;
            } else {
                result.push(ch);
                prev_was_space = false;
            }
        }
        result
    }

    fn handle_whitespace(&self, _whitespace: &str) -> String {
        String::from(" ")
    }
}

/// Whitespace handler that preserves all whitespace exactly as-is.
///
/// Port of `ghidra.util.html.PreservingWhitespaceHandler`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PreservingWhitespaceHandler;

impl WhitespaceHandler for PreservingWhitespaceHandler {
    fn handle_text(&self, text: &str) -> String {
        text.to_string()
    }

    fn handle_whitespace(&self, whitespace: &str) -> String {
        whitespace.to_string()
    }
}

/// An HTML element with tag name, attributes, children, and optional text.
///
/// Port of `ghidra.util.html.HTMLElement`.
#[derive(Debug, Clone)]
pub struct HTMLElement {
    /// The HTML tag name (e.g., "div", "span", "p").
    pub tag: String,
    /// Attributes as key-value pairs.
    pub attributes: Vec<(String, String)>,
    /// Child elements.
    pub children: Vec<HTMLElement>,
    /// Text content (mutually exclusive with children for leaf nodes).
    pub text: Option<String>,
    /// Whether this is a void element (e.g., "br", "hr", "img").
    pub is_void: bool,
}

/// Set of void HTML elements that cannot have children.
const VOID_ELEMENTS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
];

impl HTMLElement {
    /// Create a new HTML element with the given tag.
    pub fn new(tag: impl Into<String>) -> Self {
        let tag = tag.into();
        let is_void = VOID_ELEMENTS.contains(&tag.to_lowercase().as_str());
        Self {
            tag,
            attributes: Vec::new(),
            children: Vec::new(),
            text: None,
            is_void,
        }
    }

    /// Create a text-only element (no tag, just raw text).
    pub fn text(content: impl Into<String>) -> Self {
        Self {
            tag: String::new(),
            attributes: Vec::new(),
            children: Vec::new(),
            text: Some(content.into()),
            is_void: false,
        }
    }

    /// Create a `<br>` element.
    pub fn br() -> Self {
        Self::new("br")
    }

    /// Create an `<hr>` element.
    pub fn hr() -> Self {
        Self::new("hr")
    }

    /// Set an attribute.
    pub fn attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.push((key.into(), value.into()));
        self
    }

    /// Add a child element.
    pub fn child(mut self, child: HTMLElement) -> Self {
        self.children.push(child);
        self
    }

    /// Set text content.
    pub fn with_text(mut self, text: impl Into<String>) -> Self {
        self.text = Some(text.into());
        self
    }

    /// Add a child `<b>` element.
    pub fn bold(self, text: impl Into<String>) -> Self {
        self.child(HTMLElement::new("b").with_text(text))
    }

    /// Add a child `<i>` element.
    pub fn italic(self, text: impl Into<String>) -> Self {
        self.child(HTMLElement::new("i").with_text(text))
    }

    /// Add a child `<u>` element.
    pub fn underline(self, text: impl Into<String>) -> Self {
        self.child(HTMLElement::new("u").with_text(text))
    }

    /// Render this element to an HTML string.
    pub fn to_html(&self) -> String {
        if self.tag.is_empty() {
            // Raw text node
            return self.text.clone().unwrap_or_default();
        }

        let mut result = String::new();
        result.push('<');
        result.push_str(&self.tag);

        for (key, value) in &self.attributes {
            result.push(' ');
            result.push_str(key);
            result.push_str("=\"");
            result.push_str(&escape_attribute(value));
            result.push('"');
        }

        if self.is_void {
            result.push_str(" />");
            return result;
        }

        result.push('>');

        if let Some(text) = &self.text {
            result.push_str(text);
        }

        for child in &self.children {
            result.push_str(&child.to_html());
        }

        result.push_str("</");
        result.push_str(&self.tag);
        result.push('>');

        result
    }
}

impl fmt::Display for HTMLElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_html())
    }
}

/// Escape special characters in HTML attribute values.
fn escape_attribute(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => result.push_str("&amp;"),
            '"' => result.push_str("&quot;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            _ => result.push(ch),
        }
    }
    result
}

/// Splits text into lines for HTML display.
///
/// Port of `ghidra.util.html.HtmlLineSplitter`.
#[derive(Debug, Clone)]
pub struct HtmlLineSplitter {
    /// Maximum line width before wrapping.
    pub max_width: usize,
    /// Whether to preserve existing line breaks.
    pub preserve_line_breaks: bool,
}

impl Default for HtmlLineSplitter {
    fn default() -> Self {
        Self {
            max_width: 80,
            preserve_line_breaks: true,
        }
    }
}

impl HtmlLineSplitter {
    /// Create a new line splitter with the given max width.
    pub fn new(max_width: usize) -> Self {
        Self {
            max_width,
            preserve_line_breaks: true,
        }
    }

    /// Split text into lines, respecting the max width.
    pub fn split(&self, text: &str) -> Vec<String> {
        let mut lines = Vec::new();

        for raw_line in text.split('\n') {
            if raw_line.len() <= self.max_width {
                lines.push(raw_line.to_string());
            } else {
                lines.extend(self.wrap_line(raw_line));
            }
        }

        lines
    }

    /// Wrap a single line to fit within max_width.
    fn wrap_line(&self, line: &str) -> Vec<String> {
        let mut result = Vec::new();
        let mut current = String::new();

        for word in line.split_whitespace() {
            if current.is_empty() {
                current.push_str(word);
            } else if current.len() + 1 + word.len() <= self.max_width {
                current.push(' ');
                current.push_str(word);
            } else {
                result.push(current);
                current = word.to_string();
            }
        }

        if !current.is_empty() {
            result.push(current);
        }

        if result.is_empty() {
            result.push(String::new());
        }

        result
    }

    /// Split text and wrap each line with `<BR>` for HTML output.
    pub fn to_html_lines(&self, text: &str) -> String {
        let lines = self.split(text);
        lines.join("<BR>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_element_basic() {
        let elem = HTMLElement::new("div").with_text("hello");
        assert_eq!(elem.to_html(), "<div>hello</div>");
    }

    #[test]
    fn test_html_element_with_attributes() {
        let elem = HTMLElement::new("a")
            .attr("href", "https://example.com")
            .with_text("link");
        assert_eq!(elem.to_html(), "<a href=\"https://example.com\">link</a>");
    }

    #[test]
    fn test_html_element_nested() {
        let elem = HTMLElement::new("div")
            .child(HTMLElement::new("span").with_text("inner"));
        assert_eq!(elem.to_html(), "<div><span>inner</span></div>");
    }

    #[test]
    fn test_html_element_void() {
        let br = HTMLElement::br();
        assert_eq!(br.to_html(), "<br />");
        let hr = HTMLElement::hr();
        assert_eq!(hr.to_html(), "<hr />");
    }

    #[test]
    fn test_html_element_text_node() {
        let text = HTMLElement::text("raw text");
        assert_eq!(text.to_html(), "raw text");
    }

    #[test]
    fn test_html_element_bold() {
        let elem = HTMLElement::new("p").bold("important");
        assert_eq!(elem.to_html(), "<p><b>important</b></p>");
    }

    #[test]
    fn test_html_element_display() {
        let elem = HTMLElement::new("span").with_text("test");
        assert_eq!(format!("{}", elem), "<span>test</span>");
    }

    #[test]
    fn test_escape_attribute() {
        assert_eq!(escape_attribute("a&b\"c"), "a&amp;b&quot;c");
        assert_eq!(escape_attribute("normal"), "normal");
    }

    #[test]
    fn test_trimming_whitespace_handler() {
        let handler = TrimmingWhitespaceHandler;
        assert_eq!(handler.handle_text("  hello   world  "), "hello world");
        assert_eq!(handler.handle_text("no  extra   spaces"), "no extra spaces");
        assert_eq!(handler.handle_whitespace("\n  "), " ");
    }

    #[test]
    fn test_preserving_whitespace_handler() {
        let handler = PreservingWhitespaceHandler;
        assert_eq!(handler.handle_text("  hello  "), "  hello  ");
        assert_eq!(handler.handle_whitespace("\n  "), "\n  ");
    }

    #[test]
    fn test_html_line_splitter_short() {
        let splitter = HtmlLineSplitter::new(80);
        let lines = splitter.split("short line");
        assert_eq!(lines, vec!["short line"]);
    }

    #[test]
    fn test_html_line_splitter_wrap() {
        let splitter = HtmlLineSplitter::new(20);
        let lines = splitter.split("this is a very long line that should be wrapped");
        assert!(lines.len() > 1);
        for line in &lines {
            assert!(line.len() <= 20);
        }
    }

    #[test]
    fn test_html_line_splitter_multiline() {
        let splitter = HtmlLineSplitter::new(80);
        let lines = splitter.split("line1\nline2\nline3");
        assert_eq!(lines, vec!["line1", "line2", "line3"]);
    }

    #[test]
    fn test_html_line_splitter_to_html() {
        let splitter = HtmlLineSplitter::new(80);
        let html = splitter.to_html_lines("a\nb\nc");
        assert_eq!(html, "a<BR>b<BR>c");
    }

    #[test]
    fn test_html_element_attribute_escape() {
        let elem = HTMLElement::new("img")
            .attr("alt", "a \"quoted\" value & more");
        assert!(elem.to_html().contains("&quot;"));
        assert!(elem.to_html().contains("&amp;"));
    }
}
