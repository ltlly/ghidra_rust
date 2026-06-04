//! HTML utilities for the GUI.
//!
//! Ports `ghidra.util.html` and `ghidra.util.HTMLUtilities` packages.

/// HTML element builder.
#[derive(Debug, Clone)]
pub struct HTMLElement {
    /// The tag name.
    pub tag: String,
    /// Attributes (key/value pairs).
    pub attributes: Vec<(String, String)>,
    /// Child elements or text.
    pub children: Vec<HTMLChild>,
}

/// A child of an HTML element: either a nested element or text.
#[derive(Debug, Clone)]
pub enum HTMLChild {
    /// A nested element.
    Element(HTMLElement),
    /// Raw text content.
    Text(String),
}

impl HTMLElement {
    /// Create a new HTML element.
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            attributes: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Set an attribute.
    pub fn attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.push((key.into(), value.into()));
        self
    }

    /// Add text content.
    pub fn text(mut self, content: impl Into<String>) -> Self {
        self.children.push(HTMLChild::Text(content.into()));
        self
    }

    /// Add a child element.
    pub fn child(mut self, child: HTMLElement) -> Self {
        self.children.push(HTMLChild::Element(child));
        self
    }

    /// Render this element to an HTML string.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push('<');
        out.push_str(&self.tag);
        for (key, value) in &self.attributes {
            out.push(' ');
            out.push_str(key);
            out.push_str("=\"");
            out.push_str(&escape_html_attribute(value));
            out.push('"');
        }
        out.push('>');

        for child in &self.children {
            match child {
                HTMLChild::Text(text) => out.push_str(&escape_html(text)),
                HTMLChild::Element(elem) => out.push_str(&elem.render()),
            }
        }

        out.push_str("</");
        out.push_str(&self.tag);
        out.push('>');
        out
    }
}

/// Common HTML utilities.
pub struct HTMLUtilities;

impl HTMLUtilities {
    /// Wrap text in bold tags.
    pub fn bold(text: &str) -> String {
        format!("<b>{}</b>", escape_html(text))
    }

    /// Wrap text in italic tags.
    pub fn italic(text: &str) -> String {
        format!("<i>{}</i>", escape_html(text))
    }

    /// Wrap text in an anchor tag.
    pub fn link(text: &str, url: &str) -> String {
        format!(
            "<a href=\"{}\">{}</a>",
            escape_html_attribute(url),
            escape_html(text)
        )
    }

    /// Convert plain text to HTML, escaping special characters.
    pub fn to_html(text: &str) -> String {
        escape_html(text).replace('\n', "<br>")
    }

    /// Create an HTML unordered list from items.
    pub fn unordered_list(items: &[&str]) -> String {
        let mut out = String::from("<ul>");
        for item in items {
            out.push_str(&format!("<li>{}</li>", escape_html(item)));
        }
        out.push_str("</ul>");
        out
    }

    /// Convert a color name or hex to an HTML color string.
    pub fn colorize(text: &str, color: &str) -> String {
        format!(
            "<span style=\"color:{}\">{}</span>",
            escape_html_attribute(color),
            escape_html(text)
        )
    }
}

/// Escape special HTML characters in text content.
pub fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

/// Escape special characters in HTML attribute values.
pub fn escape_html_attribute(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Line splitter for HTML content.
pub struct HtmlLineSplitter {
    max_width: usize,
}

impl HtmlLineSplitter {
    /// Create a new line splitter with a maximum width.
    pub fn new(max_width: usize) -> Self {
        Self { max_width }
    }

    /// Split HTML text into lines respecting the maximum width.
    pub fn split(&self, html: &str) -> Vec<String> {
        if html.len() <= self.max_width {
            return vec![html.to_string()];
        }

        let mut lines = Vec::new();
        let mut current = String::new();
        for word in html.split_whitespace() {
            if current.is_empty() {
                current = word.to_string();
            } else if current.len() + 1 + word.len() > self.max_width {
                lines.push(current);
                current = word.to_string();
            } else {
                current.push(' ');
                current.push_str(word);
            }
        }
        if !current.is_empty() {
            lines.push(current);
        }
        lines
    }
}

/// Trait for whitespace handling in HTML parsing.
pub trait WhitespaceHandler {
    /// Process a text fragment, applying whitespace rules.
    fn handle_whitespace(&self, text: &str) -> String;
}

/// A whitespace handler that preserves all whitespace.
#[derive(Debug, Clone, Default)]
pub struct PreservingWhitespaceHandler;

impl WhitespaceHandler for PreservingWhitespaceHandler {
    fn handle_whitespace(&self, text: &str) -> String {
        text.to_string()
    }
}

/// A whitespace handler that trims leading and trailing whitespace.
#[derive(Debug, Clone, Default)]
pub struct TrimmingWhitespaceHandler;

impl WhitespaceHandler for TrimmingWhitespaceHandler {
    fn handle_whitespace(&self, text: &str) -> String {
        text.trim().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_element_basic() {
        let elem = HTMLElement::new("div").text("Hello");
        assert_eq!(elem.render(), "<div>Hello</div>");
    }

    #[test]
    fn html_element_with_attributes() {
        let elem = HTMLElement::new("a")
            .attr("href", "http://example.com")
            .text("Click");
        assert_eq!(elem.render(), "<a href=\"http://example.com\">Click</a>");
    }

    #[test]
    fn html_element_nested() {
        let inner = HTMLElement::new("b").text("bold");
        let outer = HTMLElement::new("p").text("This is ").child(inner);
        assert_eq!(outer.render(), "<p>This is <b>bold</b></p>");
    }

    #[test]
    fn escape_html_special_chars() {
        assert_eq!(escape_html("a < b & c > d"), "a &lt; b &amp; c &gt; d");
    }

    #[test]
    fn escape_attribute() {
        assert_eq!(escape_html_attribute("a\"b"), "a&quot;b");
    }

    #[test]
    fn html_utilities_bold() {
        assert_eq!(HTMLUtilities::bold("test"), "<b>test</b>");
    }

    #[test]
    fn html_utilities_italic() {
        assert_eq!(HTMLUtilities::italic("test"), "<i>test</i>");
    }

    #[test]
    fn html_utilities_link() {
        let link = HTMLUtilities::link("Click", "http://example.com");
        assert_eq!(link, "<a href=\"http://example.com\">Click</a>");
    }

    #[test]
    fn html_utilities_to_html() {
        assert_eq!(HTMLUtilities::to_html("line1\nline2"), "line1<br>line2");
    }

    #[test]
    fn html_utilities_list() {
        let list = HTMLUtilities::unordered_list(&["a", "b", "c"]);
        assert_eq!(list, "<ul><li>a</li><li>b</li><li>c</li></ul>");
    }

    #[test]
    fn html_utilities_colorize() {
        let result = HTMLUtilities::colorize("error", "red");
        assert_eq!(result, "<span style=\"color:red\">error</span>");
    }

    #[test]
    fn line_splitter_short_text() {
        let splitter = HtmlLineSplitter::new(100);
        let lines = splitter.split("short text");
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn line_splitter_long_text() {
        let splitter = HtmlLineSplitter::new(20);
        let lines = splitter.split("this is a fairly long piece of text that should be split");
        assert!(lines.len() > 1);
        for line in &lines {
            assert!(line.len() <= 20);
        }
    }

    #[test]
    fn whitespace_handler_preserving() {
        let handler = PreservingWhitespaceHandler;
        assert_eq!(handler.handle_whitespace("  hello  "), "  hello  ");
    }

    #[test]
    fn whitespace_handler_trimming() {
        let handler = TrimmingWhitespaceHandler;
        assert_eq!(handler.handle_whitespace("  hello  "), "hello");
    }
}
