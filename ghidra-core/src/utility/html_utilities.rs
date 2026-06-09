//! HTML generation and escaping utilities.
//!
//! Port of `ghidra.util.HTMLUtilities`.

/// HTML utility functions.
///
/// Port of `ghidra.util.HTMLUtilities`.
pub struct HTMLUtilities;

impl HTMLUtilities {
    /// Escape a string for safe inclusion in HTML.
    ///
    /// Replaces `&`, `<`, `>`, `"`, and `'` with their HTML entity equivalents.
    pub fn escape_html(s: &str) -> String {
        let mut result = String::with_capacity(s.len() + s.len() / 4);
        for c in s.chars() {
            match c {
                '&' => result.push_str("&amp;"),
                '<' => result.push_str("&lt;"),
                '>' => result.push_str("&gt;"),
                '"' => result.push_str("&quot;"),
                '\'' => result.push_str("&#39;"),
                _ => result.push(c),
            }
        }
        result
    }

    /// Unescape HTML entities in a string.
    ///
    /// Handles `&amp;`, `&lt;`, `&gt;`, `&quot;`, `&#39;`, and numeric character references (`&#NNN;`).
    pub fn unescape_html(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '&' {
                // Collect until ';'
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
                    "apos" | "#39" => result.push('\''),
                    e if e.starts_with('#') => {
                        // Numeric character reference: &#NNN; or &#xHHH;
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

    /// Wrap text in an HTML anchor tag (`<a href="...">...</a>`).
    pub fn anchor_tag(href: &str, text: &str) -> String {
        format!(
            "<a href=\"{}\">{}</a>",
            Self::escape_html(href),
            Self::escape_html(text)
        )
    }

    /// Wrap text in an HTML bold tag.
    pub fn bold(text: &str) -> String {
        format!("<b>{}</b>", text)
    }

    /// Wrap text in an HTML italic tag.
    pub fn italic(text: &str) -> String {
        format!("<i>{}</i>", text)
    }

    /// Wrap text in an HTML code tag.
    pub fn code(text: &str) -> String {
        format!("<code>{}</code>", text)
    }

    /// Wrap text in a `<pre>` tag.
    pub fn pre(text: &str) -> String {
        format!("<pre>{}</pre>", text)
    }

    /// Create a paragraph tag.
    pub fn paragraph(text: &str) -> String {
        format!("<p>{}</p>", text)
    }

    /// Create an unordered list from items.
    pub fn unordered_list(items: &[&str]) -> String {
        let mut result = String::from("<ul>\n");
        for item in items {
            result.push_str(&format!("  <li>{}</li>\n", item));
        }
        result.push_str("</ul>");
        result
    }

    /// Create an ordered list from items.
    pub fn ordered_list(items: &[&str]) -> String {
        let mut result = String::from("<ol>\n");
        for item in items {
            result.push_str(&format!("  <li>{}</li>\n", item));
        }
        result.push_str("</ol>");
        result
    }

    /// Create a simple HTML table from rows of strings.
    pub fn table(rows: &[Vec<&str>]) -> String {
        let mut result = String::from("<table>\n");
        for (i, row) in rows.iter().enumerate() {
            result.push_str("  <tr>\n");
            let tag = if i == 0 { "th" } else { "td" };
            for cell in row {
                result.push_str(&format!("    <{}>{}</{}>\n", tag, cell, tag));
            }
            result.push_str("  </tr>\n");
        }
        result.push_str("</table>");
        result
    }

    /// Wrap content in a `<span>` tag with a CSS style.
    pub fn span_with_style(text: &str, style: &str) -> String {
        format!("<span style=\"{}\">{}</span>", style, text)
    }

    /// Create colored text using a `<span>` with `color` CSS.
    pub fn colored_text(text: &str, color: &str) -> String {
        Self::span_with_style(text, &format!("color: {}", color))
    }

    /// Convert plain text to HTML by escaping and converting newlines to `<br>`.
    pub fn to_html(text: &str) -> String {
        Self::escape_html(text).replace('\n', "<br>\n")
    }

    /// Strip all HTML tags from a string, returning plain text.
    pub fn strip_tags(html: &str) -> String {
        let mut result = String::with_capacity(html.len());
        let mut in_tag = false;
        let mut in_entity = false;
        let mut entity_buf = String::new();

        for c in html.chars() {
            if c == '<' {
                in_tag = true;
                continue;
            }
            if c == '>' && in_tag {
                in_tag = false;
                continue;
            }
            if in_tag {
                continue;
            }
            if c == '&' {
                in_entity = true;
                entity_buf.clear();
                entity_buf.push(c);
                continue;
            }
            if in_entity {
                entity_buf.push(c);
                if c == ';' {
                    in_entity = false;
                    result.push_str(&Self::unescape_html(&entity_buf));
                }
                continue;
            }
            result.push(c);
        }
        // Handle incomplete entity
        if in_entity {
            result.push_str(&entity_buf);
        }
        result
    }

    /// Build a tooltip-compatible HTML string for Ghidra's display.
    ///
    /// Wraps the text in `<html>` with a basic style.
    pub fn tooltip(text: &str) -> String {
        format!(
            "<html><head><style>body {{ font-family: sans-serif; font-size: 12px; }}</style></head><body>{}</body></html>",
            text
        )
    }
}

/// An HTML builder for constructing HTML documents programmatically.
#[derive(Debug, Default)]
pub struct HtmlBuilder {
    buf: String,
}

impl HtmlBuilder {
    /// Create a new HTML builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start an HTML document with a doctype and opening `<html>` tag.
    pub fn start_document(&mut self) -> &mut Self {
        self.buf.push_str("<!DOCTYPE html>\n<html>\n");
        self
    }

    /// Close the HTML document.
    pub fn end_document(&mut self) -> &mut Self {
        self.buf.push_str("</html>\n");
        self
    }

    /// Add a `<head>` section with a title.
    pub fn head(&mut self, title: &str) -> &mut Self {
        self.buf.push_str(&format!(
            "<head>\n  <title>{}</title>\n</head>\n",
            HTMLUtilities::escape_html(title)
        ));
        self
    }

    /// Open a `<body>` tag.
    pub fn start_body(&mut self) -> &mut Self {
        self.buf.push_str("<body>\n");
        self
    }

    /// Close the `<body>` tag.
    pub fn end_body(&mut self) -> &mut Self {
        self.buf.push_str("</body>\n");
        self
    }

    /// Add a heading.
    pub fn heading(&mut self, level: u8, text: &str) -> &mut Self {
        let tag = format!("h{}", level.min(6));
        self.buf.push_str(&format!("<{}>{}</{}>\n", tag, HTMLUtilities::escape_html(text), tag));
        self
    }

    /// Add raw HTML content.
    pub fn raw(&mut self, html: &str) -> &mut Self {
        self.buf.push_str(html);
        self.buf.push('\n');
        self
    }

    /// Add escaped text.
    pub fn text(&mut self, text: &str) -> &mut Self {
        self.buf.push_str(&HTMLUtilities::escape_html(text));
        self
    }

    /// Add a paragraph.
    pub fn paragraph(&mut self, text: &str) -> &mut Self {
        self.buf.push_str(&HTMLUtilities::paragraph(text));
        self.buf.push('\n');
        self
    }

    /// Consume the builder and return the HTML string.
    pub fn build(self) -> String {
        self.buf
    }
}

impl std::fmt::Display for HtmlBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_html() {
        assert_eq!(
            HTMLUtilities::escape_html("<b>\"hello\" & 'world'</b>"),
            "&lt;b&gt;&quot;hello&quot; &amp; &#39;world&#39;&lt;/b&gt;"
        );
    }

    #[test]
    fn test_unescape_html() {
        assert_eq!(
            HTMLUtilities::unescape_html("&lt;b&gt;hello&lt;/b&gt;"),
            "<b>hello</b>"
        );
        assert_eq!(HTMLUtilities::unescape_html("&amp;"), "&");
        assert_eq!(HTMLUtilities::unescape_html("&#65;"), "A");
        assert_eq!(HTMLUtilities::unescape_html("&#x41;"), "A");
    }

    #[test]
    fn test_escape_unescape_roundtrip() {
        let original = "<script>alert(\"xss\") & 'hack'</script>";
        let escaped = HTMLUtilities::escape_html(original);
        let unescaped = HTMLUtilities::unescape_html(&escaped);
        assert_eq!(unescaped, original);
    }

    #[test]
    fn test_html_tags() {
        assert_eq!(HTMLUtilities::bold("hi"), "<b>hi</b>");
        assert_eq!(HTMLUtilities::italic("hi"), "<i>hi</i>");
        assert_eq!(HTMLUtilities::code("x"), "<code>x</code>");
        assert_eq!(HTMLUtilities::pre("block"), "<pre>block</pre>");
    }

    #[test]
    fn test_anchor_tag() {
        let a = HTMLUtilities::anchor_tag("https://example.com?a=1&b=2", "Click");
        assert!(a.contains("href=\"https://example.com?a=1&amp;b=2\""));
        assert!(a.contains(">Click</a>"));
    }

    #[test]
    fn test_lists() {
        let ul = HTMLUtilities::unordered_list(&["a", "b", "c"]);
        assert!(ul.contains("<ul>"));
        assert!(ul.contains("<li>a</li>"));

        let ol = HTMLUtilities::ordered_list(&["x", "y"]);
        assert!(ol.contains("<ol>"));
    }

    #[test]
    fn test_table() {
        let t = HTMLUtilities::table(&[vec!["Name", "Age"], vec!["Alice", "30"]]);
        assert!(t.contains("<th>Name</th>"));
        assert!(t.contains("<td>Alice</td>"));
    }

    #[test]
    fn test_colored_text() {
        let ct = HTMLUtilities::colored_text("hello", "red");
        assert_eq!(ct, "<span style=\"color: red\">hello</span>");
    }

    #[test]
    fn test_to_html() {
        assert_eq!(
            HTMLUtilities::to_html("line1\nline2"),
            "line1<br>\nline2"
        );
    }

    #[test]
    fn test_strip_tags() {
        assert_eq!(
            HTMLUtilities::strip_tags("<b>hello</b> <i>world</i>"),
            "hello world"
        );
        assert_eq!(
            HTMLUtilities::strip_tags("&lt;escaped&gt;"),
            "<escaped>"
        );
    }

    #[test]
    fn test_html_builder() {
        let mut b = HtmlBuilder::new();
        b.start_document()
            .head("Test Page")
            .start_body()
            .heading(1, "Hello")
            .paragraph("World")
            .end_body()
            .end_document();
        let html = b.build();
        assert!(html.contains("<title>Test Page</title>"));
        assert!(html.contains("<h1>Hello</h1>"));
        assert!(html.contains("<p>World</p>"));
    }

    #[test]
    fn test_tooltip() {
        let tt = HTMLUtilities::tooltip("some info");
        assert!(tt.starts_with("<html>"));
        assert!(tt.contains("some info"));
    }
}
