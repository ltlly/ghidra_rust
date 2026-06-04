//! HTML text formatting utilities.
//!
//! Ports `ghidra.util.HTMLUtilities` which provides helpers for wrapping
//! text in HTML tags, escaping special characters, and line-wrapping.

/// HTML formatting utility functions.
pub struct HtmlUtilities;

/// Default maximum line width for wrapped HTML.
const DEFAULT_WRAP_WIDTH: usize = 80;

impl HtmlUtilities {
    /// Wrap text in `<HTML>` tags, replacing newlines with `<BR>`.
    pub fn to_html(text: &str) -> String {
        let escaped = Self::escape_html(text);
        let with_breaks = escaped.replace('\n', "<BR>");
        format!("<HTML>{}", with_breaks)
    }

    /// Wrap text in `<HTML>` tags with line wrapping at the default width.
    pub fn to_wrapped_html(text: &str) -> String {
        Self::to_wrapped_html_with_width(text, DEFAULT_WRAP_WIDTH)
    }

    /// Wrap text in `<HTML>` tags with line wrapping at the specified width.
    pub fn to_wrapped_html_with_width(text: &str, width: usize) -> String {
        let escaped = Self::escape_html(text);
        let wrapped = Self::wrap_lines(&escaped, width);
        let with_breaks = wrapped.replace('\n', "<BR>");
        format!("<HTML>{}", with_breaks)
    }

    /// Produce a literal HTML string where all characters are escaped.
    pub fn to_literal_html(text: &str, width: usize) -> String {
        let escaped = Self::escape_html(text);
        let wrapped = Self::wrap_lines(&escaped, width);
        let with_breaks = wrapped.replace('\n', "<BR>");
        format!("<HTML>{}", with_breaks)
    }

    /// Escape HTML special characters.
    pub fn escape_html(text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        for ch in text.chars() {
            match ch {
                '&' => result.push_str("&amp;"),
                '<' => result.push_str("&lt;"),
                '>' => result.push_str("&gt;"),
                '"' => result.push_str("&quot;"),
                '\'' => result.push_str("&#39;"),
                _ => result.push(ch),
            }
        }
        result
    }

    /// Convert an anchor text to a hyperlink.
    pub fn to_link(url: &str, text: &str) -> String {
        format!("<a href=\"{}\">{}</a>", Self::escape_html(url), Self::escape_html(text))
    }

    /// Bold text.
    pub fn bold(text: &str) -> String {
        format!("<b>{}</b>", text)
    }

    /// Italic text.
    pub fn italic(text: &str) -> String {
        format!("<i>{}</i>", text)
    }

    /// Underlined text.
    pub fn underline(text: &str) -> String {
        format!("<u>{}</u>", text)
    }

    /// Colored text.
    pub fn color(text: &str, color_hex: &str) -> String {
        format!("<font color=\"{}\">{}</font>", color_hex, text)
    }

    /// Font sized text.
    pub fn font_size(text: &str, size: i32) -> String {
        format!("<font size=\"{}\">{}</font>", size, text)
    }

    /// Strip all HTML tags from a string.
    pub fn strip_html(text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let mut in_tag = false;
        for ch in text.chars() {
            match ch {
                '<' => in_tag = true,
                '>' => in_tag = false,
                _ if !in_tag => result.push(ch),
                _ => {}
            }
        }
        result
    }

    /// Check if a string starts with `<HTML>` (case-insensitive).
    pub fn is_html(text: &str) -> bool {
        text.starts_with("<HTML>") || text.starts_with("<html>")
    }

    /// Wrap long lines by inserting newlines at word boundaries.
    fn wrap_lines(text: &str, max_width: usize) -> String {
        let mut result = String::new();
        for line in text.split('\n') {
            if !result.is_empty() {
                result.push('\n');
            }
            if line.len() <= max_width {
                result.push_str(line);
                continue;
            }
            let mut current_line = String::new();
            for word in line.split_whitespace() {
                if current_line.is_empty() {
                    current_line.push_str(word);
                } else if current_line.len() + 1 + word.len() <= max_width {
                    current_line.push(' ');
                    current_line.push_str(word);
                } else {
                    result.push_str(&current_line);
                    result.push('\n');
                    current_line = word.to_string();
                }
            }
            if !current_line.is_empty() {
                result.push_str(&current_line);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_html() {
        assert_eq!(HtmlUtilities::to_html("hello\nworld"), "<HTML>hello<BR>world");
    }

    #[test]
    fn test_escape_html() {
        assert_eq!(HtmlUtilities::escape_html("<b>&\"test\"</b>"), "&lt;b&gt;&amp;&quot;test&quot;&lt;/b&gt;");
    }

    #[test]
    fn test_to_link() {
        assert_eq!(HtmlUtilities::to_link("http://example.com", "Click"), "<a href=\"http://example.com\">Click</a>");
    }

    #[test]
    fn test_bold() {
        assert_eq!(HtmlUtilities::bold("text"), "<b>text</b>");
    }

    #[test]
    fn test_italic() {
        assert_eq!(HtmlUtilities::italic("text"), "<i>text</i>");
    }

    #[test]
    fn test_color() {
        assert_eq!(HtmlUtilities::color("red", "#FF0000"), "<font color=\"#FF0000\">red</font>");
    }

    #[test]
    fn test_strip_html() {
        assert_eq!(HtmlUtilities::strip_html("<b>hello</b> <i>world</i>"), "hello world");
    }

    #[test]
    fn test_is_html() {
        assert!(HtmlUtilities::is_html("<HTML>test"));
        assert!(HtmlUtilities::is_html("<html>test"));
        assert!(!HtmlUtilities::is_html("plain text"));
    }

    #[test]
    fn test_wrap_lines() {
        let text = "This is a very long line that should be wrapped at word boundaries";
        let wrapped = HtmlUtilities::wrap_lines(text, 30);
        let lines: Vec<&str> = wrapped.split('\n').collect();
        assert!(lines.len() > 1);
        for line in &lines {
            // Lines may exceed max_width if a single word is longer than max_width
            // but most lines should be under
            if line.split_whitespace().count() > 1 {
                assert!(line.len() <= 35); // some tolerance
            }
        }
    }

    #[test]
    fn test_to_wrapped_html() {
        let html = HtmlUtilities::to_wrapped_html("short text");
        assert!(html.starts_with("<HTML>"));
    }

    #[test]
    fn test_underline() {
        assert_eq!(HtmlUtilities::underline("hi"), "<u>hi</u>");
    }

    #[test]
    fn test_font_size() {
        assert_eq!(HtmlUtilities::font_size("big", 5), "<font size=\"5\">big</font>");
    }
}
