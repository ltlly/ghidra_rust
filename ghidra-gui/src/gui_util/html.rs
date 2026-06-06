//! HTML text formatting utilities.
//!
//! Ports `ghidra.util.HTMLUtilities` which provides helpers for wrapping
//! text in HTML tags, escaping special characters, and line-wrapping.

use std::fmt::Write as FmtWrite;

/// Default maximum line width for wrapped HTML.
pub const DEFAULT_WRAP_WIDTH: usize = 80;

/// Default maximum line length for wrapped HTML (alias).
pub const DEFAULT_MAX_LINE_LENGTH: usize = 75;

/// Default maximum line length for tooltips.
const DEFAULT_TOOLTIP_MAX_LINE_LENGTH: usize = 100;

/// Maximum tooltip length in characters.
const MAX_TOOLTIP_LENGTH: usize = 2000;

/// Tab size for friendly encoding.
const TAB_SIZE: usize = 4;

/// Lower-case `<html>` tag.
pub const HTML_TAG: &str = "<html>";

/// Lower-case `</html>` tag.
pub const HTML_CLOSE: &str = "</html>";

/// Lower-case `<br>` tag.
pub const BR: &str = "<br>";

/// Non-breaking space entity.
pub const HTML_SPACE: &str = "&nbsp;";

/// Opening link placeholder.
pub const LINK_PLACEHOLDER_OPEN: &str = "<!-- LINK __CONTENT__ -->";

/// Closing link placeholder.
pub const LINK_PLACEHOLDER_CLOSE: &str = "<!-- /LINK -->";

const LINK_PLACEHOLDER_CONTENT: &str = "__CONTENT__";

/// HTML formatting utility functions.
pub struct HtmlUtilities;

impl HtmlUtilities {
    // ========================================================================
    // Basic wrapping
    // ========================================================================

    /// Wrap text in `<html>` tags, replacing newlines with `<br>`.
    pub fn to_html(text: &str) -> String {
        let with_breaks = text.replace('\n', BR);
        let fixed = fixup_html_rendering_issues(&with_breaks);
        format!("<html>{}", fixed)
    }

    /// Wrap text in `<html>` tags with line wrapping at the default width.
    pub fn to_wrapped_html(text: &str) -> String {
        Self::to_wrapped_html_with_width(text, DEFAULT_WRAP_WIDTH)
    }

    /// Wrap text in `<html>` tags with line wrapping at the specified width.
    pub fn to_wrapped_html_with_width(text: &str, width: usize) -> String {
        let wrapped = Self::line_wrap_with_html_line_breaks(text, width);
        if Self::is_html(text) {
            wrapped
        } else {
            let fixed = fixup_html_rendering_issues(&wrapped);
            format!("<html>{}", fixed)
        }
    }

    /// Produce a literal HTML string where all characters are escaped.
    pub fn to_literal_html(text: &str, width: usize) -> String {
        let lines = split_lines(text, width);
        let mut buf = String::with_capacity(text.len() * 2);
        for (i, line) in lines.iter().enumerate() {
            buf.push_str(&Self::friendly_encode_html(line));
            if i + 1 < lines.len() {
                buf.push_str(BR);
                buf.push('\n');
            }
        }
        Self::wrap_as_html(&buf)
    }

    /// Escape embedded HTML, clip to tooltip length, and wrap lines.
    pub fn to_literal_html_for_tooltip(text: &str) -> String {
        let clipped = if text.len() > MAX_TOOLTIP_LENGTH {
            format!("{}...", &text[..MAX_TOOLTIP_LENGTH])
        } else {
            text.to_string()
        };
        Self::to_literal_html(&clipped, DEFAULT_TOOLTIP_MAX_LINE_LENGTH)
    }

    /// Wrap text as HTML (prepend `<html>` tag).
    pub fn wrap_as_html(text: &str) -> String {
        format!("<html>{}", fixup_html_rendering_issues(text))
    }

    // ========================================================================
    // Line wrapping (without <html> prefix)
    // ========================================================================

    /// Replace `\n` with `<br>` (no max length).
    pub fn line_wrap_with_html_line_breaks(text: &str, max_line_length: usize) -> String {
        if Self::is_unbreakable_html(text) {
            return text.to_string();
        }
        let lines = split_lines(text, max_line_length);
        let mut buf = String::with_capacity(text.len() + lines.len() * 8);
        for (n, line) in lines.iter().enumerate() {
            buf.push_str(line);
            if n != lines.len() - 1 {
                buf.push_str(BR);
                buf.push('\n');
            }
        }
        buf
    }

    // ========================================================================
    // HTML detection
    // ========================================================================

    /// Check if a string starts with `<html>` (case-insensitive).
    pub fn is_html(text: &str) -> bool {
        let trimmed = text.trim();
        trimmed.to_lowercase().starts_with("<html>")
    }

    /// Returns `true` if text contains `&nbsp;` without real spaces, or `<br>`.
    pub fn is_unbreakable_html(text: &str) -> bool {
        if text.contains(HTML_SPACE) && !text.contains(' ') {
            return true;
        }
        if text.contains(BR) {
            return true;
        }
        false
    }

    // ========================================================================
    // HTML escaping
    // ========================================================================

    /// Escape HTML special characters.
    pub fn escape_html(text: &str) -> String {
        Self::escape_html_inner(text, false)
    }

    /// Escape HTML special characters; optionally convert spaces to `&nbsp;`.
    pub fn escape_html_with_spaces(text: &str, make_spaces_non_breaking: bool) -> String {
        Self::escape_html_inner(text, make_spaces_non_breaking)
    }

    fn escape_html_inner(text: &str, make_spaces_non_breaking: bool) -> String {
        let mut result = String::with_capacity(text.len() + text.len() / 4);
        for ch in text.chars() {
            match ch {
                ' ' => {
                    if make_spaces_non_breaking {
                        result.push_str(HTML_SPACE);
                    } else {
                        result.push(' ');
                    }
                }
                '&' => result.push_str("&amp;"),
                '<' => result.push_str("&lt;"),
                '>' => result.push_str("&gt;"),
                '"' => result.push_str("&quot;"),
                '\'' => result.push_str("&#39;"),
                _ => {
                    if char_needs_html_escaping(ch as u32) {
                        write!(result, "&#x{:X};", ch as u32).unwrap();
                    } else {
                        result.push(ch);
                    }
                }
            }
        }
        result
    }

    /// Test whether a Unicode code point needs HTML escaping.
    pub fn char_needs_html_escaping(code_point: u32) -> bool {
        if code_point == '\n' as u32
            || code_point == '\t' as u32
            || (' ' as u32 <= code_point && code_point < 0x7F)
        {
            return false;
        }
        true
    }

    /// Friendly-encode HTML: spaces become `&nbsp;`, tabs expand, special chars escaped.
    pub fn friendly_encode_html(text: &str) -> String {
        let mut buf = String::with_capacity(text.len() * 2);
        let mut col: usize = 0;

        for ch in text.chars() {
            match ch {
                '\r' => {
                    col = 0;
                    continue;
                }
                '\n' => {
                    buf.push('\n');
                    col = 0;
                    continue;
                }
                '\t' => {
                    let cnt = TAB_SIZE - (col % TAB_SIZE);
                    for _ in 0..cnt {
                        buf.push_str(HTML_SPACE);
                    }
                    col = 0;
                    continue;
                }
                ' ' => {
                    buf.push_str(HTML_SPACE);
                }
                '&' => buf.push_str("&amp;"),
                '<' => buf.push_str("&lt;"),
                '>' => buf.push_str("&gt;"),
                c if (c as u32) < 0x20 => {
                    continue;
                }
                c if (c as u32) > 0x7F => {
                    write!(buf, "&#x{:X};", c as u32).unwrap();
                }
                c => {
                    buf.push(c);
                }
            }
            col += 1;
        }
        buf
    }

    // ========================================================================
    // Formatting tags
    // ========================================================================

    /// Convert an anchor text to a hyperlink.
    pub fn to_link(url: &str, text: &str) -> String {
        format!(
            "<a href=\"{}\">{}</a>",
            Self::escape_html(url),
            Self::escape_html(text)
        )
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

    /// Wrap a numeric value in `<font color="...">` tags.
    pub fn color_int(color_hex: &str, value: i64) -> String {
        format!("<font color=\"{}\">{}</font>", color_hex, value)
    }

    /// Font sized text.
    pub fn font_size(text: &str, size: i32) -> String {
        format!("<font size=\"{}\">{}</font>", size, text)
    }

    /// Create `num` HTML non-breaking spaces.
    pub fn spaces(num: usize) -> String {
        HTML_SPACE.repeat(num)
    }

    // ========================================================================
    // Hex helpers
    // ========================================================================

    /// Return `#RRGGBB` for the given (r, g, b) components.
    pub fn to_hex_string(r: u8, g: u8, b: u8) -> String {
        format!("#{:02X}{:02X}{:02X}", r, g, b)
    }

    /// Return `rrrgggbbb` padded string.
    pub fn to_rgb_string(r: u8, g: u8, b: u8) -> String {
        format!("{:03}{:03}{:03}", r, g, b)
    }

    // ========================================================================
    // Font/span helpers
    // ========================================================================

    /// Set the font size of text by wrapping in a `<span>` with `font-size`.
    pub fn set_font_size(text: &str, pt_size: u32) -> String {
        let start = if text.to_lowercase().starts_with("<html>") {
            "<html>".len()
        } else {
            0
        };
        let end = if text.to_lowercase().ends_with("</html>") {
            text.len() - "</html>".len()
        } else {
            text.len()
        };
        let mut result = String::with_capacity(text.len() + 64);
        result.push_str(&text[..start]);
        write!(result, "<span style=\"font-size: {}pt\">", pt_size).unwrap();
        result.push_str(&text[start..end]);
        result.push_str("</span>");
        result.push_str(&text[end..]);
        result
    }

    /// Set font size and color by wrapping in a `<span>`.
    pub fn set_font(text: &str, r: u8, g: u8, b: u8, pt_size: u32) -> String {
        let rgb = Self::to_hex_string(r, g, b);
        let start = if text.to_lowercase().starts_with("<html>") {
            "<html>".len()
        } else {
            0
        };
        let end = if text.to_lowercase().ends_with("</html>") {
            text.len() - "</html>".len()
        } else {
            text.len()
        };
        let mut result = String::with_capacity(text.len() + 96);
        result.push_str(&text[..start]);
        write!(
            result,
            "<span style=\"font-size: {}pt; color: {}\">",
            pt_size, rgb
        )
        .unwrap();
        result.push_str(&text[start..end]);
        result.push_str("</span>");
        result.push_str(&text[end..]);
        result
    }

    /// Escape and wrap text in a `<SPAN>` tag with font attributes.
    pub fn style_text(
        text: &str,
        font_family: &str,
        font_size: u32,
        is_italic: bool,
        is_bold: bool,
        color: Option<&str>,
    ) -> String {
        let style = if is_italic { "italic" } else { "normal" };
        let weight = if is_bold { "bold" } else { "normal" };
        let color_css = match color {
            Some(c) => format!("color: {};", c),
            None => String::new(),
        };
        let escaped = Self::escape_html(text);
        format!(
            "<SPAN STYLE=\"{} font-family: '{}'; font-size: {}px; font-style: {}; font-weight: {};\">{}</SPAN>",
            color_css, font_family, font_size, style, weight, escaped
        )
    }

    // ========================================================================
    // Link placeholders
    // ========================================================================

    /// Wrap `html_text` in link-placeholder comment tags with the given content.
    pub fn wrap_with_link_placeholder(html_text: &str, content: &str) -> String {
        let open_tag = LINK_PLACEHOLDER_OPEN.replace(
            LINK_PLACEHOLDER_CONTENT,
            &format!("CONTENT=\"{}\"", content),
        );
        format!("{}{}{}", open_tag, html_text, LINK_PLACEHOLDER_CLOSE)
    }

    /// Convert link-placeholder comment tags to real `<a href="...">` tags.
    pub fn convert_link_placeholders_to_hyperlinks(text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let mut remaining = text;
        while let Some(start) = remaining.find("<!-- LINK CONTENT=\"") {
            result.push_str(&remaining[..start]);
            let after_open = &remaining[start + "<!-- LINK CONTENT=\"".len()..];
            if let Some(end_quote) = after_open.find('"') {
                let content_val = &after_open[..end_quote];
                let escaped = content_val.replace('$', "\\$");
                write!(result, "<a href=\"{}\">", escaped).unwrap();
                let after_tag = &after_open[end_quote + 1..];
                if let Some(close_end) = after_tag.find("-->") {
                    remaining = &after_tag[close_end + 3..];
                } else {
                    remaining = after_tag;
                }
            } else {
                remaining = after_open;
            }
        }
        result.push_str(remaining);
        result.replace(LINK_PLACEHOLDER_CLOSE, "</a>")
    }

    // ========================================================================
    // Strip HTML
    // ========================================================================

    /// Strip all HTML tags from a string.
    pub fn strip_html(text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let mut in_tag = false;
        for ch in text.chars() {
            match ch {
                '<' => in_tag = true,
                '>' => in_tag = false,
                _ if !in_tag => {
                    if ch as u32 == 0xA0 {
                        result.push(' ');
                    } else {
                        result.push(ch);
                    }
                }
                _ => {}
            }
        }
        result
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn fixup_html_rendering_issues(text: &str) -> String {
    if text.starts_with('/') {
        let mut s = String::with_capacity(HTML_SPACE.len() + text.len());
        s.push_str(HTML_SPACE);
        s.push_str(text);
        s
    } else {
        text.to_string()
    }
}

fn char_needs_html_escaping(code_point: u32) -> bool {
    if code_point == '\n' as u32
        || code_point == '\t' as u32
        || (' ' as u32 <= code_point && code_point < 0x7F)
    {
        return false;
    }
    true
}

fn split_lines(text: &str, max_line_length: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for raw_line in text.split('\n') {
        if max_line_length == 0 || raw_line.len() <= max_line_length {
            lines.push(raw_line.to_string());
        } else {
            let mut remaining = raw_line;
            while remaining.len() > max_line_length {
                let mut break_at = max_line_length;
                if let Some(space_pos) = remaining[..max_line_length].rfind(' ') {
                    break_at = space_pos + 1;
                }
                lines.push(remaining[..break_at].to_string());
                remaining = &remaining[break_at..];
            }
            if !remaining.is_empty() {
                lines.push(remaining.to_string());
            }
        }
    }
    lines
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_html() {
        assert_eq!(
            HtmlUtilities::to_html("hello\nworld"),
            "<html>hello<br>world"
        );
    }

    #[test]
    fn test_escape_html() {
        assert_eq!(
            HtmlUtilities::escape_html("<b>&\"test\"</b>"),
            "&lt;b&gt;&amp;&quot;test&quot;&lt;/b&gt;"
        );
    }

    #[test]
    fn test_escape_html_with_spaces() {
        assert_eq!(
            HtmlUtilities::escape_html_with_spaces("a b", true),
            "a&nbsp;b"
        );
    }

    #[test]
    fn test_to_link() {
        assert_eq!(
            HtmlUtilities::to_link("http://example.com", "Click"),
            "<a href=\"http://example.com\">Click</a>"
        );
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
    fn test_underline() {
        assert_eq!(HtmlUtilities::underline("hi"), "<u>hi</u>");
    }

    #[test]
    fn test_color() {
        assert_eq!(
            HtmlUtilities::color("red", "#FF0000"),
            "<font color=\"#FF0000\">red</font>"
        );
    }

    #[test]
    fn test_color_int() {
        assert_eq!(
            HtmlUtilities::color_int("#00FF00", 42),
            "<font color=\"#00FF00\">42</font>"
        );
    }

    #[test]
    fn test_font_size() {
        assert_eq!(
            HtmlUtilities::font_size("big", 5),
            "<font size=\"5\">big</font>"
        );
    }

    #[test]
    fn test_spaces() {
        assert_eq!(HtmlUtilities::spaces(0), "");
        assert_eq!(HtmlUtilities::spaces(1), "&nbsp;");
        assert_eq!(HtmlUtilities::spaces(3), "&nbsp;&nbsp;&nbsp;");
    }

    #[test]
    fn test_strip_html() {
        assert_eq!(
            HtmlUtilities::strip_html("<b>hello</b> <i>world</i>"),
            "hello world"
        );
    }

    #[test]
    fn test_is_html() {
        assert!(HtmlUtilities::is_html("<HTML>test"));
        assert!(HtmlUtilities::is_html("<html>test"));
        assert!(!HtmlUtilities::is_html("plain text"));
    }

    #[test]
    fn test_is_unbreakable_html() {
        assert!(HtmlUtilities::is_unbreakable_html("foo&nbsp;bar"));
        assert!(HtmlUtilities::is_unbreakable_html("foo<br>bar"));
        assert!(!HtmlUtilities::is_unbreakable_html("foo bar"));
    }

    #[test]
    fn test_wrap_lines() {
        let text = "This is a very long line that should be wrapped at word boundaries";
        let wrapped = split_lines(text, 30);
        assert!(wrapped.len() > 1);
    }

    #[test]
    fn test_to_wrapped_html() {
        let html = HtmlUtilities::to_wrapped_html("short text");
        assert!(html.starts_with("<html>"));
    }

    #[test]
    fn test_to_wrapped_html_with_wrap() {
        let long_text = "a".repeat(200);
        let result = HtmlUtilities::to_wrapped_html_with_width(&long_text, 50);
        assert!(result.starts_with("<html>"));
    }

    #[test]
    fn test_to_literal_html() {
        let result = HtmlUtilities::to_literal_html("a < b", 0);
        assert!(result.contains("&lt;"));
        assert!(result.starts_with("<html>"));
    }

    #[test]
    fn test_to_literal_html_for_tooltip() {
        let result = HtmlUtilities::to_literal_html_for_tooltip("test <b>bold</b>");
        assert!(result.contains("&lt;b&gt;"));
        assert!(result.starts_with("<html>"));
    }

    #[test]
    fn test_to_literal_html_for_tooltip_long() {
        let long_text = "x".repeat(3000);
        let result = HtmlUtilities::to_literal_html_for_tooltip(&long_text);
        assert!(result.contains("..."));
    }

    #[test]
    fn test_line_wrap_with_html_line_breaks() {
        let result = HtmlUtilities::line_wrap_with_html_line_breaks("a\nb", 0);
        assert!(result.contains("<br>"));
        assert!(!result.starts_with("<html>"));
    }

    #[test]
    fn test_to_hex_string() {
        assert_eq!(HtmlUtilities::to_hex_string(255, 0, 0), "#FF0000");
        assert_eq!(HtmlUtilities::to_hex_string(0, 0, 0), "#000000");
    }

    #[test]
    fn test_to_rgb_string() {
        assert_eq!(HtmlUtilities::to_rgb_string(255, 0, 0), "255000000");
    }

    #[test]
    fn test_set_font_size() {
        let result = HtmlUtilities::set_font_size("text", 14);
        assert!(result.contains("font-size: 14pt"));
    }

    #[test]
    fn test_set_font_size_with_html() {
        let result = HtmlUtilities::set_font_size("<html>text</html>", 14);
        assert!(result.starts_with("<html>"));
        assert!(result.ends_with("</html>"));
    }

    #[test]
    fn test_set_font() {
        let result = HtmlUtilities::set_font("text", 255, 0, 0, 16);
        assert!(result.contains("#FF0000"));
        assert!(result.contains("font-size: 16pt"));
    }

    #[test]
    fn test_style_text() {
        let result = HtmlUtilities::style_text("hello", "Monospace", 14, true, false, Some("#FF0000"));
        assert!(result.contains("Monospace"));
        assert!(result.contains("14px"));
        assert!(result.contains("italic"));
        assert!(result.contains("#FF0000"));
    }

    #[test]
    fn test_style_text_no_color() {
        let result = HtmlUtilities::style_text("hello", "Sans", 12, false, true, None);
        assert!(result.contains("bold"));
        assert!(!result.contains("color:"));
    }

    #[test]
    fn test_friendly_encode_html() {
        let result = HtmlUtilities::friendly_encode_html("a < b");
        assert!(result.contains("&lt;"));
        assert!(result.contains("&nbsp;"));
    }

    #[test]
    fn test_friendly_encode_html_tab() {
        let result = HtmlUtilities::friendly_encode_html("\thello");
        assert!(result.starts_with("&nbsp;"));
    }

    #[test]
    fn test_char_needs_html_escaping() {
        assert!(!char_needs_html_escaping('a' as u32));
        assert!(!char_needs_html_escaping(' ' as u32));
        assert!(!char_needs_html_escaping('\n' as u32));
        assert!(char_needs_html_escaping(0xA0));
    }

    #[test]
    fn test_link_placeholders() {
        let wrapped =
            HtmlUtilities::wrap_with_link_placeholder("click here", "http://example.com");
        assert!(wrapped.contains("CONTENT=\"http://example.com\""));
        assert!(wrapped.contains("click here"));

        let converted = HtmlUtilities::convert_link_placeholders_to_hyperlinks(&wrapped);
        assert!(converted.contains("<a href=\"http://example.com\">"));
        assert!(converted.contains("</a>"));
        assert!(converted.contains("click here"));
    }

    #[test]
    fn test_to_html_leading_slash() {
        let result = HtmlUtilities::to_html("/foo");
        assert!(result.contains("&nbsp;"));
        assert!(result.contains("/foo"));
    }

    #[test]
    fn test_constants() {
        assert_eq!(HTML_TAG, "<html>");
        assert_eq!(HTML_CLOSE, "</html>");
        assert_eq!(BR, "<br>");
        assert_eq!(HTML_SPACE, "&nbsp;");
    }
}
