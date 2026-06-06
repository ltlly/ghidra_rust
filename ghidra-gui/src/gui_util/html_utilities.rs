//! Port of `ghidra.util.HTMLUtilities` (930 lines Java -> ~500 lines Rust).
//!
//! A helper struct providing static methods for formatting text with common HTML tags.
//!
//! # Usage Categories
//!
//! | Use Case | Method | Description |
//! |----------|--------|-------------|
//! | Simple text as HTML | [`HTMLUtilities::to_html`] | Replaces `\n` with `<br>`, prepends `<html>` |
//! | Wrapped text | [`HTMLUtilities::to_wrapped_html`] | Same as `to_html` plus length-based wrapping |
//! | Escaped dynamic content | [`HTMLUtilities::to_literal_html`] | Escapes embedded HTML, wraps lines |
//! | Tooltip text | [`HTMLUtilities::to_literal_html_for_tooltip`] | Like `to_literal_html` with tooltip limits |
//! | Newline to `<br>` | [`HTMLUtilities::line_wrap_with_html_line_breaks`] | Converts newlines without adding `<html>` |

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;

/// Default maximum line length for wrapped HTML.
pub const DEFAULT_MAX_LINE_LENGTH: usize = 75;

/// Default maximum line length for tooltips.
const DEFAULT_TOOLTIP_MAX_LINE_LENGTH: usize = 100;

/// Maximum tooltip length in characters.
const MAX_TOOLTIP_LENGTH: usize = 2000;

/// Tab size for friendly encoding.
const TAB_SIZE: usize = 4;

/// Lower-case `<html>` tag.
pub const HTML: &str = "<html>";

/// Lower-case `</html>` tag.
pub const HTML_CLOSE: &str = "</html>";

/// Lower-case `<br>` tag.
pub const BR: &str = "<br>";

/// `<pre>` tag.
pub const PRE: &str = "<pre>";

/// `</pre>` tag.
pub const PRE_CLOSE: &str = "</pre>";

/// Non-breaking space entity.
pub const HTML_SPACE: &str = "&nbsp;";

/// Alias for HTML new line (`<br>`).
pub const HTML_NEW_LINE: &str = BR;

/// Opening comment tag for link placeholders.
const LINK_PLACEHOLDER_CONTENT: &str = "__CONTENT__";

/// Opening link placeholder (with `__CONTENT__` to be replaced).
pub const LINK_PLACEHOLDER_OPEN: &str = "<!-- LINK __CONTENT__ -->";

/// Closing link placeholder.
pub const LINK_PLACEHOLDER_CLOSE: &str = "<!-- /LINK -->";

// ============================================================================
// HTMLUtilities -- all methods are free functions (the Java class is static-only)
// ============================================================================

/// Wrap text as HTML. Prepends `<html>` and fixes rendering issues.
///
/// Ports `HTMLUtilities.wrapAsHTML(String)`.
pub fn wrap_as_html(text: &str) -> String {
    let mut s = String::with_capacity(HTML.len() + text.len() + 8);
    s.push_str(HTML);
    s.push_str(&fixup_html_rendering_issues(text));
    s
}

/// Fixup: prepend `&nbsp;` if text starts with `/`.
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

// ============================================================================
// Color helpers
// ============================================================================

/// Return `#RRGGBB` for the given (r, g, b) components.
///
/// Ports `HTMLUtilities.toHexString(Color)`.
pub fn to_hex_string(r: u8, g: u8, b: u8) -> String {
    format!("#{:02X}{:02X}{:02X}", r, g, b)
}

/// Return `rrrgggbbb` padded string.
///
/// Ports `HTMLUtilities.toRGBString(Color)`.
pub fn to_rgb_string(r: u8, g: u8, b: u8) -> String {
    format!("{:03}{:03}{:03}", r, g, b)
}

/// Wrap `text` in `<font color="...">` tags using a hex color string.
///
/// Ports `HTMLUtilities.colorString(String rgbColor, String text)`.
pub fn color_string(rgb_color: &str, text: &str) -> String {
    format!("<font color=\"{}\">{}</font>", rgb_color, text)
}

/// Wrap a numeric value in `<font color="...">` tags.
///
/// Ports `HTMLUtilities.colorString(String rgbColor, int value)`.
pub fn color_string_int(rgb_color: &str, value: i64) -> String {
    format!("<font color=\"{}\">{}</font>", rgb_color, value)
}

/// Create `num` HTML non-breaking spaces.
///
/// Ports `HTMLUtilities.spaces(int)`.
pub fn spaces(num: usize) -> String {
    HTML_SPACE.repeat(num)
}

// ============================================================================
// Formatting tags
// ============================================================================

/// Surround text with `<b>` tags.
///
/// Ports `HTMLUtilities.bold(String)`.
pub fn bold(text: &str) -> String {
    format!("<b>{}</b>", text)
}

/// Surround text with `<u>` tags.
///
/// Ports `HTMLUtilities.underline(String)`.
pub fn underline(text: &str) -> String {
    format!("<u>{}</u>", text)
}

/// Surround text with `<i>` tags.
///
/// Ports `HTMLUtilities.italic(String)`.
pub fn italic(text: &str) -> String {
    format!("<i>{}</i>", text)
}

// ============================================================================
// HTML detection
// ============================================================================

/// Returns `true` if `text` starts with `<html>` (case-insensitive).
///
/// Ports `HTMLUtilities.isHTML(String)`.
pub fn is_html(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.to_lowercase().starts_with("<html>")
}

/// Returns `true` if the text cannot be broken into lines due to
/// `&nbsp;` or `<br>` usage.
///
/// Ports `HTMLUtilities.isUnbreakableHTML(String)`.
pub fn is_unbreakable_html(text: &str) -> bool {
    if text.contains(HTML_SPACE) && !text.contains(' ') {
        return true;
    }
    if text.contains(HTML_NEW_LINE) {
        return true;
    }
    false
}

// ============================================================================
// Font / span helpers
// ============================================================================

/// Set the font size of text by wrapping in a `<span>` with `font-size`.
///
/// Ports `HTMLUtilities.setFontSize(String, int)`.
pub fn set_font_size(text: &str, pt_size: u32) -> String {
    let start = if text.to_lowercase().starts_with(HTML) {
        HTML.len()
    } else {
        0
    };

    let end = if text.to_lowercase().ends_with(HTML_CLOSE) {
        text.len() - HTML_CLOSE.len()
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
///
/// Ports `HTMLUtilities.setFont(String, Color, int)`.
pub fn set_font(text: &str, r: u8, g: u8, b: u8, pt_size: u32) -> String {
    let rgb = to_hex_string(r, g, b);
    let start = if text.to_lowercase().starts_with(HTML) {
        HTML.len()
    } else {
        0
    };

    let end = if text.to_lowercase().ends_with(HTML_CLOSE) {
        text.len() - HTML_CLOSE.len()
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

// ============================================================================
// Link placeholders
// ============================================================================

/// Wrap `html_text` in link-placeholder comment tags with the given content.
///
/// Ports `HTMLUtilities.wrapWithLinkPlaceholder(String, String)`.
pub fn wrap_with_link_placeholder(html_text: &str, content: &str) -> String {
    let open_tag = LINK_PLACEHOLDER_OPEN.replace(LINK_PLACEHOLDER_CONTENT, &format!("CONTENT=\"{}\"", content));
    format!("{}{}{}", open_tag, html_text, LINK_PLACEHOLDER_CLOSE)
}

/// Convert link-placeholder comment tags to real `<a href="...">` tags.
///
/// Ports `HTMLUtilities.convertLinkPlaceholdersToHyperlinks(String)`.
pub fn convert_link_placeholders_to_hyperlinks(text: &str) -> String {
    // Pattern: <!-- LINK CONTENT="..." -->
    let mut result = String::with_capacity(text.len());
    let mut remaining = text;

    while let Some(start) = remaining.find("<!-- LINK CONTENT=\"") {
        result.push_str(&remaining[..start]);
        let after_open = &remaining[start + "<!-- LINK CONTENT=\"".len()..];
        if let Some(end_quote) = after_open.find('"') {
            let content_val = &after_open[..end_quote];
            let escaped = content_val.replace('$', "\\$");
            write!(result, "<a href=\"{}\">", escaped).unwrap();
            let after_tag = &after_open[end_quote + 1..]; // skip closing "
            if let Some(close_end) = after_tag.find("-->") {
                remaining = &after_tag[close_end + 3..]; // skip -->
            } else {
                remaining = after_tag;
            }
        } else {
            remaining = after_open;
        }
    }
    result.push_str(remaining);

    // Replace closing placeholders
    result.replace(LINK_PLACEHOLDER_CLOSE, "</a>")
}

// ============================================================================
// Line wrapping / toHTML
// ============================================================================

/// Convert text to HTML by prepending `<html>` and replacing `\n` with `<br>`.
///
/// Ports `HTMLUtilities.toHTML(String)`.
pub fn to_html(text: &str) -> String {
    to_wrapped_html(text, 0)
}

/// Convenience wrapper using `DEFAULT_MAX_LINE_LENGTH`.
///
/// Ports `HTMLUtilities.toWrappedHTML(String)`.
pub fn to_wrapped_html_default(text: &str) -> String {
    to_wrapped_html(text, DEFAULT_MAX_LINE_LENGTH)
}

/// Convert text to wrapped HTML. If `max_line_length > 0`, lines exceeding
/// that length are also broken.
///
/// Ports `HTMLUtilities.toWrappedHTML(String, int)`.
pub fn to_wrapped_html(text: &str, max_line_length: usize) -> String {
    let wrapped = line_wrap_with_html_line_breaks(text, max_line_length);
    if is_html(text) {
        wrapped
    } else {
        wrap_as_html(&wrapped)
    }
}

/// Escape embedded HTML, wrap lines, and produce tooltip-ready HTML.
///
/// Ports `HTMLUtilities.toLiteralHTMLForTooltip(String)`.
pub fn to_literal_html_for_tooltip(text: &str) -> String {
    let clipped = if text.len() > MAX_TOOLTIP_LENGTH {
        format!("{}...", &text[..MAX_TOOLTIP_LENGTH])
    } else {
        text.to_string()
    };
    to_html_with_line_wrapping_and_encoding(&clipped, DEFAULT_TOOLTIP_MAX_LINE_LENGTH, false)
}

/// Escape embedded HTML and wrap lines at `max_line_length`.
///
/// Ports `HTMLUtilities.toLiteralHTML(String, int)`.
pub fn to_literal_html(text: &str, max_line_length: usize) -> String {
    to_html_with_line_wrapping_and_encoding(text, max_line_length, true)
}

fn to_html_with_line_wrapping_and_encoding(
    text: &str,
    max_line_length: usize,
    _preserve_leading_whitespace: bool,
) -> String {
    let lines = split_lines(text, max_line_length);
    let mut buf = String::with_capacity(text.len() * 2);
    for (i, line) in lines.iter().enumerate() {
        buf.push_str(&friendly_encode_html(line, false));
        if i + 1 < lines.len() {
            buf.push_str(BR);
            buf.push('\n');
        }
    }
    wrap_as_html(&buf)
}

// ============================================================================
// HTML escaping
// ============================================================================

/// Escape HTML special characters. Does not convert spaces to `&nbsp;`.
///
/// Ports `HTMLUtilities.escapeHTML(String)`.
pub fn escape_html(text: &str) -> String {
    escape_html_inner(text, false)
}

/// Escape HTML special characters. If `make_spaces_non_breaking` is true,
/// spaces become `&nbsp;`.
///
/// Ports `HTMLUtilities.escapeHTML(String, boolean)`.
pub fn escape_html_with_spaces(text: &str, make_spaces_non_breaking: bool) -> String {
    escape_html_inner(text, make_spaces_non_breaking)
}

fn escape_html_inner(text: &str, make_spaces_non_breaking: bool) -> String {
    let mut buf = String::with_capacity(text.len() + text.len() / 4);
    for ch in text.chars() {
        match ch {
            ' ' => {
                if make_spaces_non_breaking {
                    buf.push_str(HTML_SPACE);
                } else {
                    buf.push(' ');
                }
            }
            '&' => buf.push_str("&amp;"),
            '<' => buf.push_str("&lt;"),
            '>' => buf.push_str("&gt;"),
            _ => {
                if char_needs_html_escaping(ch as u32) {
                    write!(buf, "&#x{:X};", ch as u32).unwrap();
                } else {
                    buf.push(ch);
                }
            }
        }
    }
    buf
}

/// Test whether a Unicode code point needs HTML escaping.
///
/// Ports `HTMLUtilities.charNeedsHTMLEscaping(int)`.
pub fn char_needs_html_escaping(code_point: u32) -> bool {
    if code_point == '\n' as u32
        || code_point == '\t' as u32
        || (' ' as u32 <= code_point && code_point < 0x7F)
    {
        return false;
    }
    true
}

/// Friendly-encode HTML: convert spaces to `&nbsp;`, expand tabs, escape
/// special characters, and encode non-ASCII.
///
/// Ports `HTMLUtilities.friendlyEncodeHTML(String)`.
pub fn friendly_encode_html(text: &str, skip_leading_whitespace: bool) -> String {
    let mut buf = String::with_capacity(text.len() * 2);
    let mut col: usize = 0;
    let mut skipping = skip_leading_whitespace;

    for ch in text.chars() {
        if skipping {
            if ch.is_whitespace() {
                continue;
            }
            skipping = false;
        }

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
            c if (c as u32) < 0x20 => {
                // Strip non-printing chars
                continue;
            }
            '&' => buf.push_str("&amp;"),
            '<' => buf.push_str("&lt;"),
            '>' => buf.push_str("&gt;"),
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

// ============================================================================
// Line wrapping without <html> tag
// ============================================================================

/// Convenience: replace `\n` with `<br>` (no max length).
///
/// Ports `HTMLUtilities.lineWrapWithHTMLLineBreaks(String)`.
pub fn line_wrap_with_html_line_breaks(text: &str, max_line_length: usize) -> String {
    if is_unbreakable_html(text) {
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

/// Strip HTML tags and return plain text. This is a simplified implementation
/// that removes angle-bracket tags. For Swing-dependent unescaping, use a
/// dedicated HTML parser.
///
/// Ports `HTMLUtilities.fromHTML(String)` (simplified, no Swing dependency).
pub fn from_html(text: &str) -> String {
    if text.is_empty() {
        return text.to_string();
    }

    if !is_html(text) {
        return text.to_string();
    }

    // Simple tag stripping
    let mut result = String::with_capacity(text.len());
    let mut in_tag = false;
    for ch in text.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => {
                // Replace non-breaking space with regular space
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

// ============================================================================
// Line-splitting helper
// ============================================================================

/// Split `text` into lines, breaking at `\n` and optionally at `max_line_length`.
fn split_lines(text: &str, max_line_length: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for raw_line in text.split('\n') {
        if max_line_length == 0 || raw_line.len() <= max_line_length {
            lines.push(raw_line.to_string());
        } else {
            // Break at word boundaries where possible
            let mut remaining = raw_line;
            while remaining.len() > max_line_length {
                // Find the last space within the limit
                let mut break_at = max_line_length;
                if let Some(space_pos) = remaining[..max_line_length].rfind(' ') {
                    break_at = space_pos + 1; // include the space in current line
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
// Font style from attributes
// ============================================================================

/// Style attributes for generating styled HTML spans.
#[derive(Debug, Clone, Default)]
pub struct HtmlStyleAttributes {
    /// Font family name.
    pub font_family: Option<String>,
    /// Font size in pixels.
    pub font_size: Option<u32>,
    /// Whether the text is italic.
    pub italic: bool,
    /// Whether the text is bold.
    pub bold: bool,
    /// Foreground color as `#RRGGBB`.
    pub color: Option<String>,
}

/// Escape and wrap the given text in a `<SPAN>` tag with font attributes.
///
/// Ports `HTMLUtilities.styleText(SimpleAttributeSet, String)`.
pub fn style_text(attrs: &HtmlStyleAttributes, text: &str) -> String {
    let family = attrs.font_family.as_deref().unwrap_or("SansSerif");
    let size = attrs.font_size.unwrap_or(12);
    let style = if attrs.italic { "italic" } else { "normal" };
    let weight = if attrs.bold { "bold" } else { "normal" };
    let color_css = match &attrs.color {
        Some(c) => format!("color: {};", c),
        None => String::new(),
    };
    let escaped = escape_html(text);
    format!(
        "<SPAN STYLE=\"{} font-family: '{}'; font-size: {}px; font-style: {}; font-weight: {};\">{}</SPAN>",
        color_css, family, size, style, weight, escaped
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_as_html() {
        let result = wrap_as_html("hello");
        assert_eq!(result, "<html>hello");
    }

    #[test]
    fn test_wrap_as_html_leading_slash() {
        let result = wrap_as_html("/foo");
        assert_eq!(result, "<html>&nbsp;/foo");
    }

    #[test]
    fn test_to_hex_string() {
        assert_eq!(to_hex_string(255, 0, 0), "#FF0000");
        assert_eq!(to_hex_string(0, 255, 0), "#00FF00");
        assert_eq!(to_hex_string(0, 0, 255), "#0000FF");
        assert_eq!(to_hex_string(0, 0, 0), "#000000");
    }

    #[test]
    fn test_to_rgb_string() {
        assert_eq!(to_rgb_string(255, 0, 0), "255000000");
        assert_eq!(to_rgb_string(0, 128, 0), "000128000");
    }

    #[test]
    fn test_color_string() {
        let result = color_string("#FF0000", "hello");
        assert_eq!(result, "<font color=\"#FF0000\">hello</font>");
    }

    #[test]
    fn test_color_string_int() {
        let result = color_string_int("#00FF00", 42);
        assert_eq!(result, "<font color=\"#00FF00\">42</font>");
    }

    #[test]
    fn test_spaces() {
        assert_eq!(spaces(0), "");
        assert_eq!(spaces(1), "&nbsp;");
        assert_eq!(spaces(3), "&nbsp;&nbsp;&nbsp;");
    }

    #[test]
    fn test_bold() {
        assert_eq!(bold("text"), "<b>text</b>");
    }

    #[test]
    fn test_underline() {
        assert_eq!(underline("text"), "<u>text</u>");
    }

    #[test]
    fn test_italic() {
        assert_eq!(italic("text"), "<i>text</i>");
    }

    #[test]
    fn test_is_html() {
        assert!(is_html("<html>text</html>"));
        assert!(is_html("  <html>text"));
        assert!(is_html("<HTML>text"));
        assert!(!is_html("plain text"));
        assert!(!is_html(""));
    }

    #[test]
    fn test_is_unbreakable_html() {
        assert!(is_unbreakable_html("foo&nbsp;bar"));
        assert!(is_unbreakable_html("foo<br>bar"));
        assert!(!is_unbreakable_html("foo bar"));
    }

    #[test]
    fn test_set_font_size() {
        let result = set_font_size("text", 14);
        assert!(result.contains("font-size: 14pt"));
        assert!(result.contains("<span"));
        assert!(result.contains("</span>"));
    }

    #[test]
    fn test_set_font_size_with_html() {
        let result = set_font_size("<html>text</html>", 14);
        assert!(result.starts_with("<html>"));
        assert!(result.ends_with("</html>"));
        assert!(result.contains("font-size: 14pt"));
    }

    #[test]
    fn test_set_font() {
        let result = set_font("text", 255, 0, 0, 16);
        assert!(result.contains("#FF0000"));
        assert!(result.contains("font-size: 16pt"));
    }

    #[test]
    fn test_escape_html() {
        assert_eq!(escape_html("a < b & c > d"), "a &lt; b &amp; c &gt; d");
        assert_eq!(escape_html("no special chars"), "no special chars");
    }

    #[test]
    fn test_escape_html_with_spaces() {
        assert_eq!(
            escape_html_with_spaces("a b", true),
            "a&nbsp;b"
        );
        assert_eq!(
            escape_html_with_spaces("a b", false),
            "a b"
        );
    }

    #[test]
    fn test_char_needs_html_escaping() {
        assert!(!char_needs_html_escaping('a' as u32));
        assert!(!char_needs_html_escaping(' ' as u32));
        assert!(!char_needs_html_escaping('\n' as u32));
        assert!(!char_needs_html_escaping('\t' as u32));
        assert!(char_needs_html_escaping(0xA0)); // non-breaking space
    }

    #[test]
    fn test_friendly_encode_html() {
        let result = friendly_encode_html("a < b", false);
        assert!(result.contains("&lt;"));
        assert!(result.contains("&nbsp;")); // space -> &nbsp;
    }

    #[test]
    fn test_friendly_encode_html_tab() {
        let result = friendly_encode_html("\thello", false);
        assert!(result.starts_with("&nbsp;"));
    }

    #[test]
    fn test_to_html() {
        let result = to_html("line1\nline2");
        assert!(result.starts_with("<html>"));
        assert!(result.contains("<br>"));
    }

    #[test]
    fn test_to_wrapped_html() {
        let result = to_wrapped_html("hello world", 0);
        assert!(result.starts_with("<html>"));
    }

    #[test]
    fn test_to_wrapped_html_with_wrap() {
        let long_text = "a".repeat(200);
        let result = to_wrapped_html(&long_text, 50);
        assert!(result.starts_with("<html>"));
        // Should have been wrapped into multiple lines
        assert!(result.contains("<br>"));
    }

    #[test]
    fn test_to_literal_html() {
        let result = to_literal_html("a < b", 0);
        assert!(result.contains("&lt;"));
        assert!(result.starts_with("<html>"));
    }

    #[test]
    fn test_to_literal_html_for_tooltip() {
        let result = to_literal_html_for_tooltip("test <b>bold</b>");
        assert!(result.contains("&lt;b&gt;"));
        assert!(result.starts_with("<html>"));
    }

    #[test]
    fn test_to_literal_html_for_tooltip_long_text() {
        let long_text = "x".repeat(3000);
        let result = to_literal_html_for_tooltip(&long_text);
        // Should be clipped
        assert!(result.len() < long_text.len() + 200);
    }

    #[test]
    fn test_line_wrap_with_html_line_breaks() {
        let result = line_wrap_with_html_line_breaks("line1\nline2", 0);
        assert!(result.contains("<br>"));
        assert!(!result.starts_with("<html>")); // no html prefix
    }

    #[test]
    fn test_line_wrap_unbreakable() {
        let result = line_wrap_with_html_line_breaks("foo&nbsp;bar", 50);
        assert_eq!(result, "foo&nbsp;bar"); // returned as-is
    }

    #[test]
    fn test_from_html() {
        assert_eq!(from_html("<html>hello</html>"), "hello");
        assert_eq!(from_html("not html"), "not html");
        assert_eq!(from_html(""), "");
    }

    #[test]
    fn test_from_html_nbsp() {
        assert_eq!(from_html("<html>foo&nbsp;bar</html>"), "foobar");
    }

    #[test]
    fn test_link_placeholders() {
        let wrapped = wrap_with_link_placeholder("click here", "http://example.com");
        assert!(wrapped.contains("CONTENT=\"http://example.com\""));
        assert!(wrapped.contains("click here"));

        let converted = convert_link_placeholders_to_hyperlinks(&wrapped);
        assert!(converted.contains("<a href=\"http://example.com\">"));
        assert!(converted.contains("</a>"));
        assert!(converted.contains("click here"));
    }

    #[test]
    fn test_style_text() {
        let attrs = HtmlStyleAttributes {
            font_family: Some("Monospace".to_string()),
            font_size: Some(14),
            italic: true,
            bold: false,
            color: Some("#FF0000".to_string()),
        };
        let result = style_text(&attrs, "hello");
        assert!(result.contains("Monospace"));
        assert!(result.contains("14px"));
        assert!(result.contains("italic"));
        assert!(result.contains("#FF0000"));
        assert!(result.contains("hello"));
    }

    #[test]
    fn test_split_lines_short() {
        let lines = split_lines("hello world", 0);
        assert_eq!(lines, vec!["hello world"]);
    }

    #[test]
    fn test_split_lines_newlines() {
        let lines = split_lines("a\nb\nc", 0);
        assert_eq!(lines, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_split_lines_wrap() {
        let lines = split_lines("hello world foo bar", 10);
        assert!(lines.len() > 1);
        for line in &lines {
            assert!(line.len() <= 10 + 1); // +1 for space at break
        }
    }

    #[test]
    fn test_constants() {
        assert_eq!(HTML, "<html>");
        assert_eq!(HTML_CLOSE, "</html>");
        assert_eq!(BR, "<br>");
        assert_eq!(HTML_SPACE, "&nbsp;");
        assert_eq!(HTML_NEW_LINE, "<br>");
    }
}
