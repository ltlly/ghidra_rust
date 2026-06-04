//! Markdown to HTML conversion support.
//!
//! Port of Ghidra's `ghidra.markdown.MarkdownToHtml`.
//!
//! Provides a configurable Markdown-to-HTML converter with support for:
//! - Heading anchors
//! - Tables with border styling
//! - Code block styling
//! - Link fixup (`.md` -> `.html`, path rewriting)

use std::fmt::Write;
use std::path::Path;

/// Configuration for the markdown-to-HTML conversion.
#[derive(Debug, Clone)]
pub struct MarkdownConfig {
    /// CSS style for table cells.
    pub table_style: String,
    /// CSS style for headings (h1/h2).
    pub heading_style: String,
    /// CSS style for fenced code blocks.
    pub code_block_style: String,
    /// CSS style for inline code.
    pub inline_code_style: String,
    /// Whether to convert `.md` links to `.html`.
    pub fix_links: bool,
}

impl Default for MarkdownConfig {
    fn default() -> Self {
        Self {
            table_style: "border: 1px solid black; border-collapse: collapse; padding: 5px;"
                .to_string(),
            heading_style:
                "border-bottom: solid 1px; border-bottom-color: #cccccc; padding-bottom: 8px;"
                    .to_string(),
            code_block_style: concat!(
                "background: #f4f4f4; border: 1px solid #ddd; border-left: 3px solid #f36d33; ",
                "color: #666; display: block; font-family: monospace; line-height: 1.6; ",
                "margin-bottom: 1.6em; max-width: 100%; overflow: auto; padding: 1em 1.5em; ",
                "page-break-inside: avoid; word-wrap: break-word;"
            )
            .to_string(),
            inline_code_style: "background: #f4f4f4; font-family: monospace;".to_string(),
            fix_links: true,
        }
    }
}

/// Simple Markdown to HTML converter.
///
/// This is a lightweight port that handles common Markdown elements. For full
/// GFM/CommonMark compliance, consider using a dedicated Rust crate like `pulldown-cmark`.
#[derive(Debug, Clone)]
pub struct MarkdownToHtml {
    config: MarkdownConfig,
}

impl MarkdownToHtml {
    /// Create a new converter with default configuration.
    pub fn new() -> Self {
        Self {
            config: MarkdownConfig::default(),
        }
    }

    /// Create a new converter with the given configuration.
    pub fn with_config(config: MarkdownConfig) -> Self {
        Self { config }
    }

    /// Convert a markdown string to HTML.
    pub fn convert(&self, markdown: &str) -> String {
        let mut output = String::new();
        let lines: Vec<&str> = markdown.lines().collect();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i];

            // Headings
            if let Some(level) = heading_level(line) {
                let content = line.trim_start_matches('#').trim();
                let anchor = slugify(content);
                let style_attr = if level <= 2 {
                    format!(" style=\"{}\"", self.config.heading_style)
                } else {
                    String::new()
                };
                let _ = writeln!(
                    output,
                    "<h{level} id=\"{anchor}\"{style_attr}>{content}</h{level}>"
                );
                i += 1;
                continue;
            }

            // Fenced code block
            if line.trim_start().starts_with("```") {
                let lang = line.trim_start().trim_start_matches('`').trim();
                let style_attr = if !self.config.code_block_style.is_empty() {
                    format!(" style=\"{}\"", self.config.code_block_style)
                } else {
                    String::new()
                };
                let _ = write!(output, "<pre{style_attr}><code");
                if !lang.is_empty() {
                    let _ = write!(output, " class=\"language-{lang}\"");
                }
                output.push('>');
                i += 1;
                while i < lines.len() && !lines[i].trim_start().starts_with("```") {
                    let _ = writeln!(output, "{}", html_escape(lines[i]));
                    i += 1;
                }
                if i < lines.len() {
                    i += 1; // skip closing ```
                }
                output.push_str("</code></pre>\n");
                continue;
            }

            // Horizontal rule
            if is_horizontal_rule(line) {
                output.push_str("<hr />\n");
                i += 1;
                continue;
            }

            // Table detection
            if i + 1 < lines.len() && is_table_separator(lines[i + 1]) {
                i = self.emit_table(&lines, i, &mut output);
                continue;
            }

            // Unordered list
            if line.starts_with("- ") || line.starts_with("* ") || line.starts_with("+ ") {
                output.push_str("<ul>\n");
                while i < lines.len() {
                    let l = lines[i];
                    if l.starts_with("- ") || l.starts_with("* ") || l.starts_with("+ ") {
                        let content = &l[2..];
                        let _ = writeln!(output, "  <li>{}</li>", self.inline_format(content));
                        i += 1;
                    } else if l.trim().is_empty() {
                        break;
                    } else {
                        break;
                    }
                }
                output.push_str("</ul>\n");
                continue;
            }

            // Paragraph or blank line
            if line.trim().is_empty() {
                i += 1;
                continue;
            }

            // Regular paragraph
            output.push_str("<p>");
            output.push_str(&self.inline_format(line));
            i += 1;
            while i < lines.len() && !lines[i].trim().is_empty() {
                output.push(' ');
                output.push_str(&self.inline_format(lines[i]));
                i += 1;
            }
            output.push_str("</p>\n");
        }

        output
    }

    /// Convert a markdown file to an HTML file.
    pub fn convert_file(&self, input_path: &Path, output_path: &Path) -> Result<(), std::io::Error> {
        let markdown = std::fs::read_to_string(input_path)?;
        let html = self.convert(&markdown);
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(output_path, html)
    }

    /// Apply inline formatting (bold, italic, code, links).
    fn inline_format(&self, text: &str) -> String {
        let mut result = html_escape(text);

        // Inline code (must come before bold/italic to avoid conflicts)
        result = replace_inline_pattern(&result, '`', "code", "");

        // Bold **text** or __text__
        result = replace_delimited(&result, "**", "strong");
        result = replace_delimited(&result, "__", "strong");

        // Italic *text* or _text_
        result = replace_delimited(&result, "*", "em");
        result = replace_delimited(&result, "_", "em");

        // Links [text](url)
        result = replace_links(&result, self.config.fix_links);

        result
    }

    /// Emit a table and return the new line index.
    fn emit_table(&self, lines: &[&str], start: usize, output: &mut String) -> usize {
        let header_line = lines[start];
        let _separator = lines[start + 1]; // we know it's a separator
        let headers: Vec<&str> = split_table_row(header_line);

        let style_attr = if !self.config.table_style.is_empty() {
            format!(" style=\"{}\"", self.config.table_style)
        } else {
            String::new()
        };

        output.push_str("<table>\n<thead>\n<tr>\n");
        for h in &headers {
            let _ = writeln!(output, "  <th{style_attr}>{}</th>", self.inline_format(h.trim()));
        }
        output.push_str("</tr>\n</thead>\n<tbody>\n");

        let mut i = start + 2;
        while i < lines.len() && !lines[i].trim().is_empty() {
            let cells = split_table_row(lines[i]);
            output.push_str("<tr>\n");
            for cell in &cells {
                let _ = writeln!(
                    output,
                    "  <td{style_attr}>{}</td>",
                    self.inline_format(cell.trim())
                );
            }
            output.push_str("</tr>\n");
            i += 1;
        }
        output.push_str("</tbody>\n</table>\n");
        i
    }
}

impl Default for MarkdownToHtml {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a line is a heading, returning its level (1-6).
fn heading_level(line: &str) -> Option<u32> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with('#') {
        return None;
    }
    let count = trimmed.chars().take_while(|&c| c == '#').count() as u32;
    if count > 0 && count <= 6 && trimmed.len() > count as usize && trimmed.as_bytes()[count as usize] == b' ' {
        Some(count)
    } else {
        None
    }
}

/// Check if a line is a table separator (e.g., `|---|---|`).
fn is_table_separator(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }
    let parts: Vec<&str> = trimmed
        .split('|')
        .filter(|s| !s.trim().is_empty())
        .collect();
    if parts.is_empty() {
        return false;
    }
    parts.iter().all(|s| {
        let s = s.trim();
        s.chars().all(|c| c == '-' || c == ':' || c == ' ') && s.len() >= 3
    })
}

/// Split a table row into cells.
fn split_table_row(line: &str) -> Vec<&str> {
    let trimmed = line.trim();
    let trimmed = trimmed.trim_start_matches('|').trim_end_matches('|');
    trimmed.split('|').collect()
}

/// Check if a line is a horizontal rule.
fn is_horizontal_rule(line: &str) -> bool {
    let trimmed = line.trim();
    let non_space: Vec<char> = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if non_space.len() < 3 {
        return false;
    }
    let ch = non_space[0];
    (ch == '-' || ch == '*' || ch == '_') && non_space.iter().all(|&c| c == ch)
}

/// HTML-escape special characters.
fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Replace inline code (backtick-wrapped) with HTML.
fn replace_inline_pattern(text: &str, delim: char, tag: &str, attrs: &str) -> String {
    let mut result = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == delim {
            let mut inner = String::new();
            let mut found = false;
            while let Some(nc) = chars.next() {
                if nc == delim {
                    found = true;
                    break;
                }
                inner.push(nc);
            }
            if found {
                if attrs.is_empty() {
                    let _ = write!(result, "<{tag}>{inner}</{tag}>");
                } else {
                    let _ = write!(result, "<{tag} {attrs}>{inner}</{tag}>");
                }
            } else {
                result.push(delim);
                result.push_str(&inner);
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Replace `**text**` with `<strong>text</strong>` etc.
fn replace_delimited(text: &str, delim: &str, tag: &str) -> String {
    let mut result = String::new();
    let mut remaining = text;
    while let Some(start) = remaining.find(delim) {
        let after_open = &remaining[start + delim.len()..];
        if let Some(end) = after_open.find(delim) {
            let inner = &after_open[..end];
            if !inner.is_empty() {
                result.push_str(&remaining[..start]);
                let _ = write!(result, "<{tag}>{inner}</{tag}>");
                remaining = &after_open[end + delim.len()..];
                continue;
            }
        }
        result.push_str(&remaining[..start + delim.len()]);
        remaining = &remaining[start + delim.len()..];
    }
    result.push_str(remaining);
    result
}

/// Replace `[text](url)` with `<a>` tags.
fn replace_links(text: &str, fix_links: bool) -> String {
    let mut result = String::new();
    let mut remaining = text;

    while let Some(bracket_start) = remaining.find('[') {
        let after_bracket = &remaining[bracket_start + 1..];
        if let Some(bracket_end) = after_bracket.find(']') {
            let link_text = &after_bracket[..bracket_end];
            let rest = &after_bracket[bracket_end + 1..];
            if rest.starts_with('(') {
                if let Some(paren_end) = rest.find(')') {
                    let url = &rest[1..paren_end];
                    result.push_str(&remaining[..bracket_start]);

                    let final_url = if fix_links {
                        fix_link_url(url)
                    } else {
                        url.to_string()
                    };

                    let _ = write!(result, "<a href=\"{final_url}\">{link_text}</a>");
                    remaining = &rest[paren_end + 1..];
                    continue;
                }
            }
        }
        result.push_str(&remaining[..bracket_start + 1]);
        remaining = &remaining[bracket_start + 1..];
    }
    result.push_str(remaining);
    result
}

/// Fixup link URLs (`.md` -> `.html`, repository path adjustments).
fn fix_link_url(url: &str) -> String {
    // Skip anchor-only links
    if url.starts_with('#') {
        return url.to_string();
    }

    // Skip fully qualified URLs
    let lower = url.to_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return url.to_string();
    }

    let mut href = url.to_string();

    // Convert .md links to .html
    if href.to_lowercase().ends_with(".md") {
        href = format!("{}html", &href[..href.len() - 2]);
    }

    // Fix known path differences between repository and release
    if href.contains("src/main/py") {
        href = href.replace("src/main/py", "pypkg");
    } else if href.contains("src/main/java") {
        // Source code links are not meaningful in the release docs
        return String::new();
    }

    href
}

/// Convert a string to a URL-friendly slug.
fn slugify(text: &str) -> String {
    text.to_lowercase()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else if c.is_whitespace() {
                '-'
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heading() {
        let md = "## Hello World";
        let html = MarkdownToHtml::new().convert(md);
        assert!(html.contains("<h2"));
        assert!(html.contains("Hello World</h2>"));
    }

    #[test]
    fn test_heading_anchor() {
        let md = "# My Title";
        let html = MarkdownToHtml::new().convert(md);
        assert!(html.contains("id=\"my-title\""));
    }

    #[test]
    fn test_code_block() {
        let md = "```rust\nfn main() {}\n```";
        let html = MarkdownToHtml::new().convert(md);
        assert!(html.contains("<pre"));
        assert!(html.contains("language-rust"));
        assert!(html.contains("fn main"));
        assert!(html.contains("</code></pre>"));
    }

    #[test]
    fn test_table() {
        let md = "| A | B |\n|---|---|\n| 1 | 2 |";
        let html = MarkdownToHtml::new().convert(md);
        assert!(html.contains("<table>"));
        assert!(html.contains("<th"));
        assert!(html.contains("<td"));
        assert!(html.contains("</table>"));
    }

    #[test]
    fn test_inline_code() {
        let md = "Use `println!` here.";
        let html = MarkdownToHtml::new().convert(md);
        assert!(html.contains("<code>println!</code>"));
    }

    #[test]
    fn test_bold() {
        let md = "This is **bold** text.";
        let html = MarkdownToHtml::new().convert(md);
        assert!(html.contains("<strong>bold</strong>"));
    }

    #[test]
    fn test_italic() {
        let md = "This is *italic* text.";
        let html = MarkdownToHtml::new().convert(md);
        assert!(html.contains("<em>italic</em>"));
    }

    #[test]
    fn test_link() {
        let md = "[click here](https://example.com)";
        let html = MarkdownToHtml::new().convert(md);
        assert!(html.contains("<a href=\"https://example.com\">click here</a>"));
    }

    #[test]
    fn test_link_md_to_html() {
        let md = "[docs](guide.md)";
        let html = MarkdownToHtml::new().convert(md);
        assert!(html.contains("href=\"guide.html\""));
    }

    #[test]
    fn test_horizontal_rule() {
        let md = "---";
        let html = MarkdownToHtml::new().convert(md);
        assert!(html.contains("<hr"));
    }

    #[test]
    fn test_unordered_list() {
        let md = "- item 1\n- item 2";
        let html = MarkdownToHtml::new().convert(md);
        assert!(html.contains("<ul>"));
        assert!(html.contains("<li>item 1</li>"));
        assert!(html.contains("<li>item 2</li>"));
        assert!(html.contains("</ul>"));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<b>&\""), "&lt;b&gt;&amp;&quot;");
    }

    #[test]
    fn test_slugify() {
        assert_eq!(slugify("Hello World!"), "hello-world");
        assert_eq!(slugify("My---Title"), "my-title");
    }

    #[test]
    fn test_heading_level() {
        assert_eq!(heading_level("# H1"), Some(1));
        assert_eq!(heading_level("## H2"), Some(2));
        assert_eq!(heading_level("###### H6"), Some(6));
        assert_eq!(heading_level("not a heading"), None);
        assert_eq!(heading_level("#NoSpace"), None);
    }

    #[test]
    fn test_is_horizontal_rule() {
        assert!(is_horizontal_rule("---"));
        assert!(is_horizontal_rule("***"));
        assert!(is_horizontal_rule("___"));
        assert!(is_horizontal_rule("- - -"));
        assert!(!is_horizontal_rule("--"));
        assert!(!is_horizontal_rule("text"));
    }

    #[test]
    fn test_fix_link_url() {
        assert_eq!(fix_link_url("#anchor"), "#anchor");
        assert_eq!(fix_link_url("https://example.com"), "https://example.com");
        assert_eq!(fix_link_url("guide.md"), "guide.html");
        assert_eq!(
            fix_link_url("src/main/py/module.py"),
            "pypkg/module.py"
        );
        assert_eq!(fix_link_url("src/main/java/Foo.java"), "");
    }

    #[test]
    fn test_paragraph() {
        let md = "Hello world\n\nSecond paragraph";
        let html = MarkdownToHtml::new().convert(md);
        assert!(html.contains("<p>Hello world</p>"));
        assert!(html.contains("<p>Second paragraph</p>"));
    }
}
