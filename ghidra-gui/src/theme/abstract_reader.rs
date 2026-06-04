//! Abstract theme properties file reader -- port of Ghidra's
//! `generic.theme.AbstractThemeReader`.
//!
//! Handles parsing theme `.properties` files which contain default color,
//! font, and icon values.  Sections are delimited by headings like
//! `[Defaults]`, `[Dark Defaults]`, and `[Look and Feel: FlatDark]`.

use std::collections::HashMap;

use super::color_value::ColorValue;
use super::font_value::FontValue;
use super::laf_type::LafType;
use super::g_theme_value_map::GThemeValueMap;

/// A section within a theme properties file.
#[derive(Debug, Clone)]
pub struct ThemeSection {
    /// The section name (e.g., "Defaults", "Dark Defaults", "Look and Feel: FlatDark").
    pub name: String,
    /// Key-value pairs in this section, in order.
    pub entries: Vec<(String, String)>,
    /// Line number where the section header was found.
    pub line_number: usize,
}

impl ThemeSection {
    /// Create a new empty section.
    pub fn new(name: impl Into<String>, line_number: usize) -> Self {
        Self {
            name: name.into(),
            entries: Vec::new(),
            line_number,
        }
    }

    /// Whether the section has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add a key-value entry.
    pub fn push(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.entries.push((key.into(), value.into()));
    }
}

/// Type of theme section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    /// Before any section header.
    None,
    /// `[Defaults]`.
    Defaults,
    /// `[Dark Defaults]`.
    DarkDefaults,
    /// `[Look and Feel: <name>]`.
    LookAndFeel,
}

/// Results of parsing a theme properties file.
#[derive(Debug, Clone, Default)]
pub struct ParsedThemeFile {
    /// Default (light) values.
    pub defaults: GThemeValueMap,
    /// Dark default values.
    pub dark_defaults: GThemeValueMap,
    /// Look-and-feel-specific overrides.
    pub laf_sections: HashMap<LafType, GThemeValueMap>,
    /// Any errors encountered during parsing.
    pub errors: Vec<ThemeParseError>,
}

/// An error encountered during parsing of a theme properties file.
#[derive(Debug, Clone)]
pub struct ThemeParseError {
    /// Line number where the error occurred (-1 if unknown).
    pub line: i64,
    /// Error message.
    pub message: String,
}

impl std::fmt::Display for ThemeParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.line >= 0 {
            write!(f, "Line {}: {}", self.line, self.message)
        } else {
            write!(f, "{}", self.message)
        }
    }
}

/// Parse the text content of a `.theme.properties` file.
///
/// Returns a `ParsedThemeFile` with defaults, dark defaults, and any
/// LAF-specific sections.
pub fn parse_theme_properties(content: &str) -> ParsedThemeFile {
    let mut result = ParsedThemeFile::default();
    let mut current_kind = SectionKind::None;
    let mut current_laf: Option<LafType> = None;
    let mut defaults_processed = false;

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = (line_idx + 1) as i64;
        let trimmed = line.trim();

        // Skip blank lines and comments.
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        // Section header detection.
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let header = &trimmed[1..trimmed.len() - 1];
            let header_lower = header.to_lowercase();

            if header_lower == "defaults" {
                current_kind = SectionKind::Defaults;
                current_laf = None;
                defaults_processed = true;
            } else if header_lower == "dark defaults" {
                if !defaults_processed {
                    result.errors.push(ThemeParseError {
                        line: line_num,
                        message: "Defaults section must be defined before Dark Defaults section"
                            .to_string(),
                    });
                }
                current_kind = SectionKind::DarkDefaults;
                current_laf = None;
            } else if header_lower.starts_with("look and feel:") {
                if !defaults_processed {
                    result.errors.push(ThemeParseError {
                        line: line_num,
                        message: format!(
                            "Defaults section must be defined before {} section",
                            header
                        ),
                    });
                }
                let laf_name = header["Look and Feel:".len()..].trim();
                match laf_name.parse::<LafType>() {
                    Ok(lt) => {
                        current_kind = SectionKind::LookAndFeel;
                        current_laf = Some(lt);
                    }
                    Err(_) => {
                        result.errors.push(ThemeParseError {
                            line: line_num,
                            message: format!("Unknown Look and Feel section: {}", laf_name),
                        });
                        current_kind = SectionKind::None;
                        current_laf = None;
                    }
                }
            } else {
                result.errors.push(ThemeParseError {
                    line: line_num,
                    message: format!("Unknown section: {}", header),
                });
                current_kind = SectionKind::None;
                current_laf = None;
            }
            continue;
        }

        // Key=value entry.
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim().to_string();
            let value = trimmed[eq_pos + 1..].trim().to_string();

            let target_map = match current_kind {
                SectionKind::None => {
                    result.errors.push(ThemeParseError {
                        line: line_num,
                        message: "Value defined outside of a section".to_string(),
                    });
                    continue;
                }
                SectionKind::Defaults => &mut result.defaults,
                SectionKind::DarkDefaults => &mut result.dark_defaults,
                SectionKind::LookAndFeel => {
                    if let Some(laf) = current_laf {
                        result.laf_sections.entry(laf).or_insert_with(GThemeValueMap::new)
                    } else {
                        continue;
                    }
                }
            };

            // Insert as color value (font values are identified by ".font" suffix).
            if key.ends_with(".font") {
                let fv = FontValue::new(
                    &key,
                    crate::options::option_value::FontDescriptor::plain(&value, 12.0),
                );
                target_map.add_font(fv);
            } else if value.starts_with('@') {
                // Reference to another color.
                let ref_id = value[1..].trim().to_string();
                let cv = ColorValue::with_ref(&key, ref_id);
                target_map.add_color(cv);
            } else {
                // Direct hex color.
                let parsed = crate::gui_util::web_colors::WebColors::parse(&value);
                let color = parsed.unwrap_or(crate::gui_util::web_colors::RgbaColor::new(128, 128, 128));
                let cv = ColorValue::new(&key, color);
                target_map.add_color(cv);
            }
        }
    }

    // Validate: dark defaults should reference keys in defaults.
    for id in result.dark_defaults.get_color_ids() {
        if result.defaults.get_color(id).is_none() {
            result.errors.push(ThemeParseError {
                line: -1,
                message: format!(
                    "Color id found in Dark Defaults but not in Defaults: {}",
                    id
                ),
            });
        }
    }

    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_content() {
        let result = parse_theme_properties("");
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_parse_defaults_section() {
        let content = r#"
[Defaults]
color.bg = #ffffff
color.fg = #000000
"#;
        let result = parse_theme_properties(content);
        assert!(result.defaults.get_color("color.bg").is_some());
        assert!(result.defaults.get_color("color.fg").is_some());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_parse_dark_defaults() {
        let content = r#"
[Defaults]
color.bg = #ffffff

[Dark Defaults]
color.bg = #1e1e1e
"#;
        let result = parse_theme_properties(content);
        assert!(result.defaults.get_color("color.bg").is_some());
        assert!(result.dark_defaults.get_color("color.bg").is_some());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_parse_dark_defaults_before_defaults_is_error() {
        let content = r#"
[Dark Defaults]
color.bg = #1e1e1e
"#;
        let result = parse_theme_properties(content);
        assert!(result.errors.iter().any(|e| e.message.contains("Defaults section must be defined")));
    }

    #[test]
    fn test_parse_look_and_feel_section() {
        let content = r#"
[Defaults]
color.bg = #ffffff

[Look and Feel: FlatDark]
color.bg = #1e1e1e
"#;
        let result = parse_theme_properties(content);
        assert!(result.laf_sections.contains_key(&LafType::FlatDark));
        let flat_dark = &result.laf_sections[&LafType::FlatDark];
        assert!(flat_dark.get_color("color.bg").is_some());
    }

    #[test]
    fn test_parse_unknown_laf_section() {
        let content = r#"
[Defaults]
color.bg = #ffffff

[Look and Feel: UnknownLAF]
color.bg = #000000
"#;
        let result = parse_theme_properties(content);
        assert!(result.errors.iter().any(|e| e.message.contains("Unknown Look and Feel")));
    }

    #[test]
    fn test_comments_are_skipped() {
        let content = r#"
# This is a comment
[Defaults]
// This is also a comment
color.bg = #ffffff
"#;
        let result = parse_theme_properties(content);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_value_outside_section_is_error() {
        let content = "color.bg = #ffffff\n";
        let result = parse_theme_properties(content);
        assert!(result.errors.iter().any(|e| e.message.contains("outside")));
    }

    #[test]
    fn test_section_struct() {
        let mut sec = ThemeSection::new("Defaults", 1);
        assert!(sec.is_empty());
        sec.push("color.bg", "#ffffff");
        assert!(!sec.is_empty());
        assert_eq!(sec.name, "Defaults");
        assert_eq!(sec.line_number, 1);
    }

    #[test]
    fn test_parse_error_display() {
        let err = ThemeParseError {
            line: 42,
            message: "test error".to_string(),
        };
        assert_eq!(err.to_string(), "Line 42: test error");

        let err_no_line = ThemeParseError {
            line: -1,
            message: "no line".to_string(),
        };
        assert_eq!(err_no_line.to_string(), "no line");
    }
}
