//! Port of `generic.theme.ThemeReader`, `generic.theme.ThemePropertyFileReader`,
//! and `generic.theme.AbstractThemeReader`.
//!
//! Reading theme definitions from property files or configuration.

use std::collections::HashMap;
use std::path::Path;

use super::color_value::ColorValue;
use super::font_value::FontValue;
use super::icon_value::{IconValue, IconPath};
use crate::gui_util::web_colors::RgbaColor;
use crate::options::option_value::FontDescriptor;

/// A parsed theme file containing color, font, and icon values.
///
/// Mirrors the result of reading a Ghidra theme property file.
#[derive(Debug, Clone, Default)]
pub struct ThemeFile {
    /// Theme name.
    pub name: String,
    /// Color values by id (without prefix).
    pub colors: HashMap<String, ColorValue>,
    /// Font values by id (without prefix).
    pub fonts: HashMap<String, FontValue>,
    /// Icon values by id (without prefix).
    pub icons: HashMap<String, IconValue>,
}

impl ThemeFile {
    /// Create an empty theme file.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            colors: HashMap::new(),
            fonts: HashMap::new(),
            icons: HashMap::new(),
        }
    }

    /// Add a color value.
    pub fn add_color(&mut self, id: impl Into<String>, color: ColorValue) {
        self.colors.insert(id.into(), color);
    }

    /// Add a font value.
    pub fn add_font(&mut self, id: impl Into<String>, font: FontValue) {
        self.fonts.insert(id.into(), font);
    }

    /// Add an icon value.
    pub fn add_icon(&mut self, id: impl Into<String>, icon: IconValue) {
        self.icons.insert(id.into(), icon);
    }

    /// Get a color by id.
    pub fn get_color(&self, id: &str) -> Option<&ColorValue> {
        self.colors.get(id)
    }

    /// Get a font by id.
    pub fn get_font(&self, id: &str) -> Option<&FontValue> {
        self.fonts.get(id)
    }

    /// Get an icon by id.
    pub fn get_icon(&self, id: &str) -> Option<&IconValue> {
        self.icons.get(id)
    }

    /// The total number of values (colors + fonts + icons).
    pub fn total_values(&self) -> usize {
        self.colors.len() + self.fonts.len() + self.icons.len()
    }
}

/// Theme file reader for Ghidra's property-file format.
///
/// Parses `key=value` lines where the prefix determines the value type:
/// - `color.id=#RRGGBB`
/// - `font.id=Name|Size|Bold|Italic`
/// - `icon.id=path`
///
/// Mirrors `generic.theme.AbstractThemeReader` and `generic.theme.ThemePropertyFileReader`.
pub struct ThemeReader;

impl ThemeReader {
    /// Parse a theme file from a string.
    pub fn parse(name: &str, content: &str) -> ThemeFile {
        let mut file = ThemeFile::new(name);

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }

            if let Some((key, value)) = Self::split_key_value(line) {
                if let Some(id) = key.strip_prefix("color.") {
                    if let Some(color) = Self::parse_color(value) {
                        let full_id = format!("color.{}", id);
                        file.add_color(id, ColorValue::new(full_id, color));
                    }
                } else if let Some(id) = key.strip_prefix("font.") {
                    if let Some(font) = Self::parse_font(value) {
                        let full_id = format!("font.{}", id);
                        file.add_font(id, FontValue::new(full_id, font));
                    }
                } else if let Some(id) = key.strip_prefix("icon.") {
                    let full_id = format!("icon.{}", id);
                    file.add_icon(id, IconValue::new(full_id, IconPath::new(value)));
                }
            }
        }

        file
    }

    /// Parse a theme file from a path.
    pub fn read_file(path: &Path) -> Result<ThemeFile, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");
        Ok(Self::parse(name, &content))
    }

    fn split_key_value(line: &str) -> Option<(&str, &str)> {
        let eq_pos = line.find('=')?;
        let key = line[..eq_pos].trim();
        let value = line[eq_pos + 1..].trim();
        if key.is_empty() {
            return None;
        }
        Some((key, value))
    }

    fn parse_color(value: &str) -> Option<RgbaColor> {
        let hex = value.trim().strip_prefix('#').unwrap_or(value.trim());
        match hex.len() {
            6 => {
                let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
                let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
                let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
                Some(RgbaColor::new(r, g, b))
            }
            8 => {
                let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
                let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
                let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
                let a = u8::from_str_radix(&hex[6..8], 16).ok()?;
                Some(RgbaColor::with_alpha(r, g, b, a))
            }
            _ => None,
        }
    }

    fn parse_font(value: &str) -> Option<FontDescriptor> {
        let parts: Vec<&str> = value.split('|').collect();
        if parts.len() >= 2 {
            let family = parts[0].trim();
            let size = parts[1].trim().parse::<f32>().ok().unwrap_or(12.0);
            let bold = parts.get(2).map(|s| s.trim() == "true").unwrap_or(false);
            let italic = parts.get(3).map(|s| s.trim() == "true").unwrap_or(false);
            let style = match (bold, italic) {
                (true, true) => 3, // BOLD + ITALIC
                (true, false) => 1, // BOLD
                (false, true) => 2, // ITALIC
                (false, false) => 0, // PLAIN
            };
            Some(FontDescriptor::new(family, style, size))
        } else {
            // Try plain "Name,Size" format
            let parts2: Vec<&str> = value.split(',').collect();
            if parts2.len() >= 2 {
                let family = parts2[0].trim();
                let size = parts2[1].trim().parse::<f32>().ok().unwrap_or(12.0);
                Some(FontDescriptor::plain(family, size))
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_theme() {
        let content = r#"
# This is a comment
color.bg=#FFFFFF
color.fg=#000000
color.selection=#3399FF
font.default=Monospaced|14
font.heading=SansSerif|16|true|false
icon.error=images/error.png
"#;
        let theme = ThemeReader::parse("test_theme", content);
        assert_eq!(theme.name, "test_theme");
        assert_eq!(theme.colors.len(), 3);
        assert_eq!(theme.fonts.len(), 2);
        assert_eq!(theme.icons.len(), 1);

        let bg = theme.get_color("bg").unwrap();
        assert_eq!(bg.raw_value(), Some(RgbaColor::new(255, 255, 255)));

        let font = theme.get_font("default").unwrap();
        let fd = font.raw_value().unwrap();
        assert_eq!(fd.family, "Monospaced");
        assert_eq!(fd.size, 14.0);

        let heading = theme.get_font("heading").unwrap();
        let hd = heading.raw_value().unwrap();
        assert!(hd.is_bold());
        assert!(!hd.is_italic());

        let icon = theme.get_icon("error").unwrap();
        let icon_path = icon.raw_value().unwrap();
        assert_eq!(icon_path.path(), "images/error.png");
    }

    #[test]
    fn test_parse_empty_lines_and_comments() {
        let content = r#"
# comment
// another comment

color.bg=#000000

"#;
        let theme = ThemeReader::parse("test", content);
        assert_eq!(theme.total_values(), 1);
    }

    #[test]
    fn test_parse_font_comma_format() {
        let content = "font.test=Courier,18\n";
        let theme = ThemeReader::parse("test", content);
        let font = theme.get_font("test").unwrap();
        let fd = font.raw_value().unwrap();
        assert_eq!(fd.family, "Courier");
        assert_eq!(fd.size, 18.0);
        assert!(!fd.is_bold());
    }

    #[test]
    fn test_theme_file_builder() {
        let mut file = ThemeFile::new("my_theme");
        file.add_color("bg", ColorValue::new("color.bg", RgbaColor::new(255, 255, 255)));
        file.add_font("default", FontValue::new("font.default", FontDescriptor::plain("Arial", 12.0)));
        assert_eq!(file.total_values(), 2);
    }
}
