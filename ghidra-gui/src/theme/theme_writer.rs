//! Port of `generic.theme.ThemeWriter`.
//!
//! Serializes theme definitions to Ghidra's property-file format.

use super::theme_reader::ThemeFile;

/// Writer that serializes a [`ThemeFile`] to Ghidra's theme property format.
///
/// Mirrors `generic.theme.ThemeWriter`.
pub struct ThemeWriter;

impl ThemeWriter {
    /// Serialize a theme file to a string.
    pub fn write(theme: &ThemeFile) -> String {
        let mut output = String::new();
        output.push_str(&format!("# Ghidra Theme: {}\n", theme.name));
        output.push('\n');

        // Colors
        if !theme.colors.is_empty() {
            output.push_str("# Colors\n");
            let mut color_keys: Vec<&String> = theme.colors.keys().collect();
            color_keys.sort();
            for key in color_keys {
                let color = &theme.colors[key];
                if let Some(rgba) = color.raw_value() {
                    output.push_str(&format!("color.{}={}\n", key, rgba.to_hex_string()));
                }
            }
            output.push('\n');
        }

        // Fonts
        if !theme.fonts.is_empty() {
            output.push_str("# Fonts\n");
            let mut font_keys: Vec<&String> = theme.fonts.keys().collect();
            font_keys.sort();
            for key in font_keys {
                let font = &theme.fonts[key];
                if let Some(fd) = font.raw_value() {
                    let bold = fd.is_bold();
                    let italic = fd.is_italic();
                    output.push_str(&format!(
                        "font.{}={}|{}|{}|{}\n",
                        key, fd.family, fd.size as u32, bold, italic
                    ));
                }
            }
            output.push('\n');
        }

        // Icons
        if !theme.icons.is_empty() {
            output.push_str("# Icons\n");
            let mut icon_keys: Vec<&String> = theme.icons.keys().collect();
            icon_keys.sort();
            for key in icon_keys {
                let icon = &theme.icons[key];
                if let Some(ip) = icon.raw_value() {
                    output.push_str(&format!("icon.{}={}\n", key, ip.path()));
                }
            }
        }

        output
    }

    /// Write a theme to a file.
    pub fn write_file(theme: &ThemeFile, path: &std::path::Path) -> std::io::Result<()> {
        let content = Self::write(theme);
        std::fs::write(path, content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::color_value::ColorValue;
    use super::super::font_value::FontValue;
    use super::super::icon_value::{IconValue, IconPath};
    use super::super::theme_reader::ThemeReader;
    use crate::gui_util::web_colors::RgbaColor;
    use crate::options::option_value::FontDescriptor;

    #[test]
    fn test_write_roundtrip() {
        let mut theme = ThemeFile::new("RoundtripTest");
        theme.add_color("bg", ColorValue::new("color.bg", RgbaColor::new(255, 255, 255)));
        theme.add_color("fg", ColorValue::new("color.fg", RgbaColor::new(0, 0, 0)));
        theme.add_font("default", FontValue::new("font.default", FontDescriptor::plain("Monospaced", 12.0)));
        theme.add_icon("error", IconValue::new("icon.error", IconPath::new("images/error.png")));

        let output = ThemeWriter::write(&theme);
        assert!(output.contains("color.bg="));
        assert!(output.contains("color.fg="));
        assert!(output.contains("font.default="));
        assert!(output.contains("icon.error=images/error.png"));

        // Parse it back
        let parsed = ThemeReader::parse("RoundtripTest", &output);
        assert_eq!(parsed.colors.len(), theme.colors.len());
        assert_eq!(parsed.fonts.len(), theme.fonts.len());
        assert_eq!(parsed.icons.len(), theme.icons.len());
    }

    #[test]
    fn test_write_empty_theme() {
        let theme = ThemeFile::new("Empty");
        let output = ThemeWriter::write(&theme);
        assert!(output.contains("# Ghidra Theme: Empty"));
    }

    #[test]
    fn test_write_sorted_keys() {
        let mut theme = ThemeFile::new("Sorted");
        theme.add_color("z", ColorValue::new("color.z", RgbaColor::new(0, 0, 0)));
        theme.add_color("a", ColorValue::new("color.a", RgbaColor::new(255, 255, 255)));
        let output = ThemeWriter::write(&theme);
        let a_pos = output.find("color.a").unwrap();
        let z_pos = output.find("color.z").unwrap();
        assert!(a_pos < z_pos);
    }
}
