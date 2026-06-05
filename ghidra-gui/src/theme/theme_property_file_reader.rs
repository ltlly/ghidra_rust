//! ThemePropertyFileReader: parses theme .properties files.
//!
//! Ported from `generic.theme.ThemePropertyFileReader`.

use std::collections::HashMap;
use std::io::BufRead;

use super::color_value::ColorValue;
use super::font_value::FontValue;
use super::g_theme_value_map::GThemeValueMap;
use super::icon_value::{IconPath, IconValue};
use super::laf_type::LafType;
use crate::gui_util::web_colors::RgbaColor;
use crate::options::option_value::FontDescriptor;

/// Result of parsing a theme properties file.
#[derive(Debug, Clone)]
pub struct ThemePropertyFileReaderResult {
    pub defaults: GThemeValueMap,
    pub dark_defaults: GThemeValueMap,
    pub laf_sections: HashMap<LafType, GThemeValueMap>,
}

/// Read and parse a theme properties file from a reader.
pub fn read_theme_properties<R: BufRead>(reader: R) -> std::io::Result<ThemePropertyFileReaderResult> {
    let mut defaults = GThemeValueMap::new();
    let mut dark_defaults = GThemeValueMap::new();
    let mut laf_sections: HashMap<LafType, GThemeValueMap> = HashMap::new();

    let mut current_section: Option<SectionType> = None;

    for line_result in reader.lines() {
        let line = line_result?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") { continue; }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let name = &trimmed[1..trimmed.len()-1];
            current_section = Some(match name {
                "Default" => SectionType::Default,
                "DarkDefault" => SectionType::DarkDefault,
                other => match LafType::from_name(other) {
                    Some(laf) => SectionType::LookAndFeel(laf),
                    None => continue,
                },
            });
            continue;
        }

        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim().to_string();
            let value = trimmed[eq_pos+1..].trim().to_string();
            let target = match current_section {
                Some(SectionType::Default) => Some(&mut defaults),
                Some(SectionType::DarkDefault) => Some(&mut dark_defaults),
                Some(SectionType::LookAndFeel(laf)) => Some(laf_sections.entry(laf).or_default()),
                None => None,
            };
            if let Some(map) = target {
                apply_value(map, &key, &value);
            }
        }
    }

    Ok(ThemePropertyFileReaderResult { defaults, dark_defaults, laf_sections })
}

fn apply_value(map: &mut GThemeValueMap, key: &str, value: &str) {
    if key.starts_with("color.") {
        if let Some(rgba) = parse_named_color(value) {
            map.add_color(ColorValue::new(key, rgba));
        }
    } else if key.starts_with("font.") {
        map.add_font(FontValue::new(key, FontDescriptor::plain(value, 12.0)));
    } else if key.starts_with("icon.") {
        map.add_icon(IconValue::new(key, IconPath::new(value)));
    }
}

enum SectionType { Default, DarkDefault, LookAndFeel(LafType) }

/// Parse a color name or hex string into an RgbaColor.
pub fn parse_named_color(s: &str) -> Option<RgbaColor> {
    let lower = s.trim().to_lowercase();
    match lower.as_str() {
        "white" => Some(RgbaColor::new(255, 255, 255)),
        "black" => Some(RgbaColor::new(0, 0, 0)),
        "red" => Some(RgbaColor::new(255, 0, 0)),
        "green" => Some(RgbaColor::new(0, 128, 0)),
        "blue" => Some(RgbaColor::new(0, 0, 255)),
        "yellow" => Some(RgbaColor::new(255, 255, 0)),
        "cyan" => Some(RgbaColor::new(0, 255, 255)),
        "magenta" => Some(RgbaColor::new(255, 0, 255)),
        "orange" => Some(RgbaColor::new(255, 165, 0)),
        "gray" | "grey" => Some(RgbaColor::new(128, 128, 128)),
        "silver" => Some(RgbaColor::new(192, 192, 192)),
        _ => parse_hex_color(&lower),
    }
}

fn parse_hex_color(s: &str) -> Option<RgbaColor> {
    let hex = s.strip_prefix('#').unwrap_or(s);
    match hex.len() {
        6 => {
            let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
            let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
            let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
            Some(RgbaColor::new(r, g, b))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    #[test]
    fn parse_basic_properties() {
        let data = "[Default]
color.bg = white
color.fg = black
icon.refresh = images/refresh.png
";
        let result = read_theme_properties(BufReader::new(data.as_bytes())).unwrap();
        assert!(result.defaults.contains_color("color.bg"));
        assert!(result.defaults.contains_icon("icon.refresh"));
    }

    #[test]
    fn parse_hex_color_6() {
        let c = parse_named_color("#FF8000").unwrap();
        assert_eq!(c.r, 255);
        assert_eq!(c.g, 128);
        assert_eq!(c.b, 0);
    }

    #[test]
    fn dark_section_parsed() {
        let data = "[Default]
color.bg = white
[DarkDefault]
color.bg = black
";
        let result = read_theme_properties(BufReader::new(data.as_bytes())).unwrap();
        assert!(result.dark_defaults.contains_color("color.bg"));
    }

    #[test]
    fn laf_section_parsed() {
        let data = "[Default]
color.bg = white
[Flat Dark]
color.bg = gray
";
        let result = read_theme_properties(BufReader::new(data.as_bytes())).unwrap();
        assert!(result.laf_sections.contains_key(&LafType::FlatDark));
    }
}
