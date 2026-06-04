//! Port of `generic.theme.GThemeDefaults` and `generic.theme.ApplicationThemeDefaults`.
//!
//! Provides default theme values and application-level default theme definitions.

use std::collections::HashMap;

use super::color_value::ColorValue;
use super::font_value::FontValue;
use crate::gui_util::web_colors::RgbaColor;
use crate::options::option_value::FontDescriptor;

/// Default theme color values.
///
/// Mirrors `generic.theme.GThemeDefaults.Colors`.
pub struct DefaultColors;

impl DefaultColors {
    /// Get the default color for a given id.
    pub fn get(id: &str) -> Option<ColorValue> {
        Self::all().get(id).cloned()
    }

    /// Get all default colors.
    pub fn all() -> HashMap<String, ColorValue> {
        let mut m = HashMap::new();
        m.insert("color.bg".into(), ColorValue::new("color.bg", RgbaColor::new(255, 255, 255)));
        m.insert("color.fg".into(), ColorValue::new("color.fg", RgbaColor::new(0, 0, 0)));
        m.insert("color.bg.darkest".into(), ColorValue::new("color.bg.darkest", RgbaColor::new(32, 32, 32)));
        m.insert("color.bg.darker".into(), ColorValue::new("color.bg.darker", RgbaColor::new(64, 64, 64)));
        m.insert("color.bg.dark".into(), ColorValue::new("color.bg.dark", RgbaColor::new(128, 128, 128)));
        m.insert("color.bg.light".into(), ColorValue::new("color.bg.light", RgbaColor::new(220, 220, 220)));
        m.insert("color.bg.lighter".into(), ColorValue::new("color.bg.lighter", RgbaColor::new(240, 240, 240)));
        m.insert("color.bg.lightest".into(), ColorValue::new("color.bg.lightest", RgbaColor::new(250, 250, 250)));
        m.insert("color.fg.darkest".into(), ColorValue::new("color.fg.darkest", RgbaColor::new(255, 255, 255)));
        m.insert("color.fg.darker".into(), ColorValue::new("color.fg.darker", RgbaColor::new(220, 220, 220)));
        m.insert("color.fg.dark".into(), ColorValue::new("color.fg.dark", RgbaColor::new(192, 192, 192)));
        m.insert("color.fg.light".into(), ColorValue::new("color.fg.light", RgbaColor::new(128, 128, 128)));
        m.insert("color.fg.lighter".into(), ColorValue::new("color.fg.lighter", RgbaColor::new(64, 64, 64)));
        m.insert("color.fg.lightest".into(), ColorValue::new("color.fg.lightest", RgbaColor::new(32, 32, 32)));
        m.insert("color.border".into(), ColorValue::new("color.border", RgbaColor::new(160, 160, 160)));
        m.insert("color.selection.bg".into(), ColorValue::new("color.selection.bg", RgbaColor::new(51, 153, 255)));
        m.insert("color.selection.fg".into(), ColorValue::new("color.selection.fg", RgbaColor::new(255, 255, 255)));
        m.insert("color.cursor".into(), ColorValue::new("color.cursor", RgbaColor::new(0, 0, 0)));
        m
    }
}

/// Default theme font values.
///
/// Mirrors `generic.theme.GThemeDefaults.Fonts`.
pub struct DefaultFonts;

impl DefaultFonts {
    /// Get the default font for a given id.
    pub fn get(id: &str) -> Option<FontValue> {
        Self::all().get(id).cloned()
    }

    /// Get all default fonts.
    pub fn all() -> HashMap<String, FontValue> {
        let mut m = HashMap::new();
        m.insert("font.default".into(), FontValue::new("font.default", FontDescriptor::plain("Monospaced", 12.0)));
        m.insert("font.fixed".into(), FontValue::new("font.fixed", FontDescriptor::plain("Monospaced", 12.0)));
        m.insert("font.var".into(), FontValue::new("font.var", FontDescriptor::plain("SansSerif", 12.0)));
        m
    }
}

/// Application-level default theme definitions.
///
/// Mirrors `generic.theme.ApplicationThemeDefaults`.
pub struct ApplicationThemeDefaults;

impl ApplicationThemeDefaults {
    /// Get the application default theme name.
    pub fn default_theme_name() -> &'static str {
        "Default"
    }

    /// Get all application default color overrides (for dark themes).
    pub fn dark_colors() -> HashMap<String, ColorValue> {
        let mut m = HashMap::new();
        m.insert("color.bg".into(), ColorValue::new("color.bg", RgbaColor::new(40, 44, 52)));
        m.insert("color.fg".into(), ColorValue::new("color.fg", RgbaColor::new(171, 178, 191)));
        m.insert("color.bg.darkest".into(), ColorValue::new("color.bg.darkest", RgbaColor::new(22, 24, 28)));
        m.insert("color.bg.darker".into(), ColorValue::new("color.bg.darker", RgbaColor::new(30, 33, 39)));
        m.insert("color.bg.dark".into(), ColorValue::new("color.bg.dark", RgbaColor::new(36, 40, 47)));
        m.insert("color.bg.light".into(), ColorValue::new("color.bg.light", RgbaColor::new(55, 60, 70)));
        m.insert("color.bg.lighter".into(), ColorValue::new("color.bg.lighter", RgbaColor::new(65, 70, 80)));
        m.insert("color.bg.lightest".into(), ColorValue::new("color.bg.lightest", RgbaColor::new(80, 85, 95)));
        m.insert("color.fg.darkest".into(), ColorValue::new("color.fg.darkest", RgbaColor::new(255, 255, 255)));
        m.insert("color.fg.darker".into(), ColorValue::new("color.fg.darker", RgbaColor::new(220, 223, 228)));
        m.insert("color.fg.dark".into(), ColorValue::new("color.fg.dark", RgbaColor::new(180, 183, 190)));
        m.insert("color.fg.light".into(), ColorValue::new("color.fg.light", RgbaColor::new(130, 133, 140)));
        m.insert("color.fg.lighter".into(), ColorValue::new("color.fg.lighter", RgbaColor::new(90, 93, 100)));
        m.insert("color.fg.lightest".into(), ColorValue::new("color.fg.lightest", RgbaColor::new(60, 63, 70)));
        m.insert("color.border".into(), ColorValue::new("color.border", RgbaColor::new(60, 65, 75)));
        m.insert("color.selection.bg".into(), ColorValue::new("color.selection.bg", RgbaColor::new(62, 68, 81)));
        m.insert("color.selection.fg".into(), ColorValue::new("color.selection.fg", RgbaColor::new(255, 255, 255)));
        m.insert("color.cursor".into(), ColorValue::new("color.cursor", RgbaColor::new(171, 178, 191)));
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_colors() {
        let bg = DefaultColors::get("color.bg").unwrap();
        assert_eq!(bg.raw_value(), Some(RgbaColor::new(255, 255, 255)));

        let fg = DefaultColors::get("color.fg").unwrap();
        assert_eq!(fg.raw_value(), Some(RgbaColor::new(0, 0, 0)));

        assert!(DefaultColors::get("nonexistent").is_none());
    }

    #[test]
    fn test_default_colors_count() {
        let colors = DefaultColors::all();
        assert!(colors.len() >= 10);
    }

    #[test]
    fn test_default_fonts() {
        let f = DefaultFonts::get("font.default").unwrap();
        let fd = f.raw_value().unwrap();
        assert_eq!(fd.family, "Monospaced");
        assert_eq!(fd.size, 12.0);
    }

    #[test]
    fn test_application_dark_colors() {
        let dark = ApplicationThemeDefaults::dark_colors();
        let bg = dark.get("color.bg").unwrap();
        let color = bg.raw_value().unwrap();
        assert_eq!(color.r, 40);
        assert!(color.r < 100); // dark background
    }

    #[test]
    fn test_default_theme_name() {
        assert_eq!(ApplicationThemeDefaults::default_theme_name(), "Default");
    }
}
