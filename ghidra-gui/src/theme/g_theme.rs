//! Complete theme with name, LAF type, and all values.
//!
//! Ports `generic.theme.GTheme`.


use super::g_theme_value_map::GThemeValueMap;
use super::laf_type::LafType;
use super::color_value::ColorValue;
use super::font_value::FontValue;
use super::icon_value::IconValue;
use crate::gui_util::web_colors::RgbaColor;
use crate::options::option_value::FontDescriptor;

/// File extension for theme files.
pub const THEME_FILE_EXTENSION: &str = "theme";
/// File extension for zipped theme files.
pub const THEME_ZIP_EXTENSION: &str = "theme.zip";
/// Marker for file-based themes.
pub const FILE_PREFIX: &str = "File:";

/// A complete application theme with a name, look-and-feel type,
/// and all color/font/icon values.
///
/// Ported from Ghidra's `generic.theme.GTheme`.
#[derive(Debug, Clone)]
pub struct GTheme {
    name: String,
    look_and_feel: LafType,
    use_dark_defaults: bool,
    values: GThemeValueMap,
}

impl GTheme {
    /// Create a new theme with the default LAF for the current platform.
    pub fn new(name: impl Into<String>) -> Self {
        Self::with_laf(name, LafType::default_look_and_feel())
    }

    /// Create a new theme with a specific LAF type.
    pub fn with_laf(name: impl Into<String>, laf: LafType) -> Self {
        Self {
            name: name.into(),
            look_and_feel: laf,
            use_dark_defaults: laf.uses_dark_defaults(),
            values: GThemeValueMap::new(),
        }
    }

    /// Get the theme name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the look-and-feel type.
    pub fn look_and_feel(&self) -> LafType {
        self.look_and_feel
    }

    /// Whether this theme uses dark defaults.
    pub fn uses_dark_defaults(&self) -> bool {
        self.use_dark_defaults
    }

    /// Whether the LAF is supported on the current platform.
    pub fn has_supported_laf(&self) -> bool {
        self.look_and_feel.is_supported()
    }

    /// Get a reference to the theme values.
    pub fn values(&self) -> &GThemeValueMap {
        &self.values
    }

    /// Get a mutable reference to the theme values.
    pub fn values_mut(&mut self) -> &mut GThemeValueMap {
        &mut self.values
    }

    /// Set a direct color.
    pub fn set_color(&mut self, id: &str, color: RgbaColor) {
        self.values.add_color(ColorValue::new(id, color));
    }

    /// Set a color reference.
    pub fn set_color_ref(&mut self, id: &str, ref_id: &str) {
        self.values.add_color(ColorValue::with_ref(id, ref_id));
    }

    /// Set a direct font.
    pub fn set_font(&mut self, id: &str, font: FontDescriptor) {
        self.values.add_font(FontValue::new(id, font));
    }

    /// Set a font reference.
    pub fn set_font_ref(&mut self, id: &str, ref_id: &str) {
        self.values.add_font(FontValue::with_ref(id, ref_id));
    }

    /// Set a direct icon.
    pub fn set_icon(&mut self, id: &str, icon: super::icon_value::IconPath) {
        self.values.add_icon(IconValue::new(id, icon));
    }

    /// Set an icon reference.
    pub fn set_icon_ref(&mut self, id: &str, ref_id: &str) {
        self.values.add_icon(IconValue::with_ref(id, ref_id));
    }
}

impl PartialEq for GTheme {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.look_and_feel == other.look_and_feel
    }
}

impl Eq for GTheme {}

impl std::fmt::Display for GTheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtheme_new() {
        let theme = GTheme::new("My Theme");
        assert_eq!(theme.name(), "My Theme");
    }

    #[test]
    fn test_gtheme_with_laf() {
        let theme = GTheme::with_laf("Dark", LafType::FlatDark);
        assert_eq!(theme.look_and_feel(), LafType::FlatDark);
        assert!(theme.uses_dark_defaults());
    }

    #[test]
    fn test_gtheme_set_color() {
        let mut theme = GTheme::new("Test");
        theme.set_color("color.bg", RgbaColor::new(0, 0, 0));
        let resolved = theme.values().get_resolved_color("color.bg");
        assert_eq!(resolved, Some(RgbaColor::new(0, 0, 0)));
    }

    #[test]
    fn test_gtheme_set_font() {
        let mut theme = GTheme::new("Test");
        theme.set_font("font.mono", FontDescriptor::plain("Courier", 12.0));
        let resolved = theme.values().get_resolved_font("font.mono");
        assert!(resolved.is_some());
    }

    #[test]
    fn test_gtheme_set_color_ref() {
        let mut theme = GTheme::new("Test");
        theme.set_color("color.base", RgbaColor::new(128, 128, 128));
        theme.set_color_ref("color.derived", "color.base");
        let resolved = theme.values().get_resolved_color("color.derived");
        assert_eq!(resolved, Some(RgbaColor::new(128, 128, 128)));
    }

    #[test]
    fn test_gtheme_equality() {
        let t1 = GTheme::with_laf("A", LafType::Metal);
        let t2 = GTheme::with_laf("A", LafType::Metal);
        let t3 = GTheme::with_laf("A", LafType::Nimbus);
        assert_eq!(t1, t2);
        assert_ne!(t1, t3);
    }

    #[test]
    fn test_gtheme_display() {
        let theme = GTheme::new("Test Theme");
        assert_eq!(theme.to_string(), "Test Theme");
    }

    #[test]
    fn test_gtheme_has_supported_laf() {
        let theme = GTheme::with_laf("Test", LafType::FlatLight);
        assert!(theme.has_supported_laf());
    }
}
