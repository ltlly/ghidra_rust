//! Built-in theme definitions.
//!
//! Port of Ghidra's `generic.theme.builtin` package.
//!
//! Each struct represents a built-in application theme with its own
//! color, font, and icon defaults. The themes correspond to the
//! Look-and-Feel (LAF) types supported by the platform.

use super::color_value::ColorValue;
use super::font_value::FontValue;
use super::g_theme::GTheme;
use super::icon_value::IconValue;
use super::laf_type::LafType;
use crate::gui_util::web_colors::{RgbaColor, WebColors};
use crate::options::option_value::FontDescriptor;

/// Helper to parse a hex color string (e.g. "#ff0000") into an RgbaColor.
///
/// Returns black on parse failure.
fn color(hex: &str) -> RgbaColor {
    WebColors::parse(hex).unwrap_or(RgbaColor::new(0, 0, 0))
}

/// Helper to create a FontDescriptor.
fn font(family: &str, size: f32) -> FontDescriptor {
    FontDescriptor::plain(family, size)
}

/// Trait implemented by all built-in themes.
///
/// Each built-in theme provides default color, font, and icon
/// values that are appropriate for its LAF type.
pub trait BuiltinTheme: std::fmt::Debug {
    /// The unique name of this theme.
    fn name(&self) -> &str;

    /// The LAF type this theme is associated with.
    fn laf_type(&self) -> LafType;

    /// Populate the theme with default colors, fonts, and icons.
    fn populate_theme(&self, theme: &mut GTheme);

    /// Build a complete GTheme from this theme's defaults.
    fn build_theme(&self) -> GTheme {
        let mut theme = GTheme::with_laf(self.name(), self.laf_type());
        self.populate_theme(&mut theme);
        theme
    }
}

/// FlatLaf Dark theme.
///
/// A modern dark theme using the FlatLaf look-and-feel.
/// This is the recommended theme for dark mode usage.
#[derive(Debug, Clone, Default)]
pub struct FlatDarkTheme;

impl BuiltinTheme for FlatDarkTheme {
    fn name(&self) -> &str {
        "Ghidra Flat Dark"
    }

    fn laf_type(&self) -> LafType {
        LafType::FlatDark
    }

    fn populate_theme(&self, theme: &mut GTheme) {
        // Colors
        theme.set_color("color.bg", color("#1e1e1e"));
        theme.set_color("color.fg", color("#d4d4d4"));
        theme.set_color("color.bg.listing", color("#1e1e1e"));
        theme.set_color("color.fg.listing", color("#d4d4d4"));
        theme.set_color("color.bg.input", color("#252526"));
        theme.set_color("color.bg.highlight", color("#264f78"));
        theme.set_color("color.fg.highlight", color("#ffffff"));
        theme.set_color("color.bg.table", color("#1e1e1e"));
        theme.set_color("color.fg.table", color("#cccccc"));
        theme.set_color("color.border", color("#3c3c3c"));
        theme.set_color("color.tree.bg", color("#1e1e1e"));
        theme.set_color("color.tree.fg", color("#d4d4d4"));
        theme.set_color("color.button.bg", color("#333333"));
        theme.set_color("color.menu.bg", color("#2d2d2d"));
        theme.set_color("color.menu.fg", color("#cccccc"));
        theme.set_color("color.scrollbar", color("#424242"));
        theme.set_color("color.status.bg", color("#007acc"));
        theme.set_color("color.status.fg", color("#ffffff"));
        // Fonts
        theme.set_font("font.fixed", font("Courier New", 14.0));
        theme.set_font("font.var", font("SansSerif", 13.0));
        theme.set_font("font.listing", font("Courier New", 13.0));
        theme.set_font("font.menu", font("SansSerif", 13.0));
    }
}

/// FlatLaf Light theme.
///
/// A modern light theme using the FlatLaf look-and-feel.
#[derive(Debug, Clone, Default)]
pub struct FlatLightTheme;

impl BuiltinTheme for FlatLightTheme {
    fn name(&self) -> &str {
        "Ghidra Flat Light"
    }

    fn laf_type(&self) -> LafType {
        LafType::FlatLight
    }

    fn populate_theme(&self, theme: &mut GTheme) {
        theme.set_color("color.bg", color("#ffffff"));
        theme.set_color("color.fg", color("#1e1e1e"));
        theme.set_color("color.bg.listing", color("#ffffff"));
        theme.set_color("color.fg.listing", color("#1e1e1e"));
        theme.set_color("color.bg.input", color("#f5f5f5"));
        theme.set_color("color.bg.highlight", color("#add6ff"));
        theme.set_color("color.fg.highlight", color("#000000"));
        theme.set_color("color.bg.table", color("#ffffff"));
        theme.set_color("color.fg.table", color("#333333"));
        theme.set_color("color.border", color("#cccccc"));
        theme.set_color("color.tree.bg", color("#ffffff"));
        theme.set_color("color.tree.fg", color("#1e1e1e"));
        theme.set_color("color.button.bg", color("#f0f0f0"));
        theme.set_color("color.menu.bg", color("#f5f5f5"));
        theme.set_color("color.menu.fg", color("#1e1e1e"));
        theme.set_color("color.scrollbar", color("#c1c1c1"));
        theme.set_color("color.status.bg", color("#007acc"));
        theme.set_color("color.status.fg", color("#ffffff"));
        theme.set_font("font.fixed", font("Courier New", 14.0));
        theme.set_font("font.var", font("SansSerif", 13.0));
        theme.set_font("font.listing", font("Courier New", 13.0));
        theme.set_font("font.menu", font("SansSerif", 13.0));
    }
}

/// Metal theme -- the classic Java Metal look-and-feel.
#[derive(Debug, Clone, Default)]
pub struct MetalTheme;

impl BuiltinTheme for MetalTheme {
    fn name(&self) -> &str { "Metal" }
    fn laf_type(&self) -> LafType { LafType::Metal }
    fn populate_theme(&self, theme: &mut GTheme) {
        theme.set_color("color.bg", color("#ece9d8"));
        theme.set_color("color.fg", color("#000000"));
        theme.set_color("color.bg.listing", color("#ffffff"));
        theme.set_color("color.fg.listing", color("#000000"));
        theme.set_color("color.bg.highlight", color("#316ac5"));
        theme.set_color("color.fg.highlight", color("#ffffff"));
        theme.set_color("color.border", color("#808080"));
        theme.set_color("color.menu.bg", color("#ece9d8"));
        theme.set_color("color.menu.fg", color("#000000"));
        theme.set_font("font.fixed", font("Monospaced", 13.0));
        theme.set_font("font.var", font("Dialog", 12.0));
        theme.set_font("font.listing", font("Monospaced", 13.0));
        theme.set_font("font.menu", font("Dialog", 12.0));
    }
}

/// Nimbus theme -- the modern Nimbus look-and-feel.
#[derive(Debug, Clone, Default)]
pub struct NimbusTheme;

impl BuiltinTheme for NimbusTheme {
    fn name(&self) -> &str { "Nimbus" }
    fn laf_type(&self) -> LafType { LafType::Nimbus }
    fn populate_theme(&self, theme: &mut GTheme) {
        theme.set_color("color.bg", color("#f2f2f2"));
        theme.set_color("color.fg", color("#000000"));
        theme.set_color("color.bg.listing", color("#ffffff"));
        theme.set_color("color.fg.listing", color("#000000"));
        theme.set_color("color.bg.highlight", color("#3d80df"));
        theme.set_color("color.fg.highlight", color("#ffffff"));
        theme.set_color("color.border", color("#a0a0a0"));
        theme.set_color("color.menu.bg", color("#f2f2f2"));
        theme.set_color("color.menu.fg", color("#000000"));
        theme.set_font("font.fixed", font("Monospaced", 13.0));
        theme.set_font("font.var", font("SansSerif", 13.0));
        theme.set_font("font.listing", font("Monospaced", 13.0));
        theme.set_font("font.menu", font("SansSerif", 13.0));
    }
}

/// GTK theme -- the GTK look-and-feel for Linux.
#[derive(Debug, Clone, Default)]
pub struct GTKTheme;

impl BuiltinTheme for GTKTheme {
    fn name(&self) -> &str { "GTK" }
    fn laf_type(&self) -> LafType { LafType::Gtk }
    fn populate_theme(&self, theme: &mut GTheme) {
        // GTK colors are typically determined by the system theme
        theme.set_color("color.bg", color("#ece9d8"));
        theme.set_color("color.fg", color("#000000"));
        theme.set_color("color.bg.listing", color("#ffffff"));
        theme.set_color("color.fg.listing", color("#000000"));
        theme.set_color("color.bg.highlight", color("#316ac5"));
        theme.set_color("color.fg.highlight", color("#ffffff"));
        theme.set_font("font.fixed", font("Monospace", 13.0));
        theme.set_font("font.var", font("Sans", 13.0));
        theme.set_font("font.listing", font("Monospace", 13.0));
        theme.set_font("font.menu", font("Sans", 13.0));
    }
}

/// macOS theme.
#[derive(Debug, Clone, Default)]
pub struct MacTheme;

impl BuiltinTheme for MacTheme {
    fn name(&self) -> &str { "Mac" }
    fn laf_type(&self) -> LafType { LafType::Mac }
    fn populate_theme(&self, theme: &mut GTheme) {
        theme.set_color("color.bg", color("#ececec"));
        theme.set_color("color.fg", color("#000000"));
        theme.set_color("color.bg.listing", color("#ffffff"));
        theme.set_color("color.fg.listing", color("#000000"));
        theme.set_color("color.bg.highlight", color("#3b78d8"));
        theme.set_color("color.fg.highlight", color("#ffffff"));
        theme.set_color("color.border", color("#bebebe"));
        theme.set_color("color.menu.bg", color("#f6f6f6"));
        theme.set_color("color.menu.fg", color("#000000"));
        theme.set_font("font.fixed", font("Menlo", 13.0));
        theme.set_font("font.var", font("Lucida Grande", 13.0));
        theme.set_font("font.listing", font("Menlo", 13.0));
        theme.set_font("font.menu", font("Lucida Grande", 13.0));
    }
}

/// Windows theme.
#[derive(Debug, Clone, Default)]
pub struct WindowsTheme;

impl BuiltinTheme for WindowsTheme {
    fn name(&self) -> &str { "Windows" }
    fn laf_type(&self) -> LafType { LafType::Windows }
    fn populate_theme(&self, theme: &mut GTheme) {
        theme.set_color("color.bg", color("#f0f0f0"));
        theme.set_color("color.fg", color("#000000"));
        theme.set_color("color.bg.listing", color("#ffffff"));
        theme.set_color("color.fg.listing", color("#000000"));
        theme.set_color("color.bg.highlight", color("#3399ff"));
        theme.set_color("color.fg.highlight", color("#ffffff"));
        theme.set_color("color.border", color("#a0a0a0"));
        theme.set_color("color.menu.bg", color("#f0f0f0"));
        theme.set_color("color.menu.fg", color("#000000"));
        theme.set_font("font.fixed", font("Consolas", 14.0));
        theme.set_font("font.var", font("Segoe UI", 12.0));
        theme.set_font("font.listing", font("Consolas", 13.0));
        theme.set_font("font.menu", font("Segoe UI", 12.0));
    }
}

/// Windows Classic theme (pre-XP style).
#[derive(Debug, Clone, Default)]
pub struct WindowsClassicTheme;

impl BuiltinTheme for WindowsClassicTheme {
    fn name(&self) -> &str { "Windows Classic" }
    fn laf_type(&self) -> LafType { LafType::WindowsClassic }
    fn populate_theme(&self, theme: &mut GTheme) {
        theme.set_color("color.bg", color("#c0c0c0"));
        theme.set_color("color.fg", color("#000000"));
        theme.set_color("color.bg.listing", color("#ffffff"));
        theme.set_color("color.fg.listing", color("#000000"));
        theme.set_color("color.bg.highlight", color("#000080"));
        theme.set_color("color.fg.highlight", color("#ffffff"));
        theme.set_color("color.border", color("#808080"));
        theme.set_color("color.menu.bg", color("#c0c0c0"));
        theme.set_color("color.menu.fg", color("#000000"));
        theme.set_font("font.fixed", font("Courier New", 13.0));
        theme.set_font("font.var", font("MS Sans Serif", 11.0));
        theme.set_font("font.listing", font("Courier New", 13.0));
        theme.set_font("font.menu", font("MS Sans Serif", 11.0));
    }
}

/// CDE/Motif theme.
#[derive(Debug, Clone, Default)]
pub struct CDEMotifTheme;

impl BuiltinTheme for CDEMotifTheme {
    fn name(&self) -> &str { "CDE/Motif" }
    fn laf_type(&self) -> LafType { LafType::Motif }
    fn populate_theme(&self, theme: &mut GTheme) {
        theme.set_color("color.bg", color("#b4b4b4"));
        theme.set_color("color.fg", color("#000000"));
        theme.set_color("color.bg.listing", color("#ffffff"));
        theme.set_color("color.fg.listing", color("#000000"));
        theme.set_color("color.bg.highlight", color("#000080"));
        theme.set_color("color.fg.highlight", color("#ffffff"));
        theme.set_color("color.border", color("#808080"));
        theme.set_color("color.menu.bg", color("#b4b4b4"));
        theme.set_color("color.menu.fg", color("#000000"));
        theme.set_font("font.fixed", font("Courier", 13.0));
        theme.set_font("font.var", font("Helvetica", 12.0));
        theme.set_font("font.listing", font("Courier", 13.0));
        theme.set_font("font.menu", font("Helvetica", 12.0));
    }
}

/// Get all built-in themes.
pub fn all_builtin_themes() -> Vec<Box<dyn BuiltinTheme>> {
    vec![
        Box::new(FlatDarkTheme),
        Box::new(FlatLightTheme),
        Box::new(MetalTheme),
        Box::new(NimbusTheme),
        Box::new(GTKTheme),
        Box::new(MacTheme),
        Box::new(WindowsTheme),
        Box::new(WindowsClassicTheme),
        Box::new(CDEMotifTheme),
    ]
}

/// Get a built-in theme by name.
pub fn get_builtin_theme(name: &str) -> Option<Box<dyn BuiltinTheme>> {
    let themes = all_builtin_themes();
    themes.into_iter().find(|t| t.name() == name)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_themes_count() {
        let themes = all_builtin_themes();
        assert_eq!(themes.len(), 9);
    }

    #[test]
    fn test_all_themes_have_names() {
        for theme in all_builtin_themes() {
            assert!(!theme.name().is_empty());
        }
    }

    #[test]
    fn test_all_themes_build_valid_themes() {
        for theme in all_builtin_themes() {
            let gtheme = theme.build_theme();
            assert_eq!(gtheme.name(), theme.name());
            assert_eq!(gtheme.look_and_feel(), theme.laf_type());
        }
    }

    #[test]
    fn test_flat_dark_theme() {
        let theme = FlatDarkTheme;
        assert_eq!(theme.name(), "Ghidra Flat Dark");
        assert_eq!(theme.laf_type(), LafType::FlatDark);
        let gtheme = theme.build_theme();
        let values = gtheme.values();
        let bg = values.get_color("color.bg").unwrap();
        assert_eq!(bg.raw_value(), Some(RgbaColor::from_rgb(0x1e1e1e)));
    }

    #[test]
    fn test_flat_light_theme() {
        let theme = FlatLightTheme;
        assert_eq!(theme.name(), "Ghidra Flat Light");
        assert_eq!(theme.laf_type(), LafType::FlatLight);
        let gtheme = theme.build_theme();
        let values = gtheme.values();
        let bg = values.get_color("color.bg").unwrap();
        assert_eq!(bg.raw_value(), Some(RgbaColor::new(255, 255, 255)));
    }

    #[test]
    fn test_metal_theme() {
        let theme = MetalTheme;
        assert_eq!(theme.name(), "Metal");
        assert_eq!(theme.laf_type(), LafType::Metal);
        let gtheme = theme.build_theme();
        assert_eq!(gtheme.look_and_feel(), LafType::Metal);
    }

    #[test]
    fn test_nimbus_theme() {
        let gtheme = NimbusTheme.build_theme();
        assert_eq!(gtheme.name(), "Nimbus");
        assert_eq!(gtheme.look_and_feel(), LafType::Nimbus);
    }

    #[test]
    fn test_gtk_theme() {
        let gtheme = GTKTheme.build_theme();
        assert_eq!(gtheme.name(), "GTK");
        assert_eq!(gtheme.look_and_feel(), LafType::Gtk);
    }

    #[test]
    fn test_mac_theme() {
        let gtheme = MacTheme.build_theme();
        assert_eq!(gtheme.name(), "Mac");
        assert_eq!(gtheme.look_and_feel(), LafType::Mac);
    }

    #[test]
    fn test_windows_theme() {
        let gtheme = WindowsTheme.build_theme();
        assert_eq!(gtheme.name(), "Windows");
        assert_eq!(gtheme.look_and_feel(), LafType::Windows);
    }

    #[test]
    fn test_windows_classic_theme() {
        let gtheme = WindowsClassicTheme.build_theme();
        assert_eq!(gtheme.name(), "Windows Classic");
        assert_eq!(gtheme.look_and_feel(), LafType::WindowsClassic);
    }

    #[test]
    fn test_cde_motif_theme() {
        let gtheme = CDEMotifTheme.build_theme();
        assert_eq!(gtheme.name(), "CDE/Motif");
        assert_eq!(gtheme.look_and_feel(), LafType::Motif);
    }

    #[test]
    fn test_get_builtin_theme() {
        let theme = get_builtin_theme("Ghidra Flat Dark");
        assert!(theme.is_some());
        assert_eq!(theme.unwrap().name(), "Ghidra Flat Dark");

        let missing = get_builtin_theme("NonExistent");
        assert!(missing.is_none());
    }

    #[test]
    fn test_all_themes_have_font_values() {
        for theme in all_builtin_themes() {
            let gtheme = theme.build_theme();
            let values = gtheme.values();
            assert!(
                values.get_font("font.fixed").is_some(),
                "Theme {} missing font.fixed",
                theme.name()
            );
            assert!(
                values.get_font("font.var").is_some(),
                "Theme {} missing font.var",
                theme.name()
            );
        }
    }

    #[test]
    fn test_theme_font_values() {
        let gtheme = FlatDarkTheme.build_theme();
        let values = gtheme.values();
        let fixed = values.get_font("font.fixed").unwrap();
        let raw = fixed.raw_value().unwrap();
        assert_eq!(raw.family, "Courier New");
        assert_eq!(raw.size, 14.0);
    }

    #[test]
    fn test_color_helper() {
        let c = color("#ff0000");
        assert_eq!(c.r, 255);
        assert_eq!(c.g, 0);
        assert_eq!(c.b, 0);
    }

    #[test]
    fn test_color_helper_invalid() {
        let c = color("not-a-color");
        assert_eq!(c, RgbaColor::new(0, 0, 0));
    }
}
