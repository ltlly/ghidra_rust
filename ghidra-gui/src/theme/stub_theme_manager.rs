//! StubThemeManager: minimal theme manager for unit tests.
//!
//! Ported from `generic.theme.StubThemeManager`.

use super::color_value::ColorValue;
use super::g_color::GColor;
use super::g_theme::GTheme;
use super::g_theme_value_map::GThemeValueMap;
use super::theme_manager::ThemeManager;
use crate::gui_util::web_colors::RgbaColor;

/// Minimal theme manager used in unit tests before the full application
/// theme system is initialized.
pub struct StubThemeManager {
    current_values: GThemeValueMap,
    inner_manager: ThemeManager,
}

impl StubThemeManager {
    pub fn new() -> Self {
        let mut m = Self {
            current_values: GThemeValueMap::new(),
            inner_manager: ThemeManager::new(GTheme::new("Stub")),
        };
        m.install_palette_colors();
        m
    }

    fn install_palette_colors(&mut self) {
        for (name, r, g, b) in &[
            ("nocolor", 0, 0, 0), ("red", 255, 0, 0), ("green", 0, 128, 0),
            ("blue", 0, 0, 255), ("yellow", 255, 255, 0), ("orange", 255, 165, 0),
            ("white", 255, 255, 255), ("black", 0, 0, 0), ("gray", 128, 128, 128),
            ("silver", 192, 192, 192),
        ] {
            let id = format!("color.palette.{}", name);
            self.current_values.add_color(ColorValue::new(&id, RgbaColor::new(*r, *g, *b)));
        }
        GColor::refresh_all(&self.current_values.color_table());
    }

    pub fn set_color(&mut self, value: ColorValue) { self.current_values.add_color(value); }
    pub fn has_color(&self, id: &str) -> bool { self.current_values.contains_color(id) }
    pub fn current_values(&self) -> &GThemeValueMap { &self.current_values }
    pub fn inner(&self) -> &ThemeManager { &self.inner_manager }
}

impl Default for StubThemeManager {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_has_palette_colors() {
        let m = StubThemeManager::new();
        assert!(m.has_color("color.palette.red"));
        assert!(m.has_color("color.palette.blue"));
        assert!(!m.has_color("color.nonexistent"));
    }

    #[test]
    fn stub_set_color() {
        let mut m = StubThemeManager::new();
        m.set_color(ColorValue::new("color.test", RgbaColor::new(1, 2, 3)));
        assert!(m.has_color("color.test"));
    }
}
