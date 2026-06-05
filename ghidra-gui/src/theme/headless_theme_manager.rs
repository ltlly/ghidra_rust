//! HeadlessThemeManager: minimal theme manager for headless environments.
//!
//! Ported from `generic.theme.HeadlessThemeManager`.

use super::color_value::ColorValue;
use super::g_color::{GColor, MISSING_COLOR_RGB};
use super::g_icon::GIcon;
use super::g_theme::GTheme;
use super::g_theme_value_map::GThemeValueMap;
use super::theme_manager::ThemeManager;
use crate::gui_util::web_colors::RgbaColor;

/// Minimal theme manager for headless (no GUI) environments.
pub struct HeadlessThemeManager {
    current_values: GThemeValueMap,
    inner_manager: ThemeManager,
}

impl HeadlessThemeManager {
    pub fn new() -> Self {
        let mut m = Self {
            current_values: GThemeValueMap::new(),
            inner_manager: ThemeManager::new(GTheme::new("Headless")),
        };
        m.initialize_system_values();
        m
    }

    fn initialize_system_values(&mut self) {
        self.current_values.add_color(ColorValue::new("color.bg", RgbaColor::new(255, 255, 255)));
        self.current_values.add_color(ColorValue::new("color.fg", RgbaColor::new(0, 0, 0)));
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
        GIcon::refresh_all(&self.current_values.icon_path_table());
    }

    pub fn set_color(&mut self, value: ColorValue) { self.current_values.add_color(value); }
    pub fn current_values(&self) -> &GThemeValueMap { &self.current_values }
    pub fn inner(&self) -> &ThemeManager { &self.inner_manager }
}

impl Default for HeadlessThemeManager {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headless_mgr_has_palette() {
        let m = HeadlessThemeManager::new();
        assert!(m.current_values().contains_color("color.palette.red"));
        assert!(m.current_values().contains_color("color.palette.blue"));
    }

    #[test]
    fn headless_mgr_set_color() {
        let mut m = HeadlessThemeManager::new();
        m.set_color(ColorValue::new("color.custom", RgbaColor::new(42, 42, 42)));
        assert!(m.current_values().contains_color("color.custom"));
    }
}
