//! ApplicationThemeManager: fully-functional theme manager.
//!
//! Ported from `generic.theme.ApplicationThemeManager`.

use std::collections::{HashMap, HashSet};
use super::color_value::ColorValue;
use super::font_value::FontValue;
use super::g_color::{GColor, MISSING_COLOR_RGB};
use super::g_icon::GIcon;
use super::g_theme::GTheme;
use super::g_theme_value_map::GThemeValueMap;
use super::icon_value::IconValue;
use super::laf_type::LafType;
use super::theme_event::ThemeEvent;
use super::theme_manager::ThemeManager;
use crate::gui_util::web_colors::RgbaColor;
use crate::options::option_value::FontDescriptor;

/// Stores user preferences for the active theme.
#[derive(Debug, Clone)]
pub struct ThemePreferences {
    pub active_theme_name: Option<String>,
    pub blinking_cursors: bool,
}

impl Default for ThemePreferences {
    fn default() -> Self { Self { active_theme_name: None, blinking_cursors: true } }
}

/// Fully-functional theme manager used in a running application.
pub struct ApplicationThemeManager {
    all_themes: HashSet<String>,
    active_theme: Option<String>,
    active_laf: LafType,
    use_dark_defaults: bool,
    pub preferences: ThemePreferences,
    current_values: GThemeValueMap,
    application_defaults: GThemeValueMap,
    java_defaults: GThemeValueMap,
    changed_values: GThemeValueMap,
    blinking_cursors: bool,
    gcolor_map: HashMap<String, GColor>,
    inner_manager: ThemeManager,
}

impl ApplicationThemeManager {
    pub fn new() -> Self {
        Self {
            all_themes: HashSet::new(),
            active_theme: None,
            active_laf: LafType::FlatLight,
            use_dark_defaults: false,
            preferences: ThemePreferences::default(),
            current_values: GThemeValueMap::new(),
            application_defaults: GThemeValueMap::new(),
            java_defaults: GThemeValueMap::new(),
            changed_values: GThemeValueMap::new(),
            blinking_cursors: true,
            gcolor_map: HashMap::new(),
            inner_manager: ThemeManager::new(GTheme::new("Default")),
        }
    }

    pub fn set_theme(&mut self, theme: GTheme) {
        self.active_theme = Some(theme.name().to_string());
        self.active_laf = theme.look_and_feel();
        self.use_dark_defaults = theme.uses_dark_defaults();
        self.inner_manager = ThemeManager::new(theme);
        self.rebuild_current_values();
    }

    pub fn set_application_defaults(&mut self, defaults: GThemeValueMap) {
        self.application_defaults = defaults;
        self.rebuild_current_values();
    }

    pub fn set_java_defaults(&mut self, defaults: GThemeValueMap) {
        self.java_defaults = defaults;
        self.rebuild_current_values();
    }

    pub fn set_color(&mut self, value: ColorValue) {
        let id = value.id().to_string();
        let current = self.current_values.get_color(&id);
        if current == Some(&value) { return; }
        self.changed_values.add_color(value.clone());
        self.current_values.add_color(value);
    }

    pub fn set_font(&mut self, value: FontValue) {
        let id = value.id().to_string();
        let current = self.current_values.get_font(&id);
        if current == Some(&value) { return; }
        self.changed_values.add_font(value.clone());
        self.current_values.add_font(value);
    }

    pub fn has_theme_changes(&self) -> bool { !self.changed_values.is_empty() }
    pub fn blinking_cursors(&self) -> bool { self.blinking_cursors }
    pub fn active_laf(&self) -> LafType { self.active_laf }
    pub fn active_theme_name(&self) -> Option<&str> { self.active_theme.as_deref() }
    pub fn is_dark_theme(&self) -> bool { self.use_dark_defaults }
    pub fn all_themes(&self) -> &HashSet<String> { &self.all_themes }
    pub fn register_theme(&mut self, name: String) { self.all_themes.insert(name); }
    pub fn delete_theme(&mut self, name: &str) { self.all_themes.remove(name); }
    pub fn current_values(&self) -> &GThemeValueMap { &self.current_values }
    pub fn inner(&self) -> &ThemeManager { &self.inner_manager }

    pub fn restore_theme_values(&mut self) {
        self.changed_values = GThemeValueMap::new();
        self.rebuild_current_values();
    }

    pub fn get_gcolor(&mut self, id: &str) -> GColor {
        if let Some(gc) = self.gcolor_map.get(id) { return gc.clone(); }
        let gc = GColor::new(id);
        self.gcolor_map.insert(id.to_string(), gc.clone());
        gc
    }

    fn rebuild_current_values(&mut self) {
        self.current_values = GThemeValueMap::new();
        self.current_values.merge_from(&self.application_defaults);
        self.current_values.merge_from(&self.java_defaults);
        self.current_values.merge_from(&self.changed_values);
        GColor::refresh_all(&self.current_values.color_table());
        GIcon::refresh_all(&self.current_values.icon_path_table());
    }
}

impl Default for ApplicationThemeManager {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_theme_mgr_new() {
        let m = ApplicationThemeManager::new();
        assert!(m.active_theme_name().is_none());
        assert!(!m.has_theme_changes());
    }

    #[test]
    fn set_color_tracks_changes() {
        let mut m = ApplicationThemeManager::new();
        m.set_color(ColorValue::new("color.test", RgbaColor::new(255, 0, 0)));
        assert!(m.has_theme_changes());
    }

    #[test]
    fn restore_clears_changes() {
        let mut m = ApplicationThemeManager::new();
        m.set_color(ColorValue::new("color.a", RgbaColor::new(0, 0, 0)));
        assert!(m.has_theme_changes());
        m.restore_theme_values();
        assert!(!m.has_theme_changes());
    }

    #[test]
    fn get_gcolor_caches() {
        let mut m = ApplicationThemeManager::new();
        let a = m.get_gcolor("color.cached");
        let b = m.get_gcolor("color.cached");
        assert_eq!(a, b);
    }
}
