//! Theme manager singleton.
//!
//! Ports `generic.theme.ThemeManager`.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::color_value::ColorValue;
use super::font_value::FontValue;
use super::g_theme::GTheme;
use super::g_theme_value_map::GThemeValueMap;
use super::laf_type::LafType;
use super::theme_event::{ThemeEvent, ThemeListener};
use crate::gui_util::web_colors::RgbaColor;
use crate::options::option_value::FontDescriptor;

/// Default color used when a theme color is not found.
pub const DEFAULT_COLOR: RgbaColor = RgbaColor::new(0, 255, 255); // Cyan

/// Default font used when a theme font is not found.
pub fn default_font() -> FontDescriptor {
    FontDescriptor::plain("Dialog", 12.0)
}

/// Minimum font size.
const MIN_FONT_SIZE: f32 = 3.0;

/// Manages application themes and their values.
///
/// Ported from Ghidra's `generic.theme.ThemeManager`.
pub struct ThemeManager {
    active_theme: GTheme,
    active_laf_type: LafType,
    use_dark_defaults: bool,
    /// Java/look-and-feel defaults.
    java_defaults: GThemeValueMap,
    /// Application-level defaults from theme.properties files.
    application_defaults: GThemeValueMap,
    /// The currently resolved values (defaults + user overrides).
    current_values: GThemeValueMap,
    /// Registered theme listeners.
    listeners: Vec<Arc<dyn ThemeListener>>,
}

impl ThemeManager {
    /// Create a new theme manager with the given theme.
    pub fn new(theme: GTheme) -> Self {
        let laf = theme.look_and_feel();
        let use_dark = theme.uses_dark_defaults();
        Self {
            active_theme: theme,
            active_laf_type: laf,
            use_dark_defaults: use_dark,
            java_defaults: GThemeValueMap::new(),
            application_defaults: GThemeValueMap::new(),
            current_values: GThemeValueMap::new(),
            listeners: Vec::new(),
        }
    }

    /// Get the active theme.
    pub fn active_theme(&self) -> &GTheme {
        &self.active_theme
    }

    /// Get the active LAF type.
    pub fn active_laf_type(&self) -> LafType {
        self.active_laf_type
    }

    /// Whether dark defaults are in use.
    pub fn uses_dark_defaults(&self) -> bool {
        self.use_dark_defaults
    }

    /// Get the current resolved values.
    pub fn current_values(&self) -> &GThemeValueMap {
        &self.current_values
    }

    /// Set the java (LAF) defaults.
    pub fn set_java_defaults(&mut self, defaults: GThemeValueMap) {
        self.java_defaults = defaults;
    }

    /// Set the application defaults.
    pub fn set_application_defaults(&mut self, defaults: GThemeValueMap) {
        self.application_defaults = defaults;
    }

    /// Register a theme listener.
    pub fn add_theme_listener(&mut self, listener: Arc<dyn ThemeListener>) {
        self.listeners.push(listener);
    }

    /// Get a resolved color by id.
    pub fn get_color(&self, id: &str) -> RgbaColor {
        self.current_values
            .get_resolved_color(id)
            .unwrap_or(DEFAULT_COLOR)
    }

    /// Get a resolved font by id.
    pub fn get_font(&self, id: &str) -> FontDescriptor {
        self.current_values
            .get_resolved_font(id)
            .unwrap_or_else(default_font)
    }

    /// Set a color value.
    pub fn set_color(&mut self, value: ColorValue) {
        self.current_values.add_color(value.clone());
        self.active_theme.values_mut().add_color(value);
    }

    /// Set a font value.
    pub fn set_font(&mut self, value: FontValue) {
        self.current_values.add_font(value.clone());
        self.active_theme.values_mut().add_font(value);
    }

    /// Adjust all font sizes by the given amount.
    pub fn adjust_fonts(&mut self, amount: f32) {
        let font_ids: Vec<String> = self.current_values.get_font_ids().iter().map(|s| s.to_string()).collect();
        for id in font_ids {
            if let Some(fv) = self.current_values.get_font(&id) {
                if let Some(font) = fv.raw_value() {
                    let new_size = (font.size + amount).max(MIN_FONT_SIZE);
                    let new_font = font.derive_size(new_size);
                    let new_fv = FontValue::new(&id, new_font);
                    self.current_values.add_font(new_fv);
                }
            }
        }
    }

    /// Apply a theme change event.
    pub fn apply_theme_event(&mut self, event: ThemeEvent) {
        self.notify_theme_changed(&event);
    }

    /// Notify all listeners of a theme change.
    fn notify_theme_changed(&self, event: &ThemeEvent) {
        for listener in &self.listeners {
            listener.theme_changed(event);
        }
    }
}

impl std::fmt::Debug for ThemeManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThemeManager")
            .field("active_theme", &self.active_theme.name())
            .field("active_laf", &self.active_laf_type)
            .field("listeners", &self.listeners.len())
            .finish()
    }
}

/// Get the default theme for the platform.
pub fn get_default_theme() -> GTheme {
    GTheme::new("Default")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct TestListener {
        called: AtomicBool,
    }

    impl TestListener {
        fn new() -> Self {
            Self { called: AtomicBool::new(false) }
        }
    }

    impl ThemeListener for TestListener {
        fn theme_changed(&self, _event: &ThemeEvent) {
            self.called.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_theme_manager_new() {
        let theme = GTheme::new("Test");
        let tm = ThemeManager::new(theme);
        assert_eq!(tm.active_theme().name(), "Test");
    }

    #[test]
    fn test_theme_manager_get_color() {
        let mut theme = GTheme::new("Test");
        theme.set_color("color.bg", RgbaColor::new(10, 20, 30));
        let mut tm = ThemeManager::new(theme);
        tm.current_values.add_color(ColorValue::new("color.bg", RgbaColor::new(10, 20, 30)));
        assert_eq!(tm.get_color("color.bg"), RgbaColor::new(10, 20, 30));
    }

    #[test]
    fn test_theme_manager_missing_color_returns_default() {
        let theme = GTheme::new("Test");
        let tm = ThemeManager::new(theme);
        assert_eq!(tm.get_color("color.missing"), DEFAULT_COLOR);
    }

    #[test]
    fn test_theme_manager_listener() {
        let theme = GTheme::new("Test");
        let mut tm = ThemeManager::new(theme);
        let listener = Arc::new(TestListener::new());
        tm.add_theme_listener(listener.clone());
        tm.apply_theme_event(ThemeEvent::color_changed("color.bg"));
        assert!(listener.called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_theme_manager_adjust_fonts() {
        let mut theme = GTheme::new("Test");
        theme.set_font("font.mono", FontDescriptor::plain("Courier", 12.0));
        let mut tm = ThemeManager::new(theme);
        tm.current_values.add_font(FontValue::new("font.mono", FontDescriptor::plain("Courier", 12.0)));
        tm.adjust_fonts(4.0);
        let font = tm.current_values.get_resolved_font("font.mono").unwrap();
        assert_eq!(font.size, 16.0);
    }

    #[test]
    fn test_theme_manager_set_color() {
        let theme = GTheme::new("Test");
        let mut tm = ThemeManager::new(theme);
        tm.set_color(ColorValue::new("color.new", RgbaColor::new(1, 2, 3)));
        assert_eq!(tm.get_color("color.new"), RgbaColor::new(1, 2, 3));
    }

    #[test]
    fn test_default_theme() {
        let theme = get_default_theme();
        assert_eq!(theme.name(), "Default");
    }
}
