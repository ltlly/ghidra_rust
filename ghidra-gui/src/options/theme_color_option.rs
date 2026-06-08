//! Port of `ghidra.framework.options.ThemeColorOption`.
//!
//! An option implementation that binds to a theme color ID. When changed, it
//! affects the current theme rather than being stored with normal options.

use super::option_type::OptionType;
use super::option_value::OptionValue;
use crate::gui_util::help_location::HelpLocation;
use crate::gui_util::web_colors::RgbaColor;

/// An option that is bound to a theme color ID.
///
/// Ported from Ghidra's `ghidra.framework.options.ThemeColorOption`.
/// When this option's value changes, it updates the theme color directly
/// rather than being saved with normal non-theme-related options.
#[derive(Debug, Clone)]
pub struct ThemeColorOption {
    /// The option name.
    name: String,
    /// The theme color ID (e.g., "color.bg.listing").
    color_id: String,
    /// The current color value.
    current_color: RgbaColor,
    /// The default color value.
    default_color: RgbaColor,
    /// Help location for this option.
    help_location: Option<HelpLocation>,
    /// Description of the option.
    description: Option<String>,
    /// Whether the color has been changed from the default.
    is_changed: bool,
}

impl ThemeColorOption {
    /// Create a new theme color option.
    pub fn new(
        name: impl Into<String>,
        color_id: impl Into<String>,
        default_color: RgbaColor,
    ) -> Self {
        Self {
            name: name.into(),
            color_id: color_id.into(),
            current_color: default_color,
            default_color,
            help_location: None,
            description: None,
            is_changed: false,
        }
    }

    /// Set the help location.
    pub fn with_help_location(mut self, help: HelpLocation) -> Self {
        self.help_location = Some(help);
        self
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Get the option name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the theme color ID.
    pub fn color_id(&self) -> &str {
        &self.color_id
    }

    /// Get the current color value.
    pub fn current_color(&self) -> &RgbaColor {
        &self.current_color
    }

    /// Get the default color value.
    pub fn default_color(&self) -> &RgbaColor {
        &self.default_color
    }

    /// Set the current color value.
    pub fn set_color(&mut self, color: RgbaColor) {
        self.current_color = color;
        self.is_changed = self.current_color != self.default_color;
    }

    /// Get the option type.
    pub fn option_type(&self) -> OptionType {
        OptionType::ColorType
    }

    /// Whether the current color differs from the default.
    pub fn is_changed(&self) -> bool {
        self.is_changed
    }

    /// Restore the default color.
    pub fn restore_default(&mut self) {
        self.current_color = self.default_color;
        self.is_changed = false;
    }

    /// Get the help location.
    pub fn help_location(&self) -> Option<&HelpLocation> {
        self.help_location.as_ref()
    }

    /// Get the description.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Get the current value as an `OptionValue`.
    pub fn get_current_value(&self) -> OptionValue {
        OptionValue::Color(self.current_color)
    }

    /// Get the default value as an `OptionValue`.
    pub fn get_default_value(&self) -> OptionValue {
        OptionValue::Color(self.default_color)
    }
}

impl std::fmt::Display for ThemeColorOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ThemeColorOption: name='{}', color_id='{}', color=#{:02X}{:02X}{:02X}{}",
            self.name,
            self.color_id,
            self.current_color.r,
            self.current_color.g,
            self.current_color.b,
            if self.is_changed { " (changed)" } else { "" },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_theme_color_option_new() {
        let opt = ThemeColorOption::new("BG Color", "color.bg", RgbaColor::new(255, 255, 255));
        assert_eq!(opt.name(), "BG Color");
        assert_eq!(opt.color_id(), "color.bg");
        assert_eq!(opt.current_color().r, 255);
    }

    #[test]
    fn test_theme_color_option_default_not_changed() {
        let opt = ThemeColorOption::new("Test", "color.test", RgbaColor::new(0, 0, 0));
        assert!(!opt.is_changed());
    }

    #[test]
    fn test_theme_color_option_set_and_change() {
        let mut opt = ThemeColorOption::new("FG", "color.fg", RgbaColor::new(0, 0, 0));
        opt.set_color(RgbaColor::new(255, 0, 0));
        assert!(opt.is_changed());
        assert_eq!(opt.current_color().r, 255);
    }

    #[test]
    fn test_theme_color_option_restore_default() {
        let mut opt = ThemeColorOption::new("FG", "color.fg", RgbaColor::new(0, 0, 0));
        opt.set_color(RgbaColor::new(255, 0, 0));
        assert!(opt.is_changed());
        opt.restore_default();
        assert!(!opt.is_changed());
        assert_eq!(opt.current_color().r, 0);
    }

    #[test]
    fn test_theme_color_option_type() {
        let opt = ThemeColorOption::new("Test", "color.test", RgbaColor::new(0, 0, 0));
        assert_eq!(opt.option_type(), OptionType::ColorType);
    }

    #[test]
    fn test_theme_color_option_with_description() {
        let opt = ThemeColorOption::new("Test", "color.test", RgbaColor::new(0, 0, 0))
            .with_description("Background color for listings");
        assert_eq!(opt.description(), Some("Background color for listings"));
    }

    #[test]
    fn test_theme_color_option_with_help() {
        let opt = ThemeColorOption::new("Test", "color.test", RgbaColor::new(0, 0, 0))
            .with_help_location(HelpLocation::new("MyPlugin", "color_help"));
        assert!(opt.help_location().is_some());
    }

    #[test]
    fn test_theme_color_option_values() {
        let opt = ThemeColorOption::new("Test", "color.test", RgbaColor::new(10, 20, 30));
        match opt.get_current_value() {
            OptionValue::Color(c) => {
                assert_eq!(c.r, 10);
                assert_eq!(c.g, 20);
                assert_eq!(c.b, 30);
            }
            _ => panic!("Expected Color value"),
        }
        match opt.get_default_value() {
            OptionValue::Color(c) => {
                assert_eq!(c.r, 10);
                assert_eq!(c.g, 20);
                assert_eq!(c.b, 30);
            }
            _ => panic!("Expected Color value"),
        }
    }

    #[test]
    fn test_theme_color_option_display() {
        let opt = ThemeColorOption::new("BG", "color.bg", RgbaColor::new(255, 255, 255));
        let s = format!("{}", opt);
        assert!(s.contains("BG"));
        assert!(s.contains("color.bg"));
        assert!(s.contains("FFFFFF"));
    }
}
