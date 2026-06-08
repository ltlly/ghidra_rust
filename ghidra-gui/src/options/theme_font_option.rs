//! Port of `ghidra.framework.options.ThemeFontOption`.
//!
//! An option implementation that binds to a theme font ID. When changed, it
//! affects the current theme rather than being stored with normal options.

use super::option_type::OptionType;
use super::option_value::{FontDescriptor, OptionValue};
use crate::gui_util::help_location::HelpLocation;

/// An option that is bound to a theme font ID.
///
/// Ported from Ghidra's `ghidra.framework.options.ThemeFontOption`.
/// When this option's value changes, it updates the theme font directly
/// rather than being saved with normal non-theme-related options.
#[derive(Debug, Clone)]
pub struct ThemeFontOption {
    /// The option name.
    name: String,
    /// The theme font ID (e.g., "font.listing").
    font_id: String,
    /// The current font descriptor.
    current_font: FontDescriptor,
    /// The default font descriptor.
    default_font: FontDescriptor,
    /// Help location for this option.
    help_location: Option<HelpLocation>,
    /// Description of the option.
    description: Option<String>,
    /// Whether the font has been changed from the default.
    is_changed: bool,
}

impl ThemeFontOption {
    /// Create a new theme font option.
    pub fn new(
        name: impl Into<String>,
        font_id: impl Into<String>,
        default_font: FontDescriptor,
    ) -> Self {
        Self {
            name: name.into(),
            font_id: font_id.into(),
            current_font: default_font.clone(),
            default_font,
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

    /// Get the theme font ID.
    pub fn font_id(&self) -> &str {
        &self.font_id
    }

    /// Get the current font descriptor.
    pub fn current_font(&self) -> &FontDescriptor {
        &self.current_font
    }

    /// Get the default font descriptor.
    pub fn default_font(&self) -> &FontDescriptor {
        &self.default_font
    }

    /// Set the current font descriptor.
    pub fn set_font(&mut self, font: FontDescriptor) {
        self.current_font = font;
        self.is_changed = self.current_font != self.default_font;
    }

    /// Get the option type.
    pub fn option_type(&self) -> OptionType {
        OptionType::FontType
    }

    /// Whether the current font differs from the default.
    pub fn is_changed(&self) -> bool {
        self.is_changed
    }

    /// Restore the default font.
    pub fn restore_default(&mut self) {
        self.current_font = self.default_font.clone();
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
        OptionValue::Font(self.current_font.clone())
    }

    /// Get the default value as an `OptionValue`.
    pub fn get_default_value(&self) -> OptionValue {
        OptionValue::Font(self.default_font.clone())
    }

    /// Get a CSS-like font specification string for the current font.
    pub fn to_font_spec(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.current_font.is_italic() {
            parts.push("italic".to_string());
        }
        if self.current_font.is_bold() {
            parts.push("bold".to_string());
        }
        parts.push(self.current_font.family.clone());
        parts.push(format!("{}pt", self.current_font.size));
        parts.join(" ")
    }
}

impl std::fmt::Display for ThemeFontOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ThemeFontOption: name='{}', font_id='{}', font={}{}",
            self.name,
            self.font_id,
            self.to_font_spec(),
            if self.is_changed { " (changed)" } else { "" },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_theme_font_option_new() {
        let opt = ThemeFontOption::new(
            "Listing Font",
            "font.listing",
            FontDescriptor::plain("SansSerif", 12.0),
        );
        assert_eq!(opt.name(), "Listing Font");
        assert_eq!(opt.font_id(), "font.listing");
        assert_eq!(opt.current_font().family, "SansSerif");
        assert_eq!(opt.current_font().size, 12.0);
    }

    #[test]
    fn test_theme_font_option_default_not_changed() {
        let opt = ThemeFontOption::new(
            "Test",
            "font.test",
            FontDescriptor::plain("Mono", 10.0),
        );
        assert!(!opt.is_changed());
    }

    #[test]
    fn test_theme_font_option_set_and_change() {
        let mut opt = ThemeFontOption::new(
            "Test",
            "font.test",
            FontDescriptor::plain("Mono", 10.0),
        );
        opt.set_font(FontDescriptor::bold("Arial", 14.0));
        assert!(opt.is_changed());
        assert_eq!(opt.current_font().family, "Arial");
        assert!(opt.current_font().is_bold());
    }

    #[test]
    fn test_theme_font_option_restore_default() {
        let mut opt = ThemeFontOption::new(
            "Test",
            "font.test",
            FontDescriptor::plain("Mono", 10.0),
        );
        opt.set_font(FontDescriptor::bold("Arial", 14.0));
        assert!(opt.is_changed());
        opt.restore_default();
        assert!(!opt.is_changed());
        assert_eq!(opt.current_font().family, "Mono");
    }

    #[test]
    fn test_theme_font_option_type() {
        let opt = ThemeFontOption::new(
            "Test",
            "font.test",
            FontDescriptor::plain("Mono", 10.0),
        );
        assert_eq!(opt.option_type(), OptionType::FontType);
    }

    #[test]
    fn test_theme_font_option_with_description() {
        let opt = ThemeFontOption::new(
            "Test",
            "font.test",
            FontDescriptor::plain("Mono", 10.0),
        )
        .with_description("Font for the code listing");
        assert_eq!(opt.description(), Some("Font for the code listing"));
    }

    #[test]
    fn test_theme_font_option_with_help() {
        let opt = ThemeFontOption::new(
            "Test",
            "font.test",
            FontDescriptor::plain("Mono", 10.0),
        )
        .with_help_location(HelpLocation::new("MyPlugin", "font_help"));
        assert!(opt.help_location().is_some());
    }

    #[test]
    fn test_theme_font_option_values() {
        let opt = ThemeFontOption::new(
            "Test",
            "font.test",
            FontDescriptor::bold("Courier", 14.0),
        );
        match opt.get_current_value() {
            OptionValue::Font(f) => {
                assert_eq!(f.family, "Courier");
                assert!(f.is_bold());
                assert_eq!(f.size, 14.0);
            }
            _ => panic!("Expected Font value"),
        }
    }

    #[test]
    fn test_theme_font_option_font_spec() {
        let opt = ThemeFontOption::new(
            "Test",
            "font.test",
            FontDescriptor::new("Helvetica", 3, 18.0),
        );
        let spec = opt.to_font_spec();
        assert!(spec.contains("italic"));
        assert!(spec.contains("bold"));
        assert!(spec.contains("Helvetica"));
        assert!(spec.contains("18pt"));
    }

    #[test]
    fn test_theme_font_option_display() {
        let opt = ThemeFontOption::new(
            "Code Font",
            "font.code",
            FontDescriptor::plain("Mono", 10.0),
        );
        let s = format!("{}", opt);
        assert!(s.contains("Code Font"));
        assert!(s.contains("font.code"));
    }
}
