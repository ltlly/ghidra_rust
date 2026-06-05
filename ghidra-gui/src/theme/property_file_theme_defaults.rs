//! Theme defaults loaded from .properties files.
//!
//! Ports `generic.theme.PropertyFileThemeDefaults`.

use std::collections::HashMap;

/// Trait for providing default theme values.
pub trait ApplicationThemeDefaults {
    /// Get the default color for a theme ID.
    fn get_default_color(&self, id: &str) -> Option<String>;
    /// Get the default font for a theme ID.
    fn get_default_font(&self, id: &str) -> Option<String>;
    /// Get the default icon for a theme ID.
    fn get_default_icon(&self, id: &str) -> Option<String>;
}

/// Loads theme default values from Java-style .properties files.
///
/// Each .properties file contains key=value pairs mapping theme IDs
/// to their default color, font, or icon values.
#[derive(Debug, Clone)]
pub struct PropertyFileThemeDefaults {
    /// Color defaults (id -> css color string).
    pub colors: HashMap<String, String>,
    /// Font defaults (id -> font specification string).
    pub fonts: HashMap<String, String>,
    /// Icon defaults (id -> icon path).
    pub icons: HashMap<String, String>,
}

impl PropertyFileThemeDefaults {
    /// Create empty theme defaults.
    pub fn new() -> Self {
        Self {
            colors: HashMap::new(),
            fonts: HashMap::new(),
            icons: HashMap::new(),
        }
    }

    /// Parse a .properties file content into key-value pairs.
    pub fn parse_properties(content: &str) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            if let Some(idx) = line.find('=') {
                let key = line[..idx].trim().to_string();
                let value = line[idx + 1..].trim().to_string();
                map.insert(key, value);
            }
        }
        map
    }

    /// Load colors from a properties string.
    pub fn load_colors(&mut self, content: &str) {
        self.colors.extend(Self::parse_properties(content));
    }

    /// Load fonts from a properties string.
    pub fn load_fonts(&mut self, content: &str) {
        self.fonts.extend(Self::parse_properties(content));
    }

    /// Load icons from a properties string.
    pub fn load_icons(&mut self, content: &str) {
        self.icons.extend(Self::parse_properties(content));
    }

    /// Get a color value by id.
    pub fn get_color(&self, id: &str) -> Option<&str> {
        self.colors.get(id).map(|s| s.as_str())
    }

    /// Get a font value by id.
    pub fn get_font(&self, id: &str) -> Option<&str> {
        self.fonts.get(id).map(|s| s.as_str())
    }

    /// Get an icon value by id.
    pub fn get_icon(&self, id: &str) -> Option<&str> {
        self.icons.get(id).map(|s| s.as_str())
    }
}

impl Default for PropertyFileThemeDefaults {
    fn default() -> Self {
        Self::new()
    }
}

impl ApplicationThemeDefaults for PropertyFileThemeDefaults {
    fn get_default_color(&self, id: &str) -> Option<String> {
        self.colors.get(id).cloned()
    }

    fn get_default_font(&self, id: &str) -> Option<String> {
        self.fonts.get(id).cloned()
    }

    fn get_default_icon(&self, id: &str) -> Option<String> {
        self.icons.get(id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_properties() {
        let content = "# comment\ncolor.bg=#FFFFFF\ncolor.fg=#000000\n// another comment\n";
        let map = PropertyFileThemeDefaults::parse_properties(content);
        assert_eq!(map.get("color.bg").unwrap(), "#FFFFFF");
        assert_eq!(map.get("color.fg").unwrap(), "#000000");
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_load_and_get() {
        let mut defaults = PropertyFileThemeDefaults::new();
        defaults.load_colors("color.bg=#FFF\ncolor.fg=#000");
        assert_eq!(defaults.get_color("color.bg"), Some("#FFF"));
        assert_eq!(defaults.get_color("missing"), None);
    }

    #[test]
    fn test_load_fonts() {
        let mut defaults = PropertyFileThemeDefaults::new();
        defaults.load_fonts("font.listing=Monospaced-12");
        assert_eq!(defaults.get_font("font.listing"), Some("Monospaced-12"));
    }
}
