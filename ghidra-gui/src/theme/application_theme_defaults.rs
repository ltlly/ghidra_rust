//! Port of Ghidra's `generic.theme.ApplicationThemeDefaults`.

use std::collections::HashMap;

/// Provides default color and font values for an application theme.
pub trait ApplicationThemeDefaults: Send + Sync + std::fmt::Debug {
    /// Get the name of the theme.
    fn theme_name(&self) -> &str;
    /// Get default color values as (id, hex_value) pairs.
    fn default_colors(&self) -> HashMap<String, String>;
    /// Get default font values as (id, font_spec) pairs.
    fn default_fonts(&self) -> HashMap<String, String>;
    /// Get default icon values as (id, icon_path) pairs.
    fn default_icons(&self) -> HashMap<String, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestDefaults;
    impl ApplicationThemeDefaults for TestDefaults {
        fn theme_name(&self) -> &str { "test" }
        fn default_colors(&self) -> HashMap<String, String> {
            let mut m = HashMap::new();
            m.insert("bg".into(), "#FFFFFF".into());
            m.insert("fg".into(), "#000000".into());
            m
        }
        fn default_fonts(&self) -> HashMap<String, String> { HashMap::new() }
        fn default_icons(&self) -> HashMap<String, String> { HashMap::new() }
    }

    #[test]
    fn test_theme_defaults() {
        let td = TestDefaults;
        assert_eq!(td.theme_name(), "test");
        assert_eq!(td.default_colors().len(), 2);
        assert_eq!(td.default_colors()["bg"], "#FFFFFF");
    }
}
