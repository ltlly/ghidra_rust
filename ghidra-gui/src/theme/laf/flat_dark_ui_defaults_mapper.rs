//! Port of `generic.theme.laf.FlatDarkUiDefaultsMapper`.
//!
//! Stores FlatLaf Dark-specific UIDefaults key/value pairs for
//! theme color, font, and property mapping.

/// FlatLaf Dark look-and-feel UIDefaults mapper.
///
/// Stores the dark-theme UIDefaults key-value pairs that can be applied
/// to the Ghidra theme system when FlatLaf Dark is active.
///
/// Ported from Ghidra's `FlatDarkUiDefaultsMapper`.
#[derive(Debug, Clone)]
pub struct FlatDarkUiDefaultsMapper {
    /// UIDefaults key-value pairs for the FlatLaf Dark theme.
    entries: Vec<(String, String)>,
    /// Whether to apply Ghidra theme overrides.
    apply_theme_overrides: bool,
}

impl FlatDarkUiDefaultsMapper {
    /// Create a new mapper with FlatLaf Dark defaults.
    pub fn new() -> Self {
        let mut m = Self { entries: Vec::new(), apply_theme_overrides: true };
        m.set("Panel.background", "#2b2b2b"); m.set("Panel.foreground", "#bbbbbb");
        m.set("List.background", "#3c3f41"); m.set("List.foreground", "#bbbbbb");
        m.set("Tree.background", "#3c3f41"); m.set("Tree.foreground", "#bbbbbb");
        m.set("Table.background", "#3c3f41"); m.set("Table.foreground", "#bbbbbb");
        m.set("Button.background", "#3c3f41"); m.set("Button.foreground", "#bbbbbb");
        m.set("MenuBar.background", "#2b2b2b"); m.set("MenuItem.background", "#2b2b2b");
        m.set("TextField.background", "#454947"); m.set("TextField.foreground", "#bbbbbb");
        m.set("SplitPane.background", "#3c3f41"); m.set("TabbedPane.background", "#2b2b2b");
        m
    }

    fn set(&mut self, k: &str, v: &str) {
        self.entries.push((k.into(), v.into()));
    }

    /// Get the UIDefaults entries.
    pub fn entries(&self) -> &[(String, String)] { &self.entries }

    /// Whether Ghidra theme overrides should be applied.
    pub fn apply_theme_overrides(&self) -> bool { self.apply_theme_overrides }

    /// Get a value by key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// Number of entries.
    pub fn len(&self) -> usize { self.entries.len() }

    /// Whether the mapper is empty.
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

impl Default for FlatDarkUiDefaultsMapper {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        let m = FlatDarkUiDefaultsMapper::new();
        assert!(!m.is_empty());
        assert_eq!(m.get("Panel.background"), Some("#2b2b2b"));
    }

    #[test]
    fn test_apply_theme_overrides() {
        let m = FlatDarkUiDefaultsMapper::new();
        assert!(m.apply_theme_overrides());
    }
}
