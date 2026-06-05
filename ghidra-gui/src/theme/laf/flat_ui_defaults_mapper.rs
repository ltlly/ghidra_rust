//! Port of `generic.theme.laf.FlatUiDefaultsMapper`.
//!
//! Stores FlatLaf Light-specific UIDefaults key/value pairs.

/// FlatLaf Light look-and-feel UIDefaults mapper.
#[derive(Debug, Clone)]
pub struct FlatUiDefaultsMapper {
    entries: Vec<(String, String)>,
    apply_theme_overrides: bool,
}

impl FlatUiDefaultsMapper {
    pub fn new() -> Self {
        let mut m = Self { entries: Vec::new(), apply_theme_overrides: true };
        m.set("Panel.background", "#f2f2f2"); m.set("Panel.foreground", "#1e1e1e");
        m.set("List.background", "#ffffff"); m.set("List.foreground", "#1e1e1e");
        m.set("Tree.background", "#ffffff"); m.set("Tree.foreground", "#1e1e1e");
        m.set("Button.background", "#f2f2f2"); m.set("Button.foreground", "#1e1e1e");
        m.set("TextField.background", "#ffffff"); m.set("TextField.foreground", "#1e1e1e");
        m
    }
    fn set(&mut self, k: &str, v: &str) { self.entries.push((k.into(), v.into())); }
    pub fn entries(&self) -> &[(String, String)] { &self.entries }
    pub fn apply_theme_overrides(&self) -> bool { self.apply_theme_overrides }
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

impl Default for FlatUiDefaultsMapper { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_defaults() { let m = FlatUiDefaultsMapper::new(); assert!(!m.is_empty()); assert_eq!(m.get("Panel.background"), Some("#f2f2f2")); }
}
