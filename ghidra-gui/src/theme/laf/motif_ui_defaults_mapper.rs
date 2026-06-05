//! Port of `generic.theme.laf.MotifUiDefaultsMapper`.
//!
//! Stores Motif-specific UIDefaults key/value pairs.

/// Motif look-and-feel UIDefaults mapper.
#[derive(Debug, Clone)]
pub struct MotifUiDefaultsMapper {
    entries: Vec<(String, String)>,
    apply_theme_overrides: bool,
}

impl MotifUiDefaultsMapper {
    pub fn new() -> Self {
        let mut m = Self { entries: Vec::new(), apply_theme_overrides: true };
        m.set("Panel.background", "#c0c0c0"); m.set("Panel.foreground", "#000000");
        m.set("Button.background", "#c0c0c0"); m.set("Button.foreground", "#000000");
        m.set("TextField.background", "#ffffff"); m.set("TextField.foreground", "#000000");
        m.set("List.background", "#ffffff"); m.set("List.foreground", "#000000");
        m.set("MenuBar.background", "#c0c0c0");
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

impl Default for MotifUiDefaultsMapper { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_defaults() { let m = MotifUiDefaultsMapper::new(); assert!(!m.is_empty()); assert_eq!(m.get("Panel.background"), Some("#c0c0c0")); }
}
