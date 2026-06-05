//! Port of `generic.theme.laf.NimbusUiDefaultsMapper`.
//!
//! Stores Nimbus-specific UIDefaults key/value pairs.

/// Nimbus look-and-feel UIDefaults mapper.
#[derive(Debug, Clone)]
pub struct NimbusUiDefaultsMapper {
    entries: Vec<(String, String)>,
    apply_theme_overrides: bool,
}

impl NimbusUiDefaultsMapper {
    pub fn new() -> Self {
        let mut m = Self { entries: Vec::new(), apply_theme_overrides: true };
        m.set("nimbusBase", "#33628c"); m.set("nimbusBlueGrey", "#a5b0b5");
        m.set("nimbusSelectionBackground", "#39698a"); m.set("nimbusSelectedText", "#ffffff");
        m.set("nimbusLightBackground", "#f5f5f5"); m.set("nimbusBorder", "#b8c0c5");
        m.set("Panel.background", "#f5f5f5"); m.set("Panel.foreground", "#303030");
        m.set("Tree.background", "#f5f5f5"); m.set("Tree.foreground", "#303030");
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

impl Default for NimbusUiDefaultsMapper { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_defaults() { let m = NimbusUiDefaultsMapper::new(); assert!(!m.is_empty()); assert_eq!(m.get("nimbusBase"), Some("#33628c")); }
}
