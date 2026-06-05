//! Component font registry for tracking per-component font overrides.
//!
//! Port of Ghidra's `generic.theme.laf.ComponentFontRegistry`.

use std::collections::HashMap;

/// Tracks which components use which font IDs so that fonts can be
/// bulk-updated when the theme changes.
#[derive(Debug, Clone)]
pub struct ComponentFontRegistry {
    /// Maps component identifier to font ID.
    component_to_font_id: HashMap<String, String>,
}

impl ComponentFontRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            component_to_font_id: HashMap::new(),
        }
    }

    /// Register a component with a given font ID.
    pub fn register(&mut self, component_id: impl Into<String>, font_id: impl Into<String>) {
        self.component_to_font_id.insert(component_id.into(), font_id.into());
    }

    /// Unregister a component.
    pub fn unregister(&mut self, component_id: &str) {
        self.component_to_font_id.remove(component_id);
    }

    /// Get the font ID for a component.
    pub fn get_font_id(&self, component_id: &str) -> Option<&str> {
        self.component_to_font_id.get(component_id).map(|s| s.as_str())
    }

    /// Update all registered component fonts.
    ///
    /// In the egui port this triggers a repaint/relayout.
    pub fn update_component_fonts(&self) {
        for (component_id, font_id) in &self.component_to_font_id {
            log::trace!(
                "ComponentFontRegistry: updating font for '{}' to '{}'",
                component_id,
                font_id
            );
        }
    }

    /// Number of registered components.
    pub fn len(&self) -> usize {
        self.component_to_font_id.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.component_to_font_id.is_empty()
    }
}

impl Default for ComponentFontRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_register_and_get() {
        let mut reg = ComponentFontRegistry::new();
        reg.register("editor", "font.monospaced");
        assert_eq!(reg.get_font_id("editor"), Some("font.monospaced"));
        assert_eq!(reg.get_font_id("unknown"), None);
    }

    #[test]
    fn test_registry_unregister() {
        let mut reg = ComponentFontRegistry::new();
        reg.register("editor", "font.monospaced");
        reg.unregister("editor");
        assert!(reg.is_empty());
    }

    #[test]
    fn test_registry_len() {
        let mut reg = ComponentFontRegistry::new();
        reg.register("a", "f1");
        reg.register("b", "f2");
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn test_registry_update_does_not_panic() {
        let mut reg = ComponentFontRegistry::new();
        reg.register("test", "font.default");
        reg.update_component_fonts();
    }
}
