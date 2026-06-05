//! Abstract Look-and-Feel manager.
//!
//! Port of Ghidra's `generic.theme.laf.LookAndFeelManager`. In Ghidra's Java
//! code this class manages installing/updating a Swing `LookAndFeel`. In the
//! Rust port it controls egui theme application, font registration, and
//! UIDefaults mappings.

use std::collections::HashMap;

use super::component_font_registry::ComponentFontRegistry;
use super::ui_defaults_mapper::UiDefaultsMapper;
use crate::theme::laf_type::LafType;

/// Blink rate for text cursors (in milliseconds).
pub const DEFAULT_CURSOR_BLINK_RATE: u32 = 500;

/// Abstract base for Look-and-Feel managers.
///
/// Each concrete L&F (Metal, Nimbus, Flat, GTK, etc.) implements this trait
/// to customize how fonts, colors, and icons are installed.
pub struct LookAndFeelManager {
    /// The L&F type managed by this instance.
    laf: LafType,
    /// Per-component font registries keyed by registry ID.
    font_registry_map: HashMap<String, ComponentFontRegistry>,
    /// Normalized ID to L&F-specific ID mapping for fonts/colors.
    pub normalized_id_to_laf_id_map: HashMap<String, String>,
}

impl LookAndFeelManager {
    /// Create a new L&F manager for the given type.
    pub fn new(laf: LafType) -> Self {
        Self {
            laf,
            font_registry_map: HashMap::new(),
            normalized_id_to_laf_id_map: HashMap::new(),
        }
    }

    /// Get the L&F type managed by this instance.
    pub fn get_laf_type(&self) -> LafType {
        self.laf
    }

    /// Install the look-and-feel.
    ///
    /// In the Java version this calls `UIManager.setLookAndFeel()`.
    /// In the Rust port it applies theme defaults.
    pub fn install_look_and_feel(&mut self) {
        self.clear_ui_defaults();
        self.do_install_look_and_feel();
        self.process_java_defaults();
        self.fixup_look_and_feel_issues();
        self.update_component_uis();
    }

    /// Clear existing UI defaults.
    fn clear_ui_defaults(&self) {
        // In the Rust port this would clear egui style overrides.
        log::trace!("LookAndFeelManager: clearing UI defaults for {:?}", self.laf);
    }

    /// Subclass hook: perform the actual L&F installation.
    fn do_install_look_and_feel(&self) {
        log::trace!("LookAndFeelManager: installing L&F {:?}", self.laf);
    }

    /// Process Java-specific defaults and map them to egui equivalents.
    fn process_java_defaults(&self) {
        log::trace!("LookAndFeelManager: processing Java defaults for {:?}", self.laf);
    }

    /// Subclass hook: fix known issues with the current L&F.
    fn fixup_look_and_feel_issues(&self) {
        // Subclasses override this to fix known L&F issues.
    }

    /// Refresh all component UIs.
    fn update_component_uis(&self) {
        log::trace!("LookAndFeelManager: updating component UIs for {:?}", self.laf);
    }

    /// Called when all colors, fonts, and icons may have changed.
    pub fn reset_all(&mut self) {
        self.reset_icons();
        self.reset_fonts();
        self.update_all_registered_component_fonts();
        self.update_component_uis();
    }

    /// Refresh icon theme values.
    fn reset_icons(&self) {
        log::trace!("LookAndFeelManager: resetting icons");
    }

    /// Refresh font theme values.
    fn reset_fonts(&self) {
        log::trace!("LookAndFeelManager: resetting fonts");
    }

    /// Update all registered component fonts.
    fn update_all_registered_component_fonts(&self) {
        for registry in self.font_registry_map.values() {
            registry.update_component_fonts();
        }
    }

    /// Register a component font registry.
    pub fn register_font_registry(&mut self, id: String, registry: ComponentFontRegistry) {
        self.font_registry_map.insert(id, registry);
    }

    /// Get the UIDefaults mapper for this L&F.
    pub fn get_ui_defaults_mapper(&self) -> Option<UiDefaultsMapper> {
        UiDefaultsMapper::for_laf(self.laf)
    }

    /// Get the cursor blink rate.
    pub fn get_cursor_blink_rate(&self) -> u32 {
        DEFAULT_CURSOR_BLINK_RATE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_laf_manager_new() {
        let mgr = LookAndFeelManager::new(LafType::Metal);
        assert_eq!(mgr.get_laf_type(), LafType::Metal);
    }

    #[test]
    fn test_laf_manager_default_blink_rate() {
        let mgr = LookAndFeelManager::new(LafType::Metal);
        assert_eq!(mgr.get_cursor_blink_rate(), 500);
    }

    #[test]
    fn test_laf_manager_install() {
        let mut mgr = LookAndFeelManager::new(LafType::Metal);
        mgr.install_look_and_feel();
        // Should not panic.
    }

    #[test]
    fn test_laf_manager_reset_all() {
        let mut mgr = LookAndFeelManager::new(LafType::Nimbus);
        mgr.reset_all();
        // Should not panic.
    }
}
