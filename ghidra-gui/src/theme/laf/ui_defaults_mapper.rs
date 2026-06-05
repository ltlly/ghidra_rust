//! UIDefaults mapper for look-and-feel specific ID translation.
//!
//! Port of Ghidra's `generic.theme.laf.UiDefaultsMapper` and its concrete
//! implementations (`MotifUiDefaultsMapper`, `FlatDarkUiDefaultsMapper`,
//! `FlatUiDefaultsMapper`, `NimbusUiDefaultsMapper`).
//!
//! Each L&F has its own set of "UIDefaults" keys for colors, fonts, and
//! icons. The mapper translates between Ghidra's normalized IDs and the
//! L&F-specific IDs.

use std::collections::HashMap;
use crate::theme::laf_type::LafType;

/// Maps between Ghidra's normalized theme IDs and L&F-specific UI defaults IDs.
#[derive(Debug, Clone)]
pub struct UiDefaultsMapper {
    /// The L&F type this mapper is for.
    pub laf_type: LafType,
    /// Mapping from normalized ID to L&F-specific ID.
    id_map: HashMap<String, String>,
    /// Default font sizes for this L&F.
    default_font_sizes: HashMap<String, f32>,
}

impl UiDefaultsMapper {
    /// Create a mapper for the given L&F type.
    pub fn new(laf_type: LafType) -> Self {
        let mut mapper = Self {
            laf_type,
            id_map: HashMap::new(),
            default_font_sizes: HashMap::new(),
        };
        mapper.populate_defaults();
        mapper
    }

    /// Create the appropriate mapper for a given L&F type.
    pub fn for_laf(laf_type: LafType) -> Option<Self> {
        Some(Self::new(laf_type))
    }

    /// Get the L&F-specific ID for a normalized ID.
    pub fn get_laf_id(&self, normalized_id: &str) -> Option<&str> {
        self.id_map.get(normalized_id).map(|s| s.as_str())
    }

    /// Get the normalized ID for an L&F-specific ID.
    pub fn get_normalized_id(&self, laf_id: &str) -> Option<&str> {
        self.id_map
            .iter()
            .find(|(_, v)| v.as_str() == laf_id)
            .map(|(k, _)| k.as_str())
    }

    /// Add an ID mapping.
    pub fn add_mapping(&mut self, normalized_id: impl Into<String>, laf_id: impl Into<String>) {
        self.id_map.insert(normalized_id.into(), laf_id.into());
    }

    /// Get the default font size for a font ID.
    pub fn get_default_font_size(&self, font_id: &str) -> Option<f32> {
        self.default_font_sizes.get(font_id).copied()
    }

    /// Set the default font size for a font ID.
    pub fn set_default_font_size(&mut self, font_id: impl Into<String>, size: f32) {
        self.default_font_sizes.insert(font_id.into(), size);
    }

    /// Get all mappings.
    pub fn all_mappings(&self) -> &HashMap<String, String> {
        &self.id_map
    }

    /// Number of ID mappings.
    pub fn len(&self) -> usize {
        self.id_map.len()
    }

    /// Whether the mapper has no mappings.
    pub fn is_empty(&self) -> bool {
        self.id_map.is_empty()
    }

    /// Populate default mappings based on the L&F type.
    fn populate_defaults(&mut self) {
        match self.laf_type {
            LafType::Metal => self.populate_metal_defaults(),
            LafType::Nimbus => self.populate_nimbus_defaults(),
            LafType::FlatLight => self.populate_flat_defaults(),
            LafType::FlatDark => self.populate_flat_dark_defaults(),
            LafType::Gtk => self.populate_gtk_defaults(),
            LafType::Motif => self.populate_motif_defaults(),
            LafType::Windows => self.populate_windows_defaults(),
            LafType::WindowsClassic => self.populate_windows_classic_defaults(),
            LafType::Mac => self.populate_mac_defaults(),
            _ => self.populate_generic_defaults(),
        }
    }

    fn populate_metal_defaults(&mut self) {
        self.add_mapping("color.fg.default", "Panel.foreground");
        self.add_mapping("color.bg.default", "Panel.background");
        self.add_mapping("color.fg.selected", "List.selectionForeground");
        self.add_mapping("color.bg.selected", "List.selectionBackground");
        self.add_mapping("font.default", "Panel.font");
        self.add_mapping("font.monospaced", "TextArea.font");
    }

    fn populate_nimbus_defaults(&mut self) {
        self.add_mapping("color.fg.default", "text");
        self.add_mapping("color.bg.default", "control");
        self.add_mapping("color.fg.selected", "textHighlightText");
        self.add_mapping("color.bg.selected", "textHighlight");
        self.add_mapping("font.default", "defaultFont");
        self.add_mapping("font.monospaced", "monospacedFont");
    }

    fn populate_flat_defaults(&mut self) {
        self.add_mapping("color.fg.default", "foreground");
        self.add_mapping("color.bg.default", "background");
        self.add_mapping("font.default", "defaultFont");
    }

    fn populate_flat_dark_defaults(&mut self) {
        self.add_mapping("color.fg.default", "foreground");
        self.add_mapping("color.bg.default", "background");
        self.add_mapping("font.default", "defaultFont");
    }

    fn populate_gtk_defaults(&mut self) {
        self.add_mapping("color.fg.default", "foreground");
        self.add_mapping("color.bg.default", "background");
        self.add_mapping("font.default", "defaultFont");
    }

    fn populate_motif_defaults(&mut self) {
        self.add_mapping("color.fg.default", "Motif.foreground");
        self.add_mapping("color.bg.default", "Motif.background");
        self.add_mapping("font.default", "Motif.font");
    }

    fn populate_windows_defaults(&mut self) {
        self.add_mapping("color.fg.default", "foreground");
        self.add_mapping("color.bg.default", "background");
        self.add_mapping("font.default", "defaultFont");
    }

    fn populate_windows_classic_defaults(&mut self) {
        self.add_mapping("color.fg.default", "foreground");
        self.add_mapping("color.bg.default", "background");
        self.add_mapping("font.default", "defaultFont");
    }

    fn populate_mac_defaults(&mut self) {
        self.add_mapping("color.fg.default", "foreground");
        self.add_mapping("color.bg.default", "background");
        self.add_mapping("font.default", "defaultFont");
    }

    fn populate_generic_defaults(&mut self) {
        self.add_mapping("color.fg.default", "foreground");
        self.add_mapping("color.bg.default", "background");
        self.add_mapping("font.default", "defaultFont");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mapper_metal() {
        let mapper = UiDefaultsMapper::new(LafType::Metal);
        assert_eq!(mapper.get_laf_id("color.fg.default"), Some("Panel.foreground"));
        assert!(mapper.len() > 0);
    }

    #[test]
    fn test_mapper_nimbus() {
        let mapper = UiDefaultsMapper::new(LafType::Nimbus);
        assert_eq!(mapper.get_laf_id("color.bg.default"), Some("control"));
    }

    #[test]
    fn test_mapper_reverse_lookup() {
        let mapper = UiDefaultsMapper::new(LafType::Metal);
        assert_eq!(mapper.get_normalized_id("Panel.foreground"), Some("color.fg.default"));
    }

    #[test]
    fn test_mapper_font_size() {
        let mut mapper = UiDefaultsMapper::new(LafType::Metal);
        mapper.set_default_font_size("font.default", 14.0);
        assert_eq!(mapper.get_default_font_size("font.default"), Some(14.0));
    }

    #[test]
    fn test_mapper_for_laf() {
        let mapper = UiDefaultsMapper::for_laf(LafType::Gtk);
        assert!(mapper.is_some());
    }

    #[test]
    fn test_mapper_not_empty() {
        let mapper = UiDefaultsMapper::new(LafType::Mac);
        assert!(!mapper.is_empty());
    }
}
