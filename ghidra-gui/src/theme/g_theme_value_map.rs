//! Map of all theme values (colors, fonts, icons).
//!
//! Ports `generic.theme.GThemeValueMap`.

use std::collections::HashMap;

use super::color_value::ColorValue;
use super::font_value::FontValue;
use crate::gui_util::web_colors::RgbaColor;
use crate::options::option_value::FontDescriptor;

/// A map storing all theme values organized by type (colors, fonts, icons).
///
/// Ported from Ghidra's `generic.theme.GThemeValueMap`.
#[derive(Debug, Clone, Default)]
pub struct GThemeValueMap {
    color_map: HashMap<String, ColorValue>,
    font_map: HashMap<String, FontValue>,
    icon_map: HashMap<String, super::icon_value::IconValue>,
}

impl GThemeValueMap {
    /// Create an empty value map.
    pub fn new() -> Self {
        Self::default()
    }

    // -- Color operations --

    /// Add a color value to the map.
    pub fn add_color(&mut self, value: ColorValue) -> Option<ColorValue> {
        self.color_map.insert(value.id().to_string(), value)
    }

    /// Get a color value by id.
    pub fn get_color(&self, id: &str) -> Option<&ColorValue> {
        self.color_map.get(id)
    }

    /// Remove a color value by id.
    pub fn remove_color(&mut self, id: &str) -> Option<ColorValue> {
        self.color_map.remove(id)
    }

    /// Get the resolved color for the given id.
    pub fn get_resolved_color(&self, id: &str) -> Option<RgbaColor> {
        self.color_map.get(id).map(|cv| cv.resolve(self))
    }

    /// Get all color ids.
    pub fn get_color_ids(&self) -> Vec<&str> {
        self.color_map.keys().map(|s| s.as_str()).collect()
    }

    // -- Font operations --

    /// Add a font value to the map.
    pub fn add_font(&mut self, value: FontValue) -> Option<FontValue> {
        self.font_map.insert(value.id().to_string(), value)
    }

    /// Get a font value by id.
    pub fn get_font(&self, id: &str) -> Option<&FontValue> {
        self.font_map.get(id)
    }

    /// Remove a font value by id.
    pub fn remove_font(&mut self, id: &str) -> Option<FontValue> {
        self.font_map.remove(id)
    }

    /// Get the resolved font for the given id.
    pub fn get_resolved_font(&self, id: &str) -> Option<FontDescriptor> {
        self.font_map.get(id).map(|fv| fv.resolve(self))
    }

    /// Get all font ids.
    pub fn get_font_ids(&self) -> Vec<&str> {
        self.font_map.keys().map(|s| s.as_str()).collect()
    }

    // -- Icon operations --

    /// Add an icon value to the map.
    pub fn add_icon(&mut self, value: super::icon_value::IconValue) -> Option<super::icon_value::IconValue> {
        self.icon_map.insert(value.id().to_string(), value)
    }

    /// Get an icon value by id.
    pub fn get_icon(&self, id: &str) -> Option<&super::icon_value::IconValue> {
        self.icon_map.get(id)
    }

    /// Remove an icon value by id.
    pub fn remove_icon(&mut self, id: &str) -> Option<super::icon_value::IconValue> {
        self.icon_map.remove(id)
    }

    /// Get all icon ids.
    pub fn get_icon_ids(&self) -> Vec<&str> {
        self.icon_map.keys().map(|s| s.as_str()).collect()
    }

    // -- Bulk operations --

    /// Load all values from another map into this one (overwrites existing).
    pub fn load(&mut self, other: &GThemeValueMap) {
        for (id, cv) in &other.color_map {
            self.color_map.insert(id.clone(), cv.clone());
        }
        for (id, fv) in &other.font_map {
            self.font_map.insert(id.clone(), fv.clone());
        }
        for (id, iv) in &other.icon_map {
            self.icon_map.insert(id.clone(), iv.clone());
        }
    }

    /// Get a new map containing only values that differ from the base map.
    pub fn get_changed_values(&self, base: &GThemeValueMap) -> GThemeValueMap {
        let mut changed = GThemeValueMap::new();
        for (id, cv) in &self.color_map {
            if base.color_map.get(id) != Some(cv) {
                changed.color_map.insert(id.clone(), cv.clone());
            }
        }
        for (id, fv) in &self.font_map {
            if base.font_map.get(id) != Some(fv) {
                changed.font_map.insert(id.clone(), fv.clone());
            }
        }
        for (id, iv) in &self.icon_map {
            if base.icon_map.get(id) != Some(iv) {
                changed.icon_map.insert(id.clone(), iv.clone());
            }
        }
        changed
    }

    /// Get all color values.
    pub fn colors(&self) -> &HashMap<String, ColorValue> {
        &self.color_map
    }

    /// Get all font values.
    pub fn fonts(&self) -> &HashMap<String, FontValue> {
        &self.font_map
    }

    /// Get all icon values.
    pub fn icons(&self) -> &HashMap<String, super::icon_value::IconValue> {
        &self.icon_map
    }

    /// Total number of values across all maps.
    pub fn len(&self) -> usize {
        self.color_map.len() + self.font_map.len() + self.icon_map.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.color_map.is_empty() && self.font_map.is_empty() && self.icon_map.is_empty()
    }

    /// Merge all values from another map into this one (overwrites existing).
    /// Alias for [`load`](Self::load).
    pub fn merge_from(&mut self, other: &GThemeValueMap) {
        self.load(other);
    }

    /// Whether the map contains a color with the given id.
    pub fn contains_color(&self, id: &str) -> bool {
        self.color_map.contains_key(id)
    }

    /// Whether the map contains a font with the given id.
    pub fn contains_font(&self, id: &str) -> bool {
        self.font_map.contains_key(id)
    }

    /// Whether the map contains an icon with the given id.
    pub fn contains_icon(&self, id: &str) -> bool {
        self.icon_map.contains_key(id)
    }

    /// Get a property value by id (used by JavaPropertyValue).
    pub fn get_property(&self, id: &str) -> Option<&ColorValue> {
        // Properties are stored as colors for now.
        self.color_map.get(id)
    }

    /// Build a simple id -> RgbaColor table for the GColor refresh mechanism.
    pub fn color_table(&self) -> std::collections::HashMap<String, crate::gui_util::web_colors::RgbaColor> {
        self.color_map
            .iter()
            .filter_map(|(id, cv)| cv.raw_value().map(|c| (id.clone(), c)))
            .collect()
    }

    /// Build a simple id -> icon-path table for the GIcon refresh mechanism.
    pub fn icon_path_table(&self) -> std::collections::HashMap<String, String> {
        self.icon_map
            .iter()
            .filter_map(|(id, iv)| iv.raw_value().map(|p| (id.clone(), p.0.clone())))
            .collect()
    }

    /// Check for unresolved references and log warnings.
    pub fn check_for_unresolved_references(&self) {
        for cv in self.color_map.values() {
            if cv.is_indirect() {
                if let Some(ref_id) = cv.reference_id() {
                    if !self.color_map.contains_key(ref_id) {
                        log::warn!(
                            "Unresolved color reference: {} -> {}",
                            cv.id(),
                            ref_id
                        );
                    }
                }
            }
        }
        for fv in self.font_map.values() {
            if fv.is_indirect() {
                if let Some(ref_id) = fv.reference_id() {
                    if !self.font_map.contains_key(ref_id) {
                        log::warn!("Unresolved font reference: {} -> {}", fv.id(), ref_id);
                    }
                }
            }
        }
        for iv in self.icon_map.values() {
            if iv.is_indirect() {
                if let Some(ref_id) = iv.reference_id() {
                    if !self.icon_map.contains_key(ref_id) {
                        log::warn!("Unresolved icon reference: {} -> {}", iv.id(), ref_id);
                    }
                }
            }
        }
    }
}

impl PartialEq for GThemeValueMap {
    fn eq(&self, other: &Self) -> bool {
        self.color_map == other.color_map
            && self.font_map == other.font_map
            && self.icon_map == other.icon_map
    }
}

impl Eq for GThemeValueMap {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gui_util::web_colors::RgbaColor;

    #[test]
    fn test_empty_map() {
        let map = GThemeValueMap::new();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn test_add_get_color() {
        let mut map = GThemeValueMap::new();
        let cv = ColorValue::new("color.bg", RgbaColor::new(0, 0, 0));
        map.add_color(cv);
        assert!(map.get_color("color.bg").is_some());
        assert_eq!(map.get_resolved_color("color.bg"), Some(RgbaColor::new(0, 0, 0)));
    }

    #[test]
    fn test_add_get_font() {
        let mut map = GThemeValueMap::new();
        let fv = FontValue::new("font.mono", FontDescriptor::plain("Courier", 12.0));
        map.add_font(fv);
        let resolved = map.get_resolved_font("font.mono").unwrap();
        assert_eq!(resolved.family, "Courier");
    }

    #[test]
    fn test_add_get_icon() {
        use super::super::icon_value::{IconPath, IconValue};
        let mut map = GThemeValueMap::new();
        let iv = IconValue::new("icon.open", IconPath::new("open.png"));
        map.add_icon(iv);
        assert!(map.get_icon("icon.open").is_some());
    }

    #[test]
    fn test_load() {
        let mut map1 = GThemeValueMap::new();
        map1.add_color(ColorValue::new("color.a", RgbaColor::new(1, 2, 3)));

        let mut map2 = GThemeValueMap::new();
        map2.load(&map1);
        assert_eq!(map2.get_resolved_color("color.a"), Some(RgbaColor::new(1, 2, 3)));
    }

    #[test]
    fn test_get_changed_values() {
        let mut base = GThemeValueMap::new();
        base.add_color(ColorValue::new("color.a", RgbaColor::new(0, 0, 0)));

        let mut current = GThemeValueMap::new();
        current.add_color(ColorValue::new("color.a", RgbaColor::new(255, 255, 255)));
        current.add_color(ColorValue::new("color.b", RgbaColor::new(128, 128, 128)));

        let changed = current.get_changed_values(&base);
        assert!(changed.get_color("color.a").is_some());
        assert!(changed.get_color("color.b").is_some());
    }

    #[test]
    fn test_color_ids() {
        let mut map = GThemeValueMap::new();
        map.add_color(ColorValue::new("color.a", RgbaColor::new(0, 0, 0)));
        map.add_color(ColorValue::new("color.b", RgbaColor::new(0, 0, 0)));
        let ids = map.get_color_ids();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn test_remove() {
        let mut map = GThemeValueMap::new();
        map.add_color(ColorValue::new("color.a", RgbaColor::new(0, 0, 0)));
        map.remove_color("color.a");
        assert!(map.get_color("color.a").is_none());
    }
}
