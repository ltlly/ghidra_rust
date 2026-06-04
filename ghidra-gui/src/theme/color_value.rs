//! Color theme value.
//!
//! Ports `generic.theme.ColorValue`.

use super::theme_value::ThemeValue;
use super::g_theme_value_map::GThemeValueMap;
use crate::gui_util::web_colors::RgbaColor;

/// Prefix for internal color ids.
const COLOR_ID_PREFIX: &str = "color.";
/// Prefix for LAF color ids.
const LAF_ID_PREFIX: &str = "laf.color.";
/// External prefix.
const EXTERNAL_PREFIX: &str = "[color]";
/// External LAF prefix.
const EXTERNAL_LAF_ID_PREFIX: &str = "[laf.color]";

/// Fallback color when resolution fails.
pub const LAST_RESORT_DEFAULT: RgbaColor = RgbaColor::new(128, 128, 128);

/// A theme color value that is either a direct color or a reference to
/// another color value.
///
/// Ported from Ghidra's `generic.theme.ColorValue`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColorValue {
    inner: ThemeValue<RgbaColor>,
}

impl ColorValue {
    /// Create a color value with a direct color.
    pub fn new(id: impl Into<String>, color: RgbaColor) -> Self {
        Self { inner: ThemeValue::with_value(id, color) }
    }

    /// Create a color value that references another color.
    pub fn with_ref(id: impl Into<String>, ref_id: impl Into<String>) -> Self {
        Self { inner: ThemeValue::with_reference(id, ref_id) }
    }

    /// Get the id.
    pub fn id(&self) -> &str {
        self.inner.id()
    }

    /// Get the raw direct color, if any.
    pub fn raw_value(&self) -> Option<RgbaColor> {
        self.inner.raw_value().copied()
    }

    /// Get the reference id, if any.
    pub fn reference_id(&self) -> Option<&str> {
        self.inner.reference_id()
    }

    /// Whether this is an indirect (referencing) value.
    pub fn is_indirect(&self) -> bool {
        self.inner.is_indirect()
    }

    /// Whether this value represents an external LAF color.
    pub fn is_external(&self) -> bool {
        !self.inner.id().starts_with(COLOR_ID_PREFIX)
    }

    /// Resolve the color, following references through the value map.
    pub fn resolve(&self, values: &GThemeValueMap) -> RgbaColor {
        if let Some(color) = self.inner.raw_value() {
            return *color;
        }
        if let Some(ref_id) = self.inner.reference_id() {
            // Walk references manually to avoid borrowing issues
            let mut visited = std::collections::HashSet::new();
            visited.insert(self.inner.id().to_string());
            let mut current_ref = ref_id.to_string();
            loop {
                if let Some(cv) = values.get_color(&current_ref) {
                    if let Some(color) = cv.raw_value() {
                        return color;
                    }
                    if let Some(next_ref) = cv.reference_id() {
                        if visited.contains(next_ref) {
                            return LAST_RESORT_DEFAULT; // circular
                        }
                        visited.insert(next_ref.to_string());
                        current_ref = next_ref.to_string();
                        continue;
                    }
                }
                return LAST_RESORT_DEFAULT;
            }
        }
        LAST_RESORT_DEFAULT
    }

    /// Check if this value is a valid color key.
    pub fn is_color_key(key: &str) -> bool {
        key.starts_with(COLOR_ID_PREFIX)
            || key.starts_with(EXTERNAL_PREFIX)
            || key.starts_with(EXTERNAL_LAF_ID_PREFIX)
    }

    /// Convert an internal id to external form.
    pub fn to_external_id(internal_id: &str) -> String {
        if internal_id.starts_with(COLOR_ID_PREFIX) {
            return internal_id.to_string();
        }
        if internal_id.starts_with(LAF_ID_PREFIX) {
            let base = &internal_id[LAF_ID_PREFIX.len()..];
            return format!("{}{}", EXTERNAL_LAF_ID_PREFIX, base);
        }
        format!("{}{}", EXTERNAL_PREFIX, internal_id)
    }

    /// Convert an external id to internal form.
    pub fn from_external_id(external_id: &str) -> String {
        if let Some(rest) = external_id.strip_prefix(EXTERNAL_PREFIX) {
            return rest.to_string();
        }
        if let Some(rest) = external_id.strip_prefix(EXTERNAL_LAF_ID_PREFIX) {
            return format!("{}{}", LAF_ID_PREFIX, rest);
        }
        external_id.to_string()
    }

    /// Get the serialization string.
    pub fn get_serialization_string(&self) -> String {
        let output_id = Self::to_external_id(self.inner.id());
        let value_str = if let Some(ref_id) = self.inner.reference_id() {
            Self::to_external_id(ref_id)
        } else if let Some(color) = self.inner.raw_value() {
            color.to_hex_string()
        } else {
            String::new()
        };
        format!("{} = {}", output_id, value_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_value_direct() {
        let cv = ColorValue::new("color.bg", RgbaColor::new(255, 0, 0));
        assert_eq!(cv.id(), "color.bg");
        assert!(!cv.is_indirect());
        assert_eq!(cv.raw_value(), Some(RgbaColor::new(255, 0, 0)));
    }

    #[test]
    fn test_color_value_indirect() {
        let cv = ColorValue::with_ref("color.fg", "color.bg");
        assert!(cv.is_indirect());
        assert_eq!(cv.reference_id(), Some("color.bg"));
    }

    #[test]
    fn test_is_external() {
        let internal = ColorValue::new("color.bg", RgbaColor::new(0, 0, 0));
        assert!(!internal.is_external());

        let external = ColorValue::new("[laf.color]Panel.bg", RgbaColor::new(0, 0, 0));
        assert!(external.is_external());
    }

    #[test]
    fn test_is_color_key() {
        assert!(ColorValue::is_color_key("color.bg"));
        assert!(ColorValue::is_color_key("[color]bg"));
        assert!(ColorValue::is_color_key("[laf.color]Panel.bg"));
        assert!(!ColorValue::is_color_key("font.main"));
    }

    #[test]
    fn test_external_id_roundtrip() {
        let internal = "color.test";
        let external = ColorValue::to_external_id(internal);
        let back = ColorValue::from_external_id(&external);
        assert_eq!(back, internal);
    }

    #[test]
    fn test_external_laf_id_roundtrip() {
        let internal = "laf.color.Panel.bg";
        let external = ColorValue::to_external_id(internal);
        assert!(external.starts_with("[laf.color]"));
        let back = ColorValue::from_external_id(&external);
        assert_eq!(back, internal);
    }

    #[test]
    fn test_resolve_direct() {
        let cv = ColorValue::new("color.test", RgbaColor::new(0, 255, 0));
        let mut values = GThemeValueMap::new();
        values.add_color(cv.clone());
        assert_eq!(cv.resolve(&values), RgbaColor::new(0, 255, 0));
    }

    #[test]
    fn test_resolve_indirect() {
        let cv_ref = ColorValue::with_ref("color.fg", "color.bg");
        let cv_base = ColorValue::new("color.bg", RgbaColor::new(0, 0, 255));
        let mut values = GThemeValueMap::new();
        values.add_color(cv_ref.clone());
        values.add_color(cv_base);
        assert_eq!(cv_ref.resolve(&values), RgbaColor::new(0, 0, 255));
    }

    #[test]
    fn test_resolve_missing_returns_default() {
        let cv = ColorValue::with_ref("color.fg", "color.missing");
        let values = GThemeValueMap::new();
        assert_eq!(cv.resolve(&values), LAST_RESORT_DEFAULT);
    }

    #[test]
    fn test_serialization() {
        let cv = ColorValue::new("color.test", RgbaColor::new(255, 128, 0));
        let s = cv.get_serialization_string();
        assert!(s.starts_with("color.test"));
        assert!(s.contains("="));
    }
}
