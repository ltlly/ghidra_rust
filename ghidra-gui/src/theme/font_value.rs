//! Font theme value.
//!
//! Ports `generic.theme.FontValue`.

use super::theme_value::ThemeValue;
use super::g_theme_value_map::GThemeValueMap;
use super::color_value::LAST_RESORT_DEFAULT;
use crate::gui_util::web_colors::RgbaColor;
use crate::options::option_value::FontDescriptor;

/// Prefix for internal font ids.
const FONT_ID_PREFIX: &str = "font.";
/// Prefix for LAF font ids.
const LAF_FONT_ID_PREFIX: &str = "laf.font.";
/// External prefix.
const EXTERNAL_PREFIX: &str = "[font]";
/// External LAF prefix.
const EXTERNAL_LAF_ID_PREFIX: &str = "[laf.font]";

/// Fallback font when resolution fails.
pub const LAST_RESORT_FONT: FontDescriptor = FontDescriptor {
    family: String::new(), // will be set in const
    style: 0,
    size: 12.0,
};

/// Get a default font descriptor.
pub fn default_font() -> FontDescriptor {
    FontDescriptor::plain("monospaced", 12.0)
}

/// A theme font value that is either a direct font or a reference to
/// another font value.
///
/// Ported from Ghidra's `generic.theme.FontValue`.
#[derive(Debug, Clone, PartialEq)]
pub struct FontValue {
    inner: ThemeValue<FontDescriptor>,
}

impl FontValue {
    /// Create a font value with a direct font.
    pub fn new(id: impl Into<String>, font: FontDescriptor) -> Self {
        Self { inner: ThemeValue::with_value(id, font) }
    }

    /// Create a font value that references another font.
    pub fn with_ref(id: impl Into<String>, ref_id: impl Into<String>) -> Self {
        Self { inner: ThemeValue::with_reference(id, ref_id) }
    }

    /// Get the id.
    pub fn id(&self) -> &str {
        self.inner.id()
    }

    /// Get the raw direct font, if any.
    pub fn raw_value(&self) -> Option<&FontDescriptor> {
        self.inner.raw_value()
    }

    /// Get the reference id, if any.
    pub fn reference_id(&self) -> Option<&str> {
        self.inner.reference_id()
    }

    /// Whether this is an indirect (referencing) value.
    pub fn is_indirect(&self) -> bool {
        self.inner.is_indirect()
    }

    /// Whether this is an external LAF font.
    pub fn is_external(&self) -> bool {
        !self.inner.id().starts_with(FONT_ID_PREFIX)
    }

    /// Resolve the font, following references through the value map.
    pub fn resolve(&self, values: &GThemeValueMap) -> FontDescriptor {
        if let Some(font) = self.inner.raw_value() {
            return font.clone();
        }
        if let Some(ref_id) = self.inner.reference_id() {
            let mut visited = std::collections::HashSet::new();
            visited.insert(self.inner.id().to_string());
            let mut current_ref = ref_id.to_string();
            loop {
                if let Some(fv) = values.get_font(&current_ref) {
                    if let Some(font) = fv.raw_value() {
                        return font.clone();
                    }
                    if let Some(next_ref) = fv.reference_id() {
                        if visited.contains(next_ref) {
                            return default_font();
                        }
                        visited.insert(next_ref.to_string());
                        current_ref = next_ref.to_string();
                        continue;
                    }
                }
                return default_font();
            }
        }
        default_font()
    }

    /// Parse a font value from a key and value string.
    pub fn parse(key: &str, value: &str) -> Option<Self> {
        let id = Self::from_external_id(key);
        let value = value.trim().trim_start_matches('(').trim_end_matches(')');

        // Check if value is a reference
        if Self::is_font_key(value) {
            let ref_id = Self::from_external_id(value);
            return Some(Self::with_ref(id, ref_id));
        }

        // Parse "family-style-size" format
        let parts: Vec<&str> = value.splitn(3, '-').collect();
        if parts.len() == 3 {
            let family = parts[0].to_string();
            let style = match parts[1].to_lowercase().as_str() {
                "plain" => 0u32,
                "bold" => 1,
                "italic" => 2,
                "bolditalic" => 3,
                _ => 0,
            };
            if let Ok(size) = parts[2].parse::<f32>() {
                return Some(Self::new(id, FontDescriptor::new(family, style, size)));
            }
        }
        None
    }

    /// Check if a key is a font key.
    pub fn is_font_key(key: &str) -> bool {
        key.starts_with(FONT_ID_PREFIX)
            || key.starts_with(EXTERNAL_PREFIX)
            || key.starts_with(EXTERNAL_LAF_ID_PREFIX)
    }

    /// Convert internal id to external form.
    pub fn to_external_id(internal_id: &str) -> String {
        if internal_id.starts_with(FONT_ID_PREFIX) {
            return internal_id.to_string();
        }
        if internal_id.starts_with(LAF_FONT_ID_PREFIX) {
            let base = &internal_id[LAF_FONT_ID_PREFIX.len()..];
            return format!("{}{}", EXTERNAL_LAF_ID_PREFIX, base);
        }
        format!("{}{}", EXTERNAL_PREFIX, internal_id)
    }

    /// Convert external id to internal form.
    pub fn from_external_id(external_id: &str) -> String {
        if let Some(rest) = external_id.strip_prefix(EXTERNAL_PREFIX) {
            return rest.to_string();
        }
        if let Some(rest) = external_id.strip_prefix(EXTERNAL_LAF_ID_PREFIX) {
            return format!("{}{}", LAF_FONT_ID_PREFIX, rest);
        }
        external_id.to_string()
    }

    /// Get the serialization string.
    pub fn get_serialization_string(&self) -> String {
        let output_id = Self::to_external_id(self.inner.id());
        let value_str = if let Some(ref_id) = self.inner.reference_id() {
            Self::to_external_id(ref_id)
        } else if let Some(font) = self.inner.raw_value() {
            font.to_string()
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
    fn test_font_value_direct() {
        let fv = FontValue::new("font.mono", FontDescriptor::plain("Courier", 12.0));
        assert_eq!(fv.id(), "font.mono");
        assert!(!fv.is_indirect());
        assert!(fv.raw_value().is_some());
    }

    #[test]
    fn test_font_value_indirect() {
        let fv = FontValue::with_ref("font.small", "font.normal");
        assert!(fv.is_indirect());
        assert_eq!(fv.reference_id(), Some("font.normal"));
    }

    #[test]
    fn test_is_font_key() {
        assert!(FontValue::is_font_key("font.test"));
        assert!(FontValue::is_font_key("[font]test"));
        assert!(FontValue::is_font_key("[laf.font]Panel.font"));
        assert!(!FontValue::is_font_key("color.test"));
    }

    #[test]
    fn test_external_id_roundtrip() {
        let internal = "font.test";
        let external = FontValue::to_external_id(internal);
        let back = FontValue::from_external_id(&external);
        assert_eq!(back, internal);
    }

    #[test]
    fn test_parse_direct() {
        let fv = FontValue::parse("font.test", "Arial-bold-14").unwrap();
        assert_eq!(fv.id(), "font.test");
        let font = fv.raw_value().unwrap();
        assert_eq!(font.family, "Arial");
        assert!(font.is_bold());
        assert_eq!(font.size, 14.0);
    }

    #[test]
    fn test_parse_reference() {
        let fv = FontValue::parse("font.small", "font.normal").unwrap();
        assert!(fv.is_indirect());
    }

    #[test]
    fn test_resolve_direct() {
        let fv = FontValue::new("font.test", FontDescriptor::bold("Helvetica", 16.0));
        let values = GThemeValueMap::new();
        let resolved = fv.resolve(&values);
        assert_eq!(resolved.family, "Helvetica");
    }

    #[test]
    fn test_resolve_indirect() {
        let fv_ref = FontValue::with_ref("font.small", "font.normal");
        let fv_base = FontValue::new("font.normal", FontDescriptor::plain("Arial", 14.0));
        let mut values = GThemeValueMap::new();
        values.add_font(fv_ref.clone());
        values.add_font(fv_base);
        let resolved = fv_ref.resolve(&values);
        assert_eq!(resolved.family, "Arial");
        assert_eq!(resolved.size, 14.0);
    }

    #[test]
    fn test_serialization() {
        let fv = FontValue::new("font.test", FontDescriptor::plain("Courier", 12.0));
        let s = fv.get_serialization_string();
        assert!(s.contains("font.test"));
        assert!(s.contains("="));
    }
}
