//! Icon theme value.
//!
//! Ports `generic.theme.IconValue`.

use super::theme_value::ThemeValue;
use super::g_theme_value_map::GThemeValueMap;

/// Prefix for internal icon ids.
const ICON_ID_PREFIX: &str = "icon.";
/// Prefix for LAF icon ids.
const LAF_ICON_ID_PREFIX: &str = "laf.icon.";
/// External prefix.
const EXTERNAL_PREFIX: &str = "[icon]";
/// External LAF prefix.
const EXTERNAL_LAF_ID_PREFIX: &str = "[laf.icon]";

/// An icon value represented as a path string.
///
/// In the Rust port, icons are represented as string paths rather than
/// Java `Icon` objects, since we don't have Swing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IconPath(pub String);

impl IconPath {
    pub fn new(path: impl Into<String>) -> Self {
        Self(path.into())
    }

    pub fn path(&self) -> &str {
        &self.0
    }
}

/// A theme icon value that is either a direct icon path or a reference to
/// another icon value.
///
/// Ported from Ghidra's `generic.theme.IconValue`.
#[derive(Debug, Clone, PartialEq)]
pub struct IconValue {
    inner: ThemeValue<IconPath>,
}

impl IconValue {
    /// Create an icon value with a direct icon path.
    pub fn new(id: impl Into<String>, icon: IconPath) -> Self {
        Self { inner: ThemeValue::with_value(id, icon) }
    }

    /// Create an icon value that references another icon.
    pub fn with_ref(id: impl Into<String>, ref_id: impl Into<String>) -> Self {
        Self { inner: ThemeValue::with_reference(id, ref_id) }
    }

    /// Get the id.
    pub fn id(&self) -> &str {
        self.inner.id()
    }

    /// Get the raw direct icon path, if any.
    pub fn raw_value(&self) -> Option<&IconPath> {
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

    /// Whether this is an external LAF icon.
    pub fn is_external(&self) -> bool {
        !self.inner.id().starts_with(ICON_ID_PREFIX)
    }

    /// Resolve the icon path, following references through the value map.
    pub fn resolve(&self, values: &GThemeValueMap) -> Option<IconPath> {
        if let Some(icon) = self.inner.raw_value() {
            return Some(icon.clone());
        }
        if let Some(ref_id) = self.inner.reference_id() {
            let mut visited = std::collections::HashSet::new();
            visited.insert(self.inner.id().to_string());
            let mut current_ref = ref_id.to_string();
            loop {
                if let Some(iv) = values.get_icon(&current_ref) {
                    if let Some(icon) = iv.raw_value() {
                        return Some(icon.clone());
                    }
                    if let Some(next_ref) = iv.reference_id() {
                        if visited.contains(next_ref) {
                            return None; // circular
                        }
                        visited.insert(next_ref.to_string());
                        current_ref = next_ref.to_string();
                        continue;
                    }
                }
                return None;
            }
        }
        None
    }

    /// Check if a key is an icon key.
    pub fn is_icon_key(key: &str) -> bool {
        key.starts_with(ICON_ID_PREFIX)
            || key.starts_with(EXTERNAL_PREFIX)
            || key.starts_with(EXTERNAL_LAF_ID_PREFIX)
    }

    /// Convert internal id to external form.
    pub fn to_external_id(internal_id: &str) -> String {
        if internal_id.starts_with(ICON_ID_PREFIX) {
            return internal_id.to_string();
        }
        if internal_id.starts_with(LAF_ICON_ID_PREFIX) {
            let base = &internal_id[LAF_ICON_ID_PREFIX.len()..];
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
            return format!("{}{}", LAF_ICON_ID_PREFIX, rest);
        }
        external_id.to_string()
    }

    /// Get the serialization string.
    pub fn get_serialization_string(&self) -> String {
        let output_id = Self::to_external_id(self.inner.id());
        let value_str = if let Some(ref_id) = self.inner.reference_id() {
            Self::to_external_id(ref_id)
        } else if let Some(icon) = self.inner.raw_value() {
            icon.0.clone()
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
    fn test_icon_value_direct() {
        let iv = IconValue::new("icon.open", IconPath::new("images/open.png"));
        assert_eq!(iv.id(), "icon.open");
        assert!(!iv.is_indirect());
        assert_eq!(iv.raw_value().unwrap().path(), "images/open.png");
    }

    #[test]
    fn test_icon_value_indirect() {
        let iv = IconValue::with_ref("icon.small", "icon.normal");
        assert!(iv.is_indirect());
        assert_eq!(iv.reference_id(), Some("icon.normal"));
    }

    #[test]
    fn test_is_icon_key() {
        assert!(IconValue::is_icon_key("icon.test"));
        assert!(IconValue::is_icon_key("[icon]test"));
        assert!(!IconValue::is_icon_key("color.test"));
    }

    #[test]
    fn test_resolve_direct() {
        let iv = IconValue::new("icon.test", IconPath::new("test.png"));
        let values = GThemeValueMap::new();
        assert_eq!(iv.resolve(&values).unwrap().path(), "test.png");
    }

    #[test]
    fn test_resolve_indirect() {
        let iv_ref = IconValue::with_ref("icon.copy", "icon.original");
        let iv_base = IconValue::new("icon.original", IconPath::new("orig.png"));
        let mut values = GThemeValueMap::new();
        values.add_icon(iv_ref.clone());
        values.add_icon(iv_base);
        assert_eq!(iv_ref.resolve(&values).unwrap().path(), "orig.png");
    }

    #[test]
    fn test_resolve_missing() {
        let iv = IconValue::with_ref("icon.a", "icon.missing");
        let values = GThemeValueMap::new();
        assert!(iv.resolve(&values).is_none());
    }

    #[test]
    fn test_external_id_roundtrip() {
        let internal = "icon.test";
        let external = IconValue::to_external_id(internal);
        let back = IconValue::from_external_id(&external);
        assert_eq!(back, internal);
    }
}
