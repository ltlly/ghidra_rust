//! EnumIconColumnRenderer -- renders enum values as icons in table cells.
//!
//! Ported from `ghidra.app.util.bin.format.dwarf.external.gui.EnumIconColumnRenderer`.
//!
//! In the Java version this is a Swing `AbstractGColumnRenderer<E>` that
//! maps each enum ordinal to an icon and tooltip.  In Rust we provide a
//! generic, UI-framework-agnostic data structure that holds the
//! enum-to-icon mapping and can be queried by any renderer backend.

use std::collections::HashMap;

/// Describes an icon that can be displayed in a table cell.
///
/// This is a UI-framework-agnostic representation; the actual icon
/// resource (bitmap, SVG, font glyph, etc.) is identified by a
/// string key that the rendering backend can resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IconDescriptor {
    /// A string key identifying the icon resource (e.g. "icon.ok",
    /// "icon.warning", or a path to an image file).
    key: String,
    /// Optional tooltip text to display when hovering over the icon.
    tooltip: Option<String>,
}

impl IconDescriptor {
    /// Creates a new `IconDescriptor`.
    pub fn new(key: impl Into<String>, tooltip: Option<String>) -> Self {
        Self {
            key: key.into(),
            tooltip,
        }
    }

    /// Returns the icon key.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the tooltip, if any.
    pub fn tooltip(&self) -> Option<&str> {
        self.tooltip.as_deref()
    }
}

/// Generic renderer that maps enum values (by name) to [`IconDescriptor`]s.
///
/// This replaces the Java generic class `EnumIconColumnRenderer<E extends
/// Enum<E>>`.  Instead of relying on Java enum ordinals, we use a
/// `HashMap` keyed on the enum variant name (as a string).  This works
/// for any enum type that can produce a stable name string.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::dwarf_ext::gui::enum_icon_column_renderer::{
///     EnumIconColumnRenderer, IconDescriptor,
/// };
///
/// let mut renderer = EnumIconColumnRenderer::<&str>::new();
/// renderer.insert("Valid", IconDescriptor::new("icon.ok", Some("OK".into())));
/// renderer.insert("Invalid", IconDescriptor::new("icon.error", Some("Error".into())));
///
/// let icon = renderer.get_icon("Valid");
/// assert_eq!(icon.unwrap().key(), "icon.ok");
/// assert_eq!(icon.unwrap().tooltip(), Some("OK"));
/// ```
#[derive(Debug)]
pub struct EnumIconColumnRenderer<K: Eq + std::hash::Hash + ?Sized> {
    /// Maps enum variant names to their icon descriptors.
    icons: HashMap<Box<K>, IconDescriptor>,
}

impl<K: Eq + std::hash::Hash + ?Sized> EnumIconColumnRenderer<K> {
    /// Creates a new empty renderer.
    pub fn new() -> Self {
        Self {
            icons: HashMap::new(),
        }
    }

    /// Returns the number of registered enum-to-icon mappings.
    pub fn len(&self) -> usize {
        self.icons.len()
    }

    /// Returns `true` if no mappings are registered.
    pub fn is_empty(&self) -> bool {
        self.icons.is_empty()
    }
}

// Specialize for str keys (most common use case).
impl EnumIconColumnRenderer<str> {
    /// Inserts a mapping from an enum variant name to an icon descriptor.
    pub fn insert(&mut self, variant_name: &str, icon: IconDescriptor) {
        self.icons.insert(Box::from(variant_name), icon);
    }

    /// Returns the icon descriptor for the given enum variant name.
    pub fn get_icon(&self, variant_name: &str) -> Option<&IconDescriptor> {
        self.icons.get(variant_name)
    }

    /// Returns the icon key for the given enum variant name, or `None`.
    pub fn get_icon_key(&self, variant_name: &str) -> Option<&str> {
        self.icons.get(variant_name).map(|i| i.key())
    }

    /// Returns the tooltip for the given enum variant name, or `None`.
    pub fn get_tooltip(&self, variant_name: &str) -> Option<&str> {
        self.icons
            .get(variant_name)
            .and_then(|i| i.tooltip())
    }

    /// Returns `true` if the given variant name has a registered icon.
    pub fn has_icon(&self, variant_name: &str) -> bool {
        self.icons.contains_key(variant_name)
    }

    /// Returns the filter string for a cell value (used for text search).
    ///
    /// In the Java version this returns `t.toString()`.  Here we simply
    /// return the variant name itself.
    pub fn filter_string(&self, variant_name: &str) -> String {
        variant_name.to_string()
    }
}

impl Default for EnumIconColumnRenderer<str> {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for IconDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Icon({})", self.key)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icon_descriptor_new() {
        let icon = IconDescriptor::new("icon.ok", Some("All good".into()));
        assert_eq!(icon.key(), "icon.ok");
        assert_eq!(icon.tooltip(), Some("All good"));
    }

    #[test]
    fn test_icon_descriptor_no_tooltip() {
        let icon = IconDescriptor::new("icon.error", None);
        assert_eq!(icon.key(), "icon.error");
        assert_eq!(icon.tooltip(), None);
    }

    #[test]
    fn test_icon_descriptor_display() {
        let icon = IconDescriptor::new("icon.test", None);
        assert_eq!(format!("{}", icon), "Icon(icon.test)");
    }

    #[test]
    fn test_renderer_new() {
        let renderer = EnumIconColumnRenderer::<str>::new();
        assert!(renderer.is_empty());
        assert_eq!(renderer.len(), 0);
    }

    #[test]
    fn test_renderer_insert_and_get() {
        let mut renderer = EnumIconColumnRenderer::<str>::new();
        renderer.insert("Valid", IconDescriptor::new("icon.ok", Some("OK".into())));
        renderer.insert(
            "Invalid",
            IconDescriptor::new("icon.error", Some("Error".into())),
        );

        assert_eq!(renderer.len(), 2);
        assert!(!renderer.is_empty());

        let icon = renderer.get_icon("Valid").unwrap();
        assert_eq!(icon.key(), "icon.ok");
        assert_eq!(icon.tooltip(), Some("OK"));

        let icon = renderer.get_icon("Invalid").unwrap();
        assert_eq!(icon.key(), "icon.error");
        assert_eq!(icon.tooltip(), Some("Error"));
    }

    #[test]
    fn test_renderer_get_missing() {
        let renderer = EnumIconColumnRenderer::<str>::new();
        assert!(renderer.get_icon("Unknown").is_none());
        assert!(renderer.get_icon_key("Unknown").is_none());
        assert!(renderer.get_tooltip("Unknown").is_none());
        assert!(!renderer.has_icon("Unknown"));
    }

    #[test]
    fn test_renderer_overwrite() {
        let mut renderer = EnumIconColumnRenderer::<str>::new();
        renderer.insert("Valid", IconDescriptor::new("icon.old", None));
        renderer.insert("Valid", IconDescriptor::new("icon.new", None));

        assert_eq!(renderer.len(), 1);
        assert_eq!(renderer.get_icon_key("Valid"), Some("icon.new"));
    }

    #[test]
    fn test_renderer_filter_string() {
        let renderer = EnumIconColumnRenderer::<str>::new();
        assert_eq!(renderer.filter_string("Test"), "Test");
        assert_eq!(renderer.filter_string(""), "");
    }

    #[test]
    fn test_renderer_has_icon() {
        let mut renderer = EnumIconColumnRenderer::<str>::new();
        renderer.insert("Yes", IconDescriptor::new("icon.yes", None));
        assert!(renderer.has_icon("Yes"));
        assert!(!renderer.has_icon("No"));
    }

    #[test]
    fn test_renderer_get_icon_key() {
        let mut renderer = EnumIconColumnRenderer::<str>::new();
        renderer.insert(
            "Warn",
            IconDescriptor::new("icon.warning", Some("Warning".into())),
        );
        assert_eq!(renderer.get_icon_key("Warn"), Some("icon.warning"));
    }

    #[test]
    fn test_renderer_get_tooltip() {
        let mut renderer = EnumIconColumnRenderer::<str>::new();
        renderer.insert(
            "Warn",
            IconDescriptor::new("icon.warning", Some("Warning".into())),
        );
        assert_eq!(renderer.get_tooltip("Warn"), Some("Warning"));
    }

    #[test]
    fn test_renderer_default() {
        let renderer = EnumIconColumnRenderer::<str>::default();
        assert!(renderer.is_empty());
    }

    #[test]
    fn test_icon_descriptor_clone() {
        let icon = IconDescriptor::new("icon.test", Some("tooltip".into()));
        let cloned = icon.clone();
        assert_eq!(icon, cloned);
    }
}
