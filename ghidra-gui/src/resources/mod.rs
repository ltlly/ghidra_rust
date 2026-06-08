//! Resource management for icons and images.
//!
//! Ports `resources.ResourceManager`, `resources.IconProvider`,
//! and `resources.MultiIcon` / `resources.MultiIconBuilder`.

pub mod icons;
pub mod icons_ext;
pub mod multi_icon;
pub mod resource_manager_ext;

pub use icons::{
    ColorIcon, ColorIcon3D, DerivedImageIcon, DisabledImageIcon, EmptyIcon, OvalColorIcon,
    ReflectedIcon, RotateIcon, RotationAngle, ScaledImageIcon, TranslateIcon,
};
pub use icons_ext::{
    BytesImageIcon, CenterTranslateIcon, DisabledImageIconWrapper, FileBasedIcon, IconWrapper,
    ImageIconWrapper, LazyImageIcon, OvalBackgroundColorIcon, ScaledImageIconWrapper,
    UnresolvedIcon, UrlImageIcon,
};
pub use multi_icon::{BuiltinIcon, IconId, IconOverlay, MultiIcon, MultiIconBuilder, Quadrant};

use std::collections::HashMap;
use std::path::Path;
use std::sync::RwLock;

use std::sync::LazyLock;

/// Prefix for icons stored in the user's application directory.
pub const EXTERNAL_ICON_PREFIX: &str = "[EXTERNAL]";

/// A simple icon representation (path + dimensions).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Icon {
    /// Path to the icon resource.
    pub path: String,
    /// Width in pixels (0 = unknown).
    pub width: u32,
    /// Height in pixels (0 = unknown).
    pub height: u32,
    /// Optional description.
    pub description: Option<String>,
}

impl Icon {
    /// Create a new icon from a path.
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into(), width: 0, height: 0, description: None }
    }

    /// Create a sized icon.
    pub fn with_size(path: impl Into<String>, width: u32, height: u32) -> Self {
        Self { path: path.into(), width, height, description: None }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Get the path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Get the icon name (last component of path or description).
    pub fn name(&self) -> &str {
        self.description
            .as_deref()
            .unwrap_or_else(|| {
                Path::new(&self.path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(&self.path)
            })
    }
}

impl std::fmt::Display for Icon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path)
    }
}

/// Trait for providing icons by id.
pub trait IconProvider: Send + Sync {
    /// Get an icon by its path/id.
    fn get_icon(&self, path: &str) -> Option<Icon>;

    /// Get all available icon paths.
    fn available_icons(&self) -> Vec<String>;
}

/// Global icon cache.
static ICON_CACHE: LazyLock<RwLock<HashMap<String, Icon>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Resource manager for loading and caching icons.
///
/// Ported from Ghidra's `resources.ResourceManager`.
pub struct ResourceManager;

impl ResourceManager {
    /// Load an icon from the given path. Returns a cached version if available.
    ///
    /// In the Rust port, this creates an `Icon` struct. Actual image loading
    /// is deferred to the rendering layer.
    pub fn load_icon(path: &str) -> Icon {
        {
            let cache = ICON_CACHE.read().unwrap();
            if let Some(icon) = cache.get(path) {
                return icon.clone();
            }
        }

        // Handle external icon prefix
        let actual_path = if path.starts_with(EXTERNAL_ICON_PREFIX) {
            &path[EXTERNAL_ICON_PREFIX.len()..]
        } else {
            path
        };

        let icon = Icon::new(actual_path);
        let mut cache = ICON_CACHE.write().unwrap();
        cache.insert(path.to_string(), icon.clone());
        icon
    }

    /// Find an icon from the given path, returning `None` if not found
    /// (unlike `load_icon` which always returns an icon).
    pub fn find_icon(path: &str) -> Option<Icon> {
        {
            let cache = ICON_CACHE.read().unwrap();
            if let Some(icon) = cache.get(path) {
                return Some(icon.clone());
            }
        }

        let icon = Icon::new(path);
        let mut cache = ICON_CACHE.write().unwrap();
        cache.insert(path.to_string(), icon.clone());
        Some(icon)
    }

    /// Get the name of an icon.
    pub fn get_icon_name(icon: &Icon) -> &str {
        icon.name()
    }

    /// Get a disabled version of an icon (returns a new icon with a modified path).
    pub fn get_disabled_icon(icon: &Icon) -> Icon {
        Icon::new(format!("{}.disabled", icon.path))
            .with_description(icon.description.clone().unwrap_or_default())
    }

    /// Clear the icon cache.
    pub fn clear_cache() {
        let mut cache = ICON_CACHE.write().unwrap();
        cache.clear();
    }

    /// Get the number of cached icons.
    pub fn cache_size() -> usize {
        let cache = ICON_CACHE.read().unwrap();
        cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icon_new() {
        let icon = Icon::new("images/test.png");
        assert_eq!(icon.path(), "images/test.png");
        assert_eq!(icon.name(), "test.png");
    }

    #[test]
    fn test_icon_with_size() {
        let icon = Icon::with_size("test.png", 16, 16);
        assert_eq!(icon.width, 16);
        assert_eq!(icon.height, 16);
    }

    #[test]
    fn test_icon_with_description() {
        let icon = Icon::new("test.png").with_description("Test Icon");
        assert_eq!(icon.name(), "Test Icon");
    }

    #[test]
    fn test_icon_display() {
        let icon = Icon::new("images/home.png");
        assert_eq!(icon.to_string(), "images/home.png");
    }

    #[test]
    fn test_resource_manager_load_icon() {
        ResourceManager::clear_cache();
        let icon = ResourceManager::load_icon("images/test.png");
        assert_eq!(icon.path(), "images/test.png");
        assert_eq!(ResourceManager::cache_size(), 1);
    }

    #[test]
    fn test_resource_manager_caching() {
        // Use unique paths to avoid interference with parallel tests
        // sharing the global cache.
        ResourceManager::clear_cache();
        let icon_a = ResourceManager::load_icon("images/cache_test_unique_a.png");
        let icon_b = ResourceManager::load_icon("images/cache_test_unique_b.png");
        let icon_a2 = ResourceManager::load_icon("images/cache_test_unique_a.png"); // cached
        assert_eq!(icon_a.path(), icon_a2.path());
        assert_eq!(icon_a, icon_a2);
        assert_ne!(icon_a.path(), icon_b.path());
    }

    #[test]
    fn test_resource_manager_find_icon() {
        let icon = ResourceManager::find_icon("images/find_test.png");
        assert!(icon.is_some());
    }

    #[test]
    fn test_resource_manager_disabled_icon() {
        let icon = Icon::new("test.png");
        let disabled = ResourceManager::get_disabled_icon(&icon);
        assert!(disabled.path().contains("disabled"));
    }

    #[test]
    fn test_resource_manager_external_prefix() {
        let icon = ResourceManager::load_icon("[EXTERNAL]custom/myicon.png");
        assert_eq!(icon.path(), "custom/myicon.png");
    }

    #[test]
    fn test_resource_manager_clear_cache() {
        let _ = ResourceManager::load_icon("images/clear_test.png");
        ResourceManager::clear_cache();
        assert_eq!(ResourceManager::cache_size(), 0);
    }

    #[test]
    fn test_icon_get_icon_name() {
        let icon = Icon::new("path/to/icon.png").with_description("My Icon");
        assert_eq!(ResourceManager::get_icon_name(&icon), "My Icon");
    }
}
