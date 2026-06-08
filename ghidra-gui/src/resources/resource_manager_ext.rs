//! Resource and icon management -- port of Ghidra's ResourceManager.
//!
//! Provides centralized resource loading, icon caching, and icon
//! composition for the GUI framework.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::path::PathBuf;

/// Well-known resource paths in Ghidra.
pub mod well_known {
    /// Bomb icon path.
    pub const BOMB: &str = "images/core.png";
    /// Large bomb icon path.
    pub const BIG_BOMB: &str = "images/core24.png";
    /// Prefix for externally loaded icons.
    pub const EXTERNAL_ICON_PREFIX: &str = "[EXTERNAL]";
}

/// An icon reference that can be resolved to image data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IconRef {
    /// A resource file path relative to the classpath.
    Resource(String),
    /// An externally loaded icon (absolute path or URL).
    External(String),
    /// A theme-aware icon identified by its theme ID.
    ThemeIcon(String),
    /// A composite icon made of multiple layers.
    Composite(Vec<IconRef>),
    /// The default/missing icon placeholder.
    Default,
}

impl IconRef {
    /// Create a resource icon reference.
    pub fn resource(path: impl Into<String>) -> Self {
        IconRef::Resource(path.into())
    }

    /// Create an external icon reference.
    pub fn external(path: impl Into<String>) -> Self {
        IconRef::External(path.into())
    }

    /// Create a theme icon reference.
    pub fn theme(id: impl Into<String>) -> Self {
        IconRef::ThemeIcon(id.into())
    }

    /// Check if this is an external icon.
    pub fn is_external(&self) -> bool {
        matches!(self, IconRef::External(_))
    }

    /// Get the path or ID string.
    pub fn path(&self) -> Option<&str> {
        match self {
            IconRef::Resource(p) | IconRef::External(p) | IconRef::ThemeIcon(p) => Some(p),
            _ => None,
        }
    }
}

impl std::fmt::Display for IconRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IconRef::Resource(p) => write!(f, "{}", p),
            IconRef::External(p) => write!(f, "[EXTERNAL]{}", p),
            IconRef::ThemeIcon(id) => write!(f, "[THEME]{}", id),
            IconRef::Composite(layers) => {
                write!(f, "[COMPOSITE({})]", layers.len())
            }
            IconRef::Default => write!(f, "[DEFAULT]"),
        }
    }
}

/// An icon entry in the resource cache.
#[derive(Debug, Clone)]
pub struct IconEntry {
    /// The icon reference.
    pub icon_ref: IconRef,
    /// The width in pixels (0 if unknown).
    pub width: u32,
    /// The height in pixels (0 if unknown).
    pub height: u32,
    /// Whether the icon has been loaded.
    pub loaded: bool,
}

impl IconEntry {
    /// Create a new icon entry.
    pub fn new(icon_ref: IconRef) -> Self {
        Self {
            icon_ref,
            width: 0,
            height: 0,
            loaded: false,
        }
    }

    /// Create an icon entry with dimensions.
    pub fn with_size(icon_ref: IconRef, width: u32, height: u32) -> Self {
        Self {
            icon_ref,
            width,
            height,
            loaded: true,
        }
    }
}

/// The resource manager provides centralized resource loading and icon caching.
///
/// Thread-safe via internal Mutex.
#[derive(Debug)]
pub struct ResourceManager {
    /// Icon cache keyed by resource path.
    icon_cache: Mutex<HashMap<String, IconEntry>>,
    /// Search paths for resources.
    search_paths: Mutex<Vec<PathBuf>>,
}

impl ResourceManager {
    /// Get the global singleton instance.
    pub fn instance() -> &'static ResourceManager {
        static INSTANCE: OnceLock<ResourceManager> = OnceLock::new();
        INSTANCE.get_or_init(|| ResourceManager {
            icon_cache: Mutex::new(HashMap::new()),
            search_paths: Mutex::new(vec![
                PathBuf::from("resources"),
                PathBuf::from("images"),
            ]),
        })
    }

    /// Look up an icon by its resource path.
    pub fn get_icon(&self, path: &str) -> Option<IconEntry> {
        self.icon_cache.lock().unwrap().get(path).cloned()
    }

    /// Register an icon in the cache.
    pub fn register_icon(&self, entry: IconEntry) {
        if let Some(p) = entry.icon_ref.path() {
            self.icon_cache.lock().unwrap().insert(p.to_string(), entry);
        }
    }

    /// Add a resource search path.
    pub fn add_search_path(&self, path: impl Into<PathBuf>) {
        self.search_paths.lock().unwrap().push(path.into());
    }

    /// Get all registered search paths.
    pub fn search_paths(&self) -> Vec<PathBuf> {
        self.search_paths.lock().unwrap().clone()
    }

    /// Get the number of cached icons.
    pub fn icon_count(&self) -> usize {
        self.icon_cache.lock().unwrap().len()
    }

    /// Clear the icon cache.
    pub fn clear_cache(&self) {
        self.icon_cache.lock().unwrap().clear();
    }

    /// Resolve a resource path to a full filesystem path.
    ///
    /// Searches through the registered search paths.
    pub fn resolve_resource(&self, resource_path: &str) -> Option<PathBuf> {
        for search_path in self.search_paths.lock().unwrap().iter() {
            let full = search_path.join(resource_path);
            if full.exists() {
                return Some(full);
            }
        }
        None
    }
}

impl Default for ResourceManager {
    fn default() -> Self {
        Self {
            icon_cache: Mutex::new(HashMap::new()),
            search_paths: Mutex::new(vec![
                PathBuf::from("resources"),
                PathBuf::from("images"),
            ]),
        }
    }
}

/// Multi-icon builder for composing layered icons.
#[derive(Debug, Clone)]
pub struct MultiIconBuilder {
    layers: Vec<IconRef>,
}

impl MultiIconBuilder {
    /// Create a new multi-icon builder.
    pub fn new() -> Self {
        Self { layers: Vec::new() }
    }

    /// Add a layer to the composite icon.
    pub fn add_layer(&mut self, icon: IconRef) -> &mut Self {
        self.layers.push(icon);
        self
    }

    /// Build the composite icon reference.
    pub fn build(&self) -> IconRef {
        IconRef::Composite(self.layers.clone())
    }

    /// Number of layers.
    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }
}

impl Default for MultiIconBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icon_ref_resource() {
        let icon = IconRef::resource("images/test.png");
        assert!(!icon.is_external());
        assert_eq!(icon.path(), Some("images/test.png"));
    }

    #[test]
    fn test_icon_ref_external() {
        let icon = IconRef::external("/tmp/icon.png");
        assert!(icon.is_external());
    }

    #[test]
    fn test_icon_ref_theme() {
        let icon = IconRef::theme("decompiler.keyword");
        assert_eq!(icon.path(), Some("decompiler.keyword"));
    }

    #[test]
    fn test_icon_ref_display() {
        assert_eq!(IconRef::resource("x.png").to_string(), "x.png");
        assert_eq!(IconRef::external("y.png").to_string(), "[EXTERNAL]y.png");
        assert_eq!(IconRef::Default.to_string(), "[DEFAULT]");
    }

    #[test]
    fn test_icon_entry() {
        let entry = IconEntry::with_size(IconRef::resource("test.png"), 16, 16);
        assert_eq!(entry.width, 16);
        assert!(entry.loaded);
    }

    #[test]
    fn test_resource_manager_singleton() {
        let rm = ResourceManager::instance();
        let _ = rm.icon_count();
    }

    #[test]
    fn test_resource_manager_register_and_get() {
        let rm = ResourceManager::default();
        let entry = IconEntry::with_size(IconRef::resource("test/icon.png"), 24, 24);
        rm.register_icon(entry);
        let got = rm.get_icon("test/icon.png");
        assert!(got.is_some());
        assert_eq!(got.unwrap().width, 24);
    }

    #[test]
    fn test_resource_manager_search_paths() {
        let rm = ResourceManager::default();
        assert_eq!(rm.search_paths().len(), 2);
        rm.add_search_path("/opt/icons");
        assert_eq!(rm.search_paths().len(), 3);
    }

    #[test]
    fn test_resource_manager_clear_cache() {
        let rm = ResourceManager::default();
        rm.register_icon(IconEntry::new(IconRef::resource("a")));
        rm.register_icon(IconEntry::new(IconRef::resource("b")));
        assert_eq!(rm.icon_count(), 2);
        rm.clear_cache();
        assert_eq!(rm.icon_count(), 0);
    }

    #[test]
    fn test_multi_icon_builder() {
        let mut builder = MultiIconBuilder::new();
        builder.add_layer(IconRef::resource("base.png"));
        builder.add_layer(IconRef::resource("overlay.png"));
        let composite = builder.build();
        assert_eq!(builder.layer_count(), 2);
        match composite {
            IconRef::Composite(layers) => assert_eq!(layers.len(), 2),
            _ => panic!("expected Composite"),
        }
    }
}
