//! OSGi bundle management for Ghidra's plugin system.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.osgi` package.
//!
//! Provides the OSGi-like plugin loading and management system used
//! by Ghidra. Manages bundle lifecycle (install, start, stop, uninstall),
//! bundle status tracking, and dependency resolution.
//!
//! # Key Types
//!
//! - [`BundleHost`] -- Manages the lifecycle of all bundles
//! - [`GhidraBundle`] -- Represents a single plugin bundle
//! - [`BundleStatus`] -- Current state of a bundle
//! - [`BundleMap`] -- Container for all registered bundles
//! - [`BundleStatusEntry`] -- Status information for a bundle

use std::collections::HashMap;
use std::path::PathBuf;

/// Maximum number of bundles.
pub const MAX_BUNDLES: usize = 1024;

// ---------------------------------------------------------------------------
// Bundle status
// ---------------------------------------------------------------------------

/// Lifecycle states for an OSGi bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BundleStatus {
    /// Bundle is installed but not resolved.
    Installed,
    /// Bundle dependencies are resolved.
    Resolved,
    /// Bundle is starting.
    Starting,
    /// Bundle is active and running.
    Active,
    /// Bundle is stopping.
    Stopping,
    /// Bundle is stopped.
    Stopped,
    /// Bundle is uninstalled.
    Uninstalled,
    /// Bundle has an error.
    Error,
}

impl BundleStatus {
    /// Whether the bundle is in a runnable state.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Whether the bundle is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Uninstalled | Self::Error)
    }

    /// Display name for this status.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Installed => "Installed",
            Self::Resolved => "Resolved",
            Self::Starting => "Starting",
            Self::Active => "Active",
            Self::Stopping => "Stopping",
            Self::Stopped => "Stopped",
            Self::Uninstalled => "Uninstalled",
            Self::Error => "Error",
        }
    }
}

// ---------------------------------------------------------------------------
// Bundle status entry
// ---------------------------------------------------------------------------

/// Status information for a bundle in the status table.
#[derive(Debug, Clone)]
pub struct BundleStatusEntry {
    /// The bundle symbolic name.
    pub name: String,
    /// The bundle version.
    pub version: String,
    /// Current status.
    pub status: BundleStatus,
    /// Error message, if the bundle has an error.
    pub error_message: Option<String>,
    /// Bundle location.
    pub location: Option<PathBuf>,
}

impl BundleStatusEntry {
    /// Create a new bundle status entry.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        status: BundleStatus,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            status,
            error_message: None,
            location: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Ghidra bundle
// ---------------------------------------------------------------------------

/// Represents a single Ghidra plugin bundle.
///
/// Ported from `ghidra.app.plugin.core.osgi.GhidraBundle`.
#[derive(Debug, Clone)]
pub struct GhidraBundle {
    /// The symbolic name of the bundle.
    pub symbolic_name: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Version string.
    pub version: String,
    /// Current status.
    pub status: BundleStatus,
    /// Source jar/directory path.
    pub source_path: PathBuf,
    /// Bundle description.
    pub description: String,
    /// Dependencies: list of bundle symbolic names.
    pub dependencies: Vec<String>,
    /// Exported package names.
    pub exports: Vec<String>,
    /// Activator class name.
    pub activator: Option<String>,
}

impl GhidraBundle {
    /// Create a new Ghidra bundle.
    pub fn new(
        symbolic_name: impl Into<String>,
        display_name: impl Into<String>,
        version: impl Into<String>,
        source_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            symbolic_name: symbolic_name.into(),
            display_name: display_name.into(),
            version: version.into(),
            status: BundleStatus::Installed,
            source_path: source_path.into(),
            description: String::new(),
            dependencies: Vec::new(),
            exports: Vec::new(),
            activator: None,
        }
    }

    /// Whether this bundle is currently active.
    pub fn is_active(&self) -> bool {
        self.status.is_active()
    }

    /// Get the status entry for this bundle.
    pub fn status_entry(&self) -> BundleStatusEntry {
        BundleStatusEntry {
            name: self.symbolic_name.clone(),
            version: self.version.clone(),
            status: self.status,
            error_message: None,
            location: Some(self.source_path.clone()),
        }
    }
}

// ---------------------------------------------------------------------------
// Bundle map
// ---------------------------------------------------------------------------

/// Container for all registered bundles, keyed by symbolic name.
///
/// Ported from `ghidra.app.plugin.core.osgi.BundleMap`.
#[derive(Debug, Default)]
pub struct BundleMap {
    bundles: HashMap<String, GhidraBundle>,
}

impl BundleMap {
    /// Create a new empty bundle map.
    pub fn new() -> Self {
        Self {
            bundles: HashMap::new(),
        }
    }

    /// Register a bundle.
    pub fn insert(&mut self, bundle: GhidraBundle) {
        self.bundles
            .insert(bundle.symbolic_name.clone(), bundle);
    }

    /// Get a bundle by symbolic name.
    pub fn get(&self, name: &str) -> Option<&GhidraBundle> {
        self.bundles.get(name)
    }

    /// Get a mutable reference to a bundle.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut GhidraBundle> {
        self.bundles.get_mut(name)
    }

    /// Remove a bundle by symbolic name.
    pub fn remove(&mut self, name: &str) -> Option<GhidraBundle> {
        self.bundles.remove(name)
    }

    /// Number of registered bundles.
    pub fn len(&self) -> usize {
        self.bundles.len()
    }

    /// Whether the bundle map is empty.
    pub fn is_empty(&self) -> bool {
        self.bundles.is_empty()
    }

    /// Get all bundle names.
    pub fn names(&self) -> Vec<&str> {
        self.bundles.keys().map(|s| s.as_str()).collect()
    }

    /// Get all bundle status entries.
    pub fn status_entries(&self) -> Vec<BundleStatusEntry> {
        self.bundles.values().map(|b| b.status_entry()).collect()
    }

    /// Get bundles with a specific status.
    pub fn bundles_with_status(&self, status: BundleStatus) -> Vec<&GhidraBundle> {
        self.bundles
            .values()
            .filter(|b| b.status == status)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Bundle host
// ---------------------------------------------------------------------------

/// Manages the lifecycle of all bundles.
///
/// Ported from `ghidra.app.plugin.core.osgi.BundleHost`.
#[derive(Debug)]
pub struct BundleHost {
    /// All registered bundles.
    bundle_map: BundleMap,
}

impl BundleHost {
    /// Create a new bundle host.
    pub fn new() -> Self {
        Self {
            bundle_map: BundleMap::new(),
        }
    }

    /// Install a bundle.
    pub fn install(&mut self, mut bundle: GhidraBundle) -> Result<(), String> {
        if self.bundle_map.len() >= MAX_BUNDLES {
            return Err("Maximum bundle count reached".into());
        }
        bundle.status = BundleStatus::Installed;
        self.bundle_map.insert(bundle);
        Ok(())
    }

    /// Start a bundle by symbolic name.
    pub fn start(&mut self, name: &str) -> Result<(), String> {
        let bundle = self
            .bundle_map
            .get_mut(name)
            .ok_or_else(|| format!("Bundle not found: {}", name))?;

        match bundle.status {
            BundleStatus::Installed | BundleStatus::Resolved | BundleStatus::Stopped => {
                bundle.status = BundleStatus::Active;
                Ok(())
            }
            _ => Err(format!(
                "Cannot start bundle '{}' in state {}",
                name,
                bundle.status.display_name()
            )),
        }
    }

    /// Stop a bundle by symbolic name.
    pub fn stop(&mut self, name: &str) -> Result<(), String> {
        let bundle = self
            .bundle_map
            .get_mut(name)
            .ok_or_else(|| format!("Bundle not found: {}", name))?;

        if bundle.status == BundleStatus::Active {
            bundle.status = BundleStatus::Stopped;
            Ok(())
        } else {
            Err(format!(
                "Cannot stop bundle '{}' in state {}",
                name,
                bundle.status.display_name()
            ))
        }
    }

    /// Uninstall a bundle by symbolic name.
    pub fn uninstall(&mut self, name: &str) -> Result<(), String> {
        let bundle = self
            .bundle_map
            .get_mut(name)
            .ok_or_else(|| format!("Bundle not found: {}", name))?;

        bundle.status = BundleStatus::Uninstalled;
        Ok(())
    }

    /// Get the bundle map.
    pub fn bundle_map(&self) -> &BundleMap {
        &self.bundle_map
    }

    /// Get all active bundles.
    pub fn active_bundles(&self) -> Vec<&GhidraBundle> {
        self.bundle_map.bundles_with_status(BundleStatus::Active)
    }
}

impl Default for BundleHost {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundle_status() {
        assert!(BundleStatus::Active.is_active());
        assert!(!BundleStatus::Stopped.is_active());
        assert!(BundleStatus::Uninstalled.is_terminal());
        assert!(BundleStatus::Error.is_terminal());
        assert!(!BundleStatus::Active.is_terminal());
    }

    #[test]
    fn test_bundle_status_display_names() {
        assert_eq!(BundleStatus::Installed.display_name(), "Installed");
        assert_eq!(BundleStatus::Active.display_name(), "Active");
        assert_eq!(BundleStatus::Error.display_name(), "Error");
    }

    #[test]
    fn test_ghidra_bundle_creation() {
        let bundle = GhidraBundle::new("com.test", "Test Plugin", "1.0", "/path/to/plugin.jar");
        assert_eq!(bundle.symbolic_name, "com.test");
        assert_eq!(bundle.status, BundleStatus::Installed);
        assert!(!bundle.is_active());
    }

    #[test]
    fn test_bundle_map_operations() {
        let mut map = BundleMap::new();
        assert!(map.is_empty());

        let bundle = GhidraBundle::new("b1", "Bundle 1", "1.0", "/b1.jar");
        map.insert(bundle);
        assert_eq!(map.len(), 1);
        assert!(map.get("b1").is_some());
        assert!(map.get("missing").is_none());

        map.get_mut("b1").unwrap().status = BundleStatus::Active;
        assert!(map.bundles_with_status(BundleStatus::Active).len() == 1);

        map.remove("b1");
        assert!(map.is_empty());
    }

    #[test]
    fn test_bundle_host_lifecycle() {
        let mut host = BundleHost::new();
        let bundle = GhidraBundle::new("test.bundle", "Test", "1.0", "/test.jar");

        host.install(bundle).unwrap();
        assert_eq!(host.bundle_map().len(), 1);

        host.start("test.bundle").unwrap();
        assert_eq!(host.active_bundles().len(), 1);

        host.stop("test.bundle").unwrap();
        assert_eq!(host.active_bundles().len(), 0);

        host.uninstall("test.bundle").unwrap();
        assert_eq!(
            host.bundle_map().get("test.bundle").unwrap().status,
            BundleStatus::Uninstalled
        );
    }

    #[test]
    fn test_bundle_host_start_invalid_state() {
        let mut host = BundleHost::new();
        let bundle = GhidraBundle::new("test", "T", "1.0", "/t.jar");
        host.install(bundle).unwrap();
        host.start("test").unwrap();

        // Can't start an already-active bundle
        assert!(host.start("test").is_err());
    }

    #[test]
    fn test_bundle_host_not_found() {
        let mut host = BundleHost::new();
        assert!(host.start("nonexistent").is_err());
        assert!(host.stop("nonexistent").is_err());
    }

    #[test]
    fn test_status_entry() {
        let bundle = GhidraBundle::new("b", "B", "1.0", "/b.jar");
        let entry = bundle.status_entry();
        assert_eq!(entry.name, "b");
        assert_eq!(entry.status, BundleStatus::Installed);
    }
}
