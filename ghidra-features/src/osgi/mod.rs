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

/// OSGi bundle manager for plugin lifecycle management.
///
/// Ported from `ghidra.app.plugin.core.osgi` bundle manager classes.
pub mod bundle_manager;

/// Thread-safe bundle container with dual-indexed lookups.
///
/// Ported from `ghidra.app.plugin.core.osgi.BundleMap`.
pub mod bundle_map;

/// OSGi utility functions for bundle management.
///
/// Ported from `ghidra.app.plugin.core.osgi.OSGiUtils`.
pub mod utils;

/// Bundle host, GhidraBundle variants, BundleMap, BundleStatus,
/// BundleStatusTableModel, OSGiException, and OSGiUtils.
///
/// Ported from `ghidra.app.plugin.core.osgi.BundleHost`, `GhidraBundle`,
/// `GhidraJarBundle`, `GhidraSourceBundle`, `GhidraPlaceholderBundle`,
/// `BundleMap`, `BundleStatus`, `BundleStatusTableModel`, `OSGiException`,
/// and `OSGiUtils`.
pub mod bundle_host;

/// Build error types for bundle operations.
///
/// Ported from `ghidra.app.plugin.core.osgi.BuildError`.
pub mod build_error;

/// Parallel lock utility for concurrent bundle operations.
///
/// Ported from `ghidra.app.plugin.core.osgi.OSGiParallelLock`.
pub mod parallel_lock;

/// Bundle status table model for displaying bundle information.
///
/// Ported from `ghidra.app.plugin.core.osgi.BundleStatusTableModel`.
pub mod status_table;

/// Bundle status component provider.
///
/// Ported from `ghidra.app.plugin.core.osgi.BundleStatusComponentProvider`.
pub mod status_provider;

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

// ---------------------------------------------------------------------------
// Dependency resolution
// ---------------------------------------------------------------------------

/// Result of resolving bundle dependencies.
///
/// Ported from dependency resolution logic in `BundleHost`.
#[derive(Debug, Clone)]
pub struct DependencyResolution {
    /// The bundle being resolved.
    pub bundle_name: String,
    /// Bundles that this bundle depends on.
    pub dependencies: Vec<String>,
    /// Missing dependencies (not found in the bundle map).
    pub missing: Vec<String>,
    /// Circular dependency chains detected.
    pub cycles: Vec<Vec<String>>,
    /// Whether resolution was successful.
    pub success: bool,
}

impl DependencyResolution {
    /// Create a new dependency resolution result.
    pub fn new(bundle_name: impl Into<String>) -> Self {
        Self {
            bundle_name: bundle_name.into(),
            dependencies: Vec::new(),
            missing: Vec::new(),
            cycles: Vec::new(),
            success: true,
        }
    }

    /// Whether all dependencies are resolved.
    pub fn is_fully_resolved(&self) -> bool {
        self.missing.is_empty() && self.cycles.is_empty()
    }
}

/// Dependency resolver for bundles.
///
/// Ported from dependency resolution in `BundleHost`.
pub struct DependencyResolver;

impl DependencyResolver {
    /// Resolve dependencies for a specific bundle.
    pub fn resolve(bundle_map: &BundleMap, bundle_name: &str) -> DependencyResolution {
        let mut resolution = DependencyResolution::new(bundle_name);

        if let Some(bundle) = bundle_map.get(bundle_name) {
            resolution.dependencies = bundle.dependencies.clone();

            for dep in &bundle.dependencies {
                if !bundle_map.bundles.contains_key(dep) {
                    resolution.missing.push(dep.clone());
                    resolution.success = false;
                }
            }

            // Check for cycles
            let mut visited = Vec::new();
            if Self::has_cycle(bundle_map, bundle_name, &mut visited) {
                resolution.cycles.push(visited);
                resolution.success = false;
            }
        } else {
            resolution.success = false;
        }

        resolution
    }

    /// Resolve dependencies for all bundles.
    pub fn resolve_all(bundle_map: &BundleMap) -> Vec<DependencyResolution> {
        bundle_map
            .names()
            .iter()
            .map(|name| Self::resolve(bundle_map, name))
            .collect()
    }

    /// Get the start order for all bundles based on dependencies.
    ///
    /// Returns bundles in dependency-first order (topological sort).
    pub fn start_order(bundle_map: &BundleMap) -> Result<Vec<String>, String> {
        let names: Vec<String> = bundle_map.names().iter().map(|s| s.to_string()).collect();
        let mut visited = std::collections::HashSet::new();
        let mut in_stack = std::collections::HashSet::new();
        let mut order = Vec::new();

        for name in &names {
            if !visited.contains(name) {
                Self::topological_sort(
                    bundle_map,
                    name,
                    &mut visited,
                    &mut in_stack,
                    &mut order,
                )?;
            }
        }

        Ok(order)
    }

    fn topological_sort(
        bundle_map: &BundleMap,
        name: &str,
        visited: &mut std::collections::HashSet<String>,
        in_stack: &mut std::collections::HashSet<String>,
        order: &mut Vec<String>,
    ) -> Result<(), String> {
        if in_stack.contains(name) {
            return Err(format!("Circular dependency detected involving '{}'", name));
        }
        if visited.contains(name) {
            return Ok(());
        }

        in_stack.insert(name.to_string());

        if let Some(bundle) = bundle_map.get(name) {
            for dep in &bundle.dependencies {
                if bundle_map.bundles.contains_key(dep) {
                    Self::topological_sort(bundle_map, dep, visited, in_stack, order)?;
                }
            }
        }

        in_stack.remove(name);
        visited.insert(name.to_string());
        order.push(name.to_string());
        Ok(())
    }

    fn has_cycle(
        bundle_map: &BundleMap,
        name: &str,
        visited: &mut Vec<String>,
    ) -> bool {
        if visited.contains(&name.to_string()) {
            return true;
        }
        visited.push(name.to_string());

        if let Some(bundle) = bundle_map.get(name) {
            for dep in &bundle.dependencies {
                if Self::has_cycle(bundle_map, dep, visited) {
                    return true;
                }
            }
        }

        visited.pop();
        false
    }
}

// ---------------------------------------------------------------------------
// Start level management
// ---------------------------------------------------------------------------

/// Start level for bundle ordering during system startup.
///
/// Lower start levels are started first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StartLevel(pub u32);

impl StartLevel {
    /// System bundle start level (started first).
    pub const SYSTEM: StartLevel = StartLevel(0);
    /// Default start level for user bundles.
    pub const DEFAULT: StartLevel = StartLevel(10);
    /// Extension bundle start level.
    pub const EXTENSION: StartLevel = StartLevel(5);
}

/// Bundle start configuration.
#[derive(Debug, Clone)]
pub struct BundleStartConfig {
    /// The bundle name.
    pub bundle_name: String,
    /// The start level.
    pub start_level: StartLevel,
    /// Whether to start automatically.
    pub auto_start: bool,
    /// Whether the bundle is lazy-started (only started when a class is loaded).
    pub lazy_start: bool,
}

impl BundleStartConfig {
    /// Create a new start configuration.
    pub fn new(bundle_name: impl Into<String>) -> Self {
        Self {
            bundle_name: bundle_name.into(),
            start_level: StartLevel::DEFAULT,
            auto_start: true,
            lazy_start: false,
        }
    }
}

/// Manages bundle start levels and ordering.
#[derive(Debug, Default)]
pub struct StartLevelManager {
    configs: HashMap<String, BundleStartConfig>,
    current_level: u32,
}

impl StartLevelManager {
    /// Create a new start level manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the start configuration for a bundle.
    pub fn set_config(&mut self, config: BundleStartConfig) {
        self.configs.insert(config.bundle_name.clone(), config);
    }

    /// Get the start configuration for a bundle.
    pub fn get_config(&self, name: &str) -> Option<&BundleStartConfig> {
        self.configs.get(name)
    }

    /// Get bundles at a specific start level.
    pub fn bundles_at_level(&self, level: StartLevel) -> Vec<&BundleStartConfig> {
        self.configs
            .values()
            .filter(|c| c.start_level == level)
            .collect()
    }

    /// Get the current start level.
    pub fn current_level(&self) -> u32 {
        self.current_level
    }

    /// Advance the start level.
    pub fn advance_level(&mut self) {
        self.current_level += 1;
    }

    /// Get all auto-start bundles sorted by start level.
    pub fn auto_start_bundles(&self) -> Vec<&BundleStartConfig> {
        let mut bundles: Vec<&BundleStartConfig> = self
            .configs
            .values()
            .filter(|c| c.auto_start)
            .collect();
        bundles.sort_by_key(|c| c.start_level.0);
        bundles
    }
}

// ===========================================================================
// BundleHostListener
// ===========================================================================

/// Listener trait for bundle host events.
///
/// Ported from `ghidra.app.plugin.core.osgi.BundleHostListener`.
pub trait BundleHostListener: Send + Sync {
    /// Called when a bundle is installed.
    fn on_bundle_installed(&self, bundle_name: &str);
    /// Called when a bundle is uninstalled.
    fn on_bundle_uninstalled(&self, bundle_name: &str);
    /// Called when a bundle status changes.
    fn on_status_changed(&self, bundle_name: &str, new_status: BundleStatus);
}

// ===========================================================================
// BundleStatusChangeRequestListener
// ===========================================================================

/// Listener trait for bundle status change requests.
///
/// Ported from `ghidra.app.plugin.core.osgi.BundleStatusChangeRequestListener`.
pub trait BundleStatusChangeRequestListener: Send + Sync {
    /// Called when a status change is requested.  Returns true if the change
    /// should proceed.
    fn on_status_change_requested(
        &self,
        bundle_name: &str,
        current_status: BundleStatus,
        requested_status: BundleStatus,
    ) -> bool;
}

// ===========================================================================
// GhidraBundleActivator
// ===========================================================================

/// Activator for Ghidra OSGi bundles.
///
/// Ported from `ghidra.app.plugin.core.osgi.GhidraBundleActivator`.
///
/// The activator is responsible for starting and stopping OSGi bundles
/// within the Ghidra plugin framework.
#[derive(Debug, Clone)]
pub struct GhidraBundleActivator {
    /// The bundle symbolic name.
    pub bundle_name: String,
    /// Whether the activator has been started.
    pub started: bool,
    /// The bundle context.
    pub context: Option<String>,
}

impl GhidraBundleActivator {
    /// Create a new activator.
    pub fn new(bundle_name: impl Into<String>) -> Self {
        Self {
            bundle_name: bundle_name.into(),
            started: false,
            context: None,
        }
    }

    /// Start the activator.
    pub fn start(&mut self, context: impl Into<String>) -> Result<(), GhidraBundleException> {
        if self.started {
            return Err(GhidraBundleException::new("Bundle already started"));
        }
        self.context = Some(context.into());
        self.started = true;
        Ok(())
    }

    /// Stop the activator.
    pub fn stop(&mut self) -> Result<(), GhidraBundleException> {
        if !self.started {
            return Err(GhidraBundleException::new("Bundle not started"));
        }
        self.context = None;
        self.started = false;
        Ok(())
    }

    /// Whether the activator is started.
    pub fn is_started(&self) -> bool {
        self.started
    }
}

// ===========================================================================
// GhidraBundleException
// ===========================================================================

/// Exception type for Ghidra bundle operations.
///
/// Ported from `ghidra.app.plugin.core.osgi.GhidraBundleException`.
#[derive(Debug, Clone)]
pub struct GhidraBundleException {
    /// Error message.
    pub message: String,
}

impl GhidraBundleException {
    /// Create a new exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for GhidraBundleException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GhidraBundleException: {}", self.message)
    }
}

impl std::error::Error for GhidraBundleException {}

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

    #[test]
    fn test_dependency_resolution_success() {
        let mut map = BundleMap::new();
        let mut lib = GhidraBundle::new("lib", "Library", "1.0", "/lib.jar");
        lib.dependencies = vec![];
        map.insert(lib);

        let mut app = GhidraBundle::new("app", "App", "1.0", "/app.jar");
        app.dependencies = vec!["lib".into()];
        map.insert(app);

        let resolution = DependencyResolver::resolve(&map, "app");
        assert!(resolution.success);
        assert!(resolution.missing.is_empty());
        assert!(resolution.is_fully_resolved());
    }

    #[test]
    fn test_dependency_resolution_missing() {
        let mut map = BundleMap::new();
        let mut app = GhidraBundle::new("app", "App", "1.0", "/app.jar");
        app.dependencies = vec!["missing_lib".into()];
        map.insert(app);

        let resolution = DependencyResolver::resolve(&map, "app");
        assert!(!resolution.success);
        assert_eq!(resolution.missing, vec!["missing_lib"]);
        assert!(!resolution.is_fully_resolved());
    }

    #[test]
    fn test_dependency_start_order() {
        let mut map = BundleMap::new();
        let mut a = GhidraBundle::new("a", "A", "1.0", "/a.jar");
        a.dependencies = vec!["b".into()];
        map.insert(a);

        let b = GhidraBundle::new("b", "B", "1.0", "/b.jar");
        map.insert(b);

        let order = DependencyResolver::start_order(&map).unwrap();
        assert_eq!(order[0], "b");
        assert_eq!(order[1], "a");
    }

    #[test]
    fn test_dependency_circular_detection() {
        let mut map = BundleMap::new();
        let mut a = GhidraBundle::new("a", "A", "1.0", "/a.jar");
        a.dependencies = vec!["b".into()];
        map.insert(a);

        let mut b = GhidraBundle::new("b", "B", "1.0", "/b.jar");
        b.dependencies = vec!["a".into()];
        map.insert(b);

        let order = DependencyResolver::start_order(&map);
        assert!(order.is_err());
    }

    #[test]
    fn test_dependency_resolve_all() {
        let mut map = BundleMap::new();
        let mut a = GhidraBundle::new("a", "A", "1.0", "/a.jar");
        a.dependencies = vec!["b".into()];
        map.insert(a);

        let b = GhidraBundle::new("b", "B", "1.0", "/b.jar");
        map.insert(b);

        let results = DependencyResolver::resolve_all(&map);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.success));
    }

    #[test]
    fn test_start_level_ordering() {
        assert!(StartLevel::SYSTEM < StartLevel::EXTENSION);
        assert!(StartLevel::EXTENSION < StartLevel::DEFAULT);
    }

    #[test]
    fn test_bundle_start_config() {
        let config = BundleStartConfig::new("my.bundle");
        assert_eq!(config.bundle_name, "my.bundle");
        assert_eq!(config.start_level, StartLevel::DEFAULT);
        assert!(config.auto_start);
        assert!(!config.lazy_start);
    }

    #[test]
    fn test_start_level_manager() {
        let mut mgr = StartLevelManager::new();
        assert_eq!(mgr.current_level(), 0);

        let mut config = BundleStartConfig::new("b1");
        config.start_level = StartLevel::SYSTEM;
        mgr.set_config(config);

        let mut config2 = BundleStartConfig::new("b2");
        config2.start_level = StartLevel::DEFAULT;
        mgr.set_config(config2);

        let sys_bundles = mgr.bundles_at_level(StartLevel::SYSTEM);
        assert_eq!(sys_bundles.len(), 1);
        assert_eq!(sys_bundles[0].bundle_name, "b1");

        let auto_start = mgr.auto_start_bundles();
        assert_eq!(auto_start.len(), 2);
        assert_eq!(auto_start[0].bundle_name, "b1"); // SYSTEM level first
    }

    #[test]
    fn test_start_level_manager_advance() {
        let mut mgr = StartLevelManager::new();
        mgr.advance_level();
        assert_eq!(mgr.current_level(), 1);
        mgr.advance_level();
        assert_eq!(mgr.current_level(), 2);
    }

    // --- Tests for newly ported types ---

    #[test]
    fn test_ghidra_bundle_activator() {
        let mut activator = GhidraBundleActivator::new("com.ghidra.test");
        assert!(!activator.is_started());

        activator.start("test_context").unwrap();
        assert!(activator.is_started());

        activator.stop().unwrap();
        assert!(!activator.is_started());
    }

    #[test]
    fn test_ghidra_bundle_activator_double_start() {
        let mut activator = GhidraBundleActivator::new("com.ghidra.test");
        activator.start("ctx").unwrap();
        let result = activator.start("ctx2");
        assert!(result.is_err());
    }

    #[test]
    fn test_ghidra_bundle_activator_stop_not_started() {
        let mut activator = GhidraBundleActivator::new("com.ghidra.test");
        let result = activator.stop();
        assert!(result.is_err());
    }

    #[test]
    fn test_ghidra_bundle_exception() {
        let err = GhidraBundleException::new("test error");
        assert_eq!(err.message, "test error");
        assert!(format!("{}", err).contains("test error"));
    }
}
