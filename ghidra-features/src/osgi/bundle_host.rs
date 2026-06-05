// ===========================================================================
// OSGi Bundle Host -- ported from Ghidra's
// `ghidra.app.plugin.core.osgi` package.
//
// Includes:
// - BundleHost              -- the OSGi bundle host
// - BundleMap               -- map of bundles by ID
// - GhidraBundle            -- a Ghidra bundle abstraction
// - GhidraJarBundle         -- JAR-based bundle
// - GhidraSourceBundle      -- source-based bundle
// - GhidraPlaceholderBundle -- placeholder for missing bundles
// - BundleStatus            -- bundle status tracking
// - BundleStatusTableModel  -- table model for bundle status
// - OSGiException           -- OSGi-related errors
// - OSGiUtils               -- utility functions
//
// Uses `super::bundle_manager::BundleState` to avoid redefinition.
// ===========================================================================

use std::collections::{BTreeMap, HashMap};

use super::bundle_manager::BundleState;

// ---------------------------------------------------------------------------
// GhidraBundle
// ---------------------------------------------------------------------------

/// A Ghidra bundle (plugin module).
///
/// Ported from `ghidra.app.plugin.core.osgi.GhidraBundle`.
#[derive(Debug, Clone)]
pub struct GhidraBundle {
    /// The bundle symbolic name.
    pub symbolic_name: String,
    /// The bundle version.
    pub version: String,
    /// Current state.
    pub state: BundleState,
    /// Bundle ID.
    pub id: u64,
    /// The bundle description.
    pub description: String,
    /// Exported packages.
    pub exports: Vec<String>,
    /// Imported packages.
    pub imports: Vec<String>,
    /// Activator class name.
    pub activator_class: Option<String>,
    /// Start level.
    pub start_level: u32,
}

impl GhidraBundle {
    /// Create a new bundle.
    pub fn new(symbolic_name: impl Into<String>, version: impl Into<String>, id: u64) -> Self {
        Self {
            symbolic_name: symbolic_name.into(),
            version: version.into(),
            state: BundleState::Installed,
            id,
            description: String::new(),
            exports: Vec::new(),
            imports: Vec::new(),
            activator_class: None,
            start_level: 1,
        }
    }

    /// Start the bundle.
    pub fn start(&mut self) {
        self.state = BundleState::Starting;
        // In a real implementation, the activator would run here.
        self.state = BundleState::Active;
    }

    /// Stop the bundle.
    pub fn stop(&mut self) {
        self.state = BundleState::Stopping;
        self.state = BundleState::Resolved;
    }

    /// Whether the bundle is active.
    pub fn is_active(&self) -> bool {
        self.state == BundleState::Active
    }

    /// Add an exported package.
    pub fn add_export(&mut self, package: impl Into<String>) {
        self.exports.push(package.into());
    }

    /// Add an imported package.
    pub fn add_import(&mut self, package: impl Into<String>) {
        self.imports.push(package.into());
    }
}

// ---------------------------------------------------------------------------
// GhidraJarBundle
// ---------------------------------------------------------------------------

/// A bundle loaded from a JAR file.
///
/// Ported from `ghidra.app.plugin.core.osgi.GhidraJarBundle`.
#[derive(Debug, Clone)]
pub struct GhidraJarBundle {
    /// The base bundle info.
    pub bundle: GhidraBundle,
    /// The JAR file path.
    pub jar_path: String,
    /// The JAR file size in bytes.
    pub file_size: u64,
    /// Last modified timestamp.
    pub last_modified: u64,
}

impl GhidraJarBundle {
    /// Create a new JAR bundle.
    pub fn new(
        symbolic_name: impl Into<String>,
        version: impl Into<String>,
        id: u64,
        jar_path: impl Into<String>,
    ) -> Self {
        Self {
            bundle: GhidraBundle::new(symbolic_name, version, id),
            jar_path: jar_path.into(),
            file_size: 0,
            last_modified: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// GhidraSourceBundle
// ---------------------------------------------------------------------------

/// A bundle loaded from source code.
///
/// Ported from `ghidra.app.plugin.core.osgi.GhidraSourceBundle`.
#[derive(Debug, Clone)]
pub struct GhidraSourceBundle {
    /// The base bundle info.
    pub bundle: GhidraBundle,
    /// The source directory path.
    pub source_path: String,
    /// Source files.
    pub source_files: Vec<String>,
    /// Whether the bundle needs recompilation.
    pub needs_rebuild: bool,
}

impl GhidraSourceBundle {
    /// Create a new source bundle.
    pub fn new(
        symbolic_name: impl Into<String>,
        version: impl Into<String>,
        id: u64,
        source_path: impl Into<String>,
    ) -> Self {
        Self {
            bundle: GhidraBundle::new(symbolic_name, version, id),
            source_path: source_path.into(),
            source_files: Vec::new(),
            needs_rebuild: true,
        }
    }
}

// ---------------------------------------------------------------------------
// GhidraPlaceholderBundle
// ---------------------------------------------------------------------------

/// A placeholder for a bundle that could not be loaded.
///
/// Ported from `ghidra.app.plugin.core.osgi.GhidraPlaceholderBundle`.
#[derive(Debug, Clone)]
pub struct GhidraPlaceholderBundle {
    /// The base bundle info.
    pub bundle: GhidraBundle,
    /// The reason the bundle could not be loaded.
    pub reason: String,
    /// The original path that was expected.
    pub expected_path: Option<String>,
}

impl GhidraPlaceholderBundle {
    /// Create a new placeholder.
    pub fn new(
        symbolic_name: impl Into<String>,
        version: impl Into<String>,
        id: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            bundle: GhidraBundle::new(symbolic_name, version, id),
            reason: reason.into(),
            expected_path: None,
        }
    }
}

// ---------------------------------------------------------------------------
// BundleStatus
// ---------------------------------------------------------------------------

/// Status information for a bundle.
///
/// Ported from `ghidra.app.plugin.core.osgi.BundleStatus`.
#[derive(Debug, Clone)]
pub struct BundleStatus {
    /// The bundle symbolic name.
    pub name: String,
    /// Current state.
    pub state: BundleState,
    /// Status message.
    pub message: String,
    /// The bundle ID.
    pub bundle_id: u64,
    /// Whether the bundle has errors.
    pub has_errors: bool,
    /// Error details (if any).
    pub errors: Vec<String>,
}

impl BundleStatus {
    /// Create a new status.
    pub fn new(name: impl Into<String>, state: BundleState, bundle_id: u64) -> Self {
        Self {
            name: name.into(),
            state,
            message: String::new(),
            bundle_id,
            has_errors: false,
            errors: Vec::new(),
        }
    }

    /// Add an error.
    pub fn add_error(&mut self, error: impl Into<String>) {
        self.has_errors = true;
        self.errors.push(error.into());
    }
}

// ---------------------------------------------------------------------------
// BundleStatusTableModel
// ---------------------------------------------------------------------------

/// Table model for displaying bundle statuses.
///
/// Ported from `ghidra.app.plugin.core.osgi.BundleStatusTableModel`.
#[derive(Debug, Clone)]
pub struct BundleStatusTableModel {
    /// Bundle statuses.
    pub statuses: Vec<BundleStatus>,
    /// Column names.
    pub columns: Vec<String>,
}

impl BundleStatusTableModel {
    /// Create a new model.
    pub fn new() -> Self {
        Self {
            statuses: Vec::new(),
            columns: vec![
                "ID".into(),
                "Name".into(),
                "State".into(),
                "Status".into(),
            ],
        }
    }

    /// Add a status entry.
    pub fn add_status(&mut self, status: BundleStatus) {
        self.statuses.push(status);
    }

    /// Get the row count.
    pub fn row_count(&self) -> usize {
        self.statuses.len()
    }

    /// Get cell text for a specific row and column.
    pub fn cell_text(&self, row: usize, col: usize) -> Option<String> {
        self.statuses.get(row).map(|s| match col {
            0 => s.bundle_id.to_string(),
            1 => s.name.clone(),
            2 => s.state.display_name().to_string(),
            3 => s.message.clone(),
            _ => String::new(),
        })
    }

    /// Get the number of bundles with errors.
    pub fn error_count(&self) -> usize {
        self.statuses.iter().filter(|s| s.has_errors).count()
    }
}

impl Default for BundleStatusTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BundleMap
// ---------------------------------------------------------------------------

/// A map of bundles indexed by bundle ID.
///
/// Ported from `ghidra.app.plugin.core.osgi.BundleMap`.
#[derive(Debug, Clone)]
pub struct BundleMap {
    /// Bundles by ID.
    bundles: BTreeMap<u64, GhidraBundle>,
    /// Name to ID mapping.
    name_to_id: HashMap<String, u64>,
    /// Next available ID.
    next_id: u64,
}

impl BundleMap {
    /// Create a new bundle map.
    pub fn new() -> Self {
        Self {
            bundles: BTreeMap::new(),
            name_to_id: HashMap::new(),
            next_id: 1,
        }
    }

    /// Add a bundle. Returns the assigned ID.
    pub fn add(&mut self, mut bundle: GhidraBundle) -> u64 {
        let id = if bundle.id == 0 {
            let id = self.next_id;
            self.next_id += 1;
            bundle.id = id;
            id
        } else {
            bundle.id
        };
        self.name_to_id
            .insert(bundle.symbolic_name.clone(), id);
        self.bundles.insert(id, bundle);
        id
    }

    /// Get a bundle by ID.
    pub fn get(&self, id: u64) -> Option<&GhidraBundle> {
        self.bundles.get(&id)
    }

    /// Get a mutable bundle by ID.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut GhidraBundle> {
        self.bundles.get_mut(&id)
    }

    /// Get a bundle by name.
    pub fn get_by_name(&self, name: &str) -> Option<&GhidraBundle> {
        self.name_to_id.get(name).and_then(|id| self.bundles.get(id))
    }

    /// Remove a bundle by ID.
    pub fn remove(&mut self, id: u64) -> Option<GhidraBundle> {
        let bundle = self.bundles.remove(&id);
        if let Some(ref b) = bundle {
            self.name_to_id.remove(&b.symbolic_name);
        }
        bundle
    }

    /// Get the number of bundles.
    pub fn len(&self) -> usize {
        self.bundles.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.bundles.is_empty()
    }

    /// Get all bundle IDs.
    pub fn ids(&self) -> Vec<u64> {
        self.bundles.keys().copied().collect()
    }

    /// Start all bundles.
    pub fn start_all(&mut self) {
        for bundle in self.bundles.values_mut() {
            bundle.start();
        }
    }

    /// Stop all bundles.
    pub fn stop_all(&mut self) {
        for bundle in self.bundles.values_mut() {
            bundle.stop();
        }
    }

    /// Get the count of active bundles.
    pub fn active_count(&self) -> usize {
        self.bundles.values().filter(|b| b.is_active()).count()
    }
}

impl Default for BundleMap {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BundleHost
// ---------------------------------------------------------------------------

/// The OSGi bundle host that manages the lifecycle of all bundles.
///
/// Ported from `ghidra.app.plugin.core.osgi.BundleHost`.
#[derive(Debug, Clone)]
pub struct BundleHost {
    /// The bundle map.
    pub bundles: BundleMap,
    /// Whether the host is running.
    pub running: bool,
    /// The start level.
    pub start_level: u32,
    /// Host name.
    pub name: String,
}

impl BundleHost {
    /// Create a new bundle host.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            bundles: BundleMap::new(),
            running: false,
            start_level: 0,
            name: name.into(),
        }
    }

    /// Install a bundle.
    pub fn install(&mut self, bundle: GhidraBundle) -> u64 {
        self.bundles.add(bundle)
    }

    /// Uninstall a bundle by ID.
    pub fn uninstall(&mut self, id: u64) -> bool {
        self.bundles.remove(id).is_some()
    }

    /// Start all bundles.
    pub fn start(&mut self) {
        self.running = true;
        self.bundles.start_all();
    }

    /// Stop all bundles.
    pub fn stop(&mut self) {
        self.bundles.stop_all();
        self.running = false;
    }

    /// Get the bundle count.
    pub fn bundle_count(&self) -> usize {
        self.bundles.len()
    }

    /// Get the number of active bundles.
    pub fn active_count(&self) -> usize {
        self.bundles.active_count()
    }
}

// ---------------------------------------------------------------------------
// OSGiException
// ---------------------------------------------------------------------------

/// Errors that can occur in OSGi operations.
///
/// Ported from `ghidra.app.plugin.core.osgi.OSGiException`.
#[derive(Debug, Clone)]
pub struct OSGiException {
    /// The error message.
    pub message: String,
    /// The bundle name (if applicable).
    pub bundle_name: Option<String>,
}

impl OSGiException {
    /// Create a new exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            bundle_name: None,
        }
    }

    /// Create a bundle-specific exception.
    pub fn for_bundle(
        message: impl Into<String>,
        bundle_name: impl Into<String>,
    ) -> Self {
        Self {
            message: message.into(),
            bundle_name: Some(bundle_name.into()),
        }
    }
}

impl std::fmt::Display for OSGiException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.bundle_name {
            Some(name) => write!(f, "OSGi error in bundle '{}': {}", name, self.message),
            None => write!(f, "OSGi error: {}", self.message),
        }
    }
}

impl std::error::Error for OSGiException {}

// ---------------------------------------------------------------------------
// OSGiUtils
// ---------------------------------------------------------------------------

/// Utility functions for OSGi operations.
///
/// Ported from `ghidra.app.plugin.core.osgi.OSGiUtils`.
pub struct OSGiUtils;

impl OSGiUtils {
    /// Parse a bundle version string into major.minor.micro components.
    pub fn parse_version(version: &str) -> Option<(u32, u32, u32)> {
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() >= 3 {
            let major = parts[0].parse().ok()?;
            let minor = parts[1].parse().ok()?;
            let micro = parts[2].parse().ok()?;
            Some((major, minor, micro))
        } else if parts.len() == 2 {
            let major = parts[0].parse().ok()?;
            let minor = parts[1].parse().ok()?;
            Some((major, minor, 0))
        } else if parts.len() == 1 {
            let major = parts[0].parse().ok()?;
            Some((major, 0, 0))
        } else {
            None
        }
    }

    /// Format a version tuple as a string.
    pub fn format_version(major: u32, minor: u32, micro: u32) -> String {
        format!("{}.{}.{}", major, minor, micro)
    }

    /// Compare two version strings.
    pub fn compare_versions(v1: &str, v2: &str) -> Option<std::cmp::Ordering> {
        let a = Self::parse_version(v1)?;
        let b = Self::parse_version(v2)?;
        Some(a.cmp(&b))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghidra_bundle_lifecycle() {
        let mut bundle = GhidraBundle::new("com.example.plugin", "1.0.0", 1);
        assert_eq!(bundle.state, BundleState::Installed);
        bundle.start();
        assert!(bundle.is_active());
        bundle.stop();
        assert!(!bundle.is_active());
        assert_eq!(bundle.state, BundleState::Resolved);
    }

    #[test]
    fn test_ghidra_bundle_imports_exports() {
        let mut bundle = GhidraBundle::new("test", "1.0.0", 1);
        bundle.add_export("com.example.api");
        bundle.add_import("com.example.dep");
        assert_eq!(bundle.exports.len(), 1);
        assert_eq!(bundle.imports.len(), 1);
    }

    #[test]
    fn test_jar_bundle() {
        let jar = GhidraJarBundle::new("test", "1.0.0", 1, "/path/to/bundle.jar");
        assert_eq!(jar.jar_path, "/path/to/bundle.jar");
        assert_eq!(jar.bundle.symbolic_name, "test");
    }

    #[test]
    fn test_bundle_map() {
        let mut map = BundleMap::new();
        let b1 = GhidraBundle::new("com.a", "1.0", 10);
        let b2 = GhidraBundle::new("com.b", "2.0", 20);
        map.add(b1);
        map.add(b2);
        assert_eq!(map.len(), 2);
        assert!(map.get(10).is_some());
        assert_eq!(map.get_by_name("com.b").unwrap().version, "2.0");
    }

    #[test]
    fn test_bundle_map_auto_id() {
        let mut map = BundleMap::new();
        let b = GhidraBundle::new("auto", "1.0", 0);
        let id = map.add(b);
        assert_eq!(id, 1);
        let b2 = GhidraBundle::new("auto2", "1.0", 0);
        let id2 = map.add(b2);
        assert_eq!(id2, 2);
    }

    #[test]
    fn test_bundle_host() {
        let mut host = BundleHost::new("Ghidra");
        host.install(GhidraBundle::new("a", "1.0", 0));
        host.install(GhidraBundle::new("b", "2.0", 0));
        assert_eq!(host.bundle_count(), 2);

        host.start();
        assert!(host.running);
        assert_eq!(host.active_count(), 2);

        host.stop();
        assert!(!host.running);
    }

    #[test]
    fn test_bundle_status_table_model() {
        let mut model = BundleStatusTableModel::new();
        model.add_status(BundleStatus::new("com.a", BundleState::Active, 1));
        model.add_status(BundleStatus {
            name: "com.b".into(),
            state: BundleState::Installed,
            message: "Error".into(),
            bundle_id: 2,
            has_errors: true,
            errors: vec!["Missing dependency".into()],
        });
        assert_eq!(model.row_count(), 2);
        assert_eq!(model.error_count(), 1);
        assert_eq!(model.cell_text(1, 2).unwrap(), "Installed");
    }

    #[test]
    fn test_osgi_exception() {
        let err = OSGiException::new("something failed");
        assert!(err.to_string().contains("something failed"));

        let err2 = OSGiException::for_bundle("start failed", "com.example");
        assert_eq!(err2.bundle_name.as_deref(), Some("com.example"));
    }

    #[test]
    fn test_osgi_utils_parse_version() {
        assert_eq!(OSGiUtils::parse_version("1.2.3"), Some((1, 2, 3)));
        assert_eq!(OSGiUtils::parse_version("2.0"), Some((2, 0, 0)));
        assert_eq!(OSGiUtils::parse_version("5"), Some((5, 0, 0)));
        assert_eq!(OSGiUtils::parse_version("abc"), None);
    }

    #[test]
    fn test_osgi_utils_compare_versions() {
        assert_eq!(
            OSGiUtils::compare_versions("1.0.0", "2.0.0"),
            Some(std::cmp::Ordering::Less)
        );
        assert_eq!(
            OSGiUtils::compare_versions("2.0.0", "2.0.0"),
            Some(std::cmp::Ordering::Equal)
        );
    }

    #[test]
    fn test_source_bundle() {
        let src = GhidraSourceBundle::new("test", "1.0", 1, "/src/path");
        assert!(src.needs_rebuild);
    }

    #[test]
    fn test_placeholder_bundle() {
        let ph = GhidraPlaceholderBundle::new("missing", "1.0", 1, "not found");
        assert_eq!(ph.reason, "not found");
    }
}
