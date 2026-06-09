//! PDB Plugin -- the Ghidra plugin entry point for PDB loading and analysis.
//!
//! Ports Ghidra's `ghidra.app.plugin.core.analysis.PdbAnalyzer` and
//! `ghidra.framework.plugintool.Plugin` (PDB-specific aspects).
//!
//! This module provides the high-level plugin infrastructure for integrating
//! PDB support into a Ghidra-like analysis tool. It includes:
//! - [`PdbPlugin`] -- The main plugin that registers PDB-related analyzers
//!   and menu actions.
//! - [`PdbLoadAction`] -- An action for manually loading a PDB file.
//! - [`PdbAnalyzerPlugin`] -- An analyzer that automatically searches for
//!   and applies PDB files during auto-analysis.
//! - [`PdbPluginOptions`] -- Options for the plugin's behavior.

use std::fmt;
use std::path::{Path, PathBuf};

use super::default_pdb_import_options::{DefaultPdbImportOptions, PdbImportSource};
use super::pdb_applicator::ApplicatorConfig;
use super::pdb_program_attributes::PdbProgramAttributes;
use super::symbol_server::SymbolFileInfo;

// =============================================================================
// PDB Plugin Status
// =============================================================================

/// The current status of the PDB plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdbPluginStatus {
    /// The plugin has not been initialized.
    Uninitialized,
    /// The plugin is ready to accept PDB files.
    Ready,
    /// A PDB file is currently being loaded.
    Loading,
    /// A PDB file is currently being applied to the program.
    Applying,
    /// The plugin has completed PDB application.
    Complete,
    /// An error occurred during PDB processing.
    Error,
}

impl PdbPluginStatus {
    /// Get the human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            PdbPluginStatus::Uninitialized => "Uninitialized",
            PdbPluginStatus::Ready => "Ready",
            PdbPluginStatus::Loading => "Loading PDB",
            PdbPluginStatus::Applying => "Applying PDB",
            PdbPluginStatus::Complete => "Complete",
            PdbPluginStatus::Error => "Error",
        }
    }
}

impl fmt::Display for PdbPluginStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// =============================================================================
// PDB Plugin Options
// =============================================================================

/// Options for the PDB plugin.
///
/// Controls automatic PDB loading behavior during analysis.
#[derive(Debug, Clone)]
pub struct PdbPluginOptions {
    /// Whether automatic PDB loading is enabled.
    auto_load_enabled: bool,
    /// Whether to prompt the user when a PDB cannot be found automatically.
    prompt_on_failure: bool,
    /// Default import options used when auto-loading.
    default_import_options: DefaultPdbImportOptions,
    /// Maximum PDB file size to load automatically (in bytes).
    max_auto_load_size: u64,
    /// Whether to apply PDB data immediately after loading.
    apply_immediately: bool,
    /// Timeout for PDB downloads from symbol servers (in seconds).
    symbol_server_timeout_secs: u64,
}

impl PdbPluginOptions {
    /// Create default plugin options.
    pub fn new() -> Self {
        Self {
            auto_load_enabled: true,
            prompt_on_failure: true,
            default_import_options: DefaultPdbImportOptions::new(),
            max_auto_load_size: 512 * 1024 * 1024, // 512 MB
            apply_immediately: true,
            symbol_server_timeout_secs: 30,
        }
    }

    /// Whether automatic PDB loading is enabled.
    pub fn auto_load_enabled(&self) -> bool {
        self.auto_load_enabled
    }

    /// Enable or disable automatic PDB loading.
    pub fn set_auto_load_enabled(&mut self, enabled: bool) {
        self.auto_load_enabled = enabled;
    }

    /// Whether to prompt the user when automatic PDB search fails.
    pub fn prompt_on_failure(&self) -> bool {
        self.prompt_on_failure
    }

    /// Set whether to prompt the user on search failure.
    pub fn set_prompt_on_failure(&mut self, prompt: bool) {
        self.prompt_on_failure = prompt;
    }

    /// Get the default import options.
    pub fn default_import_options(&self) -> &DefaultPdbImportOptions {
        &self.default_import_options
    }

    /// Get mutable access to the default import options.
    pub fn default_import_options_mut(&mut self) -> &mut DefaultPdbImportOptions {
        &mut self.default_import_options
    }

    /// Get the maximum auto-load file size.
    pub fn max_auto_load_size(&self) -> u64 {
        self.max_auto_load_size
    }

    /// Set the maximum auto-load file size.
    pub fn set_max_auto_load_size(&mut self, size: u64) {
        self.max_auto_load_size = size;
    }

    /// Whether PDB data should be applied immediately after loading.
    pub fn apply_immediately(&self) -> bool {
        self.apply_immediately
    }

    /// Set whether to apply PDB data immediately.
    pub fn set_apply_immediately(&mut self, apply: bool) {
        self.apply_immediately = apply;
    }

    /// Get the symbol server timeout in seconds.
    pub fn symbol_server_timeout_secs(&self) -> u64 {
        self.symbol_server_timeout_secs
    }

    /// Set the symbol server timeout.
    pub fn set_symbol_server_timeout_secs(&mut self, secs: u64) {
        self.symbol_server_timeout_secs = secs;
    }
}

impl Default for PdbPluginOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PdbPluginOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PdbPluginOptions [auto_load={}, prompt={}, max_size={}, timeout={}s]",
            self.auto_load_enabled, self.prompt_on_failure,
            self.max_auto_load_size, self.symbol_server_timeout_secs,
        )
    }
}

// =============================================================================
// PDB Plugin -- main plugin entry point
// =============================================================================

/// The main PDB plugin.
///
/// Manages PDB loading, application, and analysis within a Ghidra-like
/// analysis environment. This plugin is responsible for:
/// - Registering PDB-related analyzers
/// - Handling user actions for manual PDB loading
/// - Coordinating automatic PDB discovery and application
/// - Managing plugin options and preferences
///
/// Ports Ghidra's PDB-related plugin infrastructure.
#[derive(Debug)]
pub struct PdbPlugin {
    /// Current plugin status.
    status: PdbPluginStatus,
    /// Plugin options.
    options: PdbPluginOptions,
    /// The currently loaded PDB attributes, if any.
    loaded_attributes: Option<PdbProgramAttributes>,
    /// Path to the currently loaded PDB file.
    loaded_pdb_path: Option<PathBuf>,
    /// Number of types applied from the current PDB.
    types_applied: usize,
    /// Number of symbols applied from the current PDB.
    symbols_applied: usize,
    /// Whether the plugin has been disposed.
    disposed: bool,
}

impl PdbPlugin {
    /// Create a new PDB plugin.
    pub fn new() -> Self {
        Self {
            status: PdbPluginStatus::Uninitialized,
            options: PdbPluginOptions::new(),
            loaded_attributes: None,
            loaded_pdb_path: None,
            types_applied: 0,
            symbols_applied: 0,
            disposed: false,
        }
    }

    /// Create a new PDB plugin with specific options.
    pub fn with_options(options: PdbPluginOptions) -> Self {
        Self {
            status: PdbPluginStatus::Uninitialized,
            options,
            loaded_attributes: None,
            loaded_pdb_path: None,
            types_applied: 0,
            symbols_applied: 0,
            disposed: false,
        }
    }

    /// Initialize the plugin.
    ///
    /// Must be called before the plugin can process PDB files.
    pub fn initialize(&mut self) {
        self.status = PdbPluginStatus::Ready;
    }

    /// Dispose of the plugin and release resources.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.loaded_attributes = None;
        self.loaded_pdb_path = None;
        self.status = PdbPluginStatus::Uninitialized;
    }

    /// Check if the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Get the current plugin status.
    pub fn status(&self) -> PdbPluginStatus {
        self.status
    }

    /// Get the plugin options.
    pub fn options(&self) -> &PdbPluginOptions {
        &self.options
    }

    /// Get mutable access to the plugin options.
    pub fn options_mut(&mut self) -> &mut PdbPluginOptions {
        &mut self.options
    }

    // =========================================================================
    // PDB Loading
    // =========================================================================

    /// Initiate loading of a PDB file from the given path.
    ///
    /// Returns `true` if loading was started successfully.
    pub fn load_pdb(&mut self, path: impl AsRef<Path>) -> Result<(), PdbLoadError> {
        let path = path.as_ref();
        if self.disposed {
            return Err(PdbLoadError::PluginDisposed);
        }
        if !path.exists() {
            return Err(PdbLoadError::FileNotFound(path.to_path_buf()));
        }

        self.status = PdbPluginStatus::Loading;
        self.loaded_pdb_path = Some(path.to_path_buf());
        Ok(())
    }

    /// Notify the plugin that PDB loading has completed successfully.
    pub fn notify_load_complete(&mut self, attributes: PdbProgramAttributes) {
        self.loaded_attributes = Some(attributes);
        self.status = PdbPluginStatus::Applying;
    }

    /// Notify the plugin that PDB application has completed.
    pub fn notify_apply_complete(&mut self, types_applied: usize, symbols_applied: usize) {
        self.types_applied = types_applied;
        self.symbols_applied = symbols_applied;
        self.status = PdbPluginStatus::Complete;
    }

    /// Notify the plugin that an error occurred.
    pub fn notify_error(&mut self, _error: String) {
        self.status = PdbPluginStatus::Error;
    }

    /// Reset the plugin to the ready state.
    pub fn reset(&mut self) {
        self.loaded_attributes = None;
        self.loaded_pdb_path = None;
        self.types_applied = 0;
        self.symbols_applied = 0;
        self.status = PdbPluginStatus::Ready;
    }

    // =========================================================================
    // Query methods
    // =========================================================================

    /// Get the currently loaded PDB attributes.
    pub fn loaded_attributes(&self) -> Option<&PdbProgramAttributes> {
        self.loaded_attributes.as_ref()
    }

    /// Get the path to the currently loaded PDB file.
    pub fn loaded_pdb_path(&self) -> Option<&Path> {
        self.loaded_pdb_path.as_deref()
    }

    /// Get the number of types applied.
    pub fn types_applied(&self) -> usize {
        self.types_applied
    }

    /// Get the number of symbols applied.
    pub fn symbols_applied(&self) -> usize {
        self.symbols_applied
    }

    /// Check if a PDB is currently loaded.
    pub fn is_pdb_loaded(&self) -> bool {
        self.loaded_attributes.is_some()
    }

    /// Get a summary of the current plugin state.
    pub fn state_summary(&self) -> PdbPluginStateSummary {
        PdbPluginStateSummary {
            status: self.status,
            is_disposed: self.disposed,
            has_loaded_pdb: self.loaded_attributes.is_some(),
            loaded_pdb_path: self.loaded_pdb_path.clone(),
            types_applied: self.types_applied,
            symbols_applied: self.symbols_applied,
        }
    }
}

impl Default for PdbPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PdbPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PdbPlugin [status={}, types={}, symbols={}]",
            self.status, self.types_applied, self.symbols_applied,
        )
    }
}

// =============================================================================
// PDB Plugin State Summary
// =============================================================================

/// A snapshot of the PDB plugin's current state.
#[derive(Debug, Clone)]
pub struct PdbPluginStateSummary {
    /// Current status.
    pub status: PdbPluginStatus,
    /// Whether the plugin has been disposed.
    pub is_disposed: bool,
    /// Whether a PDB is loaded.
    pub has_loaded_pdb: bool,
    /// Path to the loaded PDB.
    pub loaded_pdb_path: Option<PathBuf>,
    /// Number of types applied.
    pub types_applied: usize,
    /// Number of symbols applied.
    pub symbols_applied: usize,
}

impl fmt::Display for PdbPluginStateSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PDB Plugin [status={}, types_applied={}, symbols_applied={}]",
            self.status, self.types_applied, self.symbols_applied,
        )
    }
}

// =============================================================================
// PDB Load Error
// =============================================================================

/// Errors that can occur when loading a PDB through the plugin.
#[derive(Debug, Clone)]
pub enum PdbLoadError {
    /// The plugin has been disposed and cannot accept new PDB files.
    PluginDisposed,
    /// The PDB file was not found.
    FileNotFound(PathBuf),
    /// The PDB file exceeds the maximum allowed size.
    FileTooLarge { size: u64, max: u64 },
    /// An I/O error occurred while reading the PDB.
    IoError(String),
    /// The PDB file is not valid.
    InvalidPdb(String),
}

impl fmt::Display for PdbLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PdbLoadError::PluginDisposed => write!(f, "PDB plugin has been disposed"),
            PdbLoadError::FileNotFound(path) => {
                write!(f, "PDB file not found: {}", path.display())
            }
            PdbLoadError::FileTooLarge { size, max } => {
                write!(
                    f,
                    "PDB file too large: {} bytes (max {} bytes)",
                    size, max
                )
            }
            PdbLoadError::IoError(msg) => write!(f, "PDB I/O error: {}", msg),
            PdbLoadError::InvalidPdb(msg) => write!(f, "Invalid PDB: {}", msg),
        }
    }
}

impl std::error::Error for PdbLoadError {}

// =============================================================================
// PDB Analyzer (auto-analysis integration)
// =============================================================================

/// PDB analyzer that integrates with the auto-analysis framework.
///
/// This analyzer searches for PDB files matching a loaded binary and
/// applies the PDB's type and symbol information to the program.
///
/// Ports Ghidra's `PdbAnalyzer` Java class.
#[derive(Debug)]
pub struct PdbAnalyzer {
    /// Whether the analyzer is enabled.
    enabled: bool,
    /// The analyzer's priority (lower = runs earlier).
    priority: i32,
    /// Whether this analyzer can be cancelled.
    can_cancel: bool,
    /// Whether to add to the analysis backlog on completion.
    add_to_backlog: bool,
}

impl PdbAnalyzer {
    /// The default analyzer priority (runs early).
    pub const DEFAULT_PRIORITY: i32 = 0;

    /// Create a new PDB analyzer.
    pub fn new() -> Self {
        Self {
            enabled: true,
            priority: Self::DEFAULT_PRIORITY,
            can_cancel: true,
            add_to_backlog: false,
        }
    }

    /// Check if the analyzer is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the analyzer.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the analyzer priority.
    pub fn priority(&self) -> i32 {
        self.priority
    }

    /// Set the analyzer priority.
    pub fn set_priority(&mut self, priority: i32) {
        self.priority = priority;
    }

    /// Check if the analyzer can be cancelled.
    pub fn can_cancel(&self) -> bool {
        self.can_cancel
    }

    /// Get the analyzer description.
    pub fn description(&self) -> &'static str {
        "Loads PDB (Program Database) debug information and applies types, symbols, and source line information to the program."
    }

    /// Get the analyzer name.
    pub fn name(&self) -> &'static str {
        "PDB Universal Analyzer"
    }
}

impl Default for PdbAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PdbAnalyzer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [priority={}, enabled={}]", self.name(), self.priority, self.enabled)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_initialization() {
        let mut plugin = PdbPlugin::new();
        assert_eq!(plugin.status(), PdbPluginStatus::Uninitialized);
        assert!(!plugin.is_disposed());

        plugin.initialize();
        assert_eq!(plugin.status(), PdbPluginStatus::Ready);
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = PdbPlugin::new();
        plugin.initialize();
        plugin.dispose();
        assert!(plugin.is_disposed());
        assert_eq!(plugin.status(), PdbPluginStatus::Uninitialized);
    }

    #[test]
    fn test_plugin_load_pdb() {
        let mut plugin = PdbPlugin::new();
        plugin.initialize();

        // Non-existent file should fail
        let result = plugin.load_pdb("/nonexistent/path.pdb");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PdbLoadError::FileNotFound(_)));
    }

    #[test]
    fn test_plugin_load_disposed() {
        let mut plugin = PdbPlugin::new();
        plugin.dispose();

        let result = plugin.load_pdb("/some/path.pdb");
        assert!(matches!(result.unwrap_err(), PdbLoadError::PluginDisposed));
    }

    #[test]
    fn test_plugin_lifecycle() {
        let mut plugin = PdbPlugin::new();
        plugin.initialize();
        assert_eq!(plugin.status(), PdbPluginStatus::Ready);

        plugin.notify_load_complete(PdbProgramAttributes::new(
            Some("GUID".to_string()),
            Some("1".to_string()),
            true,
            false,
            None,
            Some("test.pdb".to_string()),
            "/path/to/exe".to_string(),
        ));
        assert_eq!(plugin.status(), PdbPluginStatus::Applying);
        assert!(plugin.is_pdb_loaded());

        plugin.notify_apply_complete(100, 50);
        assert_eq!(plugin.status(), PdbPluginStatus::Complete);
        assert_eq!(plugin.types_applied(), 100);
        assert_eq!(plugin.symbols_applied(), 50);

        plugin.reset();
        assert_eq!(plugin.status(), PdbPluginStatus::Ready);
        assert!(!plugin.is_pdb_loaded());
    }

    #[test]
    fn test_plugin_options() {
        let opts = PdbPluginOptions::new();
        assert!(opts.auto_load_enabled());
        assert!(opts.prompt_on_failure());
        assert!(opts.apply_immediately());
        assert_eq!(opts.symbol_server_timeout_secs(), 30);
        assert_eq!(opts.max_auto_load_size(), 512 * 1024 * 1024);
    }

    #[test]
    fn test_plugin_options_display() {
        let opts = PdbPluginOptions::new();
        let s = format!("{}", opts);
        assert!(s.contains("PdbPluginOptions"));
        assert!(s.contains("auto_load=true"));
    }

    #[test]
    fn test_plugin_display() {
        let plugin = PdbPlugin::new();
        let s = format!("{}", plugin);
        assert!(s.contains("PdbPlugin"));
    }

    #[test]
    fn test_plugin_state_summary() {
        let plugin = PdbPlugin::new();
        let summary = plugin.state_summary();
        assert!(!summary.is_disposed);
        assert!(!summary.has_loaded_pdb);
        assert_eq!(summary.types_applied, 0);
    }

    #[test]
    fn test_analyzer() {
        let analyzer = PdbAnalyzer::new();
        assert!(analyzer.is_enabled());
        assert_eq!(analyzer.priority(), PdbAnalyzer::DEFAULT_PRIORITY);
        assert!(analyzer.can_cancel());
        assert!(!analyzer.name().is_empty());
        assert!(!analyzer.description().is_empty());
    }

    #[test]
    fn test_analyzer_display() {
        let analyzer = PdbAnalyzer::new();
        let s = format!("{}", analyzer);
        assert!(s.contains("PDB Universal Analyzer"));
    }

    #[test]
    fn test_status_display() {
        assert_eq!(format!("{}", PdbPluginStatus::Ready), "Ready");
        assert_eq!(format!("{}", PdbPluginStatus::Loading), "Loading PDB");
        assert_eq!(format!("{}", PdbPluginStatus::Complete), "Complete");
    }

    #[test]
    fn test_load_error_display() {
        let err = PdbLoadError::FileNotFound(PathBuf::from("/test.pdb"));
        let s = format!("{}", err);
        assert!(s.contains("not found"));

        let err2 = PdbLoadError::FileTooLarge { size: 1000, max: 500 };
        let s2 = format!("{}", err2);
        assert!(s2.contains("too large"));
    }

    #[test]
    fn test_plugin_with_options() {
        let opts = PdbPluginOptions::new();
        let plugin = PdbPlugin::with_options(opts);
        assert_eq!(plugin.status(), PdbPluginStatus::Uninitialized);
        assert!(plugin.options().auto_load_enabled());
    }
}
