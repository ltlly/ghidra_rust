//! Import Plugin for loading binary files into a Ghidra project.
//!
//! Ported from `ghidra.plugin.importer.ImportPlugin`.
//!
//! Provides the [`ImportPlugin`] struct which orchestrates the import workflow:
//! - accepting file paths or raw bytes
//! - auto-detecting or manually selecting a loader
//! - configuring load options (language, base address, analysis)
//! - running the import and returning results
//!
//! This is the Rust-side equivalent of Ghidra's `ImportPlugin`, designed
//! for headless (non-GUI) use. For GUI-driven import, see the
//! [`super::plugin_importer`] module.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::loader::framework::{
    LoadError, LoadOption, LoadResults, LoadSpec, MessageLog,
};
use super::{
    AutoImporter, FirstPreferredLoadSpecChooser,
    LoadSpecChooser, LoaderFilter, AcceptAllLoaders, OptionChooser,
    DefaultOptionChooser, ProgramLoaderBuilder,
};

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

/// Tracks the lifecycle of an import operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportState {
    /// No import has been started.
    Idle,
    /// File has been accepted and format detection is complete.
    Detected,
    /// A load spec has been selected.
    LoadSpecSelected,
    /// Options have been configured.
    OptionsConfigured,
    /// The import is currently running.
    Running,
    /// The import completed successfully.
    Complete,
    /// The import failed.
    Failed,
}

impl fmt::Display for ImportState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportState::Idle => write!(f, "Idle"),
            ImportState::Detected => write!(f, "Detected"),
            ImportState::LoadSpecSelected => write!(f, "LoadSpecSelected"),
            ImportState::OptionsConfigured => write!(f, "OptionsConfigured"),
            ImportState::Running => write!(f, "Running"),
            ImportState::Complete => write!(f, "Complete"),
            ImportState::Failed => write!(f, "Failed"),
        }
    }
}

// ---------------------------------------------------------------------------
// ImportResult
// ---------------------------------------------------------------------------

/// The outcome of an import operation.
#[derive(Debug)]
pub struct ImportResult {
    /// The source file path or description.
    pub source: String,
    /// Whether the import succeeded.
    pub success: bool,
    /// The load results (programs produced), if successful.
    pub load_results: Option<LoadResults>,
    /// Error message, if the import failed.
    pub error: Option<String>,
    /// The import log.
    pub log_messages: Vec<String>,
    /// Duration of the import in milliseconds.
    pub duration_ms: u64,
}

impl ImportResult {
    /// Create a success result.
    pub fn success(source: impl Into<String>, results: LoadResults, duration_ms: u64) -> Self {
        Self {
            source: source.into(),
            success: true,
            load_results: Some(results),
            error: None,
            log_messages: Vec::new(),
            duration_ms,
        }
    }

    /// Create a failure result.
    pub fn failure(source: impl Into<String>, error: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            source: source.into(),
            success: false,
            load_results: None,
            error: Some(error.into()),
            log_messages: Vec::new(),
            duration_ms,
        }
    }

    /// Get the number of programs produced.
    pub fn num_programs(&self) -> usize {
        self.load_results.as_ref().map_or(0, |r| r.len())
    }
}

impl fmt::Display for ImportResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.success {
            write!(
                f,
                "Import '{}' succeeded: {} program(s) in {}ms",
                self.source,
                self.num_programs(),
                self.duration_ms
            )
        } else {
            write!(
                f,
                "Import '{}' failed: {} ({}ms)",
                self.source,
                self.error.as_deref().unwrap_or("unknown error"),
                self.duration_ms
            )
        }
    }
}

// ---------------------------------------------------------------------------
// ImportPlugin
// ---------------------------------------------------------------------------

/// Manages the import workflow for loading binary files into a Ghidra project.
///
/// Ported from `ghidra.plugin.importer.ImportPlugin`.
///
/// This struct orchestrates the complete import pipeline:
/// 1. Accept a file (path or raw bytes)
/// 2. Auto-detect or manually specify the loader
/// 3. Choose a load spec (language/compiler pair)
/// 4. Configure import options
/// 5. Execute the import
/// 6. Return results
///
/// # Example
///
/// ```rust,no_run
/// use ghidra_features::importer::import_plugin::ImportPlugin;
/// use ghidra_features::importer::LcsHintLoadSpecChooser;
/// use ghidra_features::loader::framework::LanguageCompilerSpecPair;
///
/// let mut plugin = ImportPlugin::new();
///
/// // Import with auto-detection
/// let data = std::fs::read("/path/to/binary.elf").unwrap();
/// let result = plugin.import_bytes(&data, "binary.elf").unwrap();
/// println!("{}", result);
///
/// // Import with explicit language hint
/// let chooser = LcsHintLoadSpecChooser::from_pair(
///     &LanguageCompilerSpecPair::new("x86:LE:64:default", "default"),
/// );
/// plugin.set_load_spec_chooser(Box::new(chooser));
/// let result = plugin.import_bytes(&data, "binary.elf").unwrap();
/// ```
pub struct ImportPlugin {
    /// Current state of the import pipeline.
    state: ImportState,
    /// The chosen load spec.
    selected_load_spec: Option<LoadSpec>,
    /// Load options to apply.
    options: Vec<LoadOption>,
    /// Strategy for choosing among available load specs.
    load_spec_chooser: Box<dyn LoadSpecChooser>,
    /// Strategy for choosing among available options.
    option_chooser: Box<dyn OptionChooser>,
    /// Filter restricting which loaders to try.
    loader_filter: Box<dyn LoaderFilter>,
    /// Whether to apply analysis after loading.
    apply_analysis: bool,
    /// Custom program name (overrides auto-detection).
    program_name: Option<String>,
    /// Destination folder in the project.
    destination_folder: String,
    /// Accumulated log messages.
    log: Vec<String>,
}

impl ImportPlugin {
    /// Create a new import plugin with default settings.
    pub fn new() -> Self {
        Self {
            state: ImportState::Idle,
            selected_load_spec: None,
            options: Vec::new(),
            load_spec_chooser: Box::new(FirstPreferredLoadSpecChooser),
            option_chooser: Box::new(DefaultOptionChooser),
            loader_filter: Box::new(AcceptAllLoaders),
            apply_analysis: true,
            program_name: None,
            destination_folder: "/".to_string(),
            log: Vec::new(),
        }
    }

    /// Get the current import state.
    pub fn state(&self) -> ImportState {
        self.state
    }

    /// Set the load spec chooser strategy.
    pub fn set_load_spec_chooser(&mut self, chooser: Box<dyn LoadSpecChooser>) {
        self.load_spec_chooser = chooser;
    }

    /// Set the option chooser strategy.
    pub fn set_option_chooser(&mut self, chooser: Box<dyn OptionChooser>) {
        self.option_chooser = chooser;
    }

    /// Set the loader filter.
    pub fn set_loader_filter(&mut self, filter: Box<dyn LoaderFilter>) {
        self.loader_filter = filter;
    }

    /// Set whether to apply analysis after loading.
    pub fn set_apply_analysis(&mut self, apply: bool) {
        self.apply_analysis = apply;
    }

    /// Set a custom program name.
    pub fn set_program_name(&mut self, name: impl Into<String>) {
        self.program_name = Some(name.into());
    }

    /// Set the destination folder.
    pub fn set_destination_folder(&mut self, folder: impl Into<String>) {
        self.destination_folder = folder.into();
    }

    /// Add a load option.
    pub fn add_option(&mut self, option: LoadOption) {
        self.options.push(option);
    }

    /// Set all load options at once.
    pub fn set_options(&mut self, options: Vec<LoadOption>) {
        self.options = options;
    }

    /// Get the accumulated log messages.
    pub fn log_messages(&self) -> &[String] {
        &self.log
    }

    /// Manually select a load spec.
    pub fn select_load_spec(&mut self, spec: LoadSpec) {
        self.selected_load_spec = Some(spec);
        self.state = ImportState::LoadSpecSelected;
    }

    /// Find available load specs for the given data.
    ///
    /// Returns pairs of (loader_name, load_specs) for each loader that
    /// recognizes the data format.
    pub fn find_load_specs(&self, data: &[u8]) -> Vec<(String, Vec<LoadSpec>)> {
        AutoImporter::find_load_specs(data)
    }

    /// Detect the format of binary data.
    pub fn detect_format(&self, data: &[u8]) -> Option<&'static str> {
        AutoImporter::detect_format(data)
    }

    /// Import binary data using auto-detection for loader and language.
    ///
    /// This is the simplest import path. The format is auto-detected,
    /// and the first preferred load spec is used.
    pub fn import_bytes(
        &mut self,
        data: &[u8],
        source_name: &str,
    ) -> Result<ImportResult, LoadError> {
        let start = std::time::Instant::now();
        self.state = ImportState::Running;
        self.log.clear();

        let name = self.program_name.as_deref().unwrap_or(source_name);
        self.log.push(format!("Importing '{}' ({} bytes)", name, data.len()));

        // Auto-detect format
        if let Some(format) = AutoImporter::detect_format(data) {
            self.log.push(format!("Detected format: {}", format));
            self.state = ImportState::Detected;
        } else {
            self.log.push("No specific format detected, using fallback".to_string());
        }

        // Run the import
        let mut message_log = MessageLog::new();
        let result = AutoImporter::import_bytes(data, name, &self.options, &mut message_log);

        // Collect log messages
        for (_level, msg) in message_log.messages() {
            self.log.push(msg.clone());
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(results) => {
                self.state = ImportState::Complete;
                self.log.push(format!(
                    "Import complete: {} program(s) loaded",
                    results.len()
                ));
                let mut import_result = ImportResult::success(source_name, results, duration_ms);
                import_result.log_messages = self.log.clone();
                Ok(import_result)
            }
            Err(e) => {
                self.state = ImportState::Failed;
                self.log.push(format!("Import failed: {}", e));
                let mut import_result =
                    ImportResult::failure(source_name, e.to_string(), duration_ms);
                import_result.log_messages = self.log.clone();
                Ok(import_result)
            }
        }
    }

    /// Import a file from disk.
    ///
    /// Reads the file and delegates to [`import_bytes`](ImportPlugin::import_bytes).
    pub fn import_file(&mut self, path: &Path) -> Result<ImportResult, LoadError> {
        let data = std::fs::read(path).map_err(|e| {
            LoadError::InvalidOption(format!("Failed to read '{}': {}", path.display(), e))
        })?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        self.import_bytes(&data, name)
    }

    /// Import binary data using a specific named loader.
    pub fn import_with_loader(
        &mut self,
        data: &[u8],
        source_name: &str,
        loader_name: &str,
    ) -> Result<ImportResult, LoadError> {
        let start = std::time::Instant::now();
        self.state = ImportState::Running;
        self.log.clear();

        let name = self.program_name.as_deref().unwrap_or(source_name);
        self.log.push(format!(
            "Importing '{}' with loader '{}' ({} bytes)",
            name, loader_name, data.len()
        ));

        let mut message_log = MessageLog::new();
        let result =
            AutoImporter::import_with_loader(data, loader_name, &self.options, &mut message_log);

        for (_level, msg) in message_log.messages() {
            self.log.push(msg.clone());
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(results) => {
                self.state = ImportState::Complete;
                let mut import_result = ImportResult::success(source_name, results, duration_ms);
                import_result.log_messages = self.log.clone();
                Ok(import_result)
            }
            Err(e) => {
                self.state = ImportState::Failed;
                let mut import_result =
                    ImportResult::failure(source_name, e.to_string(), duration_ms);
                import_result.log_messages = self.log.clone();
                Ok(import_result)
            }
        }
    }

    /// Import binary data using a program loader builder with full control.
    pub fn import_with_builder(
        &mut self,
        builder: ProgramLoaderBuilder,
        source_name: &str,
    ) -> Result<ImportResult, LoadError> {
        let start = std::time::Instant::now();
        self.state = ImportState::Running;
        self.log.clear();

        let mut message_log = MessageLog::new();
        let result = builder.run(&mut message_log);

        for (_level, msg) in message_log.messages() {
            self.log.push(msg.clone());
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(results) => {
                self.state = ImportState::Complete;
                let mut import_result = ImportResult::success(source_name, results, duration_ms);
                import_result.log_messages = self.log.clone();
                Ok(import_result)
            }
            Err(e) => {
                self.state = ImportState::Failed;
                let mut import_result =
                    ImportResult::failure(source_name, e.to_string(), duration_ms);
                import_result.log_messages = self.log.clone();
                Ok(import_result)
            }
        }
    }

    /// Reset the plugin state to idle.
    pub fn reset(&mut self) {
        self.state = ImportState::Idle;
        self.selected_load_spec = None;
        self.log.clear();
    }
}

impl Default for ImportPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BatchImportPlugin
// ---------------------------------------------------------------------------

/// Manages importing multiple files with consistent options.
///
/// Ported from the batch-import aspects of Ghidra's import workflow.
///
/// # Example
///
/// ```rust,no_run
/// use ghidra_features::importer::import_plugin::BatchImportPlugin;
///
/// let mut batch = BatchImportPlugin::new();
/// batch.set_apply_analysis(false);
/// batch.add_file("/path/to/a.exe");
/// batch.add_file("/path/to/b.elf");
///
/// for result in batch.import_all() {
///     println!("{}", result);
/// }
/// ```
pub struct BatchImportPlugin {
    /// Files to import.
    files: Vec<PathBuf>,
    /// Shared import plugin with common settings.
    plugin: ImportPlugin,
}

impl BatchImportPlugin {
    /// Create a new batch import plugin.
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            plugin: ImportPlugin::new(),
        }
    }

    /// Add a file to the batch.
    pub fn add_file(&mut self, path: impl Into<PathBuf>) {
        self.files.push(path.into());
    }

    /// Add multiple files to the batch.
    pub fn add_files(&mut self, paths: impl IntoIterator<Item = impl Into<PathBuf>>) {
        for p in paths {
            self.files.push(p.into());
        }
    }

    /// Set whether to apply analysis for all imports.
    pub fn set_apply_analysis(&mut self, apply: bool) {
        self.plugin.set_apply_analysis(apply);
    }

    /// Set the load spec chooser for all imports.
    pub fn set_load_spec_chooser(&mut self, chooser: Box<dyn LoadSpecChooser>) {
        self.plugin.set_load_spec_chooser(chooser);
    }

    /// Set the loader filter for all imports.
    pub fn set_loader_filter(&mut self, filter: Box<dyn LoaderFilter>) {
        self.plugin.set_loader_filter(filter);
    }

    /// Get the number of files in the batch.
    pub fn num_files(&self) -> usize {
        self.files.len()
    }

    /// Get the file paths.
    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    /// Import all files and return results.
    ///
    /// Each file is imported independently; failures do not stop the batch.
    pub fn import_all(&mut self) -> Vec<ImportResult> {
        let mut results = Vec::with_capacity(self.files.len());
        for path in &self.files {
            self.plugin.reset();
            let result = match self.plugin.import_file(path) {
                Ok(r) => r,
                Err(e) => ImportResult::failure(
                    path.display().to_string(),
                    e.to_string(),
                    0,
                ),
            };
            results.push(result);
        }
        results
    }

    /// Import all files and return only the failures.
    pub fn import_failures(&mut self) -> Vec<ImportResult> {
        self.import_all()
            .into_iter()
            .filter(|r| !r.success)
            .collect()
    }

    /// Import all files and report summary statistics.
    pub fn import_summary(&mut self) -> BatchImportSummary {
        let results = self.import_all();
        let total = results.len();
        let succeeded = results.iter().filter(|r| r.success).count();
        let failed = total - succeeded;
        let total_programs: usize = results.iter().map(|r| r.num_programs()).sum();
        let total_duration_ms: u64 = results.iter().map(|r| r.duration_ms).sum();

        BatchImportSummary {
            total,
            succeeded,
            failed,
            total_programs,
            total_duration_ms,
            results,
        }
    }
}

impl Default for BatchImportPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BatchImportSummary
// ---------------------------------------------------------------------------

/// Summary statistics from a batch import.
#[derive(Debug)]
pub struct BatchImportSummary {
    /// Total number of files processed.
    pub total: usize,
    /// Number of files that imported successfully.
    pub succeeded: usize,
    /// Number of files that failed to import.
    pub failed: usize,
    /// Total number of programs produced.
    pub total_programs: usize,
    /// Total duration in milliseconds.
    pub total_duration_ms: u64,
    /// Individual results.
    pub results: Vec<ImportResult>,
}

impl fmt::Display for BatchImportSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Batch import: {}/{} succeeded, {} program(s) in {}ms",
            self.succeeded, self.total, self.total_programs, self.total_duration_ms
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_plugin_new() {
        let plugin = ImportPlugin::new();
        assert_eq!(plugin.state(), ImportState::Idle);
        assert!(plugin.log_messages().is_empty());
    }

    #[test]
    fn test_import_plugin_detect_format() {
        let plugin = ImportPlugin::new();
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        assert!(plugin.detect_format(&data).is_some());
    }

    #[test]
    fn test_import_plugin_find_load_specs() {
        let plugin = ImportPlugin::new();
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 2;
        data[5] = 1;
        let specs = plugin.find_load_specs(&data);
        assert!(!specs.is_empty());
    }

    #[test]
    fn test_import_plugin_import_bytes() {
        let mut plugin = ImportPlugin::new();
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 2;
        data[5] = 1;
        data[6] = 1;
        data[16] = 2;
        data[18] = 62;

        let result = plugin.import_bytes(&data, "test.elf").unwrap();
        assert!(result.success);
        assert_eq!(result.num_programs(), 1);
        assert_eq!(plugin.state(), ImportState::Complete);
        assert!(!plugin.log_messages().is_empty());
    }

    #[test]
    fn test_import_plugin_with_name() {
        let mut plugin = ImportPlugin::new();
        plugin.set_program_name("custom_name");

        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 2;
        data[5] = 1;
        data[6] = 1;
        data[16] = 2;
        data[18] = 62;

        let result = plugin.import_bytes(&data, "test.elf").unwrap();
        assert!(result.success);
        assert_eq!(plugin.state(), ImportState::Complete);
    }

    #[test]
    fn test_import_plugin_reset() {
        let mut plugin = ImportPlugin::new();
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 2;
        data[5] = 1;
        data[6] = 1;
        data[16] = 2;
        data[18] = 62;

        let _ = plugin.import_bytes(&data, "test.elf");
        assert_eq!(plugin.state(), ImportState::Complete);

        plugin.reset();
        assert_eq!(plugin.state(), ImportState::Idle);
        assert!(plugin.log_messages().is_empty());
    }

    #[test]
    fn test_import_state_display() {
        assert_eq!(ImportState::Idle.to_string(), "Idle");
        assert_eq!(ImportState::Running.to_string(), "Running");
        assert_eq!(ImportState::Complete.to_string(), "Complete");
        assert_eq!(ImportState::Failed.to_string(), "Failed");
    }

    #[test]
    fn test_import_result_success() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 2;
        data[5] = 1;
        data[6] = 1;
        data[16] = 2;
        data[18] = 62;

        let mut log = MessageLog::new();
        let results = AutoImporter::import_bytes(&data, "test", &[], &mut log).unwrap();
        let import_result = ImportResult::success("test.elf", results, 100);
        assert!(import_result.success);
        assert!(import_result.to_string().contains("succeeded"));
    }

    #[test]
    fn test_import_result_failure() {
        let result = ImportResult::failure("bad.exe", "unsupported format", 50);
        assert!(!result.success);
        assert_eq!(result.num_programs(), 0);
        assert!(result.to_string().contains("failed"));
    }

    #[test]
    fn test_batch_import_plugin_new() {
        let batch = BatchImportPlugin::new();
        assert_eq!(batch.num_files(), 0);
        assert!(batch.files().is_empty());
    }

    #[test]
    fn test_batch_import_plugin_add_files() {
        let mut batch = BatchImportPlugin::new();
        batch.add_file("/path/a.exe");
        batch.add_files(vec!["/path/b.elf", "/path/c.so"]);
        assert_eq!(batch.num_files(), 3);
    }

    #[test]
    fn test_batch_import_summary_display() {
        let summary = BatchImportSummary {
            total: 5,
            succeeded: 3,
            failed: 2,
            total_programs: 3,
            total_duration_ms: 1500,
            results: Vec::new(),
        };
        let display = summary.to_string();
        assert!(display.contains("3/5"));
        assert!(display.contains("1500ms"));
    }
}
