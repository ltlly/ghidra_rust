//! Import Service interface for requesting binary file imports.
//!
//! Ported from `ghidra.plugin.importer.ImportService`.
//!
//! Provides the [`ImportService`] trait -- the service interface through
//! which plugins and external code request file imports into a Ghidra
//! project. The [`DefaultImportService`] provides a concrete headless
//! implementation.
//!
//! # Architecture
//!
//! In Ghidra's plugin framework, `ImportService` is registered as a
//! service provider so that other plugins can import files without
//! directly depending on the importer plugin. This Rust port follows
//! the same pattern using trait objects:
//!
//! ```rust,no_run
//! use ghidra_features::importer::import_service::*;
//! use ghidra_features::importer::import_plugin::ImportPlugin;
//!
//! let plugin = ImportPlugin::new();
//! let service = DefaultImportService::new(Box::new(plugin));
//!
//! // External code imports via the service
//! let result = service.import_bytes(&[0x7f, 0x45, 0x4c, 0x46], "binary");
//! ```

use std::fmt;
use std::path::{Path, PathBuf};

use crate::loader::framework::{
    LanguageCompilerSpecPair, LoadError, LoadSpec,
};
use super::import_plugin::{ImportPlugin, ImportResult, BatchImportPlugin};
use super::LoadSpecChooser;

// ---------------------------------------------------------------------------
// ImportServiceConfig
// ---------------------------------------------------------------------------

/// Configuration for an import service instance.
#[derive(Debug, Clone)]
pub struct ImportServiceConfig {
    /// Whether to apply analysis after import.
    pub apply_analysis: bool,
    /// Default destination folder in the project.
    pub destination_folder: String,
    /// Whether to automatically load referenced libraries.
    pub load_libraries: bool,
    /// Default language/compiler spec pair (if set, overrides auto-detection).
    pub default_lcs: Option<LanguageCompilerSpecPair>,
    /// Maximum number of concurrent imports.
    pub max_concurrent: usize,
}

impl ImportServiceConfig {
    /// Create a default configuration.
    pub fn new() -> Self {
        Self {
            apply_analysis: true,
            destination_folder: "/".to_string(),
            load_libraries: true,
            default_lcs: None,
            max_concurrent: 1,
        }
    }

    /// Set whether to apply analysis.
    pub fn with_analysis(mut self, apply: bool) -> Self {
        self.apply_analysis = apply;
        self
    }

    /// Set the destination folder.
    pub fn with_destination(mut self, folder: impl Into<String>) -> Self {
        self.destination_folder = folder.into();
        self
    }

    /// Set a default language/compiler spec pair.
    pub fn with_default_lcs(mut self, lcs: LanguageCompilerSpecPair) -> Self {
        self.default_lcs = Some(lcs);
        self
    }

    /// Set maximum concurrent imports.
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = max;
        self
    }
}

impl Default for ImportServiceConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ImportService trait
// ---------------------------------------------------------------------------

/// Service interface for requesting binary file imports.
///
/// Ported from `ghidra.plugin.importer.ImportService`.
///
/// This trait defines the contract through which plugins and external
/// code request file imports. Implementations manage the import
/// lifecycle including format detection, loader selection, option
/// configuration, and result reporting.
///
/// # Implementations
///
/// - [`DefaultImportService`]: headless implementation backed by
///   [`ImportPlugin`].
///
/// # Usage
///
/// In a plugin architecture, the service would be registered with a
/// service provider and retrieved by consumers:
///
/// ```rust,ignore
/// // Provider side (importer plugin)
/// tool.add_service(Box::new(DefaultImportService::new(plugin)));
///
/// // Consumer side (any plugin needing import)
/// let service = tool.get_service::<dyn ImportService>();
/// let result = service.import_file(Path::new("/path/to/binary.elf"));
/// ```
pub trait ImportService: Send + Sync {
    /// Import a file from disk into the project.
    ///
    /// Auto-detects the file format and selects the best load spec.
    fn import_file(&self, path: &Path) -> Result<ImportResult, LoadError>;

    /// Import raw bytes into the project.
    ///
    /// The `source_name` is used as the program name hint.
    fn import_bytes(
        &self,
        data: &[u8],
        source_name: &str,
    ) -> Result<ImportResult, LoadError>;

    /// Import a file using a specific loader.
    fn import_file_with_loader(
        &self,
        path: &Path,
        loader_name: &str,
    ) -> Result<ImportResult, LoadError>;

    /// Import raw bytes using a specific loader.
    fn import_bytes_with_loader(
        &self,
        data: &[u8],
        source_name: &str,
        loader_name: &str,
    ) -> Result<ImportResult, LoadError>;

    /// Import a file with a language/compiler spec hint.
    fn import_file_with_lcs(
        &self,
        path: &Path,
        lcs: &LanguageCompilerSpecPair,
    ) -> Result<ImportResult, LoadError>;

    /// Import raw bytes with a language/compiler spec hint.
    fn import_bytes_with_lcs(
        &self,
        data: &[u8],
        source_name: &str,
        lcs: &LanguageCompilerSpecPair,
    ) -> Result<ImportResult, LoadError>;

    /// Import multiple files as a batch.
    fn import_batch(&self, paths: &[&Path]) -> Vec<ImportResult>;

    /// Detect the format of a file without importing it.
    fn detect_format(&self, data: &[u8]) -> Option<&'static str>;

    /// Find all available load specs for the given data.
    fn find_load_specs(&self, data: &[u8]) -> Vec<(String, Vec<LoadSpec>)>;

    /// Get the service configuration.
    fn config(&self) -> &ImportServiceConfig;
}

// ---------------------------------------------------------------------------
// DefaultImportService
// ---------------------------------------------------------------------------

/// Default headless implementation of [`ImportService`].
///
/// Backed by an [`ImportPlugin`] instance that manages the actual import
/// pipeline. Each import call creates a fresh plugin state to ensure
/// thread-safety for sequential calls.
///
/// # Thread Safety
///
/// This struct is `Send + Sync`. It uses interior mutability via
/// `std::sync::Mutex` to allow concurrent access from multiple threads,
/// though imports are serialized internally.
pub struct DefaultImportService {
    /// The underlying import plugin (shared via mutex for interior mutability).
    plugin: std::sync::Mutex<ImportPlugin>,
    /// Service configuration.
    config: ImportServiceConfig,
}

impl DefaultImportService {
    /// Create a new import service with default configuration.
    pub fn new(plugin: Box<ImportPlugin>) -> Self {
        Self {
            plugin: std::sync::Mutex::new(*plugin),
            config: ImportServiceConfig::default(),
        }
    }

    /// Create a new import service with custom configuration.
    pub fn with_config(plugin: Box<ImportPlugin>, config: ImportServiceConfig) -> Self {
        Self {
            plugin: std::sync::Mutex::new(*plugin),
            config,
        }
    }

    /// Create a new import service with a new default plugin.
    pub fn with_defaults() -> Self {
        Self {
            plugin: std::sync::Mutex::new(ImportPlugin::new()),
            config: ImportServiceConfig::default(),
        }
    }

    /// Apply configuration to the plugin before an import.
    fn configure_plugin(&self, plugin: &mut ImportPlugin) {
        plugin.set_apply_analysis(self.config.apply_analysis);
        plugin.set_destination_folder(&self.config.destination_folder);
        if let Some(lcs) = &self.config.default_lcs {
            use super::LcsHintLoadSpecChooser;
            plugin.set_load_spec_chooser(Box::new(LcsHintLoadSpecChooser::from_pair(lcs)));
        }
    }
}

impl ImportService for DefaultImportService {
    fn import_file(&self, path: &Path) -> Result<ImportResult, LoadError> {
        let mut plugin = self.plugin.lock().unwrap();
        plugin.reset();
        self.configure_plugin(&mut plugin);
        plugin.import_file(path)
    }

    fn import_bytes(
        &self,
        data: &[u8],
        source_name: &str,
    ) -> Result<ImportResult, LoadError> {
        let mut plugin = self.plugin.lock().unwrap();
        plugin.reset();
        self.configure_plugin(&mut plugin);
        plugin.import_bytes(data, source_name)
    }

    fn import_file_with_loader(
        &self,
        path: &Path,
        loader_name: &str,
    ) -> Result<ImportResult, LoadError> {
        let data = std::fs::read(path).map_err(|e| {
            LoadError::InvalidOption(format!("Failed to read '{}': {}", path.display(), e))
        })?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        self.import_bytes_with_loader(&data, name, loader_name)
    }

    fn import_bytes_with_loader(
        &self,
        data: &[u8],
        source_name: &str,
        loader_name: &str,
    ) -> Result<ImportResult, LoadError> {
        let mut plugin = self.plugin.lock().unwrap();
        plugin.reset();
        self.configure_plugin(&mut plugin);
        plugin.import_with_loader(data, source_name, loader_name)
    }

    fn import_file_with_lcs(
        &self,
        path: &Path,
        lcs: &LanguageCompilerSpecPair,
    ) -> Result<ImportResult, LoadError> {
        let data = std::fs::read(path).map_err(|e| {
            LoadError::InvalidOption(format!("Failed to read '{}': {}", path.display(), e))
        })?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        self.import_bytes_with_lcs(&data, name, lcs)
    }

    fn import_bytes_with_lcs(
        &self,
        data: &[u8],
        source_name: &str,
        lcs: &LanguageCompilerSpecPair,
    ) -> Result<ImportResult, LoadError> {
        let mut plugin = self.plugin.lock().unwrap();
        plugin.reset();
        self.configure_plugin(&mut plugin);
        plugin.set_load_spec_chooser(Box::new(super::LcsHintLoadSpecChooser::from_pair(lcs)));
        plugin.import_bytes(data, source_name)
    }

    fn import_batch(&self, paths: &[&Path]) -> Vec<ImportResult> {
        let mut results = Vec::with_capacity(paths.len());
        for path in paths {
            results.push(self.import_file(path).unwrap_or_else(|e| {
                ImportResult::failure(path.display().to_string(), e.to_string(), 0)
            }));
        }
        results
    }

    fn detect_format(&self, data: &[u8]) -> Option<&'static str> {
        super::AutoImporter::detect_format(data)
    }

    fn find_load_specs(&self, data: &[u8]) -> Vec<(String, Vec<LoadSpec>)> {
        super::AutoImporter::find_load_specs(data)
    }

    fn config(&self) -> &ImportServiceConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// ImportServiceError
// ---------------------------------------------------------------------------

/// Error type for import service operations.
#[derive(Debug)]
pub enum ImportError {
    /// The source file could not be read.
    IoError(std::io::Error),
    /// The loader encountered an error.
    LoadError(LoadError),
    /// No loader was found for the data.
    NoLoaderFound,
    /// The import was cancelled by the user.
    Cancelled,
    /// A configuration error.
    ConfigError(String),
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportError::IoError(e) => write!(f, "IO error: {}", e),
            ImportError::LoadError(e) => write!(f, "Load error: {}", e),
            ImportError::NoLoaderFound => write!(f, "No loader found for the given data"),
            ImportError::Cancelled => write!(f, "Import cancelled"),
            ImportError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
        }
    }
}

impl std::error::Error for ImportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ImportError::IoError(e) => Some(e),
            ImportError::LoadError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ImportError {
    fn from(e: std::io::Error) -> Self {
        ImportError::IoError(e)
    }
}

impl From<LoadError> for ImportError {
    fn from(e: LoadError) -> Self {
        ImportError::LoadError(e)
    }
}

// ---------------------------------------------------------------------------
// ImportRequest
// ---------------------------------------------------------------------------

/// A structured request for an import operation.
///
/// Encapsulates all parameters needed to perform an import, allowing
/// requests to be constructed, queued, or serialized before execution.
#[derive(Debug, Clone)]
pub struct ImportRequest {
    /// Source file path (if importing from disk).
    pub file_path: Option<PathBuf>,
    /// Source data (if importing from memory).
    pub data: Option<Vec<u8>>,
    /// Name hint for the source.
    pub source_name: String,
    /// Preferred loader name (None = auto-detect).
    pub loader_name: Option<String>,
    /// Preferred language/compiler spec pair (None = auto-detect).
    pub lcs: Option<LanguageCompilerSpecPair>,
    /// Whether to apply analysis.
    pub apply_analysis: bool,
    /// Destination folder in the project.
    pub destination_folder: String,
}

impl ImportRequest {
    /// Create a request to import a file from disk.
    pub fn file(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        Self {
            file_path: Some(path),
            data: None,
            source_name: name,
            loader_name: None,
            lcs: None,
            apply_analysis: true,
            destination_folder: "/".to_string(),
        }
    }

    /// Create a request to import from memory.
    pub fn bytes(data: Vec<u8>, name: impl Into<String>) -> Self {
        Self {
            file_path: None,
            data: Some(data),
            source_name: name.into(),
            loader_name: None,
            lcs: None,
            apply_analysis: true,
            destination_folder: "/".to_string(),
        }
    }

    /// Set the preferred loader.
    pub fn with_loader(mut self, name: impl Into<String>) -> Self {
        self.loader_name = Some(name.into());
        self
    }

    /// Set the preferred language/compiler spec pair.
    pub fn with_lcs(mut self, lcs: LanguageCompilerSpecPair) -> Self {
        self.lcs = Some(lcs);
        self
    }

    /// Set whether to apply analysis.
    pub fn with_analysis(mut self, apply: bool) -> Self {
        self.apply_analysis = apply;
        self
    }

    /// Set the destination folder.
    pub fn with_destination(mut self, folder: impl Into<String>) -> Self {
        self.destination_folder = folder.into();
        self
    }

    /// Execute this request against an import service.
    pub fn execute(&self, service: &dyn ImportService) -> Result<ImportResult, LoadError> {
        if let Some(data) = &self.data {
            if let Some(loader) = &self.loader_name {
                service.import_bytes_with_loader(data, &self.source_name, loader)
            } else if let Some(lcs) = &self.lcs {
                service.import_bytes_with_lcs(data, &self.source_name, lcs)
            } else {
                service.import_bytes(data, &self.source_name)
            }
        } else if let Some(path) = &self.file_path {
            if let Some(loader) = &self.loader_name {
                service.import_file_with_loader(path, loader)
            } else if let Some(lcs) = &self.lcs {
                service.import_file_with_lcs(path, lcs)
            } else {
                service.import_file(path)
            }
        } else {
            Err(LoadError::InvalidOption(
                "ImportRequest has no source data or file path".into(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_service_config_default() {
        let config = ImportServiceConfig::new();
        assert!(config.apply_analysis);
        assert_eq!(config.destination_folder, "/");
        assert!(config.load_libraries);
        assert!(config.default_lcs.is_none());
        assert_eq!(config.max_concurrent, 1);
    }

    #[test]
    fn test_import_service_config_builder() {
        let lcs = LanguageCompilerSpecPair::new("x86:LE:64:default", "default");
        let config = ImportServiceConfig::new()
            .with_analysis(false)
            .with_destination("/imports")
            .with_default_lcs(lcs)
            .with_max_concurrent(4);
        assert!(!config.apply_analysis);
        assert_eq!(config.destination_folder, "/imports");
        assert!(config.default_lcs.is_some());
        assert_eq!(config.max_concurrent, 4);
    }

    #[test]
    fn test_default_import_service_detect_format() {
        let service = DefaultImportService::with_defaults();
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        assert!(service.detect_format(&data).is_some());
    }

    #[test]
    fn test_default_import_service_find_load_specs() {
        let service = DefaultImportService::with_defaults();
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 2;
        data[5] = 1;
        let specs = service.find_load_specs(&data);
        assert!(!specs.is_empty());
    }

    #[test]
    fn test_default_import_service_import_bytes() {
        let service = DefaultImportService::with_defaults();
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 2;
        data[5] = 1;
        data[6] = 1;
        data[16] = 2;
        data[18] = 62;

        let result = service.import_bytes(&data, "test.elf").unwrap();
        assert!(result.success);
        assert_eq!(result.num_programs(), 1);
    }

    #[test]
    fn test_default_import_service_import_bytes_with_lcs() {
        let service = DefaultImportService::with_defaults();
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 2;
        data[5] = 1;
        data[6] = 1;
        data[16] = 2;
        data[18] = 62;

        let lcs = LanguageCompilerSpecPair::new("x86:LE:64:default", "default");
        let result = service.import_bytes_with_lcs(&data, "test.elf", &lcs).unwrap();
        assert!(result.success);
    }

    #[test]
    fn test_import_request_file() {
        let req = ImportRequest::file("/path/to/binary.elf");
        assert_eq!(req.source_name, "binary.elf");
        assert!(req.file_path.is_some());
        assert!(req.data.is_none());
        assert!(req.loader_name.is_none());
        assert!(req.apply_analysis);
    }

    #[test]
    fn test_import_request_bytes() {
        let data = vec![0u8; 16];
        let req = ImportRequest::bytes(data, "test.bin")
            .with_loader("ELF")
            .with_analysis(false)
            .with_destination("/imports");
        assert_eq!(req.source_name, "test.bin");
        assert!(req.file_path.is_none());
        assert!(req.data.is_some());
        assert_eq!(req.loader_name.as_deref(), Some("ELF"));
        assert!(!req.apply_analysis);
        assert_eq!(req.destination_folder, "/imports");
    }

    #[test]
    fn test_import_request_with_lcs() {
        let lcs = LanguageCompilerSpecPair::new("ARM:LE:32:v8", "gcc");
        let req = ImportRequest::file("/firmware.bin").with_lcs(lcs);
        assert!(req.lcs.is_some());
    }

    #[test]
    fn test_import_request_execute_no_source() {
        let service = DefaultImportService::with_defaults();
        let req = ImportRequest {
            file_path: None,
            data: None,
            source_name: "empty".to_string(),
            loader_name: None,
            lcs: None,
            apply_analysis: true,
            destination_folder: "/".to_string(),
        };
        let result = req.execute(&service);
        assert!(result.is_err());
    }

    #[test]
    fn test_import_error_display() {
        assert_eq!(
            ImportError::NoLoaderFound.to_string(),
            "No loader found for the given data"
        );
        assert_eq!(
            ImportError::Cancelled.to_string(),
            "Import cancelled"
        );
        assert_eq!(
            ImportError::ConfigError("bad".into()).to_string(),
            "Configuration error: bad"
        );
    }

    #[test]
    fn test_import_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let err: ImportError = io_err.into();
        assert!(matches!(err, ImportError::IoError(_)));
    }

    #[test]
    fn test_import_error_from_load_error() {
        let load_err = LoadError::InvalidOption("test".into());
        let err: ImportError = load_err.into();
        assert!(matches!(err, ImportError::LoadError(_)));
    }

    #[test]
    fn test_default_import_service_config_accessor() {
        let config = ImportServiceConfig::new().with_analysis(false);
        let service = DefaultImportService::with_config(
            Box::new(ImportPlugin::new()),
            config,
        );
        assert!(!service.config().apply_analysis);
    }
}
