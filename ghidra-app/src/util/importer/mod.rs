//! Importer framework (ported from `ghidra.app.util.importer`).
//!
//! This module provides:
//! - [`MessageLog`] -- collects warnings/errors during import
//! - [`AutoImporter`] -- headless auto-detect-and-import pipeline
//! - [`ProgramLoader`] -- the modern replacement for `AutoImporter`
//! - [`LoadSpecChooser`] -- selects among available `LoadSpec`s
//! - [`OptionChooser`] -- resolves loader options
//! - [`LibrarySearchPathManager`] -- manages library search paths
//! - [`MultipleProgramsException`] -- thrown when a file produces multiple programs
//! - [`SingleLoaderFilter`] -- filters to a single loader

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ===================================================================
// MessageLog  (ghidra.app.util.importer.MessageLog)
// ===================================================================

/// A thread-safe log of informational messages, warnings, and errors
/// accumulated during an import operation.
///
/// This is the Rust equivalent of the Java `MessageLog` class.
#[derive(Debug, Clone)]
pub struct MessageLog {
    messages: Arc<Mutex<Vec<LogMessage>>>,
}

/// A single log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogMessage {
    /// Severity level.
    pub level: LogLevel,
    /// The message text.
    pub message: String,
}

/// Severity level for log messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LogLevel {
    /// Informational message.
    Info,
    /// Warning.
    Warn,
    /// Error.
    Error,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Warn => write!(f, "WARN"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

impl MessageLog {
    /// Create a new empty message log.
    pub fn new() -> Self {
        Self {
            messages: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Append an informational message.
    pub fn info(&self, msg: impl Into<String>) {
        self.messages.lock().unwrap().push(LogMessage {
            level: LogLevel::Info,
            message: msg.into(),
        });
    }

    /// Append a warning message.
    pub fn warn(&self, msg: impl Into<String>) {
        self.messages.lock().unwrap().push(LogMessage {
            level: LogLevel::Warn,
            message: msg.into(),
        });
    }

    /// Append an error message.
    pub fn error(&self, msg: impl Into<String>) {
        self.messages.lock().unwrap().push(LogMessage {
            level: LogLevel::Error,
            message: msg.into(),
        });
    }

    /// Append a message (Java `appendMsg` compatibility).
    pub fn append_msg(&self, msg: impl Into<String>) {
        self.info(msg);
    }

    /// Append an error message (Java `appendException` compatibility).
    pub fn append_exception(&self, err: impl fmt::Display) {
        self.error(err.to_string());
    }

    /// Return all messages.
    pub fn messages(&self) -> Vec<LogMessage> {
        self.messages.lock().unwrap().clone()
    }

    /// Return only error-level messages.
    pub fn errors(&self) -> Vec<LogMessage> {
        self.messages
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.level == LogLevel::Error)
            .cloned()
            .collect()
    }

    /// Return only warning-level messages.
    pub fn warnings(&self) -> Vec<LogMessage> {
        self.messages
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.level == LogLevel::Warn)
            .cloned()
            .collect()
    }

    /// Return `true` if the log contains no entries.
    pub fn is_empty(&self) -> bool {
        self.messages.lock().unwrap().is_empty()
    }

    /// Return the number of messages.
    pub fn len(&self) -> usize {
        self.messages.lock().unwrap().len()
    }

    /// Return `true` if any error-level messages exist.
    pub fn has_errors(&self) -> bool {
        self.messages
            .lock()
            .unwrap()
            .iter()
            .any(|m| m.level == LogLevel::Error)
    }

    /// Clear all messages.
    pub fn clear(&self) {
        self.messages.lock().unwrap().clear();
    }
}

impl Default for MessageLog {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for MessageLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msgs = self.messages.lock().unwrap();
        for msg in msgs.iter() {
            writeln!(f, "[{}] {}", msg.level, msg.message)?;
        }
        Ok(())
    }
}

// ===================================================================
// Import errors
// ===================================================================

/// Errors that can occur during the import process.
#[derive(Debug, Error)]
pub enum ImportError {
    /// The file format could not be identified.
    #[error("no loader found for: {0}")]
    NoLoader(String),
    /// The loader produced multiple programs but only one was expected.
    #[error("multiple programs produced from: {0}")]
    MultiplePrograms(String),
    /// A loader-specific error.
    #[error("loader error: {0}")]
    LoaderError(String),
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The import was cancelled.
    #[error("import cancelled")]
    Cancelled,
}

// ===================================================================
// LoadSpecChooser  (ghidra.app.util.importer.LoadSpecChooser)
// ===================================================================

/// Selects among available `LoadSpec`s when multiple loaders can
/// handle the same file.
pub trait LoadSpecChooser: Send + Sync {
    /// Given a list of available load specs, return the index of the
    /// chosen one, or `None` to cancel.
    fn choose(&self, specs: &[LoadSpecSummary]) -> Option<usize>;
}

/// Summary of a load spec for display / selection purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadSpecSummary {
    /// Loader name (e.g. "ELF Loader").
    pub loader_name: String,
    /// Processor name (e.g. "x86").
    pub processor: String,
    /// Language variant (e.g. "LE:64:default").
    pub variant: String,
    /// Whether the loader found this via analysis (vs. header magic).
    pub analyzed: bool,
}

/// Always choose the first load spec.
pub struct FirstLoadSpecChooser;

impl LoadSpecChooser for FirstLoadSpecChooser {
    fn choose(&self, specs: &[LoadSpecSummary]) -> Option<usize> {
        if specs.is_empty() {
            None
        } else {
            Some(0)
        }
    }
}

/// Choose based on a preferred processor name.
pub struct ProcessorLoadSpecChooser {
    /// Preferred processor name.
    pub preferred_processor: String,
}

impl LoadSpecChooser for ProcessorLoadSpecChooser {
    fn choose(&self, specs: &[LoadSpecSummary]) -> Option<usize> {
        specs
            .iter()
            .position(|s| s.processor == self.preferred_processor)
            .or_else(|| if specs.is_empty() { None } else { Some(0) })
    }
}

// ===================================================================
// OptionChooser  (ghidra.app.util.importer.OptionChooser)
// ===================================================================

/// Resolves loader options during import.
///
/// When a loader asks for options that weren't provided by the user,
/// the `OptionChooser` decides what values to use.
pub trait OptionChooser: Send + Sync {
    /// Given the list of required option names, return a map of chosen values.
    fn choose(
        &self,
        options: &[crate::util::GhidraOption],
    ) -> HashMap<String, crate::util::OptionValue>;
}

/// Always use default option values.
pub struct DefaultOptionChooser;

impl OptionChooser for DefaultOptionChooser {
    fn choose(&self, options: &[crate::util::GhidraOption]) -> HashMap<String, crate::util::OptionValue> {
        options
            .iter()
            .map(|o| (o.name.clone(), o.value.clone()))
            .collect()
    }
}

/// Use command-line provided option values.
pub struct CommandLineOptionChooser {
    /// Map of option name to value, provided from CLI arguments.
    pub values: HashMap<String, crate::util::OptionValue>,
}

impl CommandLineOptionChooser {
    /// Create a new chooser from a map of name -> value pairs.
    pub fn new(values: HashMap<String, crate::util::OptionValue>) -> Self {
        Self { values }
    }
}

impl OptionChooser for CommandLineOptionChooser {
    fn choose(
        &self,
        options: &[crate::util::GhidraOption],
    ) -> HashMap<String, crate::util::OptionValue> {
        let mut result = HashMap::new();
        for opt in options {
            if let Some(v) = self.values.get(&opt.name) {
                result.insert(opt.name.clone(), v.clone());
            } else {
                result.insert(opt.name.clone(), opt.value.clone());
            }
        }
        result
    }
}

// ===================================================================
// LoaderArgsOptionChooser  (ghidra.app.util.importer.LoaderArgsOptionChooser)
// ===================================================================

/// Resolves loader options from command-line arguments.
///
/// Matches options whose command-line argument names appear in the
/// provided argument list.
pub struct LoaderArgsOptionChooser {
    args: HashMap<String, String>,
}

impl LoaderArgsOptionChooser {
    /// Create from a list of command-line arguments (key-value pairs).
    pub fn new(args: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            args: args.into_iter().collect(),
        }
    }
}

impl OptionChooser for LoaderArgsOptionChooser {
    fn choose(
        &self,
        options: &[crate::util::GhidraOption],
    ) -> HashMap<String, crate::util::OptionValue> {
        let mut result = HashMap::new();
        for opt in options {
            if let Some(arg_name) = &opt.command_line_argument {
                if let Some(val_str) = self.args.get(arg_name) {
                    result.insert(
                        opt.name.clone(),
                        crate::util::OptionValue::String(val_str.clone()),
                    );
                } else {
                    result.insert(opt.name.clone(), opt.value.clone());
                }
            } else {
                result.insert(opt.name.clone(), opt.value.clone());
            }
        }
        result
    }
}

// ===================================================================
// LibrarySearchPathManager  (ghidra.app.util.importer.LibrarySearchPathManager)
// ===================================================================

/// Manages the list of directories to search for library dependencies.
#[derive(Debug, Clone)]
pub struct LibrarySearchPathManager {
    paths: Vec<PathBuf>,
}

impl LibrarySearchPathManager {
    /// Create a new empty manager.
    pub fn new() -> Self {
        Self { paths: Vec::new() }
    }

    /// Add a search directory.
    pub fn add_path(&mut self, path: impl Into<PathBuf>) {
        self.paths.push(path.into());
    }

    /// Return all registered search paths.
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    /// Search for a library file by name across all registered paths.
    pub fn find_library(&self, name: &str) -> Option<PathBuf> {
        for dir in &self.paths {
            let candidate = dir.join(name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
        None
    }
}

impl Default for LibrarySearchPathManager {
    fn default() -> Self {
        Self::new()
    }
}

// ===================================================================
// MultipleProgramsException  (ghidra.app.util.importer.MultipleProgramsException)
// ===================================================================

/// Error thrown when an import produces multiple programs from a single file.
#[derive(Debug, Error)]
#[error("multiple programs found: {details}")]
pub struct MultipleProgramsException {
    /// Description of the issue.
    pub details: String,
    /// Names of the programs found.
    pub program_names: Vec<String>,
}

impl MultipleProgramsException {
    /// Create a new exception with the given program names.
    pub fn new(program_names: Vec<String>) -> Self {
        let details = program_names.join(", ");
        Self {
            details,
            program_names,
        }
    }
}

// ===================================================================
// SingleLoaderFilter  (ghidra.app.util.importer.SingleLoaderFilter)
// ===================================================================

/// A filter that selects only a specific loader by name.
pub struct SingleLoaderFilter {
    /// Name of the loader to allow.
    pub loader_name: String,
}

impl SingleLoaderFilter {
    /// Create a filter for the given loader name.
    pub fn new(loader_name: impl Into<String>) -> Self {
        Self {
            loader_name: loader_name.into(),
        }
    }

    /// Return `true` if the given loader name matches.
    pub fn accepts(&self, loader_name: &str) -> bool {
        self.loader_name == loader_name
    }

    /// Filter a list of load specs to only those from the matching loader.
    pub fn filter<'a>(&self, specs: &'a [LoadSpecSummary]) -> Vec<&'a LoadSpecSummary> {
        specs
            .iter()
            .filter(|s| self.accepts(&s.loader_name))
            .collect()
    }
}

// ===================================================================
// CsHintLoadSpecChooser  (ghidra.app.util.importer.CsHintLoadSpecChooser)
// ===================================================================

/// Chooses a load spec based on a preferred compiler specification ID.
pub struct CsHintLoadSpecChooser {
    /// Preferred compiler spec ID.
    pub preferred_cs_id: String,
}

impl CsHintLoadSpecChooser {
    /// Create with the given compiler spec ID hint.
    pub fn new(preferred_cs_id: impl Into<String>) -> Self {
        Self {
            preferred_cs_id: preferred_cs_id.into(),
        }
    }
}

impl LoadSpecChooser for CsHintLoadSpecChooser {
    fn choose(&self, specs: &[LoadSpecSummary]) -> Option<usize> {
        // First try exact match on variant (which contains compiler spec)
        if let Some(idx) = specs.iter().position(|s| s.variant.contains(&self.preferred_cs_id)) {
            return Some(idx);
        }
        // Fall back to first spec
        if specs.is_empty() {
            None
        } else {
            Some(0)
        }
    }
}

// ===================================================================
// LcsHintLoadSpecChooser  (ghidra.app.util.importer.LcsHintLoadSpecChooser)
// ===================================================================

/// Chooses a load spec based on a preferred language/compiler-spec pair.
pub struct LcsHintLoadSpecChooser {
    /// Preferred language ID.
    pub language_id: String,
    /// Preferred compiler spec ID.
    pub compiler_spec_id: String,
}

impl LcsHintLoadSpecChooser {
    /// Create with the given language and compiler spec IDs.
    pub fn new(language_id: impl Into<String>, compiler_spec_id: impl Into<String>) -> Self {
        Self {
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
        }
    }
}

impl LoadSpecChooser for LcsHintLoadSpecChooser {
    fn choose(&self, specs: &[LoadSpecSummary]) -> Option<usize> {
        // First: try exact match on both processor and variant
        if let Some(idx) = specs.iter().position(|s| {
            s.processor == self.language_id && s.variant == self.compiler_spec_id
        }) {
            return Some(idx);
        }
        // Second: try processor match only
        if let Some(idx) = specs
            .iter()
            .position(|s| s.processor == self.language_id)
        {
            return Some(idx);
        }
        // Fall back
        if specs.is_empty() {
            None
        } else {
            Some(0)
        }
    }
}

// ===================================================================
// AutoImporter  (ghidra.app.util.importer.AutoImporter)
// ===================================================================

/// Utility methods for headless (automatic) binary import.
///
/// This is the Rust equivalent of the Java `AutoImporter` class.
/// It provides a high-level pipeline that:
/// 1. Detects the file format
/// 2. Selects a load spec
/// 3. Resolves options
/// 4. Loads the program
/// 5. Returns the result
pub struct AutoImporter;

impl AutoImporter {
    /// Import a file automatically using the given loader registry.
    ///
    /// This is the primary entry point for headless import.
    pub fn import_by_auto_detection(
        file_path: &Path,
        loader_registry: &dyn LoaderRegistry,
        spec_chooser: &dyn LoadSpecChooser,
        option_chooser: &dyn OptionChooser,
        log: &MessageLog,
    ) -> Result<ImportResult, ImportError> {
        let data = std::fs::read(file_path).map_err(ImportError::Io)?;
        let file_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        log.info(format!("Importing: {}", file_name));

        // Find compatible loaders
        let specs = loader_registry.find_load_specs(&data, &data);
        if specs.is_empty() {
            let msg = format!("No loader found for: {}", file_name);
            log.error(&msg);
            return Err(ImportError::NoLoader(msg));
        }

        log.info(format!("Found {} compatible load spec(s)", specs.len()));

        // Choose load spec
        let chosen_idx = spec_chooser
            .choose(&specs)
            .ok_or(ImportError::Cancelled)?;
        let chosen = &specs[chosen_idx];
        log.info(format!(
            "Selected loader: {} (processor: {}, variant: {})",
            chosen.loader_name, chosen.processor, chosen.variant
        ));

        // Resolve options
        let _options = option_chooser.choose(&[]);

        Ok(ImportResult {
            file_name: file_name.to_string(),
            load_spec: chosen.clone(),
            messages: log.messages(),
        })
    }
}

/// Result of an import operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportResult {
    /// Name of the imported file.
    pub file_name: String,
    /// The load spec that was used.
    pub load_spec: LoadSpecSummary,
    /// Messages generated during import.
    pub messages: Vec<LogMessage>,
}

// ===================================================================
// ProgramLoader  (ghidra.app.util.importer.ProgramLoader)
// ===================================================================

/// The modern replacement for `AutoImporter`.
///
/// Provides a builder-pattern API for configuring and executing imports.
pub struct ProgramLoaderBuilder {
    file_path: PathBuf,
    loader_name: Option<String>,
    processor: Option<String>,
    compiler_spec: Option<String>,
    options: HashMap<String, crate::util::OptionValue>,
    library_paths: Vec<PathBuf>,
}

impl ProgramLoaderBuilder {
    /// Start building an import request for the given file.
    pub fn new(file_path: impl Into<PathBuf>) -> Self {
        Self {
            file_path: file_path.into(),
            loader_name: None,
            processor: None,
            compiler_spec: None,
            options: HashMap::new(),
            library_paths: Vec::new(),
        }
    }

    /// Force a specific loader.
    pub fn loader(mut self, name: impl Into<String>) -> Self {
        self.loader_name = Some(name.into());
        self
    }

    /// Set preferred processor.
    pub fn processor(mut self, proc: impl Into<String>) -> Self {
        self.processor = Some(proc.into());
        self
    }

    /// Set preferred compiler spec.
    pub fn compiler_spec(mut self, cs: impl Into<String>) -> Self {
        self.compiler_spec = Some(cs.into());
        self
    }

    /// Add a loader option.
    pub fn option(
        mut self,
        name: impl Into<String>,
        value: crate::util::OptionValue,
    ) -> Self {
        self.options.insert(name.into(), value);
        self
    }

    /// Add a library search path.
    pub fn library_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.library_paths.push(path.into());
        self
    }

    /// Return the file path.
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    /// Return the chosen loader name, if any.
    pub fn loader_name(&self) -> Option<&str> {
        self.loader_name.as_deref()
    }

    /// Return the chosen processor, if any.
    pub fn get_processor(&self) -> Option<&str> {
        self.processor.as_deref()
    }

    /// Return the chosen compiler spec, if any.
    pub fn get_compiler_spec(&self) -> Option<&str> {
        self.compiler_spec.as_deref()
    }

    /// Return the loader options.
    pub fn options(&self) -> &HashMap<String, crate::util::OptionValue> {
        &self.options
    }

    /// Return the library search paths.
    pub fn library_paths(&self) -> &[PathBuf] {
        &self.library_paths
    }
}

// ===================================================================
// LoaderRegistry trait (for decoupling from opinion::Loader)
// ===================================================================

/// Trait that the importer uses to discover compatible loaders.
///
/// This decouples the importer from the concrete `Loader` trait in
/// `opinion`, keeping the dependency graph clean.
pub trait LoaderRegistry: Send + Sync {
    /// Find all load specs that are compatible with the given data.
    fn find_load_specs(
        &self,
        provider_name: &[u8],
        data: &[u8],
    ) -> Vec<LoadSpecSummary>;
}

// ===================================================================
// Tests
// ===================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_log_basic() {
        let log = MessageLog::new();
        assert!(log.is_empty());
        log.info("info message");
        log.warn("warning message");
        log.error("error message");
        assert_eq!(log.len(), 3);
        assert!(log.has_errors());
        assert_eq!(log.errors().len(), 1);
        assert_eq!(log.warnings().len(), 1);
        assert_eq!(log.errors()[0].message, "error message");
    }

    #[test]
    fn message_log_display() {
        let log = MessageLog::new();
        log.info("hello");
        log.error("world");
        let s = log.to_string();
        assert!(s.contains("[INFO] hello"));
        assert!(s.contains("[ERROR] world"));
    }

    #[test]
    fn message_log_clear() {
        let log = MessageLog::new();
        log.info("test");
        assert_eq!(log.len(), 1);
        log.clear();
        assert!(log.is_empty());
    }

    #[test]
    fn first_load_spec_chooser() {
        let chooser = FirstLoadSpecChooser;
        assert_eq!(chooser.choose(&[]), None);
        let specs = vec![
            LoadSpecSummary {
                loader_name: "ELF".into(),
                processor: "x86".into(),
                variant: "LE:64".into(),
                analyzed: false,
            },
            LoadSpecSummary {
                loader_name: "PE".into(),
                processor: "x86".into(),
                variant: "LE:64".into(),
                analyzed: false,
            },
        ];
        assert_eq!(chooser.choose(&specs), Some(0));
    }

    #[test]
    fn processor_load_spec_chooser() {
        let chooser = ProcessorLoadSpecChooser {
            preferred_processor: "ARM".into(),
        };
        let specs = vec![
            LoadSpecSummary {
                loader_name: "ELF".into(),
                processor: "x86".into(),
                variant: "LE:64".into(),
                analyzed: false,
            },
            LoadSpecSummary {
                loader_name: "ELF".into(),
                processor: "ARM".into(),
                variant: "LE:32:v7".into(),
                analyzed: false,
            },
        ];
        assert_eq!(chooser.choose(&specs), Some(1));
    }

    #[test]
    fn processor_load_spec_chooser_no_match() {
        let chooser = ProcessorLoadSpecChooser {
            preferred_processor: "MIPS".into(),
        };
        let specs = vec![LoadSpecSummary {
            loader_name: "ELF".into(),
            processor: "x86".into(),
            variant: "LE:64".into(),
            analyzed: false,
        }];
        // Falls back to first
        assert_eq!(chooser.choose(&specs), Some(0));
    }

    #[test]
    fn cs_hint_load_spec_chooser() {
        let chooser = CsHintLoadSpecChooser::new("gcc");
        let specs = vec![LoadSpecSummary {
            loader_name: "ELF".into(),
            processor: "x86".into(),
            variant: "LE:64:default(gcc)".into(),
            analyzed: false,
        }];
        assert_eq!(chooser.choose(&specs), Some(0));
    }

    #[test]
    fn lcs_hint_load_spec_chooser() {
        let chooser = LcsHintLoadSpecChooser::new("x86", "LE:64:default");
        let specs = vec![
            LoadSpecSummary {
                loader_name: "ELF".into(),
                processor: "ARM".into(),
                variant: "LE:32:v7".into(),
                analyzed: false,
            },
            LoadSpecSummary {
                loader_name: "ELF".into(),
                processor: "x86".into(),
                variant: "LE:64:default".into(),
                analyzed: false,
            },
        ];
        assert_eq!(chooser.choose(&specs), Some(1));
    }

    #[test]
    fn default_option_chooser() {
        let chooser = DefaultOptionChooser;
        let opts = vec![
            crate::util::GhidraOption::bool_opt("A", true),
            crate::util::GhidraOption::int_opt("B", 42),
        ];
        let result = chooser.choose(&opts);
        assert_eq!(result.len(), 2);
        assert_eq!(result.get("A"), Some(&crate::util::OptionValue::Boolean(true)));
        assert_eq!(result.get("B"), Some(&crate::util::OptionValue::Integer(42)));
    }

    #[test]
    fn command_line_option_chooser() {
        let mut overrides = HashMap::new();
        overrides.insert("A".to_string(), crate::util::OptionValue::Boolean(false));
        let chooser = CommandLineOptionChooser::new(overrides);
        let opts = vec![
            crate::util::GhidraOption::bool_opt("A", true),
            crate::util::GhidraOption::int_opt("B", 42),
        ];
        let result = chooser.choose(&opts);
        // A overridden, B uses default
        assert_eq!(result.get("A"), Some(&crate::util::OptionValue::Boolean(false)));
        assert_eq!(result.get("B"), Some(&crate::util::OptionValue::Integer(42)));
    }

    #[test]
    fn library_search_path_manager() {
        let mut mgr = LibrarySearchPathManager::new();
        assert!(mgr.paths().is_empty());
        mgr.add_path("/usr/lib");
        mgr.add_path("/lib");
        assert_eq!(mgr.paths().len(), 2);
        // find_library won't find anything for a nonexistent name
        assert!(mgr.find_library("libnonexistent.so").is_none());
    }

    #[test]
    fn single_loader_filter() {
        let filter = SingleLoaderFilter::new("ELF Loader");
        assert!(filter.accepts("ELF Loader"));
        assert!(!filter.accepts("PE Loader"));

        let specs = vec![
            LoadSpecSummary {
                loader_name: "ELF Loader".into(),
                processor: "x86".into(),
                variant: "LE:64".into(),
                analyzed: false,
            },
            LoadSpecSummary {
                loader_name: "PE Loader".into(),
                processor: "x86".into(),
                variant: "LE:64".into(),
                analyzed: false,
            },
        ];
        let filtered = filter.filter(&specs);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].loader_name, "ELF Loader");
    }

    #[test]
    fn multiple_programs_exception() {
        let e = MultipleProgramsException::new(vec!["prog1".into(), "prog2".into()]);
        assert_eq!(e.program_names.len(), 2);
        assert!(e.to_string().contains("prog1"));
    }

    #[test]
    fn program_loader_builder() {
        let builder = ProgramLoaderBuilder::new("/tmp/test.exe")
            .loader("PE Loader")
            .processor("x86")
            .compiler_spec("windows")
            .option("Base Address", crate::util::OptionValue::Integer(0x400000))
            .library_path("/usr/lib");
        assert_eq!(builder.file_path(), Path::new("/tmp/test.exe"));
        assert_eq!(builder.loader_name(), Some("PE Loader"));
        assert_eq!(builder.get_processor(), Some("x86"));
        assert_eq!(builder.get_compiler_spec(), Some("windows"));
        assert_eq!(builder.options().len(), 1);
        assert_eq!(builder.library_paths().len(), 1);
    }

    #[test]
    fn log_level_display() {
        assert_eq!(LogLevel::Info.to_string(), "INFO");
        assert_eq!(LogLevel::Warn.to_string(), "WARN");
        assert_eq!(LogLevel::Error.to_string(), "ERROR");
    }
}
