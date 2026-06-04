//! Exporter trait and core types, ported from Ghidra's `Exporter.java`.
//!
//! Defines the [`Exporter`] trait that all format-specific exporters must
//! implement, along with the [`ExporterOption`] value type that mirrors
//! Ghidra's `Option` class.

use ghidra_core::program::Program;
use std::io;
use std::path::Path;

// ---------------------------------------------------------------------------
// ExporterOption — option values for exporters
// ---------------------------------------------------------------------------

/// A single exporter option, analogous to Ghidra's `Option` class.
///
/// Supports boolean, integer, string, and address-space option types.
#[derive(Debug, Clone)]
pub enum ExporterOption {
    /// Boolean option.
    Boolean {
        name: String,
        value: bool,
        group: Option<String>,
    },
    /// Integer option.
    Integer {
        name: String,
        value: i64,
        group: Option<String>,
    },
    /// String option.
    String {
        name: String,
        value: String,
        group: Option<String>,
    },
}

impl ExporterOption {
    /// Create a new boolean option.
    pub fn boolean(name: impl Into<String>, value: bool) -> Self {
        ExporterOption::Boolean {
            name: name.into(),
            value,
            group: None,
        }
    }

    /// Create a new integer option.
    pub fn integer(name: impl Into<String>, value: i64) -> Self {
        ExporterOption::Integer {
            name: name.into(),
            value,
            group: None,
        }
    }

    /// Create a new string option.
    pub fn string(name: impl Into<String>, value: impl Into<String>) -> Self {
        ExporterOption::String {
            name: name.into(),
            value: value.into(),
            group: None,
        }
    }

    /// Set the group for this option.
    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        match &mut self {
            ExporterOption::Boolean { group: g, .. }
            | ExporterOption::Integer { group: g, .. }
            | ExporterOption::String { group: g, .. } => *g = Some(group.into()),
        }
        self
    }

    /// Get the option name.
    pub fn name(&self) -> &str {
        match self {
            ExporterOption::Boolean { name, .. }
            | ExporterOption::Integer { name, .. }
            | ExporterOption::String { name, .. } => name,
        }
    }

    /// Get the option group.
    pub fn group(&self) -> Option<&str> {
        match self {
            ExporterOption::Boolean { group, .. }
            | ExporterOption::Integer { group, .. }
            | ExporterOption::String { group, .. } => group.as_deref(),
        }
    }
}

/// Utility to extract a boolean option value from a list.
pub fn get_bool_option(name: &str, options: &[ExporterOption], default: bool) -> bool {
    options
        .iter()
        .find(|o| o.name() == name)
        .and_then(|o| match o {
            ExporterOption::Boolean { value, .. } => Some(*value),
            _ => None,
        })
        .unwrap_or(default)
}

/// Utility to extract an integer option value from a list.
pub fn get_int_option(name: &str, options: &[ExporterOption], default: i64) -> i64 {
    options
        .iter()
        .find(|o| o.name() == name)
        .and_then(|o| match o {
            ExporterOption::Integer { value, .. } => Some(*value),
            _ => None,
        })
        .unwrap_or(default)
}

/// Utility to extract a string option value from a list.
pub fn get_string_option<'a>(
    name: &str,
    options: &'a [ExporterOption],
    default: &'a str,
) -> String {
    options
        .iter()
        .find(|o| o.name() == name)
        .and_then(|o| match o {
            ExporterOption::String { value, .. } => Some(value.clone()),
            _ => None,
        })
        .unwrap_or_else(|| default.to_string())
}

// ---------------------------------------------------------------------------
// Exporter trait
// ---------------------------------------------------------------------------

/// The trait that all exporters must implement.
///
/// Mirrors Ghidra's abstract `Exporter` class. Each exporter has a name,
/// file extension, optional help topic, and can list/set options and perform
/// the actual export.
pub trait Exporter {
    /// Returns the display name of this exporter (e.g., "Ascii", "Intel Hex").
    fn name(&self) -> &str;

    /// Returns the default file extension for this exporter (e.g., "txt", "hex").
    fn file_extension(&self) -> &str;

    /// Returns the help topic key for this exporter, if any.
    fn help_topic(&self) -> Option<&str> {
        None
    }

    /// Returns the default file extension prefixed with a dot (e.g., ".txt").
    fn default_suffix(&self) -> String {
        format!(".{}", self.file_extension())
    }

    /// Returns true if this exporter can export a program of the given type.
    ///
    /// Most exporters can export any `Program`. Some (like GZF/GDT) are
    /// more restrictive.
    fn can_export_program(&self) -> bool {
        true
    }

    /// Returns true if this exporter supports address-restricted export
    /// (i.e., exporting only a subset of addresses).
    fn supports_address_restricted_export(&self) -> bool {
        true
    }

    /// Returns the list of configurable options for this exporter.
    ///
    /// The default implementation returns an empty list (no options).
    fn get_options(&self) -> Vec<ExporterOption> {
        Vec::new()
    }

    /// Sets the option values for this exporter.
    ///
    /// # Errors
    ///
    /// Returns [`ExporterException`] if an option value is invalid.
    fn set_options(&mut self, options: &[ExporterOption]) -> Result<(), ExporterException> {
        let _ = options;
        Ok(())
    }

    /// Export the program to the given file path.
    ///
    /// # Arguments
    ///
    /// * `file` — output file path
    /// * `program` — the program to export
    /// * `start_addr` / `end_addr` — optional address range restriction
    ///
    /// # Returns
    ///
    /// `true` on success, `false` on failure (check the message log).
    fn export(
        &self,
        file: &Path,
        program: &Program,
        start_addr: Option<u64>,
        end_addr: Option<u64>,
    ) -> Result<bool, ExporterException>;
}

// ---------------------------------------------------------------------------
// ExporterException — error type for exporters
// ---------------------------------------------------------------------------

/// Error type for exporter operations.
///
/// Analogous to Ghidra's `ExporterException`.
#[derive(Debug)]
pub enum ExporterException {
    /// A generic export error with a message.
    Message(String),
    /// An I/O error during export.
    Io(io::Error),
    /// A cancelled operation.
    Cancelled,
}

impl std::fmt::Display for ExporterException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExporterException::Message(msg) => write!(f, "{}", msg),
            ExporterException::Io(e) => write!(f, "{}", e),
            ExporterException::Cancelled => write!(f, "Export cancelled"),
        }
    }
}

impl std::error::Error for ExporterException {}

impl From<io::Error> for ExporterException {
    fn from(e: io::Error) -> Self {
        ExporterException::Io(e)
    }
}

impl From<String> for ExporterException {
    fn from(s: String) -> Self {
        ExporterException::Message(s)
    }
}

impl From<&str> for ExporterException {
    fn from(s: &str) -> Self {
        ExporterException::Message(s.to_string())
    }
}

// ---------------------------------------------------------------------------
// ExporterRegistry — dynamic registry of exporters
// ---------------------------------------------------------------------------

/// A registry that holds multiple [`Exporter`] instances and dispatches
/// export requests by name.
///
/// # Example
///
/// ```ignore
/// let mut registry = ExporterRegistry::new();
/// registry.register(Box::new(AsciiExporter::new()));
/// registry.register(Box::new(BinaryExporter::new()));
/// registry.export_by_name("Ascii", &path, &program, None, None)?;
/// ```
pub struct ExporterRegistry {
    exporters: Vec<Box<dyn Exporter>>,
}

impl ExporterRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            exporters: Vec::new(),
        }
    }

    /// Create a registry pre-populated with all built-in exporters.
    pub fn with_defaults() -> Self {
        let mut reg = Self::new();
        reg.register(Box::new(super::ascii::AsciiExporter::new()));
        reg.register(Box::new(super::binary::BinaryExporter::new()));
        reg.register(Box::new(super::intel_hex::IntelHexExporter::new()));
        reg.register(Box::new(super::xml::XmlExporter::new()));
        reg.register(Box::new(super::html_export::HtmlExporter::new()));
        reg.register(Box::new(super::gzf::GzfExporter::new()));
        reg.register(Box::new(super::gdt::GdtExporter::new()));
        reg.register(Box::new(super::original_file::OriginalFileExporter::new()));
        reg
    }

    /// Register a new exporter.
    pub fn register(&mut self, exporter: Box<dyn Exporter>) {
        self.exporters.push(exporter);
    }

    /// Get the list of registered exporter names.
    pub fn names(&self) -> Vec<&str> {
        self.exporters.iter().map(|e| e.name()).collect()
    }

    /// Find an exporter by name (case-insensitive).
    pub fn find(&self, name: &str) -> Option<&dyn Exporter> {
        let lower = name.to_lowercase();
        self.exporters
            .iter()
            .find(|e| e.name().to_lowercase() == lower)
            .map(|e| e.as_ref())
    }

    /// Export using the exporter with the given name.
    pub fn export_by_name(
        &self,
        name: &str,
        file: &Path,
        program: &Program,
        start_addr: Option<u64>,
        end_addr: Option<u64>,
    ) -> Result<bool, ExporterException> {
        let exporter = self.find(name).ok_or_else(|| {
            ExporterException::Message(format!("Unknown exporter: '{}'", name))
        })?;
        exporter.export(file, program, start_addr, end_addr)
    }

    /// Get the number of registered exporters.
    pub fn len(&self) -> usize {
        self.exporters.len()
    }

    /// Returns true if no exporters are registered.
    pub fn is_empty(&self) -> bool {
        self.exporters.is_empty()
    }
}

impl Default for ExporterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyExporter;

    impl Exporter for DummyExporter {
        fn name(&self) -> &str {
            "Dummy"
        }
        fn file_extension(&self) -> &str {
            "dummy"
        }
        fn export(
            &self,
            _file: &Path,
            _program: &Program,
            _start: Option<u64>,
            _end: Option<u64>,
        ) -> Result<bool, ExporterException> {
            Ok(true)
        }
    }

    #[test]
    fn test_exporter_option_construction() {
        let opt = ExporterOption::boolean("test", true).with_group("group1");
        assert_eq!(opt.name(), "test");
        assert_eq!(opt.group(), Some("group1"));
    }

    #[test]
    fn test_get_bool_option() {
        let options = vec![
            ExporterOption::boolean("a", true),
            ExporterOption::boolean("b", false),
        ];
        assert!(get_bool_option("a", &options, false));
        assert!(!get_bool_option("b", &options, true));
        assert!(get_bool_option("c", &options, true)); // default
    }

    #[test]
    fn test_get_int_option() {
        let options = vec![ExporterOption::integer("count", 42)];
        assert_eq!(get_int_option("count", &options, 0), 42);
        assert_eq!(get_int_option("missing", &options, 7), 7);
    }

    #[test]
    fn test_get_string_option() {
        let options = vec![ExporterOption::string("name", "hello")];
        assert_eq!(get_string_option("name", &options, "def"), "hello");
        assert_eq!(get_string_option("missing", &options, "def"), "def");
    }

    #[test]
    fn test_exporter_registry() {
        let mut reg = ExporterRegistry::new();
        reg.register(Box::new(DummyExporter));
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.names(), vec!["Dummy"]);
        assert!(reg.find("Dummy").is_some());
        assert!(reg.find("dummy").is_some()); // case-insensitive
        assert!(reg.find("NoSuch").is_none());
    }

    #[test]
    fn test_exporter_default_suffix() {
        let e = DummyExporter;
        assert_eq!(e.default_suffix(), ".dummy");
    }

    #[test]
    fn test_exporter_exception_display() {
        let e = ExporterException::Message("test error".into());
        assert_eq!(format!("{}", e), "test error");
        let e = ExporterException::Cancelled;
        assert_eq!(format!("{}", e), "Export cancelled");
    }

    #[test]
    fn test_exporter_exception_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "not found");
        let e = ExporterException::from(io_err);
        assert!(matches!(e, ExporterException::Io(_)));
    }
}
