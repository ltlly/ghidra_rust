//! BSim error and settings types.
//!
//! Ports `ghidra.features.bsim.query.description` error/settings types
//! that were not yet ported: `BSimSettings`, `ErrorInfo`, and
//! `BSimServerInformation`.

use serde::{Deserialize, Serialize};

// ============================================================================
// BSimSettings -- Signature generation settings
// ============================================================================

/// Settings that control how function signatures are generated in BSim.
///
/// Ports `ghidra.features.bsim.query.description.BSimSettings` (concept).
/// The Java version stores these in the `DatabaseInformation.settings` bitmask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BSimSettings {
    /// Whether to include mnemonic-based features in signatures.
    pub include_mnemonics: bool,
    /// Whether to include data-flow features in signatures.
    pub include_dataflow: bool,
    /// Whether to include CFG shape features in signatures.
    pub include_cfg_shape: bool,
    /// Whether to include call-graph information in signatures.
    pub include_callgraph: bool,
    /// Whether to include string references in signatures.
    pub include_string_refs: bool,
    /// Whether to normalize register names before hashing.
    pub normalize_registers: bool,
    /// The minimum function size (in bytes) to generate a signature for.
    pub min_function_size: u32,
    /// The LSH vector dimension.
    pub lsh_vector_dimension: u32,
    /// The number of LSH hash functions.
    pub lsh_hash_count: u32,
}

impl BSimSettings {
    /// Default settings for signature generation.
    pub fn default_settings() -> Self {
        Self {
            include_mnemonics: true,
            include_dataflow: true,
            include_cfg_shape: true,
            include_callgraph: false,
            include_string_refs: false,
            normalize_registers: true,
            min_function_size: 8,
            lsh_vector_dimension: 256,
            lsh_hash_count: 128,
        }
    }

    /// Encode settings into a compact bitmask (matches Ghidra's `settings` field).
    pub fn to_bitmask(&self) -> i32 {
        let mut mask: i32 = 0;
        if self.include_mnemonics { mask |= 0x01; }
        if self.include_dataflow { mask |= 0x02; }
        if self.include_cfg_shape { mask |= 0x04; }
        if self.include_callgraph { mask |= 0x08; }
        if self.include_string_refs { mask |= 0x10; }
        if self.normalize_registers { mask |= 0x20; }
        mask
    }

    /// Decode settings from a bitmask.
    pub fn from_bitmask(mask: i32) -> Self {
        Self {
            include_mnemonics: (mask & 0x01) != 0,
            include_dataflow: (mask & 0x02) != 0,
            include_cfg_shape: (mask & 0x04) != 0,
            include_callgraph: (mask & 0x08) != 0,
            include_string_refs: (mask & 0x10) != 0,
            normalize_registers: (mask & 0x20) != 0,
            min_function_size: 8,
            lsh_vector_dimension: 256,
            lsh_hash_count: 128,
        }
    }

    /// Check whether two settings are compatible for signature comparison.
    ///
    /// Returns `true` if signatures generated under `self` can be compared
    /// with signatures generated under `other` (major version and bitmask match).
    pub fn is_compatible(&self, other: &BSimSettings) -> bool {
        self.to_bitmask() == other.to_bitmask()
    }
}

impl Default for BSimSettings {
    fn default() -> Self {
        Self::default_settings()
    }
}

impl std::fmt::Display for BSimSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BSimSettings(mnemonics={}, dataflow={}, cfg={}, callgraph={}, strings={}, norm_regs={}, min_size={}, dim={}, hash_count={})",
            self.include_mnemonics,
            self.include_dataflow,
            self.include_cfg_shape,
            self.include_callgraph,
            self.include_string_refs,
            self.normalize_registers,
            self.min_function_size,
            self.lsh_vector_dimension,
            self.lsh_hash_count,
        )
    }
}

// ============================================================================
// ErrorInfo -- Describes an error from a BSim query operation
// ============================================================================

/// Describes an error that occurred during a BSim operation.
///
/// Ports `ghidra.features.bsim.query.description.ErrorInfo` (concept).
/// Ghidra's Java version uses `LSHException` for BSim-specific errors;
/// this struct provides a richer structured error type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorInfo {
    /// Error code (numeric).
    pub code: ErrorCode,
    /// Human-readable error message.
    pub message: String,
    /// Name of the database that was being operated on, if applicable.
    pub database_name: Option<String>,
    /// Name of the executable being operated on, if applicable.
    pub executable_name: Option<String>,
    /// Name of the function being operated on, if applicable.
    pub function_name: Option<String>,
    /// Stack trace or diagnostic details (for debugging).
    pub details: Option<String>,
}

/// Numeric error codes for BSim operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorCode {
    /// No error.
    Success,
    /// A general internal error.
    InternalError,
    /// Database does not exist.
    DatabaseNotFound,
    /// Database already exists.
    DatabaseAlreadyExists,
    /// Executable not found in database.
    ExecutableNotFound,
    /// Function not found in database.
    FunctionNotFound,
    /// Signature vector mismatch.
    SignatureMismatch,
    /// Duplicate entry (executable or function already exists).
    DuplicateEntry,
    /// Connection error (database or network).
    ConnectionError,
    /// Authentication error.
    AuthenticationError,
    /// Permission denied.
    PermissionDenied,
    /// Query timed out.
    Timeout,
    /// Invalid parameter or configuration.
    InvalidParameter,
    /// Database schema version mismatch.
    SchemaVersionMismatch,
    /// LSH vector factory error.
    VectorFactoryError,
    /// I/O error during XML serialization/deserialization.
    IoError,
}

impl ErrorCode {
    /// Whether this error code represents a successful result.
    pub fn is_success(&self) -> bool {
        matches!(self, ErrorCode::Success)
    }

    /// Whether this error is recoverable (retry might succeed).
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            ErrorCode::Timeout | ErrorCode::ConnectionError
        )
    }

    /// Get a short string label for this error code.
    pub fn label(&self) -> &'static str {
        match self {
            ErrorCode::Success => "OK",
            ErrorCode::InternalError => "INTERNAL",
            ErrorCode::DatabaseNotFound => "DB_NOT_FOUND",
            ErrorCode::DatabaseAlreadyExists => "DB_EXISTS",
            ErrorCode::ExecutableNotFound => "EXE_NOT_FOUND",
            ErrorCode::FunctionNotFound => "FUNC_NOT_FOUND",
            ErrorCode::SignatureMismatch => "SIG_MISMATCH",
            ErrorCode::DuplicateEntry => "DUPLICATE",
            ErrorCode::ConnectionError => "CONNECTION",
            ErrorCode::AuthenticationError => "AUTH",
            ErrorCode::PermissionDenied => "PERMISSION",
            ErrorCode::Timeout => "TIMEOUT",
            ErrorCode::InvalidParameter => "INVALID_PARAM",
            ErrorCode::SchemaVersionMismatch => "SCHEMA_MISMATCH",
            ErrorCode::VectorFactoryError => "VECTOR_ERROR",
            ErrorCode::IoError => "IO_ERROR",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

impl ErrorInfo {
    /// Create a new error info.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            database_name: None,
            executable_name: None,
            function_name: None,
            details: None,
        }
    }

    /// Create a success (no error) info.
    pub fn success() -> Self {
        Self {
            code: ErrorCode::Success,
            message: String::new(),
            database_name: None,
            executable_name: None,
            function_name: None,
            details: None,
        }
    }

    /// Set the database name.
    pub fn with_database(mut self, db: impl Into<String>) -> Self {
        self.database_name = Some(db.into());
        self
    }

    /// Set the executable name.
    pub fn with_executable(mut self, exe: impl Into<String>) -> Self {
        self.executable_name = Some(exe.into());
        self
    }

    /// Set the function name.
    pub fn with_function(mut self, func: impl Into<String>) -> Self {
        self.function_name = Some(func.into());
        self
    }

    /// Set the details.
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Whether this represents a successful result.
    pub fn is_success(&self) -> bool {
        self.code.is_success()
    }

    /// Whether this is recoverable.
    pub fn is_recoverable(&self) -> bool {
        self.code.is_recoverable()
    }
}

impl std::fmt::Display for ErrorInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)?;
        if let Some(ref db) = self.database_name {
            write!(f, " (db={})", db)?;
        }
        if let Some(ref exe) = self.executable_name {
            write!(f, " (exe={})", exe)?;
        }
        if let Some(ref func) = self.function_name {
            write!(f, " (func={})", func)?;
        }
        Ok(())
    }
}

impl std::error::Error for ErrorInfo {}

// ============================================================================
// BSimServerInformation -- Metadata about a BSim server instance
// ============================================================================

/// Information about a BSim server.
///
/// Ports the server-related metadata from Ghidra's BSim framework.
/// Used by the GUI to display connection status and server details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimServerInformation {
    /// The server URL or hostname.
    pub server_url: String,
    /// The port number.
    pub port: u16,
    /// The database name on the server.
    pub database_name: String,
    /// Whether the server is currently reachable.
    pub is_connected: bool,
    /// Server software version (if known).
    pub server_version: Option<String>,
    /// The database schema version on the server.
    pub schema_version: Option<String>,
    /// Number of executables in the database.
    pub exe_count: Option<usize>,
    /// Number of functions in the database.
    pub function_count: Option<usize>,
    /// Whether the database is read-only.
    pub read_only: bool,
    /// Whether the connection uses TLS/SSL.
    pub use_tls: bool,
    /// Server response time in milliseconds (from the last health check).
    pub latency_ms: Option<u64>,
}

impl BSimServerInformation {
    /// Create a new server information record.
    pub fn new(
        server_url: impl Into<String>,
        port: u16,
        database_name: impl Into<String>,
    ) -> Self {
        Self {
            server_url: server_url.into(),
            port,
            database_name: database_name.into(),
            is_connected: false,
            server_version: None,
            schema_version: None,
            exe_count: None,
            function_count: None,
            read_only: false,
            use_tls: false,
            latency_ms: None,
        }
    }

    /// Get the full connection string (url:port/database).
    pub fn connection_string(&self) -> String {
        format!("{}:{}/{}", self.server_url, self.port, self.database_name)
    }

    /// Mark as connected.
    pub fn set_connected(&mut self, connected: bool) {
        self.is_connected = connected;
    }

    /// Set the server version.
    pub fn set_server_version(&mut self, version: impl Into<String>) {
        self.server_version = Some(version.into());
    }

    /// Update function/exe counts.
    pub fn set_counts(&mut self, exe_count: usize, function_count: usize) {
        self.exe_count = Some(exe_count);
        self.function_count = Some(function_count);
    }
}

impl Default for BSimServerInformation {
    fn default() -> Self {
        Self {
            server_url: "localhost".to_string(),
            port: 5432,
            database_name: "bsim".to_string(),
            is_connected: false,
            server_version: None,
            schema_version: None,
            exe_count: None,
            function_count: None,
            read_only: false,
            use_tls: false,
            latency_ms: None,
        }
    }
}

impl std::fmt::Display for BSimServerInformation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.connection_string())?;
        if self.is_connected {
            write!(f, " [connected]")?;
        } else {
            write!(f, " [disconnected]")?;
        }
        if let Some(ref ver) = self.server_version {
            write!(f, " v{}", ver)?;
        }
        Ok(())
    }
}

// ============================================================================
// BSimHTMLGenerator -- Generates HTML reports from BSim results
// ============================================================================

/// Generates HTML reports from BSim query results.
///
/// Ports the concept from Ghidra's BSim GUI that renders function match
/// results as HTML for display in the results panel.
#[derive(Debug, Clone)]
pub struct BSimHTMLGenerator {
    /// Whether to include similarity scores in the output.
    pub show_similarity: bool,
    /// Whether to include significance scores.
    pub show_significance: bool,
    /// Whether to include executable metadata.
    pub show_executable_info: bool,
    /// Maximum number of results to render.
    pub max_results: usize,
    /// CSS class prefix for styling.
    pub css_prefix: String,
}

impl BSimHTMLGenerator {
    /// Create a new HTML generator with default settings.
    pub fn new() -> Self {
        Self {
            show_similarity: true,
            show_significance: true,
            show_executable_info: true,
            max_results: 500,
            css_prefix: "bsim".to_string(),
        }
    }

    /// Generate an HTML header for the report.
    pub fn header(&self, title: &str) -> String {
        format!(
            "<div class=\"{}-report\"><h2>{}</h2>",
            self.css_prefix,
            html_escape(title)
        )
    }

    /// Generate an HTML footer.
    pub fn footer(&self) -> String {
        "</div>".to_string()
    }

    /// Generate an HTML table row for a single match result.
    pub fn render_match_row(
        &self,
        func_name: &str,
        exe_name: &str,
        address: u64,
        similarity: f64,
        significance: f64,
    ) -> String {
        let mut row = format!(
            "<tr class=\"{}-row\">",
            self.css_prefix
        );
        row.push_str(&format!(
            "<td>{}</td><td>{}</td><td>0x{:x}</td>",
            html_escape(func_name),
            html_escape(exe_name),
            address,
        ));
        if self.show_similarity {
            row.push_str(&format!(
                "<td class=\"{}-similarity\">{:.4}</td>",
                self.css_prefix, similarity
            ));
        }
        if self.show_significance {
            row.push_str(&format!(
                "<td class=\"{}-significance\">{:.4}</td>",
                self.css_prefix, significance
            ));
        }
        row.push_str("</tr>");
        row
    }

    /// Generate the table header row.
    pub fn table_header(&self) -> String {
        let mut header = format!("<table class=\"{}-results\">\n<thead><tr>", self.css_prefix);
        header.push_str("<th>Function</th><th>Executable</th><th>Address</th>");
        if self.show_similarity {
            header.push_str("<th>Similarity</th>");
        }
        if self.show_significance {
            header.push_str("<th>Significance</th>");
        }
        header.push_str("</tr></thead>\n<tbody>");
        header
    }

    /// Close the table.
    pub fn table_footer(&self) -> String {
        "</tbody></table>".to_string()
    }

    /// Generate a summary section showing database information.
    pub fn render_database_summary(
        &self,
        db_name: &str,
        exe_count: usize,
        func_count: usize,
    ) -> String {
        format!(
            "<div class=\"{}-summary\">\
             <p>Database: <strong>{}</strong></p>\
             <p>Executables: <strong>{}</strong></p>\
             <p>Functions: <strong>{}</strong></p>\
             </div>",
            self.css_prefix,
            html_escape(db_name),
            exe_count,
            func_count,
        )
    }
}

impl Default for BSimHTMLGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Escape special HTML characters in a string.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- BSimSettings tests ----

    #[test]
    fn test_bsim_settings_default() {
        let settings = BSimSettings::default_settings();
        assert!(settings.include_mnemonics);
        assert!(settings.include_dataflow);
        assert!(settings.include_cfg_shape);
        assert!(!settings.include_callgraph);
        assert!(settings.normalize_registers);
        assert_eq!(settings.min_function_size, 8);
        assert_eq!(settings.lsh_vector_dimension, 256);
    }

    #[test]
    fn test_bsim_settings_bitmask_roundtrip() {
        let settings = BSimSettings::default_settings();
        let mask = settings.to_bitmask();
        let restored = BSimSettings::from_bitmask(mask);
        assert_eq!(settings, restored);
    }

    #[test]
    fn test_bsim_settings_bitmask_zero() {
        let settings = BSimSettings::from_bitmask(0);
        assert!(!settings.include_mnemonics);
        assert!(!settings.include_dataflow);
        assert!(!settings.include_cfg_shape);
    }

    #[test]
    fn test_bsim_settings_compatibility() {
        let s1 = BSimSettings::default_settings();
        let s2 = BSimSettings::default_settings();
        assert!(s1.is_compatible(&s2));

        let s3 = BSimSettings {
            include_callgraph: true,
            ..BSimSettings::default_settings()
        };
        assert!(!s1.is_compatible(&s3));
    }

    #[test]
    fn test_bsim_settings_display() {
        let settings = BSimSettings::default_settings();
        let display = format!("{}", settings);
        assert!(display.contains("BSimSettings"));
        assert!(display.contains("mnemonics=true"));
    }

    // ---- ErrorInfo tests ----

    #[test]
    fn test_error_info_success() {
        let err = ErrorInfo::success();
        assert!(err.is_success());
        assert!(err.message.is_empty());
    }

    #[test]
    fn test_error_info_with_context() {
        let err = ErrorInfo::new(ErrorCode::FunctionNotFound, "function 'main' not found")
            .with_database("mydb")
            .with_executable("test.exe")
            .with_function("main");
        assert!(!err.is_success());
        assert_eq!(err.code, ErrorCode::FunctionNotFound);
        assert_eq!(err.database_name.as_deref(), Some("mydb"));
        assert_eq!(err.executable_name.as_deref(), Some("test.exe"));
        assert_eq!(err.function_name.as_deref(), Some("main"));
    }

    #[test]
    fn test_error_code_recoverable() {
        assert!(ErrorCode::Timeout.is_recoverable());
        assert!(ErrorCode::ConnectionError.is_recoverable());
        assert!(!ErrorCode::DatabaseNotFound.is_recoverable());
        assert!(!ErrorCode::InternalError.is_recoverable());
    }

    #[test]
    fn test_error_code_label() {
        assert_eq!(ErrorCode::Success.label(), "OK");
        assert_eq!(ErrorCode::DatabaseNotFound.label(), "DB_NOT_FOUND");
        assert_eq!(ErrorCode::Timeout.label(), "TIMEOUT");
    }

    #[test]
    fn test_error_code_display() {
        assert_eq!(ErrorCode::Success.to_string(), "OK");
        assert_eq!(ErrorCode::ConnectionError.to_string(), "CONNECTION");
    }

    #[test]
    fn test_error_info_display() {
        let err = ErrorInfo::new(ErrorCode::Timeout, "query timed out")
            .with_database("bigdb");
        let display = format!("{}", err);
        assert!(display.contains("TIMEOUT"));
        assert!(display.contains("query timed out"));
        assert!(display.contains("bigdb"));
    }

    #[test]
    fn test_error_info_is_error() {
        let err = ErrorInfo::new(ErrorCode::InternalError, "something broke");
        let err_trait: &dyn std::error::Error = &err;
        assert!(err_trait.to_string().contains("something broke"));
    }

    // ---- BSimServerInformation tests ----

    #[test]
    fn test_server_info_new() {
        let info = BSimServerInformation::new("bsim.example.com", 5432, "mydb");
        assert_eq!(info.server_url, "bsim.example.com");
        assert_eq!(info.port, 5432);
        assert_eq!(info.database_name, "mydb");
        assert!(!info.is_connected);
    }

    #[test]
    fn test_server_info_connection_string() {
        let info = BSimServerInformation::new("host", 1234, "db");
        assert_eq!(info.connection_string(), "host:1234/db");
    }

    #[test]
    fn test_server_info_default() {
        let info = BSimServerInformation::default();
        assert_eq!(info.server_url, "localhost");
        assert_eq!(info.port, 5432);
        assert_eq!(info.database_name, "bsim");
    }

    #[test]
    fn test_server_info_set_connected() {
        let mut info = BSimServerInformation::new("host", 5432, "db");
        assert!(!info.is_connected);
        info.set_connected(true);
        assert!(info.is_connected);
    }

    #[test]
    fn test_server_info_set_counts() {
        let mut info = BSimServerInformation::new("host", 5432, "db");
        info.set_counts(100, 50000);
        assert_eq!(info.exe_count, Some(100));
        assert_eq!(info.function_count, Some(50000));
    }

    #[test]
    fn test_server_info_display() {
        let info = BSimServerInformation::new("host", 5432, "db");
        let display = format!("{}", info);
        assert!(display.contains("host:5432/db"));
        assert!(display.contains("disconnected"));

        let mut connected = info.clone();
        connected.set_connected(true);
        connected.set_server_version("2.0");
        let display = format!("{}", connected);
        assert!(display.contains("connected"));
        assert!(display.contains("v2.0"));
    }

    // ---- BSimHTMLGenerator tests ----

    #[test]
    fn test_html_generator_default() {
        let gen = BSimHTMLGenerator::new();
        assert!(gen.show_similarity);
        assert!(gen.show_significance);
        assert_eq!(gen.max_results, 500);
    }

    #[test]
    fn test_html_generator_header_footer() {
        let gen = BSimHTMLGenerator::new();
        let header = gen.header("Test Report");
        assert!(header.contains("Test Report"));
        assert!(header.contains("<div"));
        let footer = gen.footer();
        assert!(footer.contains("</div>"));
    }

    #[test]
    fn test_html_generator_match_row() {
        let gen = BSimHTMLGenerator::new();
        let row = gen.render_match_row("main", "test.exe", 0x1000, 0.95, 10.0);
        assert!(row.contains("<tr"));
        assert!(row.contains("main"));
        assert!(row.contains("test.exe"));
        assert!(row.contains("0x1000"));
        assert!(row.contains("0.9500"));
        assert!(row.contains("10.0000"));
    }

    #[test]
    fn test_html_generator_table_header() {
        let gen = BSimHTMLGenerator::new();
        let header = gen.table_header();
        assert!(header.contains("<table"));
        assert!(header.contains("Function"));
        assert!(header.contains("Similarity"));
        assert!(header.contains("Significance"));
    }

    #[test]
    fn test_html_generator_database_summary() {
        let gen = BSimHTMLGenerator::new();
        let summary = gen.render_database_summary("mydb", 100, 50000);
        assert!(summary.contains("mydb"));
        assert!(summary.contains("100"));
        assert!(summary.contains("50000"));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("a<b>c"), "a&lt;b&gt;c");
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(html_escape("it's"), "it&#x27;s");
    }

    #[test]
    fn test_html_generator_no_similarity() {
        let gen = BSimHTMLGenerator {
            show_similarity: false,
            show_significance: false,
            ..BSimHTMLGenerator::new()
        };
        let row = gen.render_match_row("main", "exe", 0x1000, 0.9, 1.0);
        assert!(!row.contains("similarity"));
        assert!(!row.contains("significance"));

        let header = gen.table_header();
        assert!(!header.contains("Similarity"));
        assert!(!header.contains("Significance"));
    }

    // ---- Serialization tests ----

    #[test]
    fn test_error_info_serialization() {
        let err = ErrorInfo::new(ErrorCode::DatabaseNotFound, "no such db")
            .with_database("missing");
        let json = serde_json::to_string(&err).unwrap();
        let restored: ErrorInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.code, ErrorCode::DatabaseNotFound);
        assert_eq!(restored.database_name.as_deref(), Some("missing"));
    }

    #[test]
    fn test_server_info_serialization() {
        let info = BSimServerInformation::new("host", 5432, "db");
        let json = serde_json::to_string(&info).unwrap();
        let restored: BSimServerInformation = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.server_url, "host");
        assert_eq!(restored.port, 5432);
    }

    #[test]
    fn test_bsim_settings_serialization() {
        let settings = BSimSettings::default_settings();
        let json = serde_json::to_string(&settings).unwrap();
        let restored: BSimSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(settings, restored);
    }
}
