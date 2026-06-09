//! Compile -- source code compilation integration for Ghidra.
//!
//! Ported from Ghidra's `Features/Compile` concept:
//! a plugin/provider pair that manages compilation of source code
//! associated with a program and displays the results.
//!
//! # Architecture
//!
//! ```text
//! CompilePlugin
//!   ├── CompileProvider  (primary provider, always connected)
//!   ├── compilation_state (current compilation status)
//!   └── compile_actions   (build, clean, rebuild actions)
//! ```
//!
//! # Key Types
//!
//! - [`CompilePlugin`] -- Top-level plugin managing compilation lifecycle
//! - [`CompileProvider`] -- Provider displaying compilation output and errors
//! - [`CompileStatus`] -- Current state of a compilation
//! - [`CompileMessage`] -- Individual compiler message (error, warning, info)
//! - [`CompileConfig`] -- Configuration for the compilation process

/// Compile plugin -- top-level plugin coordinating compilation.
///
/// Ported from the `CompilePlugin` Java class.
pub mod compile_plugin;

/// Compile provider -- displays compilation output and error listing.
///
/// Ported from the `CompileProvider` Java class.
pub mod compile_provider;

use std::path::PathBuf;

// ============================================================================
// CompileStatus -- current state of a compilation
// ============================================================================

/// The status of a compilation job.
///
/// Ported from Ghidra's compile status tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompileStatus {
    /// No compilation has been started.
    Idle,
    /// A compilation is currently in progress.
    Building,
    /// The compilation completed successfully.
    Success,
    /// The compilation failed with errors.
    Failed,
    /// The compilation was cancelled by the user.
    Cancelled,
}

impl CompileStatus {
    /// Returns `true` if the compilation is in a terminal state
    /// (success, failed, or cancelled).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Success | Self::Failed | Self::Cancelled)
    }

    /// Returns `true` if the compilation completed without errors.
    pub fn is_success(&self) -> bool {
        *self == Self::Success
    }

    /// Human-readable label for this status.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Building => "Building",
            Self::Success => "Success",
            Self::Failed => "Failed",
            Self::Cancelled => "Cancelled",
        }
    }
}

impl Default for CompileStatus {
    fn default() -> Self {
        Self::Idle
    }
}

// ============================================================================
// CompileSeverity -- severity of a compile message
// ============================================================================

/// Severity level for compiler messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CompileSeverity {
    /// Informational message.
    Info,
    /// Warning message.
    Warning,
    /// Error message.
    Error,
    /// Fatal error -- compilation cannot continue.
    Fatal,
}

impl CompileSeverity {
    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Fatal => "fatal",
        }
    }
}

// ============================================================================
// CompileMessage -- a single compiler diagnostic
// ============================================================================

/// A single message emitted by the compiler during compilation.
///
/// Ported from the compiler output parsing in Ghidra's compile framework.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileMessage {
    /// Severity of the message.
    pub severity: CompileSeverity,
    /// Source file path (relative or absolute).
    pub file: Option<PathBuf>,
    /// Line number in the source file (1-based).
    pub line: Option<u32>,
    /// Column number in the source file (1-based).
    pub column: Option<u32>,
    /// The message text.
    pub message: String,
    /// Optional error code from the compiler (e.g., "E0308").
    pub error_code: Option<String>,
}

impl CompileMessage {
    /// Create an info-level message.
    pub fn info(message: impl Into<String>) -> Self {
        Self {
            severity: CompileSeverity::Info,
            file: None,
            line: None,
            column: None,
            message: message.into(),
            error_code: None,
        }
    }

    /// Create a warning message.
    pub fn warning(message: impl Into<String>) -> Self {
        Self {
            severity: CompileSeverity::Warning,
            file: None,
            line: None,
            column: None,
            message: message.into(),
            error_code: None,
        }
    }

    /// Create an error message.
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            severity: CompileSeverity::Error,
            file: None,
            line: None,
            column: None,
            message: message.into(),
            error_code: None,
        }
    }

    /// Create a fatal error message.
    pub fn fatal(message: impl Into<String>) -> Self {
        Self {
            severity: CompileSeverity::Fatal,
            file: None,
            line: None,
            column: None,
            message: message.into(),
            error_code: None,
        }
    }

    /// Set the source file location for this message.
    pub fn with_location(
        mut self,
        file: impl Into<PathBuf>,
        line: u32,
        column: Option<u32>,
    ) -> Self {
        self.file = Some(file.into());
        self.line = Some(line);
        self.column = column;
        self
    }

    /// Set the compiler error code for this message.
    pub fn with_error_code(mut self, code: impl Into<String>) -> Self {
        self.error_code = Some(code.into());
        self
    }

    /// Returns `true` if this message represents an error or fatal error.
    pub fn is_error(&self) -> bool {
        matches!(self.severity, CompileSeverity::Error | CompileSeverity::Fatal)
    }

    /// Format the location as a string (e.g., "file.rs:10:5").
    pub fn location_string(&self) -> Option<String> {
        let file = self.file.as_ref()?;
        let line = self.line?;
        let mut loc = format!("{}:{}", file.display(), line);
        if let Some(col) = self.column {
            loc.push_str(&format!(":{}", col));
        }
        Some(loc)
    }

    /// Format the full message with location prefix.
    pub fn formatted(&self) -> String {
        let severity_str = self.severity.label();
        match self.location_string() {
            Some(loc) => format!("[{}] {}: {}", severity_str, loc, self.message),
            None => format!("[{}] {}", severity_str, self.message),
        }
    }
}

// ============================================================================
// CompileConfig -- compilation configuration
// ============================================================================

/// Configuration for a compilation job.
///
/// Ported from Ghidra's compile configuration options.
#[derive(Debug, Clone)]
pub struct CompileConfig {
    /// The compiler command (e.g., "gcc", "rustc", "javac").
    pub compiler: String,
    /// Source file(s) to compile.
    pub source_files: Vec<PathBuf>,
    /// Output directory for compiled artifacts.
    pub output_dir: Option<PathBuf>,
    /// Additional compiler flags.
    pub flags: Vec<String>,
    /// Working directory for the compilation.
    pub working_dir: Option<PathBuf>,
    /// Environment variables to set for the compiler process.
    pub env_vars: Vec<(String, String)>,
    /// Whether to enable verbose output.
    pub verbose: bool,
    /// Maximum compilation time in seconds (0 = no limit).
    pub timeout_secs: u64,
}

impl CompileConfig {
    /// Create a new compile configuration for the given compiler.
    pub fn new(compiler: impl Into<String>) -> Self {
        Self {
            compiler: compiler.into(),
            source_files: Vec::new(),
            output_dir: None,
            flags: Vec::new(),
            working_dir: None,
            env_vars: Vec::new(),
            verbose: false,
            timeout_secs: 0,
        }
    }

    /// Add a source file to compile.
    pub fn add_source(mut self, path: impl Into<PathBuf>) -> Self {
        self.source_files.push(path.into());
        self
    }

    /// Set the output directory.
    pub fn output_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.output_dir = Some(dir.into());
        self
    }

    /// Add a compiler flag.
    pub fn flag(mut self, flag: impl Into<String>) -> Self {
        self.flags.push(flag.into());
        self
    }

    /// Set the working directory.
    pub fn working_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    /// Add an environment variable.
    pub fn env_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.push((key.into(), value.into()));
        self
    }

    /// Enable verbose output.
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Set the timeout in seconds.
    pub fn timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Build the command-line arguments for the compiler.
    pub fn build_args(&self) -> Vec<String> {
        let mut args = self.flags.clone();
        for src in &self.source_files {
            args.push(src.to_string_lossy().into_owned());
        }
        if let Some(ref out) = self.output_dir {
            args.push("-o".into());
            args.push(out.to_string_lossy().into_owned());
        }
        args
    }
}

impl Default for CompileConfig {
    fn default() -> Self {
        Self::new("gcc")
    }
}

// ============================================================================
// CompileResult -- result of a compilation job
// ============================================================================

/// The result of a compilation job.
#[derive(Debug, Clone)]
pub struct CompileResult {
    /// Final status of the compilation.
    pub status: CompileStatus,
    /// All messages emitted during compilation.
    pub messages: Vec<CompileMessage>,
    /// Total compilation time in milliseconds.
    pub elapsed_ms: u64,
    /// The configuration used for this compilation.
    pub config: CompileConfig,
    /// Standard output from the compiler.
    pub stdout: String,
    /// Standard error from the compiler.
    pub stderr: String,
    /// Exit code of the compiler process (if available).
    pub exit_code: Option<i32>,
}

impl CompileResult {
    /// Create a new compile result.
    pub fn new(config: CompileConfig) -> Self {
        Self {
            status: CompileStatus::Idle,
            messages: Vec::new(),
            elapsed_ms: 0,
            config,
            stdout: String::new(),
            stderr: String::new(),
            exit_code: None,
        }
    }

    /// Returns `true` if the compilation succeeded.
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    /// Count messages by severity.
    pub fn count_by_severity(&self, severity: CompileSeverity) -> usize {
        self.messages.iter().filter(|m| m.severity == severity).count()
    }

    /// Get only error messages.
    pub fn errors(&self) -> Vec<&CompileMessage> {
        self.messages.iter().filter(|m| m.is_error()).collect()
    }

    /// Get only warning messages.
    pub fn warnings(&self) -> Vec<&CompileMessage> {
        self.messages
            .iter()
            .filter(|m| m.severity == CompileSeverity::Warning)
            .collect()
    }

    /// Summary string (e.g., "Build succeeded (3 warnings)" or "Build failed (2 errors)").
    pub fn summary(&self) -> String {
        let err_count = self.count_by_severity(CompileSeverity::Error)
            + self.count_by_severity(CompileSeverity::Fatal);
        let warn_count = self.count_by_severity(CompileSeverity::Warning);

        match self.status {
            CompileStatus::Success => {
                if warn_count > 0 {
                    format!("Build succeeded ({} warnings)", warn_count)
                } else {
                    "Build succeeded".into()
                }
            }
            CompileStatus::Failed => {
                format!(
                    "Build failed ({} errors, {} warnings)",
                    err_count, warn_count
                )
            }
            CompileStatus::Cancelled => "Build cancelled".into(),
            CompileStatus::Building => "Building...".into(),
            CompileStatus::Idle => "No build".into(),
        }
    }

    /// Elapsed time formatted as a human-readable string.
    pub fn elapsed_string(&self) -> String {
        if self.elapsed_ms < 1000 {
            format!("{}ms", self.elapsed_ms)
        } else {
            format!("{:.1}s", self.elapsed_ms as f64 / 1000.0)
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_status_default() {
        assert_eq!(CompileStatus::default(), CompileStatus::Idle);
    }

    #[test]
    fn test_compile_status_is_terminal() {
        assert!(!CompileStatus::Idle.is_terminal());
        assert!(!CompileStatus::Building.is_terminal());
        assert!(CompileStatus::Success.is_terminal());
        assert!(CompileStatus::Failed.is_terminal());
        assert!(CompileStatus::Cancelled.is_terminal());
    }

    #[test]
    fn test_compile_status_label() {
        assert_eq!(CompileStatus::Idle.label(), "Idle");
        assert_eq!(CompileStatus::Building.label(), "Building");
        assert_eq!(CompileStatus::Success.label(), "Success");
        assert_eq!(CompileStatus::Failed.label(), "Failed");
        assert_eq!(CompileStatus::Cancelled.label(), "Cancelled");
    }

    #[test]
    fn test_compile_severity_ordering() {
        assert!(CompileSeverity::Info < CompileSeverity::Warning);
        assert!(CompileSeverity::Warning < CompileSeverity::Error);
        assert!(CompileSeverity::Error < CompileSeverity::Fatal);
    }

    #[test]
    fn test_compile_message_info() {
        let msg = CompileMessage::info("compilation started");
        assert_eq!(msg.severity, CompileSeverity::Info);
        assert!(!msg.is_error());
        assert_eq!(msg.message, "compilation started");
    }

    #[test]
    fn test_compile_message_error_with_location() {
        let msg = CompileMessage::error("type mismatch")
            .with_location("src/main.rs", 42, Some(10));
        assert!(msg.is_error());
        assert_eq!(msg.file.as_ref().unwrap().to_str().unwrap(), "src/main.rs");
        assert_eq!(msg.line, Some(42));
        assert_eq!(msg.column, Some(10));
        assert_eq!(msg.location_string(), Some("src/main.rs:42:10".into()));
    }

    #[test]
    fn test_compile_message_location_without_column() {
        let msg = CompileMessage::warning("unused variable").with_location("lib.rs", 5, None);
        assert_eq!(msg.location_string(), Some("lib.rs:5".into()));
    }

    #[test]
    fn test_compile_message_no_location() {
        let msg = CompileMessage::info("linking");
        assert_eq!(msg.location_string(), None);
    }

    #[test]
    fn test_compile_message_formatted() {
        let msg = CompileMessage::error("missing semicolon")
            .with_location("main.rs", 10, Some(5));
        let formatted = msg.formatted();
        assert!(formatted.contains("[error]"));
        assert!(formatted.contains("main.rs:10:5"));
        assert!(formatted.contains("missing semicolon"));
    }

    #[test]
    fn test_compile_message_with_error_code() {
        let msg = CompileMessage::error("type mismatch").with_error_code("E0308");
        assert_eq!(msg.error_code.as_deref(), Some("E0308"));
    }

    #[test]
    fn test_compile_config_new() {
        let config = CompileConfig::new("rustc");
        assert_eq!(config.compiler, "rustc");
        assert!(config.source_files.is_empty());
        assert!(config.flags.is_empty());
    }

    #[test]
    fn test_compile_config_builder() {
        let config = CompileConfig::new("gcc")
            .add_source("main.c")
            .add_source("util.c")
            .flag("-Wall")
            .flag("-O2")
            .output_dir("build/")
            .verbose(true)
            .timeout(300);

        assert_eq!(config.source_files.len(), 2);
        assert_eq!(config.flags.len(), 2);
        assert!(config.output_dir.is_some());
        assert!(config.verbose);
        assert_eq!(config.timeout_secs, 300);
    }

    #[test]
    fn test_compile_config_build_args() {
        let config = CompileConfig::new("gcc")
            .add_source("main.c")
            .flag("-Wall")
            .output_dir("main");

        let args = config.build_args();
        assert!(args.contains(&"-Wall".to_string()));
        assert!(args.contains(&"main.c".to_string()));
        assert!(args.contains(&"-o".to_string()));
    }

    #[test]
    fn test_compile_config_default() {
        let config = CompileConfig::default();
        assert_eq!(config.compiler, "gcc");
    }

    #[test]
    fn test_compile_result_new() {
        let config = CompileConfig::new("gcc");
        let result = CompileResult::new(config);
        assert_eq!(result.status, CompileStatus::Idle);
        assert!(result.messages.is_empty());
        assert!(!result.is_success());
    }

    #[test]
    fn test_compile_result_summary() {
        let config = CompileConfig::new("gcc");
        let mut result = CompileResult::new(config);
        result.status = CompileStatus::Success;
        assert_eq!(result.summary(), "Build succeeded");

        result.messages.push(CompileMessage::warning("unused import"));
        assert_eq!(result.summary(), "Build succeeded (1 warnings)");
    }

    #[test]
    fn test_compile_result_failed_summary() {
        let config = CompileConfig::new("gcc");
        let mut result = CompileResult::new(config);
        result.status = CompileStatus::Failed;
        result.messages.push(CompileMessage::error("undefined symbol"));
        result.messages.push(CompileMessage::warning("implicit declaration"));
        assert_eq!(result.summary(), "Build failed (1 errors, 1 warnings)");
    }

    #[test]
    fn test_compile_result_errors_and_warnings() {
        let config = CompileConfig::new("gcc");
        let mut result = CompileResult::new(config);
        result.messages.push(CompileMessage::error("err1"));
        result.messages.push(CompileMessage::error("err2"));
        result.messages.push(CompileMessage::warning("warn1"));
        result.messages.push(CompileMessage::info("info1"));

        assert_eq!(result.errors().len(), 2);
        assert_eq!(result.warnings().len(), 1);
        assert_eq!(
            result.count_by_severity(CompileSeverity::Info),
            1
        );
    }

    #[test]
    fn test_compile_result_elapsed_string() {
        let config = CompileConfig::new("gcc");
        let mut result = CompileResult::new(config);
        result.elapsed_ms = 500;
        assert_eq!(result.elapsed_string(), "500ms");

        result.elapsed_ms = 1500;
        assert_eq!(result.elapsed_string(), "1.5s");
    }
}
