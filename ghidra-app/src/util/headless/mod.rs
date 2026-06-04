//! Headless analysis support (ported from `ghidra.app.util.headless`).
//!
//! Provides configuration and execution of headless (non-GUI) analysis
//! sessions.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for a headless analysis session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadlessConfig {
    /// Path to the project directory.
    pub project_path: PathBuf,
    /// Path to the binary file to analyze.
    pub binary_path: PathBuf,
    /// Output directory for results.
    pub output_path: Option<PathBuf>,
    /// Whether to run auto-analysis after import.
    pub auto_analyze: bool,
    /// Timeout for analysis in seconds (0 = no timeout).
    pub analysis_timeout_secs: u64,
    /// Process ID for multi-binary analysis.
    pub process_id: Option<String>,
    /// Additional script paths to run.
    pub scripts: Vec<PathBuf>,
    /// Maximum memory in megabytes.
    pub max_memory_mb: Option<usize>,
}

impl HeadlessConfig {
    /// Create a new headless config with required fields.
    pub fn new(
        project_path: impl Into<PathBuf>,
        binary_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            project_path: project_path.into(),
            binary_path: binary_path.into(),
            output_path: None,
            auto_analyze: true,
            analysis_timeout_secs: 0,
            process_id: None,
            scripts: Vec::new(),
            max_memory_mb: None,
        }
    }

    /// Set the output path.
    pub fn with_output(mut self, path: impl Into<PathBuf>) -> Self {
        self.output_path = Some(path.into());
        self
    }

    /// Set the analysis timeout.
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.analysis_timeout_secs = secs;
        self
    }

    /// Add a script to run.
    pub fn with_script(mut self, path: impl Into<PathBuf>) -> Self {
        self.scripts.push(path.into());
        self
    }

    /// Enable or disable auto-analysis.
    pub fn with_auto_analyze(mut self, enabled: bool) -> Self {
        self.auto_analyze = enabled;
        self
    }
}

/// Result of a headless analysis run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadlessResult {
    /// Whether the import succeeded.
    pub import_success: bool,
    /// Whether analysis completed.
    pub analysis_complete: bool,
    /// Path to the output project file, if created.
    pub output_project: Option<PathBuf>,
    /// Total elapsed time in milliseconds.
    pub elapsed_ms: u64,
    /// Any warnings or errors.
    pub messages: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headless_config_basic() {
        let c = HeadlessConfig::new("/project", "/binary.exe");
        assert!(c.auto_analyze);
        assert_eq!(c.analysis_timeout_secs, 0);
        assert!(c.output_path.is_none());
    }

    #[test]
    fn headless_config_builder() {
        let c = HeadlessConfig::new("/project", "/binary.exe")
            .with_output("/out")
            .with_timeout(120)
            .with_script("/script.py")
            .with_auto_analyze(false);
        assert_eq!(c.output_path.unwrap().to_str().unwrap(), "/out");
        assert_eq!(c.analysis_timeout_secs, 120);
        assert_eq!(c.scripts.len(), 1);
        assert!(!c.auto_analyze);
    }

    #[test]
    fn headless_result_default() {
        let r = HeadlessResult {
            import_success: true,
            analysis_complete: true,
            output_project: Some(PathBuf::from("/out/ghidra.proj")),
            elapsed_ms: 5000,
            messages: vec![],
        };
        assert!(r.import_success);
        assert!(r.analysis_complete);
    }
}
