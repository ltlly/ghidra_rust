//! Batch import framework for importing multiple files into a Ghidra project.
//!
//! Ported from `ghidra.plugins.importer.batch`.
//!
//! Provides a batch-mode import manager that processes multiple binary files
//! sequentially, applying consistent import options.

// ---------------------------------------------------------------------------
// BatchImportOptions
// ---------------------------------------------------------------------------

/// Options controlling batch import behavior.
#[derive(Debug, Clone)]
pub struct BatchImportOptions {
    /// Whether to apply analysis to each imported program.
    pub apply_analysis: bool,
    /// Whether to overwrite existing programs with the same name.
    pub overwrite_existing: bool,
    /// Whether to automatically detect language from file headers.
    pub auto_detect_language: bool,
    /// Default language ID if auto-detect is disabled.
    pub default_language_id: Option<String>,
    /// Default compiler spec ID if auto-detect is disabled.
    pub default_compiler_spec_id: Option<String>,
    /// Maximum number of concurrent imports.
    pub max_concurrent: usize,
}

impl BatchImportOptions {
    /// Create default batch import options.
    pub fn new() -> Self {
        Self {
            apply_analysis: true,
            overwrite_existing: false,
            auto_detect_language: true,
            default_language_id: None,
            default_compiler_spec_id: None,
            max_concurrent: 1,
        }
    }

    /// Set whether to apply analysis.
    pub fn with_analysis(mut self, apply: bool) -> Self {
        self.apply_analysis = apply;
        self
    }

    /// Set whether to overwrite existing programs.
    pub fn with_overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite_existing = overwrite;
        self
    }

    /// Set a default language for all imports.
    pub fn with_default_language(mut self, lang_id: &str, compiler_spec_id: &str) -> Self {
        self.auto_detect_language = false;
        self.default_language_id = Some(lang_id.to_string());
        self.default_compiler_spec_id = Some(compiler_spec_id.to_string());
        self
    }
}

impl Default for BatchImportOptions {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BatchImportResult
// ---------------------------------------------------------------------------

/// Result of a single file import within a batch.
#[derive(Debug, Clone)]
pub struct BatchImportResult {
    /// The path of the imported file.
    pub file_path: String,
    /// Whether the import succeeded.
    pub success: bool,
    /// Error message if the import failed.
    pub error: Option<String>,
    /// Name of the created program.
    pub program_name: Option<String>,
    /// Duration of the import in milliseconds.
    pub duration_ms: u64,
}

impl BatchImportResult {
    /// Create a success result.
    pub fn success(file_path: &str, program_name: &str, duration_ms: u64) -> Self {
        Self {
            file_path: file_path.to_string(),
            success: true,
            error: None,
            program_name: Some(program_name.to_string()),
            duration_ms,
        }
    }

    /// Create a failure result.
    pub fn failure(file_path: &str, error: &str, duration_ms: u64) -> Self {
        Self {
            file_path: file_path.to_string(),
            success: false,
            error: Some(error.to_string()),
            program_name: None,
            duration_ms,
        }
    }
}

// ---------------------------------------------------------------------------
// BatchImportManager
// ---------------------------------------------------------------------------

/// Manages batch import operations.
#[derive(Debug)]
pub struct BatchImportManager {
    /// The files to import.
    files: Vec<String>,
    /// Import options.
    options: BatchImportOptions,
    /// Results of completed imports.
    results: Vec<BatchImportResult>,
    /// Index of the next file to process.
    next_index: usize,
}

impl BatchImportManager {
    /// Create a new batch import manager.
    pub fn new(files: Vec<String>, options: BatchImportOptions) -> Self {
        Self {
            files,
            options,
            results: Vec::new(),
            next_index: 0,
        }
    }

    /// Total number of files to import.
    pub fn total_files(&self) -> usize {
        self.files.len()
    }

    /// Number of files processed so far.
    pub fn processed(&self) -> usize {
        self.next_index
    }

    /// Whether all files have been processed.
    pub fn is_complete(&self) -> bool {
        self.next_index >= self.files.len()
    }

    /// Number of successful imports.
    pub fn success_count(&self) -> usize {
        self.results.iter().filter(|r| r.success).count()
    }

    /// Number of failed imports.
    pub fn failure_count(&self) -> usize {
        self.results.iter().filter(|r| !r.success).count()
    }

    /// Get all results.
    pub fn results(&self) -> &[BatchImportResult] {
        &self.results
    }

    /// Record a result (simulates processing one file).
    pub fn record_result(&mut self, result: BatchImportResult) {
        self.results.push(result);
        self.next_index += 1;
    }

    /// Get the next file to process, or None if done.
    pub fn next_file(&self) -> Option<&str> {
        self.files.get(self.next_index).map(|s| s.as_str())
    }

    /// Get the import options.
    pub fn options(&self) -> &BatchImportOptions {
        &self.options
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_import_options_default() {
        let opts = BatchImportOptions::new();
        assert!(opts.apply_analysis);
        assert!(!opts.overwrite_existing);
        assert!(opts.auto_detect_language);
    }

    #[test]
    fn test_batch_import_options_builder() {
        let opts = BatchImportOptions::new()
            .with_analysis(false)
            .with_overwrite(true)
            .with_default_language("x86:LE:64:default", "default");
        assert!(!opts.apply_analysis);
        assert!(opts.overwrite_existing);
        assert!(!opts.auto_detect_language);
        assert_eq!(
            opts.default_language_id,
            Some("x86:LE:64:default".into())
        );
    }

    #[test]
    fn test_batch_import_manager() {
        let files = vec![
            "/path/a.exe".into(),
            "/path/b.elf".into(),
            "/path/c.so".into(),
        ];
        let opts = BatchImportOptions::new();
        let mut mgr = BatchImportManager::new(files, opts);

        assert_eq!(mgr.total_files(), 3);
        assert_eq!(mgr.processed(), 0);
        assert!(!mgr.is_complete());
        assert_eq!(mgr.next_file(), Some("/path/a.exe"));

        mgr.record_result(BatchImportResult::success("/path/a.exe", "a", 100));
        assert_eq!(mgr.processed(), 1);
        assert_eq!(mgr.success_count(), 1);

        mgr.record_result(BatchImportResult::failure("/path/b.elf", "bad format", 50));
        assert_eq!(mgr.failure_count(), 1);

        mgr.record_result(BatchImportResult::success("/path/c.so", "c", 200));
        assert!(mgr.is_complete());
        assert_eq!(mgr.success_count(), 2);
        assert_eq!(mgr.failure_count(), 1);
    }

    #[test]
    fn test_batch_import_result() {
        let success = BatchImportResult::success("/file.exe", "file", 123);
        assert!(success.success);
        assert_eq!(success.program_name, Some("file".into()));
        assert_eq!(success.duration_ms, 123);

        let failure = BatchImportResult::failure("/bad.exe", "unsupported", 10);
        assert!(!failure.success);
        assert_eq!(failure.error, Some("unsupported".into()));
    }
}
