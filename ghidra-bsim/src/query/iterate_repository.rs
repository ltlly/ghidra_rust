//! Port of `IterateRepository` from `ghidra.features.bsim.query.ingest`.
//!
//! Iterates over a repository of program files (executables), generating
//! and ingesting BSim signatures for each program's functions.

use std::path::{Path, PathBuf};

/// Result of iterating a single program in the repository.
#[derive(Debug, Clone)]
pub struct ProgramIterationResult {
    /// Path to the program file.
    pub program_path: PathBuf,
    /// MD5 hash of the program.
    pub md5: String,
    /// Number of functions found.
    pub function_count: usize,
    /// Number of signatures generated.
    pub signatures_generated: usize,
    /// Number of signatures uploaded.
    pub signatures_uploaded: usize,
    /// Whether processing was successful.
    pub success: bool,
    /// Error message, if any.
    pub error: Option<String>,
    /// Processing time in milliseconds.
    pub elapsed_ms: u64,
}

/// Configuration for repository iteration.
#[derive(Debug, Clone)]
pub struct IterateRepositoryConfig {
    /// Root directory of the repository.
    pub repository_root: PathBuf,
    /// File extensions to include (e.g., ["exe", "elf", "so"]).
    pub include_extensions: Vec<String>,
    /// Whether to recurse into subdirectories.
    pub recursive: bool,
    /// Maximum number of programs to process (0 = unlimited).
    pub max_programs: usize,
    /// Whether to skip programs already in the database.
    pub skip_existing: bool,
}

impl IterateRepositoryConfig {
    /// Create a new configuration for the given root.
    pub fn new<P: AsRef<Path>>(root: P) -> Self {
        Self {
            repository_root: root.as_ref().to_path_buf(),
            include_extensions: Vec::new(),
            recursive: true,
            max_programs: 0,
            skip_existing: true,
        }
    }

    /// Add a file extension filter.
    pub fn add_extension(&mut self, ext: &str) {
        self.include_extensions.push(ext.to_string());
    }
}

/// Iterator over a repository of program files for BSim signature ingestion.
///
/// Ports `ghidra.features.bsim.query.ingest.IterateRepository`.
#[derive(Debug, Clone)]
pub struct IterateRepository {
    /// Configuration.
    pub config: IterateRepositoryConfig,
    /// Results from processed programs.
    results: Vec<ProgramIterationResult>,
    /// Number of programs processed so far.
    processed: usize,
    /// Whether iteration is complete.
    done: bool,
}

impl IterateRepository {
    /// Create a new repository iterator.
    pub fn new(config: IterateRepositoryConfig) -> Self {
        Self {
            config,
            results: Vec::new(),
            processed: 0,
            done: false,
        }
    }

    /// Record a result from processing a program.
    pub fn record_result(&mut self, result: ProgramIterationResult) {
        self.processed += 1;
        self.results.push(result);

        if self.config.max_programs > 0 && self.processed >= self.config.max_programs {
            self.done = true;
        }
    }

    /// Get all results.
    pub fn results(&self) -> &[ProgramIterationResult] {
        &self.results
    }

    /// Get the number of programs processed.
    pub fn processed_count(&self) -> usize {
        self.processed
    }

    /// Check if iteration is complete.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Get total statistics across all results.
    pub fn aggregate_stats(&self) -> (usize, usize, usize, usize) {
        let total_funcs: usize = self.results.iter().map(|r| r.function_count).sum();
        let total_sigs: usize = self.results.iter().map(|r| r.signatures_generated).sum();
        let total_uploaded: usize = self.results.iter().map(|r| r.signatures_uploaded).sum();
        let total_errors = self.results.iter().filter(|r| !r.success).count();
        (total_funcs, total_sigs, total_uploaded, total_errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iterate_repository_config() {
        let mut config = IterateRepositoryConfig::new("/data/programs");
        config.add_extension("exe");
        config.add_extension("elf");
        assert_eq!(config.include_extensions.len(), 2);
        assert!(config.recursive);
        assert!(config.skip_existing);
    }

    #[test]
    fn test_iterate_repository_lifecycle() {
        let config = IterateRepositoryConfig::new("/tmp/test");
        let mut repo = IterateRepository::new(config);

        repo.record_result(ProgramIterationResult {
            program_path: PathBuf::from("/tmp/test/a.exe"),
            md5: "abc123".to_string(),
            function_count: 100,
            signatures_generated: 90,
            signatures_uploaded: 85,
            success: true,
            error: None,
            elapsed_ms: 500,
        });

        assert_eq!(repo.processed_count(), 1);
        assert_eq!(repo.results().len(), 1);

        let (funcs, sigs, uploaded, errors) = repo.aggregate_stats();
        assert_eq!(funcs, 100);
        assert_eq!(sigs, 90);
        assert_eq!(uploaded, 85);
        assert_eq!(errors, 0);
    }

    #[test]
    fn test_iterate_repository_max_programs() {
        let config = IterateRepositoryConfig {
            repository_root: PathBuf::from("/tmp"),
            max_programs: 2,
            ..IterateRepositoryConfig::new("/tmp")
        };
        let mut repo = IterateRepository::new(config);

        for i in 0..5 {
            if repo.is_done() {
                break;
            }
            repo.record_result(ProgramIterationResult {
                program_path: PathBuf::from(format!("/tmp/{}.exe", i)),
                md5: format!("md5_{}", i),
                function_count: 10,
                signatures_generated: 10,
                signatures_uploaded: 10,
                success: true,
                error: None,
                elapsed_ms: 100,
            });
        }

        assert_eq!(repo.processed_count(), 2);
        assert!(repo.is_done());
    }

    #[test]
    fn test_aggregate_stats_with_errors() {
        let config = IterateRepositoryConfig::new("/tmp");
        let mut repo = IterateRepository::new(config);

        repo.record_result(ProgramIterationResult {
            program_path: PathBuf::from("/tmp/a"),
            md5: "a".to_string(),
            function_count: 50,
            signatures_generated: 40,
            signatures_uploaded: 40,
            success: true,
            error: None,
            elapsed_ms: 200,
        });

        repo.record_result(ProgramIterationResult {
            program_path: PathBuf::from("/tmp/b"),
            md5: "b".to_string(),
            function_count: 30,
            signatures_generated: 0,
            signatures_uploaded: 0,
            success: false,
            error: Some("parse error".to_string()),
            elapsed_ms: 50,
        });

        let (funcs, sigs, uploaded, errors) = repo.aggregate_stats();
        assert_eq!(funcs, 80);
        assert_eq!(sigs, 40);
        assert_eq!(uploaded, 40);
        assert_eq!(errors, 1);
    }
}
