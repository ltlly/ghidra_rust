//! Bulk signature ingestion pipeline.
//!
//! Port of `ghidra.features.bsim.query.ingest`:
//! - [`BulkSignatures`]: bulk signature import
//! - [`BSimLaunchable`]: headless BSim operation launcher

use serde::{Deserialize, Serialize};

use super::super::description::{ExecutableRecord, FunctionDescription, SignatureRecord};
#[cfg(test)]
use super::super::FeatureVector;

/// Bulk signature import operation.
///
/// Imports multiple function signatures into a BSim database from
/// a collection of signature files.
pub struct BulkSignatures {
    /// Source directory or file path.
    pub source_path: String,
    /// Number of signatures processed.
    processed_count: usize,
    /// Number of errors encountered.
    error_count: usize,
    /// Whether to overwrite existing signatures.
    pub overwrite: bool,
}

impl BulkSignatures {
    /// Create a new bulk signature importer.
    pub fn new(source_path: impl Into<String>) -> Self {
        Self {
            source_path: source_path.into(),
            processed_count: 0,
            error_count: 0,
            overwrite: false,
        }
    }

    /// Get the number of processed signatures.
    pub fn processed_count(&self) -> usize {
        self.processed_count
    }

    /// Get the number of errors.
    pub fn error_count(&self) -> usize {
        self.error_count
    }

    /// Simulate processing a signature.
    pub fn process_signature(&mut self, _sig: &SignatureRecord) {
        self.processed_count += 1;
    }

    /// Record an error.
    pub fn record_error(&mut self) {
        self.error_count += 1;
    }
}

/// Headless BSim operation launcher.
///
/// Used to run BSim operations from the command line without a GUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimLaunchable {
    /// Operation to perform.
    pub operation: BSimOperation,
    /// Database URL.
    pub database_url: String,
    /// Source path for import operations.
    pub source_path: Option<String>,
}

/// Types of BSim operations that can be launched headlessly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BSimOperation {
    /// Import signatures from files.
    Import,
    /// Query for similar functions.
    Query,
    /// Export results to a file.
    Export,
    /// Initialize a new database.
    Initialize,
}

impl BSimLaunchable {
    /// Create a new headless BSim launchable.
    pub fn new(operation: BSimOperation, database_url: impl Into<String>) -> Self {
        Self {
            operation,
            database_url: database_url.into(),
            source_path: None,
        }
    }

    /// Set the source path.
    pub fn with_source(mut self, path: impl Into<String>) -> Self {
        self.source_path = Some(path.into());
        self
    }
}

/// Headless BSim application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadlessBSimApplicationConfiguration {
    /// Database URL.
    pub database_url: String,
    /// Whether to create the database if missing.
    pub create_if_missing: bool,
    /// Verbosity level.
    pub verbosity: u8,
}

impl HeadlessBSimApplicationConfiguration {
    /// Create a new headless configuration.
    pub fn new(database_url: impl Into<String>) -> Self {
        Self {
            database_url: database_url.into(),
            create_if_missing: true,
            verbosity: 0,
        }
    }
}

/// Iterator over repository directories for signature scanning.
#[derive(Debug)]
pub struct IterateRepoDirectories {
    /// Root directory.
    pub root: String,
    /// File extension filter.
    pub extension: String,
    /// Current index.
    index: usize,
    /// Collected file paths.
    paths: Vec<String>,
}

impl IterateRepoDirectories {
    /// Create a new directory iterator.
    pub fn new(root: impl Into<String>, extension: impl Into<String>) -> Self {
        Self {
            root: root.into(),
            extension: extension.into(),
            index: 0,
            paths: Vec::new(),
        }
    }

    /// Add a file path to the iterator.
    pub fn add_path(&mut self, path: impl Into<String>) {
        self.paths.push(path.into());
    }

    /// Get the number of collected paths.
    pub fn path_count(&self) -> usize {
        self.paths.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bulk_signatures() {
        let mut bulk = BulkSignatures::new("/tmp/sigs");
        assert_eq!(bulk.processed_count(), 0);
        let sig = SignatureRecord::new(FeatureVector::from_pairs(vec![1, 2], vec![1.0, 1.0]));
        bulk.process_signature(&sig);
        assert_eq!(bulk.processed_count(), 1);
        bulk.record_error();
        assert_eq!(bulk.error_count(), 1);
    }

    #[test]
    fn test_bsim_launchable() {
        let launchable = BSimLaunchable::new(BSimOperation::Import, "jdbc:postgresql://localhost/bsim")
            .with_source("/tmp/sigs");
        assert!(launchable.source_path.is_some());
    }

    #[test]
    fn test_headless_config() {
        let config = HeadlessBSimApplicationConfiguration::new("jdbc:postgresql://localhost/bsim");
        assert!(config.create_if_missing);
        assert_eq!(config.verbosity, 0);
    }

    #[test]
    fn test_iterate_repo() {
        let mut iter = IterateRepoDirectories::new("/tmp/repo", ".sig");
        iter.add_path("/tmp/repo/a.sig");
        iter.add_path("/tmp/repo/b.sig");
        assert_eq!(iter.path_count(), 2);
    }
}
