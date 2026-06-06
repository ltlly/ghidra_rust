//! Port of `BulkSignatures` from `ghidra.features.bsim.query.ingest`.
//!
//! Handles bulk generation and ingestion of function signatures into a BSim
//! database. This is used for batch operations such as ingesting all functions
//! from a set of executables.

use std::collections::HashMap;

/// Status of a bulk signature operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BulkStatus {
    /// Not started.
    NotStarted,
    /// Currently processing.
    InProgress,
    /// Completed successfully.
    Completed,
    /// Failed with an error.
    Failed,
    /// Cancelled by user.
    Cancelled,
}

/// Statistics from a bulk signature operation.
#[derive(Debug, Clone, Default)]
pub struct BulkStats {
    /// Total number of functions processed.
    pub total_functions: usize,
    /// Number of signatures successfully generated.
    pub signatures_generated: usize,
    /// Number of signatures uploaded to the database.
    pub signatures_uploaded: usize,
    /// Number of functions skipped (already present or filtered).
    pub functions_skipped: usize,
    /// Number of errors encountered.
    pub errors: usize,
    /// Processing time in milliseconds.
    pub elapsed_ms: u64,
}

impl BulkStats {
    /// Create new empty stats.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the success rate as a fraction.
    pub fn success_rate(&self) -> f64 {
        if self.total_functions == 0 {
            return 0.0;
        }
        self.signatures_generated as f64 / self.total_functions as f64
    }

    /// Get the upload rate as a fraction of generated.
    pub fn upload_rate(&self) -> f64 {
        if self.signatures_generated == 0 {
            return 0.0;
        }
        self.signatures_uploaded as f64 / self.signatures_generated as f64
    }
}

/// Result of ingesting a single function's signature.
#[derive(Debug, Clone)]
pub struct SignatureIngestResult {
    /// The function name.
    pub function_name: String,
    /// The function address.
    pub address: u64,
    /// Whether the signature was successfully generated.
    pub generated: bool,
    /// Whether the signature was successfully uploaded.
    pub uploaded: bool,
    /// Error message, if any.
    pub error: Option<String>,
    /// Similarity score if matched against existing signature.
    pub existing_score: Option<f64>,
}

/// Bulk signature generation and ingestion manager.
///
/// Ports `ghidra.features.bsim.query.ingest.BulkSignatures`.
/// Manages the batch process of generating function signatures from
/// decompiled code and uploading them to a BSim database.
#[derive(Debug, Clone)]
pub struct BulkSignatures {
    /// Current status of the bulk operation.
    status: BulkStatus,
    /// Statistics from the current/last operation.
    stats: BulkStats,
    /// Per-function results.
    results: Vec<SignatureIngestResult>,
    /// Whether to overwrite existing signatures.
    overwrite_existing: bool,
    /// Batch size for database operations.
    batch_size: usize,
    /// Number of parallel workers.
    parallelism: usize,
}

impl BulkSignatures {
    /// Create a new BulkSignatures manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the current status.
    pub fn status(&self) -> BulkStatus {
        self.status
    }

    /// Get the current statistics.
    pub fn stats(&self) -> &BulkStats {
        &self.stats
    }

    /// Get per-function results.
    pub fn results(&self) -> &[SignatureIngestResult] {
        &self.results
    }

    /// Set whether to overwrite existing signatures.
    pub fn set_overwrite_existing(&mut self, overwrite: bool) {
        self.overwrite_existing = overwrite;
    }

    /// Check if overwriting is enabled.
    pub fn overwrite_existing(&self) -> bool {
        self.overwrite_existing
    }

    /// Set the batch size.
    pub fn set_batch_size(&mut self, size: usize) {
        self.batch_size = size;
    }

    /// Get the batch size.
    pub fn batch_size(&self) -> usize {
        self.batch_size
    }

    /// Set the parallelism level.
    pub fn set_parallelism(&mut self, parallelism: usize) {
        self.parallelism = parallelism;
    }

    /// Get the parallelism level.
    pub fn parallelism(&self) -> usize {
        self.parallelism
    }

    /// Record a function result.
    pub fn record_result(&mut self, result: SignatureIngestResult) {
        if result.generated {
            self.stats.signatures_generated += 1;
        }
        if result.uploaded {
            self.stats.signatures_uploaded += 1;
        }
        if result.error.is_some() {
            self.stats.errors += 1;
        }
        self.stats.total_functions += 1;
        self.results.push(result);
    }

    /// Start a bulk operation.
    pub fn start(&mut self) {
        self.status = BulkStatus::InProgress;
        self.stats = BulkStats::new();
        self.results.clear();
    }

    /// Complete the bulk operation.
    pub fn complete(&mut self) {
        self.status = BulkStatus::Completed;
    }

    /// Fail the bulk operation.
    pub fn fail(&mut self, _error: &str) {
        self.status = BulkStatus::Failed;
    }

    /// Cancel the bulk operation.
    pub fn cancel(&mut self) {
        self.status = BulkStatus::Cancelled;
    }
}

impl Default for BulkSignatures {
    fn default() -> Self {
        Self {
            status: BulkStatus::NotStarted,
            stats: BulkStats::new(),
            results: Vec::new(),
            overwrite_existing: false,
            batch_size: 100,
            parallelism: 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bulk_signatures_default() {
        let bs = BulkSignatures::new();
        assert_eq!(bs.status(), BulkStatus::NotStarted);
        assert_eq!(bs.batch_size(), 100);
        assert_eq!(bs.parallelism(), 4);
        assert!(!bs.overwrite_existing());
    }

    #[test]
    fn test_bulk_signatures_lifecycle() {
        let mut bs = BulkSignatures::new();
        bs.start();
        assert_eq!(bs.status(), BulkStatus::InProgress);

        bs.record_result(SignatureIngestResult {
            function_name: "main".to_string(),
            address: 0x1000,
            generated: true,
            uploaded: true,
            error: None,
            existing_score: None,
        });

        bs.record_result(SignatureIngestResult {
            function_name: "fail".to_string(),
            address: 0x2000,
            generated: false,
            uploaded: false,
            error: Some("decompile error".to_string()),
            existing_score: None,
        });

        assert_eq!(bs.stats().total_functions, 2);
        assert_eq!(bs.stats().signatures_generated, 1);
        assert_eq!(bs.stats().signatures_uploaded, 1);
        assert_eq!(bs.stats().errors, 1);

        bs.complete();
        assert_eq!(bs.status(), BulkStatus::Completed);
    }

    #[test]
    fn test_bulk_stats_rates() {
        let stats = BulkStats {
            total_functions: 100,
            signatures_generated: 80,
            signatures_uploaded: 70,
            ..Default::default()
        };
        assert!((stats.success_rate() - 0.8).abs() < 0.001);
        assert!((stats.upload_rate() - 0.875).abs() < 0.001);
    }

    #[test]
    fn test_bulk_stats_empty() {
        let stats = BulkStats::new();
        assert_eq!(stats.success_rate(), 0.0);
        assert_eq!(stats.upload_rate(), 0.0);
    }

    #[test]
    fn test_bulk_signatures_config() {
        let mut bs = BulkSignatures::new();
        bs.set_overwrite_existing(true);
        bs.set_batch_size(50);
        bs.set_parallelism(8);
        assert!(bs.overwrite_existing());
        assert_eq!(bs.batch_size(), 50);
        assert_eq!(bs.parallelism(), 8);
    }
}
