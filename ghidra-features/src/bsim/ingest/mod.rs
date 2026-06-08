//! BSim signature ingestion pipeline.
//!
//! Ports `ghidra.features.bsim.query.ingest` package.
//!
//! Handles the process of importing function signatures from
//! external sources (decompiler output, Ghidra databases, etc.)
//! into a BSim database.

use serde::{Deserialize, Serialize};

use crate::bsim::BSimSignature;

/// Result of a signature ingestion operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestResult {
    /// Number of signatures successfully ingested.
    pub ingested_count: usize,
    /// Number of signatures skipped (duplicates).
    pub skipped_count: usize,
    /// Number of signatures that failed to parse.
    pub error_count: usize,
    /// Error messages for failed signatures.
    pub errors: Vec<String>,
    /// Time taken in milliseconds.
    pub elapsed_ms: u64,
}

impl IngestResult {
    /// Create a new empty result.
    pub fn new() -> Self {
        Self {
            ingested_count: 0,
            skipped_count: 0,
            error_count: 0,
            errors: Vec::new(),
            elapsed_ms: 0,
        }
    }

    /// Total number of signatures processed.
    pub fn total_processed(&self) -> usize {
        self.ingested_count + self.skipped_count + self.error_count
    }

    /// Whether all signatures were ingested without errors.
    pub fn is_clean(&self) -> bool {
        self.error_count == 0
    }
}

impl Default for IngestResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for the ingestion pipeline.
#[derive(Debug, Clone)]
pub struct IngestConfig {
    /// Maximum batch size for bulk inserts.
    pub batch_size: usize,
    /// Whether to skip duplicate signatures.
    pub skip_duplicates: bool,
    /// Whether to validate signatures before inserting.
    pub validate: bool,
    /// Maximum number of concurrent ingestion threads.
    pub max_threads: usize,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            batch_size: 1000,
            skip_duplicates: true,
            validate: true,
            max_threads: 1,
        }
    }
}

/// The signature ingestion pipeline.
pub struct SignatureIngestionPipeline {
    /// Configuration.
    pub config: IngestConfig,
    /// Collected results.
    result: IngestResult,
    /// Pending batch.
    batch: Vec<BSimSignature>,
}

impl SignatureIngestionPipeline {
    /// Create a new ingestion pipeline.
    pub fn new(config: IngestConfig) -> Self {
        Self {
            config,
            result: IngestResult::new(),
            batch: Vec::new(),
        }
    }

    /// Add a signature to the current batch.
    pub fn add(&mut self, sig: BSimSignature) {
        self.batch.push(sig);
    }

    /// Get the current batch size.
    pub fn batch_size(&self) -> usize {
        self.batch.len()
    }

    /// Get the ingestion results.
    pub fn result(&self) -> &IngestResult {
        &self.result
    }

    /// Take the current batch for processing.
    pub fn take_batch(&mut self) -> Vec<BSimSignature> {
        std::mem::take(&mut self.batch)
    }

    /// Record a successful ingestion.
    pub fn record_success(&mut self, count: usize) {
        self.result.ingested_count += count;
    }

    /// Record skipped duplicates.
    pub fn record_skipped(&mut self, count: usize) {
        self.result.skipped_count += count;
    }

    /// Record an error.
    pub fn record_error(&mut self, error: impl Into<String>) {
        self.result.error_count += 1;
        self.result.errors.push(error.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bsim::BSimMetadata;

    #[test]
    fn ingest_result_new() {
        let result = IngestResult::new();
        assert_eq!(result.total_processed(), 0);
        assert!(result.is_clean());
    }

    #[test]
    fn ingest_result_totals() {
        let mut result = IngestResult::new();
        result.ingested_count = 10;
        result.skipped_count = 5;
        result.error_count = 2;
        assert_eq!(result.total_processed(), 17);
        assert!(!result.is_clean());
    }

    #[test]
    fn pipeline_add_and_batch() {
        let config = IngestConfig::default();
        let mut pipeline = SignatureIngestionPipeline::new(config);
        assert_eq!(pipeline.batch_size(), 0);

        let sig = BSimSignature::new(
            [0u8; 32],
            vec![],
            BSimMetadata {
                function_name: "test".to_string(),
                architecture: "x86".to_string(),
                compiler: None,
                num_instructions: 10,
                num_basic_blocks: 2,
                num_calls: 0,
            },
        );
        pipeline.add(sig);
        assert_eq!(pipeline.batch_size(), 1);

        let batch = pipeline.take_batch();
        assert_eq!(batch.len(), 1);
        assert_eq!(pipeline.batch_size(), 0);
    }

    #[test]
    fn pipeline_record_results() {
        let config = IngestConfig::default();
        let mut pipeline = SignatureIngestionPipeline::new(config);

        pipeline.record_success(5);
        pipeline.record_skipped(2);
        pipeline.record_error("bad signature");

        let result = pipeline.result();
        assert_eq!(result.ingested_count, 5);
        assert_eq!(result.skipped_count, 2);
        assert_eq!(result.error_count, 1);
        assert!(!result.is_clean());
    }

    #[test]
    fn ingest_config_default() {
        let config = IngestConfig::default();
        assert_eq!(config.batch_size, 1000);
        assert!(config.skip_duplicates);
        assert!(config.validate);
    }
}
