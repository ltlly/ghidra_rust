//! BSim signature ingestion pipeline.
//!
//! Ports `ghidra.features.bsim.query.ingest` from Ghidra's Java source.
//!
//! Handles decompilation of functions and generation of BSim signatures.

use super::description::{BSimExecutableInfo, BSimFunctionDescription, FunctionSignatureInfo};
use super::function_database::FunctionDatabase;
use super::{BSimError, BSimResult};

/// Configuration for the ingestion pipeline.
#[derive(Debug, Clone)]
pub struct IngestConfig {
    /// Whether to compute LSH signatures.
    pub compute_lsh: bool,
    /// Whether to compute dataflow signatures.
    pub compute_dataflow: bool,
    /// Whether to compute mnemonic sequences.
    pub compute_mnemonics: bool,
    /// Whether to compute byte histograms.
    pub compute_byte_histogram: bool,
    /// Maximum number of functions to ingest per batch.
    pub batch_size: usize,
    /// Number of parallel threads for decompilation.
    pub thread_count: usize,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            compute_lsh: true,
            compute_dataflow: true,
            compute_mnemonics: true,
            compute_byte_histogram: true,
            batch_size: 1000,
            thread_count: 4,
        }
    }
}

/// Result of ingesting a single function.
#[derive(Debug, Clone)]
pub struct IngestResult {
    /// The function entry point.
    pub entry_point: u64,
    /// Whether ingestion succeeded.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
    /// Time taken in milliseconds.
    pub time_ms: u64,
}

/// The ingestion pipeline that processes binary functions into BSim signatures.
pub struct IngestionPipeline {
    config: IngestConfig,
}

impl IngestionPipeline {
    /// Create a new ingestion pipeline with default configuration.
    pub fn new() -> Self {
        Self {
            config: IngestConfig::default(),
        }
    }

    /// Create a pipeline with custom configuration.
    pub fn with_config(config: IngestConfig) -> Self {
        Self { config }
    }

    /// Get the configuration.
    pub fn config(&self) -> &IngestConfig {
        &self.config
    }

    /// Ingest a batch of function descriptions into the database.
    pub fn ingest_batch(
        &self,
        db: &mut dyn FunctionDatabase,
        functions: &[BSimFunctionDescription],
    ) -> BSimResult<Vec<IngestResult>> {
        let mut results = Vec::with_capacity(functions.len());

        // Process in batches.
        for chunk in functions.chunks(self.config.batch_size) {
            let start = std::time::Instant::now();
            let count = db.ingest_functions(chunk)?;
            let elapsed = start.elapsed().as_millis() as u64;

            for func in chunk {
                results.push(IngestResult {
                    entry_point: func.entry_point,
                    success: true,
                    error: None,
                    time_ms: elapsed / count.max(1) as u64,
                });
            }
        }

        Ok(results)
    }

    /// Generate a BSim signature for a function from its raw bytes and metadata.
    pub fn generate_signature(
        &self,
        function_bytes: &[u8],
        entry_point: u64,
    ) -> FunctionSignatureInfo {
        let mut sig = FunctionSignatureInfo::new();

        if self.config.compute_byte_histogram {
            sig.byte_histogram = compute_byte_histogram(function_bytes);
        }

        if self.config.compute_mnemonics && !function_bytes.is_empty() {
            // In a real implementation, this would use SLEIGH to disassemble.
            sig.mnemonic_sequence = vec!["UNKNOWN".to_string(); function_bytes.len().min(100)];
        }

        sig
    }
}

impl Default for IngestionPipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute a byte histogram (256 bins) for the given bytes.
fn compute_byte_histogram(bytes: &[u8]) -> Vec<f64> {
    let mut histogram = vec![0.0f64; 256];
    for &b in bytes {
        histogram[b as usize] += 1.0;
    }
    let total = bytes.len() as f64;
    if total > 0.0 {
        for val in &mut histogram {
            *val /= total;
        }
    }
    histogram
}

/// Ingest command for generating and storing signatures.
///
/// Ports `ghidra.features.bsim.query.GenSignatures`.
pub struct GenSignatures {
    executable_info: BSimExecutableInfo,
    pipeline: IngestionPipeline,
}

impl GenSignatures {
    /// Create a new GenSignatures command.
    pub fn new(executable_info: BSimExecutableInfo) -> Self {
        Self {
            executable_info,
            pipeline: IngestionPipeline::new(),
        }
    }

    /// Run the signature generation and ingestion.
    pub fn execute(
        &self,
        db: &mut dyn FunctionDatabase,
        functions: &[BSimFunctionDescription],
    ) -> BSimResult<usize> {
        db.register_executable(&self.executable_info)?;
        let results = self.pipeline.ingest_batch(db, functions)?;
        Ok(results.iter().filter(|r| r.success).count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::function_database::StubFunctionDatabase;

    #[test]
    fn test_ingest_config_default() {
        let config = IngestConfig::default();
        assert!(config.compute_lsh);
        assert!(config.compute_dataflow);
        assert_eq!(config.batch_size, 1000);
        assert_eq!(config.thread_count, 4);
    }

    #[test]
    fn test_ingestion_pipeline_generate_signature() {
        let pipeline = IngestionPipeline::new();
        let bytes = vec![0x55, 0x89, 0xe5, 0x83, 0xec, 0x10, 0x55, 0x89];
        let sig = pipeline.generate_signature(&bytes, 0x1000);
        assert!(!sig.byte_histogram.is_empty());
        assert_eq!(sig.byte_histogram.len(), 256);
    }

    #[test]
    fn test_ingestion_pipeline_ingest_batch() {
        let pipeline = IngestionPipeline::new();
        let mut db = StubFunctionDatabase::new();
        db.open().unwrap();

        let functions = vec![
            BSimFunctionDescription::new("exe1", "func1", 0x1000),
            BSimFunctionDescription::new("exe1", "func2", 0x2000),
            BSimFunctionDescription::new("exe1", "func3", 0x3000),
        ];

        let results = pipeline.ingest_batch(&mut db, &functions).unwrap();
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.success));
        assert_eq!(db.function_count().unwrap(), 3);
    }

    #[test]
    fn test_byte_histogram() {
        let bytes = vec![0x00, 0x00, 0x01, 0x01, 0x01, 0xFF];
        let hist = compute_byte_histogram(&bytes);
        assert_eq!(hist.len(), 256);
        assert!((hist[0] - 2.0 / 6.0).abs() < 1e-10);
        assert!((hist[1] - 3.0 / 6.0).abs() < 1e-10);
        assert!((hist[0xFF] - 1.0 / 6.0).abs() < 1e-10);
    }

    #[test]
    fn test_gen_signatures() {
        let info = BSimExecutableInfo::new("exe1", "test.exe");
        let gen = GenSignatures::new(info);

        let mut db = StubFunctionDatabase::new();
        db.open().unwrap();

        let functions = vec![
            BSimFunctionDescription::new("exe1", "main", 0x1000),
            BSimFunctionDescription::new("exe1", "helper", 0x2000),
        ];

        let count = gen.execute(&mut db, &functions).unwrap();
        assert_eq!(count, 2);
        assert!(db.has_executable("exe1").unwrap());
    }

    #[test]
    fn test_byte_histogram_empty() {
        let hist = compute_byte_histogram(&[]);
        assert_eq!(hist.len(), 256);
        assert!(hist.iter().all(|&v| v == 0.0));
    }
}
