//! BSim signature generation tool.
//!
//! Ports `ghidra.features.bsim.query.GenSignatures` from Ghidra's Java source.
//!
//! Generates BSim function signatures from a Ghidra program and writes them
//! to a database or file.  Used by the `GenSignatures` headless analyzer and
//! the `BulkSignatures` batch pipeline.

use std::collections::HashMap;

use super::description::{BSimExecutableInfo, BSimFunctionDescription, FunctionSignatureInfo};
use super::function_database::FunctionDatabase;
use super::{BSimError, BSimResult};

/// Configuration for signature generation.
#[derive(Debug, Clone)]
pub struct GenSignaturesConfig {
    /// Whether to compute LSH min-hash signatures.
    pub compute_lsh: bool,
    /// Number of LSH hash functions.
    pub lsh_hash_count: usize,
    /// Whether to compute mnemonic sequences.
    pub compute_mnemonics: bool,
    /// Whether to compute byte histograms.
    pub compute_byte_histogram: bool,
    /// Whether to compute dataflow features.
    pub compute_dataflow: bool,
    /// Minimum function size (in bytes) to include.
    pub min_function_size: usize,
    /// Maximum number of functions to process.
    pub max_function_count: Option<usize>,
    /// Whether to overwrite existing signatures.
    pub force_overwrite: bool,
}

impl Default for GenSignaturesConfig {
    fn default() -> Self {
        Self {
            compute_lsh: true,
            lsh_hash_count: 128,
            compute_mnemonics: true,
            compute_byte_histogram: true,
            compute_dataflow: true,
            min_function_size: 4,
            max_function_count: None,
            force_overwrite: false,
        }
    }
}

/// Result of generating signatures for a single function.
#[derive(Debug, Clone)]
pub struct SignatureGenResult {
    /// Entry point address of the function.
    pub entry_point: u64,
    /// Name of the function.
    pub function_name: String,
    /// Size of the function in bytes.
    pub function_size: usize,
    /// Whether signature generation succeeded.
    pub success: bool,
    /// Error message if generation failed.
    pub error: Option<String>,
    /// The generated function description (if successful).
    pub description: Option<BSimFunctionDescription>,
}

impl SignatureGenResult {
    /// Create a successful result.
    pub fn success(
        entry_point: u64,
        function_name: String,
        function_size: usize,
        description: BSimFunctionDescription,
    ) -> Self {
        Self {
            entry_point,
            function_name,
            function_size,
            success: true,
            error: None,
            description: Some(description),
        }
    }

    /// Create a failure result.
    pub fn failure(
        entry_point: u64,
        function_name: String,
        function_size: usize,
        error: String,
    ) -> Self {
        Self {
            entry_point,
            function_name,
            function_size,
            success: false,
            error: Some(error),
            description: None,
        }
    }
}

/// Summary of a signature generation run.
#[derive(Debug, Clone, Default)]
pub struct SignatureGenSummary {
    /// Total functions processed.
    pub total_processed: usize,
    /// Successful signature generations.
    pub success_count: usize,
    /// Failed signature generations.
    pub failure_count: usize,
    /// Functions skipped (too small, etc.).
    pub skipped_count: usize,
    /// Total time taken in milliseconds.
    pub total_time_ms: u64,
    /// Per-function results.
    pub results: Vec<SignatureGenResult>,
}

impl SignatureGenSummary {
    /// Get the success rate as a fraction (0.0 to 1.0).
    pub fn success_rate(&self) -> f64 {
        if self.total_processed == 0 {
            return 0.0;
        }
        self.success_count as f64 / self.total_processed as f64
    }

    /// Whether all functions were processed successfully.
    pub fn all_succeeded(&self) -> bool {
        self.failure_count == 0
    }
}

/// The main signature generator.
///
/// Ports Ghidra's `GenSignatures` class.  Processes functions from a program,
/// generates BSim signatures, and optionally writes them to a database.
pub struct SignatureGenerator {
    config: GenSignaturesConfig,
}

impl SignatureGenerator {
    /// Create a new signature generator with default configuration.
    pub fn new() -> Self {
        Self {
            config: GenSignaturesConfig::default(),
        }
    }

    /// Create a signature generator with custom configuration.
    pub fn with_config(config: GenSignaturesConfig) -> Self {
        Self { config }
    }

    /// Get the current configuration.
    pub fn config(&self) -> &GenSignaturesConfig {
        &self.config
    }

    /// Generate a signature for a single function given its mnemonic sequence
    /// and byte content.
    pub fn generate_function_signature(
        &self,
        entry_point: u64,
        function_name: &str,
        mnemonics: &[String],
        bytes: &[u8],
    ) -> BSimResult<BSimFunctionDescription> {
        if bytes.len() < self.config.min_function_size {
            return Err(BSimError::SchemaError(format!(
                "Function {} at 0x{:x} is too small ({} < {})",
                function_name,
                entry_point,
                bytes.len(),
                self.config.min_function_size
            )));
        }

        let mut signature = FunctionSignatureInfo::new();

        if self.config.compute_mnemonics {
            signature.mnemonic_sequence = mnemonics.to_vec();
        }

        if self.config.compute_byte_histogram {
            signature.byte_histogram = compute_byte_histogram(bytes);
        }

        if self.config.compute_lsh {
            // Store LSH vector as dataflow_signature bytes (reusing existing field).
            let lsh = compute_lsh_vector(mnemonics, self.config.lsh_hash_count);
            signature.dataflow_signature = lsh.iter().map(|&f| (f * 255.0) as u8).collect();
        }

        let mut desc = BSimFunctionDescription::new("", function_name, entry_point);
        desc.signature = signature;
        Ok(desc)
    }

    /// Generate signatures for a batch of functions and write them to the database.
    pub fn generate_and_write(
        &self,
        db: &mut dyn FunctionDatabase,
        executable: &BSimExecutableInfo,
        functions: &[(u64, String, Vec<String>, Vec<u8>)], // (entry, name, mnemonics, bytes)
    ) -> BSimResult<SignatureGenSummary> {
        let mut summary = SignatureGenSummary::default();
        summary.total_processed = functions.len();

        let max_count = self.config.max_function_count.unwrap_or(usize::MAX);
        let mut processed = 0;

        for (entry, name, mnemonics, bytes) in functions {
            if processed >= max_count {
                summary.skipped_count += functions.len() - processed;
                break;
            }

            if bytes.len() < self.config.min_function_size {
                summary.skipped_count += 1;
                processed += 1;
                continue;
            }

            match self.generate_function_signature(*entry, name, mnemonics, bytes) {
                Ok(desc) => {
                    summary.success_count += 1;
                    summary
                        .results
                        .push(SignatureGenResult::success(*entry, name.clone(), bytes.len(), desc));
                }
                Err(e) => {
                    summary.failure_count += 1;
                    summary.results.push(SignatureGenResult::failure(
                        *entry,
                        name.clone(),
                        bytes.len(),
                        e.to_string(),
                    ));
                }
            }
            processed += 1;
        }

        // Write successful signatures to the database.
        let successful_descs: Vec<BSimFunctionDescription> = summary
            .results
            .iter()
            .filter_map(|r| r.description.clone())
            .collect();

        if !successful_descs.is_empty() {
            db.ingest_functions(&successful_descs)?;
        }

        Ok(summary)
    }
}

impl Default for SignatureGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute a byte histogram (256 bins) from function bytes.
fn compute_byte_histogram(bytes: &[u8]) -> Vec<f64> {
    let mut hist = vec![0.0f64; 256];
    for &b in bytes {
        hist[b as usize] += 1.0;
    }
    // Normalize.
    let len = bytes.len() as f64;
    if len > 0.0 {
        for v in &mut hist {
            *v /= len;
        }
    }
    hist
}

/// Compute a simple LSH vector from a mnemonic sequence.
///
/// Uses a hash-based approach: each mnemonic is hashed to produce a feature
/// vector, then multiple hash functions are applied to create the LSH signature.
fn compute_lsh_vector(mnemonics: &[String], hash_count: usize) -> Vec<f64> {
    let mut vector = vec![0.0f64; hash_count];

    for (i, mnemonic) in mnemonics.iter().enumerate() {
        let base_hash = simple_hash(mnemonic);
        for j in 0..hash_count {
            let h = simple_hash_combine(base_hash, j as u64);
            if h % 2 == 0 {
                vector[j] += 1.0;
            }
        }
        // Weight by position (earlier ops matter more).
        let weight = 1.0 / (1.0 + i as f64 * 0.1);
        for v in &mut vector {
            *v *= weight;
        }
    }

    // Normalize to unit vector.
    let mag: f64 = vector.iter().map(|x| x * x).sum::<f64>().sqrt();
    if mag > 0.0 {
        for v in &mut vector {
            *v /= mag;
        }
    }

    vector
}

/// Simple string hash function (FNV-1a variant).
fn simple_hash(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Combine two hash values.
fn simple_hash_combine(a: u64, b: u64) -> u64 {
    a.wrapping_mul(6364136223846793005)
        .wrapping_add(b)
        .wrapping_add(1442695040888963407)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_signatures_config_default() {
        let config = GenSignaturesConfig::default();
        assert!(config.compute_lsh);
        assert!(config.compute_mnemonics);
        assert_eq!(config.lsh_hash_count, 128);
        assert_eq!(config.min_function_size, 4);
        assert!(!config.force_overwrite);
    }

    #[test]
    fn signature_gen_result_success() {
        let desc = BSimFunctionDescription::new("", "main", 0x1000);
        let result = SignatureGenResult::success(0x1000, "main".into(), 100, desc);
        assert!(result.success);
        assert!(result.description.is_some());
        assert!(result.error.is_none());
    }

    #[test]
    fn signature_gen_result_failure() {
        let result = SignatureGenResult::failure(0x2000, "foo".into(), 2, "too small".into());
        assert!(!result.success);
        assert!(result.error.is_some());
        assert!(result.description.is_none());
    }

    #[test]
    fn signature_gen_summary_default() {
        let summary = SignatureGenSummary::default();
        assert_eq!(summary.total_processed, 0);
        assert_eq!(summary.success_rate(), 0.0);
        assert!(summary.all_succeeded());
    }

    #[test]
    fn signature_gen_summary_success_rate() {
        let summary = SignatureGenSummary {
            total_processed: 10,
            success_count: 7,
            failure_count: 2,
            skipped_count: 1,
            ..Default::default()
        };
        assert!((summary.success_rate() - 0.7).abs() < 1e-6);
        assert!(!summary.all_succeeded());
    }

    #[test]
    fn generate_single_signature() {
        let gen = SignatureGenerator::new();
        let mnemonics = vec![
            "push".into(),
            "mov".into(),
            "sub".into(),
            "call".into(),
            "add".into(),
            "ret".into(),
        ];
        let bytes = vec![0x55, 0x89, 0xe5, 0x83, 0xec, 0x10, 0xe8, 0x00, 0x00, 0x00, 0x00, 0xc9, 0xc3];
        let desc = gen
            .generate_function_signature(0x1000, "main", &mnemonics, &bytes)
            .unwrap();
        assert_eq!(desc.entry_point, 0x1000);
        assert_eq!(desc.function_name, "main");
        assert_eq!(desc.signature.mnemonic_sequence.len(), 6);
        assert_eq!(desc.signature.byte_histogram.len(), 256);
        assert!(!desc.signature.dataflow_signature.is_empty());
    }

    #[test]
    fn generate_signature_too_small() {
        let gen = SignatureGenerator::new();
        let result = gen.generate_function_signature(
            0x1000,
            "tiny",
            &["nop".into()],
            &[0x90],
        );
        assert!(result.is_err());
    }

    #[test]
    fn byte_histogram_basic() {
        let hist = compute_byte_histogram(&[0x00, 0x00, 0xFF]);
        assert!((hist[0] - 2.0 / 3.0).abs() < 1e-6);
        assert!((hist[255] - 1.0 / 3.0).abs() < 1e-6);
        assert!((hist[1] - 0.0).abs() < 1e-6);
    }

    #[test]
    fn lsh_vector_basic() {
        let mnemonics = vec!["mov".into(), "add".into(), "ret".into()];
        let vec = compute_lsh_vector(&mnemonics, 32);
        assert_eq!(vec.len(), 32);
        // Should be normalized.
        let mag: f64 = vec.iter().map(|x| x * x).sum::<f64>().sqrt();
        assert!((mag - 1.0).abs() < 1e-6);
    }

    #[test]
    fn lsh_vector_empty() {
        let vec = compute_lsh_vector(&[], 32);
        assert_eq!(vec.len(), 32);
        // All zeros for empty input.
        assert!(vec.iter().all(|&x| x == 0.0));
    }

    #[test]
    fn simple_hash_deterministic() {
        assert_eq!(simple_hash("mov"), simple_hash("mov"));
        assert_ne!(simple_hash("mov"), simple_hash("add"));
    }

    #[test]
    fn signature_generator_default() {
        let gen = SignatureGenerator::default();
        assert!(gen.config().compute_lsh);
    }
}
