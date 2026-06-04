//! Bulk signature generation and ingestion for BSim.
//!
//! Ports Ghidra's `ghidra.features.bsim.query.BulkSignatures` and
//! `ghidra.features.bsim.query.GenSignatures`.
//!
//! Provides batch operations for generating BSim signatures from
//! multiple functions and bulk-loading them into a database.

use super::{BSimDatabase, BSimSignature, FeatureVector};
use ghidra_core::program::listing::Function;
use anyhow::Result;

// ============================================================================
// BulkSignatureGenerator
// ============================================================================

/// Generates BSim signatures for a batch of functions.
///
/// Ported from `ghidra.features.bsim.query.BulkSignatures` and
/// `ghidra.features.bsim.query.GenSignatures`.
#[derive(Debug)]
pub struct BulkSignatureGenerator {
    /// Number of signatures generated so far.
    generated: usize,
    /// Number of failures.
    failures: usize,
    /// Error messages from failed generations.
    errors: Vec<String>,
    /// Whether to continue on error.
    continue_on_error: bool,
}

impl BulkSignatureGenerator {
    /// Create a new bulk signature generator.
    pub fn new() -> Self {
        Self {
            generated: 0,
            failures: 0,
            errors: Vec::new(),
            continue_on_error: true,
        }
    }

    /// Set whether to continue processing after an error.
    pub fn set_continue_on_error(&mut self, val: bool) {
        self.continue_on_error = val;
    }

    /// Generate signatures for all provided functions.
    ///
    /// Each function is processed through `BSimDatabase::compute_signature`.
    /// Functions that fail to produce a signature are counted in `failures`
    /// and their error messages stored.
    pub fn generate_signatures(
        &mut self,
        functions: &[Function],
    ) -> Vec<BSimSignature> {
        let mut signatures = Vec::with_capacity(functions.len());

        for func in functions {
            match BSimDatabase::compute_signature(func) {
                Ok(sig) => {
                    signatures.push(sig);
                    self.generated += 1;
                }
                Err(e) => {
                    self.failures += 1;
                    self.errors
                        .push(format!("Failed for {}: {}", func.name, e));
                    if !self.continue_on_error {
                        break;
                    }
                }
            }
        }

        signatures
    }

    /// Generate and insert signatures into a database.
    pub fn generate_and_insert(
        &mut self,
        db: &mut BSimDatabase,
        functions: &[Function],
    ) -> Result<usize> {
        let signatures = self.generate_signatures(functions);
        let count = signatures.len();
        db.insert_batch(signatures)?;
        Ok(count)
    }

    /// Number of signatures successfully generated.
    pub fn generated(&self) -> usize {
        self.generated
    }

    /// Number of failures.
    pub fn failures(&self) -> usize {
        self.failures
    }

    /// Total number of functions processed.
    pub fn total_processed(&self) -> usize {
        self.generated + self.failures
    }

    /// Error messages from failed generations.
    pub fn errors(&self) -> &[String] {
        &self.errors
    }

    /// Whether there were any failures.
    pub fn has_failures(&self) -> bool {
        self.failures > 0
    }

    /// Reset the generator state.
    pub fn reset(&mut self) {
        self.generated = 0;
        self.failures = 0;
        self.errors.clear();
    }
}

impl Default for BulkSignatureGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// BulkIngestStats
// ============================================================================

/// Statistics from a bulk ingest operation.
#[derive(Debug, Clone, Default)]
pub struct BulkIngestStats {
    /// Number of signatures ingested.
    pub ingested: usize,
    /// Number of executables processed.
    pub executables: usize,
    /// Number of functions processed.
    pub functions: usize,
    /// Number of errors.
    pub errors: usize,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Total bytes of feature vectors.
    pub vector_bytes: u64,
}

impl BulkIngestStats {
    /// Create new empty stats.
    pub fn new() -> Self {
        Self::default()
    }

    /// Average vectors per function.
    pub fn avg_vectors_per_function(&self) -> f64 {
        if self.functions == 0 {
            0.0
        } else {
            self.ingested as f64 / self.functions as f64
        }
    }

    /// Whether there were any errors.
    pub fn has_errors(&self) -> bool {
        self.errors > 0
    }
}

impl std::fmt::Display for BulkIngestStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BulkIngest: {} signatures from {} functions ({} exes), {} errors, {}ms",
            self.ingested, self.functions, self.executables, self.errors, self.duration_ms
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::{Address, AddressRange};
    use ghidra_core::program::listing::Function;

    fn test_function(name: &str, addr: u64) -> Function {
        Function::new(
            name,
            Address::new(addr),
            AddressRange::new(Address::new(addr), Address::new(addr + 0x100)),
        )
    }

    #[test]
    fn bulk_generator_basic() {
        let mut gen = BulkSignatureGenerator::new();
        let funcs = vec![
            test_function("main", 0x1000),
            test_function("foo", 0x2000),
            test_function("bar", 0x3000),
        ];

        let sigs = gen.generate_signatures(&funcs);
        assert_eq!(sigs.len(), 3);
        assert_eq!(gen.generated(), 3);
        assert_eq!(gen.failures(), 0);
        assert!(!gen.has_failures());
    }

    #[test]
    fn bulk_generator_generate_and_insert() {
        let mut db = BSimDatabase::in_memory().unwrap();
        let mut gen = BulkSignatureGenerator::new();
        let funcs = vec![
            test_function("f1", 0x1000),
            test_function("f2", 0x2000),
        ];

        let count = gen.generate_and_insert(&mut db, &funcs).unwrap();
        assert_eq!(count, 2);
        assert_eq!(db.len(), 2);
    }

    #[test]
    fn bulk_generator_reset() {
        let mut gen = BulkSignatureGenerator::new();
        gen.generate_signatures(&[test_function("f", 0x1000)]);
        assert_eq!(gen.generated(), 1);

        gen.reset();
        assert_eq!(gen.generated(), 0);
        assert!(gen.errors().is_empty());
    }

    #[test]
    fn bulk_ingest_stats_display() {
        let stats = BulkIngestStats {
            ingested: 100,
            executables: 5,
            functions: 100,
            errors: 2,
            duration_ms: 500,
            vector_bytes: 10240,
        };
        let s = format!("{}", stats);
        assert!(s.contains("100 signatures"));
        assert!(s.contains("2 errors"));
    }
}
