//! Checksum commands -- action commands for computing checksums.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.checksums` Java package.
//!
//! Provides command-level types for computing checksums over selected
//! memory regions or entire programs.
//!
//! # Key Types
//!
//! - [`ComputeChecksumCommand`] -- command to compute a single checksum
//! - [`ComputeAllChecksumsCommand`] -- command to compute all registered checksums
//! - [`ChecksumResult`] -- result of a checksum computation

use super::ChecksumAlgorithm;

// ---------------------------------------------------------------------------
// ChecksumResult
// ---------------------------------------------------------------------------

/// Result of computing a checksum over a memory region.
#[derive(Debug, Clone)]
pub struct ChecksumResult {
    /// The algorithm name.
    pub algorithm_name: String,
    /// The checksum value as bytes.
    pub checksum_bytes: Vec<u8>,
    /// The formatted checksum string (hex or decimal).
    pub formatted: String,
    /// The number of bytes that were hashed.
    pub bytes_processed: usize,
    /// Whether the computation was successful.
    pub success: bool,
    /// Error message if the computation failed.
    pub error: Option<String>,
}

impl ChecksumResult {
    /// Create a successful result.
    pub fn success(
        algorithm_name: impl Into<String>,
        checksum_bytes: Vec<u8>,
        formatted: impl Into<String>,
        bytes_processed: usize,
    ) -> Self {
        Self {
            algorithm_name: algorithm_name.into(),
            checksum_bytes,
            formatted: formatted.into(),
            bytes_processed,
            success: true,
            error: None,
        }
    }

    /// Create a failure result.
    pub fn failure(
        algorithm_name: impl Into<String>,
        error: impl Into<String>,
        bytes_processed: usize,
    ) -> Self {
        Self {
            algorithm_name: algorithm_name.into(),
            checksum_bytes: Vec::new(),
            formatted: String::new(),
            bytes_processed,
            success: false,
            error: Some(error.into()),
        }
    }

    /// Whether the computation was successful.
    pub fn is_success(&self) -> bool {
        self.success
    }
}

// ---------------------------------------------------------------------------
// ComputeChecksumCommand
// ---------------------------------------------------------------------------

/// Command to compute a checksum using a specific algorithm.
///
/// Ported from `ghidra.app.plugin.core.checksums.ComputeChecksumCommand`.
#[derive(Debug)]
pub struct ComputeChecksumCommand {
    /// The algorithm to use.
    pub algorithm_name: String,
    /// Whether to process the selection only.
    pub selection_only: bool,
    /// The result after execution.
    result: Option<ChecksumResult>,
}

impl ComputeChecksumCommand {
    /// Create a new command.
    pub fn new(algorithm_name: impl Into<String>) -> Self {
        Self {
            algorithm_name: algorithm_name.into(),
            selection_only: false,
            result: None,
        }
    }

    /// Execute the command on the given data using the given algorithm.
    pub fn execute(&mut self, data: &[u8], algorithm: &dyn ChecksumAlgorithm) {
        let checksum = algorithm.compute(data);
        let formatted = super::format_hex(&checksum);
        self.result = Some(ChecksumResult::success(
            algorithm.name(),
            checksum,
            formatted,
            data.len(),
        ));
    }

    /// Get the result.
    pub fn result(&self) -> Option<&ChecksumResult> {
        self.result.as_ref()
    }

    /// Set whether to use only the selected addresses.
    pub fn set_selection_only(&mut self, selection_only: bool) {
        self.selection_only = selection_only;
    }
}

// ---------------------------------------------------------------------------
// ComputeAllChecksumsCommand
// ---------------------------------------------------------------------------

/// Command to compute checksums using all registered algorithms.
///
/// Ported from `ghidra.app.plugin.core.checksums.ComputeAllChecksumsCommand`.
#[derive(Debug)]
pub struct ComputeAllChecksumsCommand {
    /// Results for each algorithm.
    results: Vec<ChecksumResult>,
}

impl ComputeAllChecksumsCommand {
    /// Create a new command.
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    /// Execute all algorithms on the given data.
    pub fn execute(&mut self, data: &[u8], algorithms: &[&dyn ChecksumAlgorithm]) {
        self.results.clear();
        for algo in algorithms {
            let checksum = algo.compute(data);
            let formatted = super::format_hex(&checksum);
            self.results.push(ChecksumResult::success(
                algo.name(),
                checksum,
                formatted,
                data.len(),
            ));
        }
    }

    /// Get all results.
    pub fn results(&self) -> &[ChecksumResult] {
        &self.results
    }

    /// Number of results.
    pub fn result_count(&self) -> usize {
        self.results.len()
    }

    /// Get a result by algorithm name.
    pub fn get_result(&self, algorithm_name: &str) -> Option<&ChecksumResult> {
        self.results
            .iter()
            .find(|r| r.algorithm_name == algorithm_name)
    }
}

impl Default for ComputeAllChecksumsCommand {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestAlgorithm {
        name: String,
    }

    impl ChecksumAlgorithm for TestAlgorithm {
        fn name(&self) -> &str {
            &self.name
        }

        fn compute(&self, data: &[u8]) -> Vec<u8> {
            // Simple XOR checksum
            vec![data.iter().fold(0u8, |acc, &b| acc ^ b)]
        }
    }

    #[test]
    fn test_checksum_result_success() {
        let result = ChecksumResult::success("Test", vec![0xAB, 0xCD], "ABCD", 100);
        assert!(result.is_success());
        assert_eq!(result.algorithm_name, "Test");
        assert_eq!(result.bytes_processed, 100);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_checksum_result_failure() {
        let result = ChecksumResult::failure("Test", "Out of memory", 50);
        assert!(!result.is_success());
        assert_eq!(result.error.as_deref(), Some("Out of memory"));
        assert_eq!(result.bytes_processed, 50);
    }

    #[test]
    fn test_compute_checksum_command() {
        let algo = TestAlgorithm {
            name: "XOR".to_string(),
        };
        let mut cmd = ComputeChecksumCommand::new("XOR");
        cmd.execute(b"Hello", &algo);

        let result = cmd.result().unwrap();
        assert!(result.is_success());
        assert_eq!(result.algorithm_name, "XOR");
        assert_eq!(result.bytes_processed, 5);
        // XOR of 'H','e','l','l','o' = 0x48^0x65^0x6C^0x6C^0x6F = 0x42
        assert_eq!(result.checksum_bytes, vec![0x42]);
    }

    #[test]
    fn test_compute_checksum_command_selection_only() {
        let mut cmd = ComputeChecksumCommand::new("Test");
        assert!(!cmd.selection_only);
        cmd.set_selection_only(true);
        assert!(cmd.selection_only);
    }

    #[test]
    fn test_compute_checksum_command_no_result() {
        let cmd = ComputeChecksumCommand::new("Test");
        assert!(cmd.result().is_none());
    }

    #[test]
    fn test_compute_all_checksums_command() {
        let algo1 = TestAlgorithm {
            name: "XOR".to_string(),
        };
        let algo2 = TestAlgorithm {
            name: "SUM".to_string(),
        };
        let mut cmd = ComputeAllChecksumsCommand::new();
        cmd.execute(b"Hello", &[&algo1, &algo2]);

        assert_eq!(cmd.result_count(), 2);
        assert!(cmd.get_result("XOR").is_some());
        assert!(cmd.get_result("SUM").is_some());
        assert!(cmd.get_result("MISSING").is_none());
    }

    #[test]
    fn test_compute_all_empty_data() {
        let algo = TestAlgorithm {
            name: "XOR".to_string(),
        };
        let mut cmd = ComputeAllChecksumsCommand::new();
        cmd.execute(b"", &[&algo]);

        assert_eq!(cmd.result_count(), 1);
        let result = cmd.get_result("XOR").unwrap();
        assert_eq!(result.checksum_bytes, vec![0x00]);
    }

    #[test]
    fn test_compute_all_empty_algorithms() {
        let mut cmd = ComputeAllChecksumsCommand::new();
        cmd.execute(b"Hello", &[]);
        assert_eq!(cmd.result_count(), 0);
    }
}
