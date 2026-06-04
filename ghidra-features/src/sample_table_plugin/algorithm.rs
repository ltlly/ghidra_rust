//! Function scoring algorithms for the Sample Table Plugin.
//!
//! Ported from `FunctionAlgorithm.java`, `SizeFunctionAlgorithm.java`,
//! `BasicBlockCounterFunctionAlgorithm.java`, and
//! `ReferenceFunctionAlgorithm.java` in the SampleTablePlugin extension.
//!
//! Each algorithm implements [`FunctionAlgorithm`] and produces an integer
//! score for a function given its basic properties (body size, basic block
//! count, incoming reference count).

/// Trait for pluggable function scoring algorithms.
///
/// In the Java original this extends `ExtensionPoint` so that new algorithms
/// are discovered at runtime via `ClassSearcher`. In Rust we use a simple
/// trait object approach.
pub trait FunctionAlgorithm: Send + Sync + std::fmt::Debug {
    /// Compute a score for the function.
    ///
    /// # Parameters
    ///
    /// * `body_size` -- Number of bytes in the function body.
    /// * `basic_block_count` -- Number of basic blocks in the function.
    /// * `reference_count` -- Number of incoming references (callers).
    fn score(&self, body_size: usize, basic_block_count: usize, reference_count: usize) -> i32;

    /// Human-readable algorithm name.
    fn name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// SizeFunctionAlgorithm
// ---------------------------------------------------------------------------

/// Scores a function by its body size in bytes.
///
/// Ported from `SizeFunctionAlgorithm.java`. Returns `body_size` cast to `i32`.
#[derive(Debug, Clone, Copy)]
pub struct SizeFunctionAlgorithm;

impl SizeFunctionAlgorithm {
    /// Create a new instance.
    pub fn new() -> Self {
        Self
    }
}

impl Default for SizeFunctionAlgorithm {
    fn default() -> Self {
        Self::new()
    }
}

impl FunctionAlgorithm for SizeFunctionAlgorithm {
    fn score(&self, body_size: usize, _basic_block_count: usize, _reference_count: usize) -> i32 {
        body_size as i32
    }

    fn name(&self) -> &str {
        "Size"
    }
}

// ---------------------------------------------------------------------------
// BasicBlockCounterFunctionAlgorithm
// ---------------------------------------------------------------------------

/// Scores a function by its basic block count.
///
/// Ported from `BasicBlockCounterFunctionAlgorithm.java`. Returns the
/// number of basic blocks as the score.
#[derive(Debug, Clone, Copy)]
pub struct BasicBlockCounterFunctionAlgorithm;

impl BasicBlockCounterFunctionAlgorithm {
    /// Create a new instance.
    pub fn new() -> Self {
        Self
    }
}

impl Default for BasicBlockCounterFunctionAlgorithm {
    fn default() -> Self {
        Self::new()
    }
}

impl FunctionAlgorithm for BasicBlockCounterFunctionAlgorithm {
    fn score(&self, _body_size: usize, basic_block_count: usize, _reference_count: usize) -> i32 {
        basic_block_count as i32
    }

    fn name(&self) -> &str {
        "Basic Block Count"
    }
}

// ---------------------------------------------------------------------------
// ReferenceFunctionAlgorithm
// ---------------------------------------------------------------------------

/// Scores a function by its incoming reference (caller) count.
///
/// Ported from `ReferenceFunctionAlgorithm.java`. Returns the number
/// of references to the function as the score.
#[derive(Debug, Clone, Copy)]
pub struct ReferenceFunctionAlgorithm;

impl ReferenceFunctionAlgorithm {
    /// Create a new instance.
    pub fn new() -> Self {
        Self
    }
}

impl Default for ReferenceFunctionAlgorithm {
    fn default() -> Self {
        Self::new()
    }
}

impl FunctionAlgorithm for ReferenceFunctionAlgorithm {
    fn score(&self, _body_size: usize, _basic_block_count: usize, reference_count: usize) -> i32 {
        reference_count as i32
    }

    fn name(&self) -> &str {
        "References To"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_algorithm_typical() {
        let alg = SizeFunctionAlgorithm::new();
        assert_eq!(alg.score(1024, 10, 5), 1024);
        assert_eq!(alg.name(), "Size");
    }

    #[test]
    fn test_basic_block_algorithm_typical() {
        let alg = BasicBlockCounterFunctionAlgorithm::new();
        assert_eq!(alg.score(200, 42, 3), 42);
        assert_eq!(alg.name(), "Basic Block Count");
    }

    #[test]
    fn test_reference_algorithm_typical() {
        let alg = ReferenceFunctionAlgorithm::new();
        assert_eq!(alg.score(200, 8, 99), 99);
        assert_eq!(alg.name(), "References To");
    }

    #[test]
    fn test_algorithms_as_trait_objects() {
        let algorithms: Vec<Box<dyn FunctionAlgorithm>> = vec![
            Box::new(SizeFunctionAlgorithm::new()),
            Box::new(BasicBlockCounterFunctionAlgorithm::new()),
            Box::new(ReferenceFunctionAlgorithm::new()),
        ];
        assert_eq!(algorithms.len(), 3);

        let scores: Vec<i32> = algorithms
            .iter()
            .map(|a| a.score(100, 5, 10))
            .collect();
        assert_eq!(scores, vec![100, 5, 10]);
    }

    #[test]
    fn test_algorithms_default() {
        let _ = SizeFunctionAlgorithm::default();
        let _ = BasicBlockCounterFunctionAlgorithm::default();
        let _ = ReferenceFunctionAlgorithm::default();
    }
}
