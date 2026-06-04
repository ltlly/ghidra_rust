//! Function start callback for parallel classification.
//!
//! Ported from `FunctionStartCallback.java` in the MachineLearning
//! extension.
//!
//! Implements a callback that applies a random forest model at a given
//! address to determine the probability that the address represents a
//! function start.

use super::training::RandomForestModel;

/// A callback that applies a random forest model at an address.
///
/// Used in concurrent classification pipelines where addresses are
/// processed in parallel. Each callback instance holds the model and
/// the parameters needed to extract features from a program's byte
/// window around each address.
///
/// # Example
///
/// ```
/// use ghidra_features::machine_learning::FunctionStartCallback;
/// use ghidra_features::machine_learning::training::{DecisionTree, RandomForestModel};
///
/// let tree = DecisionTree::new(0, 128.0, true, false);
/// let model = RandomForestModel::new(vec![tree]);
/// let callback = FunctionStartCallback::new(model, 16, 32, false, 1);
///
/// // Classify using byte context
/// let pre = vec![0u8; 16];
/// let initial = vec![0x55, 0x48, 0x89, 0xe5]; // x86 prologue
/// let probability = callback.process(&pre, &initial);
/// assert!((0.0..=1.0).contains(&probability));
/// ```
#[derive(Debug, Clone)]
pub struct FunctionStartCallback {
    /// The random forest model.
    model: RandomForestModel,
    /// Number of bytes before the address.
    num_pre_bytes: usize,
    /// Number of bytes starting at the address.
    num_initial_bytes: usize,
    /// Whether to include bit-level features.
    include_bit_level_features: bool,
    /// Instruction alignment (bytes).
    alignment: usize,
}

impl FunctionStartCallback {
    /// Create a new function start callback.
    ///
    /// # Parameters
    /// - `model`: The trained random forest model.
    /// - `num_pre_bytes`: Bytes before the address to gather.
    /// - `num_initial_bytes`: Bytes after (and including) the address.
    /// - `include_bit_level_features`: Whether to expand each byte into 8 bits.
    /// - `alignment`: Instruction alignment in bytes.
    pub fn new(
        model: RandomForestModel,
        num_pre_bytes: usize,
        num_initial_bytes: usize,
        include_bit_level_features: bool,
        alignment: usize,
    ) -> Self {
        Self {
            model,
            num_pre_bytes,
            num_initial_bytes,
            include_bit_level_features,
            alignment,
        }
    }

    /// Apply the model to the given byte context.
    ///
    /// Returns the probability that the address is a function start.
    pub fn process(&self, pre_bytes: &[u8], initial_bytes: &[u8]) -> f64 {
        let features = self.extract_features(pre_bytes, initial_bytes);
        self.model.predict(&features)
    }

    /// Extract a feature vector from the byte context.
    fn extract_features(&self, pre_bytes: &[u8], initial_bytes: &[u8]) -> Vec<f64> {
        let mut features = Vec::new();

        // Pre-bytes: raw byte values
        for &b in pre_bytes.iter().take(self.num_pre_bytes) {
            features.push(b as f64);
        }

        // Initial bytes: raw byte values
        for &b in initial_bytes.iter().take(self.num_initial_bytes) {
            features.push(b as f64);
        }

        // Optional bit-level features
        if self.include_bit_level_features {
            for &b in pre_bytes.iter().take(self.num_pre_bytes) {
                for bit in 0..8 {
                    features.push(((b >> bit) & 1) as f64);
                }
            }
            for &b in initial_bytes.iter().take(self.num_initial_bytes) {
                for bit in 0..8 {
                    features.push(((b >> bit) & 1) as f64);
                }
            }
        }

        features
    }

    /// Get the number of pre-bytes.
    pub fn num_pre_bytes(&self) -> usize {
        self.num_pre_bytes
    }

    /// Get the number of initial bytes.
    pub fn num_initial_bytes(&self) -> usize {
        self.num_initial_bytes
    }

    /// Get the instruction alignment.
    pub fn alignment(&self) -> usize {
        self.alignment
    }

    /// Get whether bit-level features are included.
    pub fn include_bit_level_features(&self) -> bool {
        self.include_bit_level_features
    }

    /// Get a reference to the model.
    pub fn model(&self) -> &RandomForestModel {
        &self.model
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine_learning::training::DecisionTree;

    fn make_callback(include_bits: bool) -> FunctionStartCallback {
        let tree = DecisionTree::new(0, 128.0, true, false);
        let model = RandomForestModel::new(vec![tree]);
        FunctionStartCallback::new(model, 4, 4, include_bits, 1)
    }

    #[test]
    fn test_process_basic() {
        let cb = make_callback(false);
        let pre = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let initial = vec![0x55, 0x48, 0x89, 0xE5];
        let prob = cb.process(&pre, &initial);
        assert!((0.0..=1.0).contains(&prob));
    }

    #[test]
    fn test_process_with_bit_features() {
        let cb = make_callback(true);
        let pre = vec![0xFF, 0x00, 0xAA, 0x55];
        let initial = vec![0x55, 0x48, 0x89, 0xE5];
        let prob = cb.process(&pre, &initial);
        assert!((0.0..=1.0).contains(&prob));
    }

    #[test]
    fn test_process_empty_context() {
        let cb = make_callback(false);
        let prob = cb.process(&[], &[]);
        assert!((0.0..=1.0).contains(&prob));
    }

    #[test]
    fn test_extract_features_length() {
        let cb = make_callback(false);
        let pre = vec![0u8; 10];
        let initial = vec![0u8; 10];
        let features = cb.extract_features(&pre, &initial);
        assert_eq!(features.len(), 8); // min(pre.len, 4) + min(initial.len, 4)
    }

    #[test]
    fn test_extract_features_length_with_bits() {
        let cb = make_callback(true);
        let pre = vec![0u8; 4];
        let initial = vec![0u8; 4];
        let features = cb.extract_features(&pre, &initial);
        // 4 raw + 4 raw + 4*8 bits + 4*8 bits = 72
        assert_eq!(features.len(), 72);
    }

    #[test]
    fn test_callback_getters() {
        let cb = make_callback(true);
        assert_eq!(cb.num_pre_bytes(), 4);
        assert_eq!(cb.num_initial_bytes(), 4);
        assert!(cb.include_bit_level_features());
        assert_eq!(cb.alignment(), 1);
    }
}
