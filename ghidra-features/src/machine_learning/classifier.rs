//! Function start classifier.
//!
//! Ported from `FunctionStartClassifier.java` in the MachineLearning
//! extension.
//!
//! Uses a trained random forest ensemble to classify addresses as
//! potential function starts.

use super::training::{FeatureVector, RandomForestModel};

/// Classifies addresses as potential function starts using a trained
/// random forest model.
///
/// The classifier extracts byte-level features from a window around
/// each address and passes them through the random forest ensemble to
/// compute a probability of the address being a function start.
pub struct FunctionStartClassifier {
    /// The trained random forest model.
    model: RandomForestModel,
    /// Number of bytes before the address to include as features.
    num_pre_bytes: usize,
    /// Number of bytes after (and including) the address.
    num_initial_bytes: usize,
    /// Whether to include bit-level features.
    include_bit_features: bool,
    /// Threshold for classification (default 0.5).
    threshold: f64,
}

impl FunctionStartClassifier {
    /// Create a new classifier.
    pub fn new(
        model: RandomForestModel,
        num_pre_bytes: usize,
        num_initial_bytes: usize,
        include_bit_features: bool,
    ) -> Self {
        Self {
            model,
            num_pre_bytes,
            num_initial_bytes,
            include_bit_features,
            threshold: 0.5,
        }
    }

    /// Set the classification threshold.
    pub fn set_threshold(&mut self, threshold: f64) {
        self.threshold = threshold;
    }

    /// Get the classification threshold.
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Classify a single address given its byte context.
    ///
    /// `pre_bytes` contains the bytes before the address.
    /// `initial_bytes` contains the bytes starting at the address.
    ///
    /// Returns the probability that this address is a function start.
    pub fn classify(&self, pre_bytes: &[u8], initial_bytes: &[u8]) -> f64 {
        let features = self.extract_features(pre_bytes, initial_bytes);
        self.model.predict(&features)
    }

    /// Classify and return whether the address is a function start.
    pub fn is_function_start(&self, pre_bytes: &[u8], initial_bytes: &[u8]) -> bool {
        self.classify(pre_bytes, initial_bytes) >= self.threshold
    }

    /// Extract a feature vector from the byte context.
    fn extract_features(&self, pre_bytes: &[u8], initial_bytes: &[u8]) -> Vec<f64> {
        let mut features = Vec::new();

        // Pre-bytes (bytes before the potential function start)
        let pre_start = if pre_bytes.len() >= self.num_pre_bytes {
            pre_bytes.len() - self.num_pre_bytes
        } else {
            0
        };
        for &b in &pre_bytes[pre_start..] {
            features.push(b as f64);
        }
        // Pad if too few pre-bytes
        while features.len() < self.num_pre_bytes {
            features.insert(0, 0.0);
        }

        // Initial bytes (bytes starting at the potential function start)
        for &b in initial_bytes.iter().take(self.num_initial_bytes) {
            features.push(b as f64);
        }
        // Pad if too few initial bytes
        let target_len = self.num_pre_bytes + self.num_initial_bytes;
        while features.len() < target_len {
            features.push(0.0);
        }

        // Bit-level features
        if self.include_bit_features {
            for &b in initial_bytes.iter().take(self.num_initial_bytes) {
                for bit in 0..8 {
                    features.push(((b >> bit) & 1) as f64);
                }
            }
        }

        features
    }

    /// Classify multiple addresses in batch.
    ///
    /// Returns pairs of `(address, probability)`.
    pub fn classify_batch(
        &self,
        addresses: &[(u64, Vec<u8>, Vec<u8>)],
    ) -> Vec<(u64, f64)> {
        addresses
            .iter()
            .map(|(addr, pre, init)| {
                let prob = self.classify(pre, init);
                (*addr, prob)
            })
            .collect()
    }

    /// Get a reference to the underlying model.
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

    fn make_classifier(threshold: f64) -> FunctionStartClassifier {
        // Split on feature index 16 (first initial byte), since features
        // are [pre_bytes..., initial_bytes...].
        let tree = DecisionTree::new(16, 128.0, true, false);
        let model = RandomForestModel::new(vec![tree]);
        let mut clf = FunctionStartClassifier::new(model, 16, 16, false);
        clf.set_threshold(threshold);
        clf
    }

    #[test]
    fn test_classify_above_threshold() {
        let clf = make_classifier(0.5);
        let pre = vec![0u8; 16];
        let init = vec![200u8; 16]; // First byte >= 128 -> right_prediction = false
        let prob = clf.classify(&pre, &init);
        assert!(prob < 0.5);
        assert!(!clf.is_function_start(&pre, &init));
    }

    #[test]
    fn test_classify_below_threshold() {
        let clf = make_classifier(0.5);
        let pre = vec![0u8; 16];
        let init = vec![50u8; 16]; // First byte < 128 -> left_prediction = true
        let prob = clf.classify(&pre, &init);
        assert!(prob >= 0.5);
        assert!(clf.is_function_start(&pre, &init));
    }

    #[test]
    fn test_classify_batch() {
        let clf = make_classifier(0.5);
        let batch = vec![
            (0x1000, vec![0u8; 16], vec![50u8; 16]),
            (0x2000, vec![0u8; 16], vec![200u8; 16]),
        ];
        let results = clf.classify_batch(&batch);
        assert_eq!(results.len(), 2);
        assert!(results[0].1 >= 0.5); // 50 < 128 -> true
        assert!(results[1].1 < 0.5); // 200 >= 128 -> false
    }

    #[test]
    fn test_feature_extraction_pads_short_input() {
        let clf = make_classifier(0.5);
        let pre = vec![1u8; 4]; // Too few
        let init = vec![2u8; 4]; // Too few
        let features = clf.extract_features(&pre, &init);
        // Should be padded to num_pre_bytes + num_initial_bytes = 32
        assert_eq!(features.len(), 32);
    }

    #[test]
    fn test_feature_extraction_with_bit_features() {
        let tree = DecisionTree::new(0, 128.0, true, false);
        let model = RandomForestModel::new(vec![tree]);
        let clf = FunctionStartClassifier::new(model, 4, 4, true);
        let features = clf.extract_features(&[1, 2, 3, 4], &[5, 6, 7, 8]);
        // 4 pre + 4 init + 4*8 bit features = 40
        assert_eq!(features.len(), 40);
    }

    #[test]
    fn test_model_reference() {
        let clf = make_classifier(0.5);
        assert_eq!(clf.model().num_trees, 1);
    }
}
