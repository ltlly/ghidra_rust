//! Training utilities and data containers.
//!
//! Ported from `TrainingAndTestData.java` and `ModelTrainingUtils.java`
//! in the MachineLearning extension.

use std::collections::BTreeSet;

/// Container for training and testing address sets used during model
/// training.
///
/// The addresses are split into:
/// - **Training positive**: known function entry points for training.
/// - **Training negative**: known non-entry points for training.
/// - **Test positive**: known function entry points for evaluation.
/// - **Test negative**: known non-entry points for evaluation.
#[derive(Debug, Clone, Default)]
pub struct TrainingAndTestData {
    /// Training set of function entry addresses.
    training_positive: BTreeSet<u64>,
    /// Training set of function interior (non-entry) addresses.
    training_negative: BTreeSet<u64>,
    /// Test set of function entry addresses.
    test_positive: BTreeSet<u64>,
    /// Test set of function interior (non-entry) addresses.
    test_negative: BTreeSet<u64>,
}

impl TrainingAndTestData {
    /// Create a new container with the given address sets.
    pub fn new(
        training_positive: BTreeSet<u64>,
        training_negative: BTreeSet<u64>,
        test_positive: BTreeSet<u64>,
        test_negative: BTreeSet<u64>,
    ) -> Self {
        Self {
            training_positive,
            training_negative,
            test_positive,
            test_negative,
        }
    }

    /// Get the training positive addresses.
    pub fn training_positive(&self) -> &BTreeSet<u64> {
        &self.training_positive
    }

    /// Get the training negative addresses.
    pub fn training_negative(&self) -> &BTreeSet<u64> {
        &self.training_negative
    }

    /// Get the test positive addresses.
    pub fn test_positive(&self) -> &BTreeSet<u64> {
        &self.test_positive
    }

    /// Get the test negative addresses.
    pub fn test_negative(&self) -> &BTreeSet<u64> {
        &self.test_negative
    }

    /// Total number of training addresses.
    pub fn training_size(&self) -> usize {
        self.training_positive.len() + self.training_negative.len()
    }

    /// Total number of test addresses.
    pub fn test_size(&self) -> usize {
        self.test_positive.len() + self.test_negative.len()
    }

    /// Total number of all addresses.
    pub fn total_size(&self) -> usize {
        self.training_size() + self.test_size()
    }
}

// ---------------------------------------------------------------------------
// ModelTrainingUtils
// ---------------------------------------------------------------------------

/// A feature vector representing a byte-level window around an address.
#[derive(Debug, Clone)]
pub struct FeatureVector {
    /// The raw byte features (pre-bytes + initial-bytes).
    pub features: Vec<u8>,
    /// Optional bit-level features.
    pub bit_features: Vec<u8>,
    /// The address this vector was extracted from.
    pub address: u64,
    /// Whether this is a function start (positive) or not (negative).
    pub is_function_start: bool,
}

/// A simple random forest model for function start prediction.
///
/// This is a simplified model structure; the actual training logic
/// depends on the Tribuo library in the Java version.
#[derive(Debug, Clone)]
pub struct RandomForestModel {
    /// Number of trees in the ensemble.
    pub num_trees: usize,
    /// Per-tree predictions (simplified as threshold-based rules).
    pub trees: Vec<DecisionTree>,
}

impl RandomForestModel {
    /// Get the number of trees in the ensemble.
    pub fn num_trees(&self) -> usize {
        self.num_trees
    }
}

/// A single decision tree (simplified).
#[derive(Debug, Clone)]
pub struct DecisionTree {
    /// The feature index to split on.
    pub split_feature: usize,
    /// The threshold for the split.
    pub threshold: f64,
    /// Prediction for the left branch (< threshold): true = function start.
    pub left_prediction: bool,
    /// Prediction for the right branch (>= threshold): true = function start.
    pub right_prediction: bool,
}

impl DecisionTree {
    /// Create a simple decision tree.
    pub fn new(
        split_feature: usize,
        threshold: f64,
        left_prediction: bool,
        right_prediction: bool,
    ) -> Self {
        Self {
            split_feature,
            threshold,
            left_prediction,
            right_prediction,
        }
    }

    /// Predict whether an address is a function start.
    pub fn predict(&self, features: &[f64]) -> bool {
        let value = features.get(self.split_feature).copied().unwrap_or(0.0);
        if value < self.threshold {
            self.left_prediction
        } else {
            self.right_prediction
        }
    }
}

impl RandomForestModel {
    /// Create a new random forest model.
    pub fn new(trees: Vec<DecisionTree>) -> Self {
        let num_trees = trees.len();
        Self { num_trees, trees }
    }

    /// Predict using majority vote across all trees.
    ///
    /// Returns the probability (fraction of trees voting "true") that the
    /// given feature vector represents a function start.
    pub fn predict(&self, features: &[f64]) -> f64 {
        if self.trees.is_empty() {
            return 0.0;
        }
        let votes = self.trees.iter().filter(|t| t.predict(features)).count();
        votes as f64 / self.num_trees as f64
    }

    /// Predict whether the address is a function start (threshold 0.5).
    pub fn is_function_start(&self, features: &[f64]) -> bool {
        self.predict(features) >= 0.5
    }
}

/// Utilities for training random forest models.
pub struct ModelTrainingUtils;

impl ModelTrainingUtils {
    /// Split data into training and test sets.
    ///
    /// Uses a simple alternating assignment: even-indexed items go to
    /// training, odd-indexed to test.
    pub fn split_train_test(
        positives: &[u64],
        negatives: &[u64],
        train_ratio: f64,
    ) -> TrainingAndTestData {
        let mut train_pos = BTreeSet::new();
        let mut test_pos = BTreeSet::new();
        let mut train_neg = BTreeSet::new();
        let mut test_neg = BTreeSet::new();

        for (i, &addr) in positives.iter().enumerate() {
            if (i as f64 / positives.len().max(1) as f64) < train_ratio {
                train_pos.insert(addr);
            } else {
                test_pos.insert(addr);
            }
        }

        for (i, &addr) in negatives.iter().enumerate() {
            if (i as f64 / negatives.len().max(1) as f64) < train_ratio {
                train_neg.insert(addr);
            } else {
                test_neg.insert(addr);
            }
        }

        TrainingAndTestData::new(train_pos, train_neg, test_pos, test_neg)
    }

    /// Compute a confusion matrix from predictions.
    ///
    /// Returns `[true_positive, false_positive, true_negative, false_negative]`.
    pub fn confusion_matrix(
        actual_positive: &BTreeSet<u64>,
        actual_negative: &BTreeSet<u64>,
        predicted_positive: &BTreeSet<u64>,
    ) -> [usize; 4] {
        let tp = actual_positive
            .intersection(predicted_positive)
            .count();
        let fp = actual_negative
            .intersection(predicted_positive)
            .count();
        let tn = actual_negative.len() - fp;
        let fn_count = actual_positive.len() - tp;
        [tp, fp, tn, fn_count]
    }

    /// Compute accuracy from a confusion matrix.
    pub fn accuracy(cm: [usize; 4]) -> f64 {
        let total = cm[0] + cm[1] + cm[2] + cm[3];
        if total == 0 {
            return 0.0;
        }
        (cm[0] + cm[2]) as f64 / total as f64
    }

    /// Compute precision from a confusion matrix.
    pub fn precision(cm: [usize; 4]) -> f64 {
        let predicted_positive = cm[0] + cm[1];
        if predicted_positive == 0 {
            return 0.0;
        }
        cm[0] as f64 / predicted_positive as f64
    }

    /// Compute recall from a confusion matrix.
    pub fn recall(cm: [usize; 4]) -> f64 {
        let actual_positive = cm[0] + cm[3];
        if actual_positive == 0 {
            return 0.0;
        }
        cm[0] as f64 / actual_positive as f64
    }

    /// Compute F1 score from a confusion matrix.
    pub fn f1_score(cm: [usize; 4]) -> f64 {
        let p = Self::precision(cm);
        let r = Self::recall(cm);
        if p + r == 0.0 {
            return 0.0;
        }
        2.0 * p * r / (p + r)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_training_and_test_data() {
        let mut train_pos = BTreeSet::new();
        train_pos.insert(0x1000);
        train_pos.insert(0x2000);
        let train_neg = BTreeSet::new();
        let test_pos = BTreeSet::new();
        let mut test_neg = BTreeSet::new();
        test_neg.insert(0x3000);

        let data = TrainingAndTestData::new(train_pos, train_neg, test_pos, test_neg);
        assert_eq!(data.training_size(), 2);
        assert_eq!(data.test_size(), 1);
        assert_eq!(data.total_size(), 3);
    }

    #[test]
    fn test_split_train_test() {
        let positives = vec![0x1000, 0x2000, 0x3000, 0x4000];
        let negatives = vec![0x5000, 0x6000, 0x7000, 0x8000];

        let data = ModelTrainingUtils::split_train_test(&positives, &negatives, 0.75);
        assert!(data.training_positive().len() >= 2);
        assert!(data.training_negative().len() >= 2);
    }

    #[test]
    fn test_confusion_matrix_perfect() {
        let actual_pos: BTreeSet<u64> = [1, 2, 3].iter().copied().collect();
        let actual_neg: BTreeSet<u64> = [4, 5, 6].iter().copied().collect();
        let predicted_pos: BTreeSet<u64> = [1, 2, 3].iter().copied().collect();

        let cm = ModelTrainingUtils::confusion_matrix(&actual_pos, &actual_neg, &predicted_pos);
        assert_eq!(cm, [3, 0, 3, 0]);
        assert!((ModelTrainingUtils::accuracy(cm) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_confusion_matrix_all_wrong() {
        let actual_pos: BTreeSet<u64> = [1, 2].iter().copied().collect();
        let actual_neg: BTreeSet<u64> = [3, 4].iter().copied().collect();
        let predicted_pos: BTreeSet<u64> = [3, 4].iter().copied().collect();

        let cm = ModelTrainingUtils::confusion_matrix(&actual_pos, &actual_neg, &predicted_pos);
        assert_eq!(cm, [0, 2, 0, 2]);
        assert!((ModelTrainingUtils::accuracy(cm)).abs() < 1e-10);
    }

    #[test]
    fn test_precision_recall_f1() {
        let cm = [80, 20, 70, 30]; // tp, fp, tn, fn
        let p = ModelTrainingUtils::precision(cm);
        let r = ModelTrainingUtils::recall(cm);
        let f1 = ModelTrainingUtils::f1_score(cm);

        assert!((p - 0.8).abs() < 1e-10);
        assert!((r - 80.0 / 110.0).abs() < 1e-10);
        assert!(f1 > 0.0 && f1 < 1.0);
    }

    #[test]
    fn test_random_forest_model() {
        let tree1 = DecisionTree::new(0, 128.0, true, false);
        let tree2 = DecisionTree::new(1, 64.0, false, true);
        let model = RandomForestModel::new(vec![tree1, tree2]);

        // Feature: [200, 100] -> tree1: >= 128 -> false, tree2: >= 64 -> true
        // Vote: 1/2 = 0.5 -> function start
        let features = [200.0, 100.0];
        assert!(model.is_function_start(&features));
        assert!((model.predict(&features) - 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_random_forest_empty_model() {
        let model = RandomForestModel::new(vec![]);
        assert!((model.predict(&[1.0, 2.0])).abs() < 1e-10);
        assert!(!model.is_function_start(&[1.0, 2.0]));
    }
}
