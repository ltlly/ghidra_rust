//! Ensemble evaluator for parallel classification.
//!
//! Ported from `EnsembleEvaluatorCallback.java` in the MachineLearning
//! extension.
//!
//! Implements a short-circuit evaluator that stops computing as soon as
//! enough trees in the ensemble have been evaluated to determine the
//! final prediction.

use super::training::{DecisionTree, RandomForestModel};

/// An ensemble evaluator that short-circuits evaluation.
///
/// Rather than computing the precise probability the ensemble assigns to
/// a given address, it only determines whether the probability is >=
/// some threshold. The computation stops as soon as enough trees have
/// voted to determine the outcome.
pub struct EnsembleEvaluator {
    /// The trees in the ensemble.
    trees: Vec<DecisionTree>,
    /// Number of trees.
    num_trees: usize,
    /// The classification threshold.
    threshold: f64,
}

impl EnsembleEvaluator {
    /// Create a new ensemble evaluator from a random forest model.
    pub fn from_model(model: &RandomForestModel, threshold: f64) -> Self {
        Self {
            trees: model.trees.clone(),
            num_trees: model.num_trees,
            threshold,
        }
    }

    /// Create a new ensemble evaluator from a list of trees.
    pub fn new(trees: Vec<DecisionTree>, threshold: f64) -> Self {
        let num_trees = trees.len();
        Self {
            trees,
            num_trees,
            threshold,
        }
    }

    /// Evaluate whether the given features indicate a function start.
    ///
    /// This uses short-circuit evaluation: as soon as the remaining trees
    /// cannot change the outcome, evaluation stops.
    pub fn evaluate(&self, features: &[f64]) -> bool {
        if self.num_trees == 0 {
            return false;
        }

        let votes_needed = ((self.threshold * self.num_trees as f64).ceil() as usize)
            .min(self.num_trees);

        let mut positive_votes = 0usize;
        let mut evaluated = 0usize;

        for tree in &self.trees {
            if tree.predict(features) {
                positive_votes += 1;
            }
            evaluated += 1;

            // Short-circuit: if we already have enough positive votes
            if positive_votes >= votes_needed {
                return true;
            }

            // Short-circuit: if remaining trees can't reach the threshold
            let remaining = self.num_trees - evaluated;
            if positive_votes + remaining < votes_needed {
                return false;
            }
        }

        positive_votes >= votes_needed
    }

    /// Evaluate and return the precise probability.
    pub fn evaluate_probability(&self, features: &[f64]) -> f64 {
        if self.num_trees == 0 {
            return 0.0;
        }
        let votes = self.trees.iter().filter(|t| t.predict(features)).count();
        votes as f64 / self.num_trees as f64
    }

    /// Get the number of trees in the ensemble.
    pub fn num_trees(&self) -> usize {
        self.num_trees
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine_learning::training::DecisionTree;

    fn make_trees(n: usize, prediction: bool) -> Vec<DecisionTree> {
        (0..n)
            .map(|_| DecisionTree::new(0, 128.0, prediction, prediction))
            .collect()
    }

    #[test]
    fn test_evaluate_all_positive() {
        let trees = make_trees(10, true);
        let evaluator = EnsembleEvaluator::new(trees, 0.5);
        assert!(evaluator.evaluate(&[50.0]));
    }

    #[test]
    fn test_evaluate_all_negative() {
        let trees = make_trees(10, false);
        let evaluator = EnsembleEvaluator::new(trees, 0.5);
        assert!(!evaluator.evaluate(&[50.0]));
    }

    #[test]
    fn test_evaluate_short_circuit_positive() {
        // 7 out of 10 trees predict true. Threshold = 0.5.
        // Need ceil(5) = 5 positive votes.
        // Short-circuit should kick in before evaluating all 10 trees.
        let mut trees = make_trees(7, true);
        trees.extend(make_trees(3, false));
        let evaluator = EnsembleEvaluator::new(trees, 0.5);

        let result = evaluator.evaluate(&[50.0]);
        assert!(result);
    }

    #[test]
    fn test_evaluate_short_circuit_negative() {
        // 2 out of 10 trees predict true. Threshold = 0.5.
        // Need ceil(5) = 5 positive votes.
        // After evaluating all 10, only 2 votes -> false.
        let mut trees = make_trees(2, true);
        trees.extend(make_trees(8, false));
        let evaluator = EnsembleEvaluator::new(trees, 0.5);

        let result = evaluator.evaluate(&[50.0]);
        assert!(!result);
    }

    #[test]
    fn test_evaluate_empty_ensemble() {
        let evaluator = EnsembleEvaluator::new(vec![], 0.5);
        assert!(!evaluator.evaluate(&[1.0]));
    }

    #[test]
    fn test_evaluate_probability() {
        let mut trees = make_trees(3, true);
        trees.extend(make_trees(7, false));
        let evaluator = EnsembleEvaluator::new(trees, 0.5);

        let prob = evaluator.evaluate_probability(&[50.0]);
        assert!((prob - 0.3).abs() < 1e-10);
    }

    #[test]
    fn test_from_model() {
        let model = RandomForestModel::new(make_trees(5, true));
        let evaluator = EnsembleEvaluator::from_model(&model, 0.6);
        assert_eq!(evaluator.num_trees(), 5);
        assert!(evaluator.evaluate(&[50.0]));
    }

    #[test]
    fn test_high_threshold() {
        let mut trees = make_trees(9, true);
        trees.push(DecisionTree::new(0, 128.0, false, false));
        let evaluator = EnsembleEvaluator::new(trees, 0.9);
        // 9/10 = 0.9 >= threshold -> true
        assert!(evaluator.evaluate(&[50.0]));
    }
}
