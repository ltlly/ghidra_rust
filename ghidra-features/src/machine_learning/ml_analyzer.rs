//! Machine Learning function start analyzer.
//!
//! Ported from `MlAnalyzer.java` in the MachineLearning extension.
//!
//! This analyzer uses a trained random forest model to identify potential
//! function start addresses in a binary program. It scans executable memory
//! regions, extracts byte-level features around candidate addresses, and
//! classifies them using the ensemble model.
//!
//! # Architecture
//!
//! - [`MlAnalyzer`] -- The main analyzer that orchestrates the ML-based
//!   function start detection pipeline.
//!
//! - [`MlAnalysisResult`] -- Represents a single analysis result with
//!   address, probability, and interpretation.
//!
//! - [`MlAnalysisConfig`] -- Configuration for the analyzer including
//!   threshold, batch size, and feature extraction parameters.

use super::callback::FunctionStartCallback;
use super::classifier::FunctionStartClassifier;
use super::ensemble::EnsembleEvaluator;
use super::interpretation::Interpretation;
use super::params::FunctionStartRfParams;
use super::training::RandomForestModel;

// ---------------------------------------------------------------------------
// MlAnalysisConfig
// ---------------------------------------------------------------------------

/// Configuration for the ML analyzer.
///
/// Controls how the analyzer scans memory, extracts features, and
/// classifies addresses.
#[derive(Debug, Clone)]
pub struct MlAnalysisConfig {
    /// Minimum probability threshold for a positive classification.
    pub threshold: f64,
    /// Number of addresses to process in a single batch.
    pub batch_size: usize,
    /// Number of bytes before the candidate address to include as features.
    pub num_pre_bytes: usize,
    /// Number of bytes starting at the candidate address.
    pub num_initial_bytes: usize,
    /// Whether to include bit-level features in the feature vector.
    pub include_bit_features: bool,
    /// Instruction alignment for the target architecture.
    pub alignment: usize,
    /// Minimum function size in bytes (addresses closer than this to
    /// the end of a memory block are skipped).
    pub min_func_size: usize,
    /// Whether to skip addresses already marked as code.
    pub skip_existing_code: bool,
}

impl Default for MlAnalysisConfig {
    fn default() -> Self {
        Self {
            threshold: 0.5,
            batch_size: 1024,
            num_pre_bytes: 16,
            num_initial_bytes: 16,
            include_bit_features: false,
            alignment: 1,
            min_func_size: 1,
            skip_existing_code: true,
        }
    }
}

impl MlAnalysisConfig {
    /// Create a config from [`FunctionStartRfParams`].
    pub fn from_params(params: &FunctionStartRfParams) -> Self {
        let pre = params.pre_bytes().first().copied().unwrap_or(16);
        let init = params.initial_bytes().first().copied().unwrap_or(16);
        Self {
            num_pre_bytes: pre,
            num_initial_bytes: init,
            include_bit_features: params.include_bit_features(),
            alignment: params.instruction_alignment(),
            min_func_size: params.min_func_size(),
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// MlAnalysisResult
// ---------------------------------------------------------------------------

/// A single result from the ML analyzer.
///
/// Contains the address, its classification probability, and its
/// interpretation in the current program state.
#[derive(Debug, Clone)]
pub struct MlAnalysisResult {
    /// The candidate address.
    pub address: u64,
    /// The probability (0.0 to 1.0) that this address is a function start.
    pub probability: f64,
    /// Whether this address was classified as a function start.
    pub is_function_start: bool,
    /// The interpretation of this address in the current program state.
    pub interpretation: Interpretation,
}

// ---------------------------------------------------------------------------
// MlAnalyzer
// ---------------------------------------------------------------------------

/// ML-based function start analyzer.
///
/// Uses a trained random forest ensemble to scan executable memory and
/// identify addresses that are likely function entry points. The analyzer
/// works in three phases:
///
/// 1. **Address gathering** -- Collect aligned candidate addresses from
///    executable memory regions.
/// 2. **Feature extraction** -- For each candidate, extract a byte-level
///    feature vector from the surrounding context.
/// 3. **Classification** -- Pass feature vectors through the random forest
///    model to compute function-start probabilities.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::machine_learning::ml_analyzer::{MlAnalyzer, MlAnalysisConfig};
/// use ghidra_features::machine_learning::training::{DecisionTree, RandomForestModel};
///
/// let tree = DecisionTree::new(0, 128.0, true, false);
/// let model = RandomForestModel::new(vec![tree]);
/// let config = MlAnalysisConfig::default();
/// let analyzer = MlAnalyzer::new(model, config);
///
/// let binary = vec![0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10];
/// let results = analyzer.analyze(&binary, 0x400000);
/// ```
pub struct MlAnalyzer {
    /// The ensemble evaluator for short-circuit classification.
    evaluator: EnsembleEvaluator,
    /// The callback for feature extraction and classification.
    callback: FunctionStartCallback,
    /// Analysis configuration.
    config: MlAnalysisConfig,
}

impl MlAnalyzer {
    /// Create a new ML analyzer with the given model and configuration.
    pub fn new(model: RandomForestModel, config: MlAnalysisConfig) -> Self {
        let evaluator = EnsembleEvaluator::from_model(&model, config.threshold);
        let callback = FunctionStartCallback::new(
            model,
            config.num_pre_bytes,
            config.num_initial_bytes,
            config.include_bit_features,
            config.alignment,
        );
        Self {
            evaluator,
            callback,
            config,
        }
    }

    /// Analyze a byte buffer starting at `base_address`.
    ///
    /// Returns all addresses classified as potential function starts.
    pub fn analyze(&self, data: &[u8], base_address: u64) -> Vec<MlAnalysisResult> {
        let mut results = Vec::new();
        let alignment = self.config.alignment.max(1);
        let min_func_size = self.config.min_func_size;

        // Scan aligned addresses
        let aligned_start = Self::align_up(base_address, alignment as u64);
        let data_start = (aligned_start - base_address) as usize;

        for offset in (data_start..data.len()).step_by(alignment) {
            let addr = base_address + offset as u64;

            // Skip if too close to the end for a valid function
            if offset + min_func_size > data.len() {
                break;
            }

            // Extract byte context
            let pre_start = offset.saturating_sub(self.config.num_pre_bytes);
            let pre_bytes = &data[pre_start..offset];
            let init_end = (offset + self.config.num_initial_bytes).min(data.len());
            let initial_bytes = &data[offset..init_end];

            // Classify
            let probability = self.callback.process(pre_bytes, initial_bytes);
            let is_function_start = probability >= self.config.threshold;

            results.push(MlAnalysisResult {
                address: addr,
                probability,
                is_function_start,
                interpretation: if is_function_start {
                    Interpretation::FunctionStart
                } else {
                    Interpretation::Undefined
                },
            });
        }

        results
    }

    /// Analyze and return only the addresses classified as function starts.
    pub fn analyze_function_starts(
        &self,
        data: &[u8],
        base_address: u64,
    ) -> Vec<MlAnalysisResult> {
        self.analyze(data, base_address)
            .into_iter()
            .filter(|r| r.is_function_start)
            .collect()
    }

    /// Analyze in batches and return results.
    ///
    /// Processes addresses in chunks of `config.batch_size` for memory
    /// efficiency.
    pub fn analyze_batched(
        &self,
        data: &[u8],
        base_address: u64,
    ) -> Vec<MlAnalysisResult> {
        let mut all_results = Vec::new();
        let alignment = self.config.alignment.max(1);
        let batch_size = self.config.batch_size.max(1);

        let aligned_start = Self::align_up(base_address, alignment as u64);
        let data_start = (aligned_start - base_address) as usize;

        let mut offset = data_start;
        while offset < data.len() {
            let batch_end = (offset + batch_size * alignment).min(data.len());
            let batch_data = &data[offset..batch_end];
            let batch_base = base_address + offset as u64;

            let batch_results = self.analyze(batch_data, batch_base);
            all_results.extend(batch_results);

            offset = batch_end;
        }

        all_results
    }

    /// Get the classification threshold.
    pub fn threshold(&self) -> f64 {
        self.config.threshold
    }

    /// Get the analysis configuration.
    pub fn config(&self) -> &MlAnalysisConfig {
        &self.config
    }

    /// Get the number of trees in the ensemble.
    pub fn num_trees(&self) -> usize {
        self.evaluator.num_trees()
    }

    /// Align an address upward to the given alignment.
    fn align_up(addr: u64, alignment: u64) -> u64 {
        if alignment == 0 {
            return addr;
        }
        let rem = addr % alignment;
        if rem == 0 {
            addr
        } else {
            addr + alignment - rem
        }
    }
}

impl std::fmt::Debug for MlAnalyzer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlAnalyzer")
            .field("threshold", &self.config.threshold)
            .field("num_trees", &self.evaluator.num_trees())
            .field("alignment", &self.config.alignment)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine_learning::training::DecisionTree;

    fn make_analyzer(threshold: f64) -> MlAnalyzer {
        let tree = DecisionTree::new(16, 128.0, true, false);
        let model = RandomForestModel::new(vec![tree]);
        let config = MlAnalysisConfig {
            threshold,
            num_pre_bytes: 16,
            num_initial_bytes: 16,
            alignment: 1,
            ..Default::default()
        };
        MlAnalyzer::new(model, config)
    }

    #[test]
    fn test_analyze_basic() {
        let analyzer = make_analyzer(0.5);
        let data = vec![0u8; 64];
        let results = analyzer.analyze(&data, 0x400000);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_analyze_returns_all_addresses() {
        let analyzer = make_analyzer(0.5);
        let data = vec![0u8; 32];
        let results = analyzer.analyze(&data, 0x1000);
        // All 32 addresses should be classified
        assert_eq!(results.len(), 32);
        // First result should be at 0x1000
        assert_eq!(results[0].address, 0x1000);
    }

    #[test]
    fn test_analyze_function_starts_filter() {
        let analyzer = make_analyzer(0.5);
        let data = vec![50u8; 64]; // byte 50 < 128 -> left_prediction = true
        let starts = analyzer.analyze_function_starts(&data, 0x400000);
        // All should be function starts since 50 < 128
        assert!(!starts.is_empty());
        for r in &starts {
            assert!(r.is_function_start);
        }
    }

    #[test]
    fn test_analyze_with_alignment() {
        let tree = DecisionTree::new(0, 128.0, true, false);
        let model = RandomForestModel::new(vec![tree]);
        let config = MlAnalysisConfig {
            alignment: 4,
            num_pre_bytes: 4,
            num_initial_bytes: 4,
            ..Default::default()
        };
        let analyzer = MlAnalyzer::new(model, config);
        let data = vec![0u8; 64];
        let results = analyzer.analyze(&data, 0x1000);
        // Should only have addresses aligned to 4
        for r in &results {
            assert_eq!(r.address % 4, 0);
        }
    }

    #[test]
    fn test_analyze_batched() {
        let analyzer = make_analyzer(0.5);
        let data = vec![0u8; 2048];
        let results = analyzer.analyze_batched(&data, 0x400000);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_analyze_empty_data() {
        let analyzer = make_analyzer(0.5);
        let data: Vec<u8> = vec![];
        let results = analyzer.analyze(&data, 0x400000);
        assert!(results.is_empty());
    }

    #[test]
    fn test_analyze_short_data() {
        let analyzer = make_analyzer(0.5);
        let data = vec![0x55u8; 4];
        let results = analyzer.analyze(&data, 0x400000);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_config_from_params() {
        let mut params = FunctionStartRfParams::new(4);
        params.set_pre_bytes(vec![8]);
        params.set_initial_bytes(vec![16]);
        params.set_include_bit_features(true);
        params.set_min_func_size(32);

        let config = MlAnalysisConfig::from_params(&params);
        assert_eq!(config.num_pre_bytes, 8);
        assert_eq!(config.num_initial_bytes, 16);
        assert!(config.include_bit_features);
        assert_eq!(config.min_func_size, 32);
        assert_eq!(config.alignment, 4);
    }

    #[test]
    fn test_align_up() {
        assert_eq!(MlAnalyzer::align_up(0x1000, 4), 0x1000);
        assert_eq!(MlAnalyzer::align_up(0x1001, 4), 0x1004);
        assert_eq!(MlAnalyzer::align_up(0x1003, 4), 0x1004);
        assert_eq!(MlAnalyzer::align_up(0x1004, 4), 0x1004);
        assert_eq!(MlAnalyzer::align_up(0, 1), 0);
    }

    #[test]
    fn test_threshold_and_config() {
        let analyzer = make_analyzer(0.7);
        assert!((analyzer.threshold() - 0.7).abs() < 1e-10);
        assert_eq!(analyzer.config().alignment, 1);
        assert_eq!(analyzer.num_trees(), 1);
    }

    #[test]
    fn test_debug_format() {
        let analyzer = make_analyzer(0.5);
        let debug = format!("{:?}", analyzer);
        assert!(debug.contains("MlAnalyzer"));
        assert!(debug.contains("threshold"));
    }

    #[test]
    fn test_analysis_result_interpretation() {
        let analyzer = make_analyzer(0.5);
        let data = vec![50u8; 32];
        let results = analyzer.analyze(&data, 0x1000);
        for r in &results {
            if r.is_function_start {
                assert_eq!(r.interpretation, Interpretation::FunctionStart);
            } else {
                assert_eq!(r.interpretation, Interpretation::Undefined);
            }
        }
    }
}
