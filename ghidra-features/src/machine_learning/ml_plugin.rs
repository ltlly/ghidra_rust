//! Machine Learning plugin.
//!
//! Ported from `MlPlugin.java` in the MachineLearning extension.
//!
//! Provides the Ghidra plugin interface for ML-based function start
//! detection. The plugin manages the analyzer lifecycle, user-facing
//! settings, and result presentation.

use super::ml_analyzer::{MlAnalysisConfig, MlAnalysisResult, MlAnalyzer};
use super::params::FunctionStartRfParams;
use super::training::RandomForestModel;

// ---------------------------------------------------------------------------
// MlPlugin
// ---------------------------------------------------------------------------

/// The Machine Learning plugin for Ghidra.
///
/// Provides an interactive interface for running ML-based function start
/// detection on the current program. The plugin manages:
///
/// - Loading and validating the trained random forest model.
/// - Configuring analysis parameters (threshold, feature sizes, alignment).
/// - Running the analysis and collecting results.
/// - Presenting results for user review.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::machine_learning::ml_plugin::MlPlugin;
/// use ghidra_features::machine_learning::training::{DecisionTree, RandomForestModel};
///
/// let tree = DecisionTree::new(0, 128.0, true, false);
/// let model = RandomForestModel::new(vec![tree]);
/// let mut plugin = MlPlugin::new(model);
/// plugin.set_threshold(0.6);
///
/// let data = vec![0x55u8; 256];
/// let results = plugin.run_analysis(&data, 0x400000);
/// assert!(results.iter().all(|r| r.is_function_start));
/// ```
pub struct MlPlugin {
    /// The random forest model.
    model: RandomForestModel,
    /// Analysis configuration.
    config: MlAnalysisConfig,
    /// Whether the plugin is enabled.
    enabled: bool,
    /// Last analysis results (cached for UI display).
    last_results: Vec<MlAnalysisResult>,
    /// Plugin status message.
    status: String,
}

impl MlPlugin {
    /// Create a new ML plugin with the given model.
    pub fn new(model: RandomForestModel) -> Self {
        Self {
            model,
            config: MlAnalysisConfig::default(),
            enabled: true,
            last_results: Vec::new(),
            status: "Ready".to_string(),
        }
    }

    /// Create a new ML plugin from parameters.
    ///
    /// The model must be set separately via [`set_model`](Self::set_model).
    pub fn from_params(params: &FunctionStartRfParams) -> Self {
        Self {
            model: RandomForestModel::new(vec![]),
            config: MlAnalysisConfig::from_params(params),
            enabled: true,
            last_results: Vec::new(),
            status: "Ready (no model loaded)".to_string(),
        }
    }

    /// Set the random forest model.
    pub fn set_model(&mut self, model: RandomForestModel) {
        self.model = model;
        self.status = "Model loaded".to_string();
    }

    /// Get a reference to the current model.
    pub fn model(&self) -> &RandomForestModel {
        &self.model
    }

    /// Set the classification threshold.
    pub fn set_threshold(&mut self, threshold: f64) {
        self.config.threshold = threshold.clamp(0.0, 1.0);
    }

    /// Get the current threshold.
    pub fn threshold(&self) -> f64 {
        self.config.threshold
    }

    /// Set the analysis configuration.
    pub fn set_config(&mut self, config: MlAnalysisConfig) {
        self.config = config;
    }

    /// Get a reference to the analysis configuration.
    pub fn config(&self) -> &MlAnalysisConfig {
        &self.config
    }

    /// Get a mutable reference to the analysis configuration.
    pub fn config_mut(&mut self) -> &mut MlAnalysisConfig {
        &mut self.config
    }

    /// Whether the plugin is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the plugin.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the current status message.
    pub fn status(&self) -> &str {
        &self.status
    }

    /// Run ML-based function start analysis on the given data.
    ///
    /// Returns the number of function starts found. Results are cached
    /// internally and can be retrieved via [`last_results`](Self::last_results).
    pub fn run_analysis(&mut self, data: &[u8], base_address: u64) -> usize {
        if !self.enabled {
            self.status = "Plugin is disabled".to_string();
            return 0;
        }

        if self.model.num_trees() == 0 {
            self.status = "No model loaded".to_string();
            return 0;
        }

        self.status = "Analyzing...".to_string();

        let analyzer = MlAnalyzer::new(self.model.clone(), self.config.clone());
        let results = analyzer.analyze_function_starts(data, base_address);
        let count = results.len();

        self.last_results = results;
        self.status = format!("Analysis complete: {count} function starts found");
        count
    }

    /// Run analysis and return all results (not just function starts).
    pub fn run_analysis_all(
        &mut self,
        data: &[u8],
        base_address: u64,
    ) -> usize {
        if !self.enabled {
            self.status = "Plugin is disabled".to_string();
            return 0;
        }

        if self.model.num_trees() == 0 {
            self.status = "No model loaded".to_string();
            return 0;
        }

        self.status = "Analyzing...".to_string();

        let analyzer = MlAnalyzer::new(self.model.clone(), self.config.clone());
        let results = analyzer.analyze(data, base_address);
        let count = results.len();

        self.last_results = results;
        self.status = format!("Analysis complete: {count} addresses classified");
        count
    }

    /// Get the last analysis results.
    pub fn last_results(&self) -> &[MlAnalysisResult] {
        &self.last_results
    }

    /// Get the number of function starts from the last analysis.
    pub fn last_function_start_count(&self) -> usize {
        self.last_results
            .iter()
            .filter(|r| r.is_function_start)
            .count()
    }

    /// Clear cached results.
    pub fn clear_results(&mut self) {
        self.last_results.clear();
        self.status = "Results cleared".to_string();
    }

    /// Get a summary of the last analysis.
    pub fn analysis_summary(&self) -> MlAnalysisSummary {
        let total = self.last_results.len();
        let function_starts = self.last_function_start_count();
        let non_starts = total - function_starts;

        let avg_probability = if total > 0 {
            self.last_results
                .iter()
                .map(|r| r.probability)
                .sum::<f64>()
                / total as f64
        } else {
            0.0
        };

        let max_probability = self
            .last_results
            .iter()
            .map(|r| r.probability)
            .fold(0.0f64, f64::max);

        MlAnalysisSummary {
            total_addresses: total,
            function_starts,
            non_starts,
            avg_probability,
            max_probability,
            threshold: self.config.threshold,
            num_trees: self.model.num_trees(),
        }
    }

    /// Dispose of the plugin.
    pub fn dispose(&mut self) {
        self.enabled = false;
        self.last_results.clear();
        self.status = "Disposed".to_string();
    }
}

impl Default for MlPlugin {
    fn default() -> Self {
        Self::new(RandomForestModel::new(vec![]))
    }
}

impl std::fmt::Debug for MlPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlPlugin")
            .field("enabled", &self.enabled)
            .field("threshold", &self.config.threshold)
            .field("num_trees", &self.model.num_trees())
            .field("last_results_count", &self.last_results.len())
            .field("status", &self.status)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// MlAnalysisSummary
// ---------------------------------------------------------------------------

/// Summary of an ML analysis run.
#[derive(Debug, Clone)]
pub struct MlAnalysisSummary {
    /// Total number of addresses analyzed.
    pub total_addresses: usize,
    /// Number of addresses classified as function starts.
    pub function_starts: usize,
    /// Number of addresses classified as non-starts.
    pub non_starts: usize,
    /// Average probability across all addresses.
    pub avg_probability: f64,
    /// Maximum probability observed.
    pub max_probability: f64,
    /// The threshold used for classification.
    pub threshold: f64,
    /// Number of trees in the ensemble.
    pub num_trees: usize,
}

impl std::fmt::Display for MlAnalysisSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ML Analysis: {} addresses, {} function starts, {} non-starts \
             (threshold={:.2}, trees={}, avg_prob={:.4}, max_prob={:.4})",
            self.total_addresses,
            self.function_starts,
            self.non_starts,
            self.threshold,
            self.num_trees,
            self.avg_probability,
            self.max_probability,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine_learning::training::DecisionTree;

    fn make_model() -> RandomForestModel {
        let tree = DecisionTree::new(0, 128.0, true, false);
        RandomForestModel::new(vec![tree])
    }

    #[test]
    fn test_plugin_creation() {
        let plugin = MlPlugin::new(make_model());
        assert!(plugin.is_enabled());
        assert_eq!(plugin.status(), "Ready");
        assert!(plugin.last_results().is_empty());
    }

    #[test]
    fn test_plugin_from_params() {
        let mut params = FunctionStartRfParams::new(4);
        params.set_pre_bytes(vec![8]);
        params.set_initial_bytes(vec![16]);
        let plugin = MlPlugin::from_params(&params);
        assert!(plugin.is_enabled());
        assert_eq!(plugin.config().num_pre_bytes, 8);
    }

    #[test]
    fn test_plugin_set_model() {
        let mut plugin = MlPlugin::default();
        assert_eq!(plugin.model().num_trees(), 0);
        plugin.set_model(make_model());
        assert_eq!(plugin.model().num_trees(), 1);
        assert_eq!(plugin.status(), "Model loaded");
    }

    #[test]
    fn test_plugin_threshold() {
        let mut plugin = MlPlugin::new(make_model());
        plugin.set_threshold(0.7);
        assert!((plugin.threshold() - 0.7).abs() < 1e-10);
    }

    #[test]
    fn test_plugin_threshold_clamp() {
        let mut plugin = MlPlugin::new(make_model());
        plugin.set_threshold(1.5);
        assert!((plugin.threshold() - 1.0).abs() < 1e-10);

        plugin.set_threshold(-0.5);
        assert!((plugin.threshold() - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_plugin_run_analysis() {
        let mut plugin = MlPlugin::new(make_model());
        let data = vec![50u8; 64]; // 50 < 128 -> function start
        let count = plugin.run_analysis(&data, 0x400000);
        assert!(count > 0);
        assert_eq!(count, plugin.last_function_start_count());
    }

    #[test]
    fn test_plugin_run_analysis_no_model() {
        let mut plugin = MlPlugin::default();
        let data = vec![0u8; 64];
        let count = plugin.run_analysis(&data, 0x400000);
        assert_eq!(count, 0);
        assert_eq!(plugin.status(), "No model loaded");
    }

    #[test]
    fn test_plugin_disabled() {
        let mut plugin = MlPlugin::new(make_model());
        plugin.set_enabled(false);
        let data = vec![0u8; 64];
        let count = plugin.run_analysis(&data, 0x400000);
        assert_eq!(count, 0);
        assert_eq!(plugin.status(), "Plugin is disabled");
    }

    #[test]
    fn test_plugin_run_analysis_all() {
        let mut plugin = MlPlugin::new(make_model());
        let data = vec![0u8; 32];
        let count = plugin.run_analysis_all(&data, 0x1000);
        assert_eq!(count, 32);
    }

    #[test]
    fn test_plugin_clear_results() {
        let mut plugin = MlPlugin::new(make_model());
        let data = vec![0u8; 32];
        plugin.run_analysis(&data, 0x1000);
        assert!(!plugin.last_results().is_empty());
        plugin.clear_results();
        assert!(plugin.last_results().is_empty());
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = MlPlugin::new(make_model());
        plugin.dispose();
        assert!(!plugin.is_enabled());
        assert!(plugin.last_results().is_empty());
    }

    #[test]
    fn test_analysis_summary() {
        let mut plugin = MlPlugin::new(make_model());
        let data = vec![0u8; 64];
        plugin.run_analysis_all(&data, 0x1000);
        let summary = plugin.analysis_summary();
        assert_eq!(summary.total_addresses, 64);
        assert_eq!(summary.threshold, 0.5);
        assert_eq!(summary.num_trees, 1);
    }

    #[test]
    fn test_analysis_summary_display() {
        let mut plugin = MlPlugin::new(make_model());
        let data = vec![0u8; 32];
        plugin.run_analysis_all(&data, 0x1000);
        let summary = plugin.analysis_summary();
        let display = format!("{}", summary);
        assert!(display.contains("ML Analysis"));
        assert!(display.contains("addresses"));
    }

    #[test]
    fn test_plugin_debug_format() {
        let plugin = MlPlugin::new(make_model());
        let debug = format!("{:?}", plugin);
        assert!(debug.contains("MlPlugin"));
        assert!(debug.contains("enabled"));
    }

    #[test]
    fn test_plugin_config_mut() {
        let mut plugin = MlPlugin::new(make_model());
        plugin.config_mut().alignment = 4;
        assert_eq!(plugin.config().alignment, 4);
    }
}
