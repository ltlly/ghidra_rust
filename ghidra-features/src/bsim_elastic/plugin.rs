//! BSim Analysis LSH Plugin -- registers tokenizers and script engines.
//!
//! Ported from `AnalysisLSHPlugin.java` in the BSimElasticPlugin extension.
//!
//! This plugin integrates with an Elasticsearch-like indexing system to provide
//! LSH-based tokenizer registration and vector factory management.

use std::collections::HashMap;
use std::sync::{Mutex, LazyLock};

/// The settings prefix for LSH tokenizer configuration.
pub const TOKENIZER_SETTINGS_BASE: &str = "index.analysis.tokenizer.lsh_";

/// Setting key for the IDF configuration.
pub const IDF_CONFIG: &str = "idf_config";

/// Setting key for the LSH weights.
pub const LSH_WEIGHTS: &str = "lsh_weights";

// ---------------------------------------------------------------------------
// WeightFactory / IDFLookup / Base64VectorFactory (simplified)
// ---------------------------------------------------------------------------

/// Holds per-dimension weights for LSH vector computation.
#[derive(Debug, Clone)]
pub struct WeightFactory {
    /// The weight array.
    weights: Vec<f64>,
}

impl WeightFactory {
    /// Create an empty weight factory.
    pub fn new() -> Self {
        Self { weights: Vec::new() }
    }

    /// Set weights from a slice.
    pub fn set(&mut self, weights: &[f64]) {
        self.weights = weights.to_vec();
    }

    /// Get the weight for a given dimension.
    pub fn get(&self, index: usize) -> f64 {
        self.weights.get(index).copied().unwrap_or(0.0)
    }

    /// Number of weights.
    pub fn len(&self) -> usize {
        self.weights.len()
    }

    /// Whether the weight factory is empty.
    pub fn is_empty(&self) -> bool {
        self.weights.is_empty()
    }
}

impl Default for WeightFactory {
    fn default() -> Self {
        Self::new()
    }
}

/// Inverse document frequency lookup table.
#[derive(Debug, Clone)]
pub struct IdfLookup {
    /// The IDF values per dimension.
    values: Vec<i32>,
}

impl IdfLookup {
    /// Create an empty IDF lookup.
    pub fn new() -> Self {
        Self { values: Vec::new() }
    }

    /// Set the IDF values.
    pub fn set(&mut self, values: &[i32]) {
        self.values = values.to_vec();
    }

    /// Get the IDF value for a dimension.
    pub fn get(&self, index: usize) -> i32 {
        self.values.get(index).copied().unwrap_or(0)
    }

    /// Number of IDF entries.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the lookup is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl Default for IdfLookup {
    fn default() -> Self {
        Self::new()
    }
}

/// A factory for creating Base64-encoded LSH vectors.
///
/// Holds the weight factory, IDF lookup, and configuration needed
/// for signature generation.
#[derive(Debug, Clone)]
pub struct Base64VectorFactory {
    /// Per-dimension weights.
    weight_factory: WeightFactory,
    /// IDF lookup table.
    idf_lookup: IdfLookup,
    /// Number of signature generation settings.
    settings: i32,
}

impl Base64VectorFactory {
    /// Create a new vector factory.
    pub fn new() -> Self {
        Self {
            weight_factory: WeightFactory::new(),
            idf_lookup: IdfLookup::new(),
            settings: 0,
        }
    }

    /// Configure the factory with a weight factory and IDF lookup.
    pub fn set(&mut self, weights: WeightFactory, idf: IdfLookup, settings: i32) {
        self.weight_factory = weights;
        self.idf_lookup = idf;
        self.settings = settings;
    }

    /// Get the weight factory.
    pub fn weight_factory(&self) -> &WeightFactory {
        &self.weight_factory
    }

    /// Get the IDF lookup.
    pub fn idf_lookup(&self) -> &IdfLookup {
        &self.idf_lookup
    }
}

impl Default for Base64VectorFactory {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AnalysisLshPlugin
// ---------------------------------------------------------------------------

/// Global vector factory map shared across the plugin.
static VEC_FACTORY_MAP: LazyLock<Mutex<HashMap<String, Base64VectorFactory>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The BSim Analysis LSH Plugin.
///
/// Registers an LSH tokenizer and a BSim script engine with an
/// Elasticsearch-like indexing system.
pub struct AnalysisLshPlugin {
    /// Map of tokenizer names to their factory providers.
    tokenizer_factories: HashMap<String, String>,
}

impl AnalysisLshPlugin {
    /// Create a new plugin instance.
    pub fn new() -> Self {
        let mut tok_map = HashMap::new();
        tok_map.insert("lsh_tokenizer".to_string(), "TokenizerFactoryProvider".to_string());
        Self {
            tokenizer_factories: tok_map,
        }
    }

    /// Get the list of registered tokenizer names.
    pub fn tokenizer_names(&self) -> Vec<&str> {
        self.tokenizer_factories.keys().map(|s| s.as_str()).collect()
    }

    /// Set up a vector factory from configuration strings.
    ///
    /// `idf_config` and `lsh_weights` are space-separated numeric strings.
    pub fn setup_vector_factory(name: &str, idf_config: &str, lsh_weights: &str) {
        let weight_factory = {
            let mut wf = WeightFactory::new();
            let weights: Vec<f64> = lsh_weights
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            wf.set(&weights);
            wf
        };

        let idf_lookup = {
            let mut idf = IdfLookup::new();
            let values: Vec<i32> = idf_config
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            idf.set(&values);
            idf
        };

        let mut vector_factory = Base64VectorFactory::new();
        vector_factory.set(weight_factory, idf_lookup, 0);

        let mut map = VEC_FACTORY_MAP.lock().unwrap();
        map.insert(name.to_string(), vector_factory);
    }

    /// Look up a vector factory by tokenizer name.
    pub fn get_vector_factory(name: &str) -> Option<Base64VectorFactory> {
        let map = VEC_FACTORY_MAP.lock().unwrap();
        map.get(name).cloned()
    }

    /// Process index module settings to discover and configure LSH tokenizers.
    ///
    /// `settings` is a map of setting keys to values. The method looks for
    /// keys starting with `TOKENIZER_SETTINGS_BASE` and extracts the
    /// tokenizer name, IDF config, and LSH weights.
    pub fn on_index_module(&self, settings: &HashMap<String, String>) {
        let mut name: Option<String> = None;

        for key in settings.keys() {
            if key.starts_with(TOKENIZER_SETTINGS_BASE) {
                let rest = &key[TOKENIZER_SETTINGS_BASE.len()..];
                if let Some(pos) = rest.find('.') {
                    name = Some(rest[..pos].to_string());
                    break;
                }
            }
        }

        if let Some(n) = name {
            let tokenizer_name = format!("lsh_{n}");
            if Self::get_vector_factory(&tokenizer_name).is_some() {
                return; // Factory already exists
            }

            let base_key = format!("{TOKENIZER_SETTINGS_BASE}{n}.");
            let idf_config = settings.get(&format!("{base_key}{IDF_CONFIG}"));
            let lsh_weights = settings.get(&format!("{base_key}{LSH_WEIGHTS}"));

            if let (Some(idf), Some(weights)) = (idf_config, lsh_weights) {
                Self::setup_vector_factory(&tokenizer_name, idf, weights);
            }
        }
    }
}

impl Default for AnalysisLshPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weight_factory() {
        let mut wf = WeightFactory::new();
        wf.set(&[1.0, 2.0, 3.0]);
        assert_eq!(wf.len(), 3);
        assert!((wf.get(0) - 1.0).abs() < 1e-10);
        assert!((wf.get(2) - 3.0).abs() < 1e-10);
        assert!((wf.get(99) - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_idf_lookup() {
        let mut idf = IdfLookup::new();
        idf.set(&[10, 20, 30]);
        assert_eq!(idf.len(), 3);
        assert_eq!(idf.get(1), 20);
        assert_eq!(idf.get(99), 0);
    }

    #[test]
    fn test_base64_vector_factory() {
        let mut vf = Base64VectorFactory::new();
        let mut wf = WeightFactory::new();
        wf.set(&[1.0, 2.0]);
        let mut idf = IdfLookup::new();
        idf.set(&[10, 20]);
        vf.set(wf, idf, 0);

        assert_eq!(vf.weight_factory().len(), 2);
        assert_eq!(vf.idf_lookup().len(), 2);
    }

    #[test]
    fn test_plugin_creation() {
        let plugin = AnalysisLshPlugin::new();
        assert!(plugin.tokenizer_names().contains(&"lsh_tokenizer"));
    }

    #[test]
    fn test_setup_and_get_vector_factory() {
        let name = "test_lsh_factory";
        AnalysisLshPlugin::setup_vector_factory(name, "10 20 30", "1.0 2.0 3.0");

        let vf = AnalysisLshPlugin::get_vector_factory(name).unwrap();
        assert_eq!(vf.weight_factory().len(), 3);
        assert_eq!(vf.idf_lookup().len(), 3);
        assert!((vf.weight_factory().get(0) - 1.0).abs() < 1e-10);
        assert_eq!(vf.idf_lookup().get(0), 10);
    }

    #[test]
    fn test_on_index_module_discovers_settings() {
        let plugin = AnalysisLshPlugin::new();
        let mut settings = HashMap::new();
        settings.insert(
            format!("{TOKENIZER_SETTINGS_BASE}myindex.idf_config"),
            "5 10 15".to_string(),
        );
        settings.insert(
            format!("{TOKENIZER_SETTINGS_BASE}myindex.lsh_weights"),
            "0.5 1.0 1.5".to_string(),
        );

        plugin.on_index_module(&settings);

        let vf = AnalysisLshPlugin::get_vector_factory("lsh_myindex").unwrap();
        assert_eq!(vf.weight_factory().len(), 3);
    }

    #[test]
    fn test_on_index_module_missing_settings_is_noop() {
        let plugin = AnalysisLshPlugin::new();
        let mut settings = HashMap::new();
        settings.insert(
            format!("{TOKENIZER_SETTINGS_BASE}other.x"),
            "value".to_string(),
        );
        // Should not panic
        plugin.on_index_module(&settings);
    }

    #[test]
    fn test_constants() {
        assert!(TOKENIZER_SETTINGS_BASE.starts_with("index.analysis."));
        assert_eq!(IDF_CONFIG, "idf_config");
        assert_eq!(LSH_WEIGHTS, "lsh_weights");
    }
}
