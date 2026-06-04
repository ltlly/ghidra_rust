//! LSH Tokenizer Factory -- creates tokenizers from Elasticsearch settings.
//!
//! Ported from `LSHTokenizerFactory.java` in the BSimElasticPlugin extension.
//!
//! The factory reads `k` and `L` parameters from index settings and
//! creates configured [`LshTokenizer`] instances.

use super::tokenizer::LshTokenizer;
use std::collections::HashMap;

/// Setting key for the number of hash bits (`k`).
pub const K_SETTING: &str = "k";
/// Setting key for the number of hash tables (`L`).
pub const L_SETTING: &str = "L";

/// Factory for creating [`LshTokenizer`] instances from index settings.
///
/// Reads `k` (number of hash bits per bin) and `L` (number of hash tables)
/// from the Elasticsearch index settings and creates appropriately
/// configured tokenizers.
///
/// # Example
///
/// ```
/// use ghidra_features::bsim_elastic::tokenizer_factory::LshTokenizerFactory;
/// use std::collections::HashMap;
///
/// let mut settings = HashMap::new();
/// settings.insert("k".to_string(), "4".to_string());
/// settings.insert("L".to_string(), "8".to_string());
///
/// let factory = LshTokenizerFactory::new("my_tokenizer", &settings);
/// let tokenizer = factory.create();
/// ```
#[derive(Debug, Clone)]
pub struct LshTokenizerFactory {
    /// The name of this tokenizer.
    name: String,
    /// Number of hash bits per bin.
    k: i32,
    /// Number of hash tables.
    l: i32,
}

impl LshTokenizerFactory {
    /// Create a new factory from index settings.
    ///
    /// Looks for `k` and `L` integer settings. If not found, defaults to -1.
    pub fn new(name: impl Into<String>, settings: &HashMap<String, String>) -> Self {
        let name = name.into();
        let k = settings
            .get(K_SETTING)
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(-1);
        let l = settings
            .get(L_SETTING)
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(-1);
        Self { name, k, l }
    }

    /// Create a new factory with explicit `k` and `L` values.
    pub fn with_params(name: impl Into<String>, k: i32, l: i32) -> Self {
        Self {
            name: name.into(),
            k,
            l,
        }
    }

    /// Get the factory name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the `k` parameter.
    pub fn k(&self) -> i32 {
        self.k
    }

    /// Get the `L` parameter.
    pub fn l(&self) -> i32 {
        self.l
    }

    /// Create a new [`LshTokenizer`] configured with this factory's `k` and `L`.
    pub fn create(&self) -> LshTokenizer {
        LshTokenizer::new(self.k, self.l)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_factory_from_settings() {
        let mut settings = HashMap::new();
        settings.insert("k".to_string(), "6".to_string());
        settings.insert("L".to_string(), "12".to_string());

        let factory = LshTokenizerFactory::new("test", &settings);
        assert_eq!(factory.k(), 6);
        assert_eq!(factory.l(), 12);
        assert_eq!(factory.name(), "test");
    }

    #[test]
    fn test_factory_missing_settings() {
        let settings = HashMap::new();
        let factory = LshTokenizerFactory::new("default", &settings);
        assert_eq!(factory.k(), -1);
        assert_eq!(factory.l(), -1);
    }

    #[test]
    fn test_factory_invalid_settings() {
        let mut settings = HashMap::new();
        settings.insert("k".to_string(), "not_a_number".to_string());
        settings.insert("L".to_string(), "8".to_string());

        let factory = LshTokenizerFactory::new("bad", &settings);
        assert_eq!(factory.k(), -1);
        assert_eq!(factory.l(), 8);
    }

    #[test]
    fn test_factory_with_params() {
        let factory = LshTokenizerFactory::with_params("explicit", 4, 16);
        assert_eq!(factory.k(), 4);
        assert_eq!(factory.l(), 16);
    }

    #[test]
    fn test_factory_create_tokenizer() {
        let factory = LshTokenizerFactory::with_params("tok", 4, 8);
        let mut tokenizer = factory.create();
        // Verify the tokenizer was created (check it's not initialized yet)
        // num_tokens returns 0 before set_vector is called on the binner
        // since k=-1 before setKandL in Java, but we use explicit params here
        assert!(!tokenizer.next_token().is_some());
    }

    #[test]
    fn test_factory_clone() {
        let factory = LshTokenizerFactory::with_params("cloned", 3, 6);
        let clone = factory.clone();
        assert_eq!(clone.name(), "cloned");
        assert_eq!(clone.k(), 3);
        assert_eq!(clone.l(), 6);
    }
}
