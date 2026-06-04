//! BSim Elasticsearch Plugin - LSH analysis for Elasticsearch.
//!
//! This module ports the BSimElasticPlugin extension from Ghidra's Java source.
//! It provides Locality-Sensitive Hashing (LSH) based tokenization and scoring
//! for indexing BSim function signatures in Elasticsearch.
//!
//! # Architecture
//!
//! - [`LshBinner`] -- Computes bin IDs for LSH vectors using FFT-based random
//!   projection with 16-wide dot products.
//!
//! - [`LshTokenizer`] -- Tokenizes LSH vectors into base64-encoded bin-ID
//!   strings for Elasticsearch indexing.
//!
//! - [`LshTokenizerFactory`] -- Creates [`LshTokenizer`] instances from
//!   Elasticsearch index settings.
//!
//! - [`AnalysisLshPlugin`] -- The top-level plugin that registers tokenizers
//!   and script engines with Elasticsearch.
//!
//! - [`BSimScriptEngine`] -- Elasticsearch script engine for computing BSim
//!   similarity scores at query time.
//!
//! - [`VectorCompareScriptFactory`] -- Factory for the vector comparison script
//!   that computes cosine similarity between stored and query vectors.

pub mod binner;
pub mod plugin;
pub mod script_engine;
pub mod tokenizer;
pub mod tokenizer_factory;

pub use binner::{BytesRef, LshBinner};
pub use plugin::AnalysisLshPlugin;
pub use script_engine::{BSimScriptEngine, VectorCompareScriptFactory};
pub use tokenizer::LshTokenizer;
pub use tokenizer_factory::LshTokenizerFactory;
