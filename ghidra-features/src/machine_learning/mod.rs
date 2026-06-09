//! Machine Learning -- Random Forest function finding.
//!
//! This module ports the MachineLearning extension from Ghidra's Java source.
//! It provides a random forest based classifier for identifying function start
//! addresses in binary programs.
//!
//! # Architecture
//!
//! - [`Interpretation`] -- Enum for classifying addresses as function starts,
//!   data, undefined, etc.
//!
//! - [`FunctionStartRfParams`] -- Configuration parameters for the random forest
//!   training process (pre-bytes, initial-bytes, sampling factors, etc.).
//!
//! - [`TrainingAndTestData`] -- Container for training and testing address sets.
//!
//! - [`RandomSubsetUtils`] -- Utilities for generating random subsets of
//!   address sets (Fisher-Yates permutation).
//!
//! - [`FunctionStartClassifier`] -- Classifies addresses using a trained
//!   random forest ensemble model.
//!
//! - [`EnsembleEvaluatorCallback`] -- Short-circuit evaluator for ensemble
//!   models in parallel classification.
//!
//! - [`ModelTrainingUtils`] -- Utilities for training random forest models,
//!   including parallel tree training and model evaluation.

pub mod address_task;
pub mod callback;
pub mod classifier;
pub mod ensemble;
pub mod interpretation;
pub mod ml_analyzer;
pub mod ml_plugin;
pub mod params;
pub mod random_subset;
pub mod similar_starts;
pub mod training;

pub use address_task::AddressGatherConfig;
pub use callback::FunctionStartCallback;
pub use classifier::FunctionStartClassifier;
pub use ensemble::EnsembleEvaluator;
pub use interpretation::Interpretation;
pub use ml_analyzer::{MlAnalysisConfig, MlAnalysisResult, MlAnalyzer};
pub use ml_plugin::{MlAnalysisSummary, MlPlugin};
pub use params::FunctionStartRfParams;
pub use random_subset::RandomSubsetUtils;
pub use similar_starts::SimilarStartsFinder;
pub use training::{ModelTrainingUtils, TrainingAndTestData};
