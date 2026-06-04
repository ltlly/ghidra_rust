//! Ghidra Rust - Base analysis features.
//!
//! This module contains the auto-analysis framework ported from
//! `ghidra.app.plugin.core.analysis` and `ghidra.app.services`.
//!
//! It provides:
//! - The [`Analyzer`] trait for implementing automatic analysis passes
//! - [`AutoAnalysisManager`] for orchestrating analyzer execution
//! - Built-in analyzers (function start, code boundary, references, etc.)

pub mod analyzer;
pub mod assembler;
pub mod merge;
