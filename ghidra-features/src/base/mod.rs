//! Ghidra Rust - Base analysis features.
//!
//! This module contains the auto-analysis framework ported from
//! `ghidra.app.plugin.core.analysis` and `ghidra.app.services`.
//!
//! It provides:
//! - The [`Analyzer`] trait for implementing automatic analysis passes
//! - [`AutoAnalysisManager`] for orchestrating analyzer execution
//! - Built-in analyzers (function start, code boundary, references, etc.)
//! - [`memory`] — memory map management (add, expand, move, split, merge blocks)
//! - [`register`] — register value management (tree, value ranges, set/clear commands)

pub mod analyzer;
pub mod assembler;
pub mod bookmark;
pub mod clear;
pub mod equate;
pub mod function;
pub mod label;
pub mod memory;
pub mod merge;
pub mod operand;
pub mod register;
pub mod rename;
pub mod symbol;
