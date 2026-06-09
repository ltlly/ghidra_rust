//! Analysis framework for Features/Base.
//!
//! Ported from Ghidra's `ghidra.framework.analysis` and
//! `ghidra.app.analyzers` Java packages.
//!
//! This module provides the core auto-analysis infrastructure:
//!
//! - [`analyzer`] -- the [`Analyzer`] trait and built-in analyzer implementations
//! - [`analysis_priority`] -- priority levels for scheduling analyzers
//! - [`auto_analysis_manager`] -- the [`AutoAnalysisManager`] that orchestrates analysis
//! - [`reference_analyzer`] -- creates cross-references from instruction operands
//! - [`xref_analyzer`] -- builds and reconciles cross-reference tables
//! - [`function_analyzer`] -- discovers function boundaries via flow analysis
//! - [`data_analyzer`] -- creates data definitions in undefined memory
//! - [`string_analyzer`] -- detects and creates string data definitions
//! - [`demangler_analyzer`] -- demangles C++/Rust/Java symbol names
//! - [`pseudo_disassembler`] -- speculative disassembler for analysis passes

pub mod analysis_priority;
pub mod analyzer;
pub mod auto_analysis_manager;
pub mod data_analyzer;
pub mod demangler_analyzer;
pub mod function_analyzer;
pub mod pseudo_disassembler;
pub mod reference_analyzer;
pub mod string_analyzer;
pub mod xref_analyzer;
