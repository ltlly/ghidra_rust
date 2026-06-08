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

pub mod analysis_priority;
pub mod analyzer;
pub mod auto_analysis_manager;
