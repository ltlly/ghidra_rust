//! LISA -- Lightweight Instruction Set Analysis.
//!
//! This module ports the Lisa extension from Ghidra's Java source. It
//! provides abstract interpretation frameworks for p-code based dataflow
//! analysis.
//!
//! # Architecture
//!
//! ## Abstract Domains (in `analyses`)
//!
//! - [`PcodeTaint`] -- Two-level taint analysis (clean / tainted).
//! - [`PcodeThreeLevelTaint`] -- Three-level taint analysis (clean /
//!   untainted / tainted).
//! - [`PcodeSign`] -- Sign abstract domain (positive / negative / zero).
//! - [`PcodeParity`] -- Parity abstract domain (even / odd).
//! - [`PcodeInterval`] -- Interval abstract domain with widening/narrowing.
//! - [`PcodeStability`] -- Stability domain (stable / unstable).
//! - [`PcodeUpperBounds`] -- Upper bounds domain.
//! - [`Pentagon`] -- Pentagon domain combining interval + parity + sign + relations.
//! - [`PcodeByteBasedConstantPropagation`] -- Byte-level constant propagation.
//! - [`PcodeNonRelationalValue`] -- Combined non-relational value domain.
//! - [`PcodePowersetInterval`] -- Non-redundant powerset of intervals.
//! - [`PcodeDataflowConstantPropagation`] -- Dataflow constant propagation.
//!
//! ## Lattice
//!
//! - [`LatticeElement`] -- Core lattice trait for abstract domains.
//!
//! ## P-code Infrastructure
//!
//! - [`PcodeFrontend`] -- Translates machine instructions to p-code ops.
//! - [`PcodeFeatures`] -- Tracks opcodes/features present in analyzed code.
//! - [`PcodeBranch`] -- Represents control flow branches.
//! - [`WorkItem`] -- Work items for fixpoint iteration.
//!
//! ## Contexts, Expressions, Statements, Locations, Types
//!
//! See the respective submodules for p-code IR types.
//!
//! # Licensing
//!
//! The Lisa extension is licensed under the MIT License (see the original
//! Java source).

pub mod analyses;
pub mod lattice;
pub mod contexts;
pub mod expressions;
pub mod statements;
pub mod locations;
pub mod types;
pub mod pcode_frontend;
pub mod pcode_features;
pub mod pcode_branch;
pub mod pcode_code_member_visitor;
pub mod work_item;
pub mod lisa_analyzer;
pub mod lisa_plugin;

pub use analyses::PcodeDataflowConstantPropagation;
pub use analyses::PcodeInterval;
pub use analyses::PcodeParity;
pub use analyses::PcodeSign;
pub use analyses::PcodeTaint;
pub use analyses::PcodeThreeLevelTaint;
pub use analyses::PcodeStability;
pub use analyses::PcodeUpperBounds;
pub use analyses::Pentagon;
pub use analyses::PcodeByteBasedConstantPropagation;
pub use analyses::PcodeNonRelationalValue;
pub use analyses::PcodePowersetInterval;
pub use lattice::{LatticeElement, Satisfiability};
pub use pcode_frontend::{PcodeFrontend, PcodeOp};
pub use pcode_features::PcodeFeatures;
pub use pcode_branch::{PcodeBranch, BranchKind};
pub use work_item::WorkItem;
pub use lisa_analyzer::{
    AnalysisConfig, AnalysisResult, HeapDomainOption, InterproceduralOption,
    LisaAnalyzer, MarkType, StatementState, TaintMarker, TypeDomainOption, ValueDomainOption,
};
pub use lisa_plugin::{
    AddCfgsAction, ClearCfgsAction, FunctionInfo, LisaPlugin, LisaPluginOptions, PluginEvent,
    SetTaintAction,
};
