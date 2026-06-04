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
//! - [`PcodeByteBasedConstantPropagation`] -- Byte-level constant propagation.
//! - [`PcodeDataflowConstantPropagation`] -- Dataflow constant propagation.
//!
//! ## Lattice
//!
//! - [`Lattice`] -- Core lattice trait for abstract domains.
//!
//! # Licensing
//!
//! The Lisa extension is licensed under the MIT License (see the original
//! Java source).

pub mod analyses;
pub mod lattice;

pub use analyses::PcodeDataflowConstantPropagation;
pub use analyses::PcodeInterval;
pub use analyses::PcodeParity;
pub use analyses::PcodeSign;
pub use analyses::PcodeTaint;
pub use analyses::PcodeThreeLevelTaint;
pub use lattice::{LatticeElement, Satisfiability};
