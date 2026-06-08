//! Code comparison framework.
//!
//! Ported from Ghidra's `ghidra.features.codecompare` Java package.
//!
//! This module provides functionality for comparing decompiled code
//! between two functions, potentially from different programs or even
//! different architectures. It includes:
//!
//! - [`correlator`] -- cross-architecture address correlation
//! - [`graphanalysis`] -- Pinning algorithm for token-based code matching
//! - [`decompile`] -- decompiler output comparison and difference highlighting
//! - [`functiongraph`] -- function graph (CFG) comparison view with side-by-side display
//! - [`model`] -- function comparison model (selecting which functions to compare)
//! - [`panel`] -- comparison data abstractions and panel state management
//! - [`listing`] -- listing-level code comparison with diff highlighting

pub mod correlator;
pub mod decompile;
pub mod functiongraph;
pub mod graphanalysis;
pub mod listing;
pub mod model;
pub mod panel;
