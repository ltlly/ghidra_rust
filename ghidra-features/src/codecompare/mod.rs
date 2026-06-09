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
//!
//! # Top-level integration modules
//!
//! - [`address_correlation`] -- unified address correlation utilities and composite correlator
//! - [`code_comparison_panel`] -- integration layer connecting panel state to views
//! - [`code_comparison_view`] -- view registry and lifecycle management
//! - [`decompiler_code_comparison_panel`] -- decompiler-specific comparison panel
//! - [`listing_address_correlation`] -- listing-specific address correlation
//! - [`listing_code_comparison_panel`] -- listing-specific comparison panel

pub mod address_correlation;
pub mod code_comparison_panel;
pub mod code_comparison_view;
pub mod correlator;
pub mod decompile;
pub mod decompiler_code_comparison_panel;
pub mod functiongraph;
pub mod graphanalysis;
pub mod listing;
pub mod listing_address_correlation;
pub mod listing_code_comparison_panel;
pub mod model;
pub mod panel;
