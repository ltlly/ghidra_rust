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

pub mod correlator;
pub mod decompile;
pub mod graphanalysis;
