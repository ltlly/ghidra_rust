//! BSim wire protocol types.
//!
//! Ports `ghidra.features.bsim.query.protocol` from Ghidra's Java source.
//!
//! This module re-exports all protocol types from the core module and provides
//! per-class standalone modules matching the Java package structure.

// Core protocol types (all original definitions live here)
mod core;

// Standalone per-class modules -- re-export from core for 1:1 Java parity
pub mod child_atom;
pub mod create_database;
pub mod exe_specifier;
pub mod filter_atom;
pub mod function_entry;
pub mod function_staging;
pub mod null_staging;
pub mod pair_input;
pub mod pre_filter;
pub mod query_cluster;
pub mod query_pair;
pub mod query_response_record;
pub mod response_nearest;
pub mod response_prewarm;
pub mod similarity_note;
pub mod similarity_result;
pub mod similarity_vector_result;
pub mod staging_manager;
pub mod vector_result;

// Re-export everything from core for backward compatibility
pub use core::*;
