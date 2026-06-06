//! BSim wire protocol types.
//!
//! Ports `ghidra.features.bsim.query.protocol` from Ghidra's Java source.
//!
//! This module re-exports all protocol types from the core module and provides
//! per-class standalone modules matching the Java package structure.

// Core protocol types (all original definitions live here)
mod core;

// Standalone per-class modules -- re-export from core for 1:1 Java parity
pub mod adjust_vector_index;
pub mod child_atom;
pub mod cluster_note;
pub mod create_database;
pub mod drop_database;
pub mod exe_specifier;
pub mod executable_result_with_de_duping;
pub mod filter_atom;
pub mod function_entry;
pub mod function_staging;
pub mod id_sql_resolution;
pub mod insert_optional_values;
pub mod insert_request;
pub mod null_staging;
pub mod pair_input;
pub mod pair_note;
pub mod password_change;
pub mod pre_filter;
pub mod query_children;
pub mod query_cluster;
pub mod query_delete;
pub mod query_info;
pub mod query_name;
pub mod query_nearest;
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
