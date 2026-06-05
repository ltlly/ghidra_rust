//! BSim query engine: database abstraction, backends, and query types.
//!
//! Ports `ghidra.features.bsim.query` from Ghidra's Java source.

pub mod bsim_initializer;
pub mod bsim_plugin_package;
pub mod bsim_search_service;
pub mod bsim_server_info;
pub mod client;
pub mod client_sql;
pub mod compare_signatures;
pub mod decompile_function_task;
pub mod description;
pub mod elastic;
pub mod facade;
pub mod file;
pub mod function_database;
pub mod gen_signatures;
pub mod ingest;
pub mod lsh;
pub mod postgresql;
pub mod protocol;
pub mod additional_protocol;
pub mod server_cache;
pub mod server_config;
pub mod sf_query_service;
pub mod tables;

use std::fmt;

/// Error type for BSim query operations.
#[derive(Debug, thiserror::Error)]
pub enum BSimError {
    /// Database connection error.
    #[error("BSim connection error: {0}")]
    ConnectionError(String),
    /// Query execution error.
    #[error("BSim query error: {0}")]
    QueryError(String),
    /// Schema/validation error.
    #[error("BSim schema error: {0}")]
    SchemaError(String),
    /// Serialization/deserialization error.
    #[error("BSim serialization error: {0}")]
    SerializationError(String),
    /// Configuration error.
    #[error("BSim config error: {0}")]
    ConfigError(String),
    /// Not found.
    #[error("BSim not found: {0}")]
    NotFound(String),
    /// Permission denied.
    #[error("BSim permission denied: {0}")]
    PermissionDenied(String),
}

/// Result type for BSim operations.
pub type BSimResult<T> = std::result::Result<T, BSimError>;

/// Minimal error logger interface for BSim operations.
///
/// Ports `ghidra.features.bsim.query.MinimalErrorLogger`.
pub trait ErrorLogger: Send + Sync {
    /// Log an error message.
    fn error(&self, message: &str);
    /// Log a warning message.
    fn warn(&self, message: &str);
    /// Log an info message.
    fn info(&self, message: &str);
}

/// Default stderr-based error logger.
#[derive(Debug, Clone, Default)]
pub struct StderrErrorLogger;

impl ErrorLogger for StderrErrorLogger {
    fn error(&self, message: &str) {
        log::error!("BSim: {}", message);
    }
    fn warn(&self, message: &str) {
        log::warn!("BSim: {}", message);
    }
    fn info(&self, message: &str) {
        log::info!("BSim: {}", message);
    }
}
