use thiserror::Error;

/// Result type alias for Ghidra operations.
pub type Result<T> = std::result::Result<T, GhidraError>;

/// Top-level error type for all ghidra-core operations.
#[derive(Error, Debug)]
pub enum GhidraError {
    #[error("Address error: {0}")]
    AddressError(String),
    #[error("Memory error: {0}")]
    MemoryError(String),
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Analysis error: {0}")]
    AnalysisError(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Not supported: {0}")]
    NotSupported(String),
    #[error("Invalid data: {0}")]
    InvalidData(String),
    #[error("File format error: {0}")]
    FileFormatError(String),
    #[error("Decompiler error: {0}")]
    DecompilerError(String),
    #[error("Invalid state: {0}")]
    InvalidState(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
