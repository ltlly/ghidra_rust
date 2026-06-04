//! Error types for the merge subsystem.

use thiserror::Error;

/// Error thrown when an error occurs when attempting to merge two data types.
///
/// Port of Ghidra's `DataTypeMergeException`.
#[derive(Debug, Clone, Error)]
#[error("DataTypeMergeException: {message}")]
pub struct DataTypeMergeError {
    /// The human-readable error message.
    pub message: String,
}

impl DataTypeMergeError {
    /// Create a new merge error with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// General error type for merge operations.
#[derive(Debug, Error)]
pub enum MergeError {
    /// A data type merge conflict occurred.
    #[error("data type merge conflict: {0}")]
    DataTypeMerge(#[from] DataTypeMergeError),

    /// The merge was canceled by the user.
    #[error("merge canceled")]
    Canceled,

    /// A conflict was detected that could not be automatically resolved.
    #[error("unresolvable conflict at offset {offset}: {message}")]
    UnresolvableConflict {
        /// The byte offset where the conflict was detected.
        offset: usize,
        /// Description of the conflict.
        message: String,
    },

    /// The merged structures have incompatible sizes.
    #[error("size mismatch: {detail}")]
    SizeMismatch {
        /// Details about the size mismatch.
        detail: String,
    },

    /// A generic merge error.
    #[error("{message}")]
    Other {
        /// The error message.
        message: String,
    },
}

/// Result alias for merge operations.
pub type MergeResult<T> = Result<T, MergeError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_type_merge_error_display() {
        let err = DataTypeMergeError::new("conflict in field 'x'");
        assert_eq!(
            err.to_string(),
            "DataTypeMergeException: conflict in field 'x'"
        );
    }

    #[test]
    fn test_merge_error_canceled() {
        let err = MergeError::Canceled;
        assert_eq!(err.to_string(), "merge canceled");
    }

    #[test]
    fn test_merge_error_from_data_type() {
        let dt_err = DataTypeMergeError::new("test");
        let merge_err: MergeError = dt_err.into();
        assert!(matches!(merge_err, MergeError::DataTypeMerge(_)));
    }
}
