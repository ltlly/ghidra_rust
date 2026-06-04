//! Error types for Version Tracking.

use ghidra_core::addr::Address;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VtError {
    #[error("source program is not set")]
    MissingSourceProgram,
    #[error("destination program is not set")]
    MissingDestProgram,
    #[error("correlator '{correlator}' failed: {message}")]
    CorrelatorError { correlator: String, message: String },
    #[error("match target not found at address {address}")]
    MatchTargetNotFound { address: Address },
    #[error("association status error: {message}")]
    AssociationStatusError { message: String },
    #[error("failed to apply markup item: {message}")]
    ApplyError { message: String },
    #[error("session error: {message}")]
    SessionError { message: String },
    #[error("database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type VtResult<T> = std::result::Result<T, VtError>;
pub type VersionTrackingApplyError = VtError;
pub type VtAssociationStatusError = VtError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlator_error_display() {
        let err = VtError::CorrelatorError { correlator: "ExactMatch".to_string(), message: "no functions found".to_string() };
        assert!(format!("{}", err).contains("ExactMatch"));
    }

    #[test]
    fn test_association_status_error_display() {
        let err = VtError::AssociationStatusError { message: "cannot accept blocked".to_string() };
        assert!(format!("{}", err).contains("association status error"));
    }
}
