//! TraceRmiService progress implementation.
//!
//! Ported from TraceRmiService.java.

/// Status of a remote method invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RmiStatus {
    /// Invocation is pending.
    Pending,
    /// Invocation is in progress.
    InProgress,
    /// Invocation completed successfully.
    Success,
    /// Invocation failed.
    Failed,
    /// Invocation was cancelled.
    Cancelled,
}

/// A progress entry for an RMI operation.
#[derive(Debug, Clone)]
pub struct RmiProgressEntry {
    /// The method name.
    pub method: String,
    /// Current status.
    pub status: RmiStatus,
    /// Progress message.
    pub message: String,
    /// Progress fraction (0.0 - 1.0).
    pub progress: f64,
}

impl RmiProgressEntry {
    /// Create a new progress entry.
    pub fn new(method: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            status: RmiStatus::Pending,
            message: String::new(),
            progress: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rmi_progress() {
        let mut entry = RmiProgressEntry::new("launch");
        assert_eq!(entry.status, RmiStatus::Pending);
        entry.status = RmiStatus::InProgress;
        entry.progress = 0.5;
        assert_eq!(entry.status, RmiStatus::InProgress);
    }
}
