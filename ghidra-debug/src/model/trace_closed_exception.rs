//! TraceClosedException - error when operating on a closed trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.TraceClosedException`.

/// Error returned when an operation is attempted on a closed trace.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Trace is closed: {reason}")]
pub struct TraceClosedException {
    /// The reason the trace is closed.
    pub reason: String,
}

impl TraceClosedException {
    /// Create a new exception.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    /// Default message for a closed trace.
    pub fn default_message() -> Self {
        Self {
            reason: "The trace has been closed".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_closed_exception() {
        let err = TraceClosedException::new("user closed trace");
        assert!(err.to_string().contains("user closed trace"));
    }

    #[test]
    fn test_default_message() {
        let err = TraceClosedException::default_message();
        assert!(err.to_string().contains("closed"));
    }
}
