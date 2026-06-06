//! UnknownStatePcodeExecutionException ported from
//! UnknownStatePcodeExecutionException.java.

/// Error for when pcode encounters memory in an unknown state.
#[derive(Debug, Clone)]
pub struct UnknownStatePcodeExecutionException {
    /// The address that has unknown state.
    pub address: u64,
    /// Error message.
    pub message: String,
}

impl UnknownStatePcodeExecutionException {
    /// Create a new exception for the given address.
    pub fn new(address: u64, message: impl Into<String>) -> Self {
        Self {
            address,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for UnknownStatePcodeExecutionException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Unknown state at 0x{:x}: {}", self.address, self.message)
    }
}

impl std::error::Error for UnknownStatePcodeExecutionException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display() {
        let e = UnknownStatePcodeExecutionException::new(0x1000, "no data");
        assert!(format!("{}", e).contains("0x1000"));
    }
}
