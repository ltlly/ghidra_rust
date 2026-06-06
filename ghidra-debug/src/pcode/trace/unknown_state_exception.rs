//! Exception for unknown memory state.

/// Exception for unknown memory state.
#[derive(Debug, Clone)]
pub struct UnknownStatePcodeExecutionException {
    /// address
    pub address: u64,
    /// message
    pub message: String,
}

impl UnknownStatePcodeExecutionException {
    /// Create a new UnknownStatePcodeExecutionException.
    pub fn new(address: u64, message: String) -> Self {
        Self { address, message }
    }

    /// address
    pub fn address(&self) -> &u64 {
        &self.address
    }

    /// message
    pub fn message(&self) -> &String {
        &self.message
    }
}

impl Default for UnknownStatePcodeExecutionException {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = UnknownStatePcodeExecutionException::new(0, "test".to_string());
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = UnknownStatePcodeExecutionException::default();
    }
}
