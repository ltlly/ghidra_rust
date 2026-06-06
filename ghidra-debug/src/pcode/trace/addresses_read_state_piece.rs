//! Tracks addresses read during P-code execution.

/// Tracks addresses read during P-code execution.
#[derive(Debug, Clone)]
pub struct AddressesReadTracePcodeExecutorStatePiece {
    /// snap
    pub snap: i64,
    /// address_count
    pub address_count: usize,
}

impl AddressesReadTracePcodeExecutorStatePiece {
    /// Create a new AddressesReadTracePcodeExecutorStatePiece.
    pub fn new(snap: i64, address_count: usize) -> Self {
        Self { snap, address_count }
    }

    /// snap
    pub fn snap(&self) -> &i64 {
        &self.snap
    }

    /// address_count
    pub fn address_count(&self) -> &usize {
        &self.address_count
    }
}

impl Default for AddressesReadTracePcodeExecutorStatePiece {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = AddressesReadTracePcodeExecutorStatePiece::new(0, 4);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = AddressesReadTracePcodeExecutorStatePiece::default();
    }
}
