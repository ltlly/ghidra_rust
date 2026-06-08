//! Default AddressSnap implementation.

/// Default AddressSnap implementation.
#[derive(Debug, Clone)]
pub struct DefaultAddressSnap {
    /// address
    pub address: u64,
    /// snap
    pub snap: i64,
}

impl DefaultAddressSnap {
    /// Create a new DefaultAddressSnap.
    pub fn new(address: u64, snap: i64) -> Self {
        Self { address, snap }
    }

    /// address
    pub fn address(&self) -> &u64 {
        &self.address
    }

    /// snap
    pub fn snap(&self) -> &i64 {
        &self.snap
    }
}

impl Default for DefaultAddressSnap {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let _obj = DefaultAddressSnap::new(0, 0);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DefaultAddressSnap::default();
    }
}
