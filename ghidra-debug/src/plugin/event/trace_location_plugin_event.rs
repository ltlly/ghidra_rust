//! Trace location event.

/// Trace location event.
#[derive(Debug, Clone)]
pub struct TraceLocationPluginEvent {
    /// address
    pub address: u64,
    /// snap
    pub snap: i64,
}

impl TraceLocationPluginEvent {
    /// Create a new TraceLocationPluginEvent.
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

impl Default for TraceLocationPluginEvent {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = TraceLocationPluginEvent::new(0, 0);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = TraceLocationPluginEvent::default();
    }
}
