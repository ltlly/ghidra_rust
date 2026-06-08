//! Default TraceLocation implementation.

/// Default TraceLocation implementation.
#[derive(Debug, Clone)]
pub struct DefaultTraceLocation {
    /// address
    pub address: u64,
    /// snap
    pub snap: i64,
    /// thread_key
    pub thread_key: Option<String>,
}

impl DefaultTraceLocation {
    /// Create a new DefaultTraceLocation.
    pub fn new(address: u64, snap: i64, thread_key: Option<String>) -> Self {
        Self { address, snap, thread_key }
    }

    /// address
    pub fn address(&self) -> &u64 {
        &self.address
    }

    /// snap
    pub fn snap(&self) -> &i64 {
        &self.snap
    }

    /// thread_key
    pub fn thread_key(&self) -> Option<&str> {
        self.thread_key.as_deref()
    }
}

impl Default for DefaultTraceLocation {
    fn default() -> Self {
        Self::new(Default::default(), Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let _obj = DefaultTraceLocation::new(0, 0, None);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DefaultTraceLocation::default();
    }
}
