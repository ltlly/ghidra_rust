//! Internal P-code trace data access.

/// Internal P-code trace data access.
#[derive(Debug, Clone)]
pub struct InternalPcodeTraceDataAccess {
    /// snap
    pub snap: i64,
    /// initialized
    pub initialized: bool,
}

impl InternalPcodeTraceDataAccess {
    /// Create a new InternalPcodeTraceDataAccess.
    pub fn new(snap: i64, initialized: bool) -> Self {
        Self { snap, initialized }
    }

    /// snap
    pub fn snap(&self) -> &i64 {
        &self.snap
    }

    /// initialized
    pub fn initialized(&self) -> &bool {
        &self.initialized
    }
}

impl Default for InternalPcodeTraceDataAccess {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = InternalPcodeTraceDataAccess::new(0, true);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = InternalPcodeTraceDataAccess::default();
    }
}
