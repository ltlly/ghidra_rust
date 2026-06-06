//! Data access for P-code trace execution.

/// Data access for P-code trace execution.
#[derive(Debug, Clone)]
pub struct PcodeTraceDataAccess {
    /// snap
    pub snap: i64,
}

impl PcodeTraceDataAccess {
    /// Create a new PcodeTraceDataAccess.
    pub fn new(snap: i64) -> Self {
        Self { snap }
    }

    /// snap
    pub fn snap(&self) -> &i64 {
        &self.snap
    }
}

impl Default for PcodeTraceDataAccess {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = PcodeTraceDataAccess::new(0);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = PcodeTraceDataAccess::default();
    }
}
