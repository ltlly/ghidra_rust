//! Abstract base for P-code trace data access.

/// Abstract base for P-code trace data access.
#[derive(Debug, Clone)]
pub struct AbstractPcodeTraceDataAccess {
    /// snap
    pub snap: i64,
}

impl AbstractPcodeTraceDataAccess {
    /// Create a new AbstractPcodeTraceDataAccess.
    pub fn new(snap: i64) -> Self {
        Self { snap }
    }

    /// snap
    pub fn snap(&self) -> &i64 {
        &self.snap
    }
}

impl Default for AbstractPcodeTraceDataAccess {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = AbstractPcodeTraceDataAccess::new(0);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = AbstractPcodeTraceDataAccess::default();
    }
}
