//! Thread access for P-code trace execution.

/// Thread access for P-code trace execution.
#[derive(Debug, Clone)]
pub struct PcodeTraceThreadAccess {
    /// snap
    pub snap: i64,
}

impl PcodeTraceThreadAccess {
    /// Create a new PcodeTraceThreadAccess.
    pub fn new(snap: i64) -> Self {
        Self { snap }
    }

    /// snap
    pub fn snap(&self) -> &i64 {
        &self.snap
    }
}

impl Default for PcodeTraceThreadAccess {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = PcodeTraceThreadAccess::new(0);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = PcodeTraceThreadAccess::default();
    }
}
