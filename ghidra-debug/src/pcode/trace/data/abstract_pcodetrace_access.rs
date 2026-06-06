//! Abstract base for P-code trace access.

/// Abstract base for P-code trace access.
#[derive(Debug, Clone)]
pub struct AbstractPcodeTraceAccess {
    /// snap
    pub snap: i64,
}

impl AbstractPcodeTraceAccess {
    /// Create a new AbstractPcodeTraceAccess.
    pub fn new(snap: i64) -> Self {
        Self { snap }
    }

    /// snap
    pub fn snap(&self) -> &i64 {
        &self.snap
    }
}

impl Default for AbstractPcodeTraceAccess {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = AbstractPcodeTraceAccess::new(0);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = AbstractPcodeTraceAccess::default();
    }
}
