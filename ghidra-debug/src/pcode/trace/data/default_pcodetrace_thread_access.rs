//! Default thread access implementation.

/// Default thread access implementation.
#[derive(Debug, Clone)]
pub struct DefaultPcodeTraceThreadAccess {
    /// snap
    pub snap: i64,
}

impl DefaultPcodeTraceThreadAccess {
    /// Create a new DefaultPcodeTraceThreadAccess.
    pub fn new(snap: i64) -> Self {
        Self { snap }
    }

    /// snap
    pub fn snap(&self) -> &i64 {
        &self.snap
    }
}

impl Default for DefaultPcodeTraceThreadAccess {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = DefaultPcodeTraceThreadAccess::new(0);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DefaultPcodeTraceThreadAccess::default();
    }
}
