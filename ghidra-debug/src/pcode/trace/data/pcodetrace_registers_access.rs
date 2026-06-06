//! Register access for P-code trace execution.

/// Register access for P-code trace execution.
#[derive(Debug, Clone)]
pub struct PcodeTraceRegistersAccess {
    /// snap
    pub snap: i64,
    /// thread_key
    pub thread_key: Option<String>,
}

impl PcodeTraceRegistersAccess {
    /// Create a new PcodeTraceRegistersAccess.
    pub fn new(snap: i64, thread_key: Option<String>) -> Self {
        Self { snap, thread_key }
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

impl Default for PcodeTraceRegistersAccess {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = PcodeTraceRegistersAccess::new(0, None);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = PcodeTraceRegistersAccess::default();
    }
}
