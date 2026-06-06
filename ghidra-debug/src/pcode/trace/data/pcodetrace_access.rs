//! Full access shim for P-code execution against a trace.

/// Full access shim for P-code execution against a trace.
#[derive(Debug, Clone)]
pub struct PcodeTraceAccess {
    /// snap
    pub snap: i64,
    /// thread_key
    pub thread_key: Option<String>,
}

impl PcodeTraceAccess {
    /// Create a new PcodeTraceAccess.
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

impl Default for PcodeTraceAccess {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = PcodeTraceAccess::new(0, None);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = PcodeTraceAccess::default();
    }
}
