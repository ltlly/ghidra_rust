//! Default PcodeTraceAccess implementation.

/// Default PcodeTraceAccess implementation.
#[derive(Debug, Clone)]
pub struct DefaultPcodeTraceAccess {
    /// snap
    pub snap: i64,
    /// thread_key
    pub thread_key: Option<String>,
}

impl DefaultPcodeTraceAccess {
    /// Create a new DefaultPcodeTraceAccess.
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

impl Default for DefaultPcodeTraceAccess {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = DefaultPcodeTraceAccess::new(0, None);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DefaultPcodeTraceAccess::default();
    }
}
