//! Default register access implementation.

/// Default register access implementation.
#[derive(Debug, Clone)]
pub struct DefaultPcodeTraceRegistersAccess {
    /// snap
    pub snap: i64,
    /// thread_key
    pub thread_key: Option<String>,
}

impl DefaultPcodeTraceRegistersAccess {
    /// Create a new DefaultPcodeTraceRegistersAccess.
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

impl Default for DefaultPcodeTraceRegistersAccess {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = DefaultPcodeTraceRegistersAccess::new(0, None);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DefaultPcodeTraceRegistersAccess::default();
    }
}
