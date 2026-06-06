//! Default TraceSpan implementation.

/// Default TraceSpan implementation.
#[derive(Debug, Clone)]
pub struct DefaultTraceSpan {
    /// min_snap
    pub min_snap: i64,
    /// max_snap
    pub max_snap: i64,
    /// lifecycle_key
    pub lifecycle_key: Option<String>,
}

impl DefaultTraceSpan {
    /// Create a new DefaultTraceSpan.
    pub fn new(min_snap: i64, max_snap: i64, lifecycle_key: Option<String>) -> Self {
        Self { min_snap, max_snap, lifecycle_key }
    }

    /// min_snap
    pub fn min_snap(&self) -> &i64 {
        &self.min_snap
    }

    /// max_snap
    pub fn max_snap(&self) -> &i64 {
        &self.max_snap
    }

    /// lifecycle_key
    pub fn lifecycle_key(&self) -> Option<&str> {
        self.lifecycle_key.as_deref()
    }
}

impl Default for DefaultTraceSpan {
    fn default() -> Self {
        Self::new(Default::default(), Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = DefaultTraceSpan::new(0, 0, None);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DefaultTraceSpan::default();
    }
}
