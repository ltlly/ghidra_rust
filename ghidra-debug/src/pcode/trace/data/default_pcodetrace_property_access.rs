//! Default property access implementation.

/// Default property access implementation.
#[derive(Debug, Clone)]
pub struct DefaultPcodeTracePropertyAccess {
    /// snap
    pub snap: i64,
    /// property_name
    pub property_name: String,
}

impl DefaultPcodeTracePropertyAccess {
    /// Create a new DefaultPcodeTracePropertyAccess.
    pub fn new(snap: i64, property_name: String) -> Self {
        Self { snap, property_name }
    }

    /// snap
    pub fn snap(&self) -> &i64 {
        &self.snap
    }

    /// property_name
    pub fn property_name(&self) -> &String {
        &self.property_name
    }
}

impl Default for DefaultPcodeTracePropertyAccess {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = DefaultPcodeTracePropertyAccess::new(0, "test".to_string());
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DefaultPcodeTracePropertyAccess::default();
    }
}
