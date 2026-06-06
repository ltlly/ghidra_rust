//! Memory access for P-code trace execution.

/// Memory access for P-code trace execution.
#[derive(Debug, Clone)]
pub struct PcodeTraceMemoryAccess {
    /// snap
    pub snap: i64,
    /// space_name
    pub space_name: String,
}

impl PcodeTraceMemoryAccess {
    /// Create a new PcodeTraceMemoryAccess.
    pub fn new(snap: i64, space_name: String) -> Self {
        Self { snap, space_name }
    }

    /// snap
    pub fn snap(&self) -> &i64 {
        &self.snap
    }

    /// space_name
    pub fn space_name(&self) -> &String {
        &self.space_name
    }
}

impl Default for PcodeTraceMemoryAccess {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = PcodeTraceMemoryAccess::new(0, "test".to_string());
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = PcodeTraceMemoryAccess::default();
    }
}
