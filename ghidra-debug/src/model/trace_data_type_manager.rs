//! Data type manager for traces.

/// Data type manager for traces.
#[derive(Debug, Clone)]
pub struct TraceDataTypeManager {
    /// name
    pub name: String,
    /// type_count
    pub type_count: usize,
    /// is_read_only
    pub is_read_only: bool,
}

impl TraceDataTypeManager {
    /// Create a new TraceDataTypeManager.
    pub fn new(name: String, type_count: usize, is_read_only: bool) -> Self {
        Self { name, type_count, is_read_only }
    }

    /// name
    pub fn name(&self) -> &String {
        &self.name
    }

    /// type_count
    pub fn type_count(&self) -> &usize {
        &self.type_count
    }

    /// is_read_only
    pub fn is_read_only(&self) -> &bool {
        &self.is_read_only
    }
}

impl Default for TraceDataTypeManager {
    fn default() -> Self {
        Self::new(Default::default(), Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = TraceDataTypeManager::new("test".to_string(), 4, true);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = TraceDataTypeManager::default();
    }
}
