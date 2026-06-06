//! Static mapping panel.

/// Static mapping panel.
#[derive(Debug, Clone)]
pub struct DebuggerStaticMappingPanel {
    /// mapping_count
    pub mapping_count: usize,
}

impl DebuggerStaticMappingPanel {
    /// Create a new DebuggerStaticMappingPanel.
    pub fn new(mapping_count: usize) -> Self {
        Self { mapping_count }
    }

    /// mapping_count
    pub fn mapping_count(&self) -> &usize {
        &self.mapping_count
    }
}

impl Default for DebuggerStaticMappingPanel {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = DebuggerStaticMappingPanel::new(4);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerStaticMappingPanel::default();
    }
}
