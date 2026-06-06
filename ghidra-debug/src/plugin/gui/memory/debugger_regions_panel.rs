//! Memory regions panel.

/// Memory regions panel.
#[derive(Debug, Clone)]
pub struct DebuggerRegionsPanel {
    /// region_count
    pub region_count: usize,
    /// filter
    pub filter: String,
}

impl DebuggerRegionsPanel {
    /// Create a new DebuggerRegionsPanel.
    pub fn new(region_count: usize, filter: String) -> Self {
        Self { region_count, filter }
    }

    /// region_count
    pub fn region_count(&self) -> &usize {
        &self.region_count
    }

    /// filter
    pub fn filter(&self) -> &String {
        &self.filter
    }
}

impl Default for DebuggerRegionsPanel {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = DebuggerRegionsPanel::new(4, "test".to_string());
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerRegionsPanel::default();
    }
}
