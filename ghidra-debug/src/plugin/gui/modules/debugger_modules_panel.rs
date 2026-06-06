//! Modules panel.

/// Modules panel.
#[derive(Debug, Clone)]
pub struct DebuggerModulesPanel {
    /// module_count
    pub module_count: usize,
    /// show_sections
    pub show_sections: bool,
}

impl DebuggerModulesPanel {
    /// Create a new DebuggerModulesPanel.
    pub fn new(module_count: usize, show_sections: bool) -> Self {
        Self { module_count, show_sections }
    }

    /// module_count
    pub fn module_count(&self) -> &usize {
        &self.module_count
    }

    /// show_sections
    pub fn show_sections(&self) -> &bool {
        &self.show_sections
    }
}

impl Default for DebuggerModulesPanel {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = DebuggerModulesPanel::new(4, true);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerModulesPanel::default();
    }
}
