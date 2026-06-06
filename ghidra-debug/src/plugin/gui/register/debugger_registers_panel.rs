//! Registers panel.

/// Registers panel.
#[derive(Debug, Clone)]
pub struct DebuggerRegistersPanel {
    /// register_count
    pub register_count: usize,
    /// highlight_changes
    pub highlight_changes: bool,
}

impl DebuggerRegistersPanel {
    /// Create a new DebuggerRegistersPanel.
    pub fn new(register_count: usize, highlight_changes: bool) -> Self {
        Self { register_count, highlight_changes }
    }

    /// register_count
    pub fn register_count(&self) -> &usize {
        &self.register_count
    }

    /// highlight_changes
    pub fn highlight_changes(&self) -> &bool {
        &self.highlight_changes
    }
}

impl Default for DebuggerRegistersPanel {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = DebuggerRegistersPanel::new(4, true);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerRegistersPanel::default();
    }
}
