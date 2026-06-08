//! Memory view panel.

/// Memory view panel.
#[derive(Debug, Clone)]
pub struct DebuggerMemviewPanel {
    /// cell_size
    pub cell_size: usize,
    /// color_mode
    pub color_mode: String,
}

impl DebuggerMemviewPanel {
    /// Create a new DebuggerMemviewPanel.
    pub fn new(cell_size: usize, color_mode: String) -> Self {
        Self { cell_size, color_mode }
    }

    /// cell_size
    pub fn cell_size(&self) -> &usize {
        &self.cell_size
    }

    /// color_mode
    pub fn color_mode(&self) -> &String {
        &self.color_mode
    }
}

impl Default for DebuggerMemviewPanel {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let _obj = DebuggerMemviewPanel::new(4, "test".to_string());
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerMemviewPanel::default();
    }
}
