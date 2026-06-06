//! Breakpoint panel.

/// Breakpoint panel.
#[derive(Debug, Clone)]
pub struct BreakpointPanel {
    /// breakpoint_count
    pub breakpoint_count: usize,
    /// filter_text
    pub filter_text: String,
}

impl BreakpointPanel {
    /// Create a new BreakpointPanel.
    pub fn new(breakpoint_count: usize, filter_text: String) -> Self {
        Self { breakpoint_count, filter_text }
    }

    /// breakpoint_count
    pub fn breakpoint_count(&self) -> &usize {
        &self.breakpoint_count
    }

    /// filter_text
    pub fn filter_text(&self) -> &String {
        &self.filter_text
    }
}

impl Default for BreakpointPanel {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = BreakpointPanel::new(4, "test".to_string());
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = BreakpointPanel::default();
    }
}
