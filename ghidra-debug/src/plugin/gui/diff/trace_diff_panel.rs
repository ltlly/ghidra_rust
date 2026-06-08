//! Trace diff panel.

/// Trace diff panel.
#[derive(Debug, Clone)]
pub struct TraceDiffPanel {
    /// left_trace_name
    pub left_trace_name: String,
    /// right_trace_name
    pub right_trace_name: String,
}

impl TraceDiffPanel {
    /// Create a new TraceDiffPanel.
    pub fn new(left_trace_name: String, right_trace_name: String) -> Self {
        Self { left_trace_name, right_trace_name }
    }

    /// left_trace_name
    pub fn left_trace_name(&self) -> &String {
        &self.left_trace_name
    }

    /// right_trace_name
    pub fn right_trace_name(&self) -> &String {
        &self.right_trace_name
    }
}

impl Default for TraceDiffPanel {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let _obj = TraceDiffPanel::new("test".to_string(), "test".to_string());
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = TraceDiffPanel::default();
    }
}
