//! Call tree panel.

/// Call tree panel.
#[derive(Debug, Clone)]
pub struct DebuggerTraceCallTreePanel {
    /// root_function
    pub root_function: Option<String>,
    /// max_depth
    pub max_depth: usize,
}

impl DebuggerTraceCallTreePanel {
    /// Create a new DebuggerTraceCallTreePanel.
    pub fn new(root_function: Option<String>, max_depth: usize) -> Self {
        Self { root_function, max_depth }
    }

    /// root_function
    pub fn root_function(&self) -> Option<&str> {
        self.root_function.as_deref()
    }

    /// max_depth
    pub fn max_depth(&self) -> &usize {
        &self.max_depth
    }
}

impl Default for DebuggerTraceCallTreePanel {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = DebuggerTraceCallTreePanel::new(None, 4);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerTraceCallTreePanel::default();
    }
}
