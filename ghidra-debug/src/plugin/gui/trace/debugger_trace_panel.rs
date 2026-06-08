//! Trace panel.

/// Trace panel.
#[derive(Debug, Clone)]
pub struct DebuggerTracePanel {
    /// trace_count
    pub trace_count: usize,
    /// active_trace
    pub active_trace: Option<usize>,
}

impl DebuggerTracePanel {
    /// Create a new DebuggerTracePanel.
    pub fn new(trace_count: usize, active_trace: Option<usize>) -> Self {
        Self { trace_count, active_trace }
    }

    /// trace_count
    pub fn trace_count(&self) -> &usize {
        &self.trace_count
    }

    /// active_trace
    pub fn active_trace(&self) -> &Option<usize> {
        &self.active_trace
    }
}

impl Default for DebuggerTracePanel {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let _obj = DebuggerTracePanel::new(4, None);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerTracePanel::default();
    }
}
