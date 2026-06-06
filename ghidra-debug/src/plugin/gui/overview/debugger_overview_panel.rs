//! Overview panel.

/// Overview panel.
#[derive(Debug, Clone)]
pub struct DebuggerOverviewPanel {
    /// target_name
    pub target_name: String,
    /// process_id
    pub process_id: Option<u64>,
    /// thread_count
    pub thread_count: usize,
}

impl DebuggerOverviewPanel {
    /// Create a new DebuggerOverviewPanel.
    pub fn new(target_name: String, process_id: Option<u64>, thread_count: usize) -> Self {
        Self { target_name, process_id, thread_count }
    }

    /// target_name
    pub fn target_name(&self) -> &String {
        &self.target_name
    }

    /// process_id
    pub fn process_id(&self) -> &Option<u64> {
        &self.process_id
    }

    /// thread_count
    pub fn thread_count(&self) -> &usize {
        &self.thread_count
    }
}

impl Default for DebuggerOverviewPanel {
    fn default() -> Self {
        Self::new(Default::default(), Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = DebuggerOverviewPanel::new("test".to_string(), None, 4);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerOverviewPanel::default();
    }
}
