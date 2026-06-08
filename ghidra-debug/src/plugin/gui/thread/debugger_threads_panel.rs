//! Threads panel.

/// Threads panel.
#[derive(Debug, Clone)]
pub struct DebuggerThreadsPanel {
    /// thread_count
    pub thread_count: usize,
    /// selected_thread
    pub selected_thread: Option<u64>,
}

impl DebuggerThreadsPanel {
    /// Create a new DebuggerThreadsPanel.
    pub fn new(thread_count: usize, selected_thread: Option<u64>) -> Self {
        Self { thread_count, selected_thread }
    }

    /// thread_count
    pub fn thread_count(&self) -> &usize {
        &self.thread_count
    }

    /// selected_thread
    pub fn selected_thread(&self) -> &Option<u64> {
        &self.selected_thread
    }
}

impl Default for DebuggerThreadsPanel {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let _obj = DebuggerThreadsPanel::new(4, None);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerThreadsPanel::default();
    }
}
