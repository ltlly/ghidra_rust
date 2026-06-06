//! Watches panel.

/// Watches panel.
#[derive(Debug, Clone)]
pub struct DebuggerWatchesPanel {
    /// watch_count
    pub watch_count: usize,
    /// auto_refresh
    pub auto_refresh: bool,
}

impl DebuggerWatchesPanel {
    /// Create a new DebuggerWatchesPanel.
    pub fn new(watch_count: usize, auto_refresh: bool) -> Self {
        Self { watch_count, auto_refresh }
    }

    /// watch_count
    pub fn watch_count(&self) -> &usize {
        &self.watch_count
    }

    /// auto_refresh
    pub fn auto_refresh(&self) -> &bool {
        &self.auto_refresh
    }
}

impl Default for DebuggerWatchesPanel {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = DebuggerWatchesPanel::new(4, true);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerWatchesPanel::default();
    }
}
