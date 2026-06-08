//! Time panel.

/// Time panel.
#[derive(Debug, Clone)]
pub struct DebuggerTimePanel {
    /// current_snap
    pub current_snap: i64,
    /// snap_count
    pub snap_count: usize,
    /// is_scratch
    pub is_scratch: bool,
}

impl DebuggerTimePanel {
    /// Create a new DebuggerTimePanel.
    pub fn new(current_snap: i64, snap_count: usize, is_scratch: bool) -> Self {
        Self { current_snap, snap_count, is_scratch }
    }

    /// current_snap
    pub fn current_snap(&self) -> &i64 {
        &self.current_snap
    }

    /// snap_count
    pub fn snap_count(&self) -> &usize {
        &self.snap_count
    }

    /// is_scratch
    pub fn is_scratch(&self) -> &bool {
        &self.is_scratch
    }
}

impl Default for DebuggerTimePanel {
    fn default() -> Self {
        Self::new(Default::default(), Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let _obj = DebuggerTimePanel::new(0, 4, true);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerTimePanel::default();
    }
}
