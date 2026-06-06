//! Stack panel.

/// Stack panel.
#[derive(Debug, Clone)]
pub struct DebuggerStackPanel {
    /// frame_count
    pub frame_count: usize,
    /// selected_frame
    pub selected_frame: Option<usize>,
}

impl DebuggerStackPanel {
    /// Create a new DebuggerStackPanel.
    pub fn new(frame_count: usize, selected_frame: Option<usize>) -> Self {
        Self { frame_count, selected_frame }
    }

    /// frame_count
    pub fn frame_count(&self) -> &usize {
        &self.frame_count
    }

    /// selected_frame
    pub fn selected_frame(&self) -> &Option<usize> {
        &self.selected_frame
    }
}

impl Default for DebuggerStackPanel {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = DebuggerStackPanel::new(4, None);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerStackPanel::default();
    }
}
