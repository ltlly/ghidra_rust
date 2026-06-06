//! Console panel.

/// Console panel.
#[derive(Debug, Clone)]
pub struct ConsolePanel {
    /// max_lines
    pub max_lines: usize,
    /// auto_scroll
    pub auto_scroll: bool,
}

impl ConsolePanel {
    /// Create a new ConsolePanel.
    pub fn new(max_lines: usize, auto_scroll: bool) -> Self {
        Self { max_lines, auto_scroll }
    }

    /// max_lines
    pub fn max_lines(&self) -> &usize {
        &self.max_lines
    }

    /// auto_scroll
    pub fn auto_scroll(&self) -> &bool {
        &self.auto_scroll
    }
}

impl Default for ConsolePanel {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = ConsolePanel::new(4, true);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = ConsolePanel::default();
    }
}
