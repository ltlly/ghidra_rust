//! Listing panel.

/// Listing panel.
#[derive(Debug, Clone)]
pub struct DebuggerListingPanel {
    /// current_address
    pub current_address: Option<u64>,
    /// show_bytes
    pub show_bytes: bool,
}

impl DebuggerListingPanel {
    /// Create a new DebuggerListingPanel.
    pub fn new(current_address: Option<u64>, show_bytes: bool) -> Self {
        Self { current_address, show_bytes }
    }

    /// current_address
    pub fn current_address(&self) -> &Option<u64> {
        &self.current_address
    }

    /// show_bytes
    pub fn show_bytes(&self) -> &bool {
        &self.show_bytes
    }
}

impl Default for DebuggerListingPanel {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = DebuggerListingPanel::new(None, true);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerListingPanel::default();
    }
}
