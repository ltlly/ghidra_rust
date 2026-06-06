//! Memory bytes panel.

/// Memory bytes panel.
#[derive(Debug, Clone)]
pub struct DebuggerMemoryBytesPanel {
    /// base_address
    pub base_address: u64,
    /// bytes_per_row
    pub bytes_per_row: usize,
}

impl DebuggerMemoryBytesPanel {
    /// Create a new DebuggerMemoryBytesPanel.
    pub fn new(base_address: u64, bytes_per_row: usize) -> Self {
        Self { base_address, bytes_per_row }
    }

    /// base_address
    pub fn base_address(&self) -> &u64 {
        &self.base_address
    }

    /// bytes_per_row
    pub fn bytes_per_row(&self) -> &usize {
        &self.bytes_per_row
    }
}

impl Default for DebuggerMemoryBytesPanel {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = DebuggerMemoryBytesPanel::new(0, 4);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerMemoryBytesPanel::default();
    }
}
