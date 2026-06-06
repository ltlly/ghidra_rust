//! GoTo action.

/// GoTo action.
#[derive(Debug, Clone)]
pub struct DebuggerGoToAction {
    /// target_address
    pub target_address: u64,
    /// description
    pub description: String,
}

impl DebuggerGoToAction {
    /// Create a new DebuggerGoToAction.
    pub fn new(target_address: u64, description: String) -> Self {
        Self { target_address, description }
    }

    /// target_address
    pub fn target_address(&self) -> &u64 {
        &self.target_address
    }

    /// description
    pub fn description(&self) -> &String {
        &self.description
    }
}

impl Default for DebuggerGoToAction {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = DebuggerGoToAction::new(0, "test".to_string());
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerGoToAction::default();
    }
}
