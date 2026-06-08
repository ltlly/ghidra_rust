//! P-code stepper panel.

/// P-code stepper panel.
#[derive(Debug, Clone)]
pub struct DebuggerPcodeStepperPanel {
    /// current_op_index
    pub current_op_index: usize,
    /// op_count
    pub op_count: usize,
}

impl DebuggerPcodeStepperPanel {
    /// Create a new DebuggerPcodeStepperPanel.
    pub fn new(current_op_index: usize, op_count: usize) -> Self {
        Self { current_op_index, op_count }
    }

    /// current_op_index
    pub fn current_op_index(&self) -> &usize {
        &self.current_op_index
    }

    /// op_count
    pub fn op_count(&self) -> &usize {
        &self.op_count
    }
}

impl Default for DebuggerPcodeStepperPanel {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let _obj = DebuggerPcodeStepperPanel::new(4, 4);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerPcodeStepperPanel::default();
    }
}
