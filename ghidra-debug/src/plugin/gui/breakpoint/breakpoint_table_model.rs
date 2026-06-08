//! Breakpoint table model.

/// Breakpoint table model.
#[derive(Debug, Clone)]
pub struct BreakpointTableModel {
    /// columns
    pub columns: Vec<String>,
    /// sort_column
    pub sort_column: Option<usize>,
}

impl BreakpointTableModel {
    /// Create a new BreakpointTableModel.
    pub fn new(columns: Vec<String>, sort_column: Option<usize>) -> Self {
        Self { columns, sort_column }
    }

    /// columns
    pub fn columns(&self) -> &Vec<String> {
        &self.columns
    }

    /// sort_column
    pub fn sort_column(&self) -> &Option<usize> {
        &self.sort_column
    }
}

impl Default for BreakpointTableModel {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let _obj = BreakpointTableModel::new(vec![], None);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = BreakpointTableModel::default();
    }
}
