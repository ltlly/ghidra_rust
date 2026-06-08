//! Model panel.

/// Model panel.
#[derive(Debug, Clone)]
pub struct DebuggerModelPanel {
    /// root_path
    pub root_path: String,
    /// expanded_paths
    pub expanded_paths: Vec<String>,
}

impl DebuggerModelPanel {
    /// Create a new DebuggerModelPanel.
    pub fn new(root_path: String, expanded_paths: Vec<String>) -> Self {
        Self { root_path, expanded_paths }
    }

    /// root_path
    pub fn root_path(&self) -> &String {
        &self.root_path
    }

    /// expanded_paths
    pub fn expanded_paths(&self) -> &Vec<String> {
        &self.expanded_paths
    }
}

impl Default for DebuggerModelPanel {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let _obj = DebuggerModelPanel::new("test".to_string(), vec![]);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerModelPanel::default();
    }
}
