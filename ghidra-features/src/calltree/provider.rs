//! Call tree provider.
//!
//! Ported from Ghidra's CallTreeProvider.

use super::table::{CallTreeTableModel, CallTreeNode};

/// Configuration for the call tree display.
#[derive(Debug, Clone)]
pub struct CallTreeConfig {
    /// Show callers (true) or callees (false).
    pub show_callers: bool,
    /// Maximum depth to display.
    pub max_depth: usize,
    /// Whether to filter library functions.
    pub filter_library: bool,
}

impl Default for CallTreeConfig {
    fn default() -> Self {
        Self { show_callers: false, max_depth: 10, filter_library: false }
    }
}

/// The call tree provider managing display.
#[derive(Debug)]
pub struct CallTreeProvider {
    pub config: CallTreeConfig,
    model: CallTreeTableModel,
}

impl CallTreeProvider {
    pub fn new() -> Self {
        Self { config: CallTreeConfig::default(), model: CallTreeTableModel::new() }
    }
    pub fn set_config(&mut self, config: CallTreeConfig) { self.config = config; }
    pub fn model(&self) -> &CallTreeTableModel { &self.model }
    pub fn model_mut(&mut self) -> &mut CallTreeTableModel { &mut self.model }
}

impl Default for CallTreeProvider {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_tree_config_default() {
        let config = CallTreeConfig::default();
        assert!(!config.show_callers);
        assert_eq!(config.max_depth, 10);
    }

    #[test]
    fn test_call_tree_provider() {
        let mut provider = CallTreeProvider::new();
        provider.model_mut().add_node(CallTreeNode::new("main", "0x401000", 0));
        assert_eq!(provider.model().len(), 1);
    }
}
