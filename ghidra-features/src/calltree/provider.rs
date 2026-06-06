//! Call tree provider.
//!
//! Ported from Ghidra's CallTreeProvider.

use ghidra_core::Address;

use super::options::CallTreeOptions;
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
///
/// Ported from `ghidra.app.plugin.core.calltree.CallTreeProvider`.
#[derive(Debug)]
pub struct CallTreeProvider {
    config: CallTreeConfig,
    model: CallTreeTableModel,
    /// Whether this is a transient (non-tracking) provider.
    is_transient: bool,
    /// The function being displayed (entry point address).
    showing_function: Option<Address>,
    /// Current call tree options.
    call_tree_options: CallTreeOptions,
}

impl CallTreeProvider {
    /// Create a new call tree provider.
    pub fn new() -> Self {
        Self {
            config: CallTreeConfig::default(),
            model: CallTreeTableModel::new(),
            is_transient: false,
            showing_function: None,
            call_tree_options: CallTreeOptions::default(),
        }
    }

    /// Set the configuration.
    pub fn set_config(&mut self, config: CallTreeConfig) {
        self.config = config;
    }

    /// Get the configuration.
    pub fn config(&self) -> Option<&CallTreeConfig> {
        Some(&self.config)
    }

    /// Get the table model.
    pub fn model(&self) -> &CallTreeTableModel { &self.model }

    /// Get a mutable reference to the table model.
    pub fn model_mut(&mut self) -> &mut CallTreeTableModel { &mut self.model }

    /// Whether this is a transient provider.
    pub fn is_transient(&self) -> bool {
        self.is_transient
    }

    /// Set whether this provider is transient.
    pub fn set_transient(&mut self, is_transient: bool) {
        self.is_transient = is_transient;
    }

    /// Check if this provider is showing the given function.
    pub fn is_showing_function(&self, entry_point: &Address) -> bool {
        self.showing_function.as_ref() == Some(entry_point)
    }

    /// Check if this provider is showing the given location address.
    pub fn is_showing_location(&self, address: &Address) -> bool {
        self.is_showing_function(address)
    }

    /// Initialize the provider for a function.
    pub fn initialize(&mut self, func: &super::plugin::FunctionInfo) {
        self.showing_function = Some(func.entry_point);
    }

    /// Get the call tree options.
    pub fn call_tree_options(&self) -> &CallTreeOptions {
        &self.call_tree_options
    }

    /// Set the call tree options.
    pub fn set_call_tree_options(&mut self, options: CallTreeOptions) {
        self.call_tree_options = options;
    }
}

impl Default for CallTreeProvider {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::plugin::FunctionInfo;

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

    #[test]
    fn test_provider_transient() {
        let mut provider = CallTreeProvider::new();
        assert!(!provider.is_transient());
        provider.set_transient(true);
        assert!(provider.is_transient());
    }

    #[test]
    fn test_provider_showing_function() {
        let mut provider = CallTreeProvider::new();
        let func = FunctionInfo::new("main", Address::new(0x401000));
        provider.initialize(&func);
        assert!(provider.is_showing_function(&Address::new(0x401000)));
        assert!(!provider.is_showing_function(&Address::new(0x500000)));
    }

    #[test]
    fn test_provider_call_tree_options() {
        let mut provider = CallTreeProvider::new();
        assert_eq!(provider.call_tree_options().max_depth, 10);
        let mut opts = CallTreeOptions::large_binary();
        provider.set_call_tree_options(opts.clone());
        assert_eq!(provider.call_tree_options().max_depth, 3);
    }
}
