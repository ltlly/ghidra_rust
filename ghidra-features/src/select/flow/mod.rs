//! Flow-based selection plugin.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.select.flow` package.
//!
//! Provides selection by code flow: forward flow, backward flow, and
//! scope-limited flow selection from the current address.

use serde::{Deserialize, Serialize};

/// Flow direction for selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowDirection {
    /// Follow forward from the current address (downstream).
    Forward,
    /// Follow backward to the current address (upstream).
    Backward,
    /// Follow flow in both directions.
    Both,
}

/// Configuration for flow-based selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowSelectionConfig {
    /// Flow direction.
    pub direction: FlowDirection,
    /// Maximum number of addresses to select.
    pub max_addresses: usize,
    /// Whether to follow through calls.
    pub follow_calls: bool,
    /// Whether to include the start address.
    pub include_start: bool,
}

impl Default for FlowSelectionConfig {
    fn default() -> Self {
        Self {
            direction: FlowDirection::Forward,
            max_addresses: 1_000_000,
            follow_calls: false,
            include_start: true,
        }
    }
}

impl FlowSelectionConfig {
    /// Create a forward flow configuration.
    pub fn forward() -> Self {
        Self { direction: FlowDirection::Forward, ..Default::default() }
    }
    /// Create a backward flow configuration.
    pub fn backward() -> Self {
        Self { direction: FlowDirection::Backward, ..Default::default() }
    }
}

/// Plugin for selecting addresses by flow.
#[derive(Debug)]
pub struct SelectByFlowPlugin {
    /// Plugin name.
    pub name: String,
    /// Current configuration.
    pub config: FlowSelectionConfig,
}

impl SelectByFlowPlugin {
    /// Create a new flow selection plugin.
    pub fn new() -> Self {
        Self {
            name: "SelectByFlowPlugin".to_string(),
            config: FlowSelectionConfig::default(),
        }
    }
    /// Update the flow configuration.
    pub fn set_config(&mut self, config: FlowSelectionConfig) {
        self.config = config;
    }
}

impl Default for SelectByFlowPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Scoped flow selection plugin -- flow within the current function or scope.
#[derive(Debug)]
pub struct SelectByScopedFlowPlugin {
    /// Plugin name.
    pub name: String,
    /// Flow configuration.
    pub config: FlowSelectionConfig,
}

impl SelectByScopedFlowPlugin {
    /// Create a new scoped flow selection plugin.
    pub fn new() -> Self {
        Self {
            name: "SelectByScopedFlowPlugin".to_string(),
            config: FlowSelectionConfig::default(),
        }
    }
}

impl Default for SelectByScopedFlowPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_direction() {
        assert_ne!(FlowDirection::Forward, FlowDirection::Backward);
    }

    #[test]
    fn test_flow_config_default() {
        let config = FlowSelectionConfig::default();
        assert_eq!(config.direction, FlowDirection::Forward);
        assert_eq!(config.max_addresses, 1_000_000);
        assert!(!config.follow_calls);
        assert!(config.include_start);
    }

    #[test]
    fn test_flow_config_forward() {
        let config = FlowSelectionConfig::forward();
        assert_eq!(config.direction, FlowDirection::Forward);
    }

    #[test]
    fn test_flow_config_backward() {
        let config = FlowSelectionConfig::backward();
        assert_eq!(config.direction, FlowDirection::Backward);
    }

    #[test]
    fn test_select_by_flow_plugin() {
        let plugin = SelectByFlowPlugin::new();
        assert_eq!(plugin.name, "SelectByFlowPlugin");
    }

    #[test]
    fn test_select_by_scoped_flow_plugin() {
        let plugin = SelectByScopedFlowPlugin::new();
        assert_eq!(plugin.name, "SelectByScopedFlowPlugin");
    }
}
