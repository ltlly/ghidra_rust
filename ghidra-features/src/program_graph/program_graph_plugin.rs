//! Program graph plugin.
//!
//! Ported from Ghidra's `ProgramGraphPlugin` Java class.
//!
//! The plugin that provides graph actions for program visualization:
//! block flow, code flow, call graphs, and data reference graphs.

use super::graph_types::ProgramGraphDisplayOptions;

/// Listener for block model service changes.
pub trait BlockModelServiceListener {
    /// Called when a model is added.
    fn model_added(&self, model_name: &str, model_type: ModelType);
    /// Called when a model is removed.
    fn model_removed(&self, model_name: &str, model_type: ModelType);
}

/// The type of block model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelType {
    /// A subroutine (function) model.
    Subroutine,
    /// A basic block model.
    BasicBlock,
    /// A custom model type.
    Custom(u32),
}

/// Listener for graph display broker changes.
pub trait GraphDisplayBrokerListener {
    /// Called when the default display provider changes.
    fn default_provider_changed(&self);
}

/// Plugin configuration for the program graph plugin.
#[derive(Debug, Clone)]
pub struct ProgramGraphPluginConfig {
    /// The name of the active block model.
    pub active_block_model_name: String,
    /// Available subroutine model names.
    pub available_subroutine_models: Vec<String>,
    /// Display options.
    pub options: ProgramGraphDisplayOptions,
}

impl Default for ProgramGraphPluginConfig {
    fn default() -> Self {
        Self {
            active_block_model_name: "Subroutine".to_string(),
            available_subroutine_models: vec!["Subroutine".to_string()],
            options: ProgramGraphDisplayOptions::default(),
        }
    }
}

impl ProgramGraphPluginConfig {
    /// Whether a block model is available.
    pub fn has_block_model(&self, name: &str) -> bool {
        self.available_subroutine_models
            .iter()
            .any(|m| m == name)
    }

    /// Add a subroutine model.
    pub fn add_subroutine_model(&mut self, name: String) {
        if !self.available_subroutine_models.contains(&name) {
            self.available_subroutine_models.push(name);
        }
    }

    /// Remove a subroutine model.
    pub fn remove_subroutine_model(&mut self, name: &str) {
        self.available_subroutine_models.retain(|m| m != name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_config_default() {
        let config = ProgramGraphPluginConfig::default();
        assert_eq!(config.active_block_model_name, "Subroutine");
        assert!(config.has_block_model("Subroutine"));
    }

    #[test]
    fn test_add_remove_model() {
        let mut config = ProgramGraphPluginConfig::default();
        config.add_subroutine_model("CustomModel".to_string());
        assert!(config.has_block_model("CustomModel"));
        config.remove_subroutine_model("CustomModel");
        assert!(!config.has_block_model("CustomModel"));
    }

    #[test]
    fn test_model_type() {
        assert_ne!(ModelType::Subroutine, ModelType::BasicBlock);
    }
}
