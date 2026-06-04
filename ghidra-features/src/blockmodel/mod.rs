//! Block model service plugin.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.blockmodel` package.
//!
//! Manages code block models used for partitioning a program's code into
//! blocks based on different algorithms (basic blocks, subroutines, etc.).
//! The plugin tracks available models and provides a service for other
//! plugins to query and select models.
//!
//! # Key Types
//!
//! - [`BlockModelServicePlugin`] -- Plugin managing the block model service
//! - [`ModelType`] -- Whether a model partitions by basic blocks or subroutines
//! - [`BlockModelInfo`] -- Metadata about a registered block model
//! - [`BlockModelServiceState`] -- Persisted state of the service

use std::collections::HashMap;

/// Option key for the preferred subroutine model.
pub const SUB_OPTION: &str = "Preferred Subroutine Model";

/// Option key for the preferred basic model.
pub const BASIC_OPTION: &str = "Preferred Basic Block Model";

// ---------------------------------------------------------------------------
// Model type
// ---------------------------------------------------------------------------

/// The type of code block model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModelType {
    /// A basic block model -- partitions code into straight-line sequences.
    BasicBlock,
    /// A subroutine model -- partitions code into subroutine bodies.
    Subroutine,
}

impl ModelType {
    /// Display name for this model type.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::BasicBlock => "Basic Block",
            Self::Subroutine => "Subroutine",
        }
    }
}

// ---------------------------------------------------------------------------
// Block model info
// ---------------------------------------------------------------------------

/// Metadata about a registered code block model.
///
/// Ported from information tracked by `BlockModelServicePlugin`.
#[derive(Debug, Clone)]
pub struct BlockModelInfo {
    /// The unique model name.
    pub name: String,
    /// Whether this is a basic-block or subroutine model.
    pub model_type: ModelType,
    /// Whether this model supports the `get_destinations` method.
    pub supports_destinations: bool,
    /// Whether this model supports the `get_sources` method.
    pub supports_sources: bool,
    /// Human-readable description.
    pub description: String,
}

impl BlockModelInfo {
    /// Create a new block model info.
    pub fn new(
        name: impl Into<String>,
        model_type: ModelType,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            model_type,
            supports_destinations: true,
            supports_sources: true,
            description: description.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Block model service state
// ---------------------------------------------------------------------------

/// Persisted state for the block model service.
///
/// Tracks which models are preferred and what configuration overrides exist.
#[derive(Debug, Clone)]
pub struct BlockModelServiceState {
    /// Name of the preferred subroutine model.
    pub preferred_subroutine_model: Option<String>,
    /// Name of the preferred basic block model.
    pub preferred_basic_model: Option<String>,
    /// Custom model configurations keyed by model name.
    pub model_options: HashMap<String, HashMap<String, String>>,
}

impl Default for BlockModelServiceState {
    fn default() -> Self {
        Self {
            preferred_subroutine_model: None,
            preferred_basic_model: None,
            model_options: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Block model service plugin
// ---------------------------------------------------------------------------

/// Plugin that manages the block model service.
///
/// Discovers available block models and exposes them via the service
/// interface. Maintains preferred model settings and notifies listeners
/// when models are added or removed.
///
/// Ported from `ghidra.app.plugin.core.blockmodel.BlockModelServicePlugin`.
#[derive(Debug)]
pub struct BlockModelServicePlugin {
    /// Registered basic block model names.
    basic_models: Vec<String>,
    /// Registered subroutine model names.
    subroutine_models: Vec<String>,
    /// Currently selected basic model.
    selected_basic: Option<String>,
    /// Currently selected subroutine model.
    selected_subroutine: Option<String>,
    /// Stored options.
    state: BlockModelServiceState,
    /// Whether the plugin has been initialized.
    initialized: bool,
}

impl BlockModelServicePlugin {
    /// Create a new block model service plugin.
    pub fn new() -> Self {
        Self {
            basic_models: Vec::new(),
            subroutine_models: Vec::new(),
            selected_basic: None,
            selected_subroutine: None,
            state: BlockModelServiceState::default(),
            initialized: false,
        }
    }

    /// Initialize the plugin with available model names.
    pub fn init(
        &mut self,
        basic_models: Vec<String>,
        subroutine_models: Vec<String>,
    ) {
        self.basic_models = basic_models;
        self.subroutine_models = subroutine_models;

        if let Some(ref preferred) = self.state.preferred_subroutine_model {
            if self.subroutine_models.contains(preferred) {
                self.selected_subroutine = Some(preferred.clone());
            }
        }
        if self.selected_subroutine.is_none() && !self.subroutine_models.is_empty() {
            self.selected_subroutine = Some(self.subroutine_models[0].clone());
        }

        if let Some(ref preferred) = self.state.preferred_basic_model {
            if self.basic_models.contains(preferred) {
                self.selected_basic = Some(preferred.clone());
            }
        }
        if self.selected_basic.is_none() && !self.basic_models.is_empty() {
            self.selected_basic = Some(self.basic_models[0].clone());
        }

        self.initialized = true;
    }

    /// Whether the plugin has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get the available basic block model names.
    pub fn basic_model_names(&self) -> &[String] {
        &self.basic_models
    }

    /// Get the available subroutine model names.
    pub fn subroutine_model_names(&self) -> &[String] {
        &self.subroutine_models
    }

    /// Get the selected basic model name.
    pub fn selected_basic_model(&self) -> Option<&str> {
        self.selected_basic.as_deref()
    }

    /// Get the selected subroutine model name.
    pub fn selected_subroutine_model(&self) -> Option<&str> {
        self.selected_subroutine.as_deref()
    }

    /// Set the preferred subroutine model.
    pub fn set_preferred_subroutine_model(&mut self, name: impl Into<String>) {
        let name = name.into();
        self.state.preferred_subroutine_model = Some(name.clone());
        if self.subroutine_models.contains(&name) {
            self.selected_subroutine = Some(name);
        }
    }

    /// Set the preferred basic model.
    pub fn set_preferred_basic_model(&mut self, name: impl Into<String>) {
        let name = name.into();
        self.state.preferred_basic_model = Some(name.clone());
        if self.basic_models.contains(&name) {
            self.selected_basic = Some(name);
        }
    }

    /// Register a new model.
    pub fn add_model(&mut self, info: BlockModelInfo) {
        match info.model_type {
            ModelType::BasicBlock => {
                if !self.basic_models.contains(&info.name) {
                    self.basic_models.push(info.name);
                }
            }
            ModelType::Subroutine => {
                if !self.subroutine_models.contains(&info.name) {
                    self.subroutine_models.push(info.name);
                }
            }
        }
    }

    /// Remove a model by name.
    pub fn remove_model(&mut self, name: &str) {
        self.basic_models.retain(|n| n != name);
        self.subroutine_models.retain(|n| n != name);
        if self.selected_basic.as_deref() == Some(name) {
            self.selected_basic = self.basic_models.first().cloned();
        }
        if self.selected_subroutine.as_deref() == Some(name) {
            self.selected_subroutine = self.subroutine_models.first().cloned();
        }
    }

    /// Get the persisted service state.
    pub fn state(&self) -> &BlockModelServiceState {
        &self.state
    }
}

impl Default for BlockModelServicePlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_type_display() {
        assert_eq!(ModelType::BasicBlock.display_name(), "Basic Block");
        assert_eq!(ModelType::Subroutine.display_name(), "Subroutine");
    }

    #[test]
    fn test_block_model_info_creation() {
        let info = BlockModelInfo::new(
            "Simple Block",
            ModelType::BasicBlock,
            "A simple basic block model",
        );
        assert_eq!(info.name, "Simple Block");
        assert_eq!(info.model_type, ModelType::BasicBlock);
        assert!(info.supports_destinations);
    }

    #[test]
    fn test_plugin_init_selects_first_model() {
        let mut plugin = BlockModelServicePlugin::new();
        plugin.init(
            vec!["Basic1".into(), "Basic2".into()],
            vec!["Sub1".into(), "Sub2".into()],
        );
        assert_eq!(plugin.selected_basic_model(), Some("Basic1"));
        assert_eq!(plugin.selected_subroutine_model(), Some("Sub1"));
        assert!(plugin.is_initialized());
    }

    #[test]
    fn test_plugin_preferred_model() {
        let mut plugin = BlockModelServicePlugin::new();
        plugin.set_preferred_subroutine_model("Sub2");
        plugin.init(
            vec!["Basic1".into()],
            vec!["Sub1".into(), "Sub2".into()],
        );
        assert_eq!(plugin.selected_subroutine_model(), Some("Sub2"));
    }

    #[test]
    fn test_plugin_add_and_remove_model() {
        let mut plugin = BlockModelServicePlugin::new();
        plugin.init(vec!["B1".into()], vec!["S1".into()]);

        plugin.add_model(BlockModelInfo::new("B2", ModelType::BasicBlock, ""));
        assert_eq!(plugin.basic_model_names().len(), 2);

        plugin.remove_model("B1");
        assert_eq!(plugin.basic_model_names().len(), 1);
        assert_eq!(plugin.selected_basic_model(), Some("B2"));
    }

    #[test]
    fn test_service_state_default() {
        let state = BlockModelServiceState::default();
        assert!(state.preferred_subroutine_model.is_none());
        assert!(state.model_options.is_empty());
    }
}
