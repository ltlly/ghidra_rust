//! Module algorithm plugin for program tree organization.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.algorithmtree` package.
//!
//! Applies the "module" algorithm to a Folder or Fragment in a program tree.
//! This algorithm first applies the Multiple Entry Point Subroutine model,
//! which generates fragments; then the Partitioned Code Subroutine model
//! is applied to these fragments.
//!
//! # Key Types
//!
//! - [`ModuleAlgorithmPlugin`] -- Plugin that provides the module algorithm action
//! - [`AlgorithmAction`] -- Action that triggers the module algorithm on a tree node
//! - [`BlockModelService`] -- Trait providing access to available block models

use std::collections::HashMap;

/// The name of the module algorithm as registered with the block model service.
pub const MODULE_ALGORITHM_NAME: &str = "Module";

/// Default help topic for the algorithm tree plugin.
pub const HELP_TOPIC: &str = "ModuleAlgorithm";

// ---------------------------------------------------------------------------
// Block model service abstraction
// ---------------------------------------------------------------------------

/// Trait abstracting the block model service, providing access to
/// code block models used for program organization.
///
/// Ported from `ghidra.app.services.BlockModelService`.
pub trait BlockModelService: Send + Sync {
    /// Get names of available basic block models.
    fn get_basic_model_names(&self) -> Vec<String>;

    /// Get names of available subroutine models.
    fn get_subroutine_model_names(&self) -> Vec<String>;

    /// Get the active basic block model name.
    fn active_basic_model_name(&self) -> &str;

    /// Get the active subroutine model name.
    fn active_subroutine_model_name(&self) -> &str;

    /// Set the active basic block model by name.
    fn set_active_basic_model(&mut self, name: &str) -> Result<(), String>;

    /// Set the active subroutine model by name.
    fn set_active_subroutine_model(&mut self, name: &str) -> Result<(), String>;
}

/// Listener for block model service changes.
///
/// Ported from `ghidra.app.services.BlockModelServiceListener`.
pub trait BlockModelServiceListener: Send + Sync {
    /// Called when a new block model is added.
    fn model_added(&mut self, model_name: &str);

    /// Called when a block model is removed.
    fn model_removed(&mut self, model_name: &str);

    /// Called when the active basic model changes.
    fn basic_model_changed(&mut self, model_name: &str);

    /// Called when the active subroutine model changes.
    fn subroutine_model_changed(&mut self, model_name: &str);
}

// ---------------------------------------------------------------------------
// Algorithm action
// ---------------------------------------------------------------------------

/// Represents an action that applies a block model algorithm to a
/// folder or fragment node in the program tree.
///
/// Ported from the action classes inside `ModuleAlgorithmPlugin`.
#[derive(Debug, Clone)]
pub struct AlgorithmAction {
    /// Name of the action.
    pub name: String,
    /// Display name for the menu.
    pub menu_name: String,
    /// The model name to apply.
    pub model_name: String,
    /// Whether this action is currently enabled.
    pub enabled: bool,
}

impl AlgorithmAction {
    /// Create a new algorithm action.
    pub fn new(name: impl Into<String>, menu_name: impl Into<String>, model_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            menu_name: menu_name.into(),
            model_name: model_name.into(),
            enabled: true,
        }
    }

    /// Returns `true` if the action can be applied to the given context.
    pub fn is_enabled_for_context(&self, has_program: bool, has_tree_node: bool) -> bool {
        self.enabled && has_program && has_tree_node
    }
}

// ---------------------------------------------------------------------------
// Module algorithm plugin
// ---------------------------------------------------------------------------

/// Plugin that applies the module algorithm to a Folder or Fragment.
///
/// The module algorithm:
/// 1. Applies the Multiple Entry Point Subroutine model, generating fragments.
/// 2. Applies the Partitioned Code Subroutine model to those fragments.
///
/// This plugin requires a [`BlockModelService`] and creates actions for each
/// available subroutine model.
///
/// Ported from `ghidra.app.plugin.core.algorithmtree.ModuleAlgorithmPlugin`.
#[derive(Debug)]
pub struct ModuleAlgorithmPlugin {
    /// Available algorithm actions.
    actions: Vec<AlgorithmAction>,
    /// Currently selected subroutine model.
    selected_subroutine_model: String,
    /// Currently selected basic model.
    selected_basic_model: String,
    /// Map of model name to whether it is available.
    available_models: HashMap<String, bool>,
}

impl ModuleAlgorithmPlugin {
    /// Create a new module algorithm plugin.
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),
            selected_subroutine_model: String::new(),
            selected_basic_model: String::new(),
            available_models: HashMap::new(),
        }
    }

    /// Initialize the plugin with available model names.
    pub fn init(&mut self, basic_models: &[String], subroutine_models: &[String]) {
        for name in basic_models {
            self.available_models.insert(name.clone(), true);
        }
        for name in subroutine_models {
            self.available_models.insert(name.clone(), true);
        }

        if !basic_models.is_empty() {
            self.selected_basic_model = basic_models[0].clone();
        }
        if !subroutine_models.is_empty() {
            self.selected_subroutine_model = subroutine_models[0].clone();
        }

        // Create an action for each subroutine model
        for model_name in subroutine_models {
            let action_name = format!("Apply Module ({})", model_name);
            let menu_name = format!("Apply {}", model_name);
            self.actions.push(AlgorithmAction::new(
                action_name,
                menu_name,
                model_name,
            ));
        }
    }

    /// Get all available actions.
    pub fn actions(&self) -> &[AlgorithmAction] {
        &self.actions
    }

    /// Get the currently selected subroutine model name.
    pub fn selected_subroutine_model(&self) -> &str {
        &self.selected_subroutine_model
    }

    /// Get the currently selected basic model name.
    pub fn selected_basic_model(&self) -> &str {
        &self.selected_basic_model
    }

    /// Set the selected subroutine model.
    pub fn set_subroutine_model(&mut self, name: impl Into<String>) {
        self.selected_subroutine_model = name.into();
    }

    /// Set the selected basic model.
    pub fn set_basic_model(&mut self, name: impl Into<String>) {
        self.selected_basic_model = name.into();
    }

    /// Called when the block model service reports a model was added.
    pub fn on_model_added(&mut self, model_name: &str) {
        self.available_models.insert(model_name.to_string(), true);
    }

    /// Called when the block model service reports a model was removed.
    pub fn on_model_removed(&mut self, model_name: &str) {
        self.available_models.remove(model_name);
        self.actions.retain(|a| a.model_name != model_name);
    }
}

impl Default for ModuleAlgorithmPlugin {
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
    fn test_algorithm_action_creation() {
        let action = AlgorithmAction::new("Test", "Apply Test", "SubroutineModel");
        assert_eq!(action.name, "Test");
        assert_eq!(action.menu_name, "Apply Test");
        assert_eq!(action.model_name, "SubroutineModel");
        assert!(action.enabled);
    }

    #[test]
    fn test_algorithm_action_context_check() {
        let action = AlgorithmAction::new("Test", "Apply Test", "Sub");
        assert!(action.is_enabled_for_context(true, true));
        assert!(!action.is_enabled_for_context(false, true));
        assert!(!action.is_enabled_for_context(true, false));

        let mut disabled = action.clone();
        disabled.enabled = false;
        assert!(!disabled.is_enabled_for_context(true, true));
    }

    #[test]
    fn test_module_algorithm_plugin_new() {
        let plugin = ModuleAlgorithmPlugin::new();
        assert!(plugin.actions().is_empty());
        assert!(plugin.selected_subroutine_model().is_empty());
    }

    #[test]
    fn test_module_algorithm_plugin_init() {
        let mut plugin = ModuleAlgorithmPlugin::new();
        let basic = vec!["Basic1".to_string(), "Basic2".to_string()];
        let sub = vec!["Sub1".to_string(), "Sub2".to_string()];
        plugin.init(&basic, &sub);

        assert_eq!(plugin.selected_basic_model(), "Basic1");
        assert_eq!(plugin.selected_subroutine_model(), "Sub1");
        assert_eq!(plugin.actions().len(), 2);
        assert_eq!(plugin.actions()[0].model_name, "Sub1");
        assert_eq!(plugin.actions()[1].model_name, "Sub2");
    }

    #[test]
    fn test_module_algorithm_plugin_model_changes() {
        let mut plugin = ModuleAlgorithmPlugin::new();
        plugin.init(
            &["Basic".to_string()],
            &["SubA".to_string(), "SubB".to_string()],
        );

        plugin.on_model_removed("SubA");
        assert_eq!(plugin.actions().len(), 1);
        assert_eq!(plugin.actions()[0].model_name, "SubB");

        plugin.on_model_added("SubC");
        assert_eq!(plugin.available_models.len(), 3); // Basic, SubB, SubC
    }

    #[test]
    fn test_module_algorithm_plugin_set_models() {
        let mut plugin = ModuleAlgorithmPlugin::new();
        plugin.set_subroutine_model("CustomSub");
        plugin.set_basic_model("CustomBasic");
        assert_eq!(plugin.selected_subroutine_model(), "CustomSub");
        assert_eq!(plugin.selected_basic_model(), "CustomBasic");
    }

    #[test]
    fn test_module_algorithm_name_constant() {
        assert_eq!(MODULE_ALGORITHM_NAME, "Module");
    }
}
