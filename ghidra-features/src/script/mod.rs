//! Script manager plugin for managing and running Ghidra scripts.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.script` package.
//!
//! Provides the script manager that allows users to browse, edit, run,
//! and manage Ghidra scripts (Jython, Groovy, Java). Supports script
//! categories, key bindings, and integration with external editors.
//!
//! # Key Types
//!
//! - [`GhidraScriptMgrPlugin`] -- Plugin providing the script manager
//! - [`ScriptInfo`] -- Metadata about a script
//! - [`ScriptCategory`] -- A category grouping scripts
//! - [`ScriptAction`] -- An action associated with a script
//! - [`ScriptTableModel`] -- Table model for displaying scripts
//! - [`ScriptRunState`] -- State of a running script

/// Script manager for discovering and running Ghidra scripts.
///
/// Ported from `ghidra.app.plugin.core.script` manager classes.
pub mod manager;

/// Script file list management with lazy loading and change notification.
///
/// Ported from `ghidra.app.plugin.core.script.ScriptList`.
pub mod script_list;

/// Script grouping and categorization.
///
/// Ported from `ghidra.app.plugin.core.script.ScriptGroup`,
/// `ScriptCategoryNode`, `RootNode`.
pub mod script_groups;

/// Script key binding management.
///
/// Ported from `ghidra.app.plugin.core.script.KeyBindingsInfo`.
pub mod key_bindings;

/// Script execution task management.
///
/// Ported from `ghidra.app.plugin.core.script.RunScriptTask`.
pub mod run_task;

/// GhidraScript core: the scripting API, state management, provider system,
/// script properties, and console output.
///
/// Ported from `ghidra.app.script.GhidraScript`, `GhidraState`,
/// `GhidraScriptProvider`, `GhidraScriptProperties`, and related types.
pub mod ghidra_script;

use std::collections::HashMap;
use std::path::PathBuf;

/// Maximum script name length.
pub const MAX_SCRIPT_NAME_LEN: usize = 256;

/// Default script directories key.
pub const GHIDRA_SCRIPTS: &str = "Ghidra/Features/Base/ghidra_scripts";

// ---------------------------------------------------------------------------
// Script category
// ---------------------------------------------------------------------------

/// A category for organizing scripts in a tree.
///
/// Ported from `ghidra.app.plugin.core.script.ScriptCategoryNode`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptCategory {
    /// Category name.
    pub name: String,
    /// Parent category path (e.g., "Analysis" for "Analysis/DWARF").
    pub parent: Option<String>,
    /// Full path (e.g., "Analysis/DWARF").
    pub full_path: String,
}

impl ScriptCategory {
    /// Create a new script category.
    pub fn new(name: impl Into<String>, parent: Option<String>) -> Self {
        let name = name.into();
        let full_path = match &parent {
            Some(p) => format!("{}/{}", p, name),
            None => name.clone(),
        };
        Self {
            name,
            parent,
            full_path,
        }
    }

    /// Root-level category.
    pub fn root(name: impl Into<String>) -> Self {
        Self::new(name, None)
    }
}

// ---------------------------------------------------------------------------
// Script run state
// ---------------------------------------------------------------------------

/// State of a running script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptRunState {
    /// Script is not running.
    Idle,
    /// Script is currently executing.
    Running,
    /// Script completed successfully.
    Completed,
    /// Script failed with an error.
    Failed,
    /// Script was cancelled by the user.
    Cancelled,
}

impl ScriptRunState {
    /// Whether the script is currently executing.
    pub fn is_running(&self) -> bool {
        *self == Self::Running
    }

    /// Whether the script has reached a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

// ---------------------------------------------------------------------------
// Script info
// ---------------------------------------------------------------------------

/// Metadata about a Ghidra script.
///
/// Ported from `ghidra.app.plugin.core.script.ScriptsModel` script entries.
#[derive(Debug, Clone)]
pub struct ScriptInfo {
    /// Script name (without extension).
    pub name: String,
    /// Full file path.
    pub path: PathBuf,
    /// File extension (e.g., "py", "java", "groovy").
    pub extension: String,
    /// Category.
    pub category: ScriptCategory,
    /// Script description.
    pub description: String,
    /// Key binding, if assigned.
    pub key_binding: Option<String>,
    /// Whether the script supports a GUI.
    pub has_gui: bool,
    /// Whether the script runs in headless mode.
    pub headless_supported: bool,
    /// Author name.
    pub author: String,
}

impl ScriptInfo {
    /// Create a new script info.
    pub fn new(
        name: impl Into<String>,
        path: impl Into<PathBuf>,
        extension: impl Into<String>,
    ) -> Self {
        let name = name.into();
        Self {
            name,
            path: path.into(),
            extension: extension.into(),
            category: ScriptCategory::root("Uncategorized"),
            description: String::new(),
            key_binding: None,
            has_gui: false,
            headless_supported: true,
            author: String::new(),
        }
    }

    /// The full filename (name + extension).
    pub fn filename(&self) -> String {
        format!("{}.{}", self.name, self.extension)
    }

    /// The language based on the file extension.
    pub fn language(&self) -> &'static str {
        match self.extension.as_str() {
            "py" => "jython",
            "groovy" => "groovy",
            "java" => "java",
            "class" => "java-compiled",
            _ => "unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// Script action
// ---------------------------------------------------------------------------

/// An action associated with a script.
///
/// Ported from `ghidra.app.plugin.core.script.ScriptAction`.
#[derive(Debug, Clone)]
pub struct ScriptAction {
    /// The script info this action is for.
    pub script: ScriptInfo,
    /// The action name.
    pub action_name: String,
    /// Whether the action is currently enabled.
    pub enabled: bool,
    /// Key binding.
    pub key_binding: Option<String>,
}

impl ScriptAction {
    /// Create a new script action.
    pub fn new(script: ScriptInfo) -> Self {
        let action_name = format!("Run {}", script.name);
        Self {
            script,
            action_name,
            enabled: true,
            key_binding: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Script table model
// ---------------------------------------------------------------------------

/// Table model for displaying scripts in the script manager.
///
/// Ported from `ghidra.app.plugin.core.script.ScriptsModel`.
#[derive(Debug)]
pub struct ScriptTableModel {
    /// All known scripts.
    scripts: Vec<ScriptInfo>,
    /// Currently selected script index.
    selected: Option<usize>,
}

impl ScriptTableModel {
    /// Create a new empty script table model.
    pub fn new() -> Self {
        Self {
            scripts: Vec::new(),
            selected: None,
        }
    }

    /// Add a script to the model.
    pub fn add_script(&mut self, info: ScriptInfo) {
        self.scripts.push(info);
    }

    /// Remove a script at the given index.
    pub fn remove_script(&mut self, index: usize) -> Option<ScriptInfo> {
        if index < self.scripts.len() {
            Some(self.scripts.remove(index))
        } else {
            None
        }
    }

    /// Get the number of scripts.
    pub fn len(&self) -> usize {
        self.scripts.len()
    }

    /// Whether the model is empty.
    pub fn is_empty(&self) -> bool {
        self.scripts.is_empty()
    }

    /// Get a script by index.
    pub fn get(&self, index: usize) -> Option<&ScriptInfo> {
        self.scripts.get(index)
    }

    /// Get all scripts.
    pub fn scripts(&self) -> &[ScriptInfo] {
        &self.scripts
    }

    /// Set the selected script.
    pub fn set_selected(&mut self, index: Option<usize>) {
        self.selected = index;
    }

    /// Get the selected script info.
    pub fn selected_script(&self) -> Option<&ScriptInfo> {
        self.selected.and_then(|i| self.scripts.get(i))
    }

    /// Get all unique categories.
    pub fn categories(&self) -> Vec<&str> {
        let mut cats: Vec<&str> = self
            .scripts
            .iter()
            .map(|s| s.category.full_path.as_str())
            .collect();
        cats.sort();
        cats.dedup();
        cats
    }

    /// Find scripts by category.
    pub fn scripts_in_category(&self, category: &str) -> Vec<&ScriptInfo> {
        self.scripts
            .iter()
            .filter(|s| s.category.full_path == category)
            .collect()
    }

    /// Refresh the model by rescanning script directories.
    pub fn refresh(&mut self) {
        // In a full implementation, this would rescan the directories.
    }
}

impl Default for ScriptTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Script manager plugin
// ---------------------------------------------------------------------------

/// Plugin providing the Ghidra script manager.
///
/// Ported from `ghidra.app.plugin.core.script.GhidraScriptMgrPlugin`.
#[derive(Debug)]
pub struct GhidraScriptMgrPlugin {
    /// Script table model.
    model: ScriptTableModel,
    /// Script actions.
    actions: Vec<ScriptAction>,
    /// Currently running script state.
    run_state: ScriptRunState,
    /// Search directories for scripts.
    search_dirs: Vec<PathBuf>,
}

impl GhidraScriptMgrPlugin {
    /// Create a new script manager plugin.
    pub fn new() -> Self {
        Self {
            model: ScriptTableModel::new(),
            actions: Vec::new(),
            run_state: ScriptRunState::Idle,
            search_dirs: Vec::new(),
        }
    }

    /// Get the script model.
    pub fn model(&self) -> &ScriptTableModel {
        &self.model
    }

    /// Get a mutable reference to the script model.
    pub fn model_mut(&mut self) -> &mut ScriptTableModel {
        &mut self.model
    }

    /// Add a search directory.
    pub fn add_search_dir(&mut self, path: PathBuf) {
        self.search_dirs.push(path);
    }

    /// Get the search directories.
    pub fn search_dirs(&self) -> &[PathBuf] {
        &self.search_dirs
    }

    /// Run a script by index.
    pub fn run_script(&mut self, index: usize) -> Result<(), String> {
        if self.run_state.is_running() {
            return Err("A script is already running".into());
        }
        let _script = self
            .model
            .get(index)
            .ok_or("Script not found")?;
        self.run_state = ScriptRunState::Running;
        // In a full implementation, this would invoke the script engine.
        self.run_state = ScriptRunState::Completed;
        Ok(())
    }

    /// Get the current run state.
    pub fn run_state(&self) -> ScriptRunState {
        self.run_state
    }

    /// Refresh the script list.
    pub fn refresh(&mut self) {
        self.model.refresh();
    }

    /// Get the script actions.
    pub fn actions(&self) -> &[ScriptAction] {
        &self.actions
    }
}

impl Default for GhidraScriptMgrPlugin {
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
    fn test_script_category() {
        let root = ScriptCategory::root("Analysis");
        assert_eq!(root.name, "Analysis");
        assert_eq!(root.full_path, "Analysis");
        assert!(root.parent.is_none());

        let child = ScriptCategory::new("DWARF", Some("Analysis".into()));
        assert_eq!(child.full_path, "Analysis/DWARF");
        assert_eq!(child.parent, Some("Analysis".into()));
    }

    #[test]
    fn test_script_run_state() {
        assert!(ScriptRunState::Running.is_running());
        assert!(!ScriptRunState::Idle.is_running());
        assert!(ScriptRunState::Completed.is_terminal());
        assert!(ScriptRunState::Failed.is_terminal());
        assert!(ScriptRunState::Cancelled.is_terminal());
        assert!(!ScriptRunState::Running.is_terminal());
    }

    #[test]
    fn test_script_info() {
        let info = ScriptInfo::new("MyScript", "/scripts/MyScript.py", "py");
        assert_eq!(info.filename(), "MyScript.py");
        assert_eq!(info.language(), "jython");
        assert_eq!(info.category.full_path, "Uncategorized");
    }

    #[test]
    fn test_script_info_languages() {
        assert_eq!(
            ScriptInfo::new("a", "/a.java", "java").language(),
            "java"
        );
        assert_eq!(
            ScriptInfo::new("b", "/b.groovy", "groovy").language(),
            "groovy"
        );
        assert_eq!(
            ScriptInfo::new("c", "/c.txt", "txt").language(),
            "unknown"
        );
    }

    #[test]
    fn test_script_action() {
        let info = ScriptInfo::new("Test", "/test.py", "py");
        let action = ScriptAction::new(info);
        assert_eq!(action.action_name, "Run Test");
        assert!(action.enabled);
    }

    #[test]
    fn test_script_table_model() {
        let mut model = ScriptTableModel::new();
        assert!(model.is_empty());

        model.add_script(ScriptInfo::new("A", "/a.py", "py"));
        model.add_script(ScriptInfo::new("B", "/b.py", "py"));
        assert_eq!(model.len(), 2);

        model.set_selected(Some(0));
        assert_eq!(model.selected_script().unwrap().name, "A");

        model.remove_script(0);
        assert_eq!(model.len(), 1);
        assert_eq!(model.get(0).unwrap().name, "B");
    }

    #[test]
    fn test_script_table_model_categories() {
        let mut model = ScriptTableModel::new();
        let mut s1 = ScriptInfo::new("A", "/a.py", "py");
        s1.category = ScriptCategory::root("Analysis");
        let mut s2 = ScriptInfo::new("B", "/b.py", "py");
        s2.category = ScriptCategory::root("Utilities");

        model.add_script(s1);
        model.add_script(s2);

        let cats = model.categories();
        assert_eq!(cats, vec!["Analysis", "Utilities"]);
        assert_eq!(model.scripts_in_category("Analysis").len(), 1);
    }

    #[test]
    fn test_script_manager_plugin() {
        let mut plugin = GhidraScriptMgrPlugin::new();
        assert_eq!(plugin.run_state(), ScriptRunState::Idle);
        assert!(plugin.search_dirs().is_empty());

        plugin.add_search_dir(PathBuf::from("/scripts"));
        assert_eq!(plugin.search_dirs().len(), 1);

        plugin.model_mut().add_script(ScriptInfo::new("Test", "/test.py", "py"));
        assert!(plugin.run_script(0).is_ok());
        assert_eq!(plugin.run_state(), ScriptRunState::Completed);
    }
}
