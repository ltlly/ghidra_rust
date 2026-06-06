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

/// Detailed script metadata parsing from source file headers.
///
/// Ported from `ghidra.app.script.ScriptInfo` (the full version with
/// header parsing), `GhidraScriptInfoManager`, `GhidraScriptConstants`,
/// `GhidraScriptLoadException`, `GhidraScriptUnsupportedClassVersionError`,
/// and `ImproperUseException`.
pub mod script_info_detailed;

/// Script control mechanisms: output writers, task monitors, and decoration.
///
/// Ported from `ghidra.app.script.ScriptControls`, `DecoratingPrintWriter`,
/// and `StringTransformer`.
pub mod script_controls;

/// User-input dialog types for scripts.
///
/// Ported from `ghidra.app.script.AskDialog`, `MultipleOptionsDialog`,
/// `SelectLanguageDialog`, and `ScriptPreferences`.
pub mod ask_dialog;

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

// ---------------------------------------------------------------------------
// GhidraScriptActionManager
// ---------------------------------------------------------------------------

/// Manages script-related actions (run, rerun, rename, key binding).
///
/// Ported from `ghidra.app.plugin.core.script.GhidraScriptActionManager`.
#[derive(Debug)]
pub struct GhidraScriptActionManager {
    /// Map of script paths to their associated actions.
    pub action_map: HashMap<PathBuf, ScriptAction>,
    /// The "rerun last script" action.
    pub rerun_last_action: Option<ScriptAction>,
    /// Last run script path.
    pub last_run_script: Option<PathBuf>,
    /// Whether the action manager has been disposed.
    pub disposed: bool,
}

impl GhidraScriptActionManager {
    /// Create a new action manager.
    pub fn new() -> Self {
        Self {
            action_map: HashMap::new(),
            rerun_last_action: None,
            last_run_script: None,
            disposed: false,
        }
    }

    /// Register a script action.
    pub fn register_action(&mut self, path: PathBuf, action: ScriptAction) {
        self.action_map.insert(path, action);
    }

    /// Unregister a script action.
    pub fn unregister_action(&mut self, path: &PathBuf) -> Option<ScriptAction> {
        self.action_map.remove(path)
    }

    /// Record that a script was run (for "rerun last" functionality).
    pub fn record_run(&mut self, path: PathBuf) {
        self.last_run_script = Some(path);
    }

    /// Get the number of registered actions.
    pub fn action_count(&self) -> usize {
        self.action_map.len()
    }

    /// Dispose the action manager.
    pub fn dispose(&mut self) {
        self.action_map.clear();
        self.rerun_last_action = None;
        self.disposed = true;
    }
}

impl Default for GhidraScriptActionManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// GhidraScriptComponentProvider
// ---------------------------------------------------------------------------

/// Component provider for the script manager window.
///
/// Ported from `ghidra.app.plugin.core.script.GhidraScriptComponentProvider`.
#[derive(Debug)]
pub struct GhidraScriptComponentProvider {
    /// The provider title.
    pub title: String,
    /// Whether the provider is visible.
    pub visible: bool,
    /// The currently selected script index.
    pub selected_index: Option<usize>,
    /// Window location.
    pub window_x: i32,
    /// Window location.
    pub window_y: i32,
    /// Window size.
    pub window_width: i32,
    /// Window size.
    pub window_height: i32,
}

impl GhidraScriptComponentProvider {
    /// Create a new component provider.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            visible: false,
            selected_index: None,
            window_x: 100,
            window_y: 100,
            window_width: 800,
            window_height: 600,
        }
    }

    /// Show the provider.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Hide the provider.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Set the selected script.
    pub fn set_selected(&mut self, index: Option<usize>) {
        self.selected_index = index;
    }
}

// ---------------------------------------------------------------------------
// GhidraScriptEditorComponentProvider
// ---------------------------------------------------------------------------

/// Component provider for the script editor window.
///
/// Ported from `ghidra.app.plugin.core.script.GhidraScriptEditorComponentProvider`.
#[derive(Debug)]
pub struct GhidraScriptEditorComponentProvider {
    /// The script being edited.
    pub script_path: Option<PathBuf>,
    /// Whether the content has been modified.
    pub dirty: bool,
    /// The editor content.
    pub content: String,
    /// Whether the editor is visible.
    pub visible: bool,
}

impl GhidraScriptEditorComponentProvider {
    /// Create a new editor provider.
    pub fn new() -> Self {
        Self {
            script_path: None,
            dirty: false,
            content: String::new(),
            visible: false,
        }
    }

    /// Open a script for editing.
    pub fn open(&mut self, path: PathBuf, content: impl Into<String>) {
        self.script_path = Some(path);
        self.content = content.into();
        self.dirty = false;
        self.visible = true;
    }

    /// Set the editor content.
    pub fn set_content(&mut self, content: impl Into<String>) {
        self.content = content.into();
        self.dirty = true;
    }

    /// Save the script (clear dirty flag).
    pub fn save(&mut self) {
        self.dirty = false;
    }

    /// Close the editor.
    pub fn close(&mut self) {
        self.script_path = None;
        self.content.clear();
        self.dirty = false;
        self.visible = false;
    }
}

impl Default for GhidraScriptEditorComponentProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// GhidraScriptTableModel (extended version)
// ---------------------------------------------------------------------------

/// Extended table model for displaying scripts with status and action columns.
///
/// Ported from `ghidra.app.plugin.core.script.GhidraScriptTableModel`.
#[derive(Debug)]
pub struct GhidraScriptTableModel {
    /// Base script entries.
    pub entries: Vec<GhidraScriptTableEntry>,
    /// Column sort order.
    pub sort_column: usize,
    /// Whether sort is ascending.
    pub sort_ascending: bool,
}

/// A single row in the GhidraScriptTableModel.
#[derive(Debug, Clone)]
pub struct GhidraScriptTableEntry {
    /// Whether the script has a registered action in the tool.
    pub in_tool: bool,
    /// Script status.
    pub status: ScriptStatus,
    /// Script name.
    pub name: String,
    /// Script description.
    pub description: String,
    /// Key binding.
    pub key_binding: Option<String>,
    /// Full path.
    pub path: PathBuf,
    /// Category.
    pub category: String,
    /// Last modified time (epoch millis).
    pub modified: u64,
}

/// Status of a script in the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptStatus {
    /// Script is ready to run.
    Ready,
    /// Script has a compilation error.
    Error,
    /// Script is currently running.
    Running,
    /// Script status is unknown.
    Unknown,
}

impl GhidraScriptTableModel {
    /// Create a new extended script table model.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            sort_column: 2, // Name column
            sort_ascending: true,
        }
    }

    /// Add an entry.
    pub fn add_entry(&mut self, entry: GhidraScriptTableEntry) {
        self.entries.push(entry);
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the model is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get an entry by index.
    pub fn get(&self, index: usize) -> Option<&GhidraScriptTableEntry> {
        self.entries.get(index)
    }

    /// Find entries by status.
    pub fn entries_with_status(&self, status: ScriptStatus) -> Vec<&GhidraScriptTableEntry> {
        self.entries.iter().filter(|e| e.status == status).collect()
    }
}

impl Default for GhidraScriptTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PickProviderDialog
// ---------------------------------------------------------------------------

/// Dialog for selecting a script provider when multiple are available.
///
/// Ported from `ghidra.app.plugin.core.script.PickProviderDialog`.
#[derive(Debug, Clone)]
pub struct PickProviderDialog {
    /// Available providers.
    pub providers: Vec<ScriptProviderInfo>,
    /// The selected provider index.
    pub selected: Option<usize>,
    /// Whether the dialog was confirmed.
    pub confirmed: bool,
}

/// Information about a script provider.
#[derive(Debug, Clone)]
pub struct ScriptProviderInfo {
    /// Provider name.
    pub name: String,
    /// Supported file extensions.
    pub extensions: Vec<String>,
    /// Whether the provider is available.
    pub available: bool,
}

impl PickProviderDialog {
    /// Create a new pick provider dialog.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
            selected: None,
            confirmed: false,
        }
    }

    /// Add a provider.
    pub fn add_provider(&mut self, provider: ScriptProviderInfo) {
        self.providers.push(provider);
    }

    /// Select a provider by index.
    pub fn select(&mut self, index: usize) {
        if index < self.providers.len() {
            self.selected = Some(index);
        }
    }

    /// Confirm the selection.
    pub fn confirm(&mut self) {
        if self.selected.is_some() {
            self.confirmed = true;
        }
    }

    /// Get the selected provider.
    pub fn selected_provider(&self) -> Option<&ScriptProviderInfo> {
        self.selected.and_then(|i| self.providers.get(i))
    }
}

impl Default for PickProviderDialog {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SaveDialog / SaveNewScriptDialog / ScriptSelectionDialog
// ---------------------------------------------------------------------------

/// Dialog for saving a script.
///
/// Ported from `ghidra.app.plugin.core.script.SaveDialog`.
#[derive(Debug, Clone)]
pub struct SaveDialog {
    /// The script name.
    pub script_name: String,
    /// The save location.
    pub save_path: Option<PathBuf>,
    /// Whether to save as a new file.
    pub save_as_new: bool,
    /// Whether the dialog was confirmed.
    pub confirmed: bool,
}

impl SaveDialog {
    /// Create a new save dialog.
    pub fn new(script_name: impl Into<String>) -> Self {
        Self {
            script_name: script_name.into(),
            save_path: None,
            save_as_new: false,
            confirmed: false,
        }
    }

    /// Set the save path.
    pub fn set_save_path(&mut self, path: PathBuf) {
        self.save_path = Some(path);
    }

    /// Confirm the save.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }
}

/// Dialog for saving a new script with name and category.
///
/// Ported from `ghidra.app.plugin.core.script.SaveNewScriptDialog`.
#[derive(Debug, Clone)]
pub struct SaveNewScriptDialog {
    /// The new script name.
    pub name: String,
    /// The category for the new script.
    pub category: String,
    /// The file extension.
    pub extension: String,
    /// The directory to save in.
    pub directory: Option<PathBuf>,
    /// Whether the dialog was confirmed.
    pub confirmed: bool,
}

impl SaveNewScriptDialog {
    /// Create a new save-new-script dialog.
    pub fn new() -> Self {
        Self {
            name: String::new(),
            category: "Uncategorized".into(),
            extension: "py".into(),
            directory: None,
            confirmed: false,
        }
    }

    /// Set the script name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    /// Confirm the dialog.
    pub fn confirm(&mut self) -> bool {
        if self.name.is_empty() {
            return false;
        }
        self.confirmed = true;
        true
    }

    /// Get the full filename.
    pub fn filename(&self) -> String {
        format!("{}.{}", self.name, self.extension)
    }
}

impl Default for SaveNewScriptDialog {
    fn default() -> Self {
        Self::new()
    }
}

/// Dialog for selecting a script from the available scripts.
///
/// Ported from `ghidra.app.plugin.core.script.ScriptSelectionDialog`.
#[derive(Debug, Clone)]
pub struct ScriptSelectionDialog {
    /// Available scripts.
    pub scripts: Vec<ScriptInfo>,
    /// The selected script index.
    pub selected: Option<usize>,
    /// Filter text.
    pub filter: String,
    /// Whether the dialog was confirmed.
    pub confirmed: bool,
}

impl ScriptSelectionDialog {
    /// Create a new script selection dialog.
    pub fn new() -> Self {
        Self {
            scripts: Vec::new(),
            selected: None,
            filter: String::new(),
            confirmed: false,
        }
    }

    /// Add a script to the dialog.
    pub fn add_script(&mut self, info: ScriptInfo) {
        self.scripts.push(info);
    }

    /// Set the filter text.
    pub fn set_filter(&mut self, filter: impl Into<String>) {
        self.filter = filter.into();
    }

    /// Get filtered scripts.
    pub fn filtered_scripts(&self) -> Vec<&ScriptInfo> {
        if self.filter.is_empty() {
            return self.scripts.iter().collect();
        }
        let lower = self.filter.to_lowercase();
        self.scripts
            .iter()
            .filter(|s| s.name.to_lowercase().contains(&lower))
            .collect()
    }

    /// Select a script by index.
    pub fn select(&mut self, index: usize) {
        if index < self.scripts.len() {
            self.selected = Some(index);
        }
    }

    /// Confirm the selection.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Get the selected script.
    pub fn selected_script(&self) -> Option<&ScriptInfo> {
        self.selected.and_then(|i| self.scripts.get(i))
    }
}

impl Default for ScriptSelectionDialog {
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

    // -- GhidraScriptActionManager tests --

    #[test]
    fn test_action_manager_register() {
        let mut mgr = GhidraScriptActionManager::new();
        let path = PathBuf::from("/scripts/test.py");
        let info = ScriptInfo::new("Test", &path, "py");
        let action = ScriptAction::new(info);
        mgr.register_action(path.clone(), action);
        assert_eq!(mgr.action_count(), 1);
        assert!(mgr.unregister_action(&path).is_some());
        assert_eq!(mgr.action_count(), 0);
    }

    #[test]
    fn test_action_manager_rerun() {
        let mut mgr = GhidraScriptActionManager::new();
        assert!(mgr.last_run_script.is_none());
        mgr.record_run(PathBuf::from("/scripts/test.py"));
        assert_eq!(mgr.last_run_script, Some(PathBuf::from("/scripts/test.py")));
    }

    #[test]
    fn test_action_manager_dispose() {
        let mut mgr = GhidraScriptActionManager::new();
        let info = ScriptInfo::new("Test", "/test.py", "py");
        mgr.register_action(PathBuf::from("/test.py"), ScriptAction::new(info));
        mgr.dispose();
        assert!(mgr.disposed);
        assert_eq!(mgr.action_count(), 0);
    }

    // -- GhidraScriptComponentProvider tests --

    #[test]
    fn test_component_provider() {
        let mut provider = GhidraScriptComponentProvider::new("Script Manager");
        assert!(!provider.visible);
        provider.show();
        assert!(provider.visible);
        provider.set_selected(Some(0));
        assert_eq!(provider.selected_index, Some(0));
        provider.hide();
        assert!(!provider.visible);
    }

    // -- GhidraScriptEditorComponentProvider tests --

    #[test]
    fn test_editor_provider() {
        let mut editor = GhidraScriptEditorComponentProvider::new();
        assert!(!editor.visible);
        editor.open(PathBuf::from("/test.py"), "print('hello')");
        assert!(editor.visible);
        assert!(!editor.dirty);
        editor.set_content("print('world')");
        assert!(editor.dirty);
        editor.save();
        assert!(!editor.dirty);
        editor.close();
        assert!(!editor.visible);
        assert!(editor.content.is_empty());
    }

    // -- GhidraScriptTableModel tests --

    #[test]
    fn test_ghidra_script_table_model() {
        let mut model = GhidraScriptTableModel::new();
        assert!(model.is_empty());
        model.add_entry(GhidraScriptTableEntry {
            in_tool: true,
            status: ScriptStatus::Ready,
            name: "test.py".into(),
            description: "Test script".into(),
            key_binding: None,
            path: PathBuf::from("/test.py"),
            category: "Analysis".into(),
            modified: 1000,
        });
        assert_eq!(model.len(), 1);
        assert_eq!(model.entries_with_status(ScriptStatus::Ready).len(), 1);
        assert_eq!(model.entries_with_status(ScriptStatus::Error).len(), 0);
    }

    // -- PickProviderDialog tests --

    #[test]
    fn test_pick_provider_dialog() {
        let mut dialog = PickProviderDialog::new();
        dialog.add_provider(ScriptProviderInfo {
            name: "Jython".into(),
            extensions: vec!["py".into()],
            available: true,
        });
        dialog.add_provider(ScriptProviderInfo {
            name: "Groovy".into(),
            extensions: vec!["groovy".into()],
            available: true,
        });
        assert!(!dialog.confirmed);
        dialog.select(0);
        dialog.confirm();
        assert!(dialog.confirmed);
        assert_eq!(dialog.selected_provider().unwrap().name, "Jython");
    }

    // -- SaveDialog tests --

    #[test]
    fn test_save_dialog() {
        let mut dialog = SaveDialog::new("MyScript");
        assert!(!dialog.confirmed);
        dialog.set_save_path(PathBuf::from("/scripts/MyScript.py"));
        dialog.confirm();
        assert!(dialog.confirmed);
        assert_eq!(dialog.save_path, Some(PathBuf::from("/scripts/MyScript.py")));
    }

    // -- SaveNewScriptDialog tests --

    #[test]
    fn test_save_new_script_dialog() {
        let mut dialog = SaveNewScriptDialog::new();
        assert!(!dialog.confirm()); // empty name fails
        dialog.set_name("NewScript");
        assert!(dialog.confirm());
        assert_eq!(dialog.filename(), "NewScript.py");
        assert!(dialog.confirmed);
    }

    // -- ScriptSelectionDialog tests --

    #[test]
    fn test_script_selection_dialog() {
        let mut dialog = ScriptSelectionDialog::new();
        dialog.add_script(ScriptInfo::new("Analyze", "/analyze.py", "py"));
        dialog.add_script(ScriptInfo::new("Cleanup", "/cleanup.py", "py"));
        dialog.add_script(ScriptInfo::new("Report", "/report.py", "py"));
        assert_eq!(dialog.filtered_scripts().len(), 3);
        dialog.set_filter("ana");
        assert_eq!(dialog.filtered_scripts().len(), 1);
        assert_eq!(dialog.filtered_scripts()[0].name, "Analyze");
        dialog.set_filter("");
        dialog.select(1);
        dialog.confirm();
        assert_eq!(dialog.selected_script().unwrap().name, "Cleanup");
    }
}
