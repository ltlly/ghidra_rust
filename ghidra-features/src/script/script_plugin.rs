//! Script manager plugin: the main entry point for Ghidra script management.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.script` Java package:
//! - `GhidraScriptMgrPlugin` -- the plugin that provides the script manager
//! - `GhidraScriptComponentProvider` -- the UI provider for the script manager
//! - `GhidraScriptEditorComponentProvider` -- the script editor UI
//! - `GhidraScriptActionManager` -- manages script-related actions
//! - `GhidraScriptService` -- service interface for running scripts
//!
//! # Key Types
//!
//! - [`ScriptPlugin`] -- the main plugin coordinating script management
//! - [`ScriptComponentProvider`] -- the script manager window
//! - [`ScriptEditorProvider`] -- the script editor window
//! - [`ScriptActionManager`] -- manages script key bindings and actions
//! - [`ScriptService`] -- trait for script execution services

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use super::ghidra_script::{GhidraScript, GhidraState};
use super::ScriptRunState;
use super::ghidra_script_provider::{
    CompileCacheEntry, ScriptCompilationCache, ScriptProvider, ScriptProviderError,
    ScriptProviderRegistry,
};

// ---------------------------------------------------------------------------
// ScriptService -- trait for running scripts
// ---------------------------------------------------------------------------

/// Service interface for running Ghidra scripts.
///
/// Ported from `ghidra.app.services.GhidraScriptService`.
pub trait ScriptService: fmt::Debug {
    /// Run a script by name.
    fn run_script(&self, script_name: &str) -> Result<(), ScriptPluginError>;

    /// Run a script from a file path.
    fn run_script_file(&self, path: &Path) -> Result<(), ScriptPluginError>;

    /// Refresh the script list.
    fn refresh_script_list(&self);

    /// Get the list of available scripts.
    fn available_scripts(&self) -> Vec<PathBuf>;
}

// ---------------------------------------------------------------------------
// ScriptPluginError
// ---------------------------------------------------------------------------

/// Errors from script plugin operations.
#[derive(Debug, Clone)]
pub enum ScriptPluginError {
    /// No program is currently open.
    NoProgramOpen,
    /// A script is already running.
    ScriptAlreadyRunning,
    /// The script file was not found.
    ScriptNotFound {
        /// The path that was not found.
        path: PathBuf,
    },
    /// The script could not be loaded.
    LoadError {
        /// The script name.
        script_name: String,
        /// The error message.
        message: String,
    },
    /// A provider error occurred.
    ProviderError(ScriptProviderError),
    /// The script was cancelled.
    Cancelled,
    /// An I/O error occurred.
    IoError {
        /// The error message.
        message: String,
    },
}

impl fmt::Display for ScriptPluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoProgramOpen => write!(f, "No program is currently open"),
            Self::ScriptAlreadyRunning => write!(f, "A script is already running"),
            Self::ScriptNotFound { path } => {
                write!(f, "Script not found: {}", path.display())
            }
            Self::LoadError {
                script_name,
                message,
            } => {
                write!(f, "Failed to load script '{}': {}", script_name, message)
            }
            Self::ProviderError(e) => write!(f, "{}", e),
            Self::Cancelled => write!(f, "Script execution was cancelled"),
            Self::IoError { message } => write!(f, "I/O error: {}", message),
        }
    }
}

impl std::error::Error for ScriptPluginError {}

impl From<ScriptProviderError> for ScriptPluginError {
    fn from(e: ScriptProviderError) -> Self {
        Self::ProviderError(e)
    }
}

// ---------------------------------------------------------------------------
// ScriptPlugin -- the main plugin
// ---------------------------------------------------------------------------

/// The main script manager plugin.
///
/// Coordinates script discovery, editing, running, and action management.
///
/// Ported from `ghidra.app.plugin.core.script.GhidraScriptMgrPlugin`.
#[derive(Debug)]
pub struct ScriptPlugin {
    /// The script provider registry.
    pub provider_registry: ScriptProviderRegistry,
    /// The script component provider (main window).
    pub component_provider: ScriptComponentProvider,
    /// The script action manager.
    pub action_manager: ScriptActionManager,
    /// The compilation cache.
    compile_cache: ScriptCompilationCache,
    /// Open editor providers keyed by script path.
    editors: HashMap<PathBuf, ScriptEditorProvider>,
    /// Current script run state.
    run_state: ScriptRunState,
    /// Path of the currently running script.
    running_script: Option<PathBuf>,
    /// Recently run scripts (most recent first).
    recent_scripts: Vec<PathBuf>,
    /// Maximum number of recent scripts to track.
    max_recent_scripts: usize,
    /// The plugin's unique identifier.
    plugin_id: String,
    /// Whether the plugin has been disposed.
    disposed: bool,
}

impl ScriptPlugin {
    /// Create a new script plugin.
    pub fn new(plugin_id: impl Into<String>) -> Self {
        Self {
            provider_registry: ScriptProviderRegistry::with_defaults(),
            component_provider: ScriptComponentProvider::new("Script Manager"),
            action_manager: ScriptActionManager::new(),
            compile_cache: ScriptCompilationCache::default(),
            editors: HashMap::new(),
            run_state: ScriptRunState::Idle,
            running_script: None,
            recent_scripts: Vec::new(),
            max_recent_scripts: 10,
            plugin_id: plugin_id.into(),
            disposed: false,
        }
    }

    /// Get the plugin ID.
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// Get the current run state.
    pub fn run_state(&self) -> ScriptRunState {
        self.run_state
    }

    /// Whether a script is currently running.
    pub fn is_running(&self) -> bool {
        self.run_state.is_running()
    }

    /// Get the path of the currently running script.
    pub fn running_script(&self) -> Option<&Path> {
        self.running_script.as_deref()
    }

    /// Get the provider registry.
    pub fn provider_registry(&self) -> &ScriptProviderRegistry {
        &self.provider_registry
    }

    /// Get a mutable reference to the provider registry.
    pub fn provider_registry_mut(&mut self) -> &mut ScriptProviderRegistry {
        &mut self.provider_registry
    }

    /// Run a script from a file path.
    pub fn run_script(&mut self, path: &Path) -> Result<(), ScriptPluginError> {
        if self.disposed {
            return Err(ScriptPluginError::LoadError {
                script_name: "disposed".to_string(),
                message: "Plugin has been disposed".to_string(),
            });
        }

        if self.is_running() {
            return Err(ScriptPluginError::ScriptAlreadyRunning);
        }

        if !path.exists() {
            return Err(ScriptPluginError::ScriptNotFound {
                path: path.to_path_buf(),
            });
        }

        let filename = path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("unknown");

        let _provider = self
            .provider_registry
            .find_provider(filename)
            .ok_or_else(|| ScriptProviderError::NoProvider {
                filename: filename.to_string(),
            })?;

        self.run_state = ScriptRunState::Running;
        self.running_script = Some(path.to_path_buf());

        // Record in recent scripts
        self.record_recent(path.to_path_buf());

        // In a full implementation, this would:
        // 1. Read the source file
        // 2. Compile if needed (using compile_cache)
        // 3. Create a GhidraScript instance
        // 4. Set the GhidraState
        // 5. Execute the script's run() method
        // 6. Report results to the console

        // For now, simulate immediate completion.
        self.run_state = ScriptRunState::Completed;
        self.running_script = None;

        Ok(())
    }

    /// Cancel the currently running script.
    pub fn cancel_script(&mut self) {
        if self.is_running() {
            self.run_state = ScriptRunState::Cancelled;
            self.running_script = None;
        }
    }

    /// Get the list of recently run scripts.
    pub fn recent_scripts(&self) -> &[PathBuf] {
        &self.recent_scripts
    }

    /// Record a script path as recently run.
    fn record_recent(&mut self, path: PathBuf) {
        self.recent_scripts.retain(|p| p != &path);
        self.recent_scripts.insert(0, path);
        if self.recent_scripts.len() > self.max_recent_scripts {
            self.recent_scripts.truncate(self.max_recent_scripts);
        }
    }

    /// Open a script in the editor.
    pub fn open_editor(
        &mut self,
        path: PathBuf,
        content: impl Into<String>,
    ) -> &mut ScriptEditorProvider {
        let editor = ScriptEditorProvider::new(path.clone(), content);
        self.editors.insert(path.clone(), editor);
        self.editors.get_mut(&path).unwrap()
    }

    /// Close an editor for the given script path.
    pub fn close_editor(&mut self, path: &Path) {
        self.editors.remove(path);
    }

    /// Get all open editors.
    pub fn editors(&self) -> &HashMap<PathBuf, ScriptEditorProvider> {
        &self.editors
    }

    /// Get the number of open editors.
    pub fn editor_count(&self) -> usize {
        self.editors.len()
    }

    /// Create a new script file from a template.
    pub fn create_new_script(
        &self,
        path: &Path,
        category: &str,
    ) -> Result<(), ScriptPluginError> {
        let filename = path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("unknown");

        let provider = self
            .provider_registry
            .find_provider(filename)
            .ok_or_else(|| ScriptProviderError::NoProvider {
                filename: filename.to_string(),
            })?;

        let header = provider.write_header(category);
        let body = provider.write_body();
        let content = format!("{}{}", header, body);

        std::fs::write(path, content).map_err(|e| ScriptPluginError::IoError {
            message: e.to_string(),
        })?;

        Ok(())
    }

    /// Get the compilation cache.
    pub fn compile_cache(&self) -> &ScriptCompilationCache {
        &self.compile_cache
    }

    /// Get a mutable reference to the compilation cache.
    pub fn compile_cache_mut(&mut self) -> &mut ScriptCompilationCache {
        &mut self.compile_cache
    }

    /// Refresh the script list (rescan directories).
    pub fn refresh(&mut self) {
        self.component_provider.refresh();
    }

    /// Dispose the plugin and release all resources.
    pub fn dispose(&mut self) {
        self.editors.clear();
        self.compile_cache.clear();
        self.recent_scripts.clear();
        self.action_manager.dispose();
        self.run_state = ScriptRunState::Idle;
        self.running_script = None;
        self.disposed = true;
    }

    /// Whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Save plugin state (e.g., window positions, recent scripts).
    pub fn save_state(&self) -> ScriptPluginState {
        ScriptPluginState {
            recent_scripts: self.recent_scripts.clone(),
            window_x: self.component_provider.window_x,
            window_y: self.component_provider.window_y,
            window_width: self.component_provider.window_width,
            window_height: self.component_provider.window_height,
            filter_text: self.component_provider.filter_text.clone(),
        }
    }

    /// Restore plugin state.
    pub fn restore_state(&mut self, state: &ScriptPluginState) {
        self.recent_scripts = state.recent_scripts.clone();
        self.component_provider.window_x = state.window_x;
        self.component_provider.window_y = state.window_y;
        self.component_provider.window_width = state.window_width;
        self.component_provider.window_height = state.window_height;
        self.component_provider.filter_text = state.filter_text.clone();
    }

    /// Handle a program being closed.
    pub fn program_closed(&mut self) {
        // In the full implementation, this would update the current state
        // and disable script-related actions.
    }
}

impl Default for ScriptPlugin {
    fn default() -> Self {
        Self::new("ScriptManager")
    }
}

// ---------------------------------------------------------------------------
// ScriptPluginState -- serializable plugin state
// ---------------------------------------------------------------------------

/// Persisted state of the script plugin.
#[derive(Debug, Clone, Default)]
pub struct ScriptPluginState {
    /// Recently run script paths.
    pub recent_scripts: Vec<PathBuf>,
    /// Window X position.
    pub window_x: i32,
    /// Window Y position.
    pub window_y: i32,
    /// Window width.
    pub window_width: i32,
    /// Window height.
    pub window_height: i32,
    /// Filter text in the script table.
    pub filter_text: String,
}

// ---------------------------------------------------------------------------
// ScriptComponentProvider -- the main script manager window
// ---------------------------------------------------------------------------

/// Component provider for the script manager window.
///
/// Ported from `ghidra.app.plugin.core.script.GhidraScriptComponentProvider`.
#[derive(Debug)]
pub struct ScriptComponentProvider {
    /// The provider title.
    pub title: String,
    /// Whether the provider is visible.
    pub visible: bool,
    /// The currently selected script index.
    pub selected_index: Option<usize>,
    /// Window X position.
    pub window_x: i32,
    /// Window Y position.
    pub window_y: i32,
    /// Window width.
    pub window_width: i32,
    /// Window height.
    pub window_height: i32,
    /// Filter text for narrowing the script list.
    pub filter_text: String,
    /// Whether the script list has been refreshed at least once.
    pub has_been_refreshed: bool,
    /// The currently selected category path in the tree.
    pub selected_category: Option<String>,
    /// Description text for the selected script.
    pub description_text: String,
    /// Divider location between script list and description.
    pub description_divider_location: i32,
    /// Recently opened script paths (provider-local copy).
    pub recent_scripts: Vec<PathBuf>,
}

impl ScriptComponentProvider {
    /// Create a new component provider.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            visible: false,
            selected_index: None,
            window_x: 100,
            window_y: 100,
            window_width: 900,
            window_height: 600,
            filter_text: String::new(),
            has_been_refreshed: false,
            selected_category: None,
            description_text: String::new(),
            description_divider_location: 400,
            recent_scripts: Vec::new(),
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

    /// Toggle visibility.
    pub fn toggle_visible(&mut self) {
        self.visible = !self.visible;
    }

    /// Set the selected script index.
    pub fn set_selected(&mut self, index: Option<usize>) {
        self.selected_index = index;
    }

    /// Set the filter text.
    pub fn set_filter(&mut self, text: impl Into<String>) {
        self.filter_text = text.into();
    }

    /// Set the selected category.
    pub fn set_selected_category(&mut self, category: Option<String>) {
        self.selected_category = category;
    }

    /// Set the description text.
    pub fn set_description(&mut self, text: impl Into<String>) {
        self.description_text = text.into();
    }

    /// Refresh the script list.
    pub fn refresh(&mut self) {
        self.has_been_refreshed = true;
        // In a full implementation, this would rescan script directories
        // and update the table model.
    }

    /// Read persisted configuration state.
    pub fn read_config_state(&mut self, x: i32, y: i32, width: i32, height: i32) {
        self.window_x = x;
        self.window_y = y;
        self.window_width = width;
        self.window_height = height;
    }

    /// Dispose the provider.
    pub fn dispose(&mut self) {
        self.visible = false;
        self.selected_index = None;
        self.recent_scripts.clear();
    }
}

impl Default for ScriptComponentProvider {
    fn default() -> Self {
        Self::new("Script Manager")
    }
}

// ---------------------------------------------------------------------------
// ScriptEditorProvider -- the script editor window
// ---------------------------------------------------------------------------

/// Component provider for the script editor window.
///
/// Ported from `ghidra.app.plugin.core.script.GhidraScriptEditorComponentProvider`.
#[derive(Debug)]
pub struct ScriptEditorProvider {
    /// The script being edited.
    pub script_path: PathBuf,
    /// Whether the content has been modified since last save.
    pub dirty: bool,
    /// The editor content.
    pub content: String,
    /// Whether the editor is visible.
    pub visible: bool,
    /// Cursor position (byte offset from start).
    pub cursor_position: usize,
    /// Whether the editor is read-only.
    pub read_only: bool,
}

impl ScriptEditorProvider {
    /// Create a new editor provider for a script.
    pub fn new(path: PathBuf, content: impl Into<String>) -> Self {
        Self {
            script_path: path,
            dirty: false,
            content: content.into(),
            visible: true,
            cursor_position: 0,
            read_only: false,
        }
    }

    /// Set the editor content.
    pub fn set_content(&mut self, content: impl Into<String>) {
        self.content = content.into();
        self.dirty = true;
    }

    /// Save the script (clear dirty flag).
    pub fn save(&mut self) {
        self.dirty = false;
        // In a full implementation, this would write the content to disk.
    }

    /// Save to a specific path.
    pub fn save_as(&mut self, path: PathBuf) {
        self.script_path = path;
        self.dirty = false;
    }

    /// Close the editor.
    pub fn close(&mut self) {
        self.content.clear();
        self.dirty = false;
        self.visible = false;
    }

    /// Set the cursor position.
    pub fn set_cursor(&mut self, position: usize) {
        self.cursor_position = position;
    }

    /// Get the script filename.
    pub fn filename(&self) -> &str {
        self.script_path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("untitled")
    }
}

// ---------------------------------------------------------------------------
// ScriptActionManager -- manages script actions and key bindings
// ---------------------------------------------------------------------------

/// Manages script-related actions (run, rerun, rename, key binding).
///
/// Ported from `ghidra.app.plugin.core.script.GhidraScriptActionManager`.
#[derive(Debug)]
pub struct ScriptActionManager {
    /// Map of script paths to their associated key bindings.
    pub key_bindings: HashMap<PathBuf, String>,
    /// The last run script path (for "rerun last" functionality).
    pub last_run_script: Option<PathBuf>,
    /// Map of script paths to their menu paths.
    pub menu_paths: HashMap<PathBuf, String>,
    /// Map of script paths to their toolbar icon paths.
    pub toolbar_icons: HashMap<PathBuf, String>,
    /// Whether the action manager has been disposed.
    pub disposed: bool,
}

impl ScriptActionManager {
    /// Create a new action manager.
    pub fn new() -> Self {
        Self {
            key_bindings: HashMap::new(),
            last_run_script: None,
            menu_paths: HashMap::new(),
            toolbar_icons: HashMap::new(),
            disposed: false,
        }
    }

    /// Register a key binding for a script.
    pub fn register_key_binding(&mut self, path: PathBuf, binding: String) {
        self.key_bindings.insert(path, binding);
    }

    /// Remove a key binding for a script.
    pub fn remove_key_binding(&mut self, path: &Path) -> Option<String> {
        self.key_bindings.remove(path)
    }

    /// Get the key binding for a script.
    pub fn key_binding(&self, path: &Path) -> Option<&str> {
        self.key_bindings.get(path).map(|s| s.as_str())
    }

    /// Record that a script was run (for "rerun last" functionality).
    pub fn record_run(&mut self, path: PathBuf) {
        self.last_run_script = Some(path);
    }

    /// Register a menu path for a script.
    pub fn register_menu_path(&mut self, path: PathBuf, menu_path: String) {
        self.menu_paths.insert(path, menu_path);
    }

    /// Register a toolbar icon for a script.
    pub fn register_toolbar_icon(&mut self, path: PathBuf, icon_path: String) {
        self.toolbar_icons.insert(path, icon_path);
    }

    /// Get all registered key bindings.
    pub fn all_key_bindings(&self) -> &HashMap<PathBuf, String> {
        &self.key_bindings
    }

    /// Get the number of registered actions.
    pub fn action_count(&self) -> usize {
        self.key_bindings.len()
    }

    /// Dispose the action manager.
    pub fn dispose(&mut self) {
        self.key_bindings.clear();
        self.last_run_script = None;
        self.menu_paths.clear();
        self.toolbar_icons.clear();
        self.disposed = true;
    }
}

impl Default for ScriptActionManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ScriptTaskListener -- listens for script task completion
// ---------------------------------------------------------------------------

/// Listener for script task events.
///
/// Ported from the `TaskListener` used in `GhidraScriptComponentProvider`.
#[derive(Debug)]
pub struct ScriptTaskListener {
    /// Number of completed tasks.
    pub completed_count: u32,
    /// Number of failed tasks.
    pub failed_count: u32,
    /// Last completed script path.
    pub last_completed: Option<PathBuf>,
    /// Last error message.
    pub last_error: Option<String>,
}

impl ScriptTaskListener {
    /// Create a new task listener.
    pub fn new() -> Self {
        Self {
            completed_count: 0,
            failed_count: 0,
            last_completed: None,
            last_error: None,
        }
    }

    /// Called when a script task completes successfully.
    pub fn on_task_completed(&mut self, script_path: PathBuf) {
        self.completed_count += 1;
        self.last_completed = Some(script_path);
        self.last_error = None;
    }

    /// Called when a script task fails.
    pub fn on_task_failed(&mut self, script_path: PathBuf, error: String) {
        self.failed_count += 1;
        self.last_completed = Some(script_path);
        self.last_error = Some(error);
    }

    /// Total tasks processed.
    pub fn total_tasks(&self) -> u32 {
        self.completed_count + self.failed_count
    }
}

impl Default for ScriptTaskListener {
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

    // -- ScriptPlugin tests --

    #[test]
    fn test_script_plugin_creation() {
        let plugin = ScriptPlugin::new("TestPlugin");
        assert_eq!(plugin.plugin_id(), "TestPlugin");
        assert_eq!(plugin.run_state(), ScriptRunState::Idle);
        assert!(!plugin.is_running());
        assert!(!plugin.is_disposed());
        assert!(plugin.running_script().is_none());
    }

    #[test]
    fn test_script_plugin_default() {
        let plugin = ScriptPlugin::default();
        assert_eq!(plugin.plugin_id(), "ScriptManager");
    }

    #[test]
    fn test_script_plugin_run() {
        let mut plugin = ScriptPlugin::new("test");

        // Create a temporary file to run
        let dir = std::env::temp_dir().join("ghidra_script_test");
        let _ = std::fs::create_dir_all(&dir);
        let script_path = dir.join("test.py");
        let _ = std::fs::write(&script_path, "# test script");

        assert!(plugin.run_script(&script_path).is_ok());
        assert_eq!(plugin.run_state(), ScriptRunState::Completed);
        assert!(!plugin.is_running());
        assert_eq!(plugin.recent_scripts().len(), 1);
        assert_eq!(plugin.recent_scripts()[0], script_path);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_script_plugin_already_running() {
        let mut plugin = ScriptPlugin::new("test");

        // Force into running state
        plugin.run_state = ScriptRunState::Running;
        let path = PathBuf::from("/nonexistent/test.py");
        assert!(plugin.run_script(&path).is_err());
    }

    #[test]
    fn test_script_plugin_not_found() {
        let mut plugin = ScriptPlugin::new("test");
        let path = PathBuf::from("/nonexistent/test.py");
        assert!(plugin.run_script(&path).is_err());
    }

    #[test]
    fn test_script_plugin_cancel() {
        let mut plugin = ScriptPlugin::new("test");
        plugin.run_state = ScriptRunState::Running;
        plugin.cancel_script();
        assert_eq!(plugin.run_state(), ScriptRunState::Cancelled);
    }

    #[test]
    fn test_script_plugin_editor() {
        let mut plugin = ScriptPlugin::new("test");
        let path = PathBuf::from("/scripts/test.py");

        plugin.open_editor(path.clone(), "print('hello')");
        assert_eq!(plugin.editor_count(), 1);

        let editor = plugin.editors().get(&path).unwrap();
        assert_eq!(editor.content, "print('hello')");
        assert!(editor.visible);

        plugin.close_editor(&path);
        assert_eq!(plugin.editor_count(), 0);
    }

    #[test]
    fn test_script_plugin_create_new() {
        let dir = std::env::temp_dir().join("ghidra_script_create_test");
        let _ = std::fs::create_dir_all(&dir);
        let script_path = dir.join("NewScript.java");

        let plugin = ScriptPlugin::new("test");
        assert!(plugin.create_new_script(&script_path, "Analysis").is_ok());
        assert!(script_path.exists());

        let content = std::fs::read_to_string(&script_path).unwrap();
        assert!(content.contains("@category Analysis"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_script_plugin_dispose() {
        let mut plugin = ScriptPlugin::new("test");
        plugin.open_editor(PathBuf::from("/test.py"), "content");
        plugin.dispose();

        assert!(plugin.is_disposed());
        assert!(plugin.editors().is_empty());
    }

    #[test]
    fn test_script_plugin_save_restore_state() {
        let mut plugin = ScriptPlugin::new("test");
        plugin.component_provider.window_x = 200;
        plugin.component_provider.window_y = 300;
        plugin.component_provider.filter_text = "test".to_string();

        let state = plugin.save_state();
        assert_eq!(state.window_x, 200);
        assert_eq!(state.filter_text, "test");

        let mut plugin2 = ScriptPlugin::new("test2");
        plugin2.restore_state(&state);
        assert_eq!(plugin2.component_provider.window_x, 200);
        assert_eq!(plugin2.component_provider.filter_text, "test");
    }

    // -- ScriptComponentProvider tests --

    #[test]
    fn test_component_provider_visibility() {
        let mut provider = ScriptComponentProvider::new("Script Manager");
        assert!(!provider.visible);

        provider.show();
        assert!(provider.visible);

        provider.toggle_visible();
        assert!(!provider.visible);

        provider.toggle_visible();
        assert!(provider.visible);

        provider.hide();
        assert!(!provider.visible);
    }

    #[test]
    fn test_component_provider_selection() {
        let mut provider = ScriptComponentProvider::new("test");
        assert!(provider.selected_index.is_none());

        provider.set_selected(Some(2));
        assert_eq!(provider.selected_index, Some(2));
    }

    #[test]
    fn test_component_provider_filter() {
        let mut provider = ScriptComponentProvider::new("test");
        assert!(provider.filter_text.is_empty());

        provider.set_filter("analysis");
        assert_eq!(provider.filter_text, "analysis");
    }

    #[test]
    fn test_component_provider_category() {
        let mut provider = ScriptComponentProvider::new("test");
        assert!(provider.selected_category.is_none());

        provider.set_selected_category(Some("Analysis/DWARF".to_string()));
        assert_eq!(
            provider.selected_category,
            Some("Analysis/DWARF".to_string())
        );
    }

    #[test]
    fn test_component_provider_description() {
        let mut provider = ScriptComponentProvider::new("test");
        provider.set_description("This script performs analysis");
        assert_eq!(provider.description_text, "This script performs analysis");
    }

    #[test]
    fn test_component_provider_refresh() {
        let mut provider = ScriptComponentProvider::new("test");
        assert!(!provider.has_been_refreshed);
        provider.refresh();
        assert!(provider.has_been_refreshed);
    }

    #[test]
    fn test_component_provider_config_state() {
        let mut provider = ScriptComponentProvider::new("test");
        provider.read_config_state(50, 60, 1024, 768);
        assert_eq!(provider.window_x, 50);
        assert_eq!(provider.window_y, 60);
        assert_eq!(provider.window_width, 1024);
        assert_eq!(provider.window_height, 768);
    }

    #[test]
    fn test_component_provider_dispose() {
        let mut provider = ScriptComponentProvider::new("test");
        provider.show();
        provider.set_selected(Some(0));
        provider.dispose();

        assert!(!provider.visible);
        assert!(provider.selected_index.is_none());
    }

    // -- ScriptEditorProvider tests --

    #[test]
    fn test_editor_provider() {
        let mut editor = ScriptEditorProvider::new(
            PathBuf::from("/test.py"),
            "print('hello')",
        );
        assert!(editor.visible);
        assert!(!editor.dirty);
        assert_eq!(editor.content, "print('hello')");
        assert_eq!(editor.filename(), "test.py");

        editor.set_content("print('world')");
        assert!(editor.dirty);

        editor.save();
        assert!(!editor.dirty);

        editor.close();
        assert!(!editor.visible);
        assert!(editor.content.is_empty());
    }

    #[test]
    fn test_editor_provider_save_as() {
        let mut editor = ScriptEditorProvider::new(
            PathBuf::from("/test.py"),
            "content",
        );
        editor.set_content("modified");
        assert!(editor.dirty);

        editor.save_as(PathBuf::from("/test_new.py"));
        assert_eq!(editor.script_path, PathBuf::from("/test_new.py"));
        assert!(!editor.dirty);
    }

    #[test]
    fn test_editor_provider_cursor() {
        let mut editor = ScriptEditorProvider::new(
            PathBuf::from("/test.py"),
            "hello world",
        );
        assert_eq!(editor.cursor_position, 0);

        editor.set_cursor(5);
        assert_eq!(editor.cursor_position, 5);
    }

    // -- ScriptActionManager tests --

    #[test]
    fn test_action_manager_key_bindings() {
        let mut mgr = ScriptActionManager::new();
        let path = PathBuf::from("/scripts/analyze.py");

        mgr.register_key_binding(path.clone(), "ctrl shift A".to_string());
        assert_eq!(mgr.key_binding(&path), Some("ctrl shift A"));
        assert_eq!(mgr.action_count(), 1);

        assert!(mgr.remove_key_binding(&path).is_some());
        assert!(mgr.key_binding(&path).is_none());
        assert_eq!(mgr.action_count(), 0);
    }

    #[test]
    fn test_action_manager_rerun() {
        let mut mgr = ScriptActionManager::new();
        assert!(mgr.last_run_script.is_none());

        mgr.record_run(PathBuf::from("/scripts/test.py"));
        assert_eq!(
            mgr.last_run_script,
            Some(PathBuf::from("/scripts/test.py"))
        );
    }

    #[test]
    fn test_action_manager_menu_and_toolbar() {
        let mut mgr = ScriptActionManager::new();
        let path = PathBuf::from("/scripts/test.py");

        mgr.register_menu_path(path.clone(), "Analysis/My Script".to_string());
        mgr.register_toolbar_icon(path.clone(), "icon.png".to_string());

        assert_eq!(
            mgr.menu_paths.get(&path),
            Some(&"Analysis/My Script".to_string())
        );
        assert_eq!(
            mgr.toolbar_icons.get(&path),
            Some(&"icon.png".to_string())
        );
    }

    #[test]
    fn test_action_manager_dispose() {
        let mut mgr = ScriptActionManager::new();
        mgr.register_key_binding(PathBuf::from("/test.py"), "ctrl T".to_string());
        mgr.record_run(PathBuf::from("/test.py"));

        mgr.dispose();
        assert!(mgr.disposed);
        assert!(mgr.key_bindings.is_empty());
        assert!(mgr.last_run_script.is_none());
    }

    // -- ScriptTaskListener tests --

    #[test]
    fn test_task_listener() {
        let mut listener = ScriptTaskListener::new();
        assert_eq!(listener.total_tasks(), 0);

        listener.on_task_completed(PathBuf::from("/a.py"));
        assert_eq!(listener.completed_count, 1);
        assert_eq!(listener.total_tasks(), 1);
        assert!(listener.last_error.is_none());

        listener.on_task_failed(PathBuf::from("/b.py"), "error".to_string());
        assert_eq!(listener.failed_count, 1);
        assert_eq!(listener.total_tasks(), 2);
        assert!(listener.last_error.is_some());
    }

    // -- ScriptPluginError tests --

    #[test]
    fn test_plugin_error_display() {
        let err = ScriptPluginError::NoProgramOpen;
        assert!(format!("{}", err).contains("No program"));

        let err = ScriptPluginError::ScriptAlreadyRunning;
        assert!(format!("{}", err).contains("already running"));

        let err = ScriptPluginError::ScriptNotFound {
            path: PathBuf::from("/test.py"),
        };
        assert!(format!("{}", err).contains("test.py"));
    }

    // -- ScriptPluginState tests --

    #[test]
    fn test_plugin_state_default() {
        let state = ScriptPluginState::default();
        assert!(state.recent_scripts.is_empty());
        assert_eq!(state.window_x, 0);
        assert!(state.filter_text.is_empty());
    }
}
