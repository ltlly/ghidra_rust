//! Program tab actions -- ported from Ghidra's
//! `ghidra.app.plugin.core.progmgr` action classes.
//!
//! Provides base classes and implementations for program-management actions
//! whose menu names dynamically change based on the active program.
//!
//! # Key Types
//!
//! - [`AbstractProgramNameSwitchingAction`] -- base for actions with dynamic names
//! - [`AbstractUndoRedoAction`] -- base for undo/redo actions with repeat support
//! - [`MultiTabListener`] -- trait for tab lifecycle events
//! - [`MultiTabPlugin`] -- manages multiple program tabs
//! - [`ProgramTabActionContext`] -- context carrying the active program tab


// ---------------------------------------------------------------------------
// ProgramTabActionContext
// ---------------------------------------------------------------------------

/// Context for program tab actions.
///
/// Ported from `ghidra.app.plugin.core.progmgr.ProgramTabActionContext`.
#[derive(Debug, Clone)]
pub struct ProgramTabActionContext {
    /// The name of the plugin providing this context.
    pub plugin_name: String,
    /// The program address (if any).
    pub program_id: Option<u64>,
    /// The program's domain file name.
    pub program_name: Option<String>,
    /// Whether the program is managed globally (vs. by a specific plugin).
    pub is_global: bool,
}

impl ProgramTabActionContext {
    /// Create a new tab action context.
    pub fn new(plugin_name: impl Into<String>) -> Self {
        Self {
            plugin_name: plugin_name.into(),
            program_id: None,
            program_name: None,
            is_global: true,
        }
    }

    /// Whether this context has a program.
    pub fn has_program(&self) -> bool {
        self.program_id.is_some()
    }
}

// ---------------------------------------------------------------------------
// AbstractProgramNameSwitchingAction
// ---------------------------------------------------------------------------

/// Abstract base for program actions that change their menu name based
/// on the active program.
///
/// Ported from `AbstractProgramNameSwitchingAction.java`.
///
/// Actions derived from this class only work on globally managed programs.
/// If the action context contains a non-global program, the tool's current
/// active program is used instead.
///
/// # Example
///
/// ```
/// use ghidra_features::progmgr::tab_actions::*;
///
/// let mut action = CloseProgramAction::new("MyPlugin", "FileGroup", 1);
/// assert_eq!(action.name(), "Close File");
/// assert!(action.is_enabled());
///
/// // Simulate program change
/// action.set_program_name(Some("my_binary.exe"));
/// ```
#[derive(Debug, Clone)]
pub struct AbstractProgramNameSwitchingAction {
    /// The action name.
    name: String,
    /// The owner plugin name.
    owner: String,
    /// Whether the action is enabled.
    enabled: bool,
    /// The menu item name (dynamic).
    menu_item_name: String,
    /// Description text.
    description: String,
    /// The program name for the current context.
    program_name: Option<String>,
}

impl AbstractProgramNameSwitchingAction {
    /// Create a new action with a dynamic name.
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        let n = name.into();
        Self {
            menu_item_name: n.clone(),
            name: n,
            owner: owner.into(),
            enabled: true,
            description: String::new(),
            program_name: None,
        }
    }

    /// Get the action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the owner plugin name.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Whether the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the current menu item name.
    pub fn menu_item_name(&self) -> &str {
        &self.menu_item_name
    }

    /// Get the description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get the program name (if any).
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Update the action when the active program changes.
    ///
    /// Subclasses override the corresponding `on_program_changed` method
    /// to update their menu labels.
    pub fn set_program_name(&mut self, name: Option<&str>) {
        self.program_name = name.map(|s| s.to_string());
        self.on_program_changed(name);
    }

    /// Called when the program changes. Override to update menu names.
    fn on_program_changed(&mut self, name: Option<&str>) {
        match name {
            Some(prog_name) => {
                self.menu_item_name = format!("Close '{}'", prog_name);
                self.description = format!("Close '{}'", prog_name);
            }
            None => {
                self.menu_item_name = self.name.clone();
                self.description = self.name.clone();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CloseProgramAction
// ---------------------------------------------------------------------------

/// Action for closing a program.
///
/// Ported from `ghidra.app.plugin.core.progmgr.CloseProgramAction`.
#[derive(Debug, Clone)]
pub struct CloseProgramAction {
    inner: AbstractProgramNameSwitchingAction,
    menu_group: String,
    sub_group: i32,
}

impl CloseProgramAction {
    /// Create a new close program action.
    pub fn new(owner: impl Into<String>, menu_group: impl Into<String>, sub_group: i32) -> Self {
        let mut inner = AbstractProgramNameSwitchingAction::new("Close File", owner);
        inner.menu_item_name = "&Close".to_string();
        Self {
            inner,
            menu_group: menu_group.into(),
            sub_group,
        }
    }

    /// Get the action name.
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// Whether enabled.
    pub fn is_enabled(&self) -> bool {
        self.inner.is_enabled()
    }

    /// Get the menu item name.
    pub fn menu_item_name(&self) -> &str {
        self.inner.menu_item_name()
    }

    /// Update program name.
    pub fn set_program_name(&mut self, name: Option<&str>) {
        match name {
            Some(prog_name) => {
                self.inner.menu_item_name = format!("Close '{}'", prog_name);
                self.inner.description = format!("Close '{}'", prog_name);
            }
            None => {
                self.inner.menu_item_name = "&Close".to_string();
                self.inner.description = "Close Program".to_string();
            }
        }
        self.inner.program_name = name.map(|s| s.to_string());
    }
}

// ---------------------------------------------------------------------------
// SaveAsProgramAction
// ---------------------------------------------------------------------------

/// Action for "Save As" of a program.
///
/// Ported from `ghidra.app.plugin.core.progmgr.SaveAsProgramAction`.
#[derive(Debug, Clone)]
pub struct SaveAsProgramAction {
    inner: AbstractProgramNameSwitchingAction,
    menu_group: String,
    sub_group: i32,
}

impl SaveAsProgramAction {
    /// Create a new save-as action.
    pub fn new(owner: impl Into<String>, menu_group: impl Into<String>, sub_group: i32) -> Self {
        let mut inner = AbstractProgramNameSwitchingAction::new("Save As File", owner);
        inner.menu_item_name = "S&ave As...".to_string();
        Self {
            inner,
            menu_group: menu_group.into(),
            sub_group,
        }
    }

    /// Get the action name.
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// Whether enabled.
    pub fn is_enabled(&self) -> bool {
        self.inner.is_enabled()
    }

    /// Get the current menu item name.
    pub fn menu_item_name(&self) -> &str {
        self.inner.menu_item_name()
    }

    /// Update program name.
    pub fn set_program_name(&mut self, name: Option<&str>) {
        match name {
            Some(prog_name) => {
                self.inner.menu_item_name = format!("Save '{}' As...", prog_name);
                self.inner.description = format!("Save '{}' As", prog_name);
            }
            None => {
                self.inner.menu_item_name = "S&ave As...".to_string();
                self.inner.description = "Save As".to_string();
            }
        }
        self.inner.program_name = name.map(|s| s.to_string());
    }
}

// ---------------------------------------------------------------------------
// ProgramOptionsAction
// ---------------------------------------------------------------------------

/// Action for editing program options.
///
/// Ported from `ghidra.app.plugin.core.progmgr.ProgramOptionsAction`.
#[derive(Debug, Clone)]
pub struct ProgramOptionsAction {
    inner: AbstractProgramNameSwitchingAction,
}

impl ProgramOptionsAction {
    /// Create a new program options action.
    pub fn new(owner: impl Into<String>) -> Self {
        let inner = AbstractProgramNameSwitchingAction::new("Program Options", owner);
        Self { inner }
    }

    /// Get the action name.
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// Whether enabled.
    pub fn is_enabled(&self) -> bool {
        self.inner.is_enabled()
    }

    /// Get the current menu item name.
    pub fn menu_item_name(&self) -> &str {
        self.inner.menu_item_name()
    }

    /// Update program name.
    pub fn set_program_name(&mut self, name: Option<&str>) {
        match name {
            Some(prog_name) => {
                self.inner.menu_item_name = format!("Options for '{}'", prog_name);
            }
            None => {
                self.inner.menu_item_name = "Program Options".to_string();
            }
        }
        self.inner.program_name = name.map(|s| s.to_string());
    }
}

// ---------------------------------------------------------------------------
// AbstractUndoRedoAction
// ---------------------------------------------------------------------------

/// Abstract base class for undo and redo actions.
///
/// Ported from `ghidra.app.plugin.core.progmgr.AbstractUndoRedoAction`.
///
/// Tracks the current active program and manages transaction listeners
/// for undo/redo state.
#[derive(Debug, Clone)]
pub struct AbstractUndoRedoAction {
    /// The action name (e.g., "Undo", "Redo").
    name: String,
    /// Owner plugin.
    owner: String,
    /// Keyboard shortcut.
    key_binding: String,
    /// Icon identifier.
    icon_id: String,
    /// Subgroup for menu ordering.
    sub_group: String,
    /// Whether enabled.
    enabled: bool,
    /// Current undo/redo description.
    description: String,
    /// Number of undoable/redoable operations available.
    available_count: usize,
}

impl AbstractUndoRedoAction {
    /// Create a new undo/redo action.
    pub fn new(
        name: impl Into<String>,
        owner: impl Into<String>,
        icon_id: impl Into<String>,
        key_binding: impl Into<String>,
        sub_group: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
            key_binding: key_binding.into(),
            icon_id: icon_id.into(),
            sub_group: sub_group.into(),
            enabled: false,
            description: String::new(),
            available_count: 0,
        }
    }

    /// Get the action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the keyboard shortcut.
    pub fn key_binding(&self) -> &str {
        &self.key_binding
    }

    /// Whether the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the current description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get the number of available undo/redo operations.
    pub fn available_count(&self) -> usize {
        self.available_count
    }

    /// Update the action state from the program.
    pub fn update_state(&mut self, can_perform: bool, description: &str, count: usize) {
        self.enabled = can_perform;
        self.description = description.to_string();
        self.available_count = count;
    }
}

// ---------------------------------------------------------------------------
// UndoAction
// ---------------------------------------------------------------------------

/// Undo action for the program manager.
///
/// Ported from `ghidra.app.plugin.core.progmgr.UndoAction`.
#[derive(Debug, Clone)]
pub struct UndoAction {
    inner: AbstractUndoRedoAction,
}

impl UndoAction {
    /// Create a new undo action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            inner: AbstractUndoRedoAction::new(
                "Undo",
                owner,
                "icon.undo",
                "ctrl Z",
                "1Undo",
            ),
        }
    }

    /// Get the action name.
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// Whether enabled.
    pub fn is_enabled(&self) -> bool {
        self.inner.is_enabled()
    }

    /// Get the keyboard shortcut.
    pub fn key_binding(&self) -> &str {
        self.inner.key_binding()
    }

    /// Update state.
    pub fn update_state(&mut self, can_undo: bool, undo_name: &str, undo_count: usize) {
        self.inner.update_state(can_undo, undo_name, undo_count);
    }

    /// Get available count.
    pub fn available_count(&self) -> usize {
        self.inner.available_count()
    }
}

// ---------------------------------------------------------------------------
// RedoAction
// ---------------------------------------------------------------------------

/// Redo action for the program manager.
///
/// Ported from `ghidra.app.plugin.core.progmgr.RedoAction`.
#[derive(Debug, Clone)]
pub struct RedoAction {
    inner: AbstractUndoRedoAction,
}

impl RedoAction {
    /// Create a new redo action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            inner: AbstractUndoRedoAction::new(
                "Redo",
                owner,
                "icon.redo",
                "ctrl shift Z",
                "2Redo",
            ),
        }
    }

    /// Get the action name.
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// Whether enabled.
    pub fn is_enabled(&self) -> bool {
        self.inner.is_enabled()
    }

    /// Get the keyboard shortcut.
    pub fn key_binding(&self) -> &str {
        self.inner.key_binding()
    }

    /// Update state.
    pub fn update_state(&mut self, can_redo: bool, redo_name: &str, redo_count: usize) {
        self.inner.update_state(can_redo, redo_name, redo_count);
    }

    /// Get available count.
    pub fn available_count(&self) -> usize {
        self.inner.available_count()
    }
}

// ---------------------------------------------------------------------------
// MultiTabListener
// ---------------------------------------------------------------------------

/// Events that can occur on a multi-tab panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TabEvent {
    /// A tab was selected.
    Selected(usize),
    /// A tab was added.
    Added(usize),
    /// A tab was removed.
    Removed(usize),
    /// A tab was moved.
    Moved { from: usize, to: usize },
}

/// Trait for listeners notified of tab lifecycle events.
///
/// Ported from `ghidra.app.plugin.core.progmgr.MultiTabListener`.
pub trait MultiTabListener: std::fmt::Debug {
    /// Called when a tab is selected.
    fn object_selected(&self, index: usize);

    /// Called when a tab is added.
    fn object_added(&self, index: usize);

    /// Called to check whether a tab should be removed.
    ///
    /// Returns `true` if the tab should be removed.
    fn should_remove(&self, index: usize) -> bool;
}

// ---------------------------------------------------------------------------
// MultiTabPlugin
// ---------------------------------------------------------------------------

/// Plugin managing multiple program tabs.
///
/// Ported from `ghidra.app.plugin.core.progmgr.MultiTabPlugin`.
///
/// # Example
///
/// ```
/// use ghidra_features::progmgr::tab_actions::*;
///
/// let mut plugin = MultiTabPlugin::new("ProgramManager");
/// plugin.add_tab("program1.exe".to_string());
/// plugin.add_tab("program2.exe".to_string());
/// assert_eq!(plugin.tab_count(), 2);
///
/// plugin.select_tab(1);
/// assert_eq!(plugin.selected_tab(), Some(1));
/// assert_eq!(plugin.selected_tab_name(), Some("program2.exe"));
/// ```
#[derive(Debug)]
pub struct MultiTabPlugin {
    /// Plugin name.
    name: String,
    /// Tab names (program names).
    tabs: Vec<String>,
    /// Currently selected tab index.
    selected: Option<usize>,
    /// Whether tabs can be reordered.
    reorderable: bool,
}

impl MultiTabPlugin {
    /// Create a new multi-tab plugin.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            tabs: Vec::new(),
            selected: None,
            reorderable: true,
        }
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Add a new tab.
    pub fn add_tab(&mut self, name: String) -> usize {
        self.tabs.push(name);
        let index = self.tabs.len() - 1;
        if self.selected.is_none() {
            self.selected = Some(0);
        }
        index
    }

    /// Remove a tab by index.
    pub fn remove_tab(&mut self, index: usize) -> Option<String> {
        if index >= self.tabs.len() {
            return None;
        }
        let removed = self.tabs.remove(index);
        // Adjust selected index
        self.selected = match self.selected {
            Some(sel) if sel == index => {
                if self.tabs.is_empty() {
                    None
                } else if index >= self.tabs.len() {
                    Some(self.tabs.len() - 1)
                } else {
                    Some(index)
                }
            }
            Some(sel) if sel > index => Some(sel - 1),
            other => other,
        };
        Some(removed)
    }

    /// Remove a tab by name.
    pub fn remove_tab_by_name(&mut self, name: &str) -> Option<String> {
        if let Some(index) = self.tabs.iter().position(|t| t == name) {
            self.remove_tab(index)
        } else {
            None
        }
    }

    /// Get the number of tabs.
    pub fn tab_count(&self) -> usize {
        self.tabs.len()
    }

    /// Select a tab by index.
    pub fn select_tab(&mut self, index: usize) -> bool {
        if index < self.tabs.len() {
            self.selected = Some(index);
            true
        } else {
            false
        }
    }

    /// Get the selected tab index.
    pub fn selected_tab(&self) -> Option<usize> {
        self.selected
    }

    /// Get the name of the selected tab.
    pub fn selected_tab_name(&self) -> Option<&str> {
        self.selected.and_then(|i| self.tabs.get(i).map(|s| s.as_str()))
    }

    /// Get a tab name by index.
    pub fn tab_name(&self, index: usize) -> Option<&str> {
        self.tabs.get(index).map(|s| s.as_str())
    }

    /// Get all tab names.
    pub fn tab_names(&self) -> &[String] {
        &self.tabs
    }

    /// Whether the plugin has any tabs.
    pub fn has_tabs(&self) -> bool {
        !self.tabs.is_empty()
    }

    /// Move a tab from one position to another.
    pub fn move_tab(&mut self, from: usize, to: usize) -> bool {
        if from >= self.tabs.len() || to >= self.tabs.len() || from == to {
            return false;
        }
        let tab = self.tabs.remove(from);
        self.tabs.insert(to, tab);

        // Adjust selected index
        if let Some(sel) = self.selected {
            if sel == from {
                self.selected = Some(to);
            } else if from < sel && sel <= to {
                self.selected = Some(sel - 1);
            } else if to <= sel && sel < from {
                self.selected = Some(sel + 1);
            }
        }
        true
    }

    /// Whether tabs are reorderable.
    pub fn is_reorderable(&self) -> bool {
        self.reorderable
    }

    /// Set whether tabs are reorderable.
    pub fn set_reorderable(&mut self, reorderable: bool) {
        self.reorderable = reorderable;
    }
}

impl Default for MultiTabPlugin {
    fn default() -> Self {
        Self::new("MultiTabPlugin")
    }
}

// ===========================================================================
// SaveProgramAction
// ===========================================================================

/// Action to save the current program.
///
/// Ported from `ghidra.app.plugin.core.progmgr.SaveProgramAction`.
#[derive(Debug, Clone)]
pub struct SaveProgramAction {
    /// Action name.
    pub name: String,
    /// Owner plugin.
    pub owner: String,
    /// Whether the action is currently enabled.
    pub enabled: bool,
}

impl SaveProgramAction {
    /// Create a new save-program action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Save".to_string(),
            owner: owner.into(),
            enabled: false,
        }
    }

    /// Whether the action is enabled (requires a program with unsaved changes).
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Update enablement based on whether the program has unsaved changes.
    pub fn update_enabled(&mut self, has_unsaved_changes: bool) {
        self.enabled = has_unsaved_changes;
    }

    /// Execute the save action.  Returns true if the save was successful.
    pub fn execute(&self, program_name: &str) -> bool {
        // In the real implementation, this would call ProgramSaveManager.
        // Here we just validate.
        !program_name.is_empty()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_tab_action_context() {
        let ctx = ProgramTabActionContext::new("TestPlugin");
        assert!(!ctx.has_program());

        let mut ctx = ProgramTabActionContext::new("TestPlugin");
        ctx.program_id = Some(1);
        ctx.program_name = Some("test.exe".into());
        assert!(ctx.has_program());
    }

    #[test]
    fn test_close_program_action() {
        let mut action = CloseProgramAction::new("TestPlugin", "FileGroup", 1);
        assert_eq!(action.name(), "Close File");
        assert_eq!(action.menu_item_name(), "&Close");

        action.set_program_name(Some("my_binary.exe"));
        assert_eq!(action.menu_item_name(), "Close 'my_binary.exe'");

        action.set_program_name(None);
        assert_eq!(action.menu_item_name(), "&Close");
    }

    #[test]
    fn test_save_as_program_action() {
        let mut action = SaveAsProgramAction::new("TestPlugin", "FileGroup", 1);
        assert_eq!(action.name(), "Save As File");

        action.set_program_name(Some("test.exe"));
        assert_eq!(action.menu_item_name(), "Save 'test.exe' As...");
    }

    #[test]
    fn test_program_options_action() {
        let mut action = ProgramOptionsAction::new("TestPlugin");
        assert_eq!(action.name(), "Program Options");

        action.set_program_name(Some("myprog"));
        assert_eq!(action.menu_item_name(), "Options for 'myprog'");
    }

    #[test]
    fn test_undo_action() {
        let mut action = UndoAction::new("TestPlugin");
        assert_eq!(action.name(), "Undo");
        assert_eq!(action.key_binding(), "ctrl Z");
        assert!(!action.is_enabled());

        action.update_state(true, "Delete Selection", 3);
        assert!(action.is_enabled());
        assert_eq!(action.available_count(), 3);
    }

    #[test]
    fn test_redo_action() {
        let mut action = RedoAction::new("TestPlugin");
        assert_eq!(action.name(), "Redo");
        assert_eq!(action.key_binding(), "ctrl shift Z");
        assert!(!action.is_enabled());

        action.update_state(true, "Insert Data", 1);
        assert!(action.is_enabled());
    }

    #[test]
    fn test_multi_tab_plugin_basic() {
        let mut plugin = MultiTabPlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert_eq!(plugin.tab_count(), 0);
        assert!(!plugin.has_tabs());

        plugin.add_tab("program1.exe".to_string());
        plugin.add_tab("program2.exe".to_string());
        assert_eq!(plugin.tab_count(), 2);
        assert!(plugin.has_tabs());
        assert_eq!(plugin.selected_tab(), Some(0));
        assert_eq!(plugin.selected_tab_name(), Some("program1.exe"));
    }

    #[test]
    fn test_multi_tab_plugin_select() {
        let mut plugin = MultiTabPlugin::new("Test");
        plugin.add_tab("a".to_string());
        plugin.add_tab("b".to_string());
        plugin.add_tab("c".to_string());

        assert!(plugin.select_tab(2));
        assert_eq!(plugin.selected_tab(), Some(2));
        assert_eq!(plugin.selected_tab_name(), Some("c"));

        assert!(!plugin.select_tab(5));
        assert_eq!(plugin.selected_tab(), Some(2));
    }

    #[test]
    fn test_multi_tab_plugin_remove() {
        let mut plugin = MultiTabPlugin::new("Test");
        plugin.add_tab("a".to_string());
        plugin.add_tab("b".to_string());
        plugin.add_tab("c".to_string());

        plugin.select_tab(1);
        let removed = plugin.remove_tab(0);
        assert_eq!(removed, Some("a".to_string()));
        assert_eq!(plugin.tab_count(), 2);
        // Selected was 1, removed 0, so selected should be 0
        assert_eq!(plugin.selected_tab(), Some(0));
        assert_eq!(plugin.selected_tab_name(), Some("b"));
    }

    #[test]
    fn test_multi_tab_plugin_remove_by_name() {
        let mut plugin = MultiTabPlugin::new("Test");
        plugin.add_tab("x".to_string());
        plugin.add_tab("y".to_string());

        let removed = plugin.remove_tab_by_name("x");
        assert_eq!(removed, Some("x".to_string()));
        assert_eq!(plugin.tab_count(), 1);
    }

    #[test]
    fn test_multi_tab_plugin_remove_last() {
        let mut plugin = MultiTabPlugin::new("Test");
        plugin.add_tab("only".to_string());
        plugin.select_tab(0);

        plugin.remove_tab(0);
        assert_eq!(plugin.tab_count(), 0);
        assert_eq!(plugin.selected_tab(), None);
        assert_eq!(plugin.selected_tab_name(), None);
    }

    #[test]
    fn test_multi_tab_plugin_move() {
        let mut plugin = MultiTabPlugin::new("Test");
        plugin.add_tab("a".to_string());
        plugin.add_tab("b".to_string());
        plugin.add_tab("c".to_string());

        plugin.select_tab(0);
        assert!(plugin.move_tab(0, 2));
        assert_eq!(plugin.tab_names(), &["b", "c", "a"]);
        assert_eq!(plugin.selected_tab(), Some(2));
    }

    #[test]
    fn test_multi_tab_plugin_reorderable() {
        let mut plugin = MultiTabPlugin::new("Test");
        assert!(plugin.is_reorderable());
        plugin.set_reorderable(false);
        assert!(!plugin.is_reorderable());
    }

    #[test]
    fn test_multi_tab_plugin_tab_name() {
        let mut plugin = MultiTabPlugin::new("Test");
        plugin.add_tab("first".to_string());
        plugin.add_tab("second".to_string());

        assert_eq!(plugin.tab_name(0), Some("first"));
        assert_eq!(plugin.tab_name(1), Some("second"));
        assert_eq!(plugin.tab_name(5), None);
    }

    #[test]
    fn test_abstract_action_base() {
        let action = AbstractProgramNameSwitchingAction::new("TestAction", "Owner");
        assert_eq!(action.name(), "TestAction");
        assert_eq!(action.owner(), "Owner");
        assert!(action.is_enabled());
    }

    // --- Tests for SaveProgramAction ---

    #[test]
    fn test_save_program_action() {
        let mut action = SaveProgramAction::new("ProgramManagerPlugin");
        assert_eq!(action.name, "Save");
        assert!(!action.is_enabled()); // no unsaved changes initially

        action.update_enabled(true);
        assert!(action.is_enabled());

        action.update_enabled(false);
        assert!(!action.is_enabled());
    }

    #[test]
    fn test_save_program_action_execute() {
        let action = SaveProgramAction::new("Plugin");
        assert!(action.execute("test.exe"));
        assert!(!action.execute(""));
    }
}
