//! Undo plugin -- manages undo/redo actions and coordinates with domain objects.
//!
//! Ported from Ghidra's:
//! - `ghidra.app.plugin.core.progmgr.UndoAction` / `RedoAction`
//! - `ghidra.app.plugin.core.progmgr.AbstractUndoRedoAction`
//! - `ghidra.app.plugin.core.datamgr.actions.UndoArchiveTransactionAction`
//! - `ghidra.app.plugin.core.datamgr.actions.RedoArchiveTransactionAction`
//!
//! Provides the undo/redo plugin that binds undo/redo actions to a
//! program manager and domain objects.  The plugin tracks the active
//! program, manages action enablement and descriptions, and dispatches
//! undo/redo operations with optional repeat counts.

use super::undo_service::{UndoError, UndoService};

// ============================================================================
// UndoPlugin
// ============================================================================

/// Undo/redo plugin for the Ghidra tool.
///
/// Ported from the undo/redo action infrastructure in Ghidra's
/// `ghidra.app.plugin.core.progmgr` and
/// `ghidra.app.plugin.core.datamgr.actions` packages.
///
/// The plugin maintains the current undo/redo state and provides
/// actions for performing undo and redo on the active domain object
/// (typically a program or data-type archive).
///
/// # Example
///
/// ```
/// use ghidra_features::undo::undo_plugin::*;
///
/// let mut plugin = UndoPlugin::new("ProgramManager");
/// plugin.set_active_program(Some("my_binary.exe"));
/// assert_eq!(plugin.active_program(), Some("my_binary.exe"));
/// ```
#[derive(Debug)]
pub struct UndoPlugin {
    /// Name of the owner plugin.
    plugin_name: String,
    /// Name of the currently active program (if any).
    active_program: Option<String>,
    /// Undo action.
    undo_action: UndoAction,
    /// Redo action.
    redo_action: RedoAction,
    /// Whether the plugin is disposed.
    disposed: bool,
}

impl UndoPlugin {
    /// Create a new undo plugin.
    pub fn new(plugin_name: impl Into<String>) -> Self {
        let name = plugin_name.into();
        Self {
            undo_action: UndoAction::new(&name),
            redo_action: RedoAction::new(&name),
            plugin_name: name,
            active_program: None,
            disposed: false,
        }
    }

    /// Get the plugin name.
    pub fn plugin_name(&self) -> &str {
        &self.plugin_name
    }

    /// Get the active program name.
    pub fn active_program(&self) -> Option<&str> {
        self.active_program.as_deref()
    }

    /// Set the active program.
    ///
    /// When the program changes, the undo/redo actions are updated
    /// based on the new program's undo/redo state.
    pub fn set_active_program(&mut self, program: Option<&str>) {
        self.active_program = program.map(|s| s.to_string());
        self.update_action_names();
    }

    /// Update the undo/redo actions from an undo service.
    ///
    /// This is typically called whenever a transaction ends or an
    /// undo/redo operation occurs, to keep the action labels and
    /// enablement in sync.
    pub fn update_from_service(&mut self, service: &dyn UndoService) {
        let prog_name = self.active_program.clone().unwrap_or_default();

        // Update undo action.
        let can_undo = service.can_undo();
        let undo_name = service.undo_name().unwrap_or_default();
        let undo_count = service.all_undo_names().len();
        self.undo_action
            .update_state(can_undo, &undo_name, undo_count, &prog_name);

        // Update redo action.
        let can_redo = service.can_redo();
        let redo_name = service.redo_name().unwrap_or_default();
        let redo_count = service.all_redo_names().len();
        self.redo_action
            .update_state(can_redo, &redo_name, redo_count, &prog_name);
    }

    /// Execute the undo action.
    ///
    /// Returns `Ok(repeat_count)` on success, or an error if undo
    /// cannot be performed.
    pub fn execute_undo(
        &self,
        service: &mut dyn UndoService,
        repeat_count: usize,
    ) -> Result<usize, UndoError> {
        if !self.undo_action.is_enabled() {
            return Err(UndoError::NothingToUndo);
        }
        service.undo_n(repeat_count)?;
        Ok(repeat_count)
    }

    /// Execute the redo action.
    ///
    /// Returns `Ok(repeat_count)` on success, or an error if redo
    /// cannot be performed.
    pub fn execute_redo(
        &self,
        service: &mut dyn UndoService,
        repeat_count: usize,
    ) -> Result<usize, UndoError> {
        if !self.redo_action.is_enabled() {
            return Err(UndoError::NothingToRedo);
        }
        service.redo_n(repeat_count)?;
        Ok(repeat_count)
    }

    /// Get a reference to the undo action.
    pub fn undo_action(&self) -> &UndoAction {
        &self.undo_action
    }

    /// Get a reference to the redo action.
    pub fn redo_action(&self) -> &RedoAction {
        &self.redo_action
    }

    /// Dispose of the plugin, disabling all actions.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.undo_action.set_enabled(false);
        self.redo_action.set_enabled(false);
    }

    /// Whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Update action names based on the active program.
    fn update_action_names(&mut self) {
        let prog = self.active_program.as_deref();
        self.undo_action.update_program_name(prog);
        self.redo_action.update_program_name(prog);
    }
}

// ============================================================================
// UndoAction
// ============================================================================

/// Undo action for the undo plugin.
///
/// Ported from `ghidra.app.plugin.core.progmgr.UndoAction`.
///
/// This action performs undo on the active program.  Its menu label
/// dynamically updates to show the operation being undone and the
/// program name (e.g., "Undo Delete Selection (my_binary.exe)").
#[derive(Debug, Clone)]
pub struct UndoAction {
    /// Base name.
    name: String,
    /// Owner plugin name.
    owner: String,
    /// Keyboard shortcut.
    key_binding: String,
    /// Icon identifier.
    icon_id: String,
    /// Menu subgroup for ordering.
    sub_group: String,
    /// Whether the action is enabled.
    enabled: bool,
    /// Current description (includes operation and program name).
    description: String,
    /// Menu item name.
    menu_item_name: String,
    /// Number of available undo operations.
    available_count: usize,
    /// Repeat actions for multi-level undo.
    repeat_actions: Vec<RepeatAction>,
}

impl UndoAction {
    /// The default subgroup for undo in menu ordering.
    pub const SUBGROUP: &'static str = "1Undo";

    /// Create a new undo action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Undo".to_string(),
            owner: owner.into(),
            key_binding: "ctrl Z".to_string(),
            icon_id: "icon.undo".to_string(),
            sub_group: Self::SUBGROUP.to_string(),
            enabled: false,
            description: "Undo".to_string(),
            menu_item_name: "&Undo".to_string(),
            available_count: 0,
            repeat_actions: Vec::new(),
        }
    }

    /// Get the action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the keyboard shortcut.
    pub fn key_binding(&self) -> &str {
        &self.key_binding
    }

    /// Get the icon identifier.
    pub fn icon_id(&self) -> &str {
        &self.icon_id
    }

    /// Get the menu subgroup.
    pub fn sub_group(&self) -> &str {
        &self.sub_group
    }

    /// Get the description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get the menu item name.
    pub fn menu_item_name(&self) -> &str {
        &self.menu_item_name
    }

    /// Get the number of available undo operations.
    pub fn available_count(&self) -> usize {
        self.available_count
    }

    /// Get the repeat actions for multi-level undo.
    pub fn repeat_actions(&self) -> &[RepeatAction] {
        &self.repeat_actions
    }

    /// Update the action state.
    ///
    /// # Parameters
    /// - `can_undo`: whether undo is available
    /// - `undo_name`: the name of the next undoable operation
    /// - `undo_count`: the total number of undoable operations
    /// - `program_name`: the active program name (empty if none)
    pub fn update_state(
        &mut self,
        can_undo: bool,
        undo_name: &str,
        undo_count: usize,
        program_name: &str,
    ) {
        self.enabled = can_undo;
        self.available_count = undo_count;

        if can_undo && !undo_name.is_empty() {
            self.description = format!(
                "Undo {} ({})",
                undo_name,
                if program_name.is_empty() {
                    "unknown"
                } else {
                    program_name
                }
            );
        } else {
            self.description = "Undo".to_string();
        }

        // Update menu item name.
        if !program_name.is_empty() {
            self.menu_item_name = format!("&Undo {}", program_name);
        } else {
            self.menu_item_name = "&Undo".to_string();
        }

        // Rebuild repeat actions.
        self.repeat_actions.clear();
        for i in 1..=undo_count {
            self.repeat_actions.push(RepeatAction {
                name: format!("Undo #{}", i),
                repeat_count: i,
                enabled: true,
            });
        }
    }

    /// Update the program name in the menu label.
    fn update_program_name(&mut self, program: Option<&str>) {
        match program {
            Some(name) => {
                self.menu_item_name = format!("&Undo {}", name);
            }
            None => {
                self.menu_item_name = "&Undo".to_string();
            }
        }
    }
}

// ============================================================================
// RedoAction
// ============================================================================

/// Redo action for the undo plugin.
///
/// Ported from `ghidra.app.plugin.core.progmgr.RedoAction`.
///
/// This action performs redo on the active program.  Its menu label
/// dynamically updates to show the operation being redone and the
/// program name.
#[derive(Debug, Clone)]
pub struct RedoAction {
    /// Base name.
    name: String,
    /// Owner plugin name.
    owner: String,
    /// Keyboard shortcut.
    key_binding: String,
    /// Icon identifier.
    icon_id: String,
    /// Menu subgroup for ordering.
    sub_group: String,
    /// Whether the action is enabled.
    enabled: bool,
    /// Current description (includes operation and program name).
    description: String,
    /// Menu item name.
    menu_item_name: String,
    /// Number of available redo operations.
    available_count: usize,
    /// Repeat actions for multi-level redo.
    repeat_actions: Vec<RepeatAction>,
}

impl RedoAction {
    /// The default subgroup for redo in menu ordering.
    pub const SUBGROUP: &'static str = "2Redo";

    /// Create a new redo action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Redo".to_string(),
            owner: owner.into(),
            key_binding: "ctrl shift Z".to_string(),
            icon_id: "icon.redo".to_string(),
            sub_group: Self::SUBGROUP.to_string(),
            enabled: false,
            description: "Redo".to_string(),
            menu_item_name: "&Redo".to_string(),
            available_count: 0,
            repeat_actions: Vec::new(),
        }
    }

    /// Get the action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the keyboard shortcut.
    pub fn key_binding(&self) -> &str {
        &self.key_binding
    }

    /// Get the icon identifier.
    pub fn icon_id(&self) -> &str {
        &self.icon_id
    }

    /// Get the menu subgroup.
    pub fn sub_group(&self) -> &str {
        &self.sub_group
    }

    /// Get the description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get the menu item name.
    pub fn menu_item_name(&self) -> &str {
        &self.menu_item_name
    }

    /// Get the number of available redo operations.
    pub fn available_count(&self) -> usize {
        self.available_count
    }

    /// Get the repeat actions for multi-level redo.
    pub fn repeat_actions(&self) -> &[RepeatAction] {
        &self.repeat_actions
    }

    /// Update the action state.
    ///
    /// # Parameters
    /// - `can_redo`: whether redo is available
    /// - `redo_name`: the name of the next redoable operation
    /// - `redo_count`: the total number of redoable operations
    /// - `program_name`: the active program name (empty if none)
    pub fn update_state(
        &mut self,
        can_redo: bool,
        redo_name: &str,
        redo_count: usize,
        program_name: &str,
    ) {
        self.enabled = can_redo;
        self.available_count = redo_count;

        if can_redo && !redo_name.is_empty() {
            self.description = format!(
                "Redo {} ({})",
                redo_name,
                if program_name.is_empty() {
                    "unknown"
                } else {
                    program_name
                }
            );
        } else {
            self.description = "Redo".to_string();
        }

        // Update menu item name.
        if !program_name.is_empty() {
            self.menu_item_name = format!("&Redo {}", program_name);
        } else {
            self.menu_item_name = "&Redo".to_string();
        }

        // Rebuild repeat actions.
        self.repeat_actions.clear();
        for i in 1..=redo_count {
            self.repeat_actions.push(RepeatAction {
                name: format!("Redo #{}", i),
                repeat_count: i,
                enabled: true,
            });
        }
    }

    /// Update the program name in the menu label.
    fn update_program_name(&mut self, program: Option<&str>) {
        match program {
            Some(name) => {
                self.menu_item_name = format!("&Redo {}", name);
            }
            None => {
                self.menu_item_name = "&Redo".to_string();
            }
        }
    }
}

// ============================================================================
// RepeatAction
// ============================================================================

/// A repeated undo/redo action for multi-level undo/redo.
///
/// Ported from the inner `RepeatedAction` class in
/// `ghidra.app.plugin.core.progmgr.AbstractUndoRedoAction`.
///
/// When the user holds the undo/redo menu open, each item in the list
/// represents one additional level of undo/redo.  Clicking the Nth
/// item performs N undo/redo operations.
#[derive(Debug, Clone)]
pub struct RepeatAction {
    /// Display name (e.g., "Undo #3").
    pub name: String,
    /// How many times to repeat the operation.
    pub repeat_count: usize,
    /// Whether this action is enabled.
    pub enabled: bool,
}

impl RepeatAction {
    /// Create a new repeat action.
    pub fn new(name: impl Into<String>, repeat_count: usize) -> Self {
        Self {
            name: name.into(),
            repeat_count,
            enabled: true,
        }
    }
}

// ============================================================================
// UndoRedoPluginEvent
// ============================================================================

/// Events emitted by the undo plugin.
///
/// These events allow other plugins (e.g., listing, symbol tree) to
/// respond to undo/redo state changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UndoRedoPluginEvent {
    /// An undo operation was performed.
    UndoPerformed {
        /// The name of the undone operation.
        operation_name: String,
        /// The program name.
        program_name: Option<String>,
    },
    /// A redo operation was performed.
    RedoPerformed {
        /// The name of the redone operation.
        operation_name: String,
        /// The program name.
        program_name: Option<String>,
    },
    /// The undo/redo state changed (new transaction, clear, etc.).
    StateChanged {
        /// Whether undo is available.
        can_undo: bool,
        /// Whether redo is available.
        can_redo: bool,
    },
    /// The active program changed.
    ActiveProgramChanged {
        /// The new program name (None if no program).
        program_name: Option<String>,
    },
}

// ============================================================================
// UndoRedoPluginListener
// ============================================================================

/// Listener for undo plugin events.
pub trait UndoRedoPluginListener: std::fmt::Debug + Send + Sync {
    /// Called when an undo plugin event occurs.
    fn on_event(&self, event: &UndoRedoPluginEvent);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    // --- A test-only mock undo service ---

    #[derive(Debug)]
    struct TestUndoSvc {
        undo_stack: Vec<String>,
        redo_stack: Vec<String>,
    }

    impl TestUndoSvc {
        fn new() -> Self {
            Self {
                undo_stack: Vec::new(),
                redo_stack: Vec::new(),
            }
        }
        fn push_undo(&mut self, name: &str) {
            self.undo_stack.push(name.to_string());
            self.redo_stack.clear();
        }
    }

    impl UndoService for TestUndoSvc {
        fn can_undo(&self) -> bool { !self.undo_stack.is_empty() }
        fn can_redo(&self) -> bool { !self.redo_stack.is_empty() }
        fn undo(&mut self) -> Result<(), UndoError> {
            if let Some(name) = self.undo_stack.pop() {
                self.redo_stack.push(name);
                Ok(())
            } else {
                Err(UndoError::NothingToUndo)
            }
        }
        fn redo(&mut self) -> Result<(), UndoError> {
            if let Some(name) = self.redo_stack.pop() {
                self.undo_stack.push(name);
                Ok(())
            } else {
                Err(UndoError::NothingToRedo)
            }
        }
        fn undo_name(&self) -> Option<String> { self.undo_stack.last().cloned() }
        fn redo_name(&self) -> Option<String> { self.redo_stack.last().cloned() }
        fn all_undo_names(&self) -> Vec<String> { self.undo_stack.iter().rev().cloned().collect() }
        fn all_redo_names(&self) -> Vec<String> { self.redo_stack.iter().rev().cloned().collect() }
        fn clear_undo(&mut self) { self.undo_stack.clear(); self.redo_stack.clear(); }
    }

    // --- UndoPlugin tests ---

    #[test]
    fn test_undo_plugin_creation() {
        let plugin = UndoPlugin::new("ProgramManager");
        assert_eq!(plugin.plugin_name(), "ProgramManager");
        assert!(plugin.active_program().is_none());
        assert!(!plugin.is_disposed());
    }

    #[test]
    fn test_undo_plugin_set_active_program() {
        let mut plugin = UndoPlugin::new("PM");
        plugin.set_active_program(Some("test.exe"));
        assert_eq!(plugin.active_program(), Some("test.exe"));

        plugin.set_active_program(None);
        assert!(plugin.active_program().is_none());
    }

    #[test]
    fn test_undo_plugin_update_from_service() {
        let mut plugin = UndoPlugin::new("PM");
        plugin.set_active_program(Some("my_binary"));

        let mut svc = TestUndoSvc::new();
        svc.push_undo("Delete Selection");
        svc.push_undo("Insert Data");

        plugin.update_from_service(&svc);

        assert!(plugin.undo_action().is_enabled());
        assert!(!plugin.redo_action().is_enabled());
        assert_eq!(plugin.undo_action().available_count(), 2);
        assert!(
            plugin
                .undo_action()
                .description()
                .contains("Insert Data")
        );
        assert!(
            plugin
                .undo_action()
                .description()
                .contains("my_binary")
        );
    }

    #[test]
    fn test_undo_plugin_execute_undo() {
        let mut plugin = UndoPlugin::new("PM");
        let mut svc = TestUndoSvc::new();
        svc.push_undo("Edit A");
        svc.push_undo("Edit B");

        plugin.update_from_service(&svc);
        let result = plugin.execute_undo(&mut svc, 1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
    }

    #[test]
    fn test_undo_plugin_execute_undo_when_disabled() {
        let plugin = UndoPlugin::new("PM");
        let mut svc = TestUndoSvc::new();

        let result = plugin.execute_undo(&mut svc, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_undo_plugin_execute_redo() {
        let mut plugin = UndoPlugin::new("PM");
        let mut svc = TestUndoSvc::new();
        svc.push_undo("Edit A");
        plugin.update_from_service(&svc);

        // Undo to enable redo.
        plugin.execute_undo(&mut svc, 1).unwrap();
        plugin.update_from_service(&svc);

        let result = plugin.execute_redo(&mut svc, 1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_undo_plugin_dispose() {
        let mut plugin = UndoPlugin::new("PM");
        plugin.dispose();
        assert!(plugin.is_disposed());
        assert!(!plugin.undo_action().is_enabled());
        assert!(!plugin.redo_action().is_enabled());
    }

    // --- UndoAction tests ---

    #[test]
    fn test_undo_action_creation() {
        let action = UndoAction::new("PM");
        assert_eq!(action.name(), "Undo");
        assert_eq!(action.key_binding(), "ctrl Z");
        assert_eq!(action.icon_id(), "icon.undo");
        assert!(!action.is_enabled());
    }

    #[test]
    fn test_undo_action_update_state() {
        let mut action = UndoAction::new("PM");
        action.update_state(true, "Delete Selection", 3, "my_binary");

        assert!(action.is_enabled());
        assert_eq!(action.available_count(), 3);
        assert!(action.description().contains("Delete Selection"));
        assert!(action.description().contains("my_binary"));
        assert!(action.menu_item_name().contains("my_binary"));
        assert_eq!(action.repeat_actions().len(), 3);
    }

    #[test]
    fn test_undo_action_update_state_no_program() {
        let mut action = UndoAction::new("PM");
        action.update_state(true, "Edit", 1, "");

        assert!(action.is_enabled());
        assert!(action.description().contains("unknown"));
        assert_eq!(action.menu_item_name(), "&Undo");
    }

    #[test]
    fn test_undo_action_update_state_disabled() {
        let mut action = UndoAction::new("PM");
        action.update_state(false, "", 0, "prog");

        assert!(!action.is_enabled());
        assert_eq!(action.description(), "Undo");
    }

    // --- RedoAction tests ---

    #[test]
    fn test_redo_action_creation() {
        let action = RedoAction::new("PM");
        assert_eq!(action.name(), "Redo");
        assert_eq!(action.key_binding(), "ctrl shift Z");
        assert_eq!(action.icon_id(), "icon.redo");
        assert!(!action.is_enabled());
    }

    #[test]
    fn test_redo_action_update_state() {
        let mut action = RedoAction::new("PM");
        action.update_state(true, "Insert Data", 2, "test.exe");

        assert!(action.is_enabled());
        assert_eq!(action.available_count(), 2);
        assert!(action.description().contains("Insert Data"));
        assert!(action.menu_item_name().contains("test.exe"));
    }

    // --- RepeatAction tests ---

    #[test]
    fn test_repeat_action() {
        let action = RepeatAction::new("Undo #3", 3);
        assert_eq!(action.name, "Undo #3");
        assert_eq!(action.repeat_count, 3);
        assert!(action.enabled);
    }

    // --- UndoRedoPluginEvent tests ---

    #[test]
    fn test_undo_event_variants() {
        let event = UndoRedoPluginEvent::UndoPerformed {
            operation_name: "Delete".into(),
            program_name: Some("test.exe".into()),
        };
        match event {
            UndoRedoPluginEvent::UndoPerformed {
                operation_name,
                program_name,
            } => {
                assert_eq!(operation_name, "Delete");
                assert_eq!(program_name, Some("test.exe".into()));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_state_changed_event() {
        let event = UndoRedoPluginEvent::StateChanged {
            can_undo: true,
            can_redo: false,
        };
        assert_eq!(
            event,
            UndoRedoPluginEvent::StateChanged {
                can_undo: true,
                can_redo: false,
            }
        );
    }
}

