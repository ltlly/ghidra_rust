//! Select All action -- Rust port of
//! `ghidra.app.plugin.core.decompile.actions.SelectAllAction`.
//!
//! A simple action that selects all text in the decompiler panel.
//! Bound to Ctrl+A when the decompiler panel has focus.

use std::fmt;

use super::action_context::DecompilerActionContext;

// ---------------------------------------------------------------------------
// SelectAllAction
// ---------------------------------------------------------------------------

/// Action that selects all text in the decompiler panel.
///
/// In Ghidra this is a `DockingAction` that calls
/// `panel.selectAll(EventTrigger.GUI_ACTION)`.  The action is always
/// enabled when the decompiler panel is visible and has content.
///
/// # Key Binding
///
/// The standard key binding is `Ctrl+A` (or `Cmd+A` on macOS).
///
/// # Menu Placement
///
/// This action is not placed in the popup menu.  It is a keyboard-only
/// action registered as a local action on the decompiler provider.
#[derive(Debug)]
pub struct SelectAllAction {
    /// The action name.
    name: String,
    /// The owner (plugin class name).
    owner: String,
    /// The key binding description.
    key_binding: String,
    /// Whether the action is currently enabled.
    enabled: bool,
    /// The help topic.
    help_topic: String,
}

impl SelectAllAction {
    /// The action name.
    pub const ACTION_NAME: &'static str = "Select All";

    /// The default key binding.
    pub const DEFAULT_KEY_BINDING: &'static str = "Ctrl+A";

    /// The help topic for selection actions.
    pub const HELP_TOPIC: &'static str = "Selection";

    /// Create a new Select All action.
    ///
    /// # Arguments
    ///
    /// * `owner` - The plugin class name (typically `"Decompile"`).
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: Self::ACTION_NAME.to_string(),
            owner: owner.into(),
            key_binding: Self::DEFAULT_KEY_BINDING.to_string(),
            enabled: true,
            help_topic: Self::HELP_TOPIC.to_string(),
        }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the owner (plugin class name).
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns the key binding.
    pub fn key_binding(&self) -> &str {
        &self.key_binding
    }

    /// Returns the help topic.
    pub fn help_topic(&self) -> &str {
        &self.help_topic
    }

    /// Returns whether the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether the action is valid for the given context.
    ///
    /// The action is valid when the decompiler panel has content.
    pub fn is_valid_context(&self, _ctx: &DecompilerActionContext) -> bool {
        true
    }

    /// Whether the action is enabled for the given context.
    ///
    /// The action is always enabled when the decompiler is not busy.
    pub fn is_enabled_for_context(&self, ctx: &DecompilerActionContext) -> bool {
        !ctx.is_decompiling()
    }

    /// Execute the select-all action.
    ///
    /// Returns the action result.  In the full implementation, this calls
    /// `panel.selectAll(EventTrigger.GUI_ACTION)` on the decompiler panel.
    pub fn action_performed(&self, ctx: &DecompilerActionContext) -> SelectAllResult {
        if ctx.is_decompiling() {
            return SelectAllResult::Busy;
        }
        if !self.enabled {
            return SelectAllResult::Disabled;
        }
        // In the full implementation, this would call panel.selectAll().
        SelectAllResult::Selected
    }

    /// Get the help location for this action.
    pub fn help_location(&self) -> (&str, &str) {
        (&self.help_topic, &self.name)
    }

    /// Dispose the action.
    pub fn dispose(&mut self) {
        self.enabled = false;
    }
}

impl Default for SelectAllAction {
    fn default() -> Self {
        Self::new("Decompile")
    }
}

impl fmt::Display for SelectAllAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SelectAllAction(owner={}, key={})", self.owner, self.key_binding)
    }
}

// ---------------------------------------------------------------------------
// SelectAllResult
// ---------------------------------------------------------------------------

/// The result of executing the Select All action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelectAllResult {
    /// All text was selected.
    Selected,
    /// The decompiler was busy.
    Busy,
    /// The action was disabled.
    Disabled,
}

impl fmt::Display for SelectAllResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SelectAllResult::Selected => write!(f, "Selected"),
            SelectAllResult::Busy => write!(f, "Busy"),
            SelectAllResult::Disabled => write!(f, "Disabled"),
        }
    }
}

// ---------------------------------------------------------------------------
// EventTrigger -- mirrors Ghidra's EventTrigger enum
// ---------------------------------------------------------------------------

/// The trigger that caused a UI event.
///
/// In Ghidra this is `docking.widgets.EventTrigger`.  The panel uses
/// this to distinguish between user-initiated and programmatic changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventTrigger {
    /// The event was triggered by a GUI action (mouse click, key press).
    GuiAction,
    /// The event was triggered programmatically (e.g., by a script).
    ApiCall,
}

impl Default for EventTrigger {
    fn default() -> Self {
        Self::GuiAction
    }
}

impl fmt::Display for EventTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventTrigger::GuiAction => write!(f, "GUI_ACTION"),
            EventTrigger::ApiCall => write!(f, "API_CALL"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;

    // --- SelectAllAction ---

    #[test]
    fn test_select_all_new() {
        let action = SelectAllAction::new("Decompile");
        assert_eq!(action.name(), "Select All");
        assert_eq!(action.owner(), "Decompile");
        assert_eq!(action.key_binding(), "Ctrl+A");
        assert!(action.is_enabled());
    }

    #[test]
    fn test_select_all_default() {
        let action = SelectAllAction::default();
        assert_eq!(action.owner(), "Decompile");
    }

    #[test]
    fn test_select_all_set_enabled() {
        let mut action = SelectAllAction::new("Test");
        assert!(action.is_enabled());
        action.set_enabled(false);
        assert!(!action.is_enabled());
    }

    #[test]
    fn test_select_all_help_location() {
        let action = SelectAllAction::new("Test");
        let (topic, name) = action.help_location();
        assert_eq!(topic, "Selection");
        assert_eq!(name, "Select All");
    }

    #[test]
    fn test_select_all_action_performed_normal() {
        let action = SelectAllAction::new("Test");
        let ctx = DecompilerActionContext::new(Address::new(0x1000), false, 0);
        assert_eq!(action.action_performed(&ctx), SelectAllResult::Selected);
    }

    #[test]
    fn test_select_all_action_performed_busy() {
        let action = SelectAllAction::new("Test");
        let ctx = DecompilerActionContext::new(Address::new(0x1000), true, 0);
        assert_eq!(action.action_performed(&ctx), SelectAllResult::Busy);
    }

    #[test]
    fn test_select_all_action_performed_disabled() {
        let mut action = SelectAllAction::new("Test");
        action.set_enabled(false);
        let ctx = DecompilerActionContext::new(Address::new(0x1000), false, 0);
        assert_eq!(action.action_performed(&ctx), SelectAllResult::Disabled);
    }

    #[test]
    fn test_select_all_is_enabled_for_context() {
        let action = SelectAllAction::new("Test");

        // Not decompiling -> enabled.
        let ctx = DecompilerActionContext::new(Address::new(0x1000), false, 0);
        assert!(action.is_enabled_for_context(&ctx));

        // Decompiling -> not enabled.
        let ctx_busy = DecompilerActionContext::new(Address::new(0x1000), true, 0);
        assert!(!action.is_enabled_for_context(&ctx_busy));
    }

    #[test]
    fn test_select_all_is_valid_context() {
        let action = SelectAllAction::new("Test");
        let ctx = DecompilerActionContext::new(Address::new(0x1000), false, 0);
        assert!(action.is_valid_context(&ctx));
    }

    #[test]
    fn test_select_all_dispose() {
        let mut action = SelectAllAction::new("Test");
        assert!(action.is_enabled());
        action.dispose();
        assert!(!action.is_enabled());
    }

    #[test]
    fn test_select_all_display() {
        let action = SelectAllAction::new("MyPlugin");
        let s = format!("{}", action);
        assert!(s.contains("MyPlugin"));
        assert!(s.contains("Ctrl+A"));
    }

    // --- SelectAllResult ---

    #[test]
    fn test_select_all_result_display() {
        assert_eq!(format!("{}", SelectAllResult::Selected), "Selected");
        assert_eq!(format!("{}", SelectAllResult::Busy), "Busy");
        assert_eq!(format!("{}", SelectAllResult::Disabled), "Disabled");
    }

    #[test]
    fn test_select_all_result_equality() {
        assert_eq!(SelectAllResult::Selected, SelectAllResult::Selected);
        assert_ne!(SelectAllResult::Selected, SelectAllResult::Busy);
    }

    // --- EventTrigger ---

    #[test]
    fn test_event_trigger_default() {
        assert_eq!(EventTrigger::default(), EventTrigger::GuiAction);
    }

    #[test]
    fn test_event_trigger_display() {
        assert_eq!(format!("{}", EventTrigger::GuiAction), "GUI_ACTION");
        assert_eq!(format!("{}", EventTrigger::ApiCall), "API_CALL");
    }

    #[test]
    fn test_event_trigger_equality() {
        assert_eq!(EventTrigger::GuiAction, EventTrigger::GuiAction);
        assert_ne!(EventTrigger::GuiAction, EventTrigger::ApiCall);
    }
}
