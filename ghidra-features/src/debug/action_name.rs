//! Action names for the Debug framework.
//!
//! Ported from `ghidra.debug.api.target.ActionName` — common debugger
//! action identifiers that map across different back-end debuggers.

use std::fmt;

use super::core_types::TraceExecutionState;

// ---------------------------------------------------------------------------
// ActionShow
// ---------------------------------------------------------------------------

/// When an action should appear in menus.
///
/// Ported from `ActionName.Show`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionShow {
    /// Built-in action (not shown in general menus; the tool handles it).
    BuiltIn,
    /// Only shown in address-based contexts (e.g., right-click in listing).
    Address,
    /// Shown in all contexts (default).
    Extended,
}

// ---------------------------------------------------------------------------
// ActionEnabler
// ---------------------------------------------------------------------------

/// Determines when an action is enabled based on execution state.
///
/// Ported from `ActionName.Enabler`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionEnabler {
    /// Always enabled.
    Always,
    /// Enabled when the target is not running.
    NotRunning,
    /// Enabled when the target is not stopped.
    NotStopped,
    /// Enabled when the target is not terminated.
    NotDead,
}

impl ActionEnabler {
    /// Check if the action should be enabled for the given execution state.
    pub fn is_enabled(&self, state: Option<TraceExecutionState>) -> bool {
        match self {
            ActionEnabler::Always => true,
            ActionEnabler::NotRunning => {
                !matches!(state, Some(TraceExecutionState::Running))
            }
            ActionEnabler::NotStopped => {
                !matches!(state, Some(TraceExecutionState::Stopped))
            }
            ActionEnabler::NotDead => {
                !matches!(state, Some(TraceExecutionState::Terminated))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ActionName
// ---------------------------------------------------------------------------

/// A name for a commonly-recognized target action.
///
/// Ported from `ghidra.debug.api.target.ActionName`. Many common debugger
/// commands have varying names across different back-end debuggers. This
/// provides a common set of identifiers with associated display text and
/// icons.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActionName {
    /// The action identifier.
    name: String,
    /// When to show in menus.
    pub show: ActionShow,
    /// When the action is enabled.
    pub enabler: ActionEnabler,
    /// Default display text.
    display: String,
    /// Default text for confirm buttons.
    pub ok_text: String,
}

impl ActionName {
    /// Create a new custom action name.
    pub fn new(
        name: impl Into<String>,
        show: ActionShow,
        enabler: ActionEnabler,
        display: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            show,
            enabler,
            display: display.into(),
            ok_text: "OK".to_string(),
        }
    }

    /// Create a custom action name with an OK text.
    pub fn with_ok_text(
        name: impl Into<String>,
        show: ActionShow,
        enabler: ActionEnabler,
        display: impl Into<String>,
        ok_text: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            show,
            enabler,
            display: display.into(),
            ok_text: ok_text.into(),
        }
    }

    /// Returns the action name identifier.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the display text.
    pub fn display(&self) -> &str {
        &self.display
    }

    // --- Stock action names ---

    /// Refresh the target state.
    pub fn refresh() -> Self {
        Self::with_ok_text("refresh", ActionShow::Extended, ActionEnabler::Always, "Refresh", "Refresh")
    }

    /// Activate a given object and optionally a time.
    pub fn activate() -> Self {
        Self::new("activate", ActionShow::BuiltIn, ActionEnabler::Always, "Activate")
    }

    /// A weaker form of activate (highlight/select).
    pub fn focus() -> Self {
        Self::new("focus", ActionShow::BuiltIn, ActionEnabler::Always, "Focus")
    }

    /// Toggle a state (e.g., breakpoint).
    pub fn toggle() -> Self {
        Self::new("toggle", ActionShow::BuiltIn, ActionEnabler::Always, "Toggle")
    }

    /// Delete an object.
    pub fn delete() -> Self {
        Self::new("delete", ActionShow::BuiltIn, ActionEnabler::Always, "Delete")
    }

    /// Execute a CLI command.
    pub fn execute() -> Self {
        Self::new("execute", ActionShow::BuiltIn, ActionEnabler::Always, "Execute")
    }

    /// Connect the back-end to a (usually remote) target.
    pub fn connect() -> Self {
        Self::with_ok_text("connect", ActionShow::Extended, ActionEnabler::Always, "Connect", "Connect")
    }

    /// Attach to a running process.
    pub fn attach() -> Self {
        Self::with_ok_text("attach", ActionShow::Extended, ActionEnabler::Always, "Attach", "Attach")
    }

    /// Detach from a process.
    pub fn detach() -> Self {
        Self::with_ok_text("detach", ActionShow::Extended, ActionEnabler::Always, "Detach", "Detach")
    }

    /// Launch a new process.
    pub fn launch() -> Self {
        Self::with_ok_text("launch", ActionShow::Extended, ActionEnabler::Always, "Launch", "Launch")
    }

    /// Kill a process.
    pub fn kill() -> Self {
        Self::with_ok_text("kill", ActionShow::BuiltIn, ActionEnabler::NotDead, "Kill", "Kill")
    }

    /// Resume execution.
    pub fn resume() -> Self {
        Self::with_ok_text("resume", ActionShow::BuiltIn, ActionEnabler::NotRunning, "Resume", "Resume")
    }

    /// Interrupt execution.
    pub fn interrupt() -> Self {
        Self::with_ok_text("interrupt", ActionShow::BuiltIn, ActionEnabler::NotStopped, "Interrupt", "Interrupt")
    }

    /// Step into.
    pub fn step_into() -> Self {
        Self::with_ok_text("step_into", ActionShow::BuiltIn, ActionEnabler::NotRunning, "Step Into", "Step")
    }

    /// Step over.
    pub fn step_over() -> Self {
        Self::with_ok_text("step_over", ActionShow::BuiltIn, ActionEnabler::NotRunning, "Step Over", "Step")
    }

    /// Step out.
    pub fn step_out() -> Self {
        Self::with_ok_text("step_out", ActionShow::BuiltIn, ActionEnabler::NotRunning, "Step Out", "Step")
    }

    /// Step back (time-travel).
    pub fn step_back() -> Self {
        Self::with_ok_text("step_back", ActionShow::BuiltIn, ActionEnabler::NotRunning, "Step Back", "Back")
    }

    /// Skip over (emulator).
    pub fn step_skip() -> Self {
        Self::with_ok_text("step_skip", ActionShow::BuiltIn, ActionEnabler::NotRunning, "Skip Over", "Skip")
    }

    /// Extended/custom stepping action.
    pub fn step_ext() -> Self {
        Self::with_ok_text("step_ext", ActionShow::Address, ActionEnabler::NotRunning, "Extended Step", "Step")
    }

    /// Set a software execution breakpoint.
    pub fn break_sw_execute() -> Self {
        Self::with_ok_text("break_sw_execute", ActionShow::BuiltIn, ActionEnabler::Always, "Set Software Breakpoint", "Set")
    }

    /// Set a hardware execution breakpoint.
    pub fn break_hw_execute() -> Self {
        Self::with_ok_text("break_hw_execute", ActionShow::BuiltIn, ActionEnabler::Always, "Set Hardware Breakpoint", "Set")
    }

    /// Set a read breakpoint.
    pub fn break_read() -> Self {
        Self::with_ok_text("break_read", ActionShow::BuiltIn, ActionEnabler::Always, "Set Read Breakpoint", "Set")
    }

    /// Set a write breakpoint.
    pub fn break_write() -> Self {
        Self::with_ok_text("break_write", ActionShow::BuiltIn, ActionEnabler::Always, "Set Write Breakpoint", "Set")
    }

    /// Set an access (read+write) breakpoint.
    pub fn break_access() -> Self {
        Self::with_ok_text("break_access", ActionShow::BuiltIn, ActionEnabler::Always, "Set Access Breakpoint", "Set")
    }

    /// Extended/custom breakpoint action.
    pub fn break_ext() -> Self {
        Self::with_ok_text("break_ext", ActionShow::BuiltIn, ActionEnabler::Always, "Set Breakpoint", "Set")
    }

    /// Read memory.
    pub fn read_mem() -> Self {
        Self::with_ok_text("read_mem", ActionShow::BuiltIn, ActionEnabler::Always, "Read Memory", "Read")
    }

    /// Write memory.
    pub fn write_mem() -> Self {
        Self::with_ok_text("write_mem", ActionShow::BuiltIn, ActionEnabler::Always, "Write Memory", "Write")
    }

    /// Write a register.
    pub fn write_reg() -> Self {
        Self::with_ok_text("write_reg", ActionShow::BuiltIn, ActionEnabler::NotRunning, "Write Register", "Write")
    }
}

impl fmt::Display for ActionName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enabler_always() {
        assert!(ActionEnabler::Always.is_enabled(None));
        assert!(ActionEnabler::Always.is_enabled(Some(TraceExecutionState::Running)));
        assert!(ActionEnabler::Always.is_enabled(Some(TraceExecutionState::Terminated)));
    }

    #[test]
    fn test_enabler_not_running() {
        assert!(ActionEnabler::NotRunning.is_enabled(None));
        assert!(ActionEnabler::NotRunning.is_enabled(Some(TraceExecutionState::Stopped)));
        assert!(!ActionEnabler::NotRunning.is_enabled(Some(TraceExecutionState::Running)));
    }

    #[test]
    fn test_enabler_not_stopped() {
        assert!(ActionEnabler::NotStopped.is_enabled(Some(TraceExecutionState::Running)));
        assert!(!ActionEnabler::NotStopped.is_enabled(Some(TraceExecutionState::Stopped)));
    }

    #[test]
    fn test_enabler_not_dead() {
        assert!(ActionEnabler::NotDead.is_enabled(Some(TraceExecutionState::Alive)));
        assert!(ActionEnabler::NotDead.is_enabled(Some(TraceExecutionState::Stopped)));
        assert!(!ActionEnabler::NotDead.is_enabled(Some(TraceExecutionState::Terminated)));
    }

    #[test]
    fn test_stock_actions() {
        let resume = ActionName::resume();
        assert_eq!(resume.name(), "resume");
        assert_eq!(resume.display(), "Resume");
        assert_eq!(resume.show, ActionShow::BuiltIn);
        assert!(resume.enabler.is_enabled(Some(TraceExecutionState::Stopped)));
        assert!(!resume.enabler.is_enabled(Some(TraceExecutionState::Running)));

        let kill = ActionName::kill();
        assert_eq!(kill.name(), "kill");
        assert!(!kill.enabler.is_enabled(Some(TraceExecutionState::Terminated)));

        let launch = ActionName::launch();
        assert_eq!(launch.name(), "launch");
        assert_eq!(launch.show, ActionShow::Extended);

        let bp = ActionName::break_sw_execute();
        assert_eq!(bp.name(), "break_sw_execute");
    }

    #[test]
    fn test_custom_action() {
        let action = ActionName::new(
            "custom_action",
            ActionShow::Extended,
            ActionEnabler::Always,
            "My Custom Action",
        );
        assert_eq!(action.name(), "custom_action");
        assert_eq!(action.display(), "My Custom Action");
    }

    #[test]
    fn test_action_display() {
        assert_eq!(format!("{}", ActionName::resume()), "Resume");
        assert_eq!(format!("{}", ActionName::step_into()), "Step Into");
    }
}
