//! DebuggerResources - resource identifiers and constants for the debugger.
//!
//! Ported from Ghidra's `DebuggerResources` in `ghidra.app.plugin.core.debug`.
//! Contains icon names, action group names, and UI resource constants used
//! throughout the debugger plugin infrastructure.

use serde::{Deserialize, Serialize};

/// Icon resource names for debugger actions and UI elements.
///
/// Ported from Ghidra's `DebuggerResources` constants.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DebuggerIcon {
    /// Connect to target.
    Connect,
    /// Disconnect from target.
    Disconnect,
    /// Resume execution.
    Resume,
    /// Suspend execution.
    Suspend,
    /// Step into.
    StepInto,
    /// Step over.
    StepOver,
    /// Step out.
    StepOut,
    /// Step back (reverse execution).
    StepBack,
    /// Kill the target process.
    Kill,
    /// Add a breakpoint.
    AddBreakpoint,
    /// Remove a breakpoint.
    RemoveBreakpoint,
    /// Enable a breakpoint.
    EnableBreakpoint,
    /// Disable a breakpoint.
    DisableBreakpoint,
    /// Snapshot icon.
    Snapshot,
    /// Thread icon.
    Thread,
    /// Process icon.
    Process,
    /// Module icon.
    Module,
    /// Register icon.
    Register,
    /// Memory icon.
    Memory,
    /// Stack frame icon.
    StackFrame,
    /// Watch expression icon.
    Watch,
    /// Console icon.
    Console,
    /// Track location icon.
    TrackLocation,
    /// Map icon.
    Map,
    /// Export icon.
    Export,
    /// Custom icon (by resource name).
    Custom(String),
}

impl DebuggerIcon {
    /// Get the Ghidra resource path for this icon.
    pub fn resource_path(&self) -> String {
        match self {
            Self::Connect => "images/connect.png".into(),
            Self::Disconnect => "images/disconnect.png".into(),
            Self::Resume => "images/resume.png".into(),
            Self::Suspend => "images/suspend.png".into(),
            Self::StepInto => "images/stepInto.png".into(),
            Self::StepOver => "images/stepOver.png".into(),
            Self::StepOut => "images/stepOut.png".into(),
            Self::StepBack => "images/stepBack.png".into(),
            Self::Kill => "images/kill.png".into(),
            Self::AddBreakpoint => "images/addBreakpoint.png".into(),
            Self::RemoveBreakpoint => "images/removeBreakpoint.png".into(),
            Self::EnableBreakpoint => "images/enableBreakpoint.png".into(),
            Self::DisableBreakpoint => "images/disableBreakpoint.png".into(),
            Self::Snapshot => "images/snapshot.png".into(),
            Self::Thread => "images/thread.png".into(),
            Self::Process => "images/process.png".into(),
            Self::Module => "images/module.png".into(),
            Self::Register => "images/register.png".into(),
            Self::Memory => "images/memory.png".into(),
            Self::StackFrame => "images/stackFrame.png".into(),
            Self::Watch => "images/watch.png".into(),
            Self::Console => "images/console.png".into(),
            Self::TrackLocation => "images/trackLocation.png".into(),
            Self::Map => "images/map.png".into(),
            Self::Export => "images/export.png".into(),
            Self::Custom(name) => name.clone(),
        }
    }
}

/// Action group names used to organize debugger menus and toolbars.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionGroup {
    /// Connection management actions.
    Connection,
    /// Execution control actions (resume, suspend, step).
    Control,
    /// Breakpoint management actions.
    Breakpoints,
    /// Navigation actions.
    Navigation,
    /// Mapping actions.
    Mapping,
    /// Export actions.
    Export,
    /// Custom group.
    Custom(String),
}

impl ActionGroup {
    /// Get the string name for this group (for Ghidra API compatibility).
    pub fn name(&self) -> String {
        match self {
            Self::Connection => "Debugger.Connection".into(),
            Self::Control => "Debugger.Control".into(),
            Self::Breakpoints => "Debugger.Breakpoints".into(),
            Self::Navigation => "Debugger.Navigation".into(),
            Self::Mapping => "Debugger.Mapping".into(),
            Self::Export => "Debugger.Export".into(),
            Self::Custom(name) => name.clone(),
        }
    }
}

/// Tool/action category identifiers for debugger actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ToolActionCategory {
    /// Actions that operate on a live target.
    TargetAction,
    /// Actions that operate on the trace database.
    TraceAction,
    /// Actions that operate on the listing view.
    ListingAction,
    /// Actions that operate on the memory view.
    MemoryAction,
}

/// Constants for key binding domains used in the debugger.
pub const KEY_BINDINGS_DOMAIN: &str = "Debugger";
/// Plugin package name for the debugger.
pub const PLUGIN_PACKAGE_NAME: &str = "Debugger Plugin Package";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icon_resource_path() {
        assert_eq!(DebuggerIcon::Connect.resource_path(), "images/connect.png");
        assert_eq!(
            DebuggerIcon::StepInto.resource_path(),
            "images/stepInto.png"
        );
        assert_eq!(
            DebuggerIcon::Custom("custom/icon.png".into()).resource_path(),
            "custom/icon.png"
        );
    }

    #[test]
    fn test_action_group_name() {
        assert_eq!(ActionGroup::Connection.name(), "Debugger.Connection");
        assert_eq!(ActionGroup::Control.name(), "Debugger.Control");
        assert_eq!(
            ActionGroup::Custom("MyGroup".into()).name(),
            "MyGroup"
        );
    }

    #[test]
    fn test_icon_serde() {
        let icon = DebuggerIcon::Resume;
        let json = serde_json::to_string(&icon).unwrap();
        let back: DebuggerIcon = serde_json::from_str(&json).unwrap();
        assert_eq!(back, DebuggerIcon::Resume);
    }

    #[test]
    fn test_icon_variants_distinct() {
        assert_ne!(DebuggerIcon::Connect, DebuggerIcon::Disconnect);
        assert_ne!(DebuggerIcon::StepInto, DebuggerIcon::StepOver);
    }

    #[test]
    fn test_all_icons_have_paths() {
        let icons = vec![
            DebuggerIcon::Connect,
            DebuggerIcon::Disconnect,
            DebuggerIcon::Resume,
            DebuggerIcon::Suspend,
            DebuggerIcon::StepInto,
            DebuggerIcon::StepOver,
            DebuggerIcon::StepOut,
            DebuggerIcon::StepBack,
            DebuggerIcon::Kill,
            DebuggerIcon::AddBreakpoint,
            DebuggerIcon::RemoveBreakpoint,
            DebuggerIcon::EnableBreakpoint,
            DebuggerIcon::DisableBreakpoint,
            DebuggerIcon::Snapshot,
            DebuggerIcon::Thread,
            DebuggerIcon::Process,
            DebuggerIcon::Module,
            DebuggerIcon::Register,
            DebuggerIcon::Memory,
            DebuggerIcon::StackFrame,
            DebuggerIcon::Watch,
            DebuggerIcon::Console,
            DebuggerIcon::TrackLocation,
            DebuggerIcon::Map,
            DebuggerIcon::Export,
        ];
        for icon in icons {
            let path = icon.resource_path();
            assert!(path.ends_with(".png"), "Icon {:?} path should end with .png", icon);
        }
    }

    #[test]
    fn test_action_group_categories() {
        assert_ne!(ActionGroup::Connection.name(), ActionGroup::Control.name());
        assert!(ActionGroup::Connection.name().starts_with("Debugger."));
    }

    #[test]
    fn test_key_bindings_domain() {
        assert_eq!(KEY_BINDINGS_DOMAIN, "Debugger");
    }

    #[test]
    fn test_tool_action_category() {
        let cat = ToolActionCategory::TargetAction;
        assert_eq!(cat, ToolActionCategory::TargetAction);
        assert_ne!(cat, ToolActionCategory::TraceAction);
    }
}
