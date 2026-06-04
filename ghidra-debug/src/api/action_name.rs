//! ActionName - names of common debugger commands.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The name of a common debugger command that a target may support.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionName {
    /// Continue / resume execution.
    Continue,
    /// Single-step the target.
    Step,
    /// Step into a call.
    StepInto,
    /// Step over a call.
    StepOver,
    /// Step out of the current function.
    StepOut,
    /// Kill / terminate the target.
    Kill,
    /// Attach to a running target.
    Attach,
    /// Detach from the target.
    Detach,
    /// Launch a new target.
    Launch,
    /// Connect to a target.
    Connect,
    /// Disconnect from the target.
    Disconnect,
    /// Activate / focus on a thread or process.
    Activate,
    /// Show/display something.
    Show,
    /// Go to an address.
    GoTo,
    /// Refresh state.
    Refresh,
    /// Write memory.
    WriteMemory,
    /// Read memory.
    ReadMemory,
    /// Write register.
    WriteRegister,
    /// Read registers.
    ReadRegisters,
    /// Add a breakpoint.
    AddBreakpoint,
    /// Toggle a breakpoint.
    ToggleBreakpoint,
    /// Delete a breakpoint.
    DeleteBreakpoint,
    /// Enable a breakpoint.
    EnableBreakpoint,
    /// Disable a breakpoint.
    DisableBreakpoint,
    /// Custom or unknown action.
    Custom(String),
}

impl fmt::Display for ActionName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Continue => write!(f, "Continue"),
            Self::Step => write!(f, "Step"),
            Self::StepInto => write!(f, "Step Into"),
            Self::StepOver => write!(f, "Step Over"),
            Self::StepOut => write!(f, "Step Out"),
            Self::Kill => write!(f, "Kill"),
            Self::Attach => write!(f, "Attach"),
            Self::Detach => write!(f, "Detach"),
            Self::Launch => write!(f, "Launch"),
            Self::Connect => write!(f, "Connect"),
            Self::Disconnect => write!(f, "Disconnect"),
            Self::Activate => write!(f, "Activate"),
            Self::Show => write!(f, "Show"),
            Self::GoTo => write!(f, "Go To"),
            Self::Refresh => write!(f, "Refresh"),
            Self::WriteMemory => write!(f, "Write Memory"),
            Self::ReadMemory => write!(f, "Read Memory"),
            Self::WriteRegister => write!(f, "Write Register"),
            Self::ReadRegisters => write!(f, "Read Registers"),
            Self::AddBreakpoint => write!(f, "Add Breakpoint"),
            Self::ToggleBreakpoint => write!(f, "Toggle Breakpoint"),
            Self::DeleteBreakpoint => write!(f, "Delete Breakpoint"),
            Self::EnableBreakpoint => write!(f, "Enable Breakpoint"),
            Self::DisableBreakpoint => write!(f, "Disable Breakpoint"),
            Self::Custom(s) => write!(f, "{}", s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display() {
        assert_eq!(ActionName::Continue.to_string(), "Continue");
        assert_eq!(ActionName::StepOut.to_string(), "Step Out");
        assert_eq!(
            ActionName::Custom("Foo".into()).to_string(),
            "Foo"
        );
    }

    #[test]
    fn test_serde() {
        let a = ActionName::Kill;
        let json = serde_json::to_string(&a).unwrap();
        let back: ActionName = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }
}
