//! Trace disassembly actions.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.disassemble` package.

use serde::{Deserialize, Serialize};

/// A command to disassemble trace memory.
///
/// Ported from Ghidra's `TraceDisassembleCommand`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDisassembleCommand {
    /// The trace ID.
    pub trace_id: String,
    /// The snap to disassemble at.
    pub snap: i64,
    /// The start address.
    pub start_address: u64,
    /// The language ID to use for disassembly.
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
    /// Whether to follow branches.
    pub follow_flow: bool,
}

impl TraceDisassembleCommand {
    /// Create a new disassemble command.
    pub fn new(
        trace_id: impl Into<String>,
        snap: i64,
        start_address: u64,
        language_id: impl Into<String>,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            snap,
            start_address,
            language_id: language_id.into(),
            compiler_spec_id: "default".into(),
            follow_flow: true,
        }
    }

    /// Set the compiler spec ID.
    pub fn with_compiler_spec(mut self, id: impl Into<String>) -> Self {
        self.compiler_spec_id = id.into();
        self
    }

    /// Set whether to follow control flow.
    pub fn with_follow_flow(mut self, follow: bool) -> Self {
        self.follow_flow = follow;
        self
    }
}

/// An action to disassemble at the current platform's location.
///
/// Ported from Ghidra's `CurrentPlatformTraceDisassembleAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassembleAction {
    /// Display name.
    pub name: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// Whether this uses the current platform.
    pub use_current_platform: bool,
    /// The fixed platform language ID (if not using current).
    pub fixed_language_id: Option<String>,
}

impl DisassembleAction {
    /// Create an action that uses the current platform.
    pub fn current_platform(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            enabled: true,
            use_current_platform: true,
            fixed_language_id: None,
        }
    }

    /// Create an action with a fixed platform.
    pub fn fixed_platform(name: impl Into<String>, language_id: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            enabled: true,
            use_current_platform: false,
            fixed_language_id: Some(language_id.into()),
        }
    }
}

/// An action to patch instructions in the trace.
///
/// Ported from Ghidra's `TracePatchDataAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracePatchAction {
    /// The action name.
    pub name: String,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl TracePatchAction {
    /// Create a new patch action.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            enabled: true,
        }
    }
}

/// Injection info for custom disassembly.
///
/// Ported from Ghidra's `DisassemblyInjectInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyInjectInfo {
    /// The language ID this injection applies to.
    pub language_id: String,
    /// The name of the injection.
    pub name: String,
    /// Whether this injection is enabled.
    pub enabled: bool,
}

impl DisassemblyInjectInfo {
    /// Create a new injection info.
    pub fn new(language_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            language_id: language_id.into(),
            name: name.into(),
            enabled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassemble_command() {
        let cmd = TraceDisassembleCommand::new("trace1", 0, 0x400000, "x86:LE:64:default")
            .with_compiler_spec("gcc")
            .with_follow_flow(false);
        assert_eq!(cmd.trace_id, "trace1");
        assert_eq!(cmd.start_address, 0x400000);
        assert!(!cmd.follow_flow);
    }

    #[test]
    fn test_disassemble_action() {
        let action = DisassembleAction::current_platform("Disassemble");
        assert!(action.use_current_platform);
        assert!(action.fixed_language_id.is_none());

        let action = DisassembleAction::fixed_platform("Disassemble x86", "x86:LE:64:default");
        assert!(!action.use_current_platform);
        assert_eq!(action.fixed_language_id.as_deref(), Some("x86:LE:64:default"));
    }

    #[test]
    fn test_trace_patch_action() {
        let action = TracePatchAction::new("Patch Instruction");
        assert_eq!(action.name, "Patch Instruction");
        assert!(action.enabled);
    }

    #[test]
    fn test_disassembly_inject_info() {
        let info = DisassemblyInjectInfo::new("x86:LE:64:default", "CustomInject");
        assert_eq!(info.language_id, "x86:LE:64:default");
        assert!(info.enabled);
    }

    #[test]
    fn test_disassemble_command_serde() {
        let cmd = TraceDisassembleCommand::new("trace1", 0, 0x400000, "x86:LE:64:default");
        let json = serde_json::to_string(&cmd).unwrap();
        let back: TraceDisassembleCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(back.start_address, 0x400000);
    }
}
