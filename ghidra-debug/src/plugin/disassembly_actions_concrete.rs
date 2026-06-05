//! Concrete disassembly action types for trace debugging.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.disassemble` package:
//! - `AbstractTraceDisassembleAction`: Base action for trace disassembly.
//! - `CurrentPlatformTracePatchInstructionAction`: Patch using current platform language.
//! - `FixedPlatformTracePatchInstructionAction`: Patch using a fixed platform language.

use serde::{Deserialize, Serialize};

use super::disassemble::TraceDisassembleCommand;

/// Abstract base for trace disassembly actions.
///
/// Ported from Ghidra's `AbstractTraceDisassembleAction`. In Ghidra, this is
/// a Swing DockingAction; here we capture the configuration and execution model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbstractTraceDisassembleAction {
    /// Action name.
    pub name: String,
    /// The plugin name providing this action.
    pub plugin_name: String,
    /// The trace platform language ID.
    pub language_id: String,
    /// Whether this is for a fixed or current platform.
    pub platform_mode: PlatformMode,
}

/// Whether the action uses the current or a fixed platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PlatformMode {
    /// Use the current trace's platform.
    CurrentPlatform,
    /// Use a specific fixed platform.
    FixedPlatform,
}

impl AbstractTraceDisassembleAction {
    /// Create a new abstract disassemble action.
    pub fn new(name: impl Into<String>, plugin_name: impl Into<String>, mode: PlatformMode) -> Self {
        Self {
            name: name.into(),
            plugin_name: plugin_name.into(),
            language_id: String::new(),
            platform_mode: mode,
        }
    }

    /// Create a disassemble command from this action's configuration.
    pub fn create_command(
        &self,
        trace_id: impl Into<String>,
        snap: i64,
        address: u64,
    ) -> TraceDisassembleCommand {
        TraceDisassembleCommand::new(trace_id, snap, address, &self.language_id)
    }
}

/// Action to patch instructions using the current platform.
///
/// Ported from Ghidra's `CurrentPlatformTracePatchInstructionAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentPlatformTracePatchInstructionAction {
    /// The base action.
    pub base: AbstractTraceDisassembleAction,
    /// The assembler language to use.
    pub assembler_language_id: String,
}

impl CurrentPlatformTracePatchInstructionAction {
    /// Create a new current-platform patch action.
    pub fn new(plugin_name: impl Into<String>) -> Self {
        Self {
            base: AbstractTraceDisassembleAction::new(
                "PatchInstruction",
                plugin_name,
                PlatformMode::CurrentPlatform,
            ),
            assembler_language_id: String::new(),
        }
    }
}

/// Action to patch instructions using a fixed platform.
///
/// Ported from Ghidra's `FixedPlatformTracePatchInstructionAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixedPlatformTracePatchInstructionAction {
    /// The base action.
    pub base: AbstractTraceDisassembleAction,
    /// The fixed language ID.
    pub fixed_language_id: String,
    /// The fixed compiler spec ID.
    pub fixed_compiler_spec_id: String,
}

impl FixedPlatformTracePatchInstructionAction {
    /// Create a new fixed-platform patch action.
    pub fn new(
        plugin_name: impl Into<String>,
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> Self {
        let lang = language_id.into();
        Self {
            base: AbstractTraceDisassembleAction {
                name: "PatchInstruction".into(),
                plugin_name: plugin_name.into(),
                language_id: lang.clone(),
                platform_mode: PlatformMode::FixedPlatform,
            },
            fixed_language_id: lang,
            fixed_compiler_spec_id: compiler_spec_id.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abstract_trace_disassemble_action() {
        let action = AbstractTraceDisassembleAction::new(
            "Disassemble",
            "DisassemblerPlugin",
            PlatformMode::CurrentPlatform,
        );
        assert_eq!(action.name, "Disassemble");
        assert_eq!(action.platform_mode, PlatformMode::CurrentPlatform);
    }

    #[test]
    fn test_create_command() {
        let action = AbstractTraceDisassembleAction {
            name: "Dis".into(),
            plugin_name: "plugin".into(),
            language_id: "x86:LE:64:default".into(),
            platform_mode: PlatformMode::FixedPlatform,
        };
        let cmd = action.create_command("trace1", 5, 0x1000);
        assert_eq!(cmd.language_id, "x86:LE:64:default");
        assert_eq!(cmd.snap, 5);
        assert_eq!(cmd.start_address, 0x1000);
    }

    #[test]
    fn test_current_platform_patch() {
        let action = CurrentPlatformTracePatchInstructionAction::new("TestPlugin");
        assert_eq!(action.base.platform_mode, PlatformMode::CurrentPlatform);
    }

    #[test]
    fn test_fixed_platform_patch() {
        let action = FixedPlatformTracePatchInstructionAction::new(
            "TestPlugin",
            "ARM:LE:32:v8",
            "default",
        );
        assert_eq!(action.fixed_language_id, "ARM:LE:32:v8");
        assert_eq!(action.fixed_compiler_spec_id, "default");
        assert_eq!(action.base.platform_mode, PlatformMode::FixedPlatform);
    }

    #[test]
    fn test_platform_mode_serde() {
        let mode = PlatformMode::CurrentPlatform;
        let json = serde_json::to_string(&mode).unwrap();
        let back: PlatformMode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, PlatformMode::CurrentPlatform);
    }
}
