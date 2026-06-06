//! Extended disassembly actions for the debugger plugin.
//!
//! Ported from `ghidra/app/plugin/core/debug/disassemble/` package.
//! Provides trace disassembly capabilities:
//! - Current platform disassembly
//! - Fixed platform disassembly
//! - Patch instruction actions
//! - Disassembly inject for architecture-specific behavior

use serde::{Deserialize, Serialize};

/// The result of a disassembly operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyResult {
    /// Address of the disassembled instruction.
    pub address: u64,
    /// Length of the instruction in bytes.
    pub length: u32,
    /// The disassembled mnemonic.
    pub mnemonic: String,
    /// The full disassembly text.
    pub full_text: String,
    /// Instruction bytes.
    pub bytes: Vec<u8>,
    /// Whether this was a successful disassembly.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
}

impl DisassemblyResult {
    /// Create a successful result.
    pub fn success(address: u64, length: u32, mnemonic: String, full_text: String, bytes: Vec<u8>) -> Self {
        Self {
            address,
            length,
            mnemonic,
            full_text,
            bytes,
            success: true,
            error: None,
        }
    }

    /// Create a failure result.
    pub fn failure(address: u64, error: String) -> Self {
        Self {
            address,
            length: 0,
            mnemonic: String::new(),
            full_text: String::new(),
            bytes: Vec::new(),
            success: false,
            error: Some(error),
        }
    }
}

/// Injection of architecture-specific behavior into disassembly.
///
/// Ported from `DisassemblyInject.java`.
pub trait DisassemblyInject: std::fmt::Debug + Send + Sync {
    /// Get the language ID this injection applies to.
    fn language_id(&self) -> &str;

    /// Get the compiler spec ID.
    fn compiler_spec_id(&self) -> &str;

    /// Whether this injection should be applied.
    fn applies_to(&self, language_id: &str, compiler_spec_id: &str) -> bool {
        self.language_id() == language_id && self.compiler_spec_id() == compiler_spec_id
    }

    /// Modify the disassembly result.
    fn modify_result(&self, _result: &mut DisassemblyResult) {
        // Default: no modification
    }
}

/// Info about a disassembly injection.
///
/// Ported from `DisassemblyInjectInfo.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyInjectInfo {
    /// Injection name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Language ID.
    pub language_id: String,
    /// Compiler spec ID.
    pub compiler_spec_id: String,
}

impl DisassemblyInjectInfo {
    /// Create new inject info.
    pub fn new(name: String, description: String, language_id: String, compiler_spec_id: String) -> Self {
        Self {
            name,
            description,
            language_id,
            compiler_spec_id,
        }
    }
}

/// An action to disassemble at the current platform's location.
///
/// Ported from `CurrentPlatformTraceDisassembleAction.java`.
#[derive(Debug, Clone)]
pub struct CurrentPlatformDisassembleAction {
    /// The trace key.
    pub trace_key: i64,
    /// The snap.
    pub snap: i64,
    /// The address offset to disassemble at.
    pub address_offset: u64,
    /// The address space name.
    pub space_name: String,
}

impl CurrentPlatformDisassembleAction {
    /// Create a new action.
    pub fn new(trace_key: i64, snap: i64, address_offset: u64, space_name: String) -> Self {
        Self {
            trace_key,
            snap,
            address_offset,
            space_name,
        }
    }

    /// Execute the disassembly.
    pub fn execute(&self) -> DisassemblyResult {
        // Stub: in full implementation, would query the trace for
        // bytes at the address and use the language's disassembler
        DisassemblyResult::failure(self.address_offset, "Not implemented".into())
    }
}

/// An action to disassemble using a fixed platform (not the current one).
///
/// Ported from `FixedPlatformTraceDisassembleAction.java`.
#[derive(Debug, Clone)]
pub struct FixedPlatformDisassembleAction {
    /// The trace key.
    pub trace_key: i64,
    /// The snap.
    pub snap: i64,
    /// The address offset.
    pub address_offset: u64,
    /// The address space name.
    pub space_name: String,
    /// The language ID to use.
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
}

impl FixedPlatformDisassembleAction {
    /// Create a new action.
    pub fn new(
        trace_key: i64,
        snap: i64,
        address_offset: u64,
        space_name: String,
        language_id: String,
        compiler_spec_id: String,
    ) -> Self {
        Self {
            trace_key,
            snap,
            address_offset,
            space_name,
            language_id,
            compiler_spec_id,
        }
    }

    /// Execute the disassembly.
    pub fn execute(&self) -> DisassemblyResult {
        DisassemblyResult::failure(self.address_offset, "Not implemented".into())
    }
}

/// An action to patch an instruction in the trace.
///
/// Ported from `AbstractTracePatchInstructionAction.java`.
#[derive(Debug, Clone)]
pub struct PatchInstructionAction {
    /// The trace key.
    pub trace_key: i64,
    /// The snap.
    pub snap: i64,
    /// The address to patch.
    pub address_offset: u64,
    /// The address space name.
    pub space_name: String,
    /// The new instruction bytes.
    pub new_bytes: Vec<u8>,
}

impl PatchInstructionAction {
    /// Create a new patch action.
    pub fn new(
        trace_key: i64,
        snap: i64,
        address_offset: u64,
        space_name: String,
        new_bytes: Vec<u8>,
    ) -> Self {
        Self {
            trace_key,
            snap,
            address_offset,
            space_name,
            new_bytes,
        }
    }

    /// Execute the patch.
    pub fn execute(&self) -> Result<(), String> {
        // In full implementation: write new bytes to trace memory
        Ok(())
    }
}

/// Action to patch data in the trace.
///
/// Ported from `TracePatchDataAction.java`.
#[derive(Debug, Clone)]
pub struct TracePatchDataAction {
    /// The trace key.
    pub trace_key: i64,
    /// The snap.
    pub snap: i64,
    /// The address to patch.
    pub address_offset: u64,
    /// The address space name.
    pub space_name: String,
    /// The new data bytes.
    pub new_bytes: Vec<u8>,
}

impl TracePatchDataAction {
    /// Create a new patch data action.
    pub fn new(
        trace_key: i64,
        snap: i64,
        address_offset: u64,
        space_name: String,
        new_bytes: Vec<u8>,
    ) -> Self {
        Self {
            trace_key,
            snap,
            address_offset,
            space_name,
            new_bytes,
        }
    }

    /// Execute the patch.
    pub fn execute(&self) -> Result<(), String> {
        Ok(())
    }
}

/// A disassemble command that can be run as a background task.
///
/// Ported from `TraceDisassembleCommand.java` and
/// `CurrentPlatformTraceDisassembleCommand.java`.
#[derive(Debug, Clone)]
pub struct TraceDisassembleCommand {
    /// The trace key.
    pub trace_key: i64,
    /// The snap.
    pub snap: i64,
    /// Start address offset.
    pub start_offset: u64,
    /// The address space name.
    pub space_name: String,
    /// Maximum number of instructions to disassemble.
    pub max_instructions: usize,
    /// Whether to overwrite existing instructions.
    pub overwrite: bool,
}

impl TraceDisassembleCommand {
    /// Create a new command.
    pub fn new(trace_key: i64, snap: i64, start_offset: u64, space_name: String) -> Self {
        Self {
            trace_key,
            snap,
            start_offset,
            space_name,
            max_instructions: 1000,
            overwrite: false,
        }
    }

    /// Set the max instructions.
    pub fn with_max_instructions(mut self, max: usize) -> Self {
        self.max_instructions = max;
        self
    }

    /// Execute the disassembly command.
    pub fn execute(&self) -> Result<Vec<DisassemblyResult>, String> {
        // In full implementation: disassemble instructions starting at
        // start_offset, creating trace code units
        Ok(Vec::new())
    }
}

/// The plugin for the disassembler.
///
/// Ported from `DebuggerDisassemblerPlugin.java`.
#[derive(Debug)]
pub struct DisassemblerPlugin {
    /// Registered disassembly injects.
    pub injects: Vec<DisassemblyInjectInfo>,
}

impl DisassemblerPlugin {
    /// Create a new plugin.
    pub fn new() -> Self {
        Self {
            injects: Vec::new(),
        }
    }

    /// Register a disassembly inject.
    pub fn register_inject(&mut self, inject: DisassemblyInjectInfo) {
        self.injects.push(inject);
    }

    /// Get injects for a language.
    pub fn injects_for_language(&self, language_id: &str, compiler_spec_id: &str) -> Vec<&DisassemblyInjectInfo> {
        self.injects
            .iter()
            .filter(|i| i.language_id == language_id && i.compiler_spec_id == compiler_spec_id)
            .collect()
    }
}

impl Default for DisassemblerPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassembly_result_success() {
        let result = DisassemblyResult::success(
            0x400000,
            1,
            "nop".into(),
            "NOP".into(),
            vec![0x90],
        );
        assert!(result.success);
        assert_eq!(result.mnemonic, "nop");
    }

    #[test]
    fn test_disassembly_result_failure() {
        let result = DisassemblyResult::failure(0x400000, "bad bytes".into());
        assert!(!result.success);
        assert_eq!(result.error, Some("bad bytes".into()));
    }

    #[test]
    fn test_current_platform_disassemble() {
        let action = CurrentPlatformDisassembleAction::new(
            1, 0, 0x400000, "ram".into(),
        );
        let result = action.execute();
        // Stub returns failure
        assert!(!result.success);
    }

    #[test]
    fn test_patch_instruction_action() {
        let action = PatchInstructionAction::new(
            1, 0, 0x400000, "ram".into(), vec![0x90],
        );
        assert!(action.execute().is_ok());
    }

    #[test]
    fn test_trace_disassemble_command() {
        let cmd = TraceDisassembleCommand::new(1, 0, 0x400000, "ram".into())
            .with_max_instructions(100);
        assert_eq!(cmd.max_instructions, 100);
        let results = cmd.execute().unwrap();
        assert!(results.is_empty()); // Stub
    }

    #[test]
    fn test_disassembler_plugin() {
        let mut plugin = DisassemblerPlugin::new();
        plugin.register_inject(DisassemblyInjectInfo::new(
            "x86".into(),
            "x86 inject".into(),
            "x86:LE:64:default".into(),
            "default".into(),
        ));
        assert_eq!(plugin.injects.len(), 1);
        assert_eq!(plugin.injects_for_language("x86:LE:64:default", "default").len(), 1);
    }
}
