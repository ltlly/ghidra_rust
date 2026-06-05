//! Disassembly actions for the debugger plugin.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.disassemble` package.
//! These actions trigger disassembly at the current debug location, either
//! using the current platform's language or a user-selected language.

use serde::{Deserialize, Serialize};

/// The mode for disassembly in a trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DisassemblyMode {
    /// Disassemble using the current platform's language at the address.
    CurrentPlatform,
    /// Disassemble using a fixed (user-specified) platform language.
    FixedPlatform,
    /// Patch existing instructions (modify bytes then re-disassemble).
    Patch,
}

impl Default for DisassemblyMode {
    fn default() -> Self {
        Self::CurrentPlatform
    }
}

/// Configuration for a disassembly action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyConfig {
    /// The disassembly mode.
    pub mode: DisassemblyMode,
    /// The language ID to use (for FixedPlatform mode).
    pub language_id: Option<String>,
    /// The compiler spec ID to use.
    pub compiler_spec_id: Option<String>,
    /// The address at which to begin disassembly.
    pub start_address: u64,
    /// Maximum number of instructions to disassemble.
    pub max_instructions: u32,
    /// Whether to overwrite existing code.
    pub overwrite: bool,
}

impl DisassemblyConfig {
    /// Create a config for current-platform disassembly at the given address.
    pub fn current_platform(start_address: u64) -> Self {
        Self {
            mode: DisassemblyMode::CurrentPlatform,
            language_id: None,
            compiler_spec_id: None,
            start_address,
            max_instructions: 1,
            overwrite: false,
        }
    }

    /// Create a config for fixed-platform disassembly.
    pub fn fixed_platform(start_address: u64, language_id: impl Into<String>) -> Self {
        Self {
            mode: DisassemblyMode::FixedPlatform,
            language_id: Some(language_id.into()),
            compiler_spec_id: None,
            start_address,
            max_instructions: 1,
            overwrite: false,
        }
    }

    /// Set the maximum number of instructions.
    pub fn with_max_instructions(mut self, max: u32) -> Self {
        self.max_instructions = max;
        self
    }

    /// Set whether to overwrite existing code.
    pub fn with_overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite = overwrite;
        self
    }

    /// Set the compiler spec ID.
    pub fn with_compiler_spec(mut self, spec_id: impl Into<String>) -> Self {
        self.compiler_spec_id = Some(spec_id.into());
        self
    }
}

/// Information about a disassembly injection point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyInjectInfo {
    /// The address at which bytes were injected.
    pub address: u64,
    /// The injected bytes.
    pub bytes: Vec<u8>,
    /// The language ID used for disassembly.
    pub language_id: String,
}

impl DisassemblyInjectInfo {
    /// Create new injection info.
    pub fn new(address: u64, bytes: Vec<u8>, language_id: impl Into<String>) -> Self {
        Self {
            address,
            bytes,
            language_id: language_id.into(),
        }
    }

    /// Get the number of injected bytes.
    pub fn byte_count(&self) -> usize {
        self.bytes.len()
    }

    /// Get the end address (exclusive).
    pub fn end_address(&self) -> u64 {
        self.address + self.bytes.len() as u64
    }
}

/// Result of a disassembly action.
#[derive(Debug, Clone)]
pub struct DisassemblyResult {
    /// The trace key this was applied to.
    pub trace_key: i64,
    /// The address where disassembly started.
    pub start_address: u64,
    /// Number of instructions disassembled.
    pub instruction_count: u32,
    /// The total bytes consumed.
    pub bytes_consumed: u32,
    /// Any errors encountered.
    pub errors: Vec<String>,
}

impl DisassemblyResult {
    /// Create a new successful result.
    pub fn success(trace_key: i64, start_address: u64, count: u32, bytes: u32) -> Self {
        Self {
            trace_key,
            start_address,
            instruction_count: count,
            bytes_consumed: bytes,
            errors: Vec::new(),
        }
    }

    /// Whether the disassembly had any errors.
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
}

/// An action for patching instruction bytes in a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracePatchInstructionAction {
    /// The trace key.
    pub trace_key: i64,
    /// The address to patch.
    pub address: u64,
    /// The new bytes.
    pub new_bytes: Vec<u8>,
    /// The language ID for re-disassembly.
    pub language_id: String,
}

impl TracePatchInstructionAction {
    /// Create a new patch action.
    pub fn new(
        trace_key: i64,
        address: u64,
        new_bytes: Vec<u8>,
        language_id: impl Into<String>,
    ) -> Self {
        Self {
            trace_key,
            address,
            new_bytes,
            language_id: language_id.into(),
        }
    }

    /// Get the end address of the patch region.
    pub fn end_address(&self) -> u64 {
        self.address + self.new_bytes.len() as u64
    }
}

/// An action for patching data bytes in a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracePatchDataAction {
    /// The trace key.
    pub trace_key: i64,
    /// The address to patch.
    pub address: u64,
    /// The new data bytes.
    pub new_bytes: Vec<u8>,
}

impl TracePatchDataAction {
    /// Create a new data patch action.
    pub fn new(trace_key: i64, address: u64, new_bytes: Vec<u8>) -> Self {
        Self {
            trace_key,
            address,
            new_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassembly_config_current_platform() {
        let config = DisassemblyConfig::current_platform(0x400000);
        assert_eq!(config.mode, DisassemblyMode::CurrentPlatform);
        assert_eq!(config.start_address, 0x400000);
        assert_eq!(config.max_instructions, 1);
    }

    #[test]
    fn test_disassembly_config_fixed_platform() {
        let config = DisassemblyConfig::fixed_platform(0x400000, "x86:LE:64:default")
            .with_max_instructions(100)
            .with_overwrite(true);
        assert_eq!(config.mode, DisassemblyMode::FixedPlatform);
        assert_eq!(config.max_instructions, 100);
        assert!(config.overwrite);
        assert_eq!(config.language_id.as_deref(), Some("x86:LE:64:default"));
    }

    #[test]
    fn test_disassembly_inject_info() {
        let info = DisassemblyInjectInfo::new(0x400000, vec![0x90, 0xCC], "x86:LE:64:default");
        assert_eq!(info.byte_count(), 2);
        assert_eq!(info.end_address(), 0x400002);
    }

    #[test]
    fn test_disassembly_result_success() {
        let result = DisassemblyResult::success(1, 0x400000, 5, 20);
        assert!(!result.has_errors());
        assert_eq!(result.instruction_count, 5);
    }

    #[test]
    fn test_disassembly_result_with_errors() {
        let mut result = DisassemblyResult::success(1, 0x400000, 0, 0);
        result.errors.push("Invalid opcode".into());
        assert!(result.has_errors());
    }

    #[test]
    fn test_patch_instruction_action() {
        let action = TracePatchInstructionAction::new(
            1,
            0x400000,
            vec![0x90, 0x90, 0x90],
            "x86:LE:64:default",
        );
        assert_eq!(action.end_address(), 0x400003);
    }

    #[test]
    fn test_patch_data_action() {
        let action = TracePatchDataAction::new(1, 0x400000, vec![0xFF, 0x00]);
        assert_eq!(action.new_bytes.len(), 2);
    }

    #[test]
    fn test_disassembly_mode_default() {
        assert_eq!(DisassemblyMode::default(), DisassemblyMode::CurrentPlatform);
    }
}
