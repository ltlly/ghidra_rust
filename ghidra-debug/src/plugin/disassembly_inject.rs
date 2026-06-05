//! DisassemblyInject - injects disassembly results into a trace.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.disassemble.DisassemblyInject`
//! and related types.

use serde::{Deserialize, Serialize};

/// The result of a disassembly operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyResult {
    /// The address at which disassembly started.
    pub start_address: u64,
    /// The address range that was disassembled.
    pub length: u64,
    /// The number of instructions produced.
    pub instruction_count: usize,
    /// Whether disassembly was truncated.
    pub truncated: bool,
    /// Error message if disassembly failed.
    pub error: Option<String>,
    /// The bytes that were disassembled.
    pub bytes: Vec<u8>,
}

impl DisassemblyResult {
    /// Create a successful disassembly result.
    pub fn success(start_address: u64, length: u64, instruction_count: usize) -> Self {
        Self {
            start_address,
            length,
            instruction_count,
            truncated: false,
            error: None,
            bytes: Vec::new(),
        }
    }

    /// Create a failed disassembly result.
    pub fn error(start_address: u64, error: impl Into<String>) -> Self {
        Self {
            start_address,
            length: 0,
            instruction_count: 0,
            truncated: false,
            error: Some(error.into()),
            bytes: Vec::new(),
        }
    }

    /// Create a truncated result.
    pub fn truncated(start_address: u64, length: u64, instruction_count: usize) -> Self {
        Self {
            start_address,
            length,
            instruction_count,
            truncated: true,
            error: None,
            bytes: Vec::new(),
        }
    }

    /// Set the raw bytes.
    pub fn with_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.bytes = bytes;
        self
    }

    /// Whether the disassembly was successful.
    pub fn is_success(&self) -> bool {
        self.error.is_none()
    }

    /// The end address of the disassembly.
    pub fn end_address(&self) -> u64 {
        self.start_address + self.length
    }
}

/// A specification for how to inject disassembly into a trace.
///
/// Ported from Ghidra's `DisassemblyInject` interface. Different
/// architectures may inject disassembly differently.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyInjectSpec {
    /// The language/processor ID.
    pub language_id: String,
    /// Whether to patch bytes before disassembling.
    pub patch_before_disassemble: bool,
    /// Whether to use the emulator for disassembly.
    pub use_emulator: bool,
    /// Maximum number of instructions to disassemble.
    pub max_instructions: Option<usize>,
    /// Maximum number of bytes to disassemble.
    pub max_bytes: Option<usize>,
}

impl DisassemblyInjectSpec {
    /// Create a new spec for the given language.
    pub fn new(language_id: impl Into<String>) -> Self {
        Self {
            language_id: language_id.into(),
            patch_before_disassemble: false,
            use_emulator: false,
            max_instructions: None,
            max_bytes: None,
        }
    }

    /// Enable patching before disassembly.
    pub fn with_patching(mut self) -> Self {
        self.patch_before_disassemble = true;
        self
    }

    /// Use the emulator for disassembly.
    pub fn with_emulator(mut self) -> Self {
        self.use_emulator = true;
        self
    }

    /// Set maximum instructions.
    pub fn with_max_instructions(mut self, max: usize) -> Self {
        self.max_instructions = Some(max);
        self
    }

    /// Set maximum bytes.
    pub fn with_max_bytes(mut self, max: usize) -> Self {
        self.max_bytes = Some(max);
        self
    }
}

/// Platform-specific disassembly injection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformDisassemblyConfig {
    /// The platform name.
    pub platform: String,
    /// The inject specification.
    pub inject: DisassemblyInjectSpec,
    /// Additional compiler spec IDs.
    pub compiler_specs: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassembly_result_success() {
        let r = DisassemblyResult::success(0x1000, 4, 1);
        assert!(r.is_success());
        assert_eq!(r.end_address(), 0x1004);
        assert_eq!(r.instruction_count, 1);
    }

    #[test]
    fn test_disassembly_result_error() {
        let r = DisassemblyResult::error(0x1000, "invalid opcode");
        assert!(!r.is_success());
        assert_eq!(r.error.as_deref(), Some("invalid opcode"));
    }

    #[test]
    fn test_disassembly_result_truncated() {
        let r = DisassemblyResult::truncated(0x1000, 100, 25);
        assert!(r.truncated);
        assert!(r.is_success());
    }

    #[test]
    fn test_disassembly_result_with_bytes() {
        let r = DisassemblyResult::success(0x1000, 3, 1).with_bytes(vec![0x90, 0x90, 0xCC]);
        assert_eq!(r.bytes.len(), 3);
    }

    #[test]
    fn test_inject_spec() {
        let spec = DisassemblyInjectSpec::new("x86:LE:64:default")
            .with_patching()
            .with_max_instructions(1000);
        assert_eq!(spec.language_id, "x86:LE:64:default");
        assert!(spec.patch_before_disassemble);
        assert_eq!(spec.max_instructions, Some(1000));
    }

    #[test]
    fn test_platform_config() {
        let config = PlatformDisassemblyConfig {
            platform: "x86_64-pc-linux-gnu".into(),
            inject: DisassemblyInjectSpec::new("x86:LE:64:default"),
            compiler_specs: vec!["default".into()],
        };
        assert_eq!(config.compiler_specs.len(), 1);
    }

    #[test]
    fn test_serde() {
        let r = DisassemblyResult::success(0x1000, 4, 1);
        let json = serde_json::to_string(&r).unwrap();
        let back: DisassemblyResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.start_address, 0x1000);
    }
}
