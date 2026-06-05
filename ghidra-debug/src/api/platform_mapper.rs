//! Platform mapper and disassembly result types.
//!
//! Ported from Ghidra's `DebuggerPlatformMapper` and `DisassemblyResult`.
//!
//! Provides the interface for mapping between debug target platforms
//! and Ghidra's internal platform model, including disassembly support.

use crate::api::platform::PlatformDescription;

/// Result of a disassembly operation.
///
/// Ported from Ghidra's `DisassemblyResult`.
#[derive(Debug, Clone)]
pub struct DisassemblyResult {
    /// The disassembled instruction bytes.
    pub bytes: Vec<u8>,
    /// The disassembled mnemonic string.
    pub mnemonic: String,
    /// The full disassembled instruction text.
    pub full_text: String,
    /// The length of the instruction in bytes.
    pub length: usize,
    /// Whether this is a branch/call instruction.
    pub is_branch: bool,
    /// Whether this is a call instruction.
    pub is_call: bool,
    /// Whether this is a return instruction.
    pub is_return: bool,
    /// Whether this instruction may have a delay slot.
    pub has_delay_slot: bool,
    /// The language ID used for disassembly.
    pub language_id: String,
    /// The compiler spec ID used for disassembly.
    pub compiler_spec_id: String,
}

impl DisassemblyResult {
    /// Create a new disassembly result.
    pub fn new(mnemonic: impl Into<String>, full_text: impl Into<String>, length: usize) -> Self {
        Self {
            bytes: Vec::new(),
            mnemonic: mnemonic.into(),
            full_text: full_text.into(),
            length,
            is_branch: false,
            is_call: false,
            is_return: false,
            has_delay_slot: false,
            language_id: String::new(),
            compiler_spec_id: String::new(),
        }
    }

    /// Set the instruction bytes.
    pub fn with_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.length = bytes.len();
        self.bytes = bytes;
        self
    }

    /// Mark this instruction as a branch.
    pub fn with_branch(mut self, is_branch: bool) -> Self {
        self.is_branch = is_branch;
        self
    }

    /// Mark this instruction as a call.
    pub fn with_call(mut self, is_call: bool) -> Self {
        self.is_call = is_call;
        self
    }

    /// Mark this instruction as a return.
    pub fn with_return(mut self, is_return: bool) -> Self {
        self.is_return = is_return;
        self
    }

    /// Set language and compiler spec IDs.
    pub fn with_language(mut self, lang_id: impl Into<String>, comp_id: impl Into<String>) -> Self {
        self.language_id = lang_id.into();
        self.compiler_spec_id = comp_id.into();
        self
    }
}

/// A mapper between debug target platforms and Ghidra's platform model.
///
/// Ported from Ghidra's `DebuggerPlatformMapper`.
pub trait DebuggerPlatformMapper: Send + Sync {
    /// Get the platform description for this mapper.
    fn platform(&self) -> &PlatformDescription;

    /// Get the language ID.
    fn language_id(&self) -> &str;

    /// Get the compiler spec ID.
    fn compiler_spec_id(&self) -> &str;

    /// Map a guest address to a host address.
    fn guest_to_host(&self, guest_address: u64) -> Option<u64>;

    /// Map a host address to a guest address.
    fn host_to_guest(&self, host_address: u64) -> Option<u64>;

    /// Get the register mappings.
    fn register_mappings(&self) -> &[RegisterMapping];

    /// Disassemble bytes at the given address.
    fn disassemble(&self, address: u64, bytes: &[u8]) -> Option<DisassemblyResult>;
}

/// A mapping between a register in the debug target and Ghidra.
#[derive(Debug, Clone)]
pub struct RegisterMapping {
    /// The name of the register in the debug target.
    pub target_register: String,
    /// The name of the register in Ghidra.
    pub ghidra_register: String,
    /// The bit size of the register.
    pub bit_size: usize,
    /// The bit offset within the register (for sub-registers).
    pub bit_offset: usize,
}

impl RegisterMapping {
    /// Create a new register mapping.
    pub fn new(
        target_register: impl Into<String>,
        ghidra_register: impl Into<String>,
        bit_size: usize,
    ) -> Self {
        Self {
            target_register: target_register.into(),
            ghidra_register: ghidra_register.into(),
            bit_size,
            bit_offset: 0,
        }
    }

    /// Create a register mapping with a bit offset.
    pub fn with_offset(mut self, offset: usize) -> Self {
        self.bit_offset = offset;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassembly_result_basic() {
        let result = DisassemblyResult::new("MOV", "MOV EAX, EBX", 2);
        assert_eq!(result.mnemonic, "MOV");
        assert_eq!(result.full_text, "MOV EAX, EBX");
        assert_eq!(result.length, 2);
        assert!(!result.is_branch);
    }

    #[test]
    fn test_disassembly_result_with_bytes() {
        let result = DisassemblyResult::new("NOP", "NOP", 1)
            .with_bytes(vec![0x90]);
        assert_eq!(result.bytes, vec![0x90]);
        assert_eq!(result.length, 1);
    }

    #[test]
    fn test_disassembly_result_branch() {
        let result = DisassemblyResult::new("JMP", "JMP 0x400000", 5)
            .with_branch(true);
        assert!(result.is_branch);
        assert!(!result.is_call);
    }

    #[test]
    fn test_disassembly_result_call() {
        let result = DisassemblyResult::new("CALL", "CALL 0x400000", 5)
            .with_call(true)
            .with_branch(true);
        assert!(result.is_branch);
        assert!(result.is_call);
    }

    #[test]
    fn test_disassembly_result_with_language() {
        let result = DisassemblyResult::new("NOP", "NOP", 1)
            .with_language("x86:LE:64:default", "default");
        assert_eq!(result.language_id, "x86:LE:64:default");
        assert_eq!(result.compiler_spec_id, "default");
    }

    #[test]
    fn test_register_mapping() {
        let mapping = RegisterMapping::new("eax", "EAX", 32);
        assert_eq!(mapping.target_register, "eax");
        assert_eq!(mapping.ghidra_register, "EAX");
        assert_eq!(mapping.bit_size, 32);
        assert_eq!(mapping.bit_offset, 0);
    }

    #[test]
    fn test_register_mapping_with_offset() {
        let mapping = RegisterMapping::new("ax", "EAX", 16).with_offset(0);
        assert_eq!(mapping.bit_size, 16);
        assert_eq!(mapping.bit_offset, 0);

        let mapping = RegisterMapping::new("ah", "EAX", 8).with_offset(8);
        assert_eq!(mapping.bit_size, 8);
        assert_eq!(mapping.bit_offset, 8);
    }
}
