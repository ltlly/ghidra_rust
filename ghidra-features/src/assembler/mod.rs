//! Assembler Integration -- assemble instructions from text.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.assembler` Java package.
//!
//! Provides the logic for assembling text representations of instructions
//! into machine code bytes, and for resolving assembly errors.
//!
//! # Architecture
//!
//! - [`AssemblyInstruction`] -- a single assembled instruction.
//! - [`AssemblyError`] -- an error during assembly.
//! - [`AssemblerResult`] -- the result of an assembly operation.
//! - [`AssemblerModel`] -- the business logic for assembly operations.
//! - [`patch_actions`] -- patch instruction and data actions, assembly ratings,
//!   and the assembler plugin model.

pub mod patch_actions;

use ghidra_core::Address;

// ============================================================================
// AssemblyInstruction -- a single assembled instruction
// ============================================================================

/// A single assembled instruction.
#[derive(Debug, Clone)]
pub struct AssemblyInstruction {
    /// The source text (e.g. `"mov rax, rbx"`).
    pub source: String,
    /// The assembled bytes.
    pub bytes: Vec<u8>,
    /// The address where this instruction should be placed.
    pub address: Address,
    /// The mnemonic (e.g. `"mov"`).
    pub mnemonic: String,
}

impl AssemblyInstruction {
    /// Create a new assembled instruction.
    pub fn new(
        source: impl Into<String>,
        bytes: Vec<u8>,
        address: Address,
    ) -> Self {
        let source = source.into();
        let mnemonic = source
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
        Self {
            source,
            bytes,
            address,
            mnemonic,
        }
    }

    /// The length of the assembled bytes.
    pub fn length(&self) -> usize {
        self.bytes.len()
    }
}

// ============================================================================
// AssemblyError -- an error during assembly
// ============================================================================

/// An error that occurred during assembly.
#[derive(Debug, Clone)]
pub struct AssemblyError {
    /// The source text that caused the error.
    pub source: String,
    /// The error message.
    pub message: String,
    /// The column position of the error (if known).
    pub column: Option<usize>,
}

impl AssemblyError {
    /// Create a new assembly error.
    pub fn new(source: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            message: message.into(),
            column: None,
        }
    }
}

impl std::fmt::Display for AssemblyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Assembly error at '{}': {}", self.source, self.message)
    }
}

impl std::error::Error for AssemblyError {}

// ============================================================================
// AssemblerResult -- result of an assembly operation
// ============================================================================

/// The result of an assembly operation.
#[derive(Debug, Clone)]
pub struct AssemblerResult {
    /// Successfully assembled instructions.
    pub instructions: Vec<AssemblyInstruction>,
    /// Assembly errors.
    pub errors: Vec<AssemblyError>,
}

impl AssemblerResult {
    /// Create a new empty result.
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Whether the assembly had any errors.
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// The total number of bytes assembled.
    pub fn total_bytes(&self) -> usize {
        self.instructions.iter().map(|i| i.length()).sum()
    }
}

impl Default for AssemblerResult {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// AssemblerModel -- assembly business logic
// ============================================================================

/// Business logic for assembling instructions.
///
/// Manages the assembly of text instructions into machine code. This is the
/// headless model behind the assembler plugin.
#[derive(Debug)]
pub struct AssemblerModel {
    /// The target architecture name.
    architecture: String,
    /// Assembled instructions.
    instructions: Vec<AssemblyInstruction>,
    /// Current insertion address.
    current_address: Address,
}

impl AssemblerModel {
    /// Create a new assembler model for the given architecture.
    pub fn new(architecture: impl Into<String>) -> Self {
        Self {
            architecture: architecture.into(),
            instructions: Vec::new(),
            current_address: Address::new(0),
        }
    }

    /// Get the target architecture.
    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    /// Set the current insertion address.
    pub fn set_address(&mut self, address: Address) {
        self.current_address = address;
    }

    /// Get the current insertion address.
    pub fn current_address(&self) -> Address {
        self.current_address
    }

    /// Add an instruction to the assembly buffer.
    pub fn add_instruction(&mut self, instruction: AssemblyInstruction) {
        self.current_address =
            Address::new(instruction.address.offset + instruction.length() as u64);
        self.instructions.push(instruction);
    }

    /// Get all assembled instructions.
    pub fn get_instructions(&self) -> &[AssemblyInstruction] {
        &self.instructions
    }

    /// Get the assembled bytes for all instructions (contiguous).
    pub fn get_bytes(&self) -> Vec<u8> {
        self.instructions
            .iter()
            .flat_map(|i| i.bytes.iter().copied())
            .collect()
    }

    /// Clear all assembled instructions.
    pub fn clear(&mut self) {
        self.instructions.clear();
    }

    /// The number of assembled instructions.
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assembly_instruction() {
        let inst = AssemblyInstruction::new("mov rax, rbx", vec![0x48, 0x89, 0xD8], Address::new(0x1000));
        assert_eq!(inst.mnemonic, "mov");
        assert_eq!(inst.length(), 3);
    }

    #[test]
    fn test_assembler_result() {
        let mut result = AssemblerResult::new();
        result.instructions.push(AssemblyInstruction::new(
            "nop",
            vec![0x90],
            Address::new(0x1000),
        ));
        assert_eq!(result.total_bytes(), 1);
        assert!(!result.has_errors());
    }

    #[test]
    fn test_assembler_result_with_errors() {
        let mut result = AssemblerResult::new();
        result
            .errors
            .push(AssemblyError::new("invalid inst", "unknown mnemonic"));
        assert!(result.has_errors());
    }

    #[test]
    fn test_assembler_model() {
        let mut model = AssemblerModel::new("x86:LE:64");
        model.set_address(Address::new(0x1000));
        model.add_instruction(AssemblyInstruction::new(
            "nop",
            vec![0x90],
            Address::new(0x1000),
        ));
        assert_eq!(model.instruction_count(), 1);
        assert_eq!(model.current_address(), Address::new(0x1001));
    }

    #[test]
    fn test_assembler_model_get_bytes() {
        let mut model = AssemblerModel::new("x86:LE:64");
        model.add_instruction(AssemblyInstruction::new(
            "nop",
            vec![0x90],
            Address::new(0x1000),
        ));
        model.add_instruction(AssemblyInstruction::new(
            "ret",
            vec![0xC3],
            Address::new(0x1001),
        ));
        assert_eq!(model.get_bytes(), vec![0x90, 0xC3]);
    }

    #[test]
    fn test_assembler_model_clear() {
        let mut model = AssemblerModel::new("x86:LE:64");
        model.add_instruction(AssemblyInstruction::new(
            "nop",
            vec![0x90],
            Address::new(0x1000),
        ));
        model.clear();
        assert_eq!(model.instruction_count(), 0);
    }
}
