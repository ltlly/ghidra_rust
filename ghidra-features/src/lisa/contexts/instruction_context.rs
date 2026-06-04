//! Instruction context types for p-code analysis.
//!
//! Ported from `InstructionContext.java` and `HighInstructionContext.java`
//! in the Lisa extension.

/// Context for a machine instruction being analyzed.
#[derive(Debug, Clone)]
pub struct InstructionContext {
    /// The instruction address.
    pub address: u64,
    /// The length of the instruction in bytes.
    pub length: u32,
    /// The mnemonic (e.g., "MOV", "ADD").
    pub mnemonic: String,
    /// The p-code operations for this instruction.
    pub num_pcode_ops: u32,
}

impl InstructionContext {
    /// Create a new instruction context.
    pub fn new(
        address: u64,
        length: u32,
        mnemonic: impl Into<String>,
        num_pcode_ops: u32,
    ) -> Self {
        Self {
            address,
            length,
            mnemonic: mnemonic.into(),
            num_pcode_ops,
        }
    }

    /// The address of the byte immediately after this instruction.
    pub fn next_address(&self) -> u64 {
        self.address + self.length as u64
    }
}

/// Context for a high-level (decompiler) instruction.
///
/// Contains additional information about the decompiled representation
/// of an instruction, including the source statement and the p-code
/// operations it expands to.
#[derive(Debug, Clone)]
pub struct HighInstructionContext {
    /// The underlying instruction context.
    pub instruction: InstructionContext,
    /// The decompiled source line, if available.
    pub source_line: Option<String>,
    /// The high-level p-code address.
    pub high_pcode_address: u64,
}

impl HighInstructionContext {
    /// Create a new high instruction context.
    pub fn new(instruction: InstructionContext, high_pcode_address: u64) -> Self {
        Self {
            instruction,
            source_line: None,
            high_pcode_address,
        }
    }

    /// Set the source line.
    pub fn with_source_line(mut self, line: impl Into<String>) -> Self {
        self.source_line = Some(line.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_context() {
        let ctx = InstructionContext::new(0x1000, 3, "MOV", 1);
        assert_eq!(ctx.next_address(), 0x1003);
        assert_eq!(ctx.mnemonic, "MOV");
    }

    #[test]
    fn test_high_instruction_context() {
        let inst = InstructionContext::new(0x1000, 3, "ADD", 2);
        let ctx = HighInstructionContext::new(inst, 0x2000)
            .with_source_line("x = y + z");
        assert_eq!(ctx.source_line, Some("x = y + z".to_string()));
        assert_eq!(ctx.instruction.mnemonic, "ADD");
    }
}
