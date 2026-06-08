//! Instruction code unit types for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.listing.Instruction`.
//!
//! An instruction is a decoded machine instruction with mnemonic, operands,
//! control-flow type, fall-through address, delay slot metadata, and p-code
//! micro-operations.

use crate::addr::Address;

/// An instruction operand.
#[derive(Debug, Clone)]
pub enum Operand {
    /// A register operand.
    Register(String),
    /// A scalar/immediate value.
    Scalar(i64),
    /// An absolute address reference.
    Address(Address),
    /// A complex expression (e.g., "[rbp-0x8]").
    Expression(String),
    /// A floating-point immediate.
    Float(f64),
    /// No operand.
    None,
}

impl PartialEq for Operand {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Operand::Register(a), Operand::Register(b)) => a == b,
            (Operand::Scalar(a), Operand::Scalar(b)) => a == b,
            (Operand::Address(a), Operand::Address(b)) => a == b,
            (Operand::Expression(a), Operand::Expression(b)) => a == b,
            (Operand::Float(a), Operand::Float(b)) => a.to_bits() == b.to_bits(),
            (Operand::None, Operand::None) => true,
            _ => false,
        }
    }
}

impl Eq for Operand {}

impl std::hash::Hash for Operand {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Operand::Register(s) => s.hash(state),
            Operand::Scalar(v) => v.hash(state),
            Operand::Address(a) => a.hash(state),
            Operand::Expression(e) => e.hash(state),
            Operand::Float(v) => v.to_bits().hash(state),
            Operand::None => {}
        }
    }
}

impl Operand {
    /// Create a register operand.
    pub fn register(name: impl Into<String>) -> Self {
        Operand::Register(name.into())
    }

    /// Create a scalar operand.
    pub fn scalar(value: i64) -> Self {
        Operand::Scalar(value)
    }

    /// Create an address operand.
    pub fn address(addr: Address) -> Self {
        Operand::Address(addr)
    }

    /// Create an expression operand.
    pub fn expression(e: impl Into<String>) -> Self {
        Operand::Expression(e.into())
    }

    /// Returns true if this is a register operand.
    pub fn is_register(&self) -> bool {
        matches!(self, Operand::Register(_))
    }

    /// Returns true if this is a scalar operand.
    pub fn is_scalar(&self) -> bool {
        matches!(self, Operand::Scalar(_))
    }

    /// Returns true if this is an address operand.
    pub fn is_address(&self) -> bool {
        matches!(self, Operand::Address(_))
    }

    /// Returns true if this is an expression operand.
    pub fn is_expression(&self) -> bool {
        matches!(self, Operand::Expression(_))
    }
}

impl std::fmt::Display for Operand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operand::Register(name) => write!(f, "{}", name),
            Operand::Scalar(v) => write!(f, "0x{:x}", v),
            Operand::Address(addr) => write!(f, "{}", addr),
            Operand::Expression(e) => write!(f, "{}", e),
            Operand::Float(v) => write!(f, "{}", v),
            Operand::None => write!(f, ""),
        }
    }
}

/// The control-flow type of an instruction.
///
/// Corresponds to Ghidra's instruction flow type constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowType {
    /// Normal fall-through instruction.
    Normal,
    /// Unconditional jump/branch.
    Jump,
    /// Conditional jump/branch with fall-through.
    ConditionalJump,
    /// Unconditional call with fall-through.
    Call,
    /// Conditional call with fall-through.
    ConditionalCall,
    /// Return (terminal).
    Return,
    /// Terminal instruction (no fall-through, no jump).
    Terminator,
    /// System call with fall-through.
    SystemCall,
}

impl FlowType {
    /// Returns true if this is a branch (jump) flow.
    pub fn is_branch(&self) -> bool {
        matches!(self, FlowType::Jump | FlowType::ConditionalJump)
    }

    /// Returns true if this is a call flow.
    pub fn is_call(&self) -> bool {
        matches!(self, FlowType::Call | FlowType::ConditionalCall)
    }

    /// Returns true if execution can fall through past this instruction.
    pub fn has_fallthrough(&self) -> bool {
        matches!(
            self,
            FlowType::Normal
                | FlowType::ConditionalJump
                | FlowType::ConditionalCall
                | FlowType::Call
                | FlowType::SystemCall
        )
    }

    /// Returns true if this is a terminal instruction.
    pub fn is_terminator(&self) -> bool {
        matches!(self, FlowType::Jump | FlowType::Return | FlowType::Terminator)
    }

    /// Returns the flow type name.
    pub fn name(&self) -> &'static str {
        match self {
            FlowType::Normal => "NORMAL",
            FlowType::Jump => "JUMP",
            FlowType::ConditionalJump => "CONDITIONAL_JUMP",
            FlowType::Call => "CALL",
            FlowType::ConditionalCall => "CONDITIONAL_CALL",
            FlowType::Return => "RETURN",
            FlowType::Terminator => "TERMINATOR",
            FlowType::SystemCall => "SYSTEM_CALL",
        }
    }
}

impl Default for FlowType {
    fn default() -> Self {
        FlowType::Normal
    }
}

impl std::fmt::Display for FlowType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Override settings for instruction control flow.
///
/// Corresponds to `ghidra.program.model.listing.FlowOverride`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowOverride {
    /// No override; use the instruction's default flow type.
    None,
    /// Override a branch to a call.
    BranchToCall,
    /// Override a call to a branch.
    CallToBranch,
    /// Override to a return.
    Return,
    /// Override to a call and return (call + terminator).
    CallReturn,
    /// Override a call to a computed call.
    CallToComputed,
    /// Clear the flow (no flow at all).
    Clear,
}

impl FlowOverride {
    /// The mnemonic used when displaying flow overrides.
    pub fn mnemonic(self) -> &'static str {
        match self {
            FlowOverride::None => "",
            FlowOverride::BranchToCall => "CALL",
            FlowOverride::CallToBranch => "JMP",
            FlowOverride::Return => "RET",
            FlowOverride::CallReturn => "CALL/RET",
            FlowOverride::CallToComputed => "CALLCOMP",
            FlowOverride::Clear => "CLEAR",
        }
    }
}

impl Default for FlowOverride {
    fn default() -> Self {
        FlowOverride::None
    }
}

/// A decoded instruction within the listing.
///
/// Corresponds to Ghidra's `Instruction` interface. Includes the mnemonic,
/// operand list, flow type, fall-through address, delay slot metadata,
/// p-code micro-operations, and length override support.
#[derive(Debug, Clone)]
pub struct Instruction {
    /// The address of this instruction.
    pub address: Address,
    /// The effective length (may differ from parsed length if length-overridden).
    pub length: usize,
    /// The raw opcode bytes (effective length).
    pub bytes: Vec<u8>,
    /// The mnemonic string (e.g., "mov", "call", "jmp").
    pub mnemonic: String,
    /// The operand representation.
    pub operands: Vec<Operand>,
    /// The P-code micro-operation sequences.
    pub pcode_sequences: Vec<Vec<String>>,
    /// The default fall-through address (from the prototype).
    pub default_fallthrough: Option<Address>,
    /// The effective fall-through address (default or overridden).
    pub fallthrough_address: Option<Address>,
    /// The address that falls through to this instruction.
    pub fall_from: Option<Address>,
    /// The control-flow type.
    pub flow_type: FlowType,
    /// Flow override (if any).
    pub flow_override: FlowOverride,
    /// Delay slot depth (0 = no delay slots).
    pub delay_slot_depth: usize,
    /// Whether this instruction is itself in a delay slot.
    pub is_in_delay_slot: bool,
    /// Whether the length has been overridden.
    pub length_overridden: bool,
    /// The actual parsed length (before any length override).
    pub parsed_length: usize,
    /// Whether the fall-through has been overridden.
    pub fallthrough_overridden: bool,
    /// Optional label at this address.
    pub label: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Cross-reference targets.
    pub xref_targets: Vec<Address>,
}

impl Instruction {
    /// Maximum length override value.
    pub const MAX_LENGTH_OVERRIDE: usize = 7;

    /// Create a new instruction.
    pub fn new(
        address: Address,
        length: usize,
        bytes: Vec<u8>,
        mnemonic: impl Into<String>,
    ) -> Self {
        Self {
            address,
            length,
            bytes,
            mnemonic: mnemonic.into(),
            operands: Vec::new(),
            pcode_sequences: Vec::new(),
            default_fallthrough: None,
            fallthrough_address: None,
            fall_from: None,
            flow_type: FlowType::Normal,
            flow_override: FlowOverride::None,
            delay_slot_depth: 0,
            is_in_delay_slot: false,
            length_overridden: false,
            parsed_length: length,
            fallthrough_overridden: false,
            label: None,
            comment: None,
            xref_targets: Vec::new(),
        }
    }

    /// Builder: add an operand.
    pub fn with_operand(mut self, op: Operand) -> Self {
        self.operands.push(op);
        self
    }

    /// Builder: set all operands.
    pub fn with_operands(mut self, ops: Vec<Operand>) -> Self {
        self.operands = ops;
        self
    }

    /// Builder: set the flow type.
    pub fn with_flow_type(mut self, flow: FlowType) -> Self {
        self.flow_type = flow;
        self
    }

    /// Builder: set the fall-through address.
    pub fn with_fallthrough(mut self, addr: Address) -> Self {
        self.default_fallthrough = Some(addr);
        self.fallthrough_address = Some(addr);
        self
    }

    /// Builder: set delay slot metadata.
    pub fn with_delay_slot(mut self, depth: usize, is_in_slot: bool) -> Self {
        self.delay_slot_depth = depth;
        self.is_in_delay_slot = is_in_slot;
        self
    }

    /// Builder: set a label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Builder: set a comment.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Set the flow override.
    pub fn set_flow_override(&mut self, flow_override: FlowOverride) {
        self.flow_override = flow_override;
    }

    /// Override the fall-through address.
    pub fn set_fall_through(&mut self, addr: Option<Address>) {
        self.fallthrough_address = addr;
        self.fallthrough_overridden = true;
    }

    /// Clear the fall-through override, restoring the default.
    pub fn clear_fall_through_override(&mut self) {
        self.fallthrough_address = self.default_fallthrough;
        self.fallthrough_overridden = false;
    }

    /// Returns true if the fall-through has been overridden.
    pub fn is_fall_through_overridden(&self) -> bool {
        self.fallthrough_overridden
    }

    /// Set a length override.
    pub fn set_length_override(&mut self, length: usize) -> Result<(), String> {
        if length > Self::MAX_LENGTH_OVERRIDE {
            return Err(format!(
                "Length override {} exceeds maximum {}",
                length,
                Self::MAX_LENGTH_OVERRIDE
            ));
        }
        if length == 0 {
            self.length = self.parsed_length;
            self.length_overridden = false;
        } else {
            self.length = length;
            self.length_overridden = true;
        }
        Ok(())
    }

    /// Get the parsed (original) bytes.
    pub fn get_parsed_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Add a p-code micro-op sequence.
    pub fn add_pcode(&mut self, pcode: Vec<String>) {
        self.pcode_sequences.push(pcode);
    }

    /// Returns true if this is a branch instruction (jump or call).
    pub fn is_branch(&self) -> bool {
        self.flow_type.is_branch()
    }

    /// Returns true if this is a call instruction.
    pub fn is_call(&self) -> bool {
        self.flow_type.is_call()
    }

    /// Returns true if this is a return instruction.
    pub fn is_return(&self) -> bool {
        self.flow_type == FlowType::Return
    }

    /// Returns true if execution falls through to the next instruction.
    pub fn has_fallthrough(&self) -> bool {
        self.fallthrough_address.is_some() && self.flow_type != FlowType::Terminator
    }

    /// Returns true if this is a simple fall-through (no branch flow).
    pub fn is_fallthrough(&self) -> bool {
        self.flow_type == FlowType::Normal && self.flow_override == FlowOverride::None
    }

    /// The address immediately following this instruction.
    pub fn next_address(&self) -> Address {
        self.address.add(self.length as u64)
    }

    /// Get the effective fall-through address.
    pub fn get_fall_through(&self) -> Option<Address> {
        self.fallthrough_address
    }

    /// Get the default fall-through from the prototype.
    pub fn get_default_fall_through(&self) -> Option<Address> {
        self.default_fallthrough
    }

    /// Render the full instruction string for display.
    pub fn full_instruction(&self) -> String {
        if self.operands.is_empty() {
            self.mnemonic.clone()
        } else {
            let ops: Vec<String> = self.operands.iter().map(|o| o.to_string()).collect();
            format!("{} {}", self.mnemonic, ops.join(", "))
        }
    }

    /// Returns true if this address is within this instruction's range.
    pub fn contains(&self, addr: &Address) -> bool {
        addr.offset >= self.address.offset
            && addr.offset < self.address.offset + self.length as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_new() {
        let ins = Instruction::new(Address::new(0x1000), 3, vec![0x48, 0x89, 0xe5], "mov");
        assert_eq!(ins.mnemonic, "mov");
        assert_eq!(ins.length, 3);
        assert_eq!(ins.address, Address::new(0x1000));
    }

    #[test]
    fn test_instruction_full_output() {
        let ins = Instruction::new(
            Address::new(0x1000),
            5,
            vec![0xb8, 0x2a, 0x00, 0x00, 0x00],
            "mov",
        )
        .with_operand(Operand::register("eax"))
        .with_operand(Operand::scalar(0x2a));
        let full = ins.full_instruction();
        assert!(full.contains("mov"));
        assert!(full.contains("eax"));
    }

    #[test]
    fn test_instruction_length_override() {
        let mut ins = Instruction::new(Address::new(0x1000), 5, vec![0x90; 5], "nop");
        ins.set_length_override(3).unwrap();
        assert_eq!(ins.length, 3);
        assert!(ins.length_overridden);
        ins.set_length_override(0).unwrap();
        assert!(!ins.length_overridden);
        assert_eq!(ins.length, 5);
    }

    #[test]
    fn test_instruction_length_override_exceeds_max() {
        let mut ins = Instruction::new(Address::new(0x1000), 5, vec![0x90; 5], "nop");
        assert!(ins.set_length_override(10).is_err());
    }

    #[test]
    fn test_instruction_flow_types() {
        let ins = Instruction::new(Address::new(0x1000), 2, vec![0xeb, 0x10], "jmp")
            .with_flow_type(FlowType::Jump);
        assert!(ins.is_branch());
        assert!(!ins.is_call());
        assert!(!ins.has_fallthrough());
        assert!(ins.flow_type.is_terminator());
    }

    #[test]
    fn test_instruction_fallthrough() {
        let ins = Instruction::new(Address::new(0x1000), 1, vec![0x90], "nop")
            .with_fallthrough(Address::new(0x1001));
        assert!(ins.has_fallthrough());
        assert!(ins.is_fallthrough());
        assert_eq!(ins.get_fall_through(), Some(Address::new(0x1001)));
    }

    #[test]
    fn test_instruction_contains() {
        let ins = Instruction::new(Address::new(0x1000), 3, vec![0x48, 0x89, 0xe5], "mov");
        assert!(ins.contains(&Address::new(0x1000)));
        assert!(ins.contains(&Address::new(0x1002)));
        assert!(!ins.contains(&Address::new(0x1003)));
    }

    #[test]
    fn test_operand_display() {
        assert_eq!(Operand::register("rax").to_string(), "rax");
        assert_eq!(Operand::scalar(42).to_string(), "0x2a");
        assert_eq!(Operand::expression("[rbp-0x8]").to_string(), "[rbp-0x8]");
    }

    #[test]
    fn test_flow_type_display() {
        assert_eq!(FlowType::Normal.to_string(), "NORMAL");
        assert_eq!(FlowType::Call.to_string(), "CALL");
        assert_eq!(FlowType::Return.to_string(), "RETURN");
    }

    #[test]
    fn test_flow_override() {
        assert_eq!(FlowOverride::BranchToCall.mnemonic(), "CALL");
        assert_eq!(FlowOverride::CallToBranch.mnemonic(), "JMP");
        assert_eq!(FlowOverride::Return.mnemonic(), "RET");
    }
}
