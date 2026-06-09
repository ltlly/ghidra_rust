//! Pseudo disassembler.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.analysis.PseudoDisassembler`.
//!
//! Provides a lightweight, speculative disassembly facility used by
//! analysis passes that need to peek at instruction semantics without
//! permanently modifying the program listing.  Typical uses:
//!
//! - Prologue detection (trying common prologue patterns)
//! - Constant propagation (peeking at instruction operands)
//! - Function boundary detection (speculative flow following)
//!
//! The pseudo disassembler never mutates the program state; it
//! produces [`PseudoInstruction`] values that the caller inspects
//! and then discards.

use super::analyzer::{
    Address, AddressSet, FlowType, Instruction, Listing, MessageLog, Program, TaskMonitor,
};

// ---------------------------------------------------------------------------
// Pseudo instruction
// ---------------------------------------------------------------------------
/// A speculatively-disassembled instruction that has not been committed
/// to the program listing.
#[derive(Debug, Clone)]
pub struct PseudoInstruction {
    pub address: Address,
    pub length: u8,
    pub mnemonic: String,
    pub flow_type: FlowType,
    pub fall_through: Option<Address>,
    pub flows: Vec<Address>,
    pub num_operands: u8,
    /// Whether the instruction was successfully decoded.
    pub is_valid: bool,
    /// Raw bytes (if available).
    pub bytes: Vec<u8>,
}

impl PseudoInstruction {
    /// Create an invalid / undecodable pseudo-instruction.
    pub fn invalid(addr: Address) -> Self {
        Self {
            address: addr,
            length: 0,
            mnemonic: "???".to_string(),
            flow_type: FlowType::Fallthrough,
            fall_through: None,
            flows: Vec::new(),
            num_operands: 0,
            is_valid: false,
            bytes: Vec::new(),
        }
    }

    /// Create from an existing committed instruction.
    pub fn from_instruction(instr: &Instruction) -> Self {
        Self {
            address: instr.address,
            length: instr.length,
            mnemonic: instr.mnemonic.clone(),
            flow_type: instr.flow_type,
            fall_through: instr.fall_through,
            flows: instr.flows.clone(),
            num_operands: instr.num_operands,
            is_valid: true,
            bytes: Vec::new(),
        }
    }

    /// Whether this instruction is a function prologue instruction
    /// (e.g., `push rbp` on x86-64).
    pub fn is_prologue(&self) -> bool {
        // Common x86/x86-64 prologue patterns
        self.mnemonic == "push" || self.mnemonic == "enter"
    }

    /// Whether this instruction is a return.
    pub fn is_return(&self) -> bool {
        self.flow_type == FlowType::Return || self.flow_type == FlowType::ConditionalReturn
    }

    /// Whether this instruction is a call.
    pub fn is_call(&self) -> bool {
        self.flow_type.is_call()
    }

    /// Whether this instruction is a branch (conditional or not).
    pub fn is_branch(&self) -> bool {
        self.flow_type.is_jump()
    }

    /// Follow the control flow: return the next addresses that would
    /// execute after this instruction.
    pub fn get_flow_addresses(&self) -> Vec<Address> {
        let mut addrs = Vec::new();
        if let Some(ft) = self.fall_through {
            addrs.push(ft);
        }
        addrs.extend_from_slice(&self.flows);
        addrs
    }
}

impl From<Instruction> for PseudoInstruction {
    fn from(instr: Instruction) -> Self {
        Self::from_instruction(&instr)
    }
}

// ---------------------------------------------------------------------------
// PseudoDisassembler
// ---------------------------------------------------------------------------
/// Speculative disassembler that reads instructions without modifying
/// the program listing.
///
/// Used by analysis passes that need to peek at instruction semantics.
#[derive(Debug, Clone)]
pub struct PseudoDisassembler {
    /// Maximum number of instructions to disassemble in a single
    /// speculative pass.
    pub max_instruction_count: usize,
    /// Whether to follow fallthrough edges during speculative flow.
    pub follow_fallthrough: bool,
    /// Whether to follow branch targets during speculative flow.
    pub follow_branches: bool,
}

impl PseudoDisassembler {
    pub fn new() -> Self {
        Self {
            max_instruction_count: 1000,
            follow_fallthrough: true,
            follow_branches: false,
        }
    }

    /// Speculatively disassemble at `addr`, returning the pseudo
    /// instruction or `None` if no instruction exists at that address.
    pub fn disassemble_at(
        &self,
        addr: Address,
        listing: &Listing,
    ) -> Option<PseudoInstruction> {
        listing
            .get_instruction_containing(&addr)
            .map(PseudoInstruction::from_instruction)
    }

    /// Speculatively follow control flow from `start` for up to
    /// `max_instruction_count` instructions, returning all pseudo
    /// instructions encountered.
    pub fn trace_flow(
        &self,
        start: Address,
        listing: &Listing,
        existing_functions: &AddressSet,
    ) -> Vec<PseudoInstruction> {
        use std::collections::{HashSet, VecDeque};

        let mut result = Vec::new();
        let mut visited: HashSet<Address> = HashSet::new();
        let mut queue: VecDeque<Address> = VecDeque::new();
        queue.push_back(start);

        while let Some(addr) = queue.pop_front() {
            if visited.contains(&addr) {
                continue;
            }
            if result.len() >= self.max_instruction_count {
                break;
            }
            if existing_functions.contains(&addr) && addr != start {
                continue;
            }

            visited.insert(addr);

            if let Some(pseudo) = self.disassemble_at(addr, listing) {
                let flows = pseudo.get_flow_addresses();
                result.push(pseudo);

                for target in flows {
                    if !visited.contains(&target) {
                        queue.push_back(target);
                    }
                }
            } else {
                result.push(PseudoInstruction::invalid(addr));
                break;
            }
        }

        result
    }

    /// Check if `addr` looks like a function entry point by examining
    /// the first few instructions for prologue patterns.
    pub fn is_function_entry(
        &self,
        addr: Address,
        listing: &Listing,
    ) -> bool {
        let Some(first) = self.disassemble_at(addr, listing) else {
            return false;
        };
        if !first.is_valid {
            return false;
        }
        // Common x86-64 prologue: push rbp; mov rbp, rsp
        if first.is_prologue() {
            return true;
        }
        // Also check if the instruction is a call target with a
        // recognizable first instruction.
        first.mnemonic != "???"
    }

    /// Get the size of an instruction at `addr` without modifying the
    /// program.  Returns 0 if no instruction is found.
    pub fn instruction_length(&self, addr: Address, listing: &Listing) -> u8 {
        listing
            .get_instruction_containing(&addr)
            .map(|i| i.length)
            .unwrap_or(0)
    }
}

impl Default for PseudoDisassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::analyzer::{AddressRange, BasicTaskMonitor, Listing};

    fn make_listing() -> Listing {
        let mut listing = Listing::default();

        // 0x1000: push rbp (prologue)
        listing.instructions.insert(
            Address::new(0x1000),
            Instruction {
                address: Address::new(0x1000),
                length: 1,
                mnemonic: "push".into(),
                flow_type: FlowType::Fallthrough,
                fall_through: Some(Address::new(0x1001)),
                flows: vec![],
                num_operands: 1,
            },
        );

        // 0x1001: mov rbp, rsp
        listing.instructions.insert(
            Address::new(0x1001),
            Instruction {
                address: Address::new(0x1001),
                length: 3,
                mnemonic: "mov".into(),
                flow_type: FlowType::Fallthrough,
                fall_through: Some(Address::new(0x1004)),
                flows: vec![],
                num_operands: 2,
            },
        );

        // 0x1004: call 0x2000
        listing.instructions.insert(
            Address::new(0x1004),
            Instruction {
                address: Address::new(0x1004),
                length: 5,
                mnemonic: "call".into(),
                flow_type: FlowType::Call,
                fall_through: Some(Address::new(0x1009)),
                flows: vec![Address::new(0x2000)],
                num_operands: 1,
            },
        );

        // 0x1009: jz 0x1020
        listing.instructions.insert(
            Address::new(0x1009),
            Instruction {
                address: Address::new(0x1009),
                length: 2,
                mnemonic: "jz".into(),
                flow_type: FlowType::ConditionalBranch,
                fall_through: Some(Address::new(0x100b)),
                flows: vec![Address::new(0x1020)],
                num_operands: 1,
            },
        );

        // 0x100b: ret
        listing.instructions.insert(
            Address::new(0x100b),
            Instruction {
                address: Address::new(0x100b),
                length: 1,
                mnemonic: "ret".into(),
                flow_type: FlowType::Return,
                fall_through: None,
                flows: vec![],
                num_operands: 0,
            },
        );

        // 0x1020: nop
        listing.instructions.insert(
            Address::new(0x1020),
            Instruction {
                address: Address::new(0x1020),
                length: 1,
                mnemonic: "nop".into(),
                flow_type: FlowType::Fallthrough,
                fall_through: Some(Address::new(0x1021)),
                flows: vec![],
                num_operands: 0,
            },
        );

        // 0x1021: ret
        listing.instructions.insert(
            Address::new(0x1021),
            Instruction {
                address: Address::new(0x1021),
                length: 1,
                mnemonic: "ret".into(),
                flow_type: FlowType::Return,
                fall_through: None,
                flows: vec![],
                num_operands: 0,
            },
        );

        listing
    }

    #[test]
    fn test_pseudo_disassembler_creation() {
        let pd = PseudoDisassembler::new();
        assert_eq!(pd.max_instruction_count, 1000);
        assert!(pd.follow_fallthrough);
        assert!(!pd.follow_branches);
    }

    #[test]
    fn test_pseudo_disassembler_default() {
        let pd = PseudoDisassembler::default();
        assert_eq!(pd.max_instruction_count, 1000);
    }

    #[test]
    fn test_disassemble_at_existing() {
        let pd = PseudoDisassembler::new();
        let listing = make_listing();
        let pseudo = pd.disassemble_at(Address::new(0x1000), &listing);
        assert!(pseudo.is_some());
        let p = pseudo.unwrap();
        assert!(p.is_valid);
        assert_eq!(p.mnemonic, "push");
        assert_eq!(p.address, Address::new(0x1000));
    }

    #[test]
    fn test_disassemble_at_nonexistent() {
        let pd = PseudoDisassembler::new();
        let listing = make_listing();
        let pseudo = pd.disassemble_at(Address::new(0x9999), &listing);
        assert!(pseudo.is_none());
    }

    #[test]
    fn test_pseudo_instruction_invalid() {
        let p = PseudoInstruction::invalid(Address::new(0x5000));
        assert!(!p.is_valid);
        assert_eq!(p.mnemonic, "???");
        assert_eq!(p.address, Address::new(0x5000));
        assert_eq!(p.length, 0);
    }

    #[test]
    fn test_pseudo_instruction_from_instruction() {
        let instr = Instruction {
            address: Address::new(0x1000),
            length: 3,
            mnemonic: "mov".into(),
            flow_type: FlowType::Fallthrough,
            fall_through: Some(Address::new(0x1003)),
            flows: vec![],
            num_operands: 2,
        };
        let pseudo = PseudoInstruction::from_instruction(&instr);
        assert!(pseudo.is_valid);
        assert_eq!(pseudo.address, Address::new(0x1000));
        assert_eq!(pseudo.mnemonic, "mov");
        assert_eq!(pseudo.length, 3);
    }

    #[test]
    fn test_pseudo_instruction_from_trait() {
        let instr = Instruction {
            address: Address::new(0x1000),
            length: 1,
            mnemonic: "ret".into(),
            flow_type: FlowType::Return,
            fall_through: None,
            flows: vec![],
            num_operands: 0,
        };
        let pseudo: PseudoInstruction = instr.into();
        assert!(pseudo.is_return());
    }

    #[test]
    fn test_pseudo_instruction_prologue() {
        let pd = PseudoDisassembler::new();
        let listing = make_listing();
        let pseudo = pd.disassemble_at(Address::new(0x1000), &listing).unwrap();
        assert!(pseudo.is_prologue());
    }

    #[test]
    fn test_pseudo_instruction_not_prologue() {
        let pd = PseudoDisassembler::new();
        let listing = make_listing();
        let pseudo = pd.disassemble_at(Address::new(0x1001), &listing).unwrap();
        assert!(!pseudo.is_prologue());
    }

    #[test]
    fn test_pseudo_instruction_is_return() {
        let pd = PseudoDisassembler::new();
        let listing = make_listing();
        let pseudo = pd.disassemble_at(Address::new(0x100b), &listing).unwrap();
        assert!(pseudo.is_return());
    }

    #[test]
    fn test_pseudo_instruction_is_call() {
        let pd = PseudoDisassembler::new();
        let listing = make_listing();
        let pseudo = pd.disassemble_at(Address::new(0x1004), &listing).unwrap();
        assert!(pseudo.is_call());
    }

    #[test]
    fn test_pseudo_instruction_is_branch() {
        let pd = PseudoDisassembler::new();
        let listing = make_listing();
        let pseudo = pd.disassemble_at(Address::new(0x1009), &listing).unwrap();
        assert!(pseudo.is_branch());
    }

    #[test]
    fn test_pseudo_instruction_flow_addresses() {
        let pd = PseudoDisassembler::new();
        let listing = make_listing();

        // Conditional branch: fallthrough + branch target
        let jz = pd.disassemble_at(Address::new(0x1009), &listing).unwrap();
        let flows = jz.get_flow_addresses();
        assert_eq!(flows.len(), 2);
        assert!(flows.contains(&Address::new(0x100b)));
        assert!(flows.contains(&Address::new(0x1020)));

        // Return: no flows
        let ret = pd.disassemble_at(Address::new(0x100b), &listing).unwrap();
        let flows = ret.get_flow_addresses();
        assert!(flows.is_empty());
    }

    #[test]
    fn test_trace_flow_basic() {
        let pd = PseudoDisassembler::new();
        let listing = make_listing();
        let empty = AddressSet::new();
        let trace = pd.trace_flow(Address::new(0x1000), &listing, &empty);
        // Should follow: 0x1000 -> 0x1001 -> 0x1004 -> 0x1009 -> 0x100b -> 0x1020 -> 0x1021
        assert!(trace.len() >= 5);
        assert_eq!(trace[0].address, Address::new(0x1000));
    }

    #[test]
    fn test_trace_flow_respects_existing() {
        let pd = PseudoDisassembler::new();
        let listing = make_listing();
        let mut existing = AddressSet::new();
        existing.add(Address::new(0x1020)); // Already in a function
        let trace = pd.trace_flow(Address::new(0x1000), &listing, &existing);
        // Should not include 0x1020 since it's in another function
        assert!(!trace.iter().any(|p| p.address == Address::new(0x1020)));
    }

    #[test]
    fn test_trace_flow_max_count() {
        let mut pd = PseudoDisassembler::new();
        pd.max_instruction_count = 3;
        let listing = make_listing();
        let empty = AddressSet::new();
        let trace = pd.trace_flow(Address::new(0x1000), &listing, &empty);
        assert!(trace.len() <= 3);
    }

    #[test]
    fn test_is_function_entry() {
        let pd = PseudoDisassembler::new();
        let listing = make_listing();
        assert!(pd.is_function_entry(Address::new(0x1000), &listing));
        assert!(!pd.is_function_entry(Address::new(0x9999), &listing));
    }

    #[test]
    fn test_instruction_length() {
        let pd = PseudoDisassembler::new();
        let listing = make_listing();
        assert_eq!(pd.instruction_length(Address::new(0x1000), &listing), 1);
        assert_eq!(pd.instruction_length(Address::new(0x1004), &listing), 5);
        assert_eq!(pd.instruction_length(Address::new(0x9999), &listing), 0);
    }

    #[test]
    fn test_pseudo_instruction_not_return() {
        let pd = PseudoDisassembler::new();
        let listing = make_listing();
        let pseudo = pd.disassemble_at(Address::new(0x1000), &listing).unwrap();
        assert!(!pseudo.is_return());
    }

    #[test]
    fn test_pseudo_instruction_not_call() {
        let pd = PseudoDisassembler::new();
        let listing = make_listing();
        let pseudo = pd.disassemble_at(Address::new(0x1000), &listing).unwrap();
        assert!(!pseudo.is_call());
    }

    #[test]
    fn test_pseudo_instruction_not_branch() {
        let pd = PseudoDisassembler::new();
        let listing = make_listing();
        let pseudo = pd.disassemble_at(Address::new(0x1000), &listing).unwrap();
        assert!(!pseudo.is_branch());
    }

    #[test]
    fn test_trace_flow_single_return() {
        let pd = PseudoDisassembler::new();
        let listing = make_listing();
        let empty = AddressSet::new();
        let trace = pd.trace_flow(Address::new(0x100b), &listing, &empty);
        assert_eq!(trace.len(), 1);
        assert!(trace[0].is_return());
    }

    #[test]
    fn test_trace_flow_from_unknown() {
        let pd = PseudoDisassembler::new();
        let listing = make_listing();
        let empty = AddressSet::new();
        let trace = pd.trace_flow(Address::new(0x9999), &listing, &empty);
        assert_eq!(trace.len(), 1);
        assert!(!trace[0].is_valid);
    }

    #[test]
    fn test_pseudo_instruction_clone() {
        let pd = PseudoDisassembler::new();
        let listing = make_listing();
        let p = pd.disassemble_at(Address::new(0x1000), &listing).unwrap();
        let p2 = p.clone();
        assert_eq!(p.address, p2.address);
        assert_eq!(p.mnemonic, p2.mnemonic);
    }

    #[test]
    fn test_pseudo_instruction_debug() {
        let p = PseudoInstruction::invalid(Address::new(0x1000));
        let debug = format!("{:?}", p);
        assert!(debug.contains("PseudoInstruction"));
    }

    #[test]
    fn test_pseudo_disassembler_clone() {
        let pd1 = PseudoDisassembler::new();
        let pd2 = pd1.clone();
        assert_eq!(pd1.max_instruction_count, pd2.max_instruction_count);
    }

    #[test]
    fn test_pseudo_disassembler_debug() {
        let pd = PseudoDisassembler::new();
        let debug = format!("{:?}", pd);
        assert!(debug.contains("PseudoDisassembler"));
    }

    #[test]
    fn test_trace_flow_conditional_and_return() {
        let pd = PseudoDisassembler::new();
        let listing = make_listing();
        let empty = AddressSet::new();
        // Start at the conditional branch
        let trace = pd.trace_flow(Address::new(0x1009), &listing, &empty);
        // Should reach: 0x1009 (jz), 0x100b (ret), 0x1020 (nop), 0x1021 (ret)
        assert!(trace.len() >= 4);
    }

    #[test]
    fn test_flow_type_helpers() {
        assert!(FlowType::Call.is_call());
        assert!(FlowType::ConditionalCall.is_call());
        assert!(FlowType::IndirectCall.is_call());
        assert!(!FlowType::UnconditionalBranch.is_call());

        assert!(FlowType::UnconditionalBranch.is_jump());
        assert!(FlowType::ConditionalBranch.is_jump());
        assert!(FlowType::IndirectJump.is_jump());
        assert!(FlowType::ComputedJump.is_jump());
        assert!(!FlowType::Call.is_jump());

        assert!(FlowType::Return.is_terminal());
        assert!(FlowType::ConditionalReturn.is_terminal());
        assert!(!FlowType::Call.is_terminal());
    }
}
