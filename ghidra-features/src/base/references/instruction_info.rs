//! Instruction operand information used by the reference editor panels.
//!
//! Ported from `InstructionPanel` and `InstructionPanelListener`. Models
//! the metadata about an instruction's mnemonic and operands that is needed
//! to determine which reference types are applicable.

use ghidra_core::addr::Address;
use ghidra_core::symbol::{RefType, MNEMONIC};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Metadata about a single operand of an instruction or data unit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperandInfo {
    /// The operand index (0-based).
    pub index: i32,
    /// A human-readable representation of the operand.
    pub representation: String,
    /// The address this operand refers to, if any.
    pub address: Option<Address>,
    /// The primary reference type for this operand, if any.
    pub primary_ref_type: Option<RefType>,
}

impl OperandInfo {
    /// Create new operand info.
    pub fn new(index: i32, representation: impl Into<String>) -> Self {
        Self {
            index,
            representation: representation.into(),
            address: None,
            primary_ref_type: None,
        }
    }
}

impl fmt::Display for OperandInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OP-{}: {}", self.index, self.representation)
    }
}

/// Information about the instruction/data unit operands for the reference
/// editor.
///
/// Corresponds to the state managed by `InstructionPanel` and
/// `InstructionPanelListener`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionOperandInfo {
    /// The address of the code unit.
    pub address: Address,
    /// The mnemonic string (e.g., "MOV", "CALL").
    pub mnemonic: String,
    /// The operands of this code unit.
    pub operands: Vec<OperandInfo>,
    /// The currently selected operand index (MNEMONIC = -1).
    pub selected_index: i32,
    /// The currently selected sub-operand index (-1 = none).
    pub selected_sub_index: i32,
    /// Whether the selection is locked (editing an existing reference).
    pub locked: bool,
    /// Number of operands.
    pub num_operands: i32,
}

impl InstructionOperandInfo {
    /// Create new instruction operand info.
    pub fn new(address: Address, mnemonic: impl Into<String>, num_operands: i32) -> Self {
        Self {
            address,
            mnemonic: mnemonic.into(),
            operands: Vec::new(),
            selected_index: MNEMONIC,
            selected_sub_index: -1,
            locked: false,
            num_operands,
        }
    }

    /// Add an operand to the info.
    pub fn add_operand(&mut self, operand: OperandInfo) {
        self.operands.push(operand);
    }

    /// Set the selected operand index.
    pub fn set_selected(&mut self, index: i32, sub_index: i32) {
        self.selected_index = index;
        self.selected_sub_index = sub_index;
    }

    /// Returns the selected operand index.
    pub fn selected_operand_index(&self) -> i32 {
        self.selected_index
    }

    /// Returns the selected sub-operand index.
    pub fn selected_sub_operand_index(&self) -> i32 {
        self.selected_sub_index
    }

    /// Returns the next operand index (cycling through mnemonic -> op0 -> op1
    /// -> ... -> mnemonic).
    pub fn next_operand_index(&self) -> i32 {
        if self.operands.is_empty() {
            return MNEMONIC;
        }
        if self.selected_index == MNEMONIC {
            return 0;
        }
        if (self.selected_index as usize) < self.operands.len() - 1 {
            return self.selected_index + 1;
        }
        MNEMONIC
    }

    /// Returns the previous operand index.
    pub fn previous_operand_index(&self) -> i32 {
        if self.operands.is_empty() {
            return MNEMONIC;
        }
        if self.selected_index == MNEMONIC {
            return self.num_operands - 1;
        }
        if self.selected_index > 0 {
            return self.selected_index - 1;
        }
        MNEMONIC
    }

    /// Returns the operand representation at the given index.
    pub fn operand_representation(&self, index: i32) -> Option<&str> {
        self.operands
            .iter()
            .find(|o| o.index == index)
            .map(|o| o.representation.as_str())
    }
}

impl fmt::Display for InstructionOperandInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.address, self.mnemonic)?;
        for op in &self.operands {
            write!(f, " {}", op.representation)?;
        }
        Ok(())
    }
}

/// Callback interface for operand selection changes.
///
/// Corresponds to `InstructionPanelListener`.
pub trait InstructionPanelListener: fmt::Debug {
    /// Called when the user selects a different operand.
    fn operand_selected(&mut self, op_index: i32, sub_index: i32);

    /// Called when a selection is dropped onto the instruction panel.
    fn selection_dropped(&mut self, from_addr: Address, to_addr: Address, op_index: i32);

    /// Returns `true` if drop is supported.
    fn drop_supported(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operand_info_display() {
        let op = OperandInfo::new(0, "%eax, %ebx");
        assert_eq!(format!("{}", op), "OP-0: %eax, %ebx");
    }

    #[test]
    fn test_instruction_operand_info_cycling() {
        let mut info = InstructionOperandInfo::new(Address::new(0x1000), "MOV", 2);
        info.add_operand(OperandInfo::new(0, "%eax"));
        info.add_operand(OperandInfo::new(1, "%ebx"));

        // Start at MNEMONIC (-1)
        assert_eq!(info.selected_operand_index(), MNEMONIC);
        assert_eq!(info.next_operand_index(), 0);

        // Select op 0
        info.set_selected(0, -1);
        assert_eq!(info.next_operand_index(), 1);

        // Select op 1
        info.set_selected(1, -1);
        assert_eq!(info.next_operand_index(), MNEMONIC);

        // Previous from MNEMONIC wraps to last operand
        info.set_selected(MNEMONIC, -1);
        assert_eq!(info.previous_operand_index(), 1);
    }

    #[test]
    fn test_instruction_operand_info_display() {
        let mut info = InstructionOperandInfo::new(Address::new(0x1000), "CALL", 1);
        info.add_operand(OperandInfo::new(0, "0x2000"));
        let display = format!("{}", info);
        assert!(display.contains("CALL"));
        assert!(display.contains("0x2000"));
    }

    #[test]
    fn test_operand_representation() {
        let mut info = InstructionOperandInfo::new(Address::new(0x1000), "MOV", 2);
        info.add_operand(OperandInfo::new(0, "%eax"));
        assert_eq!(info.operand_representation(0), Some("%eax"));
        assert_eq!(info.operand_representation(1), None);
    }

    #[test]
    fn test_operand_info_new_defaults() {
        let op = OperandInfo::new(2, "[rbp-8]");
        assert_eq!(op.index, 2);
        assert_eq!(op.representation, "[rbp-8]");
        assert!(op.address.is_none());
        assert!(op.primary_ref_type.is_none());
    }

    #[test]
    fn test_operand_info_with_address() {
        let mut op = OperandInfo::new(0, "0x401000");
        op.address = Some(Address::new(0x401000));
        assert!(op.address.is_some());
        assert_eq!(op.address.unwrap().offset, 0x401000);
    }

    #[test]
    fn test_operand_info_clone() {
        let op = OperandInfo::new(1, "test");
        let cloned = op.clone();
        assert_eq!(cloned.index, 1);
        assert_eq!(cloned.representation, "test");
    }

    #[test]
    fn test_instruction_operand_info_empty_operands() {
        let info = InstructionOperandInfo::new(Address::new(0x100), "NOP", 0);
        // With no operands, cycling should stay at MNEMONIC
        assert_eq!(info.next_operand_index(), MNEMONIC);
        assert_eq!(info.previous_operand_index(), MNEMONIC);
    }

    #[test]
    fn test_instruction_operand_info_set_selected() {
        let mut info = InstructionOperandInfo::new(Address::new(0x1000), "MOV", 2);
        info.add_operand(OperandInfo::new(0, "%eax"));
        info.add_operand(OperandInfo::new(1, "%ebx"));

        info.set_selected(1, 3);
        assert_eq!(info.selected_operand_index(), 1);
        assert_eq!(info.selected_sub_operand_index(), 3);
    }

    #[test]
    fn test_instruction_operand_info_previous_from_first() {
        let mut info = InstructionOperandInfo::new(Address::new(0x1000), "ADD", 2);
        info.add_operand(OperandInfo::new(0, "eax"));
        info.add_operand(OperandInfo::new(1, "ebx"));

        info.set_selected(0, -1);
        assert_eq!(info.previous_operand_index(), MNEMONIC);
    }

    #[test]
    fn test_instruction_operand_info_clone() {
        let mut info = InstructionOperandInfo::new(Address::new(0x500), "JMP", 1);
        info.add_operand(OperandInfo::new(0, "0x1000"));
        info.locked = true;
        let cloned = info.clone();
        assert_eq!(cloned.address, info.address);
        assert_eq!(cloned.mnemonic, "JMP");
        assert!(cloned.locked);
        assert_eq!(cloned.operands.len(), 1);
    }

    #[test]
    fn test_instruction_operand_info_serialization() {
        let mut info = InstructionOperandInfo::new(Address::new(0x1000), "MOV", 1);
        info.add_operand(OperandInfo::new(0, "%rax"));
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: InstructionOperandInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.mnemonic, "MOV");
        assert_eq!(deserialized.address, Address::new(0x1000));
        assert_eq!(deserialized.operands.len(), 1);
    }

    #[test]
    fn test_instruction_panel_listener_trait() {
        #[derive(Debug)]
        struct MockListener {
            last_op: Option<(i32, i32)>,
            drop_count: usize,
        }

        impl InstructionPanelListener for MockListener {
            fn operand_selected(&mut self, op_index: i32, sub_index: i32) {
                self.last_op = Some((op_index, sub_index));
            }
            fn selection_dropped(&mut self, _from: Address, _to: Address, _op: i32) {
                self.drop_count += 1;
            }
            fn drop_supported(&self) -> bool {
                true
            }
        }

        let mut listener = MockListener {
            last_op: None,
            drop_count: 0,
        };
        assert!(listener.drop_supported());
        listener.operand_selected(1, 0);
        assert_eq!(listener.last_op, Some((1, 0)));
        listener.selection_dropped(Address::new(0x100), Address::new(0x200), 0);
        assert_eq!(listener.drop_count, 1);
    }

    #[test]
    fn test_operand_info_with_primary_ref_type() {
        use ghidra_core::symbol::{DataRefType, FlowType};
        let mut op = OperandInfo::new(0, "CALL 0x2000");
        op.primary_ref_type = Some(RefType::Flow(FlowType::UnconditionalCall));
        assert!(op.primary_ref_type.is_some());

        let mut op2 = OperandInfo::new(1, "MOV [eax]");
        op2.primary_ref_type = Some(RefType::Data(DataRefType::Read));
        assert!(op2.primary_ref_type.is_some());
    }
}
