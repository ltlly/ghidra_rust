//! P-code utility helpers (ported from `ghidra.app.util.pcode`).
//!
//! Provides utilities for working with P-code / sleigh representations.

use serde::{Deserialize, Serialize};

// ===================================================================
// PCodeOp types
// ===================================================================

/// A simplified P-code operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PCodeOp {
    /// Copy.
    Copy,
    /// Load from memory.
    Load,
    /// Store to memory.
    Store,
    /// Branch (conditional or unconditional).
    Branch,
    /// Conditional branch.
    CBranch,
    /// Call.
    Call,
    /// Call/return (indirect).
    CallInd,
    /// Return.
    Return,
    /// Integer addition.
    IntAdd,
    /// Integer subtraction.
    IntSub,
    /// Integer multiplication.
    IntMult,
    /// Integer division (signed).
    IntDiv,
    /// Integer division (unsigned).
    IntDivUnsigned,
    /// Integer modulo.
    IntRem,
    /// Bitwise AND.
    IntAnd,
    /// Bitwise OR.
    IntOr,
    /// Bitwise XOR.
    IntXor,
    /// Bitwise NOT (complement).
    IntNot,
    /// Left shift.
    IntLeft,
    /// Right shift (logical).
    IntRight,
    /// Right shift (arithmetic).
    IntSRight,
    /// Integer less-than (signed).
    IntLess,
    /// Integer less-than (unsigned).
    IntLessUnsigned,
    /// Integer equal.
    IntEqual,
    /// Integer not-equal.
    IntNotEqual,
    /// Boolean AND.
    BoolAnd,
    /// Boolean OR.
    BoolOr,
    /// Boolean NOT.
    BoolNot,
    /// Float add.
    FloatAdd,
    /// Float subtract.
    FloatSub,
    /// Float multiply.
    FloatMult,
    /// Float divide.
    FloatDiv,
    /// Subpiece (extract low bits).
    Subpiece,
    /// Piece (concatenate).
    Piece,
    /// Integer extension (zero or sign).
    IntZext,
    /// Integer sign extension.
    IntSext,
    /// Custom/user-defined.
    Callother,
}

// ===================================================================
// Varnode  (simplified)
// ===================================================================

/// A simplified P-code varnode: a triple of (space_id, offset, size).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Varnode {
    /// Address space ID.
    pub space_id: u32,
    /// Offset within the address space.
    pub offset: u64,
    /// Size in bytes.
    pub size: u16,
}

impl Varnode {
    /// Create a new varnode.
    pub fn new(space_id: u32, offset: u64, size: u16) -> Self {
        Self {
            space_id,
            offset,
            size,
        }
    }

    /// Create a register varnode.
    pub fn register(offset: u64, size: u16) -> Self {
        Self::new(1, offset, size) // space_id 1 = register
    }

    /// Create a memory varnode.
    pub fn memory(offset: u64, size: u16) -> Self {
        Self::new(0, offset, size) // space_id 0 = memory/ram
    }

    /// Create a constant varnode.
    pub fn constant(value: u64, size: u16) -> Self {
        Self::new(3, value, size) // space_id 3 = constant
    }

    /// Create a unique (temporary) varnode.
    pub fn unique(offset: u64, size: u16) -> Self {
        Self::new(4, offset, size) // space_id 4 = unique
    }
}

// ===================================================================
// PCodeOpInstance
// ===================================================================

/// A fully instantiated P-code operation with inputs and output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PCodeOpInstance {
    /// The operation type.
    pub op: PCodeOp,
    /// The output varnode (if any).
    pub output: Option<Varnode>,
    /// The input varnodes.
    pub inputs: Vec<Varnode>,
    /// The address of the instruction this op belongs to.
    pub instruction_address: u64,
    /// Sequence number within the instruction.
    pub seq_num: u32,
}

impl PCodeOpInstance {
    /// Create a new P-code operation instance.
    pub fn new(
        op: PCodeOp,
        output: Option<Varnode>,
        inputs: Vec<Varnode>,
        instruction_address: u64,
        seq_num: u32,
    ) -> Self {
        Self {
            op,
            output,
            inputs,
            instruction_address,
            seq_num,
        }
    }

    /// Return the number of inputs.
    pub fn num_inputs(&self) -> usize {
        self.inputs.len()
    }

    /// Return `true` if this operation has an output.
    pub fn has_output(&self) -> bool {
        self.output.is_some()
    }
}

// ===================================================================
// Tests
// ===================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varnode_factory() {
        let reg = Varnode::register(0x10, 4);
        assert_eq!(reg.space_id, 1);
        assert_eq!(reg.offset, 0x10);
        assert_eq!(reg.size, 4);

        let mem = Varnode::memory(0x400000, 1);
        assert_eq!(mem.space_id, 0);

        let c = Varnode::constant(0xFF, 1);
        assert_eq!(c.space_id, 3);

        let u = Varnode::unique(0x100, 8);
        assert_eq!(u.space_id, 4);
    }

    #[test]
    fn pcode_op_instance() {
        let op = PCodeOpInstance::new(
            PCodeOp::IntAdd,
            Some(Varnode::unique(0x100, 4)),
            vec![
                Varnode::register(0, 4),
                Varnode::constant(1, 4),
            ],
            0x400000,
            0,
        );
        assert_eq!(op.num_inputs(), 2);
        assert!(op.has_output());
        assert_eq!(op.op, PCodeOp::IntAdd);
    }

    #[test]
    fn pcode_op_instance_no_output() {
        let op = PCodeOpInstance::new(
            PCodeOp::Store,
            None,
            vec![
                Varnode::memory(0x1000, 8),
                Varnode::register(0, 8),
            ],
            0x400004,
            1,
        );
        assert!(!op.has_output());
        assert_eq!(op.num_inputs(), 2);
    }
}
