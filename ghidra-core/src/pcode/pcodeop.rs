//! PcodeOp -- a generic machine operation in pcode.
//!
//! Ported from `ghidra.program.model.pcode.PcodeOp` and
//! `ghidra.program.model.pcode.SequenceNumber`.

use crate::addr::Address;
use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================================
// SequenceNumber -- unique address for a PcodeOp
// ============================================================================

/// A unique identifier for a [`PcodeOp`].
///
/// Corresponds to Ghidra's `SequenceNumber`. Maintains the original assembly
/// instruction address and a sub-address for distinguishing multiple pcode ops
/// at the same instruction address.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SequenceNumber {
    /// Address of the assembly instruction that generated this pcode op.
    pub pc: Address,
    /// Sub-address for distinguishing multiple PcodeOps at one instruction
    /// address.  Does not change over the lifetime of the PcodeOp.
    pub uniq: u32,
    /// Relative position of this PcodeOp within a basic block. May change
    /// as the basic block is edited.
    pub order: i32,
}

impl SequenceNumber {
    /// Create a new sequence number at the given address and sub-address.
    pub fn new(pc: Address, uniq: u32) -> Self {
        Self { pc, uniq, order: 0 }
    }

    /// Create a sequence number with an explicit ordering value.
    pub fn with_order(pc: Address, uniq: u32, order: i32) -> Self {
        Self { pc, uniq, order }
    }

    /// Returns the assembly instruction address.
    pub fn get_target(&self) -> Address {
        self.pc
    }

    /// Returns the unique sub-address (does not change over the op's lifetime).
    pub fn get_time(&self) -> u32 {
        self.uniq
    }

    /// Returns the ordering value within a basic block.
    pub fn get_order(&self) -> i32 {
        self.order
    }
}

impl PartialOrd for SequenceNumber {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SequenceNumber {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.pc
            .offset
            .cmp(&other.pc.offset)
            .then(self.uniq.cmp(&other.uniq))
            .then(self.order.cmp(&other.order))
    }
}

impl fmt::Display for SequenceNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}:{}:{})", self.pc, self.uniq, self.order)
    }
}

// ============================================================================
// OpCode -- all pcode operation codes
// ============================================================================

/// Pcode operation codes.
///
/// These are the microcode operations that Ghidra uses to represent any
/// processor instruction. Each variant has a unique numeric ID matching the
/// Java constants in `PcodeOp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u16)]
pub enum OpCode {
    /// Place holder for unimplemented instruction.
    UNIMPLEMENTED = 0,
    /// Copy one operand to another.
    COPY = 1,
    /// Dereference a pointer into specified space.
    LOAD = 2,
    /// Store at a pointer into specified space.
    STORE = 3,
    /// Always branch.
    BRANCH = 4,
    /// Conditional branch.
    CBRANCH = 5,
    /// An indirect branch (jumptable).
    BRANCHIND = 6,
    /// A call with absolute address.
    CALL = 7,
    /// An indirect call.
    CALLIND = 8,
    /// Other unusual subroutine calling conventions.
    CALLOTHER = 9,
    /// A return from subroutine.
    RETURN = 10,
    /// Return TRUE if operand1 == operand2.
    INT_EQUAL = 11,
    /// Return TRUE if operand1 != operand2.
    INT_NOTEQUAL = 12,
    /// Return TRUE if signed op1 < signed op2.
    INT_SLESS = 13,
    /// Return TRUE if signed op1 <= signed op2.
    INT_SLESSEQUAL = 14,
    /// Return TRUE if unsigned op1 < unsigned op2 (also borrow on unsigned sub).
    INT_LESS = 15,
    /// Return TRUE if unsigned op1 <= unsigned op2.
    INT_LESSEQUAL = 16,
    /// Zero extend operand.
    INT_ZEXT = 17,
    /// Sign extend operand.
    INT_SEXT = 18,
    /// Unsigned addition of operands of same size.
    INT_ADD = 19,
    /// Unsigned subtraction of operands of same size.
    INT_SUB = 20,
    /// TRUE if adding two operands has overflow (carry).
    INT_CARRY = 21,
    /// TRUE if carry in signed addition of 2 operands.
    INT_SCARRY = 22,
    /// TRUE if borrow in signed subtraction of 2 operands.
    INT_SBORROW = 23,
    /// Twos complement (for subtracting) of operand.
    INT_2COMP = 24,
    /// Bitwise negate.
    INT_NEGATE = 25,
    /// Exclusive OR of two operands of same size.
    INT_XOR = 26,
    /// Bitwise AND.
    INT_AND = 27,
    /// Bitwise OR.
    INT_OR = 28,
    /// Left shift.
    INT_LEFT = 29,
    /// Right shift zero fill.
    INT_RIGHT = 30,
    /// Signed right shift.
    INT_SRIGHT = 31,
    /// Integer multiplication.
    INT_MULT = 32,
    /// Unsigned integer division.
    INT_DIV = 33,
    /// Signed integer division.
    INT_SDIV = 34,
    /// Unsigned mod (remainder).
    INT_REM = 35,
    /// Signed mod (remainder).
    INT_SREM = 36,
    /// Boolean negate or not.
    BOOL_NEGATE = 37,
    /// Boolean xor.
    BOOL_XOR = 38,
    /// Boolean and (&&).
    BOOL_AND = 39,
    /// Boolean or (||).
    BOOL_OR = 40,
    /// Return TRUE if operand1 == operand2 (float).
    FLOAT_EQUAL = 41,
    /// Return TRUE if operand1 != operand2 (float).
    FLOAT_NOTEQUAL = 42,
    /// Return TRUE if op1 < op2 (float).
    FLOAT_LESS = 43,
    /// Return TRUE if op1 <= op2 (float).
    FLOAT_LESSEQUAL = 44,
    /// Return TRUE if op1 is NaN.
    FLOAT_NAN = 46,
    /// Float addition.
    FLOAT_ADD = 47,
    /// Float division.
    FLOAT_DIV = 48,
    /// Float multiplication.
    FLOAT_MULT = 49,
    /// Float subtraction.
    FLOAT_SUB = 50,
    /// Float negation.
    FLOAT_NEG = 51,
    /// Float absolute value.
    FLOAT_ABS = 52,
    /// Float square root.
    FLOAT_SQRT = 53,
    /// Convert int type to float type.
    FLOAT_INT2FLOAT = 54,
    /// Convert between float sizes.
    FLOAT_FLOAT2FLOAT = 55,
    /// Round towards zero.
    FLOAT_TRUNC = 56,
    /// Round towards +infinity.
    FLOAT_CEIL = 57,
    /// Round towards -infinity.
    FLOAT_FLOOR = 58,
    /// Round towards nearest.
    FLOAT_ROUND = 59,
    /// Output equal to one of inputs (SSA phi-node).
    MULTIEQUAL = 60,
    /// Output probably equals input, but may be indirectly affected.
    INDIRECT = 61,
    /// Output is constructed from multiple pieces.
    PIECE = 62,
    /// Output is a subpiece of input0 (input1 = offset into input0).
    SUBPIECE = 63,
    /// Cast from one type to another.
    CAST = 64,
    /// outptr = ptrbase, offset (size multiplier).
    PTRADD = 65,
    /// outptr = &(ptr->subfield).
    PTRSUB = 66,
    /// Segmented address operation.
    SEGMENTOP = 67,
    /// Constant pool reference.
    CPOOLREF = 68,
    /// Allocation of new object.
    NEW = 69,
    /// Bit-field insert.
    INSERT = 70,
    /// Pull bits from a varnode.
    ZPULL = 71,
    /// Population count.
    POPCOUNT = 72,
    /// Leading zero count.
    LZCOUNT = 73,
    /// Signed pull bits from a varnode.
    SPULL = 74,
    /// Special user-defined op.
    CALLOTHER_UNUSED = 75,
    /// Used for CUSTOM/processor-specific ops.
    MAX = 76,
}

impl OpCode {
    /// Returns the numeric opcode value (matching Java PcodeOp constants).
    pub fn id(self) -> u16 {
        self as u16
    }

    /// Returns the OpCode for a given numeric value, or `None` if invalid.
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(OpCode::UNIMPLEMENTED),
            1 => Some(OpCode::COPY),
            2 => Some(OpCode::LOAD),
            3 => Some(OpCode::STORE),
            4 => Some(OpCode::BRANCH),
            5 => Some(OpCode::CBRANCH),
            6 => Some(OpCode::BRANCHIND),
            7 => Some(OpCode::CALL),
            8 => Some(OpCode::CALLIND),
            9 => Some(OpCode::CALLOTHER),
            10 => Some(OpCode::RETURN),
            11 => Some(OpCode::INT_EQUAL),
            12 => Some(OpCode::INT_NOTEQUAL),
            13 => Some(OpCode::INT_SLESS),
            14 => Some(OpCode::INT_SLESSEQUAL),
            15 => Some(OpCode::INT_LESS),
            16 => Some(OpCode::INT_LESSEQUAL),
            17 => Some(OpCode::INT_ZEXT),
            18 => Some(OpCode::INT_SEXT),
            19 => Some(OpCode::INT_ADD),
            20 => Some(OpCode::INT_SUB),
            21 => Some(OpCode::INT_CARRY),
            22 => Some(OpCode::INT_SCARRY),
            23 => Some(OpCode::INT_SBORROW),
            24 => Some(OpCode::INT_2COMP),
            25 => Some(OpCode::INT_NEGATE),
            26 => Some(OpCode::INT_XOR),
            27 => Some(OpCode::INT_AND),
            28 => Some(OpCode::INT_OR),
            29 => Some(OpCode::INT_LEFT),
            30 => Some(OpCode::INT_RIGHT),
            31 => Some(OpCode::INT_SRIGHT),
            32 => Some(OpCode::INT_MULT),
            33 => Some(OpCode::INT_DIV),
            34 => Some(OpCode::INT_SDIV),
            35 => Some(OpCode::INT_REM),
            36 => Some(OpCode::INT_SREM),
            37 => Some(OpCode::BOOL_NEGATE),
            38 => Some(OpCode::BOOL_XOR),
            39 => Some(OpCode::BOOL_AND),
            40 => Some(OpCode::BOOL_OR),
            41 => Some(OpCode::FLOAT_EQUAL),
            42 => Some(OpCode::FLOAT_NOTEQUAL),
            43 => Some(OpCode::FLOAT_LESS),
            44 => Some(OpCode::FLOAT_LESSEQUAL),
            46 => Some(OpCode::FLOAT_NAN),
            47 => Some(OpCode::FLOAT_ADD),
            48 => Some(OpCode::FLOAT_DIV),
            49 => Some(OpCode::FLOAT_MULT),
            50 => Some(OpCode::FLOAT_SUB),
            51 => Some(OpCode::FLOAT_NEG),
            52 => Some(OpCode::FLOAT_ABS),
            53 => Some(OpCode::FLOAT_SQRT),
            54 => Some(OpCode::FLOAT_INT2FLOAT),
            55 => Some(OpCode::FLOAT_FLOAT2FLOAT),
            56 => Some(OpCode::FLOAT_TRUNC),
            57 => Some(OpCode::FLOAT_CEIL),
            58 => Some(OpCode::FLOAT_FLOOR),
            59 => Some(OpCode::FLOAT_ROUND),
            60 => Some(OpCode::MULTIEQUAL),
            61 => Some(OpCode::INDIRECT),
            62 => Some(OpCode::PIECE),
            63 => Some(OpCode::SUBPIECE),
            64 => Some(OpCode::CAST),
            65 => Some(OpCode::PTRADD),
            66 => Some(OpCode::PTRSUB),
            67 => Some(OpCode::SEGMENTOP),
            68 => Some(OpCode::CPOOLREF),
            69 => Some(OpCode::NEW),
            70 => Some(OpCode::INSERT),
            71 => Some(OpCode::ZPULL),
            72 => Some(OpCode::POPCOUNT),
            73 => Some(OpCode::LZCOUNT),
            74 => Some(OpCode::SPULL),
            _ => None,
        }
    }

    /// Returns a human-readable mnemonic for this opcode.
    pub fn mnemonic(self) -> &'static str {
        match self {
            OpCode::UNIMPLEMENTED => "UNIMPLEMENTED",
            OpCode::COPY => "COPY",
            OpCode::LOAD => "LOAD",
            OpCode::STORE => "STORE",
            OpCode::BRANCH => "BRANCH",
            OpCode::CBRANCH => "CBRANCH",
            OpCode::BRANCHIND => "BRANCHIND",
            OpCode::CALL => "CALL",
            OpCode::CALLIND => "CALLIND",
            OpCode::CALLOTHER => "CALLOTHER",
            OpCode::RETURN => "RETURN",
            OpCode::INT_EQUAL => "INT_EQUAL",
            OpCode::INT_NOTEQUAL => "INT_NOTEQUAL",
            OpCode::INT_SLESS => "INT_SLESS",
            OpCode::INT_SLESSEQUAL => "INT_SLESSEQUAL",
            OpCode::INT_LESS => "INT_LESS",
            OpCode::INT_LESSEQUAL => "INT_LESSEQUAL",
            OpCode::INT_ZEXT => "INT_ZEXT",
            OpCode::INT_SEXT => "INT_SEXT",
            OpCode::INT_ADD => "INT_ADD",
            OpCode::INT_SUB => "INT_SUB",
            OpCode::INT_CARRY => "INT_CARRY",
            OpCode::INT_SCARRY => "INT_SCARRY",
            OpCode::INT_SBORROW => "INT_SBORROW",
            OpCode::INT_2COMP => "INT_2COMP",
            OpCode::INT_NEGATE => "INT_NEGATE",
            OpCode::INT_XOR => "INT_XOR",
            OpCode::INT_AND => "INT_AND",
            OpCode::INT_OR => "INT_OR",
            OpCode::INT_LEFT => "INT_LEFT",
            OpCode::INT_RIGHT => "INT_RIGHT",
            OpCode::INT_SRIGHT => "INT_SRIGHT",
            OpCode::INT_MULT => "INT_MULT",
            OpCode::INT_DIV => "INT_DIV",
            OpCode::INT_SDIV => "INT_SDIV",
            OpCode::INT_REM => "INT_REM",
            OpCode::INT_SREM => "INT_SREM",
            OpCode::BOOL_NEGATE => "BOOL_NEGATE",
            OpCode::BOOL_XOR => "BOOL_XOR",
            OpCode::BOOL_AND => "BOOL_AND",
            OpCode::BOOL_OR => "BOOL_OR",
            OpCode::FLOAT_EQUAL => "FLOAT_EQUAL",
            OpCode::FLOAT_NOTEQUAL => "FLOAT_NOTEQUAL",
            OpCode::FLOAT_LESS => "FLOAT_LESS",
            OpCode::FLOAT_LESSEQUAL => "FLOAT_LESSEQUAL",
            OpCode::FLOAT_NAN => "FLOAT_NAN",
            OpCode::FLOAT_ADD => "FLOAT_ADD",
            OpCode::FLOAT_DIV => "FLOAT_DIV",
            OpCode::FLOAT_MULT => "FLOAT_MULT",
            OpCode::FLOAT_SUB => "FLOAT_SUB",
            OpCode::FLOAT_NEG => "FLOAT_NEG",
            OpCode::FLOAT_ABS => "FLOAT_ABS",
            OpCode::FLOAT_SQRT => "FLOAT_SQRT",
            OpCode::FLOAT_INT2FLOAT => "FLOAT_INT2FLOAT",
            OpCode::FLOAT_FLOAT2FLOAT => "FLOAT_FLOAT2FLOAT",
            OpCode::FLOAT_TRUNC => "FLOAT_TRUNC",
            OpCode::FLOAT_CEIL => "FLOAT_CEIL",
            OpCode::FLOAT_FLOOR => "FLOAT_FLOOR",
            OpCode::FLOAT_ROUND => "FLOAT_ROUND",
            OpCode::MULTIEQUAL => "MULTIEQUAL",
            OpCode::INDIRECT => "INDIRECT",
            OpCode::PIECE => "PIECE",
            OpCode::SUBPIECE => "SUBPIECE",
            OpCode::CAST => "CAST",
            OpCode::PTRADD => "PTRADD",
            OpCode::PTRSUB => "PTRSUB",
            OpCode::SEGMENTOP => "SEGMENTOP",
            OpCode::CPOOLREF => "CPOOLREF",
            OpCode::NEW => "NEW",
            OpCode::INSERT => "INSERT",
            OpCode::ZPULL => "ZPULL",
            OpCode::POPCOUNT => "POPCOUNT",
            OpCode::LZCOUNT => "LZCOUNT",
            OpCode::SPULL => "SPULL",
            OpCode::CALLOTHER_UNUSED => "CALLOTHER_UNUSED",
            OpCode::MAX => "MAX",
        }
    }

    /// Returns `true` if this opcode takes no output varnode.
    pub fn has_no_output(self) -> bool {
        matches!(
            self,
            OpCode::STORE
                | OpCode::BRANCH
                | OpCode::CBRANCH
                | OpCode::BRANCHIND
                | OpCode::CALL
                | OpCode::CALLIND
                | OpCode::CALLOTHER
                | OpCode::RETURN
        )
    }

    /// Returns `true` if this is a comparison opcode.
    pub fn is_comparison(self) -> bool {
        matches!(
            self,
            OpCode::INT_EQUAL
                | OpCode::INT_NOTEQUAL
                | OpCode::INT_SLESS
                | OpCode::INT_SLESSEQUAL
                | OpCode::INT_LESS
                | OpCode::INT_LESSEQUAL
                | OpCode::FLOAT_EQUAL
                | OpCode::FLOAT_NOTEQUAL
                | OpCode::FLOAT_LESS
                | OpCode::FLOAT_LESSEQUAL
                | OpCode::FLOAT_NAN
        )
    }

    /// Returns `true` if this is a branch opcode.
    pub fn is_branch(self) -> bool {
        matches!(
            self,
            OpCode::BRANCH | OpCode::CBRANCH | OpCode::BRANCHIND
        )
    }

    /// Returns `true` if this is a call opcode.
    pub fn is_call(self) -> bool {
        matches!(
            self,
            OpCode::CALL | OpCode::CALLIND | OpCode::CALLOTHER
        )
    }

    /// Returns `true` if this is a floating-point opcode.
    pub fn is_float(self) -> bool {
        (self as u16) >= 41 && (self as u16) <= 59
    }

    /// Returns `true` if this is an integer arithmetic opcode.
    pub fn is_arithmetic(self) -> bool {
        matches!(
            self,
            OpCode::INT_ADD
                | OpCode::INT_SUB
                | OpCode::INT_MULT
                | OpCode::INT_DIV
                | OpCode::INT_SDIV
                | OpCode::INT_REM
                | OpCode::INT_SREM
        )
    }

    /// Returns `true` if this is a bitwise opcode.
    pub fn is_bitwise(self) -> bool {
        matches!(
            self,
            OpCode::INT_XOR
                | OpCode::INT_AND
                | OpCode::INT_OR
                | OpCode::INT_LEFT
                | OpCode::INT_RIGHT
                | OpCode::INT_SRIGHT
                | OpCode::INT_NEGATE
        )
    }
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.mnemonic())
    }
}

// ============================================================================
// PcodeOp -- a raw pcode operation
// ============================================================================

/// A pcode operation -- the fundamental microcode instruction in Ghidra.
///
/// Corresponds to Ghidra's `PcodeOp`. Contains an opcode, a sequence number,
/// input varnodes, and an optional output varnode.
///
/// In the raw (non-AST) form, input/output varnodes are indices or addresses
/// rather than graph-linked nodes. Use [`PcodeOpAST`] for the graph form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcodeOp {
    /// The operation code.
    pub opcode: OpCode,
    /// Sequence number uniquely identifying this op.
    pub seqnum: SequenceNumber,
    /// Input varnode indices (into a [`VarnodeBank`] or similar storage).
    pub input: Vec<u32>,
    /// Output varnode index, or `None` for store/branch/return ops.
    pub output: Option<u32>,
}

impl PcodeOp {
    /// Create a new pcode op with the given opcode, sequence, and arities.
    pub fn new(opcode: OpCode, seqnum: SequenceNumber, num_inputs: usize) -> Self {
        Self {
            opcode,
            seqnum,
            input: vec![0; num_inputs],
            output: if opcode.has_no_output() {
                None
            } else {
                Some(0)
            },
        }
    }

    /// Create a pcode op with explicit input/output varnode indices.
    pub fn with_varnodes(
        opcode: OpCode,
        seqnum: SequenceNumber,
        input: Vec<u32>,
        output: Option<u32>,
    ) -> Self {
        Self {
            opcode,
            seqnum,
            input,
            output,
        }
    }

    /// Returns the number of input varnodes.
    pub fn num_inputs(&self) -> usize {
        self.input.len()
    }

    /// Returns the assembly instruction address.
    pub fn get_address(&self) -> Address {
        self.seqnum.pc
    }

    /// Returns the unique sequence number.
    pub fn get_seqnum(&self) -> &SequenceNumber {
        &self.seqnum
    }

    /// Returns the opcode.
    pub fn get_opcode(&self) -> OpCode {
        self.opcode
    }

    /// Returns `true` if this op has an output varnode.
    pub fn has_output(&self) -> bool {
        self.output.is_some()
    }

    /// Returns the mnemonic for this op.
    pub fn mnemonic(&self) -> &'static str {
        self.opcode.mnemonic()
    }
}

impl fmt::Display for PcodeOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} (seq: {})", self.opcode, self.input.len(), self.seqnum)
    }
}

// ============================================================================
// PcodeOpAST -- a graph-linked pcode operation
// ============================================================================

/// A pcode operation that participates in the Abstract Syntax Tree.
///
/// Corresponds to Ghidra's `PcodeOpAST`. Extends the raw op with a back-pointer
/// to the parent [`PcodeBlock`] and the indices of linked varnode AST nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcodeOpAST {
    /// The underlying raw pcode op data.
    pub op: PcodeOp,
    /// Index of the parent basic block in the block graph (u32::MAX if none).
    pub parent_block_index: u32,
    /// Unique id for this op within the syntax tree.
    pub unique_id: u32,
    /// Input varnode AST node indices.
    pub input_vn_ids: Vec<u32>,
    /// Output varnode AST node index, if any.
    pub output_vn_id: Option<u32>,
}

impl PcodeOpAST {
    /// Create a new AST pcode op.
    pub fn new(opcode: OpCode, seqnum: SequenceNumber, num_inputs: usize) -> Self {
        Self {
            op: PcodeOp::new(opcode, seqnum, num_inputs),
            parent_block_index: u32::MAX,
            unique_id: 0,
            input_vn_ids: Vec::new(),
            output_vn_id: None,
        }
    }

    /// Create with explicit varnode AST ids.
    pub fn with_varnodes(
        opcode: OpCode,
        seqnum: SequenceNumber,
        input_ids: Vec<u32>,
        output_id: Option<u32>,
        unique_id: u32,
    ) -> Self {
        let n = input_ids.len();
        Self {
            op: PcodeOp::with_varnodes(opcode, seqnum, vec![0; n], output_id),
            parent_block_index: u32::MAX,
            unique_id,
            input_vn_ids: input_ids,
            output_vn_id: output_id,
        }
    }

    /// Returns the opcode.
    pub fn get_opcode(&self) -> OpCode {
        self.op.opcode
    }

    /// Returns the sequence number.
    pub fn get_seqnum(&self) -> &SequenceNumber {
        &self.op.seqnum
    }

    /// Returns the assembly instruction address.
    pub fn get_address(&self) -> Address {
        self.op.seqnum.pc
    }

    /// Returns the number of input varnodes.
    pub fn num_inputs(&self) -> usize {
        self.input_vn_ids.len()
    }

    /// Set the parent block index.
    pub fn set_parent_block(&mut self, block_index: u32) {
        self.parent_block_index = block_index;
    }

    /// Returns `true` if this op has a parent block.
    pub fn has_parent(&self) -> bool {
        self.parent_block_index != u32::MAX
    }
}

impl fmt::Display for PcodeOpAST {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} (seq: {}, inputs: {})",
            self.unique_id,
            self.op.opcode,
            self.op.seqnum,
            self.input_vn_ids.len()
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequence_number_ord() {
        let a = SequenceNumber::new(Address::new(0x1000), 0);
        let b = SequenceNumber::new(Address::new(0x1000), 1);
        let c = SequenceNumber::new(Address::new(0x2000), 0);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn test_sequence_number_display() {
        let seq = SequenceNumber::new(Address::new(0x401000), 3);
        assert_eq!(format!("{}", seq), "(00401000:3:0)");
    }

    #[test]
    fn test_opcode_from_id_roundtrip() {
        for id in 0..=74u16 {
            if id == 45 {
                continue; // slot 45 is unused
            }
            let opcode = OpCode::from_id(id).expect(&format!("id {id} should be valid"));
            assert_eq!(opcode.id(), id, "roundtrip failed for {id}");
        }
        assert!(OpCode::from_id(45).is_none());
        assert!(OpCode::from_id(100).is_none());
    }

    #[test]
    fn test_opcode_mnemonic() {
        assert_eq!(OpCode::COPY.mnemonic(), "COPY");
        assert_eq!(OpCode::INT_ADD.mnemonic(), "INT_ADD");
        assert_eq!(OpCode::FLOAT_SQRT.mnemonic(), "FLOAT_SQRT");
    }

    #[test]
    fn test_opcode_classification() {
        assert!(OpCode::BRANCH.is_branch());
        assert!(OpCode::CALL.is_call());
        assert!(OpCode::FLOAT_ADD.is_float());
        assert!(OpCode::INT_ADD.is_arithmetic());
        assert!(OpCode::INT_AND.is_bitwise());
        assert!(OpCode::INT_EQUAL.is_comparison());
        assert!(OpCode::STORE.has_no_output());
        assert!(!OpCode::COPY.has_no_output());
    }

    #[test]
    fn test_pcodeop_creation() {
        let seq = SequenceNumber::new(Address::new(0x1000), 0);
        let op = PcodeOp::new(OpCode::COPY, seq.clone(), 1);
        assert_eq!(op.opcode, OpCode::COPY);
        assert_eq!(op.num_inputs(), 1);
        assert!(op.has_output());
        assert_eq!(op.get_address(), Address::new(0x1000));
    }

    #[test]
    fn test_pcodeop_store_no_output() {
        let seq = SequenceNumber::new(Address::new(0x1000), 0);
        let op = PcodeOp::new(OpCode::STORE, seq, 2);
        assert!(!op.has_output());
    }

    #[test]
    fn test_pcodeop_ast() {
        let seq = SequenceNumber::new(Address::new(0x2000), 1);
        let mut ast = PcodeOpAST::new(OpCode::INT_ADD, seq, 2);
        assert!(!ast.has_parent());
        ast.set_parent_block(5);
        assert!(ast.has_parent());
        assert_eq!(ast.get_opcode(), OpCode::INT_ADD);
    }

    #[test]
    fn test_pcodeop_display() {
        let seq = SequenceNumber::new(Address::new(0x401000), 0);
        let op = PcodeOp::with_varnodes(
            OpCode::INT_ADD,
            seq,
            vec![1, 2],
            Some(3),
        );
        let s = format!("{}", op);
        assert!(s.contains("INT_ADD"));
        assert!(s.contains("2"));
    }
}
