//! P-code fundamental types used throughout the SLEIGH system.
//!
//! P-code is Ghidra's intermediate representation for processor instructions.
//! Every decoded instruction is translated into a sequence of P-code operations,
//! each operating on Varnodes (storage location triples).
//!
//! # Key Types
//! - [`SpaceType`] - Categories of address spaces (register, RAM, constant, etc.)
//! - [`Varnode`] - A (space, offset, size) triple representing a storage location
//! - [`OpCode`] - Enumeration of all P-code operation codes
//! - [`PcodeOp`] - A single P-code operation with output varnode and input varnodes

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// SpaceType
// ---------------------------------------------------------------------------

/// Address space types in the P-code model.
///
/// P-code organizes storage into named address spaces. The standard spaces are
/// `Register`, `Ram`, `Constant`, and `Unique`. Processor-specific spaces use
/// the `Other` variant with a custom identifier.
///
/// Space indices are used in the binary `.sla` format for compact representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SpaceType {
    /// Processor register space (index 0)
    Register,
    /// Main memory / RAM space (index 1)
    Ram,
    /// Constant / immediate space (index 2)
    Constant,
    /// Unique temporary space for SSA values (index 3)
    Unique,
    /// Processor-specific or user-defined space with the given index
    Other(u32),
}

impl SpaceType {
    /// Return the numeric index for this space type.
    ///
    /// Standard spaces use indices 0-3; custom spaces use their assigned index.
    pub fn index(&self) -> u32 {
        match self {
            SpaceType::Register => 0,
            SpaceType::Ram => 1,
            SpaceType::Constant => 2,
            SpaceType::Unique => 3,
            SpaceType::Other(i) => *i,
        }
    }

    /// Construct a `SpaceType` from its numeric index.
    pub fn from_index(idx: u32) -> Self {
        match idx {
            0 => SpaceType::Register,
            1 => SpaceType::Ram,
            2 => SpaceType::Constant,
            3 => SpaceType::Unique,
            other => SpaceType::Other(other),
        }
    }

    /// Returns `true` if this is the register space.
    pub fn is_register(&self) -> bool {
        matches!(self, SpaceType::Register)
    }

    /// Returns `true` if this is the RAM (memory) space.
    pub fn is_ram(&self) -> bool {
        matches!(self, SpaceType::Ram)
    }

    /// Returns `true` if this is the constant (immediate) space.
    pub fn is_constant(&self) -> bool {
        matches!(self, SpaceType::Constant)
    }

    /// Returns `true` if this is the unique (temporary) space.
    pub fn is_unique(&self) -> bool {
        matches!(self, SpaceType::Unique)
    }

    /// Human-readable name for this space.
    pub fn name(&self) -> &'static str {
        match self {
            SpaceType::Register => "register",
            SpaceType::Ram => "ram",
            SpaceType::Constant => "constant",
            SpaceType::Unique => "unique",
            SpaceType::Other(_) => "other",
        }
    }
}

impl fmt::Display for SpaceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpaceType::Register => write!(f, "register"),
            SpaceType::Ram => write!(f, "ram"),
            SpaceType::Constant => write!(f, "const"),
            SpaceType::Unique => write!(f, "unique"),
            SpaceType::Other(idx) => write!(f, "space_{}", idx),
        }
    }
}

// ---------------------------------------------------------------------------
// Varnode
// ---------------------------------------------------------------------------

/// A Varnode is the fundamental storage unit in P-code.
///
/// It is a triple `(space, offset, size)`:
/// - `space` identifies the address space (register, RAM, constant, or unique)
/// - `offset` is the byte offset within that space
/// - `size` is the number of bytes
///
/// Every P-code operation reads from and writes to Varnodes. A Varnode can
/// represent a register (`register:0x4,4` = EAX on x86-32), a memory location
/// (`ram:0x7fff1234,4`), a constant (`const:0x2a,4` = 42 encoded as 4 bytes),
/// or a temporary (`unique:0x0,4`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Varnode {
    /// Address space this varnode lives in
    pub space: SpaceType,
    /// Byte offset within the address space
    pub offset: u64,
    /// Size in bytes
    pub size: usize,
}

impl Varnode {
    /// Create a new Varnode.
    pub fn new(space: SpaceType, offset: u64, size: usize) -> Self {
        Self {
            space,
            offset,
            size,
        }
    }

    /// Create a register varnode at the given offset with the given size.
    pub fn register(offset: u64, size: usize) -> Self {
        Self {
            space: SpaceType::Register,
            offset,
            size,
        }
    }

    /// Create a RAM (memory) varnode at the given address with the given size.
    pub fn ram(offset: u64, size: usize) -> Self {
        Self {
            space: SpaceType::Ram,
            offset,
            size,
        }
    }

    /// Create a constant varnode with the given value encoded in the given size.
    pub fn constant(value: u64, size: usize) -> Self {
        Self {
            space: SpaceType::Constant,
            offset: value,
            size,
        }
    }

    /// Create a unique (temporary/SSA) varnode at the given index.
    pub fn unique(index: u64, size: usize) -> Self {
        Self {
            space: SpaceType::Unique,
            offset: index,
            size,
        }
    }

    /// Returns `true` if this varnode lives in the register space.
    pub fn is_register(&self) -> bool {
        self.space.is_register()
    }

    /// Returns `true` if this varnode lives in the RAM (memory) space.
    pub fn is_ram(&self) -> bool {
        self.space.is_ram()
    }

    /// Returns `true` if this is a constant varnode.
    pub fn is_constant(&self) -> bool {
        self.space.is_constant()
    }

    /// Returns `true` if this is a unique (temporary) varnode.
    pub fn is_unique(&self) -> bool {
        self.space.is_unique()
    }

    /// Returns the constant value if this is a constant varnode, otherwise `None`.
    pub fn constant_value(&self) -> Option<u64> {
        if self.is_constant() {
            Some(self.offset)
        } else {
            None
        }
    }

    /// Returns `true` if this varnode represents an address in RAM.
    pub fn is_address(&self) -> bool {
        self.space == SpaceType::Ram
    }

    /// Returns `true` if this varnode is "free" (uninitialized or wildcard).
    /// A free varnode has space `Unique` and offset `u64::MAX`.
    pub fn is_free(&self) -> bool {
        self.space == SpaceType::Unique && self.offset == u64::MAX
    }

    /// Create a free (wildcard) varnode.
    pub fn free() -> Self {
        Self {
            space: SpaceType::Unique,
            offset: u64::MAX,
            size: 0,
        }
    }

    /// Endian-flip the offset. For big-endian registers accessed with
    /// little-endian conventions, this adjusts the offset relative to the size.
    pub fn flip_offset_endian(&self, wordsize: usize, big_endian: bool) -> u64 {
        if !big_endian && self.is_register() {
            let sub_off = self.offset % wordsize as u64;
            self.offset - sub_off + (wordsize as u64 - sub_off - self.size as u64)
        } else {
            self.offset
        }
    }
}

impl fmt::Display for Varnode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}:0x{:x},{})", self.space, self.offset, self.size)
    }
}

// ---------------------------------------------------------------------------
// OpCode
// ---------------------------------------------------------------------------

/// All P-code operation codes.
///
/// P-code is a register-transfer language. Each opcode describes a simple
/// operation with at most two input varnodes and one output varnode.
///
/// The opcode set is divided into categories:
/// - **Data movement**: `Copy`, `Load`, `Store`
/// - **Integer arithmetic**: `IntAdd`, `IntSub`, `IntMult`, `IntDiv`, etc.
/// - **Boolean/logical**: `IntAnd`, `IntOr`, `IntXor`, `IntNeg`
/// - **Shifts**: `IntLeft`, `IntRight`, `IntSright`
/// - **Floating-point**: `FloatAdd`, `FloatSub`, etc.
/// - **Control flow**: `Branch`, `Cbranch`, `Call`, `Return`, etc.
/// - **Extension**: `SegmentOp`, `CpoolRef`, `New`
/// - **User-defined**: `UserDefined(u32)` for processor-specific ops
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OpCode {
    // --- Data Movement ---
    /// Copy v1 to v0:  `v0 = v1`
    Copy,
    /// Load from memory: `v0 = *v1`
    Load,
    /// Store to memory: `*v0 = v1`
    Store,

    // --- Integer Arithmetic ---
    /// Unsigned integer addition
    IntAdd,
    /// Unsigned integer subtraction
    IntSub,
    /// Unsigned integer multiplication
    IntMul,
    /// Unsigned integer division
    IntDiv,
    /// Signed integer division
    IntSdiv,
    /// Unsigned integer remainder
    IntRem,
    /// Signed integer remainder
    IntSrem,
    /// Two's complement negation
    IntNegate,
    /// Zero-extension (v0 = zext(v1))
    IntZext,
    /// Sign-extension (v0 = sext(v1))
    IntSext,
    /// Carry flag from addition
    IntCarry,
    /// Signed borrow flag from subtraction
    IntScarry,
    /// Signed borrow flag from subtraction
    IntSborrow,

    // --- Boolean / Logical ---
    /// Bitwise AND
    IntAnd,
    /// Bitwise OR
    IntOr,
    /// Bitwise XOR
    IntXor,

    // --- Shifts ---
    /// Logical left shift
    IntLeft,
    /// Logical right shift
    IntRight,
    /// Arithmetic (signed) right shift
    IntSright,

    // --- Comparison ---
    /// Equality comparison
    IntEqual,
    /// Not-equal comparison
    IntNotEqual,
    /// Unsigned less-than
    IntLess,
    /// Unsigned less-than-or-equal
    IntLessEqual,
    /// Signed less-than
    IntSless,
    /// Signed less-than-or-equal
    IntSlessEqual,

    // --- Boolean ---
    /// Boolean AND (v1 && v2)
    BoolAnd,
    /// Boolean OR (v1 || v2)
    BoolOr,
    /// Boolean XOR
    BoolXor,
    /// Boolean NOT
    BoolNeg,

    // --- Floating-Point ---
    /// Floating-point addition
    FloatAdd,
    /// Floating-point subtraction
    FloatSub,
    /// Floating-point multiplication
    FloatMult,
    /// Floating-point division
    FloatDiv,
    /// Floating-point negation
    FloatNeg,
    /// Convert integer to floating-point
    Float2Float,
    /// Convert integer to floating-point
    Int2Float,
    /// Convert floating-point to integer
    Float2Int,
    /// Floating-point truncation
    FloatTrunc,
    /// Floating-point ceiling
    FloatCeil,
    /// Floating-point floor
    FloatFloor,
    /// Floating-point round
    FloatRound,
    /// Floating-point NaN check
    FloatNan,
    /// Floating-point equality
    FloatEqual,
    /// Floating-point not-equal
    FloatNotEqual,
    /// Floating-point less-than
    FloatLess,
    /// Floating-point less-than-or-equal
    FloatLessEqual,

    // --- Control Flow ---
    /// Unconditional branch to v0
    Branch,
    /// Conditional branch: if v0 goto v1
    Cbranch,
    /// Indirect branch through v0
    BranchInd,
    /// Call to address v0
    Call,
    /// Indirect call through v0
    CallInd,
    /// Call to v0 with override specification
    Callother,
    /// Return from function
    Return,

    // --- Extension Operations ---
    /// Segment / protection check operation
    SegmentOp,
    /// Constant pool / table reference lookup
    CpoolRef,
    /// Heap memory allocation
    New,
    /// Insert bit-field into varnode
    Insert,
    /// Extract bit-field from varnode
    Extract,
    /// Population count (number of set bits)
    Popcount,
    /// Count leading zeros
    Lzcount,

    /// Concatenate two varnodes: out = msb || lsb  (PIECE)
    Piece,
    /// Truncate varnode: out = v0[low..low+size]  (SUBPIECE)
    Subpiece,
    /// Type cast: out = (cast)v0  (CAST)
    Cast,
    /// Pointer addition: out = base + (index * scale)  (PTRADD)
    PtrAdd,
    /// Pointer subtraction: out = base - index  (PTRSUB)
    PtrSub,
    /// Phi-node in SSA form: out = phi(v0, v1, ...)  (MULTIEQUAL)
    MultiEqual,
    /// Indirect effect -- may alias any varnode (INDIRECT)
    Indirect,

    /// User-defined pcode operation (opaque for processor-specific instructions)
    UserDefined(u32),
}

impl OpCode {
    /// Return the numeric opcode used in the binary `.sla` format.
    pub fn to_u32(&self) -> u32 {
        match self {
            OpCode::Copy => 1,
            OpCode::Load => 2,
            OpCode::Store => 3,
            OpCode::Branch => 4,
            OpCode::Cbranch => 5,
            OpCode::BranchInd => 6,
            OpCode::Call => 7,
            OpCode::CallInd => 8,
            OpCode::Callother => 9,
            OpCode::Return => 10,
            OpCode::IntAdd => 11,
            OpCode::IntSub => 12,
            OpCode::IntMul => 13,
            OpCode::IntDiv => 14,
            OpCode::IntSdiv => 15,
            OpCode::IntRem => 16,
            OpCode::IntSrem => 17,
            OpCode::IntNegate => 18,
            OpCode::IntZext => 19,
            OpCode::IntSext => 20,
            OpCode::IntCarry => 21,
            OpCode::IntScarry => 22,
            OpCode::IntSborrow => 23,
            OpCode::IntAnd => 24,
            OpCode::IntOr => 25,
            OpCode::IntXor => 26,
            OpCode::IntLeft => 27,
            OpCode::IntRight => 28,
            OpCode::IntSright => 29,
            OpCode::IntEqual => 30,
            OpCode::IntNotEqual => 31,
            OpCode::IntLess => 32,
            OpCode::IntLessEqual => 33,
            OpCode::IntSless => 34,
            OpCode::IntSlessEqual => 35,
            OpCode::BoolAnd => 36,
            OpCode::BoolOr => 37,
            OpCode::BoolXor => 38,
            OpCode::BoolNeg => 39,
            OpCode::FloatAdd => 40,
            OpCode::FloatSub => 41,
            OpCode::FloatMult => 42,
            OpCode::FloatDiv => 43,
            OpCode::FloatNeg => 44,
            OpCode::Float2Float => 45,
            OpCode::Int2Float => 46,
            OpCode::Float2Int => 47,
            OpCode::FloatTrunc => 48,
            OpCode::FloatCeil => 49,
            OpCode::FloatFloor => 50,
            OpCode::FloatRound => 51,
            OpCode::FloatNan => 52,
            OpCode::FloatEqual => 53,
            OpCode::FloatNotEqual => 54,
            OpCode::FloatLess => 55,
            OpCode::FloatLessEqual => 56,
            OpCode::SegmentOp => 57,
            OpCode::CpoolRef => 58,
            OpCode::New => 59,
            OpCode::Insert => 60,
            OpCode::Extract => 61,
            OpCode::Popcount => 62,
            OpCode::Lzcount => 63,
            OpCode::Piece => 64,
            OpCode::Subpiece => 65,
            OpCode::Cast => 66,
            OpCode::PtrAdd => 67,
            OpCode::PtrSub => 68,
            OpCode::MultiEqual => 69,
            OpCode::Indirect => 70,
            OpCode::UserDefined(n) => *n,
        }
    }

    /// Reconstruct an OpCode from its numeric representation.
    pub fn from_u32(n: u32) -> Self {
        match n {
            1 => OpCode::Copy,
            2 => OpCode::Load,
            3 => OpCode::Store,
            4 => OpCode::Branch,
            5 => OpCode::Cbranch,
            6 => OpCode::BranchInd,
            7 => OpCode::Call,
            8 => OpCode::CallInd,
            9 => OpCode::Callother,
            10 => OpCode::Return,
            11 => OpCode::IntAdd,
            12 => OpCode::IntSub,
            13 => OpCode::IntMul,
            14 => OpCode::IntDiv,
            15 => OpCode::IntSdiv,
            16 => OpCode::IntRem,
            17 => OpCode::IntSrem,
            18 => OpCode::IntNegate,
            19 => OpCode::IntZext,
            20 => OpCode::IntSext,
            21 => OpCode::IntCarry,
            22 => OpCode::IntScarry,
            23 => OpCode::IntSborrow,
            24 => OpCode::IntAnd,
            25 => OpCode::IntOr,
            26 => OpCode::IntXor,
            27 => OpCode::IntLeft,
            28 => OpCode::IntRight,
            29 => OpCode::IntSright,
            30 => OpCode::IntEqual,
            31 => OpCode::IntNotEqual,
            32 => OpCode::IntLess,
            33 => OpCode::IntLessEqual,
            34 => OpCode::IntSless,
            35 => OpCode::IntSlessEqual,
            36 => OpCode::BoolAnd,
            37 => OpCode::BoolOr,
            38 => OpCode::BoolXor,
            39 => OpCode::BoolNeg,
            40 => OpCode::FloatAdd,
            41 => OpCode::FloatSub,
            42 => OpCode::FloatMult,
            43 => OpCode::FloatDiv,
            44 => OpCode::FloatNeg,
            45 => OpCode::Float2Float,
            46 => OpCode::Int2Float,
            47 => OpCode::Float2Int,
            48 => OpCode::FloatTrunc,
            49 => OpCode::FloatCeil,
            50 => OpCode::FloatFloor,
            51 => OpCode::FloatRound,
            52 => OpCode::FloatNan,
            53 => OpCode::FloatEqual,
            54 => OpCode::FloatNotEqual,
            55 => OpCode::FloatLess,
            56 => OpCode::FloatLessEqual,
            57 => OpCode::SegmentOp,
            58 => OpCode::CpoolRef,
            59 => OpCode::New,
            60 => OpCode::Insert,
            61 => OpCode::Extract,
            62 => OpCode::Popcount,
            63 => OpCode::Lzcount,
            64 => OpCode::Piece,
            65 => OpCode::Subpiece,
            66 => OpCode::Cast,
            67 => OpCode::PtrAdd,
            68 => OpCode::PtrSub,
            69 => OpCode::MultiEqual,
            70 => OpCode::Indirect,
            other => OpCode::UserDefined(other),
        }
    }

    /// Returns `true` if this opcode is a control-flow operation.
    pub fn is_control_flow(&self) -> bool {
        matches!(
            self,
            OpCode::Branch
                | OpCode::Cbranch
                | OpCode::BranchInd
                | OpCode::Call
                | OpCode::CallInd
                | OpCode::Callother
                | OpCode::Return
        )
    }

    /// Returns `true` if this opcode produces a boolean result.
    pub fn is_boolean_op(&self) -> bool {
        matches!(
            self,
            OpCode::IntEqual
                | OpCode::IntNotEqual
                | OpCode::IntLess
                | OpCode::IntLessEqual
                | OpCode::IntSless
                | OpCode::IntSlessEqual
                | OpCode::BoolAnd
                | OpCode::BoolOr
                | OpCode::BoolXor
                | OpCode::BoolNeg
                | OpCode::FloatEqual
                | OpCode::FloatNotEqual
                | OpCode::FloatLess
                | OpCode::FloatLessEqual
                | OpCode::FloatNan
        )
    }
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpCode::Copy => write!(f, "COPY"),
            OpCode::Load => write!(f, "LOAD"),
            OpCode::Store => write!(f, "STORE"),
            OpCode::Branch => write!(f, "BRANCH"),
            OpCode::Cbranch => write!(f, "CBRANCH"),
            OpCode::BranchInd => write!(f, "BRANCHIND"),
            OpCode::Call => write!(f, "CALL"),
            OpCode::CallInd => write!(f, "CALLIND"),
            OpCode::Callother => write!(f, "CALLOTHER"),
            OpCode::Return => write!(f, "RETURN"),
            OpCode::IntAdd => write!(f, "INT_ADD"),
            OpCode::IntSub => write!(f, "INT_SUB"),
            OpCode::IntMul => write!(f, "INT_MULT"),
            OpCode::IntDiv => write!(f, "INT_DIV"),
            OpCode::IntSdiv => write!(f, "INT_SDIV"),
            OpCode::IntRem => write!(f, "INT_REM"),
            OpCode::IntSrem => write!(f, "INT_SREM"),
            OpCode::IntNegate => write!(f, "INT_NEG"),
            OpCode::IntZext => write!(f, "INT_ZEXT"),
            OpCode::IntSext => write!(f, "INT_SEXT"),
            OpCode::IntCarry => write!(f, "INT_CARRY"),
            OpCode::IntScarry => write!(f, "INT_SCARRY"),
            OpCode::IntSborrow => write!(f, "INT_SBORROW"),
            OpCode::IntAnd => write!(f, "INT_AND"),
            OpCode::IntOr => write!(f, "INT_OR"),
            OpCode::IntXor => write!(f, "INT_XOR"),
            OpCode::IntLeft => write!(f, "INT_LEFT"),
            OpCode::IntRight => write!(f, "INT_RIGHT"),
            OpCode::IntSright => write!(f, "INT_SRIGHT"),
            OpCode::IntEqual => write!(f, "INT_EQUAL"),
            OpCode::IntNotEqual => write!(f, "INT_NOTEQUAL"),
            OpCode::IntLess => write!(f, "INT_LESS"),
            OpCode::IntLessEqual => write!(f, "INT_LESSEQUAL"),
            OpCode::IntSless => write!(f, "INT_SLESS"),
            OpCode::IntSlessEqual => write!(f, "INT_SLESSEQUAL"),
            OpCode::BoolAnd => write!(f, "BOOL_AND"),
            OpCode::BoolOr => write!(f, "BOOL_OR"),
            OpCode::BoolXor => write!(f, "BOOL_XOR"),
            OpCode::BoolNeg => write!(f, "BOOL_NEG"),
            OpCode::FloatAdd => write!(f, "FLOAT_ADD"),
            OpCode::FloatSub => write!(f, "FLOAT_SUB"),
            OpCode::FloatMult => write!(f, "FLOAT_MULT"),
            OpCode::FloatDiv => write!(f, "FLOAT_DIV"),
            OpCode::FloatNeg => write!(f, "FLOAT_NEG"),
            OpCode::Float2Float => write!(f, "FLOAT2FLOAT"),
            OpCode::Int2Float => write!(f, "INT2FLOAT"),
            OpCode::Float2Int => write!(f, "FLOAT2INT"),
            OpCode::FloatTrunc => write!(f, "FLOAT_TRUNC"),
            OpCode::FloatCeil => write!(f, "FLOAT_CEIL"),
            OpCode::FloatFloor => write!(f, "FLOAT_FLOOR"),
            OpCode::FloatRound => write!(f, "FLOAT_ROUND"),
            OpCode::FloatNan => write!(f, "FLOAT_NAN"),
            OpCode::FloatEqual => write!(f, "FLOAT_EQUAL"),
            OpCode::FloatNotEqual => write!(f, "FLOAT_NOTEQUAL"),
            OpCode::FloatLess => write!(f, "FLOAT_LESS"),
            OpCode::FloatLessEqual => write!(f, "FLOAT_LESSEQUAL"),
            OpCode::SegmentOp => write!(f, "SEGMENTOP"),
            OpCode::CpoolRef => write!(f, "CPOOLREF"),
            OpCode::New => write!(f, "NEW"),
            OpCode::Insert => write!(f, "INSERT"),
            OpCode::Extract => write!(f, "EXTRACT"),
            OpCode::Popcount => write!(f, "POPCOUNT"),
            OpCode::Lzcount => write!(f, "LZCOUNT"),
            OpCode::Piece => write!(f, "PIECE"),
            OpCode::Subpiece => write!(f, "SUBPIECE"),
            OpCode::Cast => write!(f, "CAST"),
            OpCode::PtrAdd => write!(f, "PTRADD"),
            OpCode::PtrSub => write!(f, "PTRSUB"),
            OpCode::MultiEqual => write!(f, "MULTIEQUAL"),
            OpCode::Indirect => write!(f, "INDIRECT"),
            OpCode::UserDefined(n) => write!(f, "USERDEF_{}", n),
        }
    }
}

// ---------------------------------------------------------------------------
// PcodeOp
// ---------------------------------------------------------------------------

/// A single P-code operation within a translation.
///
/// Each P-code operation consists of:
/// - An [`OpCode`] that identifies the operation type
/// - An optional output [`Varnode`] (destination of the operation)
/// - A list of input [`Varnode`]s (sources)
///
/// In the context of SLEIGH, P-code operations are emitted by constructor
/// templates when an instruction pattern matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeOp {
    /// The operation to perform
    pub opcode: OpCode,
    /// Output (destination) varnode, if any
    pub output: Option<Varnode>,
    /// Input (source) varnodes
    pub inputs: Vec<Varnode>,
    /// Sequence number within the translation (maintains original order)
    pub sequence: u32,
}

impl PcodeOp {
    /// Create a new P-code operation.
    pub fn new(opcode: OpCode, output: Option<Varnode>, inputs: Vec<Varnode>) -> Self {
        Self {
            opcode,
            output,
            inputs,
            sequence: 0,
        }
    }

    /// Create a new P-code operation with an explicit sequence number.
    pub fn with_sequence(
        opcode: OpCode,
        output: Option<Varnode>,
        inputs: Vec<Varnode>,
        sequence: u32,
    ) -> Self {
        Self {
            opcode,
            output,
            inputs,
            sequence,
        }
    }

    /// Returns the number of input varnodes.
    pub fn num_inputs(&self) -> usize {
        self.inputs.len()
    }

    /// Returns `true` if this operation is a no-op copy.
    /// A copy operation `v0 = v1` where the output varnode equals the input
    /// varnode is a no-op.
    pub fn is_noop_copy(&self) -> bool {
        if self.opcode != OpCode::Copy {
            return false;
        }
        if let (Some(out), Some(inp)) = (self.output.as_ref(), self.inputs.first()) {
            out == inp
        } else {
            false
        }
    }

    /// Returns `true` if this operation has no effect (dead code).
    /// An operation without an output varnode and without control-flow effect
    /// can be considered dead.
    pub fn is_dead(&self) -> bool {
        self.output.is_none() && !self.opcode.is_control_flow()
    }
}

impl fmt::Display for PcodeOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref out) = self.output {
            write!(f, "{} = {}", out, self.opcode)?;
        } else {
            write!(f, "{}", self.opcode)?;
        }
        for (i, inp) in self.inputs.iter().enumerate() {
            if i == 0 && self.output.is_some() {
                write!(f, "({}", inp)?;
            } else if i == 0 {
                write!(f, " {}", inp)?;
            } else {
                write!(f, ", {}", inp)?;
            }
        }
        if !self.inputs.is_empty() && self.output.is_some() {
            write!(f, ")")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spacetype_index_roundtrip() {
        for idx in 0..10u32 {
            let st = SpaceType::from_index(idx);
            assert_eq!(
                st.index(),
                idx,
                "SpaceType index roundtrip failed for {}",
                idx
            );
        }
    }

    #[test]
    fn test_varnode_constructors() {
        let reg = Varnode::register(0, 4);
        assert!(reg.is_register());
        assert!(!reg.is_constant());

        let ram = Varnode::ram(0x1000, 8);
        assert!(ram.is_address());

        let cnst = Varnode::constant(42, 4);
        assert!(cnst.is_constant());
        assert_eq!(cnst.offset, 42);

        let uniq = Varnode::unique(0, 4);
        assert!(uniq.is_unique());
    }

    #[test]
    fn test_opcode_roundtrip() {
        for n in 1..=70u32 {
            let op = OpCode::from_u32(n);
            assert_eq!(
                op.to_u32(),
                n,
                "OpCode roundtrip failed for {} (got {:?})",
                n,
                op
            );
        }
    }

    #[test]
    fn test_opcode_is_control_flow() {
        assert!(OpCode::Branch.is_control_flow());
        assert!(OpCode::Call.is_control_flow());
        assert!(OpCode::Return.is_control_flow());
        assert!(!OpCode::IntAdd.is_control_flow());
        assert!(!OpCode::Copy.is_control_flow());
    }

    #[test]
    fn test_pcodeop_display() {
        let op = PcodeOp::new(
            OpCode::IntAdd,
            Some(Varnode::register(0, 4)),
            vec![Varnode::register(4, 4), Varnode::constant(1, 4)],
        );
        let s = format!("{}", op);
        assert!(s.contains("INT_ADD"));
        assert!(s.contains("register"));
    }
}
