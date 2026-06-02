//! P-code operation codes.
//!
//! Defines all ~65 P-code opcodes used by Ghidra's decompiler intermediate
//! language, along with classification helpers, display formatting, and
//! parsing.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

// ---------------------------------------------------------------------------
// OpCode
// ---------------------------------------------------------------------------

/// All P-code operation codes.
///
/// P-code is a register-transfer language.  Every machine instruction
/// specified in a SLEIGH `.slaspec` file is lowered into one or more of these
/// operations.  The opcodes closely follow Ghidra's `CPUI_*` enumeration.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OpCode {
    // -- data movement -------------------------------------------------------
    /// Copy: `v = u`
    COPY,
    /// Load from memory: `v = *u` (pointer dereference)
    LOAD,
    /// Store to memory: `*u = v`
    STORE,

    // -- integer arithmetic --------------------------------------------------
    /// Unsigned integer addition: `out = in0 + in1`
    INT_ADD,
    /// Unsigned integer subtraction: `out = in0 - in1`
    INT_SUB,
    /// Unsigned integer multiplication: `out = in0 * in1`
    INT_MUL,
    /// Unsigned integer division: `out = in0 / in1`
    INT_DIV,
    /// Unsigned integer remainder: `out = in0 % in1`
    INT_REM,
    /// Signed integer division: `out = (signed)in0 / (signed)in1`
    INT_SDIV,
    /// Signed integer remainder: `out = (signed)in0 % (signed)in1`
    INT_SREM,
    /// Two's complement negation: `out = -in0`
    INT_NEGATE,
    /// Unsigned carry flag: `out = carry(in0 + in1)`
    INT_CARRY,
    /// Signed carry flag: `out = scarry(in0 + in1)`
    INT_SCARRY,
    /// Signed borrow flag: `out = sborrow(in0 - in1)`
    /// Sign extension: `out = sext(in0)`
    INT_SEXT,
    /// Zero extension: `out = zext(in0)`
    INT_ZEXT,

    // -- integer bitwise / shifts --------------------------------------------
    /// Bitwise AND: `out = in0 & in1`
    INT_AND,
    /// Bitwise OR: `out = in0 | in1`
    INT_OR,
    /// Bitwise XOR: `out = in0 ^ in1`
    INT_XOR,
    /// Logical left shift: `out = in0 << in1`
    INT_LEFT,
    /// Logical right shift: `out = in0 >> in1`
    INT_RIGHT,
    /// Arithmetic (signed) right shift: `out = in0 >>> in1`
    INT_SRIGHT,

    // -- boolean operations --------------------------------------------------
    /// Boolean negation: `out = !in0`
    BOOL_NEGATE,
    /// Boolean AND: `out = in0 && in1`
    BOOL_AND,
    /// Boolean OR: `out = in0 || in1`
    BOOL_OR,
    /// Boolean XOR: `out = in0 ^^ in1`
    BOOL_XOR,

    // -- floating-point arithmetic -------------------------------------------
    /// Float addition: `out = in0 + in1`
    FLOAT_ADD,
    /// Float subtraction: `out = in0 - in1`
    FLOAT_SUB,
    /// Float multiplication: `out = in0 * in1`
    FLOAT_MUL,
    /// Float division: `out = in0 / in1`
    FLOAT_DIV,
    /// Float negation: `out = -in0`
    FLOAT_NEG,
    /// Float absolute value: `out = abs(in0)`
    FLOAT_ABS,
    /// Float square root: `out = sqrt(in0)`
    FLOAT_SQRT,
    /// Float ceiling: `out = ceil(in0)`
    FLOAT_CEIL,
    /// Float floor: `out = floor(in0)`
    FLOAT_FLOOR,
    /// Float round to nearest: `out = round(in0)`
    FLOAT_ROUND,
    /// Float NaN: `out = NaN`
    FLOAT_NAN,

    // -- floating-point comparisons ------------------------------------------
    /// Float equality: `out = (in0 == in1) ? 1 : 0`
    FLOAT_EQUAL,
    /// Float inequality: `out = (in0 != in1) ? 1 : 0`
    FLOAT_NOTEQUAL,
    /// Float less-than: `out = (in0 < in1) ? 1 : 0`
    FLOAT_LESS,
    /// Float less-than-or-equal: `out = (in0 <= in1) ? 1 : 0`
    FLOAT_LESSEQUAL,

    // -- float <-> integer conversions ---------------------------------------
    /// Convert integer to float: `out = (float)in0`
    FLOAT_INT2FLOAT,
    /// Convert float to integer: `out = (int)in0`
    FLOAT_FLOAT2INT,
    /// Float truncation toward zero: `out = trunc(in0)`
    FLOAT_TRUNC,

    // -- control flow --------------------------------------------------------
    /// Unconditional branch to address
    BRANCH,
    /// Conditional branch: `if in1 then goto in0`
    CBRANCH,
    /// Indirect branch through register: `goto *in0`
    BRANCHIND,
    /// Call to fixed address
    CALL,
    /// Call to an external pseudo-operation (e.g., `syscall`)
    /// Indirect call through register: `call *in0`
    CALLIND,
    /// Return from subroutine: `return [in0]`
    RETURN,

    // -- integer comparisons -------------------------------------------------
    /// Equality: `out = (in0 == in1) ? 1 : 0`
    INT_EQUAL,
    /// Inequality: `out = (in0 != in1) ? 1 : 0`
    INT_NOTEQUAL,
    /// Unsigned less-than: `out = (in0 < in1) ? 1 : 0`
    INT_LESS,
    /// Unsigned less-than-or-equal: `out = (in0 <= in1) ? 1 : 0`
    INT_LESSEQUAL,
    /// Signed less-than: `out = (in0 <s in1) ? 1 : 0`
    INT_SLESS,
    /// Signed less-than-or-equal: `out = (in0 <=s in1) ? 1 : 0`
    INT_SLESSEQUAL,

    // -- extension / composition ---------------------------------------------
    /// Concatenate two varnodes: `out = in0 || in1`  (in0 = most-significant)
    PIECE,
    /// Truncate: `out = in0[low..low+size]`
    SUBPIECE,
    /// Popcount: `out = popcount(in0)`
    POPCOUNT,
    /// Leading-zero count: `out = lzcount(in0)`
    LZCOUNT,

    // -- user-defined / miscellaneous ----------------------------------------
    /// Constant-pool reference: load a value from the constant pool
    CPOOLREF,
    /// Allocate memory: `out = new(in0)`
    NEW,
    /// Bit-field insert: `out = insert(in0, in1, position, size)`
    INSERT,
    /// Bit-field extract: `out = extract(in0, position, size)`
    EXTRACT,

    // -- special -------------------------------------------------------------
    /// Segment-base operation: `out = segmentop(in0)`
    SEGMENTOP,
    /// Type cast: `out = (cast)in0`
    CAST,
    /// Phi-node: `out = phi(in0, in1, ...)`  (used in SSA form)
    MULTIEQUAL,
    /// Indirect effect (for analysis, may alias any varnode)
    INDIRECT,
    /// Pointer addition: `out = in0 + (in1 * in2)`  (base + index * scale)
    PTRADD,
    /// Pointer subtraction: `out = in0 - in1`
    PTRSUB,

    // -- sentinel ------------------------------------------------------------
    /// Unimplemented / illegal opcode placeholder
    UNIMPLEMENTED,
}

impl OpCode {
    /// Number of distinct opcodes.
    pub const COUNT: usize = 70;

    /// Human-readable name of this opcode (e.g., `"INT_ADD"`).
    pub fn name(self) -> &'static str {
        match self {
            OpCode::COPY => "COPY",
            OpCode::LOAD => "LOAD",
            OpCode::STORE => "STORE",
            OpCode::INT_ADD => "INT_ADD",
            OpCode::INT_SUB => "INT_SUB",
            OpCode::INT_MUL => "INT_MUL",
            OpCode::INT_DIV => "INT_DIV",
            OpCode::INT_REM => "INT_REM",
            OpCode::INT_SDIV => "INT_SDIV",
            OpCode::INT_SREM => "INT_SREM",
            OpCode::INT_NEGATE => "INT_NEGATE",
            OpCode::INT_CARRY => "INT_CARRY",
            OpCode::INT_SCARRY => "INT_SCARRY",
            OpCode::INT_SEXT => "INT_SEXT",
            OpCode::INT_ZEXT => "INT_ZEXT",
            OpCode::INT_AND => "INT_AND",
            OpCode::INT_OR => "INT_OR",
            OpCode::INT_XOR => "INT_XOR",
            OpCode::INT_LEFT => "INT_LEFT",
            OpCode::INT_RIGHT => "INT_RIGHT",
            OpCode::INT_SRIGHT => "INT_SRIGHT",
            OpCode::BOOL_NEGATE => "BOOL_NEGATE",
            OpCode::BOOL_AND => "BOOL_AND",
            OpCode::BOOL_OR => "BOOL_OR",
            OpCode::BOOL_XOR => "BOOL_XOR",
            OpCode::FLOAT_ADD => "FLOAT_ADD",
            OpCode::FLOAT_SUB => "FLOAT_SUB",
            OpCode::FLOAT_MUL => "FLOAT_MUL",
            OpCode::FLOAT_DIV => "FLOAT_DIV",
            OpCode::FLOAT_NEG => "FLOAT_NEG",
            OpCode::FLOAT_ABS => "FLOAT_ABS",
            OpCode::FLOAT_SQRT => "FLOAT_SQRT",
            OpCode::FLOAT_CEIL => "FLOAT_CEIL",
            OpCode::FLOAT_FLOOR => "FLOAT_FLOOR",
            OpCode::FLOAT_ROUND => "FLOAT_ROUND",
            OpCode::FLOAT_NAN => "FLOAT_NAN",
            OpCode::FLOAT_EQUAL => "FLOAT_EQUAL",
            OpCode::FLOAT_NOTEQUAL => "FLOAT_NOTEQUAL",
            OpCode::FLOAT_LESS => "FLOAT_LESS",
            OpCode::FLOAT_LESSEQUAL => "FLOAT_LESSEQUAL",
            OpCode::FLOAT_INT2FLOAT => "FLOAT_INT2FLOAT",
            OpCode::FLOAT_FLOAT2INT => "FLOAT_FLOAT2INT",
            OpCode::FLOAT_TRUNC => "FLOAT_TRUNC",
            OpCode::BRANCH => "BRANCH",
            OpCode::CBRANCH => "CBRANCH",
            OpCode::BRANCHIND => "BRANCHIND",
            OpCode::CALL => "CALL",
            OpCode::CALLIND => "CALLIND",
            OpCode::RETURN => "RETURN",
            OpCode::INT_EQUAL => "INT_EQUAL",
            OpCode::INT_NOTEQUAL => "INT_NOTEQUAL",
            OpCode::INT_LESS => "INT_LESS",
            OpCode::INT_LESSEQUAL => "INT_LESSEQUAL",
            OpCode::INT_SLESS => "INT_SLESS",
            OpCode::INT_SLESSEQUAL => "INT_SLESSEQUAL",
            OpCode::PIECE => "PIECE",
            OpCode::SUBPIECE => "SUBPIECE",
            OpCode::POPCOUNT => "POPCOUNT",
            OpCode::LZCOUNT => "LZCOUNT",
            OpCode::CPOOLREF => "CPOOLREF",
            OpCode::NEW => "NEW",
            OpCode::INSERT => "INSERT",
            OpCode::EXTRACT => "EXTRACT",
            OpCode::SEGMENTOP => "SEGMENTOP",
            OpCode::CAST => "CAST",
            OpCode::MULTIEQUAL => "MULTIEQUAL",
            OpCode::INDIRECT => "INDIRECT",
            OpCode::PTRADD => "PTRADD",
            OpCode::PTRSUB => "PTRSUB",
            OpCode::UNIMPLEMENTED => "UNIMPLEMENTED",
        }
    }

    // ------------------------------------------------------------------
    // Classification helpers
    // ------------------------------------------------------------------

    /// Is this opcode an unconditional or conditional branch?
    pub fn is_branch(self) -> bool {
        matches!(self, OpCode::BRANCH | OpCode::CBRANCH | OpCode::BRANCHIND)
    }

    /// Is this opcode a call (direct or indirect)?
    pub fn is_call(self) -> bool {
        matches!(self, OpCode::CALL | OpCode::CALLIND)
    }

    /// Is this opcode a return?
    pub fn is_return(self) -> bool {
        matches!(self, OpCode::RETURN)
    }

    /// Does this opcode alter control flow (branch, call, return)?
    pub fn is_flow(self) -> bool {
        self.is_branch() || self.is_call() || self.is_return()
    }

    /// Does this opcode perform integer arithmetic?
    pub fn is_arithmetic(self) -> bool {
        matches!(
            self,
            OpCode::INT_ADD
                | OpCode::INT_SUB
                | OpCode::INT_MUL
                | OpCode::INT_DIV
                | OpCode::INT_SDIV
                | OpCode::INT_REM
                | OpCode::INT_SREM
                | OpCode::INT_NEGATE
                | OpCode::INT_CARRY
                | OpCode::INT_SCARRY
        )
    }

    /// Does this opcode involve floating-point computation?
    pub fn is_float(self) -> bool {
        matches!(
            self,
            OpCode::FLOAT_ADD
                | OpCode::FLOAT_SUB
                | OpCode::FLOAT_MUL
                | OpCode::FLOAT_DIV
                | OpCode::FLOAT_NEG
                | OpCode::FLOAT_ABS
                | OpCode::FLOAT_SQRT
                | OpCode::FLOAT_CEIL
                | OpCode::FLOAT_FLOOR
                | OpCode::FLOAT_ROUND
                | OpCode::FLOAT_NAN
                | OpCode::FLOAT_EQUAL
                | OpCode::FLOAT_NOTEQUAL
                | OpCode::FLOAT_LESS
                | OpCode::FLOAT_LESSEQUAL
                | OpCode::FLOAT_INT2FLOAT
                | OpCode::FLOAT_FLOAT2INT
                | OpCode::FLOAT_TRUNC
        )
    }

    /// Does this opcode perform bitwise or boolean logic?
    pub fn is_logical(self) -> bool {
        matches!(
            self,
            OpCode::INT_AND
                | OpCode::INT_OR
                | OpCode::INT_XOR
                | OpCode::BOOL_AND
                | OpCode::BOOL_OR
                | OpCode::BOOL_XOR
                | OpCode::BOOL_NEGATE
        )
    }

    /// Is this opcode an integer or float comparison?
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
        )
    }

    /// Is this opcode a shift or rotate?
    pub fn is_shift(self) -> bool {
        matches!(self, OpCode::INT_LEFT | OpCode::INT_RIGHT | OpCode::INT_SRIGHT)
    }

    /// Does this opcode modify memory or global state?
    pub fn has_side_effects(self) -> bool {
        matches!(
            self,
            OpCode::STORE
                | OpCode::CALL
                | OpCode::CALLIND
                | OpCode::BRANCH
                | OpCode::CBRANCH
                | OpCode::BRANCHIND
                | OpCode::RETURN
                | OpCode::NEW
        )
    }

    /// Is this opcode commutative? (i.e., `f(a,b) == f(b,a)`)
    pub fn is_commutative(self) -> bool {
        matches!(
            self,
            OpCode::INT_ADD
                | OpCode::INT_MUL
                | OpCode::INT_AND
                | OpCode::INT_OR
                | OpCode::INT_XOR
                | OpCode::FLOAT_ADD
                | OpCode::FLOAT_MUL
                | OpCode::BOOL_AND
                | OpCode::BOOL_OR
                | OpCode::BOOL_XOR
                | OpCode::INT_EQUAL
                | OpCode::INT_NOTEQUAL
                | OpCode::FLOAT_EQUAL
                | OpCode::FLOAT_NOTEQUAL
                | OpCode::PIECE
        )
    }

    /// Is this opcode a binary operation (exactly 2 inputs)?
    pub fn is_binary(self) -> bool {
        self.input_count_hint() == Some(2)
    }

    /// Is this opcode a unary operation (exactly 1 input)?
    pub fn is_unary(self) -> bool {
        self.input_count_hint() == Some(1)
    }

    // ------------------------------------------------------------------
    // Input / output hints
    // ------------------------------------------------------------------

    /// Returns the typical number of input varnodes for this opcode.
    ///
    /// Returns `None` when the count is variable (e.g., `CALL`).
    pub fn input_count_hint(self) -> Option<usize> {
        match self {
            OpCode::COPY => Some(1),
            OpCode::LOAD => Some(2),
            OpCode::STORE => Some(3),
            OpCode::INT_ADD
            | OpCode::INT_SUB
            | OpCode::INT_MUL
            | OpCode::INT_DIV
            | OpCode::INT_SDIV
            | OpCode::INT_REM
            | OpCode::INT_SREM
            | OpCode::INT_AND
            | OpCode::INT_OR
            | OpCode::INT_XOR
            | OpCode::INT_LEFT
            | OpCode::INT_RIGHT
            | OpCode::INT_SRIGHT
            | OpCode::INT_EQUAL
            | OpCode::INT_NOTEQUAL
            | OpCode::INT_SLESS
            | OpCode::INT_SLESSEQUAL
            | OpCode::INT_LESS
            | OpCode::INT_LESSEQUAL
            | OpCode::FLOAT_ADD
            | OpCode::FLOAT_SUB
            | OpCode::FLOAT_MUL
            | OpCode::FLOAT_DIV
            | OpCode::FLOAT_EQUAL
            | OpCode::FLOAT_NOTEQUAL
            | OpCode::FLOAT_LESS
            | OpCode::FLOAT_LESSEQUAL
            | OpCode::BOOL_AND
            | OpCode::BOOL_OR
            | OpCode::BOOL_XOR => Some(2),
            OpCode::INT_NEGATE
            | OpCode::INT_SEXT
            | OpCode::INT_ZEXT
            | OpCode::BOOL_NEGATE
            | OpCode::FLOAT_NEG
            | OpCode::FLOAT_ABS
            | OpCode::FLOAT_SQRT
            | OpCode::FLOAT_CEIL
            | OpCode::FLOAT_FLOOR
            | OpCode::FLOAT_ROUND
            | OpCode::FLOAT_INT2FLOAT
            | OpCode::FLOAT_FLOAT2INT
            | OpCode::FLOAT_TRUNC
            | OpCode::SUBPIECE
            | OpCode::POPCOUNT
            | OpCode::LZCOUNT
            | OpCode::CAST
            | OpCode::BRANCHIND => Some(1),
            OpCode::BRANCH => Some(1),
            OpCode::CBRANCH => Some(2),
            OpCode::PTRADD => Some(3),
            OpCode::PTRSUB => Some(2),
            OpCode::PIECE => Some(2),
            OpCode::INT_CARRY | OpCode::INT_SCARRY => Some(2),
            OpCode::FLOAT_NAN => Some(0),
            OpCode::RETURN => None,                              // optional return value
            OpCode::CALL | OpCode::CALLIND => None,              // variable args
            OpCode::INSERT | OpCode::EXTRACT => None,            // variable operands
            OpCode::SEGMENTOP | OpCode::CPOOLREF | OpCode::NEW => None,
            OpCode::MULTIEQUAL => None,                          // phi nodes have variable inputs
            OpCode::INDIRECT => Some(1),
            OpCode::UNIMPLEMENTED => Some(0),
        }
    }

    /// Returns the typical number of output varnodes for this opcode.
    ///
    /// Most opcodes produce exactly one output.  Stores, branches, and calls
    /// may produce zero, and `CALL` may produce one optional output.
    pub fn output_count_hint(self) -> Option<usize> {
        match self {
            OpCode::STORE
            | OpCode::BRANCH
            | OpCode::CBRANCH
            | OpCode::BRANCHIND
            | OpCode::RETURN
            | OpCode::UNIMPLEMENTED => Some(0),
            OpCode::CALL | OpCode::CALLIND => None, // optional
            _ => Some(1),
        }
    }

    /// Returns `true` when this opcode always produces an output varnode.
    pub fn always_has_output(self) -> bool {
        self.output_count_hint() == Some(1)
    }
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// FromStr -- parse an opcode name
// ---------------------------------------------------------------------------

/// Error returned when parsing an opcode name fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseOpCodeError {
    pub name: String,
}

impl fmt::Display for ParseOpCodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown P-code opcode: {}", self.name)
    }
}

impl std::error::Error for ParseOpCodeError {}

impl FromStr for OpCode {
    type Err = ParseOpCodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "COPY" => Ok(OpCode::COPY),
            "LOAD" => Ok(OpCode::LOAD),
            "STORE" => Ok(OpCode::STORE),
            "INT_ADD" => Ok(OpCode::INT_ADD),
            "INT_SUB" => Ok(OpCode::INT_SUB),
            "INT_MUL" => Ok(OpCode::INT_MUL),
            "INT_DIV" => Ok(OpCode::INT_DIV),
            "INT_REM" => Ok(OpCode::INT_REM),
            "INT_SDIV" => Ok(OpCode::INT_SDIV),
            "INT_SREM" => Ok(OpCode::INT_SREM),
            "INT_NEGATE" => Ok(OpCode::INT_NEGATE),
            "INT_CARRY" => Ok(OpCode::INT_CARRY),
            "INT_SCARRY" => Ok(OpCode::INT_SCARRY),
            "INT_SEXT" => Ok(OpCode::INT_SEXT),
            "INT_ZEXT" => Ok(OpCode::INT_ZEXT),
            "INT_AND" => Ok(OpCode::INT_AND),
            "INT_OR" => Ok(OpCode::INT_OR),
            "INT_XOR" => Ok(OpCode::INT_XOR),
            "INT_LEFT" => Ok(OpCode::INT_LEFT),
            "INT_RIGHT" => Ok(OpCode::INT_RIGHT),
            "INT_SRIGHT" => Ok(OpCode::INT_SRIGHT),
            "BOOL_NEGATE" => Ok(OpCode::BOOL_NEGATE),
            "BOOL_AND" => Ok(OpCode::BOOL_AND),
            "BOOL_OR" => Ok(OpCode::BOOL_OR),
            "BOOL_XOR" => Ok(OpCode::BOOL_XOR),
            "FLOAT_ADD" => Ok(OpCode::FLOAT_ADD),
            "FLOAT_SUB" => Ok(OpCode::FLOAT_SUB),
            "FLOAT_MUL" => Ok(OpCode::FLOAT_MUL),
            "FLOAT_DIV" => Ok(OpCode::FLOAT_DIV),
            "FLOAT_NEG" => Ok(OpCode::FLOAT_NEG),
            "FLOAT_ABS" => Ok(OpCode::FLOAT_ABS),
            "FLOAT_SQRT" => Ok(OpCode::FLOAT_SQRT),
            "FLOAT_CEIL" => Ok(OpCode::FLOAT_CEIL),
            "FLOAT_FLOOR" => Ok(OpCode::FLOAT_FLOOR),
            "FLOAT_ROUND" => Ok(OpCode::FLOAT_ROUND),
            "FLOAT_NAN" => Ok(OpCode::FLOAT_NAN),
            "FLOAT_EQUAL" => Ok(OpCode::FLOAT_EQUAL),
            "FLOAT_NOTEQUAL" => Ok(OpCode::FLOAT_NOTEQUAL),
            "FLOAT_LESS" => Ok(OpCode::FLOAT_LESS),
            "FLOAT_LESSEQUAL" => Ok(OpCode::FLOAT_LESSEQUAL),
            "FLOAT_INT2FLOAT" => Ok(OpCode::FLOAT_INT2FLOAT),
            "FLOAT_FLOAT2INT" => Ok(OpCode::FLOAT_FLOAT2INT),
            "FLOAT_TRUNC" => Ok(OpCode::FLOAT_TRUNC),
            "BRANCH" => Ok(OpCode::BRANCH),
            "CBRANCH" => Ok(OpCode::CBRANCH),
            "BRANCHIND" => Ok(OpCode::BRANCHIND),
            "CALL" => Ok(OpCode::CALL),
            "CALLIND" => Ok(OpCode::CALLIND),
            "RETURN" => Ok(OpCode::RETURN),
            "INT_EQUAL" => Ok(OpCode::INT_EQUAL),
            "INT_NOTEQUAL" => Ok(OpCode::INT_NOTEQUAL),
            "INT_LESS" => Ok(OpCode::INT_LESS),
            "INT_LESSEQUAL" => Ok(OpCode::INT_LESSEQUAL),
            "INT_SLESS" => Ok(OpCode::INT_SLESS),
            "INT_SLESSEQUAL" => Ok(OpCode::INT_SLESSEQUAL),
            "PIECE" => Ok(OpCode::PIECE),
            "SUBPIECE" => Ok(OpCode::SUBPIECE),
            "POPCOUNT" => Ok(OpCode::POPCOUNT),
            "LZCOUNT" => Ok(OpCode::LZCOUNT),
            "CPOOLREF" => Ok(OpCode::CPOOLREF),
            "NEW" => Ok(OpCode::NEW),
            "INSERT" => Ok(OpCode::INSERT),
            "EXTRACT" => Ok(OpCode::EXTRACT),
            "SEGMENTOP" => Ok(OpCode::SEGMENTOP),
            "CAST" => Ok(OpCode::CAST),
            "MULTIEQUAL" => Ok(OpCode::MULTIEQUAL),
            "INDIRECT" => Ok(OpCode::INDIRECT),
            "PTRADD" => Ok(OpCode::PTRADD),
            "PTRSUB" => Ok(OpCode::PTRSUB),
            "UNIMPLEMENTED" => Ok(OpCode::UNIMPLEMENTED),
            _ => Err(ParseOpCodeError {
                name: s.to_string(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// u8 <-> OpCode conversions (wire / serialisation)
// ---------------------------------------------------------------------------

impl TryFrom<u8> for OpCode {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(OpCode::COPY),
            2 => Ok(OpCode::LOAD),
            3 => Ok(OpCode::STORE),
            4 => Ok(OpCode::BRANCH),
            5 => Ok(OpCode::CBRANCH),
            6 => Ok(OpCode::BRANCHIND),
            7 => Ok(OpCode::CALL),
            8 => Ok(OpCode::CALLIND),
            9 => Ok(OpCode::RETURN),
            10 => Ok(OpCode::INT_EQUAL),
            11 => Ok(OpCode::INT_NOTEQUAL),
            12 => Ok(OpCode::INT_SLESS),
            13 => Ok(OpCode::INT_SLESSEQUAL),
            14 => Ok(OpCode::INT_LESS),
            15 => Ok(OpCode::INT_LESSEQUAL),
            16 => Ok(OpCode::INT_ZEXT),
            17 => Ok(OpCode::INT_SEXT),
            18 => Ok(OpCode::INT_ADD),
            19 => Ok(OpCode::INT_SUB),
            20 => Ok(OpCode::INT_CARRY),
            21 => Ok(OpCode::INT_SCARRY),
            22 => Ok(OpCode::INT_NEGATE),
            23 => Ok(OpCode::INT_XOR),
            24 => Ok(OpCode::INT_AND),
            25 => Ok(OpCode::INT_OR),
            26 => Ok(OpCode::INT_LEFT),
            27 => Ok(OpCode::INT_RIGHT),
            28 => Ok(OpCode::INT_SRIGHT),
            29 => Ok(OpCode::INT_MUL),
            30 => Ok(OpCode::INT_DIV),
            31 => Ok(OpCode::INT_SDIV),
            32 => Ok(OpCode::INT_REM),
            33 => Ok(OpCode::INT_SREM),
            34 => Ok(OpCode::BOOL_NEGATE),
            35 => Ok(OpCode::BOOL_XOR),
            36 => Ok(OpCode::BOOL_AND),
            37 => Ok(OpCode::BOOL_OR),
            38 => Ok(OpCode::FLOAT_EQUAL),
            39 => Ok(OpCode::FLOAT_NOTEQUAL),
            40 => Ok(OpCode::FLOAT_LESS),
            41 => Ok(OpCode::FLOAT_LESSEQUAL),
            42 => Ok(OpCode::FLOAT_NAN),
            43 => Ok(OpCode::FLOAT_ADD),
            44 => Ok(OpCode::FLOAT_DIV),
            45 => Ok(OpCode::FLOAT_MUL),
            46 => Ok(OpCode::FLOAT_SUB),
            47 => Ok(OpCode::FLOAT_NEG),
            48 => Ok(OpCode::FLOAT_ABS),
            49 => Ok(OpCode::FLOAT_SQRT),
            50 => Ok(OpCode::FLOAT_INT2FLOAT),
            51 => Ok(OpCode::FLOAT_FLOAT2INT),
            52 => Ok(OpCode::FLOAT_TRUNC),
            53 => Ok(OpCode::FLOAT_CEIL),
            54 => Ok(OpCode::FLOAT_FLOOR),
            55 => Ok(OpCode::FLOAT_ROUND),
            56 => Ok(OpCode::MULTIEQUAL),
            57 => Ok(OpCode::INDIRECT),
            58 => Ok(OpCode::PIECE),
            59 => Ok(OpCode::SUBPIECE),
            60 => Ok(OpCode::CAST),
            61 => Ok(OpCode::PTRADD),
            62 => Ok(OpCode::PTRSUB),
            63 => Ok(OpCode::SEGMENTOP),
            64 => Ok(OpCode::CPOOLREF),
            65 => Ok(OpCode::NEW),
            66 => Ok(OpCode::INSERT),
            67 => Ok(OpCode::EXTRACT),
            68 => Ok(OpCode::POPCOUNT),
            69 => Ok(OpCode::LZCOUNT),
            70 => Ok(OpCode::UNIMPLEMENTED),
            _ => Err("unknown P-code opcode number"),
        }
    }
}

impl From<OpCode> for u8 {
    fn from(op: OpCode) -> u8 {
        match op {
            OpCode::COPY => 1,
            OpCode::LOAD => 2,
            OpCode::STORE => 3,
            OpCode::BRANCH => 4,
            OpCode::CBRANCH => 5,
            OpCode::BRANCHIND => 6,
            OpCode::CALL => 7,
            OpCode::CALLIND => 8,
            OpCode::RETURN => 9,
            OpCode::INT_EQUAL => 10,
            OpCode::INT_NOTEQUAL => 11,
            OpCode::INT_SLESS => 12,
            OpCode::INT_SLESSEQUAL => 13,
            OpCode::INT_LESS => 14,
            OpCode::INT_LESSEQUAL => 15,
            OpCode::INT_ZEXT => 16,
            OpCode::INT_SEXT => 17,
            OpCode::INT_ADD => 18,
            OpCode::INT_SUB => 19,
            OpCode::INT_CARRY => 20,
            OpCode::INT_SCARRY => 21,
            OpCode::INT_NEGATE => 22,
            OpCode::INT_XOR => 23,
            OpCode::INT_AND => 24,
            OpCode::INT_OR => 25,
            OpCode::INT_LEFT => 26,
            OpCode::INT_RIGHT => 27,
            OpCode::INT_SRIGHT => 28,
            OpCode::INT_MUL => 29,
            OpCode::INT_DIV => 30,
            OpCode::INT_SDIV => 31,
            OpCode::INT_REM => 32,
            OpCode::INT_SREM => 33,
            OpCode::BOOL_NEGATE => 34,
            OpCode::BOOL_XOR => 35,
            OpCode::BOOL_AND => 36,
            OpCode::BOOL_OR => 37,
            OpCode::FLOAT_EQUAL => 38,
            OpCode::FLOAT_NOTEQUAL => 39,
            OpCode::FLOAT_LESS => 40,
            OpCode::FLOAT_LESSEQUAL => 41,
            OpCode::FLOAT_NAN => 42,
            OpCode::FLOAT_ADD => 43,
            OpCode::FLOAT_DIV => 44,
            OpCode::FLOAT_MUL => 45,
            OpCode::FLOAT_SUB => 46,
            OpCode::FLOAT_NEG => 47,
            OpCode::FLOAT_ABS => 48,
            OpCode::FLOAT_SQRT => 49,
            OpCode::FLOAT_INT2FLOAT => 50,
            OpCode::FLOAT_FLOAT2INT => 51,
            OpCode::FLOAT_TRUNC => 52,
            OpCode::FLOAT_CEIL => 53,
            OpCode::FLOAT_FLOOR => 54,
            OpCode::FLOAT_ROUND => 55,
            OpCode::MULTIEQUAL => 56,
            OpCode::INDIRECT => 57,
            OpCode::PIECE => 58,
            OpCode::SUBPIECE => 59,
            OpCode::CAST => 60,
            OpCode::PTRADD => 61,
            OpCode::PTRSUB => 62,
            OpCode::SEGMENTOP => 63,
            OpCode::CPOOLREF => 64,
            OpCode::NEW => 65,
            OpCode::INSERT => 66,
            OpCode::EXTRACT => 67,
            OpCode::POPCOUNT => 68,
            OpCode::LZCOUNT => 69,
            OpCode::UNIMPLEMENTED => 70,
        }
    }
}

// ---------------------------------------------------------------------------
// Iterator over all opcodes
// ---------------------------------------------------------------------------

/// Iterator that yields every [`OpCode`] variant exactly once.
pub struct OpCodeIter {
    idx: u8,
}

impl OpCodeIter {
    /// Create a new iterator over all opcodes.
    pub fn new() -> Self {
        Self { idx: 1 }
    }
}

impl Default for OpCodeIter {
    fn default() -> Self {
        Self::new()
    }
}

impl Iterator for OpCodeIter {
    type Item = OpCode;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let v = self.idx;
            self.idx += 1;
            match OpCode::try_from(v) {
                Ok(op) => return Some(op),
                Err(_) if v > 70 => return None,
                Err(_) => continue,
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = 70usize.saturating_sub(self.idx as usize).min(OpCode::COUNT);
        (0, Some(remaining))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_count_unique() {
        // Every opcode has a unique name.
        let mut seen = std::collections::HashSet::new();
        for op in OpCodeIter::new() {
            let name = op.name();
            assert!(seen.insert(name), "duplicate opcode name: {}", name);
        }
        assert_eq!(seen.len(), OpCode::COUNT);
    }

    #[test]
    fn test_opcode_display() {
        assert_eq!(OpCode::COPY.to_string(), "COPY");
        assert_eq!(OpCode::INT_ADD.to_string(), "INT_ADD");
        assert_eq!(OpCode::FLOAT_NEG.to_string(), "FLOAT_NEG");
        assert_eq!(OpCode::UNIMPLEMENTED.to_string(), "UNIMPLEMENTED");
    }

    #[test]
    fn test_opcode_from_str() {
        assert_eq!("COPY".parse::<OpCode>().unwrap(), OpCode::COPY);
        assert_eq!("INT_ADD".parse::<OpCode>().unwrap(), OpCode::INT_ADD);
        assert_eq!("BRANCH".parse::<OpCode>().unwrap(), OpCode::BRANCH);
        assert_eq!(
            "UNIMPLEMENTED".parse::<OpCode>().unwrap(),
            OpCode::UNIMPLEMENTED
        );
    }

    #[test]
    fn test_from_str_roundtrip() {
        for op in OpCodeIter::new() {
            let s = op.to_string();
            let parsed: OpCode = s.parse().expect("roundtrip parse failed");
            assert_eq!(op, parsed, "roundtrip failed for {:?}", op);
        }
    }

    #[test]
    fn test_from_str_invalid() {
        assert!("INVALID".parse::<OpCode>().is_err());
        assert!("".parse::<OpCode>().is_err());
        assert!("float_add".parse::<OpCode>().is_err());
    }

    #[test]
    fn test_opcode_u8_roundtrip() {
        for op in OpCodeIter::new() {
            let v: u8 = op.into();
            let back = OpCode::try_from(v).expect("u8 roundtrip failed");
            assert_eq!(op, back, "u8 roundtrip failed for {:?} (value={})", op, v);
        }
    }

    #[test]
    fn test_classification() {
        // Arithmetic
        assert!(OpCode::INT_ADD.is_arithmetic());
        assert!(OpCode::INT_SUB.is_arithmetic());
        assert!(OpCode::INT_MUL.is_arithmetic());
        assert!(!OpCode::INT_AND.is_arithmetic());

        // Float
        assert!(OpCode::FLOAT_ADD.is_float());
        assert!(OpCode::FLOAT_NEG.is_float());
        assert!(!OpCode::INT_ADD.is_float());

        // Branch
        assert!(OpCode::BRANCH.is_branch());
        assert!(OpCode::CBRANCH.is_branch());
        assert!(OpCode::BRANCHIND.is_branch());
        assert!(!OpCode::CALL.is_branch());

        // Call
        assert!(OpCode::CALL.is_call());
        assert!(OpCode::CALLIND.is_call());

        // Flow
        assert!(OpCode::BRANCH.is_flow());
        assert!(OpCode::CALL.is_flow());
        assert!(OpCode::RETURN.is_flow());

        // Logical
        assert!(OpCode::INT_AND.is_logical());
        assert!(OpCode::BOOL_NEGATE.is_logical());

        // Comparison
        assert!(OpCode::INT_EQUAL.is_comparison());
        assert!(OpCode::FLOAT_LESS.is_comparison());

        // Shift
        assert!(OpCode::INT_LEFT.is_shift());
        assert!(OpCode::INT_RIGHT.is_shift());
        assert!(OpCode::INT_SRIGHT.is_shift());

        // Side effects
        assert!(OpCode::STORE.has_side_effects());
        assert!(OpCode::RETURN.has_side_effects());
        assert!(!OpCode::INT_ADD.has_side_effects());

        // Commutative
        assert!(OpCode::INT_ADD.is_commutative());
        assert!(!OpCode::INT_SUB.is_commutative());
        assert!(OpCode::INT_AND.is_commutative());
    }

    #[test]
    fn test_input_output_hints() {
        // Binary
        assert_eq!(OpCode::INT_ADD.input_count_hint(), Some(2));
        assert_eq!(OpCode::INT_MUL.input_count_hint(), Some(2));
        // Unary
        assert_eq!(OpCode::INT_NEGATE.input_count_hint(), Some(1));
        assert_eq!(OpCode::COPY.input_count_hint(), Some(1));
        // Variable
        assert_eq!(OpCode::CALL.input_count_hint(), None);
        assert_eq!(OpCode::MULTIEQUAL.input_count_hint(), None);
        // No output
        assert_eq!(OpCode::STORE.output_count_hint(), Some(0));
        assert_eq!(OpCode::BRANCH.output_count_hint(), Some(0));
        // Has output
        assert_eq!(OpCode::INT_ADD.output_count_hint(), Some(1));
        // Variable output
        assert_eq!(OpCode::CALL.output_count_hint(), None);

        assert!(OpCode::INT_ADD.always_has_output());
        assert!(!OpCode::BRANCH.always_has_output());
    }

    #[test]
    fn test_is_binary_unary() {
        assert!(OpCode::INT_ADD.is_binary());
        assert!(!OpCode::INT_NEGATE.is_binary());
        assert!(OpCode::INT_NEGATE.is_unary());
        assert!(!OpCode::INT_ADD.is_unary());
    }
}
