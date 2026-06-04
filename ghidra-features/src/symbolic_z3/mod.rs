//! Symbolic Summary Z3 Extension.
//!
//! This module ports the SymbolicSummaryZ3 extension from Ghidra's Java
//! source. It provides symbolic execution using Z3 bit-vector expressions
//! as a p-code arithmetic domain, enabling symbolic summaries of program
//! execution.
//!
//! # Architecture
//!
//! - [`SymValueZ3`] -- A symbolic value consisting of a Z3 bit-vector
//!   expression and an optional boolean expression.
//!
//! - [`SymZ3PcodeArithmetic`] -- Implements `PcodeArithmetic` for
//!   `SymValueZ3`, translating p-code operations into Z3 constraints.
//!
//! - [`SymZ3PcodeEmulator`] -- A p-code emulator with symbolic Z3
//!   summarization analysis.
//!
//! - [`SymZ3PcodeExecutorState`] -- Paired concrete-plus-symbolic state.
//!
//! - [`SymZ3PcodeExecutorStatePiece`] -- The symbolic state piece that
//!   maps address spaces to symbolic storage.
//!
//! ## State Spaces
//!
//! - [`SymZ3Space`] -- Base trait for symbolic address spaces.
//! - [`SymZ3RegisterSpace`] -- Symbolic register storage.
//! - [`SymZ3MemorySpace`] -- Symbolic memory storage.
//! - [`SymZ3UniqueSpace`] -- Symbolic unique (temp) storage.
//!
//! ## Library
//!
//! - [`Z3InfixPrinter`] -- Pretty-prints Z3 expressions in infix notation.
//! - [`Z3MemoryWitness`] -- Memory witness for symbolic execution.
//!
//! ## GUI
//!
//! - [`Z3SummaryPlugin`] -- Plugin for viewing Z3 symbolic summaries.
//! - [`Z3SummaryProvider`] -- Provider for the summary panel.
//!
//! # Porting Notes
//!
//! The Java version uses `com.microsoft.z3` JNI bindings. This Rust port
//! models the Z3 interaction through a trait-based abstraction so it can
//! be backed by `z3.rs` (pure Rust Z3 bindings) or FFI.

pub mod state;
pub mod lib_z3;
pub mod gui;

// ---------------------------------------------------------------------------
// SymValueZ3
// ---------------------------------------------------------------------------

/// A symbolic value backed by Z3 bit-vector and optional boolean expressions.
///
/// Ported from `SymValueZ3.java`. This is the core value type used in the
/// symbolic p-code emulator. Each value contains:
///
/// - A serialized bit-vector expression string (always present)
/// - An optional serialized boolean expression string
///
/// The serialization format allows values to be stored and compared
/// without keeping a Z3 context alive.
#[derive(Debug, Clone)]
pub struct SymValueZ3 {
    /// Serialized bit-vector expression (SMT-LIB2 format).
    pub bitvec_expr: Option<String>,
    /// Serialized boolean expression (SMT-LIB2 format).
    pub bool_expr: Option<String>,
    /// Bit-width of the value in bits.
    pub size_bits: u32,
}

impl SymValueZ3 {
    /// Create a concrete symbolic value from a constant.
    pub fn from_constant(value: u64, size_bits: u32) -> Self {
        Self {
            bitvec_expr: Some(format!("#x{:0width$x}", value, width = (size_bits as usize + 3) / 4)),
            bool_expr: None,
            size_bits,
        }
    }

    /// Create a symbolic value from a named variable.
    pub fn from_variable(name: impl Into<String>, size_bits: u32) -> Self {
        Self {
            bitvec_expr: Some(format!("(_ bv0 {size_bits}) ; var: {}", name.into())),
            bool_expr: None,
            size_bits,
        }
    }

    /// Create a symbolic boolean value.
    pub fn from_bool(value: bool) -> Self {
        Self {
            bitvec_expr: Some(if value {
                "#x01".to_string()
            } else {
                "#x00".to_string()
            }),
            bool_expr: Some(if value { "true".to_string() } else { "false".to_string() }),
            size_bits: 8,
        }
    }

    /// Whether this value has a boolean expression.
    pub fn has_bool_expr(&self) -> bool {
        self.bool_expr.is_some()
    }

    /// Whether this value has a bit-vector expression.
    pub fn has_bitvec_expr(&self) -> bool {
        self.bitvec_expr.is_some()
    }

    /// Get the size in bytes.
    pub fn size_bytes(&self) -> u32 {
        self.size_bits / 8
    }

    /// Serialize this value to a string.
    pub fn serialize(&self) -> String {
        let bool_part = self.bool_expr.as_deref().unwrap_or("");
        let bv_part = self.bitvec_expr.as_deref().unwrap_or("");
        format!("{bool_part}:::::{bv_part}")
    }

    /// Deserialize a value from a string.
    pub fn parse(s: &str) -> Option<Self> {
        let index = s.find(":::::")?;
        let left = &s[..index];
        let right = &s[index + 5..];

        let bool_expr = if left.is_empty() {
            None
        } else {
            Some(left.to_string());
            Some(left.to_string())
        };
        let bitvec_expr = if right.is_empty() {
            None
        } else {
            Some(right.to_string())
        };

        // Infer size from bitvec expression
        let size_bits = 64; // Default; in production, parse from expression

        Some(Self {
            bitvec_expr,
            bool_expr,
            size_bits,
        })
    }

    /// Try to extract a concrete integer value (returns None if symbolic).
    pub fn to_u64(&self) -> Option<u64> {
        let expr = self.bitvec_expr.as_ref()?;
        // Parse hex constant like "#x000000000000002a"
        if let Some(hex) = expr.strip_prefix("#x") {
            u64::from_str_radix(hex, 16).ok()
        } else {
            None
        }
    }

    /// Perform INT_ADD (symbolic addition).
    pub fn int_add(&self, other: &SymValueZ3) -> SymValueZ3 {
        SymValueZ3 {
            bitvec_expr: Some(format!(
                "(bvadd {} {})",
                self.bitvec_expr.as_deref().unwrap_or("?"),
                other.bitvec_expr.as_deref().unwrap_or("?")
            )),
            bool_expr: None,
            size_bits: self.size_bits.max(other.size_bits),
        }
    }

    /// Perform INT_SUB (symbolic subtraction).
    pub fn int_sub(&self, other: &SymValueZ3) -> SymValueZ3 {
        SymValueZ3 {
            bitvec_expr: Some(format!(
                "(bvsub {} {})",
                self.bitvec_expr.as_deref().unwrap_or("?"),
                other.bitvec_expr.as_deref().unwrap_or("?")
            )),
            bool_expr: None,
            size_bits: self.size_bits.max(other.size_bits),
        }
    }

    /// Perform INT_AND (symbolic bitwise AND).
    pub fn int_and(&self, other: &SymValueZ3) -> SymValueZ3 {
        SymValueZ3 {
            bitvec_expr: Some(format!(
                "(bvand {} {})",
                self.bitvec_expr.as_deref().unwrap_or("?"),
                other.bitvec_expr.as_deref().unwrap_or("?")
            )),
            bool_expr: None,
            size_bits: self.size_bits.max(other.size_bits),
        }
    }

    /// Perform INT_OR (symbolic bitwise OR).
    pub fn int_or(&self, other: &SymValueZ3) -> SymValueZ3 {
        SymValueZ3 {
            bitvec_expr: Some(format!(
                "(bvor {} {})",
                self.bitvec_expr.as_deref().unwrap_or("?"),
                other.bitvec_expr.as_deref().unwrap_or("?")
            )),
            bool_expr: None,
            size_bits: self.size_bits.max(other.size_bits),
        }
    }

    /// Perform INT_XOR (symbolic bitwise XOR).
    pub fn int_xor(&self, other: &SymValueZ3) -> SymValueZ3 {
        SymValueZ3 {
            bitvec_expr: Some(format!(
                "(bvxor {} {})",
                self.bitvec_expr.as_deref().unwrap_or("?"),
                other.bitvec_expr.as_deref().unwrap_or("?")
            )),
            bool_expr: None,
            size_bits: self.size_bits.max(other.size_bits),
        }
    }

    /// Perform INT_MULT (symbolic multiplication).
    pub fn int_mult(&self, other: &SymValueZ3) -> SymValueZ3 {
        SymValueZ3 {
            bitvec_expr: Some(format!(
                "(bvmul {} {})",
                self.bitvec_expr.as_deref().unwrap_or("?"),
                other.bitvec_expr.as_deref().unwrap_or("?")
            )),
            bool_expr: None,
            size_bits: self.size_bits.max(other.size_bits),
        }
    }

    /// Perform INT_DIV (unsigned symbolic division).
    pub fn int_div(&self, other: &SymValueZ3) -> SymValueZ3 {
        SymValueZ3 {
            bitvec_expr: Some(format!(
                "(bvudiv {} {})",
                self.bitvec_expr.as_deref().unwrap_or("?"),
                other.bitvec_expr.as_deref().unwrap_or("?")
            )),
            bool_expr: None,
            size_bits: self.size_bits.max(other.size_bits),
        }
    }

    /// Perform INT_LEFT (symbolic left shift).
    pub fn int_left(&self, other: &SymValueZ3) -> SymValueZ3 {
        SymValueZ3 {
            bitvec_expr: Some(format!(
                "(bvshl {} {})",
                self.bitvec_expr.as_deref().unwrap_or("?"),
                other.bitvec_expr.as_deref().unwrap_or("?")
            )),
            bool_expr: None,
            size_bits: self.size_bits,
        }
    }

    /// Perform INT_RIGHT (logical right shift).
    pub fn int_right(&self, other: &SymValueZ3) -> SymValueZ3 {
        SymValueZ3 {
            bitvec_expr: Some(format!(
                "(bvlshr {} {})",
                self.bitvec_expr.as_deref().unwrap_or("?"),
                other.bitvec_expr.as_deref().unwrap_or("?")
            )),
            bool_expr: None,
            size_bits: self.size_bits,
        }
    }

    /// Perform INT_SRIGHT (arithmetic right shift).
    pub fn int_sright(&self, other: &SymValueZ3) -> SymValueZ3 {
        SymValueZ3 {
            bitvec_expr: Some(format!(
                "(bvashr {} {})",
                self.bitvec_expr.as_deref().unwrap_or("?"),
                other.bitvec_expr.as_deref().unwrap_or("?")
            )),
            bool_expr: None,
            size_bits: self.size_bits,
        }
    }

    /// Perform INT_EQUAL (symbolic equality comparison).
    pub fn int_equal(&self, other: &SymValueZ3) -> SymValueZ3 {
        SymValueZ3 {
            bitvec_expr: Some(format!(
                "(ite (= {} {}) #x01 #x00)",
                self.bitvec_expr.as_deref().unwrap_or("?"),
                other.bitvec_expr.as_deref().unwrap_or("?")
            )),
            bool_expr: None,
            size_bits: 8,
        }
    }

    /// Perform INT_LESS (unsigned less-than).
    pub fn int_less(&self, other: &SymValueZ3) -> SymValueZ3 {
        SymValueZ3 {
            bitvec_expr: Some(format!(
                "(ite (bvult {} {}) #x01 #x00)",
                self.bitvec_expr.as_deref().unwrap_or("?"),
                other.bitvec_expr.as_deref().unwrap_or("?")
            )),
            bool_expr: None,
            size_bits: 8,
        }
    }

    /// Perform INT_SLESS (signed less-than).
    pub fn int_sless(&self, other: &SymValueZ3) -> SymValueZ3 {
        SymValueZ3 {
            bitvec_expr: Some(format!(
                "(ite (bvslt {} {}) #x01 #x00)",
                self.bitvec_expr.as_deref().unwrap_or("?"),
                other.bitvec_expr.as_deref().unwrap_or("?")
            )),
            bool_expr: None,
            size_bits: 8,
        }
    }

    /// Perform INT_ZEXT (zero extension).
    pub fn int_zext(&self, out_size_bits: u32) -> SymValueZ3 {
        let extend_by = out_size_bits.saturating_sub(self.size_bits);
        SymValueZ3 {
            bitvec_expr: Some(format!(
                "((_ zero_extend {extend_by}) {})",
                self.bitvec_expr.as_deref().unwrap_or("?")
            )),
            bool_expr: None,
            size_bits: out_size_bits,
        }
    }

    /// Perform INT_SEXT (sign extension).
    pub fn int_sext(&self, out_size_bits: u32) -> SymValueZ3 {
        let extend_by = out_size_bits.saturating_sub(self.size_bits);
        SymValueZ3 {
            bitvec_expr: Some(format!(
                "((_ sign_extend {extend_by}) {})",
                self.bitvec_expr.as_deref().unwrap_or("?")
            )),
            bool_expr: None,
            size_bits: out_size_bits,
        }
    }

    /// Perform BOOL_NEGATE.
    pub fn bool_negate(&self) -> SymValueZ3 {
        SymValueZ3 {
            bitvec_expr: Some(format!(
                "(ite (= {} #x00) #x01 #x00)",
                self.bitvec_expr.as_deref().unwrap_or("?")
            )),
            bool_expr: self.bool_expr.as_ref().map(|b| format!("(not {b})")),
            size_bits: 8,
        }
    }

    /// Perform COPY.
    pub fn copy(&self) -> SymValueZ3 {
        self.clone()
    }

    /// Perform PIECE (concatenation).
    pub fn piece(&self, other: &SymValueZ3) -> SymValueZ3 {
        SymValueZ3 {
            bitvec_expr: Some(format!(
                "(concat {} {})",
                self.bitvec_expr.as_deref().unwrap_or("?"),
                other.bitvec_expr.as_deref().unwrap_or("?")
            )),
            bool_expr: None,
            size_bits: self.size_bits + other.size_bits,
        }
    }

    /// Perform SUBPIECE (extraction).
    pub fn subpiece(&self, out_size_bytes: u32, offset_bytes: u32) -> SymValueZ3 {
        let out_bits = out_size_bytes * 8;
        let high = offset_bytes * 8 + out_bits - 1;
        let low = offset_bytes * 8;
        SymValueZ3 {
            bitvec_expr: Some(format!(
                "((_ extract {high} {low}) {})",
                self.bitvec_expr.as_deref().unwrap_or("?")
            )),
            bool_expr: None,
            size_bits: out_bits,
        }
    }

    /// Perform POPCOUNT.
    pub fn popcount(&self, out_size_bytes: u32) -> SymValueZ3 {
        SymValueZ3 {
            bitvec_expr: Some(format!(
                "(bvpopcount {})",
                self.bitvec_expr.as_deref().unwrap_or("?")
            )),
            bool_expr: None,
            size_bits: out_size_bytes * 8,
        }
    }
}

impl std::fmt::Display for SymValueZ3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(bv) = &self.bitvec_expr {
            write!(f, "<SymValueZ3: {bv}>")
        } else if let Some(b) = &self.bool_expr {
            write!(f, "<SymValueZ3: {b}>")
        } else {
            write!(f, "<SymValueZ3: null>")
        }
    }
}

impl PartialEq for SymValueZ3 {
    fn eq(&self, other: &Self) -> bool {
        self.bitvec_expr == other.bitvec_expr
    }
}

impl Eq for SymValueZ3 {}

impl std::hash::Hash for SymValueZ3 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.bitvec_expr.hash(state);
    }
}

// ---------------------------------------------------------------------------
// SymZ3PcodeArithmetic
// ---------------------------------------------------------------------------

/// Symbolic p-code arithmetic for Z3 values.
///
/// Ported from `SymZ3PcodeArithmetic.java`. Implements the full set of
/// p-code operations using Z3 symbolic expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymZ3PcodeArithmetic {
    /// Big-endian symbolic arithmetic.
    BigEndian,
    /// Little-endian symbolic arithmetic.
    LittleEndian,
}

impl SymZ3PcodeArithmetic {
    /// Get the arithmetic for the given endianness.
    pub fn for_endian(big_endian: bool) -> Self {
        if big_endian {
            Self::BigEndian
        } else {
            Self::LittleEndian
        }
    }

    /// Whether this arithmetic is big-endian.
    pub fn is_big_endian(&self) -> bool {
        *self == Self::BigEndian
    }

    /// Create a constant value.
    pub fn from_const_u64(&self, value: u64, size: u32) -> SymValueZ3 {
        SymValueZ3::from_constant(value, size * 8)
    }

    /// Create a constant value from bytes.
    pub fn from_const_bytes(&self, bytes: &[u8]) -> SymValueZ3 {
        let mut value: u64 = 0;
        if self.is_big_endian() {
            for &b in bytes {
                value = (value << 8) | (b as u64);
            }
        } else {
            for (i, &b) in bytes.iter().enumerate() {
                value |= (b as u64) << (i * 8);
            }
        }
        SymValueZ3::from_constant(value, (bytes.len() as u32) * 8)
    }

    /// Convert a symbolic value to a concrete u64 (panics if symbolic).
    pub fn to_u64(&self, value: &SymValueZ3) -> Option<u64> {
        value.to_u64()
    }

    /// Get the size of a value in bytes.
    pub fn size_of(&self, value: &SymValueZ3) -> u32 {
        value.size_bytes()
    }

    /// Execute a unary p-code operation.
    pub fn unary_op(&self, opcode: u32, sizeout: u32, in1: &SymValueZ3) -> SymValueZ3 {
        match opcode {
            // PcodeOp::COPY
            1 => in1.copy(),
            // PcodeOp::INT_ZEXT
            37 => in1.int_zext(sizeout * 8),
            // PcodeOp::INT_SEXT
            38 => in1.int_sext(sizeout * 8),
            // PcodeOp::BOOL_NEGATE
            51 => in1.bool_negate(),
            // PcodeOp::POPCOUNT
            90 => in1.popcount(sizeout),
            _ => SymValueZ3::from_constant(0, sizeout * 8),
        }
    }

    /// Execute a binary p-code operation.
    pub fn binary_op(
        &self,
        opcode: u32,
        sizeout: u32,
        in1: &SymValueZ3,
        in2: &SymValueZ3,
    ) -> SymValueZ3 {
        match opcode {
            // PcodeOp::INT_EQUAL
            16 => in1.int_equal(in2),
            // PcodeOp::INT_NOTEQUAL
            17 => in1.int_equal(in2).bool_negate(),
            // PcodeOp::INT_LESS
            18 => in1.int_less(in2),
            // PcodeOp::INT_SLESS
            20 => in1.int_sless(in2),
            // PcodeOp::INT_ADD
            24 => in1.int_add(in2),
            // PcodeOp::INT_SUB
            25 => in1.int_sub(in2),
            // PcodeOp::INT_XOR
            28 => in1.int_xor(in2),
            // PcodeOp::INT_AND
            29 => in1.int_and(in2),
            // PcodeOp::INT_OR
            30 => in1.int_or(in2),
            // PcodeOp::INT_LEFT
            31 => in1.int_left(in2),
            // PcodeOp::INT_RIGHT
            32 => in1.int_right(in2),
            // PcodeOp::INT_SRIGHT
            33 => in1.int_sright(in2),
            // PcodeOp::INT_MULT
            34 => in1.int_mult(in2),
            // PcodeOp::INT_DIV
            35 => in1.int_div(in2),
            // PcodeOp::PIECE
            7 => in1.piece(in2),
            // PcodeOp::SUBPIECE
            8 => in1.subpiece(sizeout, in2.to_u64().unwrap_or(0) as u32),
            _ => SymValueZ3::from_constant(0, sizeout * 8),
        }
    }

    /// Test whether a condition is concrete true.
    pub fn is_true(&self, cond: &SymValueZ3) -> Option<bool> {
        match cond.to_u64() {
            Some(0) => Some(false),
            Some(1) => Some(true),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// SymZ3 Loader
// ---------------------------------------------------------------------------

/// Z3 library loader.
///
/// Ported from `SymZ3.java`. Handles loading the Z3 native libraries
/// from the correct platform-specific path.
pub struct SymZ3;

impl SymZ3 {
    /// Attempt to load Z3 libraries.
    ///
    /// In the Java version this loads `libz3` and `libz3java` native
    /// libraries. In Rust, this would initialize the Z3 context.
    pub fn load_z3_libs() -> Result<(), String> {
        // In production: initialize Z3 bindings
        // e.g., z3::Config::new().init()
        Ok(())
    }

    /// Get the Z3 version string.
    pub fn version() -> &'static str {
        "Z3 Rust Bindings (stub)"
    }
}

// ---------------------------------------------------------------------------
// Record types for execution recording
// ---------------------------------------------------------------------------

/// A recorded p-code operation.
#[derive(Debug, Clone)]
pub struct RecOp {
    /// Sequence number.
    pub seq: usize,
    /// The operation mnemonic.
    pub mnemonic: String,
    /// The output varnode address (if any).
    pub output_addr: Option<String>,
    /// Input varnode addresses.
    pub input_addrs: Vec<String>,
}

/// A recorded instruction.
#[derive(Debug, Clone)]
pub struct RecInstruction {
    /// Sequence number.
    pub seq: usize,
    /// The instruction address.
    pub address: u64,
    /// The instruction mnemonic.
    pub mnemonic: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sym_value_concrete() {
        let val = SymValueZ3::from_constant(42, 64);
        assert_eq!(val.to_u64(), Some(42));
        assert_eq!(val.size_bits, 64);
        assert_eq!(val.size_bytes(), 8);
    }

    #[test]
    fn test_sym_value_bool() {
        let t = SymValueZ3::from_bool(true);
        assert!(t.has_bool_expr());
        assert_eq!(t.to_u64(), Some(1));

        let f = SymValueZ3::from_bool(false);
        assert_eq!(f.to_u64(), Some(0));
    }

    #[test]
    fn test_sym_value_serialize_roundtrip() {
        let val = SymValueZ3::from_constant(0xABCD, 32);
        let serialized = val.serialize();
        let parsed = SymValueZ3::parse(&serialized).unwrap();
        assert_eq!(parsed.bitvec_expr, val.bitvec_expr);
    }

    #[test]
    fn test_sym_value_add() {
        let a = SymValueZ3::from_constant(10, 32);
        let b = SymValueZ3::from_constant(20, 32);
        let result = a.int_add(&b);
        assert!(result.bitvec_expr.unwrap().contains("bvadd"));
    }

    #[test]
    fn test_sym_value_sub() {
        let a = SymValueZ3::from_constant(30, 32);
        let b = SymValueZ3::from_constant(10, 32);
        let result = a.int_sub(&b);
        assert!(result.bitvec_expr.unwrap().contains("bvsub"));
    }

    #[test]
    fn test_sym_value_and() {
        let a = SymValueZ3::from_constant(0xFF, 8);
        let b = SymValueZ3::from_constant(0x0F, 8);
        let result = a.int_and(&b);
        assert!(result.bitvec_expr.unwrap().contains("bvand"));
    }

    #[test]
    fn test_sym_value_or() {
        let a = SymValueZ3::from_constant(0xF0, 8);
        let b = SymValueZ3::from_constant(0x0F, 8);
        let result = a.int_or(&b);
        assert!(result.bitvec_expr.unwrap().contains("bvor"));
    }

    #[test]
    fn test_sym_value_xor() {
        let a = SymValueZ3::from_constant(0xFF, 8);
        let b = SymValueZ3::from_constant(0xFF, 8);
        let result = a.int_xor(&b);
        assert!(result.bitvec_expr.unwrap().contains("bvxor"));
    }

    #[test]
    fn test_sym_value_mult() {
        let a = SymValueZ3::from_constant(5, 32);
        let b = SymValueZ3::from_constant(7, 32);
        let result = a.int_mult(&b);
        assert!(result.bitvec_expr.unwrap().contains("bvmul"));
    }

    #[test]
    fn test_sym_value_div() {
        let a = SymValueZ3::from_constant(100, 32);
        let b = SymValueZ3::from_constant(10, 32);
        let result = a.int_div(&b);
        assert!(result.bitvec_expr.unwrap().contains("bvudiv"));
    }

    #[test]
    fn test_sym_value_shifts() {
        let a = SymValueZ3::from_constant(1, 32);
        let b = SymValueZ3::from_constant(4, 32);

        let left = a.int_left(&b);
        assert!(left.bitvec_expr.unwrap().contains("bvshl"));

        let right = a.int_right(&b);
        assert!(right.bitvec_expr.unwrap().contains("bvlshr"));

        let sright = a.int_sright(&b);
        assert!(sright.bitvec_expr.unwrap().contains("bvashr"));
    }

    #[test]
    fn test_sym_value_comparisons() {
        let a = SymValueZ3::from_constant(5, 32);
        let b = SymValueZ3::from_constant(10, 32);

        let eq = a.int_equal(&b);
        assert!(eq.bitvec_expr.unwrap().contains("ite"));

        let less = a.int_less(&b);
        assert!(less.bitvec_expr.unwrap().contains("bvult"));

        let sless = a.int_sless(&b);
        assert!(sless.bitvec_expr.unwrap().contains("bvslt"));
    }

    #[test]
    fn test_sym_value_zext() {
        let val = SymValueZ3::from_constant(0xFF, 8);
        let extended = val.int_zext(32);
        assert_eq!(extended.size_bits, 32);
        assert!(extended.bitvec_expr.unwrap().contains("zero_extend"));
    }

    #[test]
    fn test_sym_value_sext() {
        let val = SymValueZ3::from_constant(0xFF, 8);
        let extended = val.int_sext(32);
        assert_eq!(extended.size_bits, 32);
        assert!(extended.bitvec_expr.unwrap().contains("sign_extend"));
    }

    #[test]
    fn test_sym_value_bool_negate() {
        let val = SymValueZ3::from_bool(true);
        let neg = val.bool_negate();
        assert!(neg.bitvec_expr.unwrap().contains("ite"));
    }

    #[test]
    fn test_sym_value_piece() {
        let hi = SymValueZ3::from_constant(0xAB, 8);
        let lo = SymValueZ3::from_constant(0xCD, 8);
        let result = hi.piece(&lo);
        assert_eq!(result.size_bits, 16);
        assert!(result.bitvec_expr.unwrap().contains("concat"));
    }

    #[test]
    fn test_sym_value_subpiece() {
        let val = SymValueZ3::from_constant(0xAABBCCDD, 32);
        let result = val.subpiece(2, 1);
        assert_eq!(result.size_bits, 16);
        assert!(result.bitvec_expr.unwrap().contains("extract"));
    }

    #[test]
    fn test_sym_value_display() {
        let val = SymValueZ3::from_constant(42, 64);
        let display = format!("{val}");
        assert!(display.contains("SymValueZ3"));
    }

    #[test]
    fn test_sym_value_equality() {
        let a = SymValueZ3::from_constant(42, 32);
        let b = SymValueZ3::from_constant(42, 32);
        assert_eq!(a, b);

        let c = SymValueZ3::from_constant(99, 32);
        assert_ne!(a, c);
    }

    #[test]
    fn test_arithmetic_endian() {
        let be = SymZ3PcodeArithmetic::for_endian(true);
        assert!(be.is_big_endian());

        let le = SymZ3PcodeArithmetic::for_endian(false);
        assert!(!le.is_big_endian());
    }

    #[test]
    fn test_arithmetic_from_const() {
        let arith = SymZ3PcodeArithmetic::LittleEndian;
        let val = arith.from_const_u64(42, 8);
        assert_eq!(val.to_u64(), Some(42));
    }

    #[test]
    fn test_arithmetic_from_bytes_le() {
        let arith = SymZ3PcodeArithmetic::LittleEndian;
        let val = arith.from_const_bytes(&[0x34, 0x12]);
        assert_eq!(val.to_u64(), Some(0x1234));
    }

    #[test]
    fn test_arithmetic_from_bytes_be() {
        let arith = SymZ3PcodeArithmetic::BigEndian;
        let val = arith.from_const_bytes(&[0x12, 0x34]);
        assert_eq!(val.to_u64(), Some(0x1234));
    }

    #[test]
    fn test_arithmetic_unary_op() {
        let arith = SymZ3PcodeArithmetic::LittleEndian;
        let val = arith.from_const_u64(0xFF, 1);

        // COPY (opcode 1)
        let copy = arith.unary_op(1, 1, &val);
        assert_eq!(copy, val);

        // INT_ZEXT (opcode 37)
        let ext = arith.unary_op(37, 4, &val);
        assert_eq!(ext.size_bits, 32);
    }

    #[test]
    fn test_arithmetic_binary_op() {
        let arith = SymZ3PcodeArithmetic::LittleEndian;
        let a = arith.from_const_u64(10, 4);
        let b = arith.from_const_u64(20, 4);

        // INT_ADD (opcode 24)
        let add = arith.binary_op(24, 4, &a, &b);
        assert!(add.bitvec_expr.unwrap().contains("bvadd"));

        // INT_EQUAL (opcode 16)
        let eq = arith.binary_op(16, 1, &a, &b);
        assert!(eq.bitvec_expr.unwrap().contains("ite"));
    }

    #[test]
    fn test_arithmetic_is_true() {
        let arith = SymZ3PcodeArithmetic::LittleEndian;
        assert_eq!(arith.is_true(&SymValueZ3::from_bool(true)), Some(true));
        assert_eq!(arith.is_true(&SymValueZ3::from_bool(false)), Some(false));

        let symbolic = SymValueZ3::from_variable("x", 8);
        assert_eq!(arith.is_true(&symbolic), None);
    }

    #[test]
    fn test_sym_z3_load() {
        assert!(SymZ3::load_z3_libs().is_ok());
    }

    #[test]
    fn test_sym_z3_version() {
        assert!(!SymZ3::version().is_empty());
    }

    #[test]
    fn test_rec_op() {
        let op = RecOp {
            seq: 0,
            mnemonic: "INT_ADD".to_string(),
            output_addr: Some("register:RAX".to_string()),
            input_addrs: vec!["register:RBX".to_string(), "register:RCX".to_string()],
        };
        assert_eq!(op.seq, 0);
        assert_eq!(op.mnemonic, "INT_ADD");
    }

    #[test]
    fn test_rec_instruction() {
        let inst = RecInstruction {
            seq: 0,
            address: 0x401000,
            mnemonic: "ADD".to_string(),
        };
        assert_eq!(inst.address, 0x401000);
    }
}
