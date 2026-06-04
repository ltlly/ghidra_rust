//! Symbolic P-code Arithmetic -- dispatches p-code operations to SymValueZ3.
//!
//! Ported from `SymZ3PcodeArithmetic.java` in the SymbolicSummaryZ3 extension.
//!
//! This module provides the arithmetic dispatch that converts p-code opcodes
//! into symbolic operations on `SymValueZ3` values.

use super::model::SymValueZ3;

/// The purpose of an arithmetic operation.
///
/// Different purposes may require different handling (e.g., extracting an
/// integer value from a symbolic value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Extracting a value by definition (always concrete).
    ByDef,
    /// Extracting a value for display purposes.
    Display,
    /// Extracting a value for comparison.
    Comparison,
}

/// Symbolic P-code arithmetic implementation.
///
/// Dispatches p-code operations (as opcodes) to the corresponding
/// `SymValueZ3` methods, producing new symbolic values.
#[derive(Debug, Clone, Copy)]
pub struct SymZ3PcodeArithmetic;

impl SymZ3PcodeArithmetic {
    /// Perform a unary symbolic operation.
    ///
    /// `opcode` is the p-code opcode name (e.g., "INT_NEGATE", "BOOL_NEGATE").
    /// `out_size` is the output size in bytes.
    /// `input_size` is the input size in bytes.
    pub fn unary_op(
        opcode: &str,
        _out_size: u32,
        _input_size: u32,
        input: &SymValueZ3,
    ) -> SymValueZ3 {
        match opcode {
            "INT_NEGATE" | "INT_2COMP" | "FLOAT_NEG" => {
                // Negate: 0 - input
                let zero = SymValueZ3::from_bitvec("bv0");
                zero.int_sub(input)
            }
            "BOOL_NEGATE" => input.bool_negate(),
            "INT_ZEXT" => input.int_zext(_out_size),
            "INT_SEXT" => input.int_sext(_out_size),
            "POPCOUNT" => input.popcount(_out_size),
            _ => input.clone(),
        }
    }

    /// Perform a binary symbolic operation.
    ///
    /// `opcode` is the p-code opcode name.
    pub fn binary_op(
        opcode: &str,
        _out_size: u32,
        left: &SymValueZ3,
        right: &SymValueZ3,
    ) -> SymValueZ3 {
        match opcode {
            "INT_ADD" | "FLOAT_ADD" => left.int_add(right),
            "INT_SUB" | "FLOAT_SUB" => left.int_sub(right),
            "INT_MULT" | "FLOAT_MULT" => left.int_mult(right),
            "INT_DIV" | "FLOAT_DIV" => left.int_div(right),
            "INT_SDIV" => left.int_sdiv(right),
            "INT_AND" => left.int_and(right),
            "INT_OR" => left.int_or(right),
            "INT_XOR" => left.int_xor(right),
            "INT_LEFT" => left.int_left(right),
            "INT_RIGHT" => left.int_right(right),
            "INT_SRIGHT" => left.int_sright(right),
            "INT_CARRY" => left.int_carry(right),
            "INT_SCARRY" => left.int_scarry(right),
            "INT_SBORROW" => left.int_sborrow(right),
            "INT_EQUAL" => left.int_equal(right),
            "INT_NOTEQUAL" => left.int_not_equal(right),
            "INT_SLESS" => left.int_sless(right),
            "INT_SLESSEQUAL" => left.int_sless_equal(right),
            "INT_LESS" => left.int_less(right),
            "INT_LESSEQUAL" => left.int_less_equal(right),
            "BOOL_AND" => left.bool_and(right),
            "BOOL_OR" => left.bool_or(right),
            "BOOL_XOR" => left.bool_xor(right),
            "PIECE" => left.piece(right),
            _ => left.clone(),
        }
    }

    /// Perform a subpiece operation.
    pub fn subpiece(
        input: &SymValueZ3,
        out_size: u32,
        offset_bytes: u32,
    ) -> SymValueZ3 {
        input.subpiece(out_size, offset_bytes)
    }

    /// Try to extract a concrete integer value from a symbolic value.
    ///
    /// Returns `None` if the value is symbolic (not a constant).
    pub fn is_int(value: &SymValueZ3, _purpose: Purpose) -> Option<u64> {
        let bv = value.bitvec_expr_string.as_deref()?;
        // Check if it's a simple bitvector numeral like "bv42" or "#x..."
        if let Some(rest) = bv.strip_prefix("bv") {
            return rest.parse().ok();
        }
        // Hex literal
        if let Some(rest) = bv.strip_prefix("#x") {
            return u64::from_str_radix(rest, 16).ok();
        }
        // Binary literal
        if let Some(rest) = bv.strip_prefix("#b") {
            return u64::from_str_radix(rest, 2).ok();
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unary_negate() {
        let v = SymValueZ3::from_bitvec("x");
        let result = SymZ3PcodeArithmetic::unary_op("INT_NEGATE", 8, 8, &v);
        let expr = result.bitvec_expr_string.unwrap();
        assert!(expr.contains("bvsub"));
    }

    #[test]
    fn test_unary_bool_negate() {
        let v = SymValueZ3::from_bool("p");
        let result = SymZ3PcodeArithmetic::unary_op("BOOL_NEGATE", 1, 1, &v);
        assert!(result.has_bitvec_expr());
        assert!(result.bitvec_expr_string.unwrap().contains("not"));
    }

    #[test]
    fn test_unary_zext() {
        let v = SymValueZ3::from_bitvec("x");
        let result = SymZ3PcodeArithmetic::unary_op("INT_ZEXT", 8, 4, &v);
        assert!(result.bitvec_expr_string.unwrap().contains("zero_extend"));
    }

    #[test]
    fn test_unary_unknown_passthrough() {
        let v = SymValueZ3::from_bitvec("x");
        let result = SymZ3PcodeArithmetic::unary_op("UNKNOWN_OP", 8, 8, &v);
        assert_eq!(result, v);
    }

    #[test]
    fn test_binary_add() {
        let a = SymValueZ3::from_bitvec("x");
        let b = SymValueZ3::from_bitvec("y");
        let result = SymZ3PcodeArithmetic::binary_op("INT_ADD", 8, &a, &b);
        assert!(result.bitvec_expr_string.unwrap().contains("bvadd"));
    }

    #[test]
    fn test_binary_sub() {
        let a = SymValueZ3::from_bitvec("x");
        let b = SymValueZ3::from_bitvec("y");
        let result = SymZ3PcodeArithmetic::binary_op("INT_SUB", 8, &a, &b);
        assert!(result.bitvec_expr_string.unwrap().contains("bvsub"));
    }

    #[test]
    fn test_binary_mult() {
        let a = SymValueZ3::from_bitvec("x");
        let b = SymValueZ3::from_bitvec("y");
        let result = SymZ3PcodeArithmetic::binary_op("INT_MULT", 8, &a, &b);
        assert!(result.bitvec_expr_string.unwrap().contains("bvmul"));
    }

    #[test]
    fn test_binary_div() {
        let a = SymValueZ3::from_bitvec("x");
        let b = SymValueZ3::from_bitvec("y");
        let result = SymZ3PcodeArithmetic::binary_op("INT_DIV", 8, &a, &b);
        assert!(result.bitvec_expr_string.unwrap().contains("bvudiv"));
    }

    #[test]
    fn test_binary_bitwise() {
        let a = SymValueZ3::from_bitvec("x");
        let b = SymValueZ3::from_bitvec("y");

        assert!(
            SymZ3PcodeArithmetic::binary_op("INT_AND", 8, &a, &b)
                .bitvec_expr_string
                .unwrap()
                .contains("bvand")
        );
        assert!(
            SymZ3PcodeArithmetic::binary_op("INT_OR", 8, &a, &b)
                .bitvec_expr_string
                .unwrap()
                .contains("bvor")
        );
        assert!(
            SymZ3PcodeArithmetic::binary_op("INT_XOR", 8, &a, &b)
                .bitvec_expr_string
                .unwrap()
                .contains("bvxor")
        );
    }

    #[test]
    fn test_binary_comparison() {
        let a = SymValueZ3::from_bitvec("x");
        let b = SymValueZ3::from_bitvec("y");

        assert!(
            SymZ3PcodeArithmetic::binary_op("INT_EQUAL", 8, &a, &b)
                .bitvec_expr_string
                .unwrap()
                .contains("=")
        );
        assert!(
            SymZ3PcodeArithmetic::binary_op("INT_LESS", 8, &a, &b)
                .bitvec_expr_string
                .unwrap()
                .contains("bvult")
        );
    }

    #[test]
    fn test_binary_piece() {
        let a = SymValueZ3::from_bitvec("hi");
        let b = SymValueZ3::from_bitvec("lo");
        let result = SymZ3PcodeArithmetic::binary_op("PIECE", 8, &a, &b);
        assert!(result.bitvec_expr_string.unwrap().contains("concat"));
    }

    #[test]
    fn test_binary_unknown_passthrough() {
        let a = SymValueZ3::from_bitvec("x");
        let b = SymValueZ3::from_bitvec("y");
        let result = SymZ3PcodeArithmetic::binary_op("UNKNOWN", 8, &a, &b);
        assert_eq!(result, a);
    }

    #[test]
    fn test_subpiece() {
        let v = SymValueZ3::from_bitvec("x");
        let result = SymZ3PcodeArithmetic::subpiece(&v, 4, 0);
        assert!(result.bitvec_expr_string.unwrap().contains("extract"));
    }

    #[test]
    fn test_is_int_concrete() {
        let v = SymValueZ3::from_bitvec("bv42");
        assert_eq!(
            SymZ3PcodeArithmetic::is_int(&v, Purpose::ByDef),
            Some(42)
        );
    }

    #[test]
    fn test_is_int_hex() {
        let v = SymValueZ3::from_bitvec("#xff");
        assert_eq!(
            SymZ3PcodeArithmetic::is_int(&v, Purpose::ByDef),
            Some(255)
        );
    }

    #[test]
    fn test_is_int_binary() {
        let v = SymValueZ3::from_bitvec("#b1010");
        assert_eq!(
            SymZ3PcodeArithmetic::is_int(&v, Purpose::ByDef),
            Some(10)
        );
    }

    #[test]
    fn test_is_int_symbolic() {
        let v = SymValueZ3::from_bitvec("(bvadd x y)");
        assert_eq!(SymZ3PcodeArithmetic::is_int(&v, Purpose::ByDef), None);
    }

    #[test]
    fn test_is_int_none() {
        let v = SymValueZ3::from_bool("true");
        assert_eq!(SymZ3PcodeArithmetic::is_int(&v, Purpose::ByDef), None);
    }
}
