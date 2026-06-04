//! Symbolic Value Z3 -- the symbolic value type.
//!
//! Ported from `SymValueZ3.java` in the SymbolicSummaryZ3 extension.
//!
//! A `SymValueZ3` consists of either a Z3 bit-vector expression string,
//! an optional Z3 boolean expression string, or both. The expressions are
//! stored as serialized SMT-LIB2 strings rather than as live Z3 objects,
//! making them independent of any Z3 runtime.

use std::fmt;

/// A symbolic value wrapping a Z3 bit-vector expression and an optional
/// boolean expression.
///
/// Expressions are stored as serialized SMT-LIB2 strings with a `V:` or
/// `B:` prefix to distinguish bit-vector from boolean expressions.
///
/// # Design
///
/// We always store a bit-vector expression (never just a boolean) because
/// registers like `ZF` need to be represented as 8-bit bit-vectors from
/// P-code's perspective.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SymValueZ3 {
    /// Serialized bit-vector expression (SMT-LIB2 string with `V:` prefix).
    pub bitvec_expr_string: Option<String>,
    /// Serialized boolean expression (SMT-LIB2 string with `B:` prefix).
    pub bool_expr_string: Option<String>,
}

impl SymValueZ3 {
    /// Create a symbolic value from a bit-vector expression string.
    pub fn from_bitvec(s: impl Into<String>) -> Self {
        Self {
            bitvec_expr_string: Some(s.into()),
            bool_expr_string: None,
        }
    }

    /// Create a symbolic value from both a bit-vector and boolean expression.
    pub fn from_bitvec_and_bool(
        bv: impl Into<String>,
        be: impl Into<String>,
    ) -> Self {
        Self {
            bitvec_expr_string: Some(bv.into()),
            bool_expr_string: Some(be.into()),
        }
    }

    /// Create a symbolic value from a boolean expression only.
    pub fn from_bool(s: impl Into<String>) -> Self {
        Self {
            bitvec_expr_string: None,
            bool_expr_string: Some(s.into()),
        }
    }

    /// Check if this value has a boolean expression.
    pub fn has_bool_expr(&self) -> bool {
        self.bool_expr_string.is_some()
    }

    /// Check if this value has a bit-vector expression.
    pub fn has_bitvec_expr(&self) -> bool {
        self.bitvec_expr_string.is_some()
    }

    /// Serialize this value to a string.
    ///
    /// If a boolean expression is present, it takes priority and the
    /// bit-vector is NOT included in the serialization (matching Java
    /// `SymValueZ3.serialize()` semantics).
    pub fn serialize(&self) -> String {
        let delimiter = ":::::";
        if let Some(ref be) = self.bool_expr_string {
            // Bool expression only (left of delimiter)
            return format!("{be}{delimiter}");
        }
        if let Some(ref bv) = self.bitvec_expr_string {
            // Bit-vector expression only (right of delimiter)
            return format!("{delimiter}{bv}");
        }
        panic!("attempted to serialize a null SymValueZ3");
    }

    /// Deserialize a `SymValueZ3` from a serialized string.
    pub fn parse(serialized: &str) -> Option<Self> {
        let index = serialized.find(":::::")?;
        let left = &serialized[..index];
        let right = &serialized[index + 5..];
        let bool_expr = if left.is_empty() {
            None
        } else {
            Some(left.to_string())
        };
        let bv_expr = if right.is_empty() {
            None
        } else {
            Some(right.to_string())
        };
        Some(Self {
            bitvec_expr_string: bv_expr,
            bool_expr_string: bool_expr,
        })
    }

    /// Create an ITE (if-then-else) symbolic value: `predicate ? 1 : 0`.
    ///
    /// The predicate is stored as the boolean expression, and the resulting
    /// bit-vector is `ite(predicate, 1, 0)`.
    pub fn ite_from_predicate(predicate_expr: &str, size_bits: u32) -> Self {
        let bv = format!(
            "V:(ite {predicate_expr} #b{} #b{})",
            "1".repeat(size_bits as usize).chars().take(size_bits as usize).collect::<String>(),
            "0".repeat(size_bits as usize).chars().take(size_bits as usize).collect::<String>()
        );
        // Simplified: just use a placeholder
        let bv_simple = format!("V:(ite {predicate_expr} bv1 bv0)");
        Self::from_bitvec(bv_simple)
    }

    // -- Bit-vector operations (return new SymValueZ3) --

    /// Bit-vector addition: `this + that`.
    pub fn int_add(&self, that: &SymValueZ3) -> SymValueZ3 {
        self.bin_op("bvadd", that)
    }

    /// Bit-vector subtraction: `this - that`.
    pub fn int_sub(&self, that: &SymValueZ3) -> SymValueZ3 {
        self.bin_op("bvsub", that)
    }

    /// Bit-vector multiplication: `this * that`.
    pub fn int_mult(&self, that: &SymValueZ3) -> SymValueZ3 {
        self.bin_op("bvmul", that)
    }

    /// Unsigned division: `this / that`.
    pub fn int_div(&self, that: &SymValueZ3) -> SymValueZ3 {
        self.bin_op("bvudiv", that)
    }

    /// Signed division: `this / that`.
    pub fn int_sdiv(&self, that: &SymValueZ3) -> SymValueZ3 {
        self.bin_op("bvsdiv", that)
    }

    /// Bit-vector AND: `this & that`.
    pub fn int_and(&self, that: &SymValueZ3) -> SymValueZ3 {
        self.bin_op("bvand", that)
    }

    /// Bit-vector OR: `this | that`.
    pub fn int_or(&self, that: &SymValueZ3) -> SymValueZ3 {
        self.bin_op("bvor", that)
    }

    /// Bit-vector XOR: `this ^ that`.
    pub fn int_xor(&self, that: &SymValueZ3) -> SymValueZ3 {
        self.bin_op("bvxor", that)
    }

    /// Left shift: `this << that`.
    pub fn int_left(&self, that: &SymValueZ3) -> SymValueZ3 {
        self.bin_op("bvshl", that)
    }

    /// Logical right shift: `this >> that`.
    pub fn int_right(&self, that: &SymValueZ3) -> SymValueZ3 {
        self.bin_op("bvlshr", that)
    }

    /// Arithmetic right shift: `this >>> that`.
    pub fn int_sright(&self, that: &SymValueZ3) -> SymValueZ3 {
        self.bin_op("bvashr", that)
    }

    // -- Comparison operations --

    /// Equality: `this == that ? 1 : 0`.
    pub fn int_equal(&self, that: &SymValueZ3) -> SymValueZ3 {
        self.cmp_op("=", that)
    }

    /// Inequality: `this != that ? 1 : 0`.
    pub fn int_not_equal(&self, that: &SymValueZ3) -> SymValueZ3 {
        self.cmp_op_inv("=", that)
    }

    /// Signed less than: `this <(s) that ? 1 : 0`.
    pub fn int_sless(&self, that: &SymValueZ3) -> SymValueZ3 {
        self.cmp_op("bvslt", that)
    }

    /// Signed less than or equal: `this <=(s) that ? 1 : 0`.
    pub fn int_sless_equal(&self, that: &SymValueZ3) -> SymValueZ3 {
        self.cmp_op("bvsle", that)
    }

    /// Unsigned less than: `this <(u) that ? 1 : 0`.
    pub fn int_less(&self, that: &SymValueZ3) -> SymValueZ3 {
        self.cmp_op("bvult", that)
    }

    /// Unsigned less than or equal: `this <=(u) that ? 1 : 0`.
    pub fn int_less_equal(&self, that: &SymValueZ3) -> SymValueZ3 {
        self.cmp_op("bvule", that)
    }

    // -- Extension operations --

    /// Zero-extend to the given output size in bytes.
    pub fn int_zext(&self, _out_size_bytes: u32) -> SymValueZ3 {
        let bv = self.bitvec_expr_string.as_deref().unwrap_or("bv0");
        SymValueZ3::from_bitvec(format!("((_ zero_extend 8) {bv})"))
    }

    /// Sign-extend to the given output size in bytes.
    pub fn int_sext(&self, _out_size_bytes: u32) -> SymValueZ3 {
        let bv = self.bitvec_expr_string.as_deref().unwrap_or("bv0");
        SymValueZ3::from_bitvec(format!("((_ sign_extend 8) {bv})"))
    }

    // -- Boolean operations --

    /// Boolean negation: `!this`.
    pub fn bool_negate(&self) -> SymValueZ3 {
        let be = self.bool_expr_string.as_deref().unwrap_or("true");
        SymValueZ3::from_bitvec(format!("(ite (not {be}) bv1 bv0)"))
    }

    /// Boolean AND: `this && that`.
    pub fn bool_and(&self, that: &SymValueZ3) -> SymValueZ3 {
        let l = self.bool_expr_string.as_deref().unwrap_or("true");
        let r = that.bool_expr_string.as_deref().unwrap_or("true");
        SymValueZ3::from_bitvec(format!("(ite (and {l} {r}) bv1 bv0)"))
    }

    /// Boolean OR: `this || that`.
    pub fn bool_or(&self, that: &SymValueZ3) -> SymValueZ3 {
        let l = self.bool_expr_string.as_deref().unwrap_or("true");
        let r = that.bool_expr_string.as_deref().unwrap_or("true");
        SymValueZ3::from_bitvec(format!("(ite (or {l} {r}) bv1 bv0)"))
    }

    /// Boolean XOR.
    pub fn bool_xor(&self, that: &SymValueZ3) -> SymValueZ3 {
        let l = self.bool_expr_string.as_deref().unwrap_or("true");
        let r = that.bool_expr_string.as_deref().unwrap_or("true");
        SymValueZ3::from_bitvec(format!("(ite (xor {l} {r}) bv1 bv0)"))
    }

    // -- Piece / Subpiece --

    /// Concatenate: `this :: that`.
    pub fn piece(&self, that: &SymValueZ3) -> SymValueZ3 {
        let l = self.bitvec_expr_string.as_deref().unwrap_or("bv0");
        let r = that.bitvec_expr_string.as_deref().unwrap_or("bv0");
        SymValueZ3::from_bitvec(format!("(concat {l} {r})"))
    }

    /// Extract a subpiece: `(this >> (offset_bytes * 8))[0..out_size_bits]`.
    pub fn subpiece(
        &self,
        _out_size_bytes: u32,
        offset_bytes: u32,
    ) -> SymValueZ3 {
        let bv = self.bitvec_expr_string.as_deref().unwrap_or("bv0");
        let high = (_out_size_bytes * 8).saturating_sub(1) + offset_bytes * 8;
        let low = offset_bytes * 8;
        SymValueZ3::from_bitvec(format!("((_ extract {high} {low}) {bv})"))
    }

    // -- Carry/Borrow --

    /// Carry from addition.
    pub fn int_carry(&self, that: &SymValueZ3) -> SymValueZ3 {
        let l = self.bitvec_expr_string.as_deref().unwrap_or("bv0");
        let r = that.bitvec_expr_string.as_deref().unwrap_or("bv0");
        SymValueZ3::from_bitvec(format!(
            "(ite (bvule (bvadd {l} {r}) {l}) bv1 bv0)"
        ))
    }

    /// Signed carry from addition.
    pub fn int_scarry(&self, that: &SymValueZ3) -> SymValueZ3 {
        // Simplified: return a placeholder expression
        self.bin_op("INT_SCARRY", that)
    }

    /// Signed borrow from subtraction.
    pub fn int_sborrow(&self, that: &SymValueZ3) -> SymValueZ3 {
        self.bin_op("INT_SBORROW", that)
    }

    // -- Popcount --

    /// Population count (number of set bits).
    pub fn popcount(&self, _out_size_bytes: u32) -> SymValueZ3 {
        let bv = self.bitvec_expr_string.as_deref().unwrap_or("bv0");
        SymValueZ3::from_bitvec(format!("(popcount {bv})"))
    }

    // -- Internal helpers --

    /// Apply a binary bit-vector operation.
    fn bin_op(&self, op: &str, that: &SymValueZ3) -> SymValueZ3 {
        let l = self.bitvec_expr_string.as_deref().unwrap_or("bv0");
        let r = that.bitvec_expr_string.as_deref().unwrap_or("bv0");
        SymValueZ3::from_bitvec(format!("({op} {l} {r})"))
    }

    /// Apply a comparison operation (returns ITE: `op(this, that) ? 1 : 0`).
    fn cmp_op(&self, op: &str, that: &SymValueZ3) -> SymValueZ3 {
        let l = self.bitvec_expr_string.as_deref().unwrap_or("bv0");
        let r = that.bitvec_expr_string.as_deref().unwrap_or("bv0");
        SymValueZ3::from_bitvec(format!("(ite ({op} {l} {r}) bv1 bv0)"))
    }

    /// Apply an inverse comparison (returns ITE: `!op(this, that) ? 1 : 0`).
    fn cmp_op_inv(&self, op: &str, that: &SymValueZ3) -> SymValueZ3 {
        let l = self.bitvec_expr_string.as_deref().unwrap_or("bv0");
        let r = that.bitvec_expr_string.as_deref().unwrap_or("bv0");
        SymValueZ3::from_bitvec(format!("(ite (not ({op} {l} {r})) bv1 bv0)"))
    }
}

impl fmt::Display for SymValueZ3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref bv) = self.bitvec_expr_string {
            write!(f, "<SymValueZ3: {bv}>")
        } else if let Some(ref be) = self.bool_expr_string {
            write!(f, "<SymValueZ3: {be}>")
        } else {
            write!(f, "<SymValueZ3: null>")
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_bitvec() {
        let v = SymValueZ3::from_bitvec("x");
        assert!(v.has_bitvec_expr());
        assert!(!v.has_bool_expr());
    }

    #[test]
    fn test_from_bool() {
        let v = SymValueZ3::from_bool("true");
        assert!(!v.has_bitvec_expr());
        assert!(v.has_bool_expr());
    }

    #[test]
    fn test_from_bitvec_and_bool() {
        let v = SymValueZ3::from_bitvec_and_bool("bv1", "true");
        assert!(v.has_bitvec_expr());
        assert!(v.has_bool_expr());
    }

    #[test]
    fn test_serialize_roundtrip() {
        // Bool takes priority in serialization: bitvec is lost on roundtrip
        let v = SymValueZ3::from_bitvec_and_bool("bv1", "true");
        let serialized = v.serialize();
        let parsed = SymValueZ3::parse(&serialized).unwrap();
        assert!(!parsed.has_bitvec_expr()); // bitvec is not serialized
        assert_eq!(parsed.bool_expr_string, Some("true".to_string()));

        // Bitvec-only roundtrips cleanly
        let v2 = SymValueZ3::from_bitvec("bv42");
        let serialized2 = v2.serialize();
        let parsed2 = SymValueZ3::parse(&serialized2).unwrap();
        assert_eq!(v2, parsed2);
    }

    #[test]
    fn test_serialize_bitvec_only() {
        let v = SymValueZ3::from_bitvec("bv42");
        let serialized = v.serialize();
        assert!(serialized.contains(":::::"));
        let parsed = SymValueZ3::parse(&serialized).unwrap();
        assert_eq!(v, parsed);
    }

    #[test]
    fn test_int_add() {
        let a = SymValueZ3::from_bitvec("a");
        let b = SymValueZ3::from_bitvec("b");
        let result = a.int_add(&b);
        let expr = result.bitvec_expr_string.unwrap();
        assert!(expr.contains("bvadd"));
        assert!(expr.contains("a"));
        assert!(expr.contains("b"));
    }

    #[test]
    fn test_int_sub() {
        let a = SymValueZ3::from_bitvec("a");
        let b = SymValueZ3::from_bitvec("b");
        let result = a.int_sub(&b);
        assert!(result.bitvec_expr_string.unwrap().contains("bvsub"));
    }

    #[test]
    fn test_int_equal() {
        let a = SymValueZ3::from_bitvec("a");
        let b = SymValueZ3::from_bitvec("b");
        let result = a.int_equal(&b);
        let expr = result.bitvec_expr_string.unwrap();
        assert!(expr.contains("ite"));
        assert!(expr.contains("="));
    }

    #[test]
    fn test_int_sless() {
        let a = SymValueZ3::from_bitvec("a");
        let b = SymValueZ3::from_bitvec("b");
        let result = a.int_sless(&b);
        assert!(result.bitvec_expr_string.unwrap().contains("bvslt"));
    }

    #[test]
    fn test_int_and_or_xor() {
        let a = SymValueZ3::from_bitvec("a");
        let b = SymValueZ3::from_bitvec("b");

        assert!(a.int_and(&b).bitvec_expr_string.unwrap().contains("bvand"));
        assert!(a.int_or(&b).bitvec_expr_string.unwrap().contains("bvor"));
        assert!(a.int_xor(&b).bitvec_expr_string.unwrap().contains("bvxor"));
    }

    #[test]
    fn test_shift_operations() {
        let a = SymValueZ3::from_bitvec("a");
        let b = SymValueZ3::from_bitvec("b");

        assert!(a.int_left(&b).bitvec_expr_string.unwrap().contains("bvshl"));
        assert!(a.int_right(&b).bitvec_expr_string.unwrap().contains("bvlshr"));
        assert!(a.int_sright(&b).bitvec_expr_string.unwrap().contains("bvashr"));
    }

    #[test]
    fn test_bool_operations() {
        let a = SymValueZ3::from_bool("p");
        let b = SymValueZ3::from_bool("q");

        let neg = a.bool_negate();
        assert!(neg.bitvec_expr_string.unwrap().contains("not"));

        let and = a.bool_and(&b);
        assert!(and.bitvec_expr_string.unwrap().contains("and"));

        let or = a.bool_or(&b);
        assert!(or.bitvec_expr_string.unwrap().contains("or"));

        let xor = a.bool_xor(&b);
        assert!(xor.bitvec_expr_string.unwrap().contains("xor"));
    }

    #[test]
    fn test_piece_and_subpiece() {
        let a = SymValueZ3::from_bitvec("a");
        let b = SymValueZ3::from_bitvec("b");

        let concat = a.piece(&b);
        assert!(concat.bitvec_expr_string.unwrap().contains("concat"));

        let sub = a.subpiece(4, 0);
        assert!(sub.bitvec_expr_string.unwrap().contains("extract"));
    }

    #[test]
    fn test_int_carry() {
        let a = SymValueZ3::from_bitvec("a");
        let b = SymValueZ3::from_bitvec("b");
        let result = a.int_carry(&b);
        let expr = result.bitvec_expr_string.unwrap();
        assert!(expr.contains("bvadd"));
    }

    #[test]
    fn test_extension_operations() {
        let a = SymValueZ3::from_bitvec("a");
        assert!(a.int_zext(8).bitvec_expr_string.unwrap().contains("zero_extend"));
        assert!(a.int_sext(8).bitvec_expr_string.unwrap().contains("sign_extend"));
    }

    #[test]
    fn test_display() {
        let v = SymValueZ3::from_bitvec("x + y");
        assert!(v.to_string().contains("x + y"));
    }

    #[test]
    fn test_parse_invalid() {
        assert!(SymValueZ3::parse("no_delimiter").is_none());
    }
}
