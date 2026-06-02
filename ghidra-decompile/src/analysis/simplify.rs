//! Expression simplification for P-code operations.
//!
//! Applies a set of rewrite rules to simplify P-code operations. The
//! simplifier supports:
//!
//! - **Constant folding** -- when all inputs are constants, the entire
//!   expression is evaluated at compile time and replaced with a COPY
//!   from the resulting constant.
//! - **Algebraic identities** -- `x + 0 => x`, `x * 1 => x`, `x ^ x => 0`,
//!   etc.
//! - **Copy propagation** -- `COPY` chains are collapsed to their ultimate
//!   source.
//!
//! The simplifier is designed to be used as a pass in the decompiler
//! pipeline, applied after constant propagation and before C output
//! generation.

use std::collections::HashMap;

use crate::pcode::{OpCode, PcodeOperation, Varnode};

// ============================================================================
// ExpressionSimplifier
// ============================================================================

/// The expression simplifier.
///
/// Applies a configurable set of simplification rules to a sequence of
/// P-code operations. Rules are checked in order, and the first matching
/// rule produces the simplified output.
///
/// # Example
///
/// ```ignore
/// let mut simplifier = ExpressionSimplifier::new();
/// simplifier.enable_constant_folding(true);
/// simplifier.enable_algebraic_identities(true);
/// let simplified = simplifier.simplify(&operations);
/// ```
pub struct ExpressionSimplifier {
    /// Known constant values for varnodes (from external constant
    /// propagation).
    constants: HashMap<Varnode, u64>,
    /// Enable constant folding (evaluate ops with all-constant inputs).
    enable_constant_folding: bool,
    /// Enable algebraic identity rules (e.g., x + 0 => x).
    enable_algebraic_identities: bool,
    /// Enable copy-chain collapsing.
    enable_copy_propagation: bool,
}

impl ExpressionSimplifier {
    /// Create a new simplifier with an empty constants table and all
    /// rules enabled.
    pub fn new() -> Self {
        Self {
            constants: HashMap::new(),
            enable_constant_folding: true,
            enable_algebraic_identities: true,
            enable_copy_propagation: true,
        }
    }

    /// Create a simplifier pre-seeded with constant values.
    pub fn with_constants(constants: HashMap<Varnode, u64>) -> Self {
        Self {
            constants,
            enable_constant_folding: true,
            enable_algebraic_identities: true,
            enable_copy_propagation: true,
        }
    }

    /// Enable or disable constant folding.
    pub fn enable_constant_folding(&mut self, enabled: bool) -> &mut Self {
        self.enable_constant_folding = enabled;
        self
    }

    /// Enable or disable algebraic identity rules.
    pub fn enable_algebraic_identities(&mut self, enabled: bool) -> &mut Self {
        self.enable_algebraic_identities = enabled;
        self
    }

    /// Enable or disable copy-propagation collapsing.
    pub fn enable_copy_propagation(&mut self, enabled: bool) -> &mut Self {
        self.enable_copy_propagation = enabled;
        self
    }

    /// Add a known constant value for a varnode.
    pub fn add_constant(&mut self, vn: Varnode, value: u64) {
        self.constants.insert(vn, value);
    }

    /// Simplify a list of operations in place.
    ///
    /// Each operation is checked against all enabled rules. The first
    /// applicable rule produces the replacement operation.
    pub fn simplify(&self, operations: &[PcodeOperation]) -> Vec<PcodeOperation> {
        let mut result = Vec::with_capacity(operations.len());

        for op in operations {
            let simplified = self.try_simplify(op);
            result.push(simplified.unwrap_or_else(|| op.clone()));
        }

        result
    }

    /// Attempt to simplify a single operation.
    ///
    /// Returns `Some(simplified_op)` if a rule matched, or `None` if no
    /// simplification applies.
    fn try_simplify(&self, op: &PcodeOperation) -> Option<PcodeOperation> {
        // Collect constant values for inputs.
        let const_inputs: Vec<Option<u64>> = op
            .inputs
            .iter()
            .map(|inp| self.resolve_constant(inp))
            .collect();

        let all_const = const_inputs.iter().all(|c| c.is_some());
        let consts: Vec<u64> = const_inputs.iter().filter_map(|c| *c).collect();

        // Rule: constant folding (all inputs are known constants).
        if self.enable_constant_folding && all_const && op.output.is_some() {
            if let Some(folded_val) = self.constant_fold(op.opcode, &consts) {
                let out_size = op.output.as_ref().unwrap().size;
                return Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    op.output.clone(),
                    vec![Varnode::constant(folded_val, out_size)],
                ));
            }
        }

        // Rule: algebraic identities.
        if self.enable_algebraic_identities {
            if let Some(simplified) = self.try_algebraic_identity(op, &consts, &const_inputs) {
                return Some(simplified);
            }
        }

        // Rule: copy propagation (collapse COPY chains).
        if self.enable_copy_propagation && op.opcode == OpCode::COPY {
            if let Some(simplified) = self.try_copy_propagation(op) {
                return Some(simplified);
            }
        }

        None
    }

    // ------------------------------------------------------------------
    // Constant folding
    // ------------------------------------------------------------------

    /// Evaluate a P-code operation at compile time when all inputs are
    /// known constants.
    fn constant_fold(&self, opcode: OpCode, consts: &[u64]) -> Option<u64> {
        if consts.len() < 1 {
            return None;
        }

        match opcode {
            // -- Unary --
            OpCode::COPY => Some(consts[0]),
            OpCode::INT_NEGATE => Some((-(consts[0] as i64)) as u64),
            OpCode::INT_ZEXT => Some(consts[0]), // zext preserves value
            OpCode::INT_SEXT => Some(consts[0]), // sext handled by mask
            OpCode::BOOL_NEGATE => Some(if consts[0] == 0 { 1 } else { 0 }),

            // -- Binary arithmetic (require 2 inputs) --
            OpCode::INT_ADD if consts.len() >= 2 => {
                Some(consts[0].wrapping_add(consts[1]))
            }
            OpCode::INT_SUB if consts.len() >= 2 => {
                Some(consts[0].wrapping_sub(consts[1]))
            }
            OpCode::INT_MUL if consts.len() >= 2 => {
                Some(consts[0].wrapping_mul(consts[1]))
            }
            OpCode::INT_DIV if consts.len() >= 2 && consts[1] != 0 => {
                Some(consts[0] / consts[1])
            }
            OpCode::INT_SDIV if consts.len() >= 2 && consts[1] != 0 => {
                Some(((consts[0] as i64).wrapping_div(consts[1] as i64)) as u64)
            }
            OpCode::INT_REM if consts.len() >= 2 && consts[1] != 0 => {
                Some(consts[0] % consts[1])
            }
            OpCode::INT_SREM if consts.len() >= 2 && consts[1] != 0 => {
                Some(((consts[0] as i64).wrapping_rem(consts[1] as i64)) as u64)
            }

            // -- Bitwise --
            OpCode::INT_AND if consts.len() >= 2 => Some(consts[0] & consts[1]),
            OpCode::INT_OR if consts.len() >= 2 => Some(consts[0] | consts[1]),
            OpCode::INT_XOR if consts.len() >= 2 => Some(consts[0] ^ consts[1]),

            // -- Shifts --
            OpCode::INT_LEFT if consts.len() >= 2 && consts[1] < 64 => {
                Some(consts[0].wrapping_shl(consts[1] as u32))
            }
            OpCode::INT_RIGHT if consts.len() >= 2 && consts[1] < 64 => {
                Some(consts[0].wrapping_shr(consts[1] as u32))
            }
            OpCode::INT_SRIGHT if consts.len() >= 2 && consts[1] < 64 => {
                Some(((consts[0] as i64).wrapping_shr(consts[1] as u32)) as u64)
            }

            // -- Comparisons (result is 0 or 1) --
            OpCode::INT_EQUAL if consts.len() >= 2 => {
                Some(if consts[0] == consts[1] { 1 } else { 0 })
            }
            OpCode::INT_NOTEQUAL if consts.len() >= 2 => {
                Some(if consts[0] != consts[1] { 1 } else { 0 })
            }
            OpCode::INT_LESS if consts.len() >= 2 => {
                Some(if consts[0] < consts[1] { 1 } else { 0 })
            }
            OpCode::INT_LESSEQUAL if consts.len() >= 2 => {
                Some(if consts[0] <= consts[1] { 1 } else { 0 })
            }
            OpCode::INT_SLESS if consts.len() >= 2 => {
                Some(if (consts[0] as i64) < (consts[1] as i64) { 1 } else { 0 })
            }
            OpCode::INT_SLESSEQUAL if consts.len() >= 2 => {
                Some(if (consts[0] as i64) <= (consts[1] as i64) { 1 } else { 0 })
            }

            // -- Boolean --
            OpCode::BOOL_AND if consts.len() >= 2 => {
                Some(if consts[0] != 0 && consts[1] != 0 { 1 } else { 0 })
            }
            OpCode::BOOL_OR if consts.len() >= 2 => {
                Some(if consts[0] != 0 || consts[1] != 0 { 1 } else { 0 })
            }
            OpCode::BOOL_XOR if consts.len() >= 2 => {
                Some(if (consts[0] != 0) ^ (consts[1] != 0) { 1 } else { 0 })
            }

            // -- POPCOUNT / LZCOUNT --
            OpCode::POPCOUNT => Some(consts[0].count_ones() as u64),
            OpCode::LZCOUNT => Some(consts[0].leading_zeros() as u64),

            // -- SUBPIECE (truncation) --
            OpCode::SUBPIECE if consts.len() >= 2 => {
                let low_byte = consts[1];
                let out_size = 4u64; // default
                if low_byte * 8 < 64 {
                    let shift = (low_byte * 8) as u32;
                    Some(consts[0] >> shift)
                } else {
                    Some(0)
                }
            }

            // -- PIECE (concatenation) --
            OpCode::PIECE if consts.len() >= 2 => {
                let lo = consts[1];
                // The low part's size determines the shift for the high part.
                Some((consts[0] << 32) | lo)
            }

            _ => None,
        }
    }

    // ------------------------------------------------------------------
    // Algebraic identities
    // ------------------------------------------------------------------

    /// Apply algebraic identity rules to simplify the operation.
    ///
    /// These rules reduce expressions to canonical forms:
    /// - x + 0 => x
    /// - x - 0 => x
    /// - x * 0 => 0
    /// - x * 1 => x
    /// - x & 0 => 0
    /// - x & -1 => x
    /// - x | 0 => x
    /// - x | -1 => -1
    /// - x ^ 0 => x
    /// - x ^ x => 0
    /// - x << 0 => x
    /// - x >> 0 => x
    /// - -(-x) => x
    fn try_algebraic_identity(
        &self,
        op: &PcodeOperation,
        consts: &[u64],
        const_inputs: &[Option<u64>],
    ) -> Option<PcodeOperation> {
        let out = op.output.clone()?;

        match op.opcode {
            // x + 0 => x
            OpCode::INT_ADD if consts.len() >= 2 && consts[1] == 0 => {
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[0].clone()],
                ))
            }

            // 0 + x => x
            OpCode::INT_ADD if consts.len() >= 2 && consts[0] == 0 => {
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[1].clone()],
                ))
            }

            // x - 0 => x
            OpCode::INT_SUB if consts.len() >= 2 && consts[1] == 0 => {
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[0].clone()],
                ))
            }

            // x - x => 0
            OpCode::INT_SUB
                if op.inputs.len() >= 2 && op.inputs[0] == op.inputs[1] =>
            {
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out.clone()),
                    vec![Varnode::constant(0, out.size)],
                ))
            }

            // x * 0 => 0
            OpCode::INT_MUL if consts.len() >= 2 && (consts[0] == 0 || consts[1] == 0) => {
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out.clone()),
                    vec![Varnode::constant(0, out.size)],
                ))
            }

            // x * 1 => x
            OpCode::INT_MUL if consts.len() >= 2 && consts[1] == 1 => {
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[0].clone()],
                ))
            }

            // 1 * x => x
            OpCode::INT_MUL if consts.len() >= 2 && consts[0] == 1 => {
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[1].clone()],
                ))
            }

            // x / 1 => x
            OpCode::INT_DIV | OpCode::INT_SDIV
                if consts.len() >= 2 && consts[1] == 1 =>
            {
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[0].clone()],
                ))
            }

            // x % 1 => 0
            OpCode::INT_REM | OpCode::INT_SREM
                if consts.len() >= 2 && consts[1] == 1 =>
            {
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out.clone()),
                    vec![Varnode::constant(0, out.size)],
                ))
            }

            // x & 0 => 0
            OpCode::INT_AND if consts.len() >= 2 && (consts[0] == 0 || consts[1] == 0) => {
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out.clone()),
                    vec![Varnode::constant(0, out.size)],
                ))
            }

            // x & -1 => x  (all-ones mask)
            OpCode::INT_AND if consts.len() >= 2 && consts[1] == u64::MAX => {
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[0].clone()],
                ))
            }

            // -1 & x => x
            OpCode::INT_AND if consts.len() >= 2 && consts[0] == u64::MAX => {
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[1].clone()],
                ))
            }

            // x | 0 => x
            OpCode::INT_OR if consts.len() >= 2 && consts[1] == 0 => {
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[0].clone()],
                ))
            }

            // x | -1 => -1
            OpCode::INT_OR if consts.len() >= 2 && consts[1] == u64::MAX => {
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out.clone()),
                    vec![Varnode::constant(u64::MAX, out.size)],
                ))
            }

            // x ^ 0 => x
            OpCode::INT_XOR if consts.len() >= 2 && consts[1] == 0 => {
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[0].clone()],
                ))
            }

            // x ^ x => 0
            OpCode::INT_XOR
                if op.inputs.len() >= 2 && op.inputs[0] == op.inputs[1] =>
            {
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out.clone()),
                    vec![Varnode::constant(0, out.size)],
                ))
            }

            // x ^ -1 => ~x  (bitwise NOT)
            OpCode::INT_XOR if consts.len() >= 2 && consts[1] == u64::MAX => {
                Some(PcodeOperation::new_unannotated(
                    OpCode::INT_XOR,
                    Some(out),
                    vec![op.inputs[0].clone(), Varnode::constant(u64::MAX, op.inputs[0].size)],
                ))
            }

            // x << 0 => x
            OpCode::INT_LEFT if consts.len() >= 2 && consts[1] == 0 => {
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[0].clone()],
                ))
            }

            // x >> 0 => x (both logical and arithmetic)
            OpCode::INT_RIGHT | OpCode::INT_SRIGHT
                if consts.len() >= 2 && consts[1] == 0 =>
            {
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[0].clone()],
                ))
            }

            // --(x) => x
            OpCode::INT_NEGATE
                if op.inputs.len() == 1 =>
            {
                // Check if the input is itself a negation.
                // This requires access to the original op, which we don't have
                // in this context. Skip for now.
                None
            }

            // !(!x) => x (not yet foldable without cross-op access)
            OpCode::BOOL_NEGATE => None,

            // Copy propagation: if output is same as input, remove the COPY.
            OpCode::COPY
                if op.output.as_ref() == Some(&op.inputs[0]) =>
            {
                // This COPY is redundant; we can't remove it entirely without
                // rewriting all uses, so keep it as-is but note that a later
                // copy-propagation pass will eliminate it.
                None
            }

            // No identity applies.
            _ => None,
        }
    }

    // ------------------------------------------------------------------
    // Copy propagation
    // ------------------------------------------------------------------

    /// Attempt to collapse a COPY chain.
    ///
    /// If the source of a COPY is itself a known constant (from the
    /// constants table), replace the COPY with a direct constant load.
    fn try_copy_propagation(&self, op: &PcodeOperation) -> Option<PcodeOperation> {
        if op.opcode != OpCode::COPY {
            return None;
        }

        let src = op.inputs.first()?;
        let out = op.output.clone()?;

        // If the source is a known constant, replace with direct constant.
        if let Some(&val) = self.constants.get(src) {
            return Some(PcodeOperation::new_unannotated(
                OpCode::COPY,
                Some(out),
                vec![Varnode::constant(val, src.size)],
            ));
        }

        // If the source itself is a constant-space varnode, use that.
        if src.is_constant() {
            return Some(PcodeOperation::new_unannotated(
                OpCode::COPY,
                Some(out),
                vec![src.clone()],
            ));
        }

        None
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// Resolve the constant value of a varnode.
    ///
    /// Checks the internal constants table first, then falls back to
    /// checking if the varnode is in the constant address space.
    fn resolve_constant(&self, vn: &Varnode) -> Option<u64> {
        if vn.is_constant() {
            return Some(vn.offset);
        }
        self.constants.get(vn).copied()
    }
}

impl Default for ExpressionSimplifier {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn cnst(val: u64, size: u32) -> Varnode {
        Varnode::constant(val, size)
    }

    fn uniq(id: u64, size: u32) -> Varnode {
        Varnode::unique(id, size)
    }

    fn reg(offset: u64, size: u32) -> Varnode {
        Varnode::register("r", offset, size)
    }

    #[test]
    fn test_constant_fold_add() {
        let s = ExpressionSimplifier::new();
        let op = PcodeOperation::new_unannotated(
            OpCode::INT_ADD,
            Some(uniq(0, 4)),
            vec![cnst(10, 4), cnst(20, 4)],
        );

        let simplified = s.simplify(&[op]);
        assert_eq!(simplified.len(), 1);
        assert_eq!(simplified[0].opcode, OpCode::COPY);
        assert_eq!(simplified[0].inputs[0].constant_value(), Some(30));
    }

    #[test]
    fn test_constant_fold_sub() {
        let s = ExpressionSimplifier::new();
        let op = PcodeOperation::new_unannotated(
            OpCode::INT_SUB,
            Some(uniq(0, 4)),
            vec![cnst(100, 4), cnst(30, 4)],
        );

        let simplified = s.simplify(&[op]);
        assert_eq!(simplified[0].opcode, OpCode::COPY);
        assert_eq!(simplified[0].inputs[0].constant_value(), Some(70));
    }

    #[test]
    fn test_constant_fold_mul() {
        let s = ExpressionSimplifier::new();
        let op = PcodeOperation::new_unannotated(
            OpCode::INT_MUL,
            Some(uniq(0, 4)),
            vec![cnst(7, 4), cnst(6, 4)],
        );

        let simplified = s.simplify(&[op]);
        assert_eq!(simplified[0].inputs[0].constant_value(), Some(42));
    }

    #[test]
    fn test_constant_fold_div() {
        let s = ExpressionSimplifier::new();
        let op = PcodeOperation::new_unannotated(
            OpCode::INT_DIV,
            Some(uniq(0, 4)),
            vec![cnst(100, 4), cnst(5, 4)],
        );

        let simplified = s.simplify(&[op]);
        assert_eq!(simplified[0].inputs[0].constant_value(), Some(20));
    }

    #[test]
    fn test_constant_fold_div_by_zero_no_crash() {
        let s = ExpressionSimplifier::new();
        let op = PcodeOperation::new_unannotated(
            OpCode::INT_DIV,
            Some(uniq(0, 4)),
            vec![cnst(10, 4), cnst(0, 4)],
        );

        let simplified = s.simplify(&[op]);
        // Should not fold (division by zero is undefined), op unchanged.
        assert_eq!(simplified[0].opcode, OpCode::INT_DIV);
    }

    #[test]
    fn test_algebraic_add_zero() {
        let s = ExpressionSimplifier::new();
        let op = PcodeOperation::new_unannotated(
            OpCode::INT_ADD,
            Some(uniq(0, 4)),
            vec![reg(0, 4), cnst(0, 4)],
        );

        let simplified = s.simplify(&[op]);
        assert_eq!(simplified[0].opcode, OpCode::COPY);
        assert_eq!(simplified[0].inputs[0], reg(0, 4));
    }

    #[test]
    fn test_algebraic_add_zero_commuted() {
        let s = ExpressionSimplifier::new();
        let op = PcodeOperation::new_unannotated(
            OpCode::INT_ADD,
            Some(uniq(0, 4)),
            vec![cnst(0, 4), reg(0, 4)],
        );

        let simplified = s.simplify(&[op]);
        assert_eq!(simplified[0].opcode, OpCode::COPY);
        assert_eq!(simplified[0].inputs[0], reg(0, 4));
    }

    #[test]
    fn test_algebraic_sub_zero() {
        let s = ExpressionSimplifier::new();
        let op = PcodeOperation::new_unannotated(
            OpCode::INT_SUB,
            Some(uniq(0, 4)),
            vec![reg(0, 4), cnst(0, 4)],
        );

        let simplified = s.simplify(&[op]);
        assert_eq!(simplified[0].opcode, OpCode::COPY);
        assert_eq!(simplified[0].inputs[0], reg(0, 4));
    }

    #[test]
    fn test_algebraic_mul_one() {
        let s = ExpressionSimplifier::new();
        let op = PcodeOperation::new_unannotated(
            OpCode::INT_MUL,
            Some(uniq(0, 4)),
            vec![reg(0, 4), cnst(1, 4)],
        );

        let simplified = s.simplify(&[op]);
        assert_eq!(simplified[0].opcode, OpCode::COPY);
    }

    #[test]
    fn test_algebraic_mul_zero() {
        let s = ExpressionSimplifier::new();
        let op = PcodeOperation::new_unannotated(
            OpCode::INT_MUL,
            Some(uniq(0, 4)),
            vec![reg(0, 4), cnst(0, 4)],
        );

        let simplified = s.simplify(&[op]);
        assert_eq!(simplified[0].opcode, OpCode::COPY);
        assert_eq!(simplified[0].inputs[0].constant_value(), Some(0));
    }

    #[test]
    fn test_algebraic_and_zero() {
        let s = ExpressionSimplifier::new();
        let op = PcodeOperation::new_unannotated(
            OpCode::INT_AND,
            Some(uniq(0, 4)),
            vec![reg(0, 4), cnst(0, 4)],
        );

        let simplified = s.simplify(&[op]);
        assert_eq!(simplified[0].opcode, OpCode::COPY);
        assert_eq!(simplified[0].inputs[0].constant_value(), Some(0));
    }

    #[test]
    fn test_algebraic_or_zero() {
        let s = ExpressionSimplifier::new();
        let op = PcodeOperation::new_unannotated(
            OpCode::INT_OR,
            Some(uniq(0, 4)),
            vec![reg(0, 4), cnst(0, 4)],
        );

        let simplified = s.simplify(&[op]);
        assert_eq!(simplified[0].opcode, OpCode::COPY);
        assert_eq!(simplified[0].inputs[0], reg(0, 4));
    }

    #[test]
    fn test_algebraic_xor_zero() {
        let s = ExpressionSimplifier::new();
        let op = PcodeOperation::new_unannotated(
            OpCode::INT_XOR,
            Some(uniq(0, 4)),
            vec![reg(0, 4), cnst(0, 4)],
        );

        let simplified = s.simplify(&[op]);
        assert_eq!(simplified[0].opcode, OpCode::COPY);
        assert_eq!(simplified[0].inputs[0], reg(0, 4));
    }

    #[test]
    fn test_algebraic_xor_self() {
        let s = ExpressionSimplifier::new();
        let v = reg(0, 4);
        let op = PcodeOperation::new_unannotated(
            OpCode::INT_XOR,
            Some(uniq(0, 4)),
            vec![v.clone(), v.clone()],
        );

        let simplified = s.simplify(&[op]);
        assert_eq!(simplified[0].opcode, OpCode::COPY);
        assert_eq!(simplified[0].inputs[0].constant_value(), Some(0));
    }

    #[test]
    fn test_algebraic_shift_zero() {
        let s = ExpressionSimplifier::new();
        let op = PcodeOperation::new_unannotated(
            OpCode::INT_LEFT,
            Some(uniq(0, 4)),
            vec![reg(0, 4), cnst(0, 4)],
        );

        let simplified = s.simplify(&[op]);
        assert_eq!(simplified[0].opcode, OpCode::COPY);
        assert_eq!(simplified[0].inputs[0], reg(0, 4));
    }

    #[test]
    fn test_copy_propagation_with_constants() {
        let mut s = ExpressionSimplifier::new();
        s.add_constant(uniq(5, 4), 42);
        let op = PcodeOperation::new_unannotated(
            OpCode::COPY,
            Some(uniq(0, 4)),
            vec![uniq(5, 4)],
        );

        let simplified = s.simplify(&[op]);
        assert_eq!(simplified[0].opcode, OpCode::COPY);
        assert_eq!(simplified[0].inputs[0].constant_value(), Some(42));
    }

    #[test]
    fn test_disable_constant_folding() {
        let mut s = ExpressionSimplifier::new();
        s.enable_constant_folding(false);
        let op = PcodeOperation::new_unannotated(
            OpCode::INT_ADD,
            Some(uniq(0, 4)),
            vec![cnst(3, 4), cnst(4, 4)],
        );

        let simplified = s.simplify(&[op]);
        // Should NOT be folded; op should remain INT_ADD.
        assert_eq!(simplified[0].opcode, OpCode::INT_ADD);
    }

    #[test]
    fn test_non_foldable_op() {
        let s = ExpressionSimplifier::new();
        let op = PcodeOperation::new_unannotated(
            OpCode::STORE,
            None,
            vec![cnst(0, 8), cnst(0x1000, 4), reg(0, 4)],
        );

        let simplified = s.simplify(&[op]);
        // STORE should pass through unchanged.
        assert_eq!(simplified[0].opcode, OpCode::STORE);
    }
}
