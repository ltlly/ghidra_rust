//! OpBehaviorFactory: creates OpBehavior instances for P-code opcodes.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorFactory`.

use ghidra_decompile::pcode::OpCode;

use super::binary::BinaryOpBehavior;
use super::unary::UnaryOpBehavior;
use super::special::SpecialOpBehavior;

// Binary operations
use super::int_add::OpBehaviorIntAdd;
use super::int_sub::OpBehaviorIntSub;
use super::int_mult::OpBehaviorIntMult;
use super::int_div::OpBehaviorIntDiv;
use super::int_sdiv::OpBehaviorIntSdiv;
use super::int_rem::OpBehaviorIntRem;
use super::int_srem::OpBehaviorIntSrem;
use super::int_and::OpBehaviorIntAnd;
use super::int_or::OpBehaviorIntOr;
use super::int_xor::OpBehaviorIntXor;
use super::int_left::OpBehaviorIntLeft;
use super::int_right::OpBehaviorIntRight;
use super::int_sright::OpBehaviorIntSright;
use super::int_less::OpBehaviorIntLess;
use super::int_sless::OpBehaviorIntSless;
use super::int_less_equal::OpBehaviorIntLessEqual;
use super::int_sless_equal::OpBehaviorIntSlessEqual;
use super::int_equal::OpBehaviorEqual;
use super::int_not_equal::OpBehaviorNotEqual;
use super::int_carry::OpBehaviorIntCarry;
use super::int_scarry::OpBehaviorIntScarry;
use super::int_sborrow::OpBehaviorIntSborrow;
use super::bool_and::OpBehaviorBoolAnd;
use super::bool_or::OpBehaviorBoolOr;
use super::bool_xor::OpBehaviorBoolXor;
use super::piece::OpBehaviorPiece;
use super::subpiece::OpBehaviorSubpiece;

// Unary operations
use super::copy::OpBehaviorCopy;
use super::int_negate::OpBehaviorIntNegate;
use super::int_2comp::OpBehaviorInt2Comp;
use super::int_sext::OpBehaviorIntSext;
use super::int_zext::OpBehaviorIntZext;
use super::bool_negate::OpBehaviorBoolNegate;
use super::popcount::OpBehaviorPopcount;
use super::lzcount::OpBehaviorLzcount;

/// Enum representing any P-code operation behavior.
///
/// This unifies binary, unary, and special operation behaviors into a single
/// type that can be dispatched by opcode.
#[derive(Debug, Clone)]
pub enum OpBehavior {
    // Binary operations
    IntAdd(OpBehaviorIntAdd),
    IntSub(OpBehaviorIntSub),
    IntMul(OpBehaviorIntMult),
    IntDiv(OpBehaviorIntDiv),
    IntSdiv(OpBehaviorIntSdiv),
    IntRem(OpBehaviorIntRem),
    IntSrem(OpBehaviorIntSrem),
    IntAnd(OpBehaviorIntAnd),
    IntOr(OpBehaviorIntOr),
    IntXor(OpBehaviorIntXor),
    IntLeft(OpBehaviorIntLeft),
    IntRight(OpBehaviorIntRight),
    IntSright(OpBehaviorIntSright),
    IntLess(OpBehaviorIntLess),
    IntSless(OpBehaviorIntSless),
    IntLessEqual(OpBehaviorIntLessEqual),
    IntSlessEqual(OpBehaviorIntSlessEqual),
    IntEqual(OpBehaviorEqual),
    IntNotEqual(OpBehaviorNotEqual),
    IntCarry(OpBehaviorIntCarry),
    IntScarry(OpBehaviorIntScarry),
    IntSborrow(OpBehaviorIntSborrow),
    BoolAnd(OpBehaviorBoolAnd),
    BoolOr(OpBehaviorBoolOr),
    BoolXor(OpBehaviorBoolXor),
    Piece(OpBehaviorPiece),
    Subpiece(OpBehaviorSubpiece),

    // Unary operations
    Copy(OpBehaviorCopy),
    IntNegate(OpBehaviorIntNegate),
    Int2Comp(OpBehaviorInt2Comp),
    IntSext(OpBehaviorIntSext),
    IntZext(OpBehaviorIntZext),
    BoolNegate(OpBehaviorBoolNegate),
    Popcount(OpBehaviorPopcount),
    Lzcount(OpBehaviorLzcount),

    // Special operations
    Special(SpecialOpBehavior),
}

impl OpBehavior {
    /// Get the opcode for this behavior.
    pub fn opcode(&self) -> OpCode {
        match self {
            OpBehavior::IntAdd(_) => OpCode::INT_ADD,
            OpBehavior::IntSub(_) => OpCode::INT_SUB,
            OpBehavior::IntMul(_) => OpCode::INT_MUL,
            OpBehavior::IntDiv(_) => OpCode::INT_DIV,
            OpBehavior::IntSdiv(_) => OpCode::INT_SDIV,
            OpBehavior::IntRem(_) => OpCode::INT_REM,
            OpBehavior::IntSrem(_) => OpCode::INT_SREM,
            OpBehavior::IntAnd(_) => OpCode::INT_AND,
            OpBehavior::IntOr(_) => OpCode::INT_OR,
            OpBehavior::IntXor(_) => OpCode::INT_XOR,
            OpBehavior::IntLeft(_) => OpCode::INT_LEFT,
            OpBehavior::IntRight(_) => OpCode::INT_RIGHT,
            OpBehavior::IntSright(_) => OpCode::INT_SRIGHT,
            OpBehavior::IntLess(_) => OpCode::INT_LESS,
            OpBehavior::IntSless(_) => OpCode::INT_SLESS,
            OpBehavior::IntLessEqual(_) => OpCode::INT_LESSEQUAL,
            OpBehavior::IntSlessEqual(_) => OpCode::INT_SLESSEQUAL,
            OpBehavior::IntEqual(_) => OpCode::INT_EQUAL,
            OpBehavior::IntNotEqual(_) => OpCode::INT_NOTEQUAL,
            OpBehavior::IntCarry(_) => OpCode::INT_CARRY,
            OpBehavior::IntScarry(_) => OpCode::INT_SCARRY,
            OpBehavior::IntSborrow(_) => OpCode::INT_SBORROW,
            OpBehavior::BoolAnd(_) => OpCode::BOOL_AND,
            OpBehavior::BoolOr(_) => OpCode::BOOL_OR,
            OpBehavior::BoolXor(_) => OpCode::BOOL_XOR,
            OpBehavior::Piece(_) => OpCode::PIECE,
            OpBehavior::Subpiece(_) => OpCode::SUBPIECE,
            OpBehavior::Copy(_) => OpCode::COPY,
            OpBehavior::IntNegate(_) => OpCode::INT_NEGATE,
            // INT_2COMP maps to INT_NEGATE in the Rust OpCode enum
            OpBehavior::Int2Comp(_) => OpCode::INT_NEGATE,
            OpBehavior::IntSext(_) => OpCode::INT_SEXT,
            OpBehavior::IntZext(_) => OpCode::INT_ZEXT,
            OpBehavior::BoolNegate(_) => OpCode::BOOL_NEGATE,
            OpBehavior::Popcount(_) => OpCode::POPCOUNT,
            OpBehavior::Lzcount(_) => OpCode::LZCOUNT,
            OpBehavior::Special(s) => {
                // For special ops, we just return COPY as a placeholder
                // since we can't easily convert back from u32
                let _ = s;
                OpCode::UNIMPLEMENTED
            }
        }
    }

    /// Evaluate a binary operation.
    ///
    /// Returns None if this is not a binary operation.
    pub fn eval_binary(&self, sizeout: usize, sizein: usize, in1: u64, in2: u64) -> Option<u64> {
        match self {
            OpBehavior::IntAdd(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::IntSub(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::IntMul(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::IntDiv(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::IntSdiv(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::IntRem(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::IntSrem(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::IntAnd(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::IntOr(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::IntXor(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::IntLeft(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::IntRight(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::IntSright(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::IntLess(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::IntSless(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::IntLessEqual(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::IntSlessEqual(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::IntEqual(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::IntNotEqual(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::IntCarry(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::IntScarry(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::IntSborrow(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::BoolAnd(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::BoolOr(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::BoolXor(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::Piece(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            OpBehavior::Subpiece(b) => Some(b.evaluate_binary_u64(sizeout, sizein, in1, in2)),
            _ => None,
        }
    }

    /// Evaluate a unary operation.
    ///
    /// Returns None if this is not a unary operation.
    pub fn eval_unary(&self, sizeout: usize, sizein: usize, in1: u64) -> Option<u64> {
        match self {
            OpBehavior::Copy(u) => Some(u.evaluate_unary_u64(sizeout, sizein, in1)),
            OpBehavior::IntNegate(u) => Some(u.evaluate_unary_u64(sizeout, sizein, in1)),
            OpBehavior::Int2Comp(u) => Some(u.evaluate_unary_u64(sizeout, sizein, in1)),
            OpBehavior::IntSext(u) => Some(u.evaluate_unary_u64(sizeout, sizein, in1)),
            OpBehavior::IntZext(u) => Some(u.evaluate_unary_u64(sizeout, sizein, in1)),
            OpBehavior::BoolNegate(u) => Some(u.evaluate_unary_u64(sizeout, sizein, in1)),
            OpBehavior::Popcount(u) => Some(u.evaluate_unary_u64(sizeout, sizein, in1)),
            OpBehavior::Lzcount(u) => Some(u.evaluate_unary_u64(sizeout, sizein, in1)),
            _ => None,
        }
    }
}

/// Factory for creating `OpBehavior` instances from opcodes.
pub struct OpBehaviorFactory;

impl OpBehaviorFactory {
    /// Get the `OpBehavior` for the given opcode.
    pub fn get_op_behavior(opcode: OpCode) -> OpBehavior {
        match opcode {
            OpCode::COPY => OpBehavior::Copy(OpBehaviorCopy),
            OpCode::LOAD | OpCode::STORE | OpCode::BRANCH | OpCode::CBRANCH
            | OpCode::BRANCHIND | OpCode::CALL | OpCode::CALLIND | OpCode::CALLOTHER
            | OpCode::RETURN | OpCode::MULTIEQUAL | OpCode::INDIRECT | OpCode::CAST
            | OpCode::PTRADD | OpCode::PTRSUB | OpCode::SEGMENTOP | OpCode::CPOOLREF
            | OpCode::NEW | OpCode::INSERT | OpCode::EXTRACT => {
                OpBehavior::Special(SpecialOpBehavior::new(opcode as u32))
            }
            OpCode::PIECE => OpBehavior::Piece(OpBehaviorPiece),
            OpCode::SUBPIECE => OpBehavior::Subpiece(OpBehaviorSubpiece),
            OpCode::INT_EQUAL => OpBehavior::IntEqual(OpBehaviorEqual),
            OpCode::INT_NOTEQUAL => OpBehavior::IntNotEqual(OpBehaviorNotEqual),
            OpCode::INT_SLESS => OpBehavior::IntSless(OpBehaviorIntSless),
            OpCode::INT_SLESSEQUAL => OpBehavior::IntSlessEqual(OpBehaviorIntSlessEqual),
            OpCode::INT_LESS => OpBehavior::IntLess(OpBehaviorIntLess),
            OpCode::INT_LESSEQUAL => OpBehavior::IntLessEqual(OpBehaviorIntLessEqual),
            OpCode::INT_ZEXT => OpBehavior::IntZext(OpBehaviorIntZext),
            OpCode::INT_SEXT => OpBehavior::IntSext(OpBehaviorIntSext),
            OpCode::INT_ADD => OpBehavior::IntAdd(OpBehaviorIntAdd),
            OpCode::INT_SUB => OpBehavior::IntSub(OpBehaviorIntSub),
            OpCode::INT_CARRY => OpBehavior::IntCarry(OpBehaviorIntCarry),
            OpCode::INT_SCARRY => OpBehavior::IntScarry(OpBehaviorIntScarry),
            OpCode::INT_SBORROW => OpBehavior::IntSborrow(OpBehaviorIntSborrow),
            OpCode::INT_NEGATE => OpBehavior::IntNegate(OpBehaviorIntNegate),
            OpCode::INT_XOR => OpBehavior::IntXor(OpBehaviorIntXor),
            OpCode::INT_AND => OpBehavior::IntAnd(OpBehaviorIntAnd),
            OpCode::INT_OR => OpBehavior::IntOr(OpBehaviorIntOr),
            OpCode::INT_LEFT => OpBehavior::IntLeft(OpBehaviorIntLeft),
            OpCode::INT_RIGHT => OpBehavior::IntRight(OpBehaviorIntRight),
            OpCode::INT_SRIGHT => OpBehavior::IntSright(OpBehaviorIntSright),
            OpCode::INT_MUL => OpBehavior::IntMul(OpBehaviorIntMult),
            OpCode::INT_DIV => OpBehavior::IntDiv(OpBehaviorIntDiv),
            OpCode::INT_SDIV => OpBehavior::IntSdiv(OpBehaviorIntSdiv),
            OpCode::INT_REM => OpBehavior::IntRem(OpBehaviorIntRem),
            OpCode::INT_SREM => OpBehavior::IntSrem(OpBehaviorIntSrem),
            OpCode::BOOL_NEGATE => OpBehavior::BoolNegate(OpBehaviorBoolNegate),
            OpCode::BOOL_XOR => OpBehavior::BoolXor(OpBehaviorBoolXor),
            OpCode::BOOL_AND => OpBehavior::BoolAnd(OpBehaviorBoolAnd),
            OpCode::BOOL_OR => OpBehavior::BoolOr(OpBehaviorBoolOr),
            OpCode::POPCOUNT => OpBehavior::Popcount(OpBehaviorPopcount),
            OpCode::LZCOUNT => OpBehavior::Lzcount(OpBehaviorLzcount),
            _ => OpBehavior::Special(SpecialOpBehavior::new(opcode as u32)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_factory_returns_correct_behavior() {
        let add = OpBehaviorFactory::get_op_behavior(OpCode::INT_ADD);
        assert_eq!(add.opcode(), OpCode::INT_ADD);

        let copy = OpBehaviorFactory::get_op_behavior(OpCode::COPY);
        assert_eq!(copy.opcode(), OpCode::COPY);

        let branch = OpBehaviorFactory::get_op_behavior(OpCode::BRANCH);
        assert_eq!(branch.opcode(), OpCode::UNIMPLEMENTED); // Special ops return UNIMPLEMENTED
    }

    #[test]
    fn test_eval_binary_dispatch() {
        let add = OpBehaviorFactory::get_op_behavior(OpCode::INT_ADD);
        assert_eq!(add.eval_binary(8, 8, 10, 20), Some(30));

        let sub = OpBehaviorFactory::get_op_behavior(OpCode::INT_SUB);
        assert_eq!(sub.eval_binary(8, 8, 30, 10), Some(20));
    }

    #[test]
    fn test_eval_unary_dispatch() {
        let copy = OpBehaviorFactory::get_op_behavior(OpCode::COPY);
        assert_eq!(copy.eval_unary(8, 8, 42), Some(42));

        let negate = OpBehaviorFactory::get_op_behavior(OpCode::INT_NEGATE);
        assert_eq!(negate.eval_unary(1, 1, 0x00), Some(0xFF));
    }

    #[test]
    fn test_special_returns_none_for_binary() {
        let branch = OpBehaviorFactory::get_op_behavior(OpCode::BRANCH);
        assert_eq!(branch.eval_binary(8, 8, 0, 0), None);
    }

    #[test]
    fn test_mul_dispatch() {
        let mul = OpBehaviorFactory::get_op_behavior(OpCode::INT_MUL);
        assert_eq!(mul.eval_binary(8, 8, 6, 7), Some(42));
    }
}
