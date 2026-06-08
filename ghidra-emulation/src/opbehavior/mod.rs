//! P-code operation behavior implementations.
//!
//! This module provides Rust implementations of Ghidra's `OpBehavior` hierarchy
//! from `ghidra.pcode.opbehavior`. Each behavior implements the evaluation logic
//! for a specific P-code operation.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehavior`,
//! `BinaryOpBehavior`, `UnaryOpBehavior`, `SpecialOpBehavior`, `OpBehaviorFactory`.

pub mod utils;
pub mod binary;
pub mod unary;
pub mod special;
pub mod factory;

// Integer arithmetic operations
pub mod int_add;
pub mod int_sub;
pub mod int_mult;
pub mod int_div;
pub mod int_sdiv;
pub mod int_rem;
pub mod int_srem;

// Bitwise operations
pub mod int_and;
pub mod int_or;
pub mod int_xor;
pub mod int_negate;
pub mod int_2comp;

// Shift operations
pub mod int_left;
pub mod int_right;
pub mod int_sright;

// Comparison operations
pub mod int_less;
pub mod int_sless;
pub mod int_less_equal;
pub mod int_sless_equal;
pub mod int_equal;
pub mod int_not_equal;

// Carry/borrow operations
pub mod int_carry;
pub mod int_scarry;
pub mod int_sborrow;

// Extension operations
pub mod int_sext;
pub mod int_zext;

// Boolean operations
pub mod bool_and;
pub mod bool_or;
pub mod bool_xor;
pub mod bool_negate;

// Piece operations
pub mod piece;
pub mod subpiece;
pub mod copy;

// Additional operations
pub mod popcount;
pub mod lzcount;

// Re-exports
pub use binary::BinaryOpBehavior;
pub use unary::UnaryOpBehavior;
pub use special::SpecialOpBehavior;
pub use factory::OpBehaviorFactory;
