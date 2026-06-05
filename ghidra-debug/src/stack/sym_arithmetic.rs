//! Symbolic arithmetic for p-code interpretation during stack analysis.
//!
//! Ported from Ghidra's `SymPcodeArithmetic`. Provides the arithmetic
//! operations over `Sym` values, matching p-code opcodes to symbolic
//! transformations.

use super::sym::{ConstSym, Sym};

/// P-code opcodes relevant to stack analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcodeOp {
    /// Copy (identity).
    Copy,
    /// Integer addition.
    IntAdd,
    /// Integer subtraction.
    IntSub,
    /// Integer AND.
    IntAnd,
    /// Integer OR (results in opaque).
    IntOr,
    /// Integer XOR (results in opaque).
    IntXor,
    /// Load from memory (dereference).
    Load,
    /// Store to memory.
    Store,
    /// Other (results in opaque).
    Other(u32),
}

/// Arithmetic engine for `Sym` values, parameterised by the stack-pointer
/// register name so it can work for any ISA.
#[derive(Debug, Clone)]
pub struct SymArithmetic {
    /// The name of the stack pointer register for the target ISA.
    pub sp_name: String,
    /// Whether the architecture is big-endian.
    pub big_endian: bool,
}

impl SymArithmetic {
    /// Create a new symbolic arithmetic engine.
    pub fn new(sp_name: impl Into<String>, big_endian: bool) -> Self {
        Self {
            sp_name: sp_name.into(),
            big_endian,
        }
    }

    /// Evaluate a unary p-code operation.
    pub fn unary_op(&self, op: PcodeOp, in1: &Sym) -> Sym {
        match op {
            PcodeOp::Copy => in1.clone(),
            _ => Sym::opaque(),
        }
    }

    /// Evaluate a binary p-code operation.
    pub fn binary_op(&self, op: PcodeOp, in1: &Sym, in2: &Sym) -> Sym {
        match op {
            PcodeOp::IntAdd => in1.add(&self.sp_name, in2),
            PcodeOp::IntSub => in1.sub(&self.sp_name, in2),
            PcodeOp::IntAnd => in1.and(&self.sp_name, in2),
            _ => Sym::opaque(),
        }
    }

    /// Evaluate a load (dereference) operation.
    pub fn load_op(&self, _space: &str, offset: &Sym, _size: u32) -> Sym {
        offset.deref(&self.sp_name)
    }

    /// Construct a `Sym::Const` from raw bytes.
    pub fn from_const(&self, bytes: &[u8]) -> Sym {
        let value = if self.big_endian {
            let mut buf = [0u8; 8];
            let len = bytes.len().min(8);
            buf[8 - len..].copy_from_slice(&bytes[..len]);
            i64::from_be_bytes(buf)
        } else {
            let mut buf = [0u8; 8];
            let len = bytes.len().min(8);
            buf[..len].copy_from_slice(&bytes[..len]);
            i64::from_le_bytes(buf)
        };
        Sym::Const(ConstSym {
            value,
            size: bytes.len() as u32,
        })
    }

    /// Try to concretize a symbolic value to bytes.
    ///
    /// Returns `None` if the value is not a constant.
    pub fn to_concrete(&self, sym: &Sym, size: u32) -> Option<Vec<u8>> {
        match sym {
            Sym::Const(c) => {
                let mut bytes = vec![0u8; size as usize];
                let val_bytes = if self.big_endian {
                    c.value.to_be_bytes()
                } else {
                    c.value.to_le_bytes()
                };
                let copy_len = (size as usize).min(8);
                if self.big_endian {
                    bytes[..copy_len].copy_from_slice(&val_bytes[8 - copy_len..]);
                } else {
                    bytes[..copy_len].copy_from_slice(&val_bytes[..copy_len]);
                }
                Some(bytes)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arithmetic() -> SymArithmetic {
        SymArithmetic::new("SP", false)
    }

    #[test]
    fn test_copy() {
        let arith = arithmetic();
        let c = Sym::constant(42);
        assert_eq!(arith.unary_op(PcodeOp::Copy, &c), c);
    }

    #[test]
    fn test_int_add_consts() {
        let arith = arithmetic();
        let a = Sym::constant(10);
        let b = Sym::constant(20);
        let result = arith.binary_op(PcodeOp::IntAdd, &a, &b);
        assert_eq!(result.as_const_value(), Some(30));
    }

    #[test]
    fn test_int_add_sp_offset() {
        let arith = arithmetic();
        let sp = Sym::register("SP", 8);
        let c = Sym::constant(-0x10);
        let result = arith.binary_op(PcodeOp::IntAdd, &sp, &c);
        assert_eq!(result, Sym::stack_offset(-0x10));
    }

    #[test]
    fn test_int_sub() {
        let arith = arithmetic();
        let sp = Sym::register("SP", 8);
        let c = Sym::constant(8);
        let result = arith.binary_op(PcodeOp::IntSub, &sp, &c);
        assert_eq!(result, Sym::stack_offset(-8));
    }

    #[test]
    fn test_int_and() {
        let arith = arithmetic();
        let a = Sym::constant(0xFF00);
        let b = Sym::constant(0x00FF);
        let result = arith.binary_op(PcodeOp::IntAnd, &a, &b);
        assert_eq!(result.as_const_value(), Some(0));
    }

    #[test]
    fn test_load_op() {
        let arith = arithmetic();
        let offset = Sym::stack_offset(-8);
        let result = arith.load_op("stack", &offset, 8);
        assert!(result.is_stack_deref());
    }

    #[test]
    fn test_from_const_le() {
        let arith = SymArithmetic::new("SP", false);
        let bytes = [0x78, 0x56, 0x34, 0x12];
        let sym = arith.from_const(&bytes);
        assert_eq!(sym.as_const_value(), Some(0x12345678));
    }

    #[test]
    fn test_from_const_be() {
        let arith = SymArithmetic::new("SP", true);
        let bytes = [0x12, 0x34, 0x56, 0x78];
        let sym = arith.from_const(&bytes);
        assert_eq!(sym.as_const_value(), Some(0x12345678));
    }

    #[test]
    fn test_to_concrete_le() {
        let arith = SymArithmetic::new("SP", false);
        let sym = Sym::Const(ConstSym {
            value: 0x12345678,
            size: 4,
        });
        let bytes = arith.to_concrete(&sym, 4).unwrap();
        assert_eq!(bytes, [0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_to_concrete_opaque_returns_none() {
        let arith = arithmetic();
        assert!(arith.to_concrete(&Sym::opaque(), 4).is_none());
    }

    #[test]
    fn test_other_op_produces_opaque() {
        let arith = arithmetic();
        let result = arith.binary_op(PcodeOp::IntOr, &Sym::constant(1), &Sym::constant(2));
        assert!(result.is_opaque());
    }
}
