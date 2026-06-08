//! P-code arithmetic trait for abstract value operations.
//!
//! Ported from Java: `ghidra.pcode.exec.PcodeArithmetic`.
//!
//! This trait defines arithmetic operations on values of type `T`. Implementations
//! provide the actual evaluation logic for P-code operations.

/// Reasons for requiring a concrete value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// The value is needed to parse an instruction.
    Decode,
    /// The value is needed for disassembly context.
    Context,
    /// The value is needed to decide a conditional branch.
    Condition,
    /// The value will be used as the address of an indirect branch.
    Branch,
    /// The value will be used as the address of a value to load.
    Load,
    /// The value will be used as the address of a value to store.
    Store,
    /// The p-code specification defines the operand as a constant.
    ByDef,
    /// Some other reason.
    Other,
    /// The user or a tool is inspecting the value.
    Inspect,
}

/// Trait defining P-code arithmetic operations on values of type `T`.
///
/// Each arithmetic provides operations for manipulating values in the P-code
/// execution engine. The typical implementation operates on byte arrays with
/// a specific endianness.
pub trait PcodeArithmetic<T> {
    /// Apply a unary operator to the given input.
    fn unary_op(&self, opcode: u32, sizeout: usize, sizein1: usize, in1: T) -> T;

    /// Apply a binary operator to the given inputs.
    fn binary_op(
        &self,
        opcode: u32,
        sizeout: usize,
        sizein1: usize,
        in1: T,
        sizein2: usize,
        in2: T,
    ) -> T;

    /// Convert a constant byte value to type T with unsigned extension.
    fn from_const_byte(&self, value: u8, size: usize) -> T;

    /// Convert a constant u64 value to type T with the given size.
    fn from_const_u64(&self, value: u64, size: usize) -> T;

    /// Convert a constant byte array to type T.
    fn from_const_bytes(&self, value: &[u8]) -> T;

    /// Convert, if possible, the given abstract value to a concrete byte array.
    fn to_concrete(&self, value: &T, purpose: Purpose) -> Result<Vec<u8>, String>;

    /// Convert, if possible, the given abstract condition to a concrete boolean.
    fn is_true(&self, cond: &T, purpose: Purpose) -> bool {
        match self.to_concrete(cond, purpose) {
            Ok(bytes) => bytes.iter().any(|&b| b != 0),
            Err(_) => false,
        }
    }

    /// Convert, if possible, the given abstract value to a concrete u64.
    fn to_u64(&self, value: &T, purpose: Purpose) -> Result<u64, String> {
        let bytes = self.to_concrete(value, purpose)?;
        let mut buf = [0u8; 8];
        let len = bytes.len().min(8);
        buf[..len].copy_from_slice(&bytes[..len]);
        Ok(u64::from_le_bytes(buf))
    }

    /// Get the size in bytes of the given abstract value.
    fn size_of(&self, value: &T) -> usize;

    /// Apply the PTRADD operator.
    fn ptr_add(
        &self,
        sizeout: usize,
        sizein_base: usize,
        in_base: T,
        sizein_index: usize,
        in_index: T,
        in_size: usize,
    ) -> T {
        let index_sized = self.binary_op(
            12, // INT_MULT
            sizeout,
            sizein_index,
            in_index,
            4,
            self.from_const_u64(in_size as u64, 4),
        );
        self.binary_op(10, sizeout, sizein_base, in_base, sizeout, index_sized) // INT_ADD
    }

    /// Apply the PTRSUB operator.
    fn ptr_sub(
        &self,
        sizeout: usize,
        sizein_base: usize,
        in_base: T,
        sizein_offset: usize,
        in_offset: T,
    ) -> T {
        self.binary_op(10, sizeout, sizein_base, in_base, sizein_offset, in_offset) // INT_ADD
    }

    /// Apply modifications before a value is stored.
    fn mod_before_store(
        &self,
        sizein_offset: usize,
        space_name: &str,
        _in_offset: T,
        sizein_value: usize,
        in_value: T,
    ) -> T {
        let _ = (sizein_offset, space_name, sizein_value);
        // Default: no modification
        in_value
    }

    /// Apply modifications after a value is loaded.
    fn mod_after_load(
        &self,
        sizein_offset: usize,
        space_name: &str,
        _in_offset: T,
        sizein_value: usize,
        in_value: T,
    ) -> T {
        let _ = (sizein_offset, space_name, sizein_value);
        // Default: no modification
        in_value
    }
}

/// Concrete byte-array arithmetic implementation.
///
/// This is the typical implementation for P-code execution, operating on
/// little-endian byte arrays.
#[derive(Debug, Clone, Copy)]
pub struct BytesPcodeArithmetic {
    /// Whether this arithmetic uses big-endian byte order.
    pub is_big_endian: bool,
}

impl BytesPcodeArithmetic {
    /// Create a little-endian arithmetic.
    pub fn little_endian() -> Self {
        Self {
            is_big_endian: false,
        }
    }

    /// Create a big-endian arithmetic.
    pub fn big_endian() -> Self {
        Self {
            is_big_endian: true,
        }
    }
}

impl PcodeArithmetic<Vec<u8>> for BytesPcodeArithmetic {
    fn unary_op(&self, opcode: u32, sizeout: usize, sizein1: usize, in1: Vec<u8>) -> Vec<u8> {
        use crate::opbehavior::factory::OpBehaviorFactory;
        use ghidra_decompile::pcode::OpCode;

        let opcode_enum = OpCode::try_from(opcode as u8).unwrap_or(OpCode::COPY);
        let behavior = OpBehaviorFactory::get_op_behavior(opcode_enum);

        let val1 = bytes_to_u64(&in1, self.is_big_endian);
        if let Some(result) = behavior.eval_unary(sizeout, sizein1, val1) {
            u64_to_bytes(result, sizeout, self.is_big_endian)
        } else {
            vec![0; sizeout]
        }
    }

    fn binary_op(
        &self,
        opcode: u32,
        sizeout: usize,
        sizein1: usize,
        in1: Vec<u8>,
        _sizein2: usize,
        in2: Vec<u8>,
    ) -> Vec<u8> {
        use crate::opbehavior::factory::OpBehaviorFactory;
        use ghidra_decompile::pcode::OpCode;

        let opcode_enum = OpCode::try_from(opcode as u8).unwrap_or(OpCode::COPY);
        let behavior = OpBehaviorFactory::get_op_behavior(opcode_enum);

        let val1 = bytes_to_u64(&in1, self.is_big_endian);
        let val2 = bytes_to_u64(&in2, self.is_big_endian);
        if let Some(result) = behavior.eval_binary(sizeout, sizein1, val1, val2) {
            u64_to_bytes(result, sizeout, self.is_big_endian)
        } else {
            vec![0; sizeout]
        }
    }

    fn from_const_byte(&self, value: u8, size: usize) -> Vec<u8> {
        let mut result = vec![0u8; size];
        if self.is_big_endian {
            result[size - 1] = value;
        } else {
            result[0] = value;
        }
        result
    }

    fn from_const_u64(&self, value: u64, size: usize) -> Vec<u8> {
        u64_to_bytes(value, size, self.is_big_endian)
    }

    fn from_const_bytes(&self, value: &[u8]) -> Vec<u8> {
        value.to_vec()
    }

    fn to_concrete(&self, value: &Vec<u8>, _purpose: Purpose) -> Result<Vec<u8>, String> {
        Ok(value.clone())
    }

    fn size_of(&self, value: &Vec<u8>) -> usize {
        value.len()
    }
}

/// Convert a byte array to a u64 value.
pub fn bytes_to_u64(bytes: &[u8], is_big_endian: bool) -> u64 {
    let mut buf = [0u8; 8];
    let len = bytes.len().min(8);
    if is_big_endian {
        let start = 8 - len;
        buf[start..].copy_from_slice(&bytes[..len]);
        u64::from_be_bytes(buf)
    } else {
        buf[..len].copy_from_slice(&bytes[..len]);
        u64::from_le_bytes(buf)
    }
}

/// Convert a u64 value to a byte array.
pub fn u64_to_bytes(value: u64, size: usize, is_big_endian: bool) -> Vec<u8> {
    let bytes = if is_big_endian {
        // For big-endian, the significant bytes are at the end of to_be_bytes()
        let all = value.to_be_bytes();
        all[8 - size..].to_vec()
    } else {
        value.to_le_bytes()[..size].to_vec()
    };
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_u64_le() {
        assert_eq!(bytes_to_u64(&[0x78, 0x56, 0x34, 0x12], false), 0x12345678);
    }

    #[test]
    fn test_bytes_to_u64_be() {
        assert_eq!(bytes_to_u64(&[0x12, 0x34, 0x56, 0x78], true), 0x12345678);
    }

    #[test]
    fn test_u64_to_bytes_le() {
        assert_eq!(
            u64_to_bytes(0x12345678, 4, false),
            vec![0x78, 0x56, 0x34, 0x12]
        );
    }

    #[test]
    fn test_u64_to_bytes_be() {
        assert_eq!(
            u64_to_bytes(0x12345678, 4, true),
            vec![0x12, 0x34, 0x56, 0x78]
        );
    }

    #[test]
    fn test_bytes_arithmetic_add() {
        let arith = BytesPcodeArithmetic::little_endian();
        let a = vec![10, 0, 0, 0, 0, 0, 0, 0];
        let b = vec![20, 0, 0, 0, 0, 0, 0, 0];
        let result = arith.binary_op(18, 8, 8, a, 8, b); // INT_ADD = 18
        assert_eq!(result, vec![30, 0, 0, 0, 0, 0, 0, 0]);
    }
}
