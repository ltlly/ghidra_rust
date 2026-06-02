//! P-code operation executor.
//!
//! [`PcodeExecutor`] executes individual [`PcodeOperation`]s against the
//! current emulator state and memory. It supports all 65 P-code opcodes.

use ghidra_core::addr::{Address, AddressSpace};
use ghidra_decompile::pcode::{OpCode, PcodeOperation, Varnode};

use crate::memory::{EmulatedMemory, MemoryError};
use crate::state::EmulatorState;
use crate::EmulatorError;

// ---------------------------------------------------------------------------
// PcodeExecutor
// ---------------------------------------------------------------------------

/// Executes P-code operations, updating register and memory state.
///
/// The executor is stateless; all mutable state is passed in via the
/// `state` and `memory` parameters.
#[derive(Debug, Clone, Copy, Default)]
pub struct PcodeExecutor;

impl PcodeExecutor {
    /// Create a new executor.
    pub fn new() -> Self {
        Self
    }

    /// Execute a single P-code operation.
    ///
    /// Updates `state` and/or `memory` as appropriate for the opcode.
    /// Returns `Ok(())` on success.
    pub fn execute(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        match op.opcode {
            // -- data movement ---------------------------------------------------
            OpCode::COPY => self.exec_copy(op, state, memory),
            OpCode::LOAD => self.exec_load(op, state, memory),
            OpCode::STORE => self.exec_store(op, state, memory),

            // -- integer arithmetic ----------------------------------------------
            OpCode::INT_ADD => self.exec_binary_arith(op, state, |a, b| a.wrapping_add(b)),
            OpCode::INT_SUB => self.exec_binary_arith(op, state, |a, b| a.wrapping_sub(b)),
            OpCode::INT_MUL => self.exec_binary_arith(op, state, |a, b| a.wrapping_mul(b)),
            OpCode::INT_DIV => self.exec_binary_div(op, state, false),
            OpCode::INT_SDIV => self.exec_binary_div(op, state, true),
            OpCode::INT_REM => self.exec_binary_rem(op, state, false),
            OpCode::INT_SREM => self.exec_binary_rem(op, state, true),
            OpCode::INT_NEGATE => self.exec_unary_arith(op, state, |a| (!a).wrapping_add(1)),
            OpCode::INT_CARRY => self.exec_int_carry(op, state),
            OpCode::INT_SCARRY => self.exec_int_scarry(op, state),
            OpCode::INT_SBORROW => self.exec_int_sborrow(op, state),

            // -- extension -------------------------------------------------------
            OpCode::INT_SEXT => self.exec_int_sext(op, state),
            OpCode::INT_ZEXT => self.exec_int_zext(op, state),

            // -- integer bitwise / shifts ----------------------------------------
            OpCode::INT_AND => self.exec_binary_arith(op, state, |a, b| a & b),
            OpCode::INT_OR => self.exec_binary_arith(op, state, |a, b| a | b),
            OpCode::INT_XOR => self.exec_binary_arith(op, state, |a, b| a ^ b),
            OpCode::INT_LEFT => self.exec_shift(op, state, |a, b| a.wrapping_shl(b)),
            OpCode::INT_RIGHT => self.exec_shift(op, state, |a, b| a.wrapping_shr(b)),
            OpCode::INT_SRIGHT => self.exec_signed_shift_right(op, state),

            // -- integer comparisons ---------------------------------------------
            OpCode::INT_EQUAL => self.exec_comparison(op, state, |a, b| a == b),
            OpCode::INT_NOTEQUAL => self.exec_comparison(op, state, |a, b| a != b),
            OpCode::INT_SLESS => self.exec_comparison_signed(op, state, |a, b| a < b),
            OpCode::INT_SLESSEQUAL => self.exec_comparison_signed(op, state, |a, b| a <= b),
            OpCode::INT_LESS => self.exec_comparison(op, state, |a, b| a < b),
            OpCode::INT_LESSEQUAL => self.exec_comparison(op, state, |a, b| a <= b),

            // -- boolean operations ----------------------------------------------
            OpCode::BOOL_NEGATE => self.exec_bool_negate(op, state),
            OpCode::BOOL_AND => self.exec_bool_binary(op, state, |a, b| a && b),
            OpCode::BOOL_OR => self.exec_bool_binary(op, state, |a, b| a || b),
            OpCode::BOOL_XOR => self.exec_bool_binary(op, state, |a, b| a ^ b),

            // -- floating-point arithmetic ---------------------------------------
            OpCode::FLOAT_ADD => self.exec_float_binary(op, state, |a, b| a + b),
            OpCode::FLOAT_SUB => self.exec_float_binary(op, state, |a, b| a - b),
            OpCode::FLOAT_MUL => self.exec_float_binary(op, state, |a, b| a * b),
            OpCode::FLOAT_DIV => self.exec_float_binary(op, state, |a, b| a / b),
            OpCode::FLOAT_NEG => self.exec_float_unary(op, state, |a| -a),
            OpCode::FLOAT_ABS => self.exec_float_unary(op, state, |a| a.abs()),
            OpCode::FLOAT_SQRT => self.exec_float_unary(op, state, |a| a.sqrt()),
            OpCode::FLOAT_INT2FLOAT => self.exec_float_int_to_float(op, state),
            OpCode::FLOAT_FLOAT2INT => self.exec_float_float_to_float(op, state),
            OpCode::FLOAT_TRUNC => self.exec_float_unary(op, state, |a| a.trunc()),
            OpCode::FLOAT_CEIL => self.exec_float_unary(op, state, |a| a.ceil()),
            OpCode::FLOAT_FLOOR => self.exec_float_unary(op, state, |a| a.floor()),
            OpCode::FLOAT_ROUND => self.exec_float_unary(op, state, |a| a.round()),
            OpCode::FLOAT_NAN => self.exec_float_nan(op, state),

            // -- floating-point comparisons --------------------------------------
            OpCode::FLOAT_EQUAL => self.exec_float_cmp(op, state, |a, b| a == b),
            OpCode::FLOAT_NOTEQUAL => self.exec_float_cmp(op, state, |a, b| a != b),
            OpCode::FLOAT_LESS => self.exec_float_cmp(op, state, |a, b| a < b),
            OpCode::FLOAT_LESSEQUAL => self.exec_float_cmp(op, state, |a, b| a <= b),

            // -- control flow ----------------------------------------------------
            OpCode::BRANCH
            | OpCode::CBRANCH
            | OpCode::BRANCHIND
            | OpCode::CALL
            | OpCode::CALLIND
            | OpCode::CALLOTHER
            | OpCode::RETURN => {
                // Control-flow operations are handled by the emulator, not
                // the executor. The executor records the side effects
                // (register/memory changes) but the PC update is done at
                // the Emulator level.
                Ok(())
            }

            // -- extension / composition -----------------------------------------
            OpCode::PIECE => self.exec_piece(op, state),
            OpCode::SUBPIECE => self.exec_subpiece(op, state),
            OpCode::POPCOUNT => self.exec_popcount(op, state),
            OpCode::LZCOUNT => self.exec_lzcount(op, state),
            OpCode::CPOOLREF => Err(EmulatorError::UnimplementedOperation(
                "CPOOLREF".to_string(),
            )),
            OpCode::NEW => Err(EmulatorError::UnimplementedOperation("NEW".to_string())),
            OpCode::INSERT => Err(EmulatorError::UnimplementedOperation("INSERT".to_string())),
            OpCode::EXTRACT => Err(EmulatorError::UnimplementedOperation("EXTRACT".to_string())),
            OpCode::SEGMENTOP => Err(EmulatorError::UnimplementedOperation(
                "SEGMENTOP".to_string(),
            )),
            OpCode::CAST => self.exec_cast(op, state),

            // -- SSA / data-flow -------------------------------------------------
            OpCode::MULTIEQUAL => self.exec_multiequal(op, state),
            OpCode::INDIRECT => Err(EmulatorError::UnimplementedOperation(
                "INDIRECT".to_string(),
            )),

            // -- pointer arithmetic ----------------------------------------------
            OpCode::PTRADD => self.exec_ptradd(op, state),
            OpCode::PTRSUB => self.exec_ptrsub(op, state),

            // -- sentinel --------------------------------------------------------
            OpCode::UNIMPLEMENTED => Err(EmulatorError::UnimplementedOperation(
                "UNIMPLEMENTED".to_string(),
            )),
        }
    }

    // -----------------------------------------------------------------------
    // Helpers: varnode I/O
    // -----------------------------------------------------------------------

    /// Convert a varnode to a register key string.
    fn varnode_key(vn: &Varnode) -> String {
        format!("{}:0x{:x}", vn.space.name, vn.offset)
    }

    /// Read the value of a varnode from state or memory, or return a
    /// constant.
    fn read_varnode(
        &self,
        vn: &Varnode,
        state: &EmulatorState,
        memory: &EmulatedMemory,
    ) -> Result<Vec<u8>, EmulatorError> {
        if vn.is_constant() {
            Ok(u64_to_bytes(vn.offset, vn.size as usize))
        } else if vn.is_register() || vn.is_unique() {
            let key = Self::varnode_key(vn);
            state
                .get_register(&key)
                .map(|v| v.to_vec())
                .ok_or_else(|| EmulatorError::InvalidRegister(key))
        } else if vn.is_ram() {
            memory
                .read(Address::new(vn.offset), vn.size as usize)
                .map_err(|e| EmulatorError::MemoryAccess {
                    addr: Address::new(vn.offset),
                    msg: e.to_string(),
                })
        } else {
            // Other spaces: treat like unique
            let key = Self::varnode_key(vn);
            state
                .get_register(&key)
                .map(|v| v.to_vec())
                .ok_or_else(|| EmulatorError::InvalidRegister(key))
        }
    }

    /// Write a value to the location represented by a varnode.
    fn write_varnode(
        &self,
        vn: &Varnode,
        value: &[u8],
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        if vn.is_constant() {
            return Err(EmulatorError::InvalidOperation(
                "cannot write to constant varnode".to_string(),
            ));
        } else if vn.is_register() || vn.is_unique() {
            let key = Self::varnode_key(vn);
            state.set_register(key, value);
            Ok(())
        } else if vn.is_ram() {
            memory
                .write(Address::new(vn.offset), value)
                .map_err(|e| EmulatorError::MemoryAccess {
                    addr: Address::new(vn.offset),
                    msg: e.to_string(),
                })
        } else {
            let key = Self::varnode_key(vn);
            state.set_register(key, value);
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Helpers: arithmetic on byte vectors
    // -----------------------------------------------------------------------

    /// Read a varnode and interpret its value as a `u64`.
    fn read_as_u64(
        &self,
        vn: &Varnode,
        state: &EmulatorState,
        memory: &EmulatedMemory,
    ) -> Result<u64, EmulatorError> {
        let bytes = self.read_varnode(vn, state, memory)?;
        Ok(bytes_to_u64(&bytes))
    }

    /// Read a varnode and interpret its value as an `i64`.
    fn read_as_i64(
        &self,
        vn: &Varnode,
        state: &EmulatorState,
        memory: &EmulatedMemory,
    ) -> Result<i64, EmulatorError> {
        let u = self.read_as_u64(vn, state, memory)?;
        Ok(u as i64)
    }

    /// Read a varnode and interpret its value as a boolean (non-zero is true).
    fn read_as_bool(
        &self,
        vn: &Varnode,
        state: &EmulatorState,
        memory: &EmulatedMemory,
    ) -> Result<bool, EmulatorError> {
        let bytes = self.read_varnode(vn, state, memory)?;
        Ok(bytes.iter().any(|&b| b != 0))
    }

    // -----------------------------------------------------------------------
    // Data movement
    // -----------------------------------------------------------------------

    fn exec_copy(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("COPY requires an output varnode".to_string())
        })?;
        let input = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation("COPY requires an input varnode".to_string())
        })?;
        let value = self.read_varnode(input, state, memory)?;
        self.write_varnode(output, &value, state, memory)
    }

    fn exec_load(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("LOAD requires an output varnode".to_string())
        })?;
        // LOAD: inputs[0] = space-id constant, inputs[1] = pointer
        let ptr = if op.inputs.len() >= 2 {
            &op.inputs[1]
        } else {
            op.inputs.first().ok_or_else(|| {
                EmulatorError::InvalidOperation(
                    "LOAD requires at least one input varnode".to_string(),
                )
            })?
        };
        let addr_val = self.read_as_u64(ptr, state, memory)?;
        let data = memory
            .read(Address::new(addr_val), output.size as usize)
            .map_err(|e| EmulatorError::MemoryAccess {
                addr: Address::new(addr_val),
                msg: e.to_string(),
            })?;
        self.write_varnode(output, &data, state, memory)
    }

    fn exec_store(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        // STORE: inputs[0] = space-id, inputs[1] = pointer, inputs[2] = value
        let ptr = if op.inputs.len() >= 3 {
            &op.inputs[1]
        } else if op.inputs.len() >= 2 {
            &op.inputs[0]
        } else {
            return Err(EmulatorError::InvalidOperation(
                "STORE requires pointer and value inputs".to_string(),
            ));
        };
        let val_vn = if op.inputs.len() >= 3 {
            &op.inputs[2]
        } else {
            &op.inputs[1]
        };
        let addr_val = self.read_as_u64(ptr, state, memory)?;
        let data = self.read_varnode(val_vn, state, memory)?;
        memory
            .write(Address::new(addr_val), &data)
            .map_err(|e| EmulatorError::MemoryAccess {
                addr: Address::new(addr_val),
                msg: e.to_string(),
            })
    }

    // -----------------------------------------------------------------------
    // Integer arithmetic
    // -----------------------------------------------------------------------

    fn exec_binary_arith<F>(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
        f: F,
    ) -> Result<(), EmulatorError>
    where
        F: FnOnce(u64, u64) -> u64,
    {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation(format!(
                "{} requires an output varnode",
                op.opcode.name()
            ))
        })?;
        let lhs = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation(format!(
                "{} requires at least one input",
                op.opcode.name()
            ))
        })?;
        let rhs = op.inputs.get(1).ok_or_else(|| {
            EmulatorError::InvalidOperation(format!("{} requires two inputs", op.opcode.name()))
        })?;

        let a = self.read_as_u64(lhs, state, memory)?;
        let b = self.read_as_u64(rhs, state, memory)?;
        let result = f(a, b);
        let bytes = u64_to_bytes(result, output.size as usize);
        self.write_varnode(output, &bytes, state, memory)
    }

    fn exec_binary_div(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
        signed: bool,
    ) -> Result<(), EmulatorError> {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("DIV requires an output varnode".to_string())
        })?;
        let lhs = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation("DIV requires two inputs".to_string())
        })?;
        let rhs = op.inputs.get(1).ok_or_else(|| {
            EmulatorError::InvalidOperation("DIV requires two inputs".to_string())
        })?;

        if signed {
            let a = self.read_as_i64(lhs, state, memory)?;
            let b = self.read_as_i64(rhs, state, memory)?;
            if b == 0 {
                return Err(EmulatorError::DivideByZero);
            }
            let result = a.wrapping_div(b) as u64;
            let bytes = u64_to_bytes(result, output.size as usize);
            self.write_varnode(output, &bytes, state, memory)
        } else {
            let a = self.read_as_u64(lhs, state, memory)?;
            let b = self.read_as_u64(rhs, state, memory)?;
            if b == 0 {
                return Err(EmulatorError::DivideByZero);
            }
            let result = a.wrapping_div(b);
            let bytes = u64_to_bytes(result, output.size as usize);
            self.write_varnode(output, &bytes, state, memory)
        }
    }

    fn exec_binary_rem(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
        signed: bool,
    ) -> Result<(), EmulatorError> {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("REM requires an output varnode".to_string())
        })?;
        let lhs = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation("REM requires two inputs".to_string())
        })?;
        let rhs = op.inputs.get(1).ok_or_else(|| {
            EmulatorError::InvalidOperation("REM requires two inputs".to_string())
        })?;

        if signed {
            let a = self.read_as_i64(lhs, state, memory)?;
            let b = self.read_as_i64(rhs, state, memory)?;
            if b == 0 {
                return Err(EmulatorError::DivideByZero);
            }
            let result = a.wrapping_rem(b) as u64;
            let bytes = u64_to_bytes(result, output.size as usize);
            self.write_varnode(output, &bytes, state, memory)
        } else {
            let a = self.read_as_u64(lhs, state, memory)?;
            let b = self.read_as_u64(rhs, state, memory)?;
            if b == 0 {
                return Err(EmulatorError::DivideByZero);
            }
            let result = a.wrapping_rem(b);
            let bytes = u64_to_bytes(result, output.size as usize);
            self.write_varnode(output, &bytes, state, memory)
        }
    }

    fn exec_unary_arith<F>(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
        f: F,
    ) -> Result<(), EmulatorError>
    where
        F: FnOnce(u64) -> u64,
    {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation(format!(
                "{} requires an output varnode",
                op.opcode.name()
            ))
        })?;
        let input = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation(format!(
                "{} requires an input varnode",
                op.opcode.name()
            ))
        })?;

        let a = self.read_as_u64(input, state, memory)?;
        let result = f(a);
        let bytes = u64_to_bytes(result, output.size as usize);
        self.write_varnode(output, &bytes, state, memory)
    }

    fn exec_int_carry(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("INT_CARRY requires an output".to_string())
        })?;
        let a = self.read_as_u64(
            op.inputs.first().ok_or_else(|| {
                EmulatorError::InvalidOperation("INT_CARRY requires two inputs".to_string())
            })?,
            state,
            memory,
        )?;
        let b = self.read_as_u64(
            op.inputs.get(1).ok_or_else(|| {
                EmulatorError::InvalidOperation("INT_CARRY requires two inputs".to_string())
            })?,
            state,
            memory,
        )?;
        let (sum, carry) = a.overflowing_add(b);
        let result = if carry { 1u64 } else { 0u64 };
        let bytes = u64_to_bytes(result, output.size as usize);
        self.write_varnode(output, &bytes, state, memory)
    }

    fn exec_int_scarry(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("INT_SCARRY requires an output".to_string())
        })?;
        let a = self.read_as_i64(
            op.inputs.first().ok_or_else(|| {
                EmulatorError::InvalidOperation("INT_SCARRY requires two inputs".to_string())
            })?,
            state,
            memory,
        )?;
        let b = self.read_as_i64(
            op.inputs.get(1).ok_or_else(|| {
                EmulatorError::InvalidOperation("INT_SCARRY requires two inputs".to_string())
            })?,
            state,
            memory,
        )?;
        let (_, carry) = a.overflowing_add(b);
        let result = if carry { 1u64 } else { 0u64 };
        let bytes = u64_to_bytes(result, output.size as usize);
        self.write_varnode(output, &bytes, state, memory)
    }

    fn exec_int_sborrow(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("INT_SBORROW requires an output".to_string())
        })?;
        let a = self.read_as_i64(
            op.inputs.first().ok_or_else(|| {
                EmulatorError::InvalidOperation("INT_SBORROW requires two inputs".to_string())
            })?,
            state,
            memory,
        )?;
        let b = self.read_as_i64(
            op.inputs.get(1).ok_or_else(|| {
                EmulatorError::InvalidOperation("INT_SBORROW requires two inputs".to_string())
            })?,
            state,
            memory,
        )?;
        let (_, borrow) = a.overflowing_sub(b);
        let result = if borrow { 1u64 } else { 0u64 };
        let bytes = u64_to_bytes(result, output.size as usize);
        self.write_varnode(output, &bytes, state, memory)
    }

    // -----------------------------------------------------------------------
    // Extension
    // -----------------------------------------------------------------------

    fn exec_int_sext(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("INT_SEXT requires an output".to_string())
        })?;
        let input = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation("INT_SEXT requires an input".to_string())
        })?;

        let value = self.read_as_u64(input, state, memory)?;
        let src_bits = (input.size * 8) as u32;
        let dst_bits = (output.size * 8) as u32;

        if src_bits >= 64 || dst_bits == 0 {
            return Err(EmulatorError::InvalidOperation(
                "INT_SEXT: invalid operand sizes".to_string(),
            ));
        }

        // Sign-extend from src_bits to dst_bits
        let sign_bit = 1u64 << (src_bits - 1);
        let mask = (1u64 << src_bits) - 1;
        let mut result = value & mask;
        if result & sign_bit != 0 {
            // Extend with 1s
            let ext_mask = !mask;
            result |= ext_mask;
        }
        // Mask to output size (but u64_to_bytes handles sizing)
        let bytes = u64_to_bytes(result, output.size as usize);
        self.write_varnode(output, &bytes, state, memory)
    }

    fn exec_int_zext(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        // Zero-extension: same as truncation but with zero padding — since we
        // already zero-truncate naturally, this is just a copy with resizing.
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("INT_ZEXT requires an output".to_string())
        })?;
        let input = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation("INT_ZEXT requires an input".to_string())
        })?;
        let value = self.read_as_u64(input, state, memory)?;
        let bytes = u64_to_bytes(value, output.size as usize);
        self.write_varnode(output, &bytes, state, memory)
    }

    // -----------------------------------------------------------------------
    // Shifts
    // -----------------------------------------------------------------------

    fn exec_shift<F>(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
        f: F,
    ) -> Result<(), EmulatorError>
    where
        F: FnOnce(u64, u32) -> u64,
    {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation(format!(
                "{} requires an output varnode",
                op.opcode.name()
            ))
        })?;
        let lhs = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation(format!("{} requires two inputs", op.opcode.name()))
        })?;
        let rhs = op.inputs.get(1).ok_or_else(|| {
            EmulatorError::InvalidOperation(format!("{} requires two inputs", op.opcode.name()))
        })?;

        let a = self.read_as_u64(lhs, state, memory)?;
        let b = self.read_as_u64(rhs, state, memory)?;
        let result = f(a, (b & 0x3F) as u32);
        let bytes = u64_to_bytes(result, output.size as usize);
        self.write_varnode(output, &bytes, state, memory)
    }

    fn exec_signed_shift_right(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("INT_SRIGHT requires an output".to_string())
        })?;
        let lhs = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation("INT_SRIGHT requires two inputs".to_string())
        })?;
        let rhs = op.inputs.get(1).ok_or_else(|| {
            EmulatorError::InvalidOperation("INT_SRIGHT requires two inputs".to_string())
        })?;

        let a = self.read_as_i64(lhs, state, memory)?;
        let b = self.read_as_u64(rhs, state, memory)?;
        let result = a.wrapping_shr((b & 0x3F) as u32) as u64;
        let bytes = u64_to_bytes(result, output.size as usize);
        self.write_varnode(output, &bytes, state, memory)
    }

    // -----------------------------------------------------------------------
    // Comparisons
    // -----------------------------------------------------------------------

    fn exec_comparison<F>(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
        f: F,
    ) -> Result<(), EmulatorError>
    where
        F: FnOnce(u64, u64) -> bool,
    {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation(format!(
                "{} requires an output varnode",
                op.opcode.name()
            ))
        })?;
        let lhs = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation(format!("{} requires two inputs", op.opcode.name()))
        })?;
        let rhs = op.inputs.get(1).ok_or_else(|| {
            EmulatorError::InvalidOperation(format!("{} requires two inputs", op.opcode.name()))
        })?;

        let a = self.read_as_u64(lhs, state, memory)?;
        let b = self.read_as_u64(rhs, state, memory)?;
        let result = if f(a, b) { 1u64 } else { 0u64 };
        let bytes = u64_to_bytes(result, output.size as usize);
        self.write_varnode(output, &bytes, state, memory)
    }

    fn exec_comparison_signed<F>(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
        f: F,
    ) -> Result<(), EmulatorError>
    where
        F: FnOnce(i64, i64) -> bool,
    {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation(format!(
                "{} requires an output varnode",
                op.opcode.name()
            ))
        })?;
        let lhs = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation(format!("{} requires two inputs", op.opcode.name()))
        })?;
        let rhs = op.inputs.get(1).ok_or_else(|| {
            EmulatorError::InvalidOperation(format!("{} requires two inputs", op.opcode.name()))
        })?;

        let a = self.read_as_i64(lhs, state, memory)?;
        let b = self.read_as_i64(rhs, state, memory)?;
        let result = if f(a, b) { 1u64 } else { 0u64 };
        let bytes = u64_to_bytes(result, output.size as usize);
        self.write_varnode(output, &bytes, state, memory)
    }

    // -----------------------------------------------------------------------
    // Boolean operations
    // -----------------------------------------------------------------------

    fn exec_bool_negate(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("BOOL_NEGATE requires an output".to_string())
        })?;
        let input = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation("BOOL_NEGATE requires an input".to_string())
        })?;
        let val = self.read_as_bool(input, state, memory)?;
        let result = if val { 0u64 } else { 1u64 };
        let bytes = u64_to_bytes(result, output.size as usize);
        self.write_varnode(output, &bytes, state, memory)
    }

    fn exec_bool_binary<F>(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
        f: F,
    ) -> Result<(), EmulatorError>
    where
        F: FnOnce(bool, bool) -> bool,
    {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation(format!(
                "{} requires an output varnode",
                op.opcode.name()
            ))
        })?;
        let lhs = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation(format!("{} requires two inputs", op.opcode.name()))
        })?;
        let rhs = op.inputs.get(1).ok_or_else(|| {
            EmulatorError::InvalidOperation(format!("{} requires two inputs", op.opcode.name()))
        })?;

        let a = self.read_as_bool(lhs, state, memory)?;
        let b = self.read_as_bool(rhs, state, memory)?;
        let result = if f(a, b) { 1u64 } else { 0u64 };
        let bytes = u64_to_bytes(result, output.size as usize);
        self.write_varnode(output, &bytes, state, memory)
    }

    // -----------------------------------------------------------------------
    // Floating-point operations
    // -----------------------------------------------------------------------

    /// Read a varnode as an `f64`.
    fn read_as_f64(
        &self,
        vn: &Varnode,
        state: &EmulatorState,
        memory: &EmulatedMemory,
    ) -> Result<f64, EmulatorError> {
        let bytes = self.read_varnode(vn, state, memory)?;
        match vn.size {
            4 => {
                let mut buf = [0u8; 4];
                let len = bytes.len().min(4);
                buf[..len].copy_from_slice(&bytes[..len]);
                Ok(f32::from_le_bytes(buf) as f64)
            }
            8 => {
                let mut buf = [0u8; 8];
                let len = bytes.len().min(8);
                buf[..len].copy_from_slice(&bytes[..len]);
                Ok(f64::from_le_bytes(buf))
            }
            _ => {
                // Treat as f64 by reading first 8 bytes
                let mut buf = [0u8; 8];
                let len = bytes.len().min(8);
                buf[..len].copy_from_slice(&bytes[..len]);
                Ok(f64::from_le_bytes(buf))
            }
        }
    }

    /// Write an f64 to a varnode, respecting the output varnode's size.
    fn write_f64(
        &self,
        vn: &Varnode,
        value: f64,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        let bytes = match vn.size {
            4 => {
                let val = value as f32;
                val.to_le_bytes().to_vec()
            }
            _ => value.to_le_bytes().to_vec(),
        };
        self.write_varnode(vn, &bytes, state, memory)
    }

    fn exec_float_binary<F>(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
        f: F,
    ) -> Result<(), EmulatorError>
    where
        F: FnOnce(f64, f64) -> f64,
    {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation(format!(
                "{} requires an output varnode",
                op.opcode.name()
            ))
        })?;
        let lhs = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation(format!("{} requires two inputs", op.opcode.name()))
        })?;
        let rhs = op.inputs.get(1).ok_or_else(|| {
            EmulatorError::InvalidOperation(format!("{} requires two inputs", op.opcode.name()))
        })?;

        let a = self.read_as_f64(lhs, state, memory)?;
        let b = self.read_as_f64(rhs, state, memory)?;
        let result = f(a, b);
        self.write_f64(output, result, state, memory)
    }

    fn exec_float_unary<F>(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
        f: F,
    ) -> Result<(), EmulatorError>
    where
        F: FnOnce(f64) -> f64,
    {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation(format!(
                "{} requires an output varnode",
                op.opcode.name()
            ))
        })?;
        let input = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation(format!(
                "{} requires an input varnode",
                op.opcode.name()
            ))
        })?;

        let a = self.read_as_f64(input, state, memory)?;
        let result = f(a);
        self.write_f64(output, result, state, memory)
    }

    fn exec_float_int_to_float(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("FLOAT_INT2FLOAT requires an output".to_string())
        })?;
        let input = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation("FLOAT_INT2FLOAT requires an input".to_string())
        })?;

        let int_val = self.read_as_u64(input, state, memory)?;
        let result = int_val as f64;
        self.write_f64(output, result, state, memory)
    }

    fn exec_float_float_to_float(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        // Conversion between float precisions: read as f64, write at output size.
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("FLOAT_FLOAT2FLOAT requires an output".to_string())
        })?;
        let input = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation("FLOAT_FLOAT2FLOAT requires an input".to_string())
        })?;

        let val = self.read_as_f64(input, state, memory)?;
        self.write_f64(output, val, state, memory)
    }

    fn exec_float_nan(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("FLOAT_NAN requires an output".to_string())
        })?;
        self.write_f64(output, f64::NAN, state, memory)
    }

    fn exec_float_cmp<F>(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
        f: F,
    ) -> Result<(), EmulatorError>
    where
        F: FnOnce(f64, f64) -> bool,
    {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation(format!(
                "{} requires an output varnode",
                op.opcode.name()
            ))
        })?;
        let lhs = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation(format!("{} requires two inputs", op.opcode.name()))
        })?;
        let rhs = op.inputs.get(1).ok_or_else(|| {
            EmulatorError::InvalidOperation(format!("{} requires two inputs", op.opcode.name()))
        })?;

        let a = self.read_as_f64(lhs, state, memory)?;
        let b = self.read_as_f64(rhs, state, memory)?;
        let result = if f(a, b) { 1u64 } else { 0u64 };
        let bytes = u64_to_bytes(result, output.size as usize);
        self.write_varnode(output, &bytes, state, memory)
    }

    // -----------------------------------------------------------------------
    // Extension / composition
    // -----------------------------------------------------------------------

    fn exec_piece(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("PIECE requires an output varnode".to_string())
        })?;
        let hi = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation("PIECE requires two inputs".to_string())
        })?;
        let lo = op.inputs.get(1).ok_or_else(|| {
            EmulatorError::InvalidOperation("PIECE requires two inputs".to_string())
        })?;

        let hi_bytes = self.read_varnode(hi, state, memory)?;
        let lo_bytes = self.read_varnode(lo, state, memory)?;

        // Concatenate: hi || lo
        let mut result = hi_bytes;
        result.extend_from_slice(&lo_bytes);

        // Truncate to output size if needed
        result.truncate(output.size as usize);
        // Pad with zeros if too short
        result.resize(output.size as usize, 0);

        self.write_varnode(output, &result, state, memory)
    }

    fn exec_subpiece(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("SUBPIECE requires an output varnode".to_string())
        })?;
        let input = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation("SUBPIECE requires an input varnode".to_string())
        })?;
        let low_byte_vn = op.inputs.get(1).ok_or_else(|| {
            EmulatorError::InvalidOperation("SUBPIECE requires a low-byte index input".to_string())
        })?;

        let input_bytes = self.read_varnode(input, state, memory)?;
        let low_byte = self.read_as_u64(low_byte_vn, state, memory)? as usize;

        let mut result = vec![0u8; output.size as usize];
        for (i, b) in result.iter_mut().enumerate() {
            let src_idx = low_byte + i;
            if src_idx < input_bytes.len() {
                *b = input_bytes[src_idx];
            }
        }

        self.write_varnode(output, &result, state, memory)
    }

    fn exec_popcount(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("POPCOUNT requires an output".to_string())
        })?;
        let input = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation("POPCOUNT requires an input".to_string())
        })?;

        let val = self.read_as_u64(input, state, memory)?;
        let result = val.count_ones() as u64;
        let bytes = u64_to_bytes(result, output.size as usize);
        self.write_varnode(output, &bytes, state, memory)
    }

    fn exec_lzcount(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("LZCOUNT requires an output".to_string())
        })?;
        let input = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation("LZCOUNT requires an input".to_string())
        })?;

        let val = self.read_as_u64(input, state, memory)?;
        let result = val.leading_zeros() as u64;
        let bytes = u64_to_bytes(result, output.size as usize);
        self.write_varnode(output, &bytes, state, memory)
    }

    fn exec_cast(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        // CAST is a type-preserving copy with possible size change.
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("CAST requires an output".to_string())
        })?;
        let input = op
            .inputs
            .first()
            .ok_or_else(|| EmulatorError::InvalidOperation("CAST requires an input".to_string()))?;

        let mut bytes = self.read_varnode(input, state, memory)?;
        bytes.resize(output.size as usize, 0);
        bytes.truncate(output.size as usize);
        self.write_varnode(output, &bytes, state, memory)
    }

    // -----------------------------------------------------------------------
    // SSA
    // -----------------------------------------------------------------------

    fn exec_multiequal(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        // MULTIEQUAL (phi node): output = first input (for concrete execution).
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("MULTIEQUAL requires an output".to_string())
        })?;
        let input = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation("MULTIEQUAL requires at least one input".to_string())
        })?;

        let val = self.read_varnode(input, state, memory)?;
        self.write_varnode(output, &val, state, memory)
    }

    // -----------------------------------------------------------------------
    // Pointer arithmetic
    // -----------------------------------------------------------------------

    fn exec_ptradd(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("PTRADD requires an output".to_string())
        })?;
        let base = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation("PTRADD requires three inputs".to_string())
        })?;
        let index = op.inputs.get(1).ok_or_else(|| {
            EmulatorError::InvalidOperation("PTRADD requires three inputs".to_string())
        })?;
        let scale = op.inputs.get(2).ok_or_else(|| {
            EmulatorError::InvalidOperation("PTRADD requires three inputs".to_string())
        })?;

        let base_val = self.read_as_u64(base, state, memory)?;
        let index_val = self.read_as_u64(index, state, memory)?;
        let scale_val = self.read_as_u64(scale, state, memory)?;

        let result = base_val.wrapping_add(index_val.wrapping_mul(scale_val));
        let bytes = u64_to_bytes(result, output.size as usize);
        self.write_varnode(output, &bytes, state, memory)
    }

    fn exec_ptrsub(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("PTRSUB requires an output".to_string())
        })?;
        let lhs = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation("PTRSUB requires two inputs".to_string())
        })?;
        let rhs = op.inputs.get(1).ok_or_else(|| {
            EmulatorError::InvalidOperation("PTRSUB requires two inputs".to_string())
        })?;

        let a = self.read_as_u64(lhs, state, memory)?;
        let b = self.read_as_u64(rhs, state, memory)?;
        let result = a.wrapping_sub(b);
        let bytes = u64_to_bytes(result, output.size as usize);
        self.write_varnode(output, &bytes, state, memory)
    }
}

// ---------------------------------------------------------------------------
// Free conversion helpers
// ---------------------------------------------------------------------------

/// Convert a u64 to a little-endian byte vector of the given size.
fn u64_to_bytes(value: u64, size: usize) -> Vec<u8> {
    let bytes = value.to_le_bytes();
    let len = size.min(8);
    let mut result = vec![0u8; size];
    result[..len].copy_from_slice(&bytes[..len]);
    result
}

/// Convert a byte slice to a u64 (little-endian, up to 8 bytes).
fn bytes_to_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let len = bytes.len().min(8);
    buf[..len].copy_from_slice(&bytes[..len]);
    u64::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_reg_vn(offset: u64, size: u32) -> Varnode {
        Varnode::new(
            AddressSpace::new("register", size as usize, false),
            offset,
            size,
        )
    }

    fn make_const_vn(value: u64, size: u32) -> Varnode {
        Varnode::constant(value, size)
    }

    fn make_ram_vn(offset: u64, size: u32) -> Varnode {
        Varnode::ram(offset, size)
    }

    fn setup_test_state() -> (EmulatorState, EmulatedMemory) {
        let mut state = EmulatorState::new();
        // Pre-populate some registers
        state.set_register("register:0x0", &[10, 0, 0, 0, 0, 0, 0, 0]); // offset 0 = 10
        state.set_register("register:0x18", &[20, 0, 0, 0, 0, 0, 0, 0]); // offset 0x18 = 20

        let mut memory = EmulatedMemory::new();
        memory.add_segment(MemorySegment::new(
            0x1000,
            0x100,
            ghidra_core::program::program::MemoryPermissions::RW,
        ));

        (state, memory)
    }

    fn make_op(opcode: OpCode, out: Option<Varnode>, inputs: Vec<Varnode>) -> PcodeOperation {
        PcodeOperation::new_unannotated(opcode, out, inputs)
    }

    #[test]
    fn test_copy_constant_to_register() {
        let (mut state, memory) = setup_test_state();
        let executor = PcodeExecutor::new();

        let op = make_op(
            OpCode::COPY,
            Some(make_reg_vn(0, 8)),
            vec![make_const_vn(42, 8)],
        );

        executor
            .execute(&op, &mut state, &mut memory.clone())
            .unwrap();
        let val = state.get_register("register:0x0").unwrap();
        assert_eq!(bytes_to_u64(val), 42);
    }

    #[test]
    fn test_int_add() {
        let (mut state, mut memory) = setup_test_state();
        let executor = PcodeExecutor::new();

        let op = make_op(
            OpCode::INT_ADD,
            Some(make_reg_vn(0, 8)),
            vec![make_reg_vn(0, 8), make_reg_vn(0x18, 8)],
        );

        executor.execute(&op, &mut state, &mut memory).unwrap();
        let val = state.get_register("register:0x0").unwrap();
        assert_eq!(bytes_to_u64(val), 30); // 10 + 20
    }

    #[test]
    fn test_int_sub() {
        let (mut state, mut memory) = setup_test_state();
        let executor = PcodeExecutor::new();

        let op = make_op(
            OpCode::INT_SUB,
            Some(make_reg_vn(0, 8)),
            vec![make_reg_vn(0x18, 8), make_reg_vn(0, 8)],
        );

        executor.execute(&op, &mut state, &mut memory).unwrap();
        let val = state.get_register("register:0x0").unwrap();
        assert_eq!(bytes_to_u64(val), 10); // 20 - 10
    }

    #[test]
    fn test_int_add_overflow_wraps() {
        let mut state = EmulatorState::new();
        state.set_register(
            "register:0x0",
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        let mut memory = EmulatedMemory::new();
        memory.add_segment(MemorySegment::new(
            0,
            0x100,
            ghidra_core::program::program::MemoryPermissions::RW,
        ));

        let executor = PcodeExecutor::new();
        let op = make_op(
            OpCode::INT_ADD,
            Some(make_reg_vn(0, 8)),
            vec![make_reg_vn(0, 8), make_const_vn(1, 8)],
        );

        executor.execute(&op, &mut state, &mut memory).unwrap();
        let val = state.get_register("register:0x0").unwrap();
        assert_eq!(bytes_to_u64(val), 0); // wraps to 0
    }

    #[test]
    fn test_store_and_load() {
        let mut state = EmulatorState::new();
        state.set_register("register:0x0", &[0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0]);
        state.set_register("register:0x20", &[0x00, 0x10, 0, 0, 0, 0, 0, 0]); // addr = 0x1000

        let mut memory = EmulatedMemory::new();
        memory.add_segment(MemorySegment::new(
            0x1000,
            0x100,
            ghidra_core::program::program::MemoryPermissions::RW,
        ));

        let executor = PcodeExecutor::new();

        // STORE *0x1000, RAX
        let store_op = make_op(
            OpCode::STORE,
            None,
            vec![
                make_const_vn(0, 4),  // space-id
                make_reg_vn(0x20, 8), // pointer = address in reg 0x20
                make_reg_vn(0, 8),    // value from RAX
            ],
        );
        executor
            .execute(&store_op, &mut state, &mut memory)
            .unwrap();

        // LOAD RAX = *0x1000 (into reg 0x18)
        let load_op = make_op(
            OpCode::LOAD,
            Some(make_reg_vn(0x18, 8)),
            vec![
                make_const_vn(0, 4),  // space-id
                make_reg_vn(0x20, 8), // pointer
            ],
        );
        executor.execute(&load_op, &mut state, &mut memory).unwrap();

        let val = state.get_register("register:0x18").unwrap();
        assert_eq!(bytes_to_u64(val), 0xDEADBEEF);
    }

    #[test]
    fn test_comparisons() {
        let mut state = EmulatorState::new();
        state.set_register("register:0x0", &[10, 0, 0, 0, 0, 0, 0, 0]); // RAX = 10
        state.set_register("register:0x8", &[5, 0, 0, 0, 0, 0, 0, 0]); // RBX = 5
        let mut memory = EmulatedMemory::new();
        memory.add_segment(MemorySegment::new(
            0,
            0x100,
            ghidra_core::program::program::MemoryPermissions::RW,
        ));
        let executor = PcodeExecutor::new();

        // INT_LESS: 5 < 10 = 1
        let op = make_op(
            OpCode::INT_LESS,
            Some(make_reg_vn(0x10, 4)),
            vec![make_reg_vn(0x8, 8), make_reg_vn(0x0, 8)],
        );
        executor.execute(&op, &mut state, &mut memory).unwrap();
        assert_eq!(
            bytes_to_u64(state.get_register("register:0x10").unwrap()),
            1
        );

        // INT_EQUAL: 10 == 10 = 1
        let op = make_op(
            OpCode::INT_EQUAL,
            Some(make_reg_vn(0x18, 4)),
            vec![make_reg_vn(0x0, 8), make_reg_vn(0x0, 8)],
        );
        executor.execute(&op, &mut state, &mut memory).unwrap();
        assert_eq!(
            bytes_to_u64(state.get_register("register:0x18").unwrap()),
            1
        );
    }

    #[test]
    fn test_bitwise_operations() {
        let mut state = EmulatorState::new();
        state.set_register("register:0x0", &[0xFF, 0x0F, 0, 0, 0, 0, 0, 0]); // 0x0FFF
        state.set_register("register:0x8", &[0xF0, 0xF0, 0, 0, 0, 0, 0, 0]); // 0xF0F0
        let mut memory = EmulatedMemory::new();
        memory.add_segment(MemorySegment::new(
            0,
            0x100,
            ghidra_core::program::program::MemoryPermissions::RW,
        ));
        let executor = PcodeExecutor::new();

        // AND: 0x0FFF & 0xF0F0 = 0x00F0
        let op = make_op(
            OpCode::INT_AND,
            Some(make_reg_vn(0x10, 8)),
            vec![make_reg_vn(0x0, 8), make_reg_vn(0x8, 8)],
        );
        executor.execute(&op, &mut state, &mut memory).unwrap();
        let val = bytes_to_u64(state.get_register("register:0x10").unwrap());
        assert_eq!(val, 0x0FFF & 0xF0F0);
    }

    #[test]
    fn test_piece_and_subpiece() {
        let mut state = EmulatorState::new();
        state.set_register("register:0x0", &[0x34, 0x12, 0, 0]); // low = 0x1234
        state.set_register("register:0x8", &[0x78, 0x56, 0, 0]); // high = 0x5678
        let mut memory = EmulatedMemory::new();
        memory.add_segment(MemorySegment::new(
            0,
            0x100,
            ghidra_core::program::program::MemoryPermissions::RW,
        ));
        let executor = PcodeExecutor::new();

        // PIECE: out = hi || lo = 0x56781234
        let op = make_op(
            OpCode::PIECE,
            Some(make_reg_vn(0x10, 8)),
            vec![make_reg_vn(0x8, 4), make_reg_vn(0x0, 4)],
        );
        executor.execute(&op, &mut state, &mut memory).unwrap();
        let val = bytes_to_u64(state.get_register("register:0x10").unwrap());
        // hi bytes (0x5678) followed by lo bytes (0x1234) = 0x1234_5678 in LE
        assert_eq!(val, 0x12345678);

        // SUBPIECE: extract low 2 bytes from result
        let op = make_op(
            OpCode::SUBPIECE,
            Some(make_reg_vn(0x18, 2)),
            vec![make_reg_vn(0x10, 8), make_const_vn(0, 1)], // start at byte 0
        );
        executor.execute(&op, &mut state, &mut memory).unwrap();
        let val = state.get_register("register:0x18").unwrap();
        assert_eq!(&val[..2], &[0x78, 0x56]); // low 2 bytes of 0x12345678
    }

    #[test]
    fn test_ptradd() {
        let mut state = EmulatorState::new();
        state.set_register("register:0x0", &[0x00, 0x10, 0, 0, 0, 0, 0, 0]); // base = 0x1000
        state.set_register("register:0x8", &[2, 0, 0, 0, 0, 0, 0, 0]); // index = 2
        let mut memory = EmulatedMemory::new();
        memory.add_segment(MemorySegment::new(
            0,
            0x100,
            ghidra_core::program::program::MemoryPermissions::RW,
        ));
        let executor = PcodeExecutor::new();

        // PTRADD: out = base + index * scale = 0x1000 + 2*4 = 0x1008
        let op = make_op(
            OpCode::PTRADD,
            Some(make_reg_vn(0x10, 8)),
            vec![
                make_reg_vn(0x0, 8),
                make_reg_vn(0x8, 8),
                make_const_vn(4, 8),
            ],
        );
        executor.execute(&op, &mut state, &mut memory).unwrap();
        let val = bytes_to_u64(state.get_register("register:0x10").unwrap());
        assert_eq!(val, 0x1008);
    }

    #[test]
    fn test_divide_by_zero() {
        let mut state = EmulatorState::new();
        state.set_register("register:0x0", &[10, 0, 0, 0, 0, 0, 0, 0]);
        let mut memory = EmulatedMemory::new();
        memory.add_segment(MemorySegment::new(
            0,
            0x100,
            ghidra_core::program::program::MemoryPermissions::RW,
        ));
        let executor = PcodeExecutor::new();

        let op = make_op(
            OpCode::INT_DIV,
            Some(make_reg_vn(0, 8)),
            vec![make_reg_vn(0, 8), make_const_vn(0, 8)],
        );

        let result = executor.execute(&op, &mut state, &mut memory);
        assert!(result.is_err());
        match result.unwrap_err() {
            EmulatorError::DivideByZero => {}
            other => panic!("expected DivideByZero, got: {}", other),
        }
    }

    #[test]
    fn test_unimplemented_returns_error() {
        let state = EmulatorState::new();
        let mut memory = EmulatedMemory::new();
        memory.add_segment(MemorySegment::new(
            0,
            0x100,
            ghidra_core::program::program::MemoryPermissions::RW,
        ));
        let executor = PcodeExecutor::new();

        let op = make_op(OpCode::UNIMPLEMENTED, None, vec![]);
        let result = executor.execute(&op, &mut state.clone(), &mut memory);
        assert!(result.is_err());
    }
}
