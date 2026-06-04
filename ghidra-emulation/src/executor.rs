//! P-code operation executor.
//!
//! [`PcodeExecutor`] executes individual [`PcodeOperation`]s against the
//! current emulator state and memory. It supports all P-code opcodes
//! including INSERT, EXTRACT, and CALLOTHER.
//!
//! This module also provides:
//! - [`PcodeFrame`] -- tracks the execution position within a P-code
//!   instruction sequence (ported from Ghidra's `PcodeFrame`).
//! - [`UseropLibrary`] -- a registry of user-defined operations for
//!   CALLOTHER (ported from Ghidra's `PcodeUseropLibrary`).
//! - [`MemoryAccessCallback`] -- before/after load/store hooks (ported
//!   from Ghidra's executor extension points).

use ghidra_core::addr::{Address, AddressSpace, AddrSpaceType};
use ghidra_decompile::pcode::{OpCode, PcodeOperation, Varnode};

use crate::memory::EmulatedMemory;
use crate::state::EmulatorState;
use crate::EmulatorError;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// PcodeFrame
// ---------------------------------------------------------------------------

/// Tracks the execution position within a sequence of P-code operations.
///
/// Ported from Ghidra's `PcodeFrame`. A frame holds a list of P-code
/// operations for a single machine instruction and tracks which operation
/// is next to execute.
#[derive(Debug, Clone)]
pub struct PcodeFrame {
    /// The machine instruction address this frame belongs to.
    pub instruction_address: Address,
    /// The list of P-code operations to execute.
    pub ops: Vec<PcodeOperation>,
    /// Index of the next operation to execute.
    pub pc: usize,
    /// Whether execution is complete.
    pub finished: bool,
    /// Userop number-to-name mapping.
    pub userop_names: HashMap<u32, String>,
}

impl PcodeFrame {
    /// Create a new frame for the given instruction address.
    pub fn new(instruction_address: Address, ops: Vec<PcodeOperation>) -> Self {
        Self {
            instruction_address,
            ops,
            pc: 0,
            finished: false,
            userop_names: HashMap::new(),
        }
    }

    /// Create a frame with userop name mapping.
    pub fn with_userop_names(
        instruction_address: Address,
        ops: Vec<PcodeOperation>,
        userop_names: HashMap<u32, String>,
    ) -> Self {
        Self {
            instruction_address,
            ops,
            pc: 0,
            finished: false,
            userop_names,
        }
    }

    /// Get the next operation to execute, advancing the frame position.
    ///
    /// Returns `None` if the frame is finished.
    pub fn next_op(&mut self) -> Option<&PcodeOperation> {
        if self.finished || self.pc >= self.ops.len() {
            self.finished = true;
            return None;
        }
        let op = &self.ops[self.pc];
        self.pc += 1;
        if self.pc >= self.ops.len() {
            self.finished = true;
        }
        Some(op)
    }

    /// Get the next operation without advancing.
    pub fn peek(&self) -> Option<&PcodeOperation> {
        self.ops.get(self.pc)
    }

    /// Skip the next operation (advance without executing).
    pub fn skip(&mut self) {
        if self.pc < self.ops.len() {
            self.pc += 1;
        }
        if self.pc >= self.ops.len() {
            self.finished = true;
        }
    }

    /// Returns true if all operations have been executed.
    pub fn is_finished(&self) -> bool {
        self.finished || self.pc >= self.ops.len()
    }

    /// Reset the frame to the beginning.
    pub fn reset(&mut self) {
        self.pc = 0;
        self.finished = false;
    }

    /// Return the number of remaining operations.
    pub fn remaining(&self) -> usize {
        if self.finished {
            0
        } else {
            self.ops.len().saturating_sub(self.pc)
        }
    }
}

// ---------------------------------------------------------------------------
// UseropLibrary
// ---------------------------------------------------------------------------

/// A library of user-defined P-code operations (CALLOTHER targets).
///
/// Ported from Ghidra's `PcodeUseropLibrary`. When the executor
/// encounters a CALLOTHER operation, it looks up the userop by its
/// numeric ID and invokes the handler.
pub struct UseropLibrary {
    /// Map of userop number -> name.
    pub names: HashMap<u32, String>,
    /// Map of userop name -> handler function.
    handlers: HashMap<String, Box<dyn UseropHandler>>,
}

/// A handler for a single user-defined operation.
pub trait UseropHandler: std::fmt::Debug {
    /// Execute the userop.
    ///
    /// `inputs` are the input varnode values (as raw byte vectors).
    /// Returns the output value (as a raw byte vector), or `None` if
    /// the userop has no output.
    fn execute(
        &self,
        inputs: &[Vec<u8>],
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<Option<Vec<u8>>, EmulatorError>;
}

impl std::fmt::Debug for UseropLibrary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UseropLibrary")
            .field("names", &self.names)
            .finish()
    }
}

impl Clone for UseropLibrary {
    fn clone(&self) -> Self {
        Self {
            names: self.names.clone(),
            handlers: HashMap::new(), // Cannot clone trait objects
        }
    }
}

impl UseropLibrary {
    /// Create an empty userop library.
    pub fn new() -> Self {
        Self {
            names: HashMap::new(),
            handlers: HashMap::new(),
        }
    }

    /// Register a userop handler with a numeric ID and name.
    pub fn register(
        &mut self,
        id: u32,
        name: impl Into<String>,
        handler: Box<dyn UseropHandler>,
    ) {
        let n = name.into();
        self.names.insert(id, n.clone());
        self.handlers.insert(n, handler);
    }

    /// Look up and execute a userop by its numeric ID.
    pub fn execute(
        &self,
        id: u32,
        inputs: &[Vec<u8>],
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<Option<Vec<u8>>, EmulatorError> {
        let name = self.names.get(&id).ok_or_else(|| {
            EmulatorError::UnimplementedOperation(format!("CALLOTHER userop #{}", id))
        })?;
        let handler = self.handlers.get(name).ok_or_else(|| {
            EmulatorError::UnimplementedOperation(format!("CALLOTHER handler not found: {}", name))
        })?;
        handler.execute(inputs, state, memory)
    }

    /// Returns true if a userop is registered with the given ID.
    pub fn has_userop(&self, id: u32) -> bool {
        self.names.contains_key(&id)
    }

    /// Return the name of a userop by its numeric ID.
    pub fn name_of(&self, id: u32) -> Option<&str> {
        self.names.get(&id).map(|s| s.as_str())
    }
}

// ---------------------------------------------------------------------------
// MemoryAccessCallback
// ---------------------------------------------------------------------------

/// Callback hooks for memory load/store operations.
///
/// Ported from Ghidra's executor extension points (beforeLoad/afterLoad,
/// beforeStore/afterStore).
pub trait MemoryAccessCallback: std::fmt::Debug {
    /// Called before a LOAD operation.
    fn before_load(&mut self, _addr: u64, _size: u32) -> Result<(), EmulatorError> {
        Ok(())
    }

    /// Called after a LOAD operation.
    fn after_load(&mut self, _addr: u64, _size: u32, _value: &[u8]) -> Result<(), EmulatorError> {
        Ok(())
    }

    /// Called before a STORE operation.
    fn before_store(
        &mut self,
        _addr: u64,
        _size: u32,
        _value: &[u8],
    ) -> Result<(), EmulatorError> {
        Ok(())
    }

    /// Called after a STORE operation.
    fn after_store(
        &mut self,
        _addr: u64,
        _size: u32,
        _value: &[u8],
    ) -> Result<(), EmulatorError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PcodeExecutor
// ---------------------------------------------------------------------------

/// Executes P-code operations, updating register and memory state.
///
/// Supports an optional [`UseropLibrary`] for CALLOTHER operations and
/// an optional [`MemoryAccessCallback`] for before/after load/store hooks.
#[derive(Debug, Clone)]
pub struct PcodeExecutor {
    /// Library of user-defined operations (CALLOTHER targets).
    pub userop_library: UseropLibrary,
    /// Current instruction address (for CALLOTHER metadata).
    current_instr_addr: u64,
}

impl Default for PcodeExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl PcodeExecutor {
    /// Create a new executor.
    pub fn new() -> Self {
        Self {
            userop_library: UseropLibrary::new(),
            current_instr_addr: 0,
        }
    }

    /// Create an executor with a userop library.
    pub fn with_library(userop_library: UseropLibrary) -> Self {
        Self {
            userop_library,
            current_instr_addr: 0,
        }
    }

    /// Set the current instruction address (for context in hooks).
    pub fn set_instruction_address(&mut self, addr: u64) {
        self.current_instr_addr = addr;
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
            OpCode::INT_ADD => self.exec_binary_arith(op, state, memory, |a, b| a.wrapping_add(b)),
            OpCode::INT_SUB => self.exec_binary_arith(op, state, memory, |a, b| a.wrapping_sub(b)),
            OpCode::INT_MUL => self.exec_binary_arith(op, state, memory, |a, b| a.wrapping_mul(b)),
            OpCode::INT_DIV => self.exec_binary_div(op, state, memory, false),
            OpCode::INT_SDIV => self.exec_binary_div(op, state, memory, true),
            OpCode::INT_REM => self.exec_binary_rem(op, state, memory, false),
            OpCode::INT_SREM => self.exec_binary_rem(op, state, memory, true),
            OpCode::INT_NEGATE => self.exec_unary_arith(op, state, memory, |a| (!a).wrapping_add(1)),
            OpCode::INT_CARRY => self.exec_int_carry(op, state, memory),
            OpCode::INT_SCARRY => self.exec_int_scarry(op, state, memory),
            OpCode::INT_SBORROW => self.exec_int_sborrow(op, state, memory),

            // -- extension -------------------------------------------------------
            OpCode::INT_SEXT => self.exec_int_sext(op, state, memory),
            OpCode::INT_ZEXT => self.exec_int_zext(op, state, memory),

            // -- integer bitwise / shifts ----------------------------------------
            OpCode::INT_AND => self.exec_binary_arith(op, state, memory, |a, b| a & b),
            OpCode::INT_OR => self.exec_binary_arith(op, state, memory, |a, b| a | b),
            OpCode::INT_XOR => self.exec_binary_arith(op, state, memory, |a, b| a ^ b),
            OpCode::INT_LEFT => self.exec_shift(op, state, memory, |a, b| a.wrapping_shl(b)),
            OpCode::INT_RIGHT => self.exec_shift(op, state, memory, |a, b| a.wrapping_shr(b)),
            OpCode::INT_SRIGHT => self.exec_signed_shift_right(op, state, memory),

            // -- integer comparisons ---------------------------------------------
            OpCode::INT_EQUAL => self.exec_comparison(op, state, memory, |a, b| a == b),
            OpCode::INT_NOTEQUAL => self.exec_comparison(op, state, memory, |a, b| a != b),
            OpCode::INT_SLESS => self.exec_comparison_signed(op, state, memory, |a, b| a < b),
            OpCode::INT_SLESSEQUAL => self.exec_comparison_signed(op, state, memory, |a, b| a <= b),
            OpCode::INT_LESS => self.exec_comparison(op, state, memory, |a, b| a < b),
            OpCode::INT_LESSEQUAL => self.exec_comparison(op, state, memory, |a, b| a <= b),

            // -- boolean operations ----------------------------------------------
            OpCode::BOOL_NEGATE => self.exec_bool_negate(op, state, memory),
            OpCode::BOOL_AND => self.exec_bool_binary(op, state, memory, |a, b| a && b),
            OpCode::BOOL_OR => self.exec_bool_binary(op, state, memory, |a, b| a || b),
            OpCode::BOOL_XOR => self.exec_bool_binary(op, state, memory, |a, b| a ^ b),

            // -- floating-point arithmetic ---------------------------------------
            OpCode::FLOAT_ADD => self.exec_float_binary(op, state, memory, |a, b| a + b),
            OpCode::FLOAT_SUB => self.exec_float_binary(op, state, memory, |a, b| a - b),
            OpCode::FLOAT_MUL => self.exec_float_binary(op, state, memory, |a, b| a * b),
            OpCode::FLOAT_DIV => self.exec_float_binary(op, state, memory, |a, b| a / b),
            OpCode::FLOAT_NEG => self.exec_float_unary(op, state, memory, |a| -a),
            OpCode::FLOAT_ABS => self.exec_float_unary(op, state, memory, |a| a.abs()),
            OpCode::FLOAT_SQRT => self.exec_float_unary(op, state, memory, |a| a.sqrt()),
            OpCode::FLOAT_INT2FLOAT => self.exec_float_int_to_float(op, state, memory),
            OpCode::FLOAT_FLOAT2INT => self.exec_float_float_to_float(op, state, memory),
            OpCode::FLOAT_TRUNC => self.exec_float_unary(op, state, memory, |a| a.trunc()),
            OpCode::FLOAT_CEIL => self.exec_float_unary(op, state, memory, |a| a.ceil()),
            OpCode::FLOAT_FLOOR => self.exec_float_unary(op, state, memory, |a| a.floor()),
            OpCode::FLOAT_ROUND => self.exec_float_unary(op, state, memory, |a| a.round()),
            OpCode::FLOAT_NAN => self.exec_float_nan(op, state, memory),

            // -- floating-point comparisons --------------------------------------
            OpCode::FLOAT_EQUAL => self.exec_float_cmp(op, state, memory, |a, b| a == b),
            OpCode::FLOAT_NOTEQUAL => self.exec_float_cmp(op, state, memory, |a, b| a != b),
            OpCode::FLOAT_LESS => self.exec_float_cmp(op, state, memory, |a, b| a < b),
            OpCode::FLOAT_LESSEQUAL => self.exec_float_cmp(op, state, memory, |a, b| a <= b),

            // -- control flow ----------------------------------------------------
            OpCode::BRANCH
            | OpCode::CBRANCH
            | OpCode::BRANCHIND
            | OpCode::CALL
            | OpCode::CALLIND
            | OpCode::RETURN => {
                // Control-flow operations are handled by the emulator, not
                // the executor.
                Ok(())
            }

            // -- CALLOTHER (user-defined) ----------------------------------------
            OpCode::CALLOTHER => self.exec_callother(op, state, memory),

            // -- extension / composition -----------------------------------------
            OpCode::PIECE => self.exec_piece(op, state, memory),
            OpCode::SUBPIECE => self.exec_subpiece(op, state, memory),
            OpCode::POPCOUNT => self.exec_popcount(op, state, memory),
            OpCode::LZCOUNT => self.exec_lzcount(op, state, memory),
            OpCode::INSERT => self.exec_insert(op, state, memory),
            OpCode::EXTRACT => self.exec_extract(op, state, memory),
            OpCode::CPOOLREF => Err(EmulatorError::UnimplementedOperation(
                "CPOOLREF".to_string(),
            )),
            OpCode::NEW => Err(EmulatorError::UnimplementedOperation("NEW".to_string())),
            OpCode::SEGMENTOP => Err(EmulatorError::UnimplementedOperation(
                "SEGMENTOP".to_string(),
            )),
            OpCode::CAST => self.exec_cast(op, state, memory),

            // -- SSA / data-flow -------------------------------------------------
            OpCode::MULTIEQUAL => self.exec_multiequal(op, state, memory),
            OpCode::INDIRECT => self.exec_indirect(op, state, memory),

            // -- pointer arithmetic ----------------------------------------------
            OpCode::PTRADD => self.exec_ptradd(op, state, memory),
            OpCode::PTRSUB => self.exec_ptrsub(op, state, memory),

            // -- sentinel --------------------------------------------------------
            OpCode::UNIMPLEMENTED => Err(EmulatorError::UnimplementedOperation(
                "UNIMPLEMENTED".to_string(),
            )),
        }
    }

    /// Execute all operations in a [`PcodeFrame`].
    ///
    /// Returns the frame (potentially advanced) and whether execution
    /// completed without error.
    pub fn execute_frame(
        &self,
        frame: &mut PcodeFrame,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        while let Some(op) = frame.next_op() {
            self.execute(op, state, memory)?;
        }
        Ok(())
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
        let (_sum, carry) = a.overflowing_add(b);
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
        let bytes = u64_to_bytes(result, output.size as usize);
        self.write_varnode(output, &bytes, state, memory)
    }

    fn exec_int_zext(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
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
    // CALLOTHER (user-defined operations)
    // -----------------------------------------------------------------------

    /// Execute a CALLOTHER operation using the userop library.
    fn exec_callother(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        // The first input is the userop number (constant)
        let userop_id = op
            .inputs
            .first()
            .ok_or_else(|| {
                EmulatorError::InvalidOperation("CALLOTHER requires a userop ID".to_string())
            })?
            .offset as u32;

        // Read remaining inputs
        let input_values: Vec<Vec<u8>> = op.inputs[1..]
            .iter()
            .map(|vn| self.read_varnode(vn, state, memory))
            .collect::<Result<Vec<_>, _>>()?;

        // Execute via library
        let result = self
            .userop_library
            .execute(userop_id, &input_values, state, memory)?;

        // Write output if any
        if let Some(output_vn) = &op.output {
            if let Some(val) = result {
                self.write_varnode(output_vn, &val, state, memory)?;
            }
        }

        Ok(())
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

    /// Execute INSERT: insert bits from `in1` into `in0` at a given position.
    ///
    /// `INSERT out, in0, in1, position, size`
    /// - `in0`: the destination value
    /// - `in1`: the source value to insert
    /// - `inputs[2]` (constant): bit position
    /// - `inputs[3]` (constant): bit size of the insert field
    fn exec_insert(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("INSERT requires an output".to_string())
        })?;
        let dest_vn = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation("INSERT requires 4 inputs".to_string())
        })?;
        let src_vn = op.inputs.get(1).ok_or_else(|| {
            EmulatorError::InvalidOperation("INSERT requires 4 inputs".to_string())
        })?;
        let pos_vn = op.inputs.get(2).ok_or_else(|| {
            EmulatorError::InvalidOperation("INSERT requires 4 inputs".to_string())
        })?;
        let size_vn = op.inputs.get(3).ok_or_else(|| {
            EmulatorError::InvalidOperation("INSERT requires 4 inputs".to_string())
        })?;

        let dest = self.read_as_u64(dest_vn, state, memory)?;
        let src = self.read_as_u64(src_vn, state, memory)?;
        let pos = self.read_as_u64(pos_vn, state, memory)? as u32;
        let bits = self.read_as_u64(size_vn, state, memory)? as u32;

        if bits == 0 || bits > 64 || pos >= 64 {
            return Err(EmulatorError::InvalidOperation(format!(
                "INSERT: invalid pos={}, bits={}",
                pos, bits
            )));
        }

        // Create a mask for the bit field and clear those bits in dest,
        // then set them from src.
        let field_mask = if bits >= 64 {
            u64::MAX
        } else {
            ((1u64 << bits) - 1) << pos
        };
        let cleared = dest & !field_mask;
        let inserted = cleared | ((src & ((1u64 << bits) - 1)) << pos);
        let bytes = u64_to_bytes(inserted, output.size as usize);
        self.write_varnode(output, &bytes, state, memory)
    }

    /// Execute EXTRACT: extract bits from `in0` at a given position.
    ///
    /// `EXTRACT out, in0, position, size`
    /// - `in0`: the source value
    /// - `inputs[1]` (constant): bit position
    /// - `inputs[2]` (constant): bit size of the field to extract
    fn exec_extract(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("EXTRACT requires an output".to_string())
        })?;
        let src_vn = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation("EXTRACT requires 3 inputs".to_string())
        })?;
        let pos_vn = op.inputs.get(1).ok_or_else(|| {
            EmulatorError::InvalidOperation("EXTRACT requires 3 inputs".to_string())
        })?;
        let size_vn = op.inputs.get(2).ok_or_else(|| {
            EmulatorError::InvalidOperation("EXTRACT requires 3 inputs".to_string())
        })?;

        let src = self.read_as_u64(src_vn, state, memory)?;
        let pos = self.read_as_u64(pos_vn, state, memory)? as u32;
        let bits = self.read_as_u64(size_vn, state, memory)? as u32;

        if bits == 0 || bits > 64 || pos >= 64 {
            return Err(EmulatorError::InvalidOperation(format!(
                "EXTRACT: invalid pos={}, bits={}",
                pos, bits
            )));
        }

        let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
        let result = (src >> pos) & mask;
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

    /// INDIRECT: output = input (passthrough for concrete execution).
    fn exec_indirect(
        &self,
        op: &PcodeOperation,
        state: &mut EmulatorState,
        memory: &mut EmulatedMemory,
    ) -> Result<(), EmulatorError> {
        let output = op.output.as_ref().ok_or_else(|| {
            EmulatorError::InvalidOperation("INDIRECT requires an output".to_string())
        })?;
        let input = op.inputs.first().ok_or_else(|| {
            EmulatorError::InvalidOperation("INDIRECT requires an input".to_string())
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
    use crate::MemorySegment;

    fn make_reg_vn(offset: u64, size: u32) -> Varnode {
        Varnode::new(
            AddressSpace::new("register", size as usize, false, AddrSpaceType::Register, 2),
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
        state.set_register("register:0x0", &[10, 0, 0, 0, 0, 0, 0, 0]);
        state.set_register("register:0x18", &[20, 0, 0, 0, 0, 0, 0, 0]);

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
        let (mut state, mut memory) = setup_test_state();
        let executor = PcodeExecutor::new();

        let op = make_op(
            OpCode::COPY,
            Some(make_reg_vn(0, 8)),
            vec![make_const_vn(42, 8)],
        );

        executor.execute(&op, &mut state, &mut memory).unwrap();
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
        assert_eq!(bytes_to_u64(val), 30);
    }

    #[test]
    fn test_insert() {
        let (mut state, mut memory) = setup_test_state();
        let executor = PcodeExecutor::new();

        // register:0x0 = 0xFF (value to insert into)
        state.set_register("register:0x0", &[0xFF, 0, 0, 0, 0, 0, 0, 0]);
        // register:0x18 = 0xAB (value to insert)
        state.set_register("register:0x18", &[0xAB, 0, 0, 0, 0, 0, 0, 0]);

        // INSERT: out = (in0 & ~(mask << pos)) | ((in1 & mask) << pos)
        // pos=4, bits=8 -> insert 0xAB at bit position 4 of 0xFF
        let op = make_op(
            OpCode::INSERT,
            Some(make_reg_vn(0x20, 8)),
            vec![
                make_reg_vn(0, 8),      // dest = 0xFF
                make_reg_vn(0x18, 8),   // src = 0xAB
                make_const_vn(4, 8),    // position = 4
                make_const_vn(8, 8),    // size = 8 bits
            ],
        );
        executor.execute(&op, &mut state, &mut memory).unwrap();
        let val = bytes_to_u64(state.get_register("register:0x20").unwrap());
        // 0xFF = 0b11111111, clear bits [4..12) -> 0b00001111 = 0x0F
        // insert 0xAB = 0b10101011 at position 4 -> 0b10101011_1111 = 0xABF
        assert_eq!(val & 0xFFF, 0xABF);
    }

    #[test]
    fn test_extract() {
        let (mut state, mut memory) = setup_test_state();
        let executor = PcodeExecutor::new();

        // register:0x0 = 0xDEADBEEF
        state.set_register(
            "register:0x0",
            &[0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0],
        );

        // EXTRACT: out = (in0 >> pos) & mask
        // Extract 8 bits at position 8 -> gets bits [8..16) of 0xDEADBEEF
        let op = make_op(
            OpCode::EXTRACT,
            Some(make_reg_vn(0x18, 8)),
            vec![
                make_reg_vn(0, 8),      // src
                make_const_vn(8, 8),    // position = 8
                make_const_vn(8, 8),    // size = 8 bits
            ],
        );
        executor.execute(&op, &mut state, &mut memory).unwrap();
        let val = bytes_to_u64(state.get_register("register:0x18").unwrap());
        assert_eq!(val, 0xBE); // bits [8..16) of 0xEFBE
    }

    #[test]
    fn test_indirect_passthrough() {
        let (mut state, mut memory) = setup_test_state();
        let executor = PcodeExecutor::new();

        state.set_register("register:0x0", &[42, 0, 0, 0, 0, 0, 0, 0]);

        let op = make_op(
            OpCode::INDIRECT,
            Some(make_reg_vn(0x18, 8)),
            vec![make_reg_vn(0, 8)],
        );
        executor.execute(&op, &mut state, &mut memory).unwrap();
        let val = state.get_register("register:0x18").unwrap();
        assert_eq!(bytes_to_u64(val), 42);
    }

    #[test]
    fn test_pcode_frame() {
        let ops = vec![
            make_op(
                OpCode::COPY,
                Some(make_reg_vn(0, 8)),
                vec![make_const_vn(10, 8)],
            ),
            make_op(
                OpCode::INT_ADD,
                Some(make_reg_vn(0, 8)),
                vec![make_reg_vn(0, 8), make_const_vn(5, 8)],
            ),
        ];

        let mut frame = PcodeFrame::new(Address::new(0x1000), ops);
        assert_eq!(frame.remaining(), 2);
        assert!(!frame.is_finished());

        let op = frame.next_op().unwrap();
        assert_eq!(op.opcode, OpCode::COPY);
        assert_eq!(frame.remaining(), 1);

        let op = frame.next_op().unwrap();
        assert_eq!(op.opcode, OpCode::INT_ADD);
        assert!(frame.is_finished());
        assert!(frame.next_op().is_none());
    }

    #[test]
    fn test_execute_frame() {
        let (mut state, mut memory) = setup_test_state();
        let executor = PcodeExecutor::new();

        let ops = vec![
            make_op(
                OpCode::COPY,
                Some(make_reg_vn(0, 8)),
                vec![make_const_vn(100, 8)],
            ),
            make_op(
                OpCode::INT_ADD,
                Some(make_reg_vn(0, 8)),
                vec![make_reg_vn(0, 8), make_const_vn(50, 8)],
            ),
        ];

        let mut frame = PcodeFrame::new(Address::new(0x1000), ops);
        executor.execute_frame(&mut frame, &mut state, &mut memory).unwrap();

        let val = state.get_register("register:0x0").unwrap();
        assert_eq!(bytes_to_u64(val), 150);
        assert!(frame.is_finished());
    }
}
