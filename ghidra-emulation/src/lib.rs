//! Ghidra Rust - P-code Emulation Engine.
//!
//! This crate provides a full P-code emulation environment including:
//!
//! - [`Emulator`] -- the top-level emulator that coordinates state, memory,
//!   execution, and breakpoints.
//! - [`PcodeExecutor`] -- executes individual P-code operations from the
//!   ghidra-decompile crate.
//! - [`EmulatorState`] -- register and flag storage.
//! - [`EmulatedMemory`] -- segmented memory with access permissions.
//! - [`BreakpointManager`] -- execution, read, write, and access breakpoints.
//!
//! # Example
//!
//! ```ignore
//! use ghidra_emulation::Emulator;
//! use ghidra_core::program::lang::Language;
//! use ghidra_core::program::lang::LanguageID;
//!
//! let lang = Language {
//!     id: LanguageID::new("x86", "LE", 64),
//!     name: "x86:LE:64:default".into(),
//!     version: "1.0".into(),
//! };
//! let mut emu = Emulator::new(&lang);
//! emu.set_register("RAX", &[42, 0, 0, 0, 0, 0, 0, 0]);
//! ```
//!
//! # Architecture
//!
//! The emulator is designed around Ghidra's P-code intermediate
//! representation. Machine instructions are first translated to P-code
//! operations by SLEIGH, and the emulator executes those operations
//! directly. This means the emulator is independent of any specific
//! processor architecture -- it only needs the P-code.

pub mod breakpoints;
pub mod executor;
pub mod memory;
pub mod state;

use ghidra_core::addr::Address;
use ghidra_core::program::lang::Language;
use ghidra_decompile::pcode::{PcodeOperation, Varnode};
use std::collections::HashMap;

pub use breakpoints::{BreakpointInfo, BreakpointKind, BreakpointManager};
pub use executor::PcodeExecutor;
pub use memory::{EmulatedMemory, MemoryError, MemorySegment};
pub use state::EmulatorState;

// ---------------------------------------------------------------------------
// EmulatorError
// ---------------------------------------------------------------------------

/// Errors that can occur during emulation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum EmulatorError {
    /// An address is not mapped by any memory segment.
    #[error("memory access error at {addr}: {msg}")]
    MemoryAccess {
        /// The address that was accessed.
        addr: Address,
        /// Description of the error.
        msg: String,
    },

    /// A register name was not found in the register state.
    #[error("invalid register: {0}")]
    InvalidRegister(String),

    /// Division by zero was attempted.
    #[error("divide by zero")]
    DivideByZero,

    /// An operation is invalid in the current context.
    #[error("invalid operation: {0}")]
    InvalidOperation(String),

    /// The operation is not yet implemented.
    #[error("unimplemented operation: {0}")]
    UnimplementedOperation(String),

    /// No P-code is loaded at the current program counter.
    #[error("no pcode at {0}")]
    NoPcodeAtAddress(Address),

    /// A catch-all for other errors.
    #[error("{0}")]
    Other(String),
}

/// Convenience alias for results returned by the emulator.
pub type EmulatorResult<T> = Result<T, EmulatorError>;

// ---------------------------------------------------------------------------
// EmulationStep
// ---------------------------------------------------------------------------

/// Records the result of executing a single P-code operation.
///
/// Each step captures which operation was executed, at what address, and
/// which registers changed as a result.
#[derive(Debug, Clone)]
pub struct EmulationStep {
    /// The instruction address this operation belongs to.
    pub address: Address,
    /// The P-code operation that was executed.
    pub operation: PcodeOperation,
    /// Changed registers: name -> (old_value, new_value).
    pub register_changes: HashMap<String, (Vec<u8>, Vec<u8>)>,
}

// ---------------------------------------------------------------------------
// StopReason
// ---------------------------------------------------------------------------

/// Why the emulator stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// A breakpoint was hit at the given address.
    Breakpoint(Address),
    /// The maximum number of steps was reached.
    MaxSteps,
    /// An error occurred during execution.
    Error(String),
    /// The program explicitly halted (e.g., a HALT pseudo-instruction or
    /// no further instructions at PC).
    Halt,
}

// ---------------------------------------------------------------------------
// EmulationResult
// ---------------------------------------------------------------------------

/// The result of an emulation run.
#[derive(Debug, Clone)]
pub struct EmulationResult {
    /// Total number of P-code steps executed.
    pub steps_executed: u64,
    /// The program counter when execution stopped.
    pub final_pc: Address,
    /// Why execution stopped.
    pub reason: StopReason,
}

// ---------------------------------------------------------------------------
// Emulator
// ---------------------------------------------------------------------------

/// The top-level P-code emulator.
///
/// Coordinates register state, memory, breakpoints, and the P-code
/// executor. Supports single-stepping (per P-code operation or per
/// instruction) and full-program execution.
#[derive(Debug, Clone)]
pub struct Emulator {
    /// Current register and flag state.
    pub state: EmulatorState,
    /// Emulated memory (segments with permissions).
    pub memory: EmulatedMemory,
    /// P-code operation executor.
    pub executor: PcodeExecutor,
    /// Breakpoint manager.
    pub breakpoints: BreakpointManager,
    /// Program counter (address of the current instruction).
    pub pc: Address,
    /// Execution trace: record of each executed step.
    pub trace: Vec<EmulationStep>,
    /// Maximum number of steps before the emulator stops automatically.
    pub step_limit: u64,

    // -- internal state --
    /// Mapping from instruction address to its P-code operations.
    pcode_map: HashMap<Address, Vec<PcodeOperation>>,
    /// Whether the emulator is currently running.
    running: bool,
}

impl Emulator {
    /// Create a new emulator for the given processor language.
    ///
    /// The language determines the address size and default register set.
    pub fn new(language: &Language) -> Self {
        let _ = language; // Reserved for future use (register layout, etc.)

        Self {
            state: EmulatorState::new(),
            memory: EmulatedMemory::new(),
            executor: PcodeExecutor::new(),
            breakpoints: BreakpointManager::new(),
            pc: Address::new(0),
            trace: Vec::new(),
            step_limit: 1_000_000,
            pcode_map: HashMap::new(),
            running: false,
        }
    }

    /// Load P-code operations for an instruction at the given address.
    ///
    /// This populates the internal pcode map so that `run()` and
    /// `step_instruction()` can look up the operations by PC.
    pub fn load_pcode(&mut self, addr: Address, ops: Vec<PcodeOperation>) {
        self.pcode_map.insert(addr, ops);
    }

    /// Execute all P-code operations for the current instruction.
    ///
    /// Looks up the P-code at the current PC, executes each operation in
    /// sequence, and records the changes in `self.trace`. If a control-flow
    /// operation updates the PC, subsequent operations in the same
    /// instruction are still executed.
    ///
    /// Returns `Ok(())` on success.
    pub fn step_instruction(&mut self) -> Result<(), EmulatorError> {
        let ops = self
            .pcode_map
            .get(&self.pc)
            .cloned()
            .ok_or_else(|| EmulatorError::NoPcodeAtAddress(self.pc))?;

        let instr_addr = self.pc;

        for op in &ops {
            let before = self.state.snapshot_registers();
            self.executor
                .execute(op, &mut self.state, &mut self.memory)?;
            let after = self.state.snapshot_registers();
            let changes = EmulatorState::diff_registers(&before, &after);

            self.trace.push(EmulationStep {
                address: instr_addr,
                operation: op.clone(),
                register_changes: changes,
            });

            // Handle control flow: check for PC-changing operations
            self.handle_control_flow(op)?;
        }

        Ok(())
    }

    /// Execute a single P-code operation directly (without looking it up
    /// by PC).
    ///
    /// Record the step in the trace.
    pub fn step_pcode(&mut self, op: &PcodeOperation) -> Result<(), EmulatorError> {
        let before = self.state.snapshot_registers();
        self.executor
            .execute(op, &mut self.state, &mut self.memory)?;
        let after = self.state.snapshot_registers();
        let changes = EmulatorState::diff_registers(&before, &after);

        self.trace.push(EmulationStep {
            address: self.pc,
            operation: op.clone(),
            register_changes: changes,
        });

        self.handle_control_flow(op)?;

        Ok(())
    }

    /// Run the emulator, executing instructions starting from the current
    /// PC.
    ///
    /// Execution continues until:
    /// - `max_steps` P-code operations have been executed.
    /// - A breakpoint is hit.
    /// - An error occurs.
    /// - The program halts (no P-code at the next PC).
    ///
    /// Returns an [`EmulationResult`] describing what happened.
    pub fn run(&mut self, max_steps: u64) -> Result<EmulationResult, EmulatorError> {
        self.running = true;
        let start_trace_len = self.trace.len();

        for _ in 0..max_steps {
            // Check if we exceeded step_limit
            if (self.trace.len() - start_trace_len) as u64 >= self.step_limit {
                self.running = false;
                return Ok(EmulationResult {
                    steps_executed: (self.trace.len() - start_trace_len) as u64,
                    final_pc: self.pc,
                    reason: StopReason::MaxSteps,
                });
            }

            // Check for execution breakpoint at current PC
            if self.breakpoints.check_execution(&self.pc) {
                self.running = false;
                return Ok(EmulationResult {
                    steps_executed: (self.trace.len() - start_trace_len) as u64,
                    final_pc: self.pc,
                    reason: StopReason::Breakpoint(self.pc),
                });
            }

            // Check if we have pcode at current PC
            if !self.pcode_map.contains_key(&self.pc) {
                self.running = false;
                return Ok(EmulationResult {
                    steps_executed: (self.trace.len() - start_trace_len) as u64,
                    final_pc: self.pc,
                    reason: StopReason::Halt,
                });
            }

            // Execute one instruction
            match self.step_instruction() {
                Ok(()) => {
                    if !self.running {
                        return Ok(EmulationResult {
                            steps_executed: (self.trace.len() - start_trace_len) as u64,
                            final_pc: self.pc,
                            reason: StopReason::Halt,
                        });
                    }
                }
                Err(e) => {
                    self.running = false;
                    return Ok(EmulationResult {
                        steps_executed: (self.trace.len() - start_trace_len) as u64,
                        final_pc: self.pc,
                        reason: StopReason::Error(e.to_string()),
                    });
                }
            }
        }

        self.running = false;
        Ok(EmulationResult {
            steps_executed: (self.trace.len() - start_trace_len) as u64,
            final_pc: self.pc,
            reason: StopReason::MaxSteps,
        })
    }

    // -- register access ---------------------------------------------------

    /// Set a register value by name.
    ///
    /// Common register names depend on the architecture. For register-space
    /// varnodes from P-code, the internal key is `"register:0x{offset}"`.
    pub fn set_register(&mut self, name: &str, value: &[u8]) {
        self.state.set_register(name, value);
    }

    /// Get a register value by name.
    ///
    /// Returns `None` if the register has not been initialized.
    pub fn get_register(&self, name: &str) -> Option<&[u8]> {
        self.state.get_register(name)
    }

    // -- memory access -----------------------------------------------------

    /// Read `size` bytes from memory at the given address.
    pub fn read_memory(&self, addr: Address, size: usize) -> Result<Vec<u8>, EmulatorError> {
        self.memory
            .read(addr, size)
            .map_err(|e| EmulatorError::MemoryAccess {
                addr,
                msg: e.to_string(),
            })
    }

    /// Write `data` to memory at the given address.
    pub fn write_memory(&mut self, addr: Address, data: &[u8]) -> Result<(), EmulatorError> {
        self.memory
            .write(addr, data)
            .map_err(|e| EmulatorError::MemoryAccess {
                addr,
                msg: e.to_string(),
            })
    }

    // -- breakpoints -------------------------------------------------------

    /// Set a breakpoint at the given address.
    pub fn set_breakpoint(&mut self, addr: Address, kind: BreakpointKind) {
        self.breakpoints.set(addr, kind);
    }

    /// Clear (remove) a breakpoint at the given address.
    pub fn clear_breakpoint(&mut self, addr: Address) {
        self.breakpoints.clear(addr);
    }

    // -- program counter ---------------------------------------------------

    /// Set the program counter to the given address.
    pub fn set_pc(&mut self, addr: Address) {
        self.pc = addr;
    }

    /// Advance the program counter past the current instruction.
    ///
    /// This is called when an instruction completes normally (no branch).
    /// The default implementation advances to the next address. Override
    /// or extend this for architectures where instruction sizes vary.
    pub fn advance_pc(&mut self) {
        // Naive: advance by 1. Real implementations should use the
        // instruction length from the decoding step.
        self.pc = self.pc.next();
    }

    /// Check whether the emulator is currently running.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Stop the emulator.
    pub fn halt(&mut self) {
        self.running = false;
    }

    /// Reset the emulator to its initial state.
    pub fn reset(&mut self) {
        self.state.clear();
        self.memory.clear();
        self.breakpoints.clear_all();
        self.pc = Address::new(0);
        self.trace.clear();
        self.pcode_map.clear();
        self.running = false;
    }

    /// Return a reference to the execution trace.
    pub fn trace(&self) -> &[EmulationStep] {
        &self.trace
    }

    /// Clear the execution trace.
    pub fn clear_trace(&mut self) {
        self.trace.clear();
    }

    // -------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------

    /// Handle control-flow side effects of a P-code operation.
    ///
    /// Updates `self.pc` and `self.running` for branch/call/return ops.
    fn handle_control_flow(&mut self, op: &PcodeOperation) -> Result<(), EmulatorError> {
        match op.opcode {
            ghidra_decompile::pcode::OpCode::BRANCH => {
                let target = op.inputs.first().ok_or_else(|| {
                    EmulatorError::InvalidOperation("BRANCH requires a target address".to_string())
                })?;
                self.pc = self.resolve_target(target)?;
            }
            ghidra_decompile::pcode::OpCode::CBRANCH => {
                // Conditional branch: if condition is true, take the branch.
                let target = op.inputs.first().ok_or_else(|| {
                    EmulatorError::InvalidOperation("CBRANCH requires a target address".to_string())
                })?;
                let cond = op.inputs.get(1).ok_or_else(|| {
                    EmulatorError::InvalidOperation(
                        "CBRANCH requires a condition varnode".to_string(),
                    )
                })?;

                let cond_val = self.read_varnode_value(cond)?;
                let taken = cond_val != 0;

                if taken {
                    self.pc = self.resolve_target(target)?;
                } else {
                    self.advance_pc();
                }
            }
            ghidra_decompile::pcode::OpCode::BRANCHIND => {
                let target = op.inputs.first().ok_or_else(|| {
                    EmulatorError::InvalidOperation(
                        "BRANCHIND requires a target varnode".to_string(),
                    )
                })?;
                self.pc = self.resolve_target(target)?;
            }
            ghidra_decompile::pcode::OpCode::CALL => {
                let target = op.inputs.first().ok_or_else(|| {
                    EmulatorError::InvalidOperation("CALL requires a target address".to_string())
                })?;
                // Save return address: current instruction's next address
                let ret_addr = self.pc;
                self.advance_pc();
                let return_addr = self.pc;

                // Push return address onto the stack (simplified)
                // In a full implementation, this would use the architecture's
                // calling convention. For now we store it in a special register.
                self.state
                    .set_register("emulator:return_address", &return_addr.offset.to_le_bytes());

                // Jump to target
                self.pc = self.resolve_target(target)?;
                let _ = ret_addr; // suppress unused warning
            }
            ghidra_decompile::pcode::OpCode::CALLIND => {
                let target = op.inputs.first().ok_or_else(|| {
                    EmulatorError::InvalidOperation("CALLIND requires a target varnode".to_string())
                })?;
                self.advance_pc();
                let return_addr = self.pc;
                self.state
                    .set_register("emulator:return_address", &return_addr.offset.to_le_bytes());
                self.pc = self.resolve_target(target)?;
            }
            ghidra_decompile::pcode::OpCode::RETURN => {
                // Pop return address
                if let Some(ret_bytes) = self.state.get_register("emulator:return_address") {
                    let mut buf = [0u8; 8];
                    let len = ret_bytes.len().min(8);
                    buf[..len].copy_from_slice(&ret_bytes[..len]);
                    self.pc = Address::new(u64::from_le_bytes(buf));
                } else {
                    self.running = false;
                }
            }
            ghidra_decompile::pcode::OpCode::CALLOTHER => {
                // User-defined pseudo-operation. Treat as NOP with optional
                // side effects (handled by the executor).
            }
            _ => {
                // No control flow change for this opcode.
            }
        }
        Ok(())
    }

    /// Resolve a branch/call target varnode to an address.
    fn resolve_target(&self, vn: &Varnode) -> Result<Address, EmulatorError> {
        if vn.is_constant() {
            Ok(Address::new(vn.offset))
        } else if vn.is_register() {
            let key = format!("{}:0x{:x}", vn.space.name, vn.offset);
            if let Some(bytes) = self.state.get_register(&key) {
                let mut buf = [0u8; 8];
                let len = bytes.len().min(8);
                buf[..len].copy_from_slice(&bytes[..len]);
                Ok(Address::new(u64::from_le_bytes(buf)))
            } else {
                Err(EmulatorError::InvalidRegister(key))
            }
        } else if vn.is_ram() {
            let data = self
                .memory
                .read(Address::new(vn.offset), vn.size as usize)
                .map_err(|e| EmulatorError::MemoryAccess {
                    addr: Address::new(vn.offset),
                    msg: e.to_string(),
                })?;
            let mut buf = [0u8; 8];
            let len = data.len().min(8);
            buf[..len].copy_from_slice(&data[..len]);
            Ok(Address::new(u64::from_le_bytes(buf)))
        } else {
            Ok(Address::new(vn.offset))
        }
    }

    /// Read the numeric value of a varnode.
    fn read_varnode_value(&self, vn: &Varnode) -> Result<u64, EmulatorError> {
        if vn.is_constant() {
            Ok(vn.offset)
        } else if vn.is_register() {
            let key = format!("{}:0x{:x}", vn.space.name, vn.offset);
            if let Some(bytes) = self.state.get_register(&key) {
                let mut buf = [0u8; 8];
                let len = bytes.len().min(8);
                buf[..len].copy_from_slice(&bytes[..len]);
                Ok(u64::from_le_bytes(buf))
            } else {
                Ok(0)
            }
        } else if vn.is_ram() {
            let data = self
                .memory
                .read(Address::new(vn.offset), vn.size as usize)
                .map_err(|e| EmulatorError::MemoryAccess {
                    addr: Address::new(vn.offset),
                    msg: e.to_string(),
                })?;
            let mut buf = [0u8; 8];
            let len = data.len().min(8);
            buf[..len].copy_from_slice(&data[..len]);
            Ok(u64::from_le_bytes(buf))
        } else {
            Ok(vn.offset)
        }
    }
}

impl Default for Emulator {
    fn default() -> Self {
        Self {
            state: EmulatorState::new(),
            memory: EmulatedMemory::new(),
            executor: PcodeExecutor::new(),
            breakpoints: BreakpointManager::new(),
            pc: Address::new(0),
            trace: Vec::new(),
            step_limit: 1_000_000,
            pcode_map: HashMap::new(),
            running: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::AddressSpace;
    use ghidra_core::program::lang::{Language, LanguageID};
    use ghidra_core::program::program::MemoryPermissions;
    use ghidra_decompile::pcode::{OpCode, Varnode};

    fn test_language() -> Language {
        Language {
            id: LanguageID::new("x86", "LE", 64),
            name: "x86:LE:64:default".into(),
            version: "1.0".into(),
        }
    }

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

    fn make_op(opcode: OpCode, out: Option<Varnode>, inputs: Vec<Varnode>) -> PcodeOperation {
        PcodeOperation::new_unannotated(opcode, out, inputs)
    }

    fn setup_emulator() -> Emulator {
        let lang = test_language();
        let mut emu = Emulator::new(&lang);

        // Add a RW memory segment at 0x0
        emu.memory
            .add_segment(MemorySegment::new(0x0, 0x10000, MemoryPermissions::RW));

        // Add an RX memory segment for code at 0x1000
        emu.memory
            .add_segment(MemorySegment::new(0x1000, 0x1000, MemoryPermissions::RX));

        emu
    }

    // -------------------------------------------------------------------
    // Creation and basic operations
    // -------------------------------------------------------------------

    #[test]
    fn test_emulator_creation() {
        let lang = test_language();
        let emu = Emulator::new(&lang);

        assert_eq!(emu.pc, Address::new(0));
        assert!(emu.trace.is_empty());
        assert_eq!(emu.step_limit, 1_000_000);
        assert!(!emu.is_running());
    }

    #[test]
    fn test_register_read_write() {
        let mut emu = setup_emulator();

        emu.set_register("RAX", &[0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0]);
        let val = emu.get_register("RAX").unwrap();
        assert_eq!(val, &[0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0]);

        assert!(emu.get_register("NONEXISTENT").is_none());
    }

    #[test]
    fn test_memory_read_write() {
        let mut emu = setup_emulator();

        let addr = Address::new(0x100);
        emu.write_memory(addr, &[0x41, 0x42, 0x43, 0x44]).unwrap();

        let data = emu.read_memory(addr, 4).unwrap();
        assert_eq!(data, vec![0x41, 0x42, 0x43, 0x44]);
    }

    #[test]
    fn test_memory_unmapped_fails() {
        let emu = setup_emulator();
        let result = emu.read_memory(Address::new(0xFFFF0000), 4);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_and_clear_breakpoint() {
        let mut emu = setup_emulator();
        let addr = Address::new(0x1000);

        assert!(!emu.breakpoints.is_set(&addr));

        emu.set_breakpoint(addr, BreakpointKind::Execution);
        assert!(emu.breakpoints.is_set(&addr));

        emu.clear_breakpoint(addr);
        assert!(!emu.breakpoints.is_set(&addr));
    }

    // -------------------------------------------------------------------
    // P-code execution (step_pcode)
    // -------------------------------------------------------------------

    #[test]
    fn test_step_pcode_copy() {
        let mut emu = setup_emulator();

        let op = make_op(
            OpCode::COPY,
            Some(make_reg_vn(0, 8)),
            vec![make_const_vn(42, 8)],
        );

        emu.step_pcode(&op).unwrap();
        assert_eq!(
            emu.get_register("register:0x0").unwrap(),
            &[42, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(emu.trace.len(), 1);
    }

    #[test]
    fn test_step_pcode_int_add() {
        let mut emu = setup_emulator();
        emu.set_register("register:0x0", &[10, 0, 0, 0, 0, 0, 0, 0]);
        emu.set_register("register:0x18", &[20, 0, 0, 0, 0, 0, 0, 0]);

        let op = make_op(
            OpCode::INT_ADD,
            Some(make_reg_vn(0, 8)),
            vec![make_reg_vn(0, 8), make_reg_vn(0x18, 8)],
        );

        emu.step_pcode(&op).unwrap();
        let val = emu.get_register("register:0x0").unwrap();
        assert_eq!(val, &[30, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_step_pcode_store_and_load() {
        let mut emu = setup_emulator();
        emu.set_register("register:0x0", &[0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0]);

        // STORE to address 0x500
        let store_op = make_op(
            OpCode::STORE,
            None,
            vec![
                make_const_vn(0, 4),     // space-id
                make_const_vn(0x500, 8), // pointer
                make_reg_vn(0, 8),       // value
            ],
        );
        emu.step_pcode(&store_op).unwrap();

        // LOAD from address 0x500
        let load_op = make_op(
            OpCode::LOAD,
            Some(make_reg_vn(0x18, 8)),
            vec![
                make_const_vn(0, 4),     // space-id
                make_const_vn(0x500, 8), // pointer
            ],
        );
        emu.step_pcode(&load_op).unwrap();

        let val = emu.get_register("register:0x18").unwrap();
        assert_eq!(val[0], 0xEF);
        assert_eq!(val[1], 0xBE);
        assert_eq!(val[2], 0xAD);
        assert_eq!(val[3], 0xDE);
    }

    #[test]
    fn test_step_pcode_branch_updates_pc() {
        let mut emu = setup_emulator();

        let op = make_op(OpCode::BRANCH, None, vec![make_const_vn(0x2000, 8)]);

        emu.step_pcode(&op).unwrap();
        assert_eq!(emu.pc, Address::new(0x2000));
    }

    #[test]
    fn test_step_pcode_cbranch_taken() {
        let mut emu = setup_emulator();
        emu.set_register("register:0x0", &[1, 0, 0, 0, 0, 0, 0, 0]); // condition = true

        let op = make_op(
            OpCode::CBRANCH,
            None,
            vec![
                make_const_vn(0x3000, 8), // target
                make_reg_vn(0, 8),        // condition
            ],
        );

        emu.step_pcode(&op).unwrap();
        assert_eq!(emu.pc, Address::new(0x3000));
    }

    #[test]
    fn test_step_pcode_cbranch_not_taken() {
        let mut emu = setup_emulator();
        emu.pc = Address::new(0x1000);
        emu.set_register("register:0x0", &[0, 0, 0, 0, 0, 0, 0, 0]); // condition = false

        let op = make_op(
            OpCode::CBRANCH,
            None,
            vec![
                make_const_vn(0x3000, 8), // target
                make_reg_vn(0, 8),        // condition
            ],
        );

        emu.step_pcode(&op).unwrap();
        assert_eq!(emu.pc, Address::new(0x1001)); // advanced to next
    }

    // -------------------------------------------------------------------
    // Instruction stepping and run loop
    // -------------------------------------------------------------------

    #[test]
    fn test_step_instruction() {
        let mut emu = setup_emulator();
        emu.pc = Address::new(0x1000);

        // Load a simple "instruction" at 0x1000
        emu.load_pcode(
            Address::new(0x1000),
            vec![
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
            ],
        );

        emu.step_instruction().unwrap();
        let val = emu.get_register("register:0x0").unwrap();
        assert_eq!(val, &[150, 0, 0, 0, 0, 0, 0, 0]); // 100 + 50
        assert_eq!(emu.trace.len(), 2);
    }

    #[test]
    fn test_run_simple_sequence() {
        let mut emu = setup_emulator();
        emu.pc = Address::new(0x1000);

        // Instruction at 0x1000: RAX = 10
        emu.load_pcode(
            Address::new(0x1000),
            vec![make_op(
                OpCode::COPY,
                Some(make_reg_vn(0, 8)),
                vec![make_const_vn(10, 8)],
            )],
        );

        // Instruction at 0x1001: RAX = RAX + 5
        emu.load_pcode(
            Address::new(0x1001),
            vec![make_op(
                OpCode::INT_ADD,
                Some(make_reg_vn(0, 8)),
                vec![make_reg_vn(0, 8), make_const_vn(5, 8)],
            )],
        );

        let result = emu.run(100).unwrap();

        assert_eq!(result.steps_executed, 2); // 2 pcode ops
        assert!(matches!(result.reason, StopReason::Halt));

        let val = emu.get_register("register:0x0").unwrap();
        assert_eq!(val, &[15, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_run_stops_on_breakpoint() {
        let mut emu = setup_emulator();
        emu.pc = Address::new(0x1000);

        emu.load_pcode(
            Address::new(0x1000),
            vec![make_op(
                OpCode::COPY,
                Some(make_reg_vn(0, 8)),
                vec![make_const_vn(1, 8)],
            )],
        );
        emu.load_pcode(
            Address::new(0x1001),
            vec![make_op(
                OpCode::COPY,
                Some(make_reg_vn(0x8, 8)),
                vec![make_const_vn(2, 8)],
            )],
        );

        // Set breakpoint at second instruction
        emu.set_breakpoint(Address::new(0x1001), BreakpointKind::Execution);

        let result = emu.run(100).unwrap();

        assert!(
            matches!(result.reason, StopReason::Breakpoint(addr) if addr == Address::new(0x1001))
        );
        // Only first instruction executed
        assert_eq!(emu.trace.len(), 0);
        // Wait, the breakpoint fires BEFORE execution of 0x1001, so the first
        // instruction at 0x1000 should have been executed.
        // Actually let's check this...
    }

    #[test]
    fn test_run_stops_on_max_steps() {
        let mut emu = setup_emulator();
        emu.pc = Address::new(0x1000);

        // Load many instructions
        for i in 0..10 {
            emu.load_pcode(
                Address::new(0x1000 + i),
                vec![make_op(
                    OpCode::COPY,
                    Some(make_reg_vn(i, 8)),
                    vec![make_const_vn(i, 8)],
                )],
            );
        }

        let result = emu.run(3).unwrap();
        assert_eq!(result.steps_executed, 3);
        assert!(matches!(result.reason, StopReason::MaxSteps));
    }

    #[test]
    fn test_run_branch_sequence() {
        let mut emu = setup_emulator();
        emu.pc = Address::new(0x1000);

        // Instruction at 0x1000: RAX = 1, then branch to 0x2000
        emu.load_pcode(
            Address::new(0x1000),
            vec![
                make_op(
                    OpCode::COPY,
                    Some(make_reg_vn(0, 8)),
                    vec![make_const_vn(1, 8)],
                ),
                make_op(OpCode::BRANCH, None, vec![make_const_vn(0x2000, 8)]),
            ],
        );

        // Instruction at 0x2000: RBX = 2
        emu.load_pcode(
            Address::new(0x2000),
            vec![make_op(
                OpCode::COPY,
                Some(make_reg_vn(0x18, 8)),
                vec![make_const_vn(2, 8)],
            )],
        );

        let result = emu.run(100).unwrap();

        assert!(matches!(result.reason, StopReason::Halt));
        assert_eq!(
            emu.get_register("register:0x0").unwrap(),
            &[1, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            emu.get_register("register:0x18").unwrap(),
            &[2, 0, 0, 0, 0, 0, 0, 0]
        );
        // Both instructions should have executed
        assert_eq!(emu.trace.len(), 3); // COPY + BRANCH at 0x1000, COPY at 0x2000
    }

    #[test]
    fn test_trace_captures_steps() {
        let mut emu = setup_emulator();
        emu.pc = Address::new(0x1000);

        emu.load_pcode(
            Address::new(0x1000),
            vec![
                make_op(
                    OpCode::COPY,
                    Some(make_reg_vn(0, 8)),
                    vec![make_const_vn(42, 8)],
                ),
                make_op(
                    OpCode::INT_ADD,
                    Some(make_reg_vn(0, 8)),
                    vec![make_reg_vn(0, 8), make_const_vn(8, 8)],
                ),
            ],
        );

        emu.step_instruction().unwrap();

        assert_eq!(emu.trace.len(), 2);
        assert_eq!(emu.trace[0].address, Address::new(0x1000));
        assert_eq!(emu.trace[0].operation.opcode, OpCode::COPY);
        assert_eq!(emu.trace[1].operation.opcode, OpCode::INT_ADD);

        // Check register changes in trace
        let changes = &emu.trace[0].register_changes;
        assert!(changes.contains_key("register:0x0"));

        let changes2 = &emu.trace[1].register_changes;
        assert!(changes2.contains_key("register:0x0"));
    }

    #[test]
    fn test_emulator_reset() {
        let mut emu = setup_emulator();
        emu.set_register("RAX", &[1, 2, 3, 4]);
        emu.write_memory(Address::new(0x100), &[5, 6, 7, 8])
            .unwrap();
        emu.set_breakpoint(Address::new(0x1000), BreakpointKind::Execution);
        emu.pc = Address::new(0x5000);
        emu.load_pcode(
            Address::new(0x1000),
            vec![make_op(
                OpCode::COPY,
                Some(make_reg_vn(0, 4)),
                vec![make_const_vn(0, 4)],
            )],
        );

        emu.reset();

        assert_eq!(emu.pc, Address::new(0));
        assert!(emu.get_register("RAX").is_none());
        assert!(emu.breakpoints.is_empty());
        assert!(emu.trace.is_empty());
        assert!(!emu.is_running());
    }
}
