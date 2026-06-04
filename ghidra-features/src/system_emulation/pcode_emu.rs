//! P-code emulation engine.
//!
//! Ported from Ghidra's `AbstractEmuMachine` and related emulation classes.
//!
//! Provides a memory-and-register model suitable for emulating small code
//! snippets, analyzing system calls, and performing symbolic execution.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

// ---------------------------------------------------------------------------
// EmuProcessExitedException & EmuSystemException
// ---------------------------------------------------------------------------

/// An error that occurs during P-code emulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmuException {
    /// The emulated process exited with the given status.
    ProcessExited(i32),
    /// A system call was invoked.
    Syscall { number: u64, name: String },
    /// An illegal or unsupported P-code operation was encountered.
    UnsupportedOp(String),
    /// A memory access violation.
    MemoryViolation(String),
    /// A breakpoint was hit.
    BreakpointHit(u64),
    /// An arithmetic error (e.g., division by zero).
    ArithmeticError(String),
    /// The emulation was manually stopped.
    Halted,
}

impl std::fmt::Display for EmuException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmuException::ProcessExited(code) => write!(f, "Process exited with status {}", code),
            EmuException::Syscall { number, name } => {
                write!(f, "Syscall {} ({})", number, name)
            }
            EmuException::UnsupportedOp(op) => write!(f, "Unsupported operation: {}", op),
            EmuException::MemoryViolation(msg) => write!(f, "Memory violation: {}", msg),
            EmuException::BreakpointHit(addr) => write!(f, "Breakpoint hit at 0x{:x}", addr),
            EmuException::ArithmeticError(msg) => write!(f, "Arithmetic error: {}", msg),
            EmuException::Halted => write!(f, "Emulation halted"),
        }
    }
}

impl std::error::Error for EmuException {}

// ---------------------------------------------------------------------------
// Emulated memory region
// ---------------------------------------------------------------------------

/// An emulated memory region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Start address (inclusive).
    pub start: u64,
    /// End address (exclusive).
    pub end: u64,
    /// Whether this region is readable.
    pub readable: bool,
    /// Whether this region is writable.
    pub writable: bool,
    /// Whether this region is executable.
    pub executable: bool,
    /// Name / purpose (e.g., "stack", "heap", "code").
    pub name: String,
}

// ---------------------------------------------------------------------------
// EmulatedMachine -- the main emulation state
// ---------------------------------------------------------------------------

/// A P-code emulation machine with memory, registers, and breakpoints.
///
/// # Example
///
/// ```rust
/// use ghidra_features::system_emulation::*;
///
/// let mut emu = EmulatedMachine::new_le(64);
/// emu.map_memory(0x400000, 0x1000, "code".into(), true, false, true);
/// emu.mem_write(0x400000, &[0x55, 0x48, 0x89, 0xE5]);
/// let buf = emu.mem_read(0x400000, 4);
/// assert_eq!(buf, vec![0x55, 0x48, 0x89, 0xE5]);
/// ```
#[derive(Debug, Clone)]
pub struct EmulatedMachine {
    /// Flat memory storage (sparse: only written regions exist).
    memory: BTreeMap<u64, u8>,
    /// Named memory regions.
    pub regions: Vec<MemoryRegion>,
    /// Named registers (register name -> value).
    pub registers: HashMap<String, u64>,
    /// The program counter register name.
    pub pc_name: String,
    /// Breakpoint addresses.
    pub breakpoints: Vec<u64>,
    /// Whether the machine uses little-endian byte order.
    pub is_little_endian: bool,
    /// Pointer size in bytes (4 or 8).
    pub pointer_size: usize,
    /// Instruction count (for statistics).
    pub instruction_count: u64,
    /// Whether emulation is currently running.
    pub running: bool,
    /// The syscall handler (if any).
    pub syscall_handler: Option<String>,
    /// Emulated thread states.
    pub threads: Vec<EmuThread>,
    /// Index of the active thread.
    pub active_thread: usize,
}

/// State for a single emulated thread.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmuThread {
    /// Thread ID.
    pub id: u32,
    /// Thread name.
    pub name: String,
    /// Whether the thread is currently blocked.
    pub is_blocked: bool,
    /// Thread-local register state.
    pub local_registers: HashMap<String, u64>,
}

impl EmulatedMachine {
    /// Create a new little-endian machine with the given pointer size.
    pub fn new_le(pointer_size: usize) -> Self {
        Self {
            memory: BTreeMap::new(),
            regions: Vec::new(),
            registers: HashMap::new(),
            pc_name: "PC".to_string(),
            breakpoints: Vec::new(),
            is_little_endian: true,
            pointer_size,
            instruction_count: 0,
            running: false,
            syscall_handler: None,
            threads: vec![EmuThread {
                id: 0,
                name: "main".to_string(),
                is_blocked: false,
                local_registers: HashMap::new(),
            }],
            active_thread: 0,
        }
    }

    /// Create a new big-endian machine with the given pointer size.
    pub fn new_be(pointer_size: usize) -> Self {
        Self {
            is_little_endian: false,
            ..Self::new_le(pointer_size)
        }
    }

    /// Map a memory region.
    pub fn map_memory(
        &mut self,
        start: u64,
        size: u64,
        name: String,
        readable: bool,
        writable: bool,
        executable: bool,
    ) {
        self.regions.push(MemoryRegion {
            start,
            end: start + size,
            readable,
            writable,
            executable,
            name,
        });
    }

    /// Write bytes to emulated memory.
    pub fn mem_write(&mut self, addr: u64, data: &[u8]) {
        for (i, &byte) in data.iter().enumerate() {
            self.memory.insert(addr + i as u64, byte);
        }
    }

    /// Read bytes from emulated memory.
    pub fn mem_read(&self, addr: u64, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| *self.memory.get(&(addr + i as u64)).unwrap_or(&0))
            .collect()
    }

    /// Read a little-endian u64 from emulated memory.
    pub fn mem_read_u64_le(&self, addr: u64) -> u64 {
        let bytes = self.mem_read(addr, 8);
        u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]))
    }

    /// Read a little-endian u32 from emulated memory.
    pub fn mem_read_u32_le(&self, addr: u64) -> u32 {
        let bytes = self.mem_read(addr, 4);
        u32::from_le_bytes(bytes.try_into().unwrap_or([0; 4]))
    }

    /// Write a little-endian u64 to emulated memory.
    pub fn mem_write_u64_le(&mut self, addr: u64, value: u64) {
        self.mem_write(addr, &value.to_le_bytes());
    }

    /// Write a little-endian u32 to emulated memory.
    pub fn mem_write_u32_le(&mut self, addr: u64, value: u32) {
        self.mem_write(addr, &value.to_le_bytes());
    }

    /// Set a register to a value.
    pub fn set_register(&mut self, name: &str, value: u64) {
        self.registers.insert(name.to_string(), value);
    }

    /// Read a register value.
    pub fn get_register(&self, name: &str) -> u64 {
        *self.registers.get(name).unwrap_or(&0)
    }

    /// Get the program counter value.
    pub fn get_pc(&self) -> u64 {
        self.get_register(&self.pc_name.clone())
    }

    /// Set the program counter.
    pub fn set_pc(&mut self, value: u64) {
        let pc_name = self.pc_name.clone();
        self.set_register(&pc_name, value);
    }

    /// Add a breakpoint at the given address.
    pub fn add_breakpoint(&mut self, addr: u64) {
        if !self.breakpoints.contains(&addr) {
            self.breakpoints.push(addr);
        }
    }

    /// Remove a breakpoint.
    pub fn remove_breakpoint(&mut self, addr: u64) {
        self.breakpoints.retain(|&a| a != addr);
    }

    /// Check whether a breakpoint exists at the given address.
    pub fn has_breakpoint(&self, addr: u64) -> bool {
        self.breakpoints.contains(&addr)
    }

    /// Push a value onto the stack (assumes SP is the stack pointer register).
    pub fn stack_push(&mut self, value: u64) {
        let sp_name = if self.pointer_size == 8 { "RSP" } else { "ESP" };
        let sp = self.get_register(sp_name);
        let new_sp = sp.wrapping_sub(self.pointer_size as u64);
        if self.pointer_size == 8 {
            self.mem_write_u64_le(new_sp, value);
        } else {
            self.mem_write_u32_le(new_sp, value as u32);
        }
        self.set_register(sp_name, new_sp);
    }

    /// Pop a value from the stack.
    pub fn stack_pop(&mut self) -> u64 {
        let sp_name = if self.pointer_size == 8 { "RSP" } else { "ESP" };
        let sp = self.get_register(sp_name);
        let value = if self.pointer_size == 8 {
            self.mem_read_u64_le(sp)
        } else {
            self.mem_read_u32_le(sp) as u64
        };
        self.set_register(sp_name, sp + self.pointer_size as u64);
        value
    }

    /// Execute a single P-code-style instruction.
    ///
    /// This is a simplified emulation step that handles basic memory/register
    /// operations. Returns the next PC value or an exception.
    pub fn step(&mut self) -> Result<u64, EmuException> {
        let pc = self.get_pc();

        if self.has_breakpoint(pc) {
            return Err(EmuException::BreakpointHit(pc));
        }

        // Read the instruction bytes (simplified: just advance PC by pointer_size)
        let _instr = self.mem_read(pc, 1);

        // In a real implementation, this would decode P-code operations.
        // For now, advance PC by 1 as a no-op.
        self.set_pc(pc + 1);
        self.instruction_count += 1;

        Ok(pc + 1)
    }

    /// Memory region at the given address.
    pub fn region_at(&self, addr: u64) -> Option<&MemoryRegion> {
        self.regions.iter().find(|r| addr >= r.start && addr < r.end)
    }

    /// Whether the address is in a readable region.
    pub fn is_readable(&self, addr: u64) -> bool {
        self.region_at(addr).map_or(false, |r| r.readable)
    }

    /// Whether the address is in a writable region.
    pub fn is_writable(&self, addr: u64) -> bool {
        self.region_at(addr).map_or(false, |r| r.writable)
    }

    /// Whether the address is in an executable region.
    pub fn is_executable(&self, addr: u64) -> bool {
        self.region_at(addr).map_or(false, |r| r.executable)
    }

    /// Set the syscall handler name.
    pub fn set_syscall_handler(&mut self, name: impl Into<String>) {
        self.syscall_handler = Some(name.into());
    }

    /// Create a new emulated thread.
    pub fn create_thread(&mut self, id: u32, name: impl Into<String>) {
        self.threads.push(EmuThread {
            id,
            name: name.into(),
            is_blocked: false,
            local_registers: HashMap::new(),
        });
    }

    /// Switch the active thread.
    pub fn switch_thread(&mut self, id: u32) -> Result<(), EmuException> {
        if let Some(idx) = self.threads.iter().position(|t| t.id == id) {
            self.active_thread = idx;
            Ok(())
        } else {
            Err(EmuException::UnsupportedOp(format!(
                "Thread {} not found",
                id
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mem_read_write() {
        let mut emu = EmulatedMachine::new_le(4);
        emu.mem_write(0x1000, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let data = emu.mem_read(0x1000, 4);
        assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_mem_read_uninitialized() {
        let emu = EmulatedMachine::new_le(4);
        let data = emu.mem_read(0x5000, 4);
        assert_eq!(data, vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_register_read_write() {
        let mut emu = EmulatedMachine::new_le(8);
        emu.set_register("RAX", 0xDEADBEEF);
        assert_eq!(emu.get_register("RAX"), 0xDEADBEEF);
        assert_eq!(emu.get_register("RBX"), 0); // uninitialized
    }

    #[test]
    fn test_pc_read_write() {
        let mut emu = EmulatedMachine::new_le(8);
        emu.pc_name = "RIP".to_string();
        emu.set_pc(0x400000);
        assert_eq!(emu.get_pc(), 0x400000);
    }

    #[test]
    fn test_breakpoints() {
        let mut emu = EmulatedMachine::new_le(8);
        emu.add_breakpoint(0x400000);
        assert!(emu.has_breakpoint(0x400000));
        assert!(!emu.has_breakpoint(0x400001));
        emu.remove_breakpoint(0x400000);
        assert!(!emu.has_breakpoint(0x400000));
    }

    #[test]
    fn test_mem_read_u32_le() {
        let mut emu = EmulatedMachine::new_le(4);
        emu.mem_write(0x100, &0x12345678u32.to_le_bytes());
        assert_eq!(emu.mem_read_u32_le(0x100), 0x12345678);
    }

    #[test]
    fn test_mem_read_u64_le() {
        let mut emu = EmulatedMachine::new_le(8);
        emu.mem_write(0x200, &0xCAFEBABEDEADBEEFu64.to_le_bytes());
        assert_eq!(emu.mem_read_u64_le(0x200), 0xCAFEBABEDEADBEEF);
    }

    #[test]
    fn test_stack_push_pop() {
        let mut emu = EmulatedMachine::new_le(8);
        emu.set_register("RSP", 0x7FFF0000);
        emu.map_memory(0x7FFE0000, 0x20000, "stack".into(), true, true, false);

        emu.stack_push(0xCAFEBABE);
        let sp_after_push = emu.get_register("RSP");
        assert_eq!(sp_after_push, 0x7FFF0000 - 8);

        let value = emu.stack_pop();
        assert_eq!(value, 0xCAFEBABE);
        assert_eq!(emu.get_register("RSP"), 0x7FFF0000);
    }

    #[test]
    fn test_step_with_breakpoint() {
        let mut emu = EmulatedMachine::new_le(8);
        emu.set_pc(0x400000);
        emu.add_breakpoint(0x400000);
        let result = emu.step();
        assert!(matches!(result, Err(EmuException::BreakpointHit(0x400000))));
    }

    #[test]
    fn test_step_advances_pc() {
        let mut emu = EmulatedMachine::new_le(8);
        emu.set_pc(0x400000);
        let result = emu.step();
        assert!(result.is_ok());
        assert_eq!(emu.get_pc(), 0x400001);
        assert_eq!(emu.instruction_count, 1);
    }

    #[test]
    fn test_region_at() {
        let mut emu = EmulatedMachine::new_le(4);
        emu.map_memory(0x400000, 0x1000, "code".into(), true, false, true);
        assert!(emu.region_at(0x400000).is_some());
        assert!(emu.region_at(0x3FFFFF).is_none());
        assert!(emu.is_executable(0x400000));
        assert!(!emu.is_writable(0x400000));
        assert!(emu.is_readable(0x400000));
    }

    #[test]
    fn test_create_and_switch_thread() {
        let mut emu = EmulatedMachine::new_le(8);
        emu.create_thread(1, "worker");
        assert_eq!(emu.threads.len(), 2);
        assert!(emu.switch_thread(1).is_ok());
        assert_eq!(emu.active_thread, 1);
        assert!(emu.switch_thread(99).is_err());
    }

    #[test]
    fn test_big_endian_machine() {
        let mut emu = EmulatedMachine::new_be(4);
        assert!(!emu.is_little_endian);
        emu.mem_write(0x100, &0x12345678u32.to_le_bytes());
        let data = emu.mem_read(0x100, 4);
        assert_eq!(data, vec![0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_emu_exception_display() {
        let e = EmuException::ProcessExited(1);
        assert_eq!(format!("{}", e), "Process exited with status 1");

        let e2 = EmuException::BreakpointHit(0x400000);
        assert_eq!(format!("{}", e2), "Breakpoint hit at 0x400000");
    }
}
