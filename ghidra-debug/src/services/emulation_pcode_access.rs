//! P-code debugger access implementations.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service.emulation.data` package.
//! Provides the data access layer for p-code emulation, including memory,
//! registers, and property access backed by the trace database.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from p-code debugger data access.
#[derive(Debug, Error)]
pub enum PcodeAccessError {
    /// Memory access error.
    #[error("Memory access error at 0x{address:016x}: {message}")]
    MemoryAccess {
        /// The target address.
        address: u64,
        /// Error message.
        message: String,
    },

    /// Register access error.
    #[error("Register access error for '{register}': {message}")]
    RegisterAccess {
        /// The register name.
        register: String,
        /// Error message.
        message: String,
    },

    /// Property access error.
    #[error("Property access error: {0}")]
    PropertyAccess(String),

    /// Emulation state error.
    #[error("Emulation state error: {0}")]
    EmulationState(String),

    /// No active thread.
    #[error("No active thread selected")]
    NoActiveThread,

    /// No active frame.
    #[error("No active frame selected")]
    NoActiveFrame,
}

/// The current execution state of a p-code debugger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PcodeExecutionState {
    /// Debugger is idle (not emulating).
    Idle,
    /// Debugger is running.
    Running,
    /// Debugger is paused (e.g., at breakpoint).
    Paused,
    /// Debugger has finished execution.
    Finished,
    /// Debugger encountered an error.
    Error(String),
}

/// Memory access trait for p-code debugger.
///
/// Ported from Ghidra's `PcodeDebuggerMemoryAccess`.
pub trait PcodeDebuggerMemoryAccess {
    /// Read bytes from the given address.
    fn read_memory(&self, address: u64, length: usize) -> Result<Vec<u8>, PcodeAccessError>;

    /// Write bytes to the given address.
    fn write_memory(&mut self, address: u64, data: &[u8]) -> Result<(), PcodeAccessError>;

    /// Get the state of memory at the given address.
    fn memory_state(&self, address: u64) -> MemoryState;

    /// Get the state of a memory region.
    fn memory_state_region(&self, address: u64, length: u64) -> Vec<(u64, MemoryState)>;
}

/// Register access trait for p-code debugger.
///
/// Ported from Ghidra's `PcodeDebuggerRegistersAccess`.
pub trait PcodeDebuggerRegistersAccess {
    /// Read a register value by name.
    fn read_register(&self, name: &str) -> Result<Vec<u8>, PcodeAccessError>;

    /// Write a register value by name.
    fn write_register(&mut self, name: &str, data: &[u8]) -> Result<(), PcodeAccessError>;

    /// Get the value of the program counter register.
    fn get_pc(&self) -> Result<u64, PcodeAccessError>;

    /// Get the value of the stack pointer register.
    fn get_sp(&self) -> Result<u64, PcodeAccessError>;

    /// List all available register names.
    fn register_names(&self) -> Vec<String>;
}

/// Property access trait for p-code debugger.
///
/// Ported from Ghidra's `PcodeDebuggerPropertyAccess`.
pub trait PcodeDebuggerPropertyAccess {
    /// Get a property value by key.
    fn get_property(&self, key: &str) -> Option<String>;

    /// Set a property value.
    fn set_property(&mut self, key: &str, value: &str);

    /// Remove a property.
    fn remove_property(&mut self, key: &str);

    /// List all property keys.
    fn property_keys(&self) -> Vec<String>;
}

/// Combined data access trait for p-code debugger.
///
/// Ported from Ghidra's `PcodeDebuggerDataAccess`.
pub trait PcodeDebuggerDataAccess:
    PcodeDebuggerMemoryAccess + PcodeDebuggerRegistersAccess + PcodeDebuggerPropertyAccess
{
    /// Get the current execution state.
    fn execution_state(&self) -> &PcodeExecutionState;

    /// Get the current thread ID.
    fn active_thread_id(&self) -> Option<u64>;

    /// Set the active thread.
    fn set_active_thread(&mut self, thread_id: u64);
}

/// Memory state at a given address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryState {
    /// Memory is initialized with known data.
    Known,
    /// Memory is uninitialized / unknown.
    Unknown,
    /// Memory has been written but not yet committed.
    Written,
    /// Memory access produced an error.
    Error,
}

/// Default implementation of p-code debugger memory access backed by
/// a simple in-memory buffer.
#[derive(Debug, Clone, Default)]
pub struct DefaultPcodeDebuggerMemoryAccess {
    memory: BTreeMap<u64, u8>,
    states: BTreeMap<u64, MemoryState>,
}

impl DefaultPcodeDebuggerMemoryAccess {
    /// Create a new empty memory access.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load a block of bytes at the given address.
    pub fn load_bytes(&mut self, address: u64, data: &[u8]) {
        for (i, &byte) in data.iter().enumerate() {
            self.memory.insert(address + i as u64, byte);
            self.states.insert(address + i as u64, MemoryState::Known);
        }
    }
}

impl PcodeDebuggerMemoryAccess for DefaultPcodeDebuggerMemoryAccess {
    fn read_memory(&self, address: u64, length: usize) -> Result<Vec<u8>, PcodeAccessError> {
        let mut result = Vec::with_capacity(length);
        for i in 0..length {
            let addr = address + i as u64;
            match self.memory.get(&addr) {
                Some(&byte) => result.push(byte),
                None => result.push(0), // Return 0 for unmapped memory
            }
        }
        Ok(result)
    }

    fn write_memory(&mut self, address: u64, data: &[u8]) -> Result<(), PcodeAccessError> {
        for (i, &byte) in data.iter().enumerate() {
            self.memory.insert(address + i as u64, byte);
            self.states.insert(address + i as u64, MemoryState::Written);
        }
        Ok(())
    }

    fn memory_state(&self, address: u64) -> MemoryState {
        self.states.get(&address).copied().unwrap_or(MemoryState::Unknown)
    }

    fn memory_state_region(&self, address: u64, length: u64) -> Vec<(u64, MemoryState)> {
        (0..length)
            .map(|i| {
                let addr = address + i;
                (addr, self.memory_state(addr))
            })
            .collect()
    }
}

/// Default implementation of p-code debugger register access.
#[derive(Debug, Clone)]
pub struct DefaultPcodeDebuggerRegistersAccess {
    registers: BTreeMap<String, Vec<u8>>,
    pc_register: String,
    sp_register: String,
}

impl DefaultPcodeDebuggerRegistersAccess {
    /// Create a new register access with default PC/SP register names.
    pub fn new(pc: impl Into<String>, sp: impl Into<String>) -> Self {
        Self {
            registers: BTreeMap::new(),
            pc_register: pc.into(),
            sp_register: sp.into(),
        }
    }

    /// Set a register value.
    pub fn set_register(&mut self, name: impl Into<String>, value: Vec<u8>) {
        self.registers.insert(name.into(), value);
    }
}

impl Default for DefaultPcodeDebuggerRegistersAccess {
    fn default() -> Self {
        Self::new("PC", "SP")
    }
}

impl PcodeDebuggerRegistersAccess for DefaultPcodeDebuggerRegistersAccess {
    fn read_register(&self, name: &str) -> Result<Vec<u8>, PcodeAccessError> {
        self.registers.get(name).cloned().ok_or_else(|| PcodeAccessError::RegisterAccess {
            register: name.to_string(),
            message: "Register not found".to_string(),
        })
    }

    fn write_register(&mut self, name: &str, data: &[u8]) -> Result<(), PcodeAccessError> {
        self.registers.insert(name.to_string(), data.to_vec());
        Ok(())
    }

    fn get_pc(&self) -> Result<u64, PcodeAccessError> {
        let bytes = self.read_register(&self.pc_register)?;
        if bytes.len() >= 8 {
            Ok(u64::from_le_bytes(bytes[..8].try_into().unwrap()))
        } else if bytes.len() >= 4 {
            Ok(u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64)
        } else {
            Err(PcodeAccessError::RegisterAccess {
                register: self.pc_register.clone(),
                message: format!("PC register too small: {} bytes", bytes.len()),
            })
        }
    }

    fn get_sp(&self) -> Result<u64, PcodeAccessError> {
        let bytes = self.read_register(&self.sp_register)?;
        if bytes.len() >= 8 {
            Ok(u64::from_le_bytes(bytes[..8].try_into().unwrap()))
        } else if bytes.len() >= 4 {
            Ok(u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64)
        } else {
            Err(PcodeAccessError::RegisterAccess {
                register: self.sp_register.clone(),
                message: format!("SP register too small: {} bytes", bytes.len()),
            })
        }
    }

    fn register_names(&self) -> Vec<String> {
        self.registers.keys().cloned().collect()
    }
}

/// Default implementation of p-code debugger property access.
#[derive(Debug, Clone, Default)]
pub struct DefaultPcodeDebuggerPropertyAccess {
    properties: BTreeMap<String, String>,
}

impl DefaultPcodeDebuggerPropertyAccess {
    /// Create a new empty property access.
    pub fn new() -> Self {
        Self::default()
    }
}

impl PcodeDebuggerPropertyAccess for DefaultPcodeDebuggerPropertyAccess {
    fn get_property(&self, key: &str) -> Option<String> {
        self.properties.get(key).cloned()
    }

    fn set_property(&mut self, key: &str, value: &str) {
        self.properties.insert(key.to_string(), value.to_string());
    }

    fn remove_property(&mut self, key: &str) {
        self.properties.remove(key);
    }

    fn property_keys(&self) -> Vec<String> {
        self.properties.keys().cloned().collect()
    }
}

/// Composite p-code debugger data access combining memory, registers, and properties.
#[derive(Debug)]
pub struct DefaultPcodeDebuggerAccess {
    /// Memory access.
    pub memory: DefaultPcodeDebuggerMemoryAccess,
    /// Register access.
    pub registers: DefaultPcodeDebuggerRegistersAccess,
    /// Property access.
    pub properties: DefaultPcodeDebuggerPropertyAccess,
    /// Current execution state.
    pub state: PcodeExecutionState,
    /// Active thread ID.
    pub thread_id: Option<u64>,
}

impl Default for DefaultPcodeDebuggerAccess {
    fn default() -> Self {
        Self {
            memory: DefaultPcodeDebuggerMemoryAccess::new(),
            registers: DefaultPcodeDebuggerRegistersAccess::default(),
            properties: DefaultPcodeDebuggerPropertyAccess::new(),
            state: PcodeExecutionState::Idle,
            thread_id: None,
        }
    }
}

impl DefaultPcodeDebuggerAccess {
    /// Create a new composite data access.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the execution state.
    pub fn set_state(&mut self, state: PcodeExecutionState) {
        self.state = state;
    }

    /// Get the current execution state.
    pub fn execution_state(&self) -> &PcodeExecutionState {
        &self.state
    }

    /// Get the current thread ID.
    pub fn active_thread_id(&self) -> Option<u64> {
        self.thread_id
    }

    /// Set the active thread.
    pub fn set_active_thread(&mut self, thread_id: u64) {
        self.thread_id = Some(thread_id);
    }
}

impl PcodeDebuggerMemoryAccess for DefaultPcodeDebuggerAccess {
    fn read_memory(&self, address: u64, length: usize) -> Result<Vec<u8>, PcodeAccessError> {
        self.memory.read_memory(address, length)
    }

    fn write_memory(&mut self, address: u64, data: &[u8]) -> Result<(), PcodeAccessError> {
        self.memory.write_memory(address, data)
    }

    fn memory_state(&self, address: u64) -> MemoryState {
        self.memory.memory_state(address)
    }

    fn memory_state_region(&self, address: u64, length: u64) -> Vec<(u64, MemoryState)> {
        self.memory.memory_state_region(address, length)
    }
}

impl PcodeDebuggerRegistersAccess for DefaultPcodeDebuggerAccess {
    fn read_register(&self, name: &str) -> Result<Vec<u8>, PcodeAccessError> {
        self.registers.read_register(name)
    }

    fn write_register(&mut self, name: &str, data: &[u8]) -> Result<(), PcodeAccessError> {
        self.registers.write_register(name, data)
    }

    fn get_pc(&self) -> Result<u64, PcodeAccessError> {
        self.registers.get_pc()
    }

    fn get_sp(&self) -> Result<u64, PcodeAccessError> {
        self.registers.get_sp()
    }

    fn register_names(&self) -> Vec<String> {
        self.registers.register_names()
    }
}

impl PcodeDebuggerPropertyAccess for DefaultPcodeDebuggerAccess {
    fn get_property(&self, key: &str) -> Option<String> {
        self.properties.get_property(key)
    }

    fn set_property(&mut self, key: &str, value: &str) {
        self.properties.set_property(key, value);
    }

    fn remove_property(&mut self, key: &str) {
        self.properties.remove_property(key);
    }

    fn property_keys(&self) -> Vec<String> {
        self.properties.property_keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_read_write() {
        let mut mem = DefaultPcodeDebuggerMemoryAccess::new();
        mem.write_memory(0x1000, &[0x90, 0xcc, 0x48, 0x89]).unwrap();
        let data = mem.read_memory(0x1000, 4).unwrap();
        assert_eq!(data, vec![0x90, 0xcc, 0x48, 0x89]);
    }

    #[test]
    fn test_memory_unmapped() {
        let mem = DefaultPcodeDebuggerMemoryAccess::new();
        let data = mem.read_memory(0x1000, 4).unwrap();
        assert_eq!(data, vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_memory_state() {
        let mut mem = DefaultPcodeDebuggerMemoryAccess::new();
        assert_eq!(mem.memory_state(0x1000), MemoryState::Unknown);

        mem.write_memory(0x1000, &[0x90]).unwrap();
        assert_eq!(mem.memory_state(0x1000), MemoryState::Written);

        mem.load_bytes(0x2000, &[0xcc]);
        assert_eq!(mem.memory_state(0x2000), MemoryState::Known);
    }

    #[test]
    fn test_memory_state_region() {
        let mut mem = DefaultPcodeDebuggerMemoryAccess::new();
        mem.write_memory(0x1000, &[0x90, 0xcc]).unwrap();
        let states = mem.memory_state_region(0x1000, 3);
        assert_eq!(states.len(), 3);
        assert_eq!(states[0].1, MemoryState::Written);
        assert_eq!(states[1].1, MemoryState::Written);
        assert_eq!(states[2].1, MemoryState::Unknown);
    }

    #[test]
    fn test_register_read_write() {
        let mut regs = DefaultPcodeDebuggerRegistersAccess::default();
        regs.write_register("RAX", &[0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00]).unwrap();
        let data = regs.read_register("RAX").unwrap();
        assert_eq!(data.len(), 8);
    }

    #[test]
    fn test_register_not_found() {
        let regs = DefaultPcodeDebuggerRegistersAccess::default();
        assert!(regs.read_register("RAX").is_err());
    }

    #[test]
    fn test_pc_register() {
        let mut regs = DefaultPcodeDebuggerRegistersAccess::new("RIP", "RSP");
        regs.set_register("RIP", vec![0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(regs.get_pc().unwrap(), 0x4000);
    }

    #[test]
    fn test_property_access() {
        let mut props = DefaultPcodeDebuggerPropertyAccess::new();
        props.set_property("key1", "value1");
        assert_eq!(props.get_property("key1"), Some("value1".to_string()));
        assert!(props.property_keys().contains(&"key1".to_string()));

        props.remove_property("key1");
        assert!(props.get_property("key1").is_none());
    }

    #[test]
    fn test_composite_access() {
        let mut access = DefaultPcodeDebuggerAccess::new();

        // Write memory
        access.write_memory(0x1000, &[0xcc]).unwrap();
        let data = access.read_memory(0x1000, 1).unwrap();
        assert_eq!(data[0], 0xcc);

        // Set register
        access.write_register("RAX", &[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(access.read_register("RAX").unwrap().len(), 8);

        // Set property
        access.set_property("breakpoint", "true");
        assert_eq!(access.get_property("breakpoint"), Some("true".to_string()));

        // State
        access.set_state(PcodeExecutionState::Running);
        assert_eq!(*access.execution_state(), PcodeExecutionState::Running);

        // Thread
        assert!(access.active_thread_id().is_none());
        access.set_active_thread(1);
        assert_eq!(access.active_thread_id(), Some(1));
    }

    #[test]
    fn test_register_names() {
        let mut regs = DefaultPcodeDebuggerRegistersAccess::default();
        regs.write_register("RAX", &[0; 8]).unwrap();
        regs.write_register("RBX", &[0; 8]).unwrap();
        let names = regs.register_names();
        assert!(names.contains(&"RAX".to_string()));
        assert!(names.contains(&"RBX".to_string()));
    }

    #[test]
    fn test_pcode_execution_state_variants() {
        let states = vec![
            PcodeExecutionState::Idle,
            PcodeExecutionState::Running,
            PcodeExecutionState::Paused,
            PcodeExecutionState::Finished,
            PcodeExecutionState::Error("test".to_string()),
        ];
        assert_eq!(states.len(), 5);
    }

    #[test]
    fn test_memory_state_variants() {
        assert_ne!(MemoryState::Known, MemoryState::Unknown);
        assert_ne!(MemoryState::Written, MemoryState::Error);
    }
}
