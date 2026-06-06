//! Pcode trace data access interfaces.
//!
//! Ported from Ghidra's `ghidra.pcode.exec.trace.data` package.
//!
//! These types provide the bridge between p-code executors/emulators and
//! trace data storage. They allow p-code operations to read and write
//! memory, registers, and properties from a trace database.

use std::collections::BTreeMap;

use crate::model::TraceMemoryState;

// ---------------------------------------------------------------------------
// PcodeTraceAccess — base trait for trace data access
// ---------------------------------------------------------------------------

/// Trait for accessing trace data during p-code execution.
///
/// Ported from `ghidra.pcode.exec.trace.data.PcodeTraceAccess`.
pub trait PcodeTraceAccess: Send + Sync {
    /// Get the memory access interface for shared state.
    fn get_data_for_shared_state(&self) -> Box<dyn PcodeTraceMemoryAccess>;

    /// Get the register access interface for local state.
    fn get_data_for_local_state(&self, thread_key: i64, frame: i32) -> Box<dyn PcodeTraceRegistersAccess>;
}

// ---------------------------------------------------------------------------
// PcodeTraceMemoryAccess
// ---------------------------------------------------------------------------

/// Trait for accessing trace memory during p-code execution.
///
/// Ported from `ghidra.pcode.exec.trace.data.PcodeTraceMemoryAccess`.
pub trait PcodeTraceMemoryAccess: Send + Sync {
    /// Read bytes from trace memory.
    ///
    /// Returns the number of bytes actually read. May return fewer bytes
    /// if some have unknown state.
    fn read_memory(&self, address: u64, buffer: &mut [u8]) -> Result<usize, String>;

    /// Write bytes to trace memory.
    fn write_memory(&mut self, address: u64, data: &[u8]) -> Result<(), String>;

    /// Get the state of a memory byte.
    fn get_memory_state(&self, address: u64) -> TraceMemoryState;

    /// Get the state of a range of memory bytes.
    fn get_memory_state_range(&self, address: u64, length: usize) -> Vec<TraceMemoryState>;

    /// Set the state of a memory byte.
    fn set_memory_state(&mut self, address: u64, state: TraceMemoryState) -> Result<(), String>;

    /// Whether the given address is valid (mapped).
    fn is_valid_address(&self, address: u64) -> bool;

    /// Get the address space name for this memory access.
    fn space_name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// PcodeTraceRegistersAccess
// ---------------------------------------------------------------------------

/// Trait for accessing trace registers during p-code execution.
///
/// Ported from `ghidra.pcode.exec.trace.data.PcodeTraceRegistersAccess`.
pub trait PcodeTraceRegistersAccess: Send + Sync {
    /// Read a register value.
    ///
    /// Returns `None` if the register value is unknown.
    fn read_register(&self, register_name: &str) -> Option<Vec<u8>>;

    /// Write a register value.
    fn write_register(&mut self, register_name: &str, value: &[u8]) -> Result<(), String>;

    /// Get the state of a register.
    fn get_register_state(&self, register_name: &str) -> TraceMemoryState;

    /// Get the value of the program counter register.
    fn get_program_counter(&self) -> Option<u64>;

    /// Set the program counter register.
    fn set_program_counter(&mut self, address: u64) -> Result<(), String>;

    /// Get all known register names.
    fn register_names(&self) -> Vec<String>;

    /// Get the value of a register as a u64 (little-endian interpretation).
    fn read_register_u64(&self, register_name: &str) -> Option<u64> {
        let bytes = self.read_register(register_name)?;
        if bytes.len() >= 8 {
            Some(u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
            ]))
        } else if bytes.is_empty() {
            None
        } else {
            let mut buf = [0u8; 8];
            buf[..bytes.len()].copy_from_slice(&bytes);
            Some(u64::from_le_bytes(buf))
        }
    }

    /// Write a register value from a u64.
    fn write_register_u64(&mut self, register_name: &str, value: u64, num_bytes: usize) -> Result<(), String> {
        let bytes = value.to_le_bytes();
        self.write_register(register_name, &bytes[..num_bytes.min(8)])
    }
}

// ---------------------------------------------------------------------------
// PcodeTracePropertyAccess
// ---------------------------------------------------------------------------

/// Trait for accessing trace properties during p-code execution.
///
/// Ported from `ghidra.pcode.exec.trace.data.PcodeTracePropertyAccess`.
pub trait PcodeTracePropertyAccess: Send + Sync {
    /// Get a property value.
    fn get_property(&self, address: u64, property_name: &str) -> Option<String>;

    /// Set a property value.
    fn set_property(&mut self, address: u64, property_name: &str, value: &str) -> Result<(), String>;

    /// Remove a property.
    fn remove_property(&mut self, address: u64, property_name: &str) -> Result<(), String>;

    /// Get all property names at the given address.
    fn property_names_at(&self, address: u64) -> Vec<String>;
}

// ---------------------------------------------------------------------------
// PcodeTraceThreadAccess
// ---------------------------------------------------------------------------

/// Trait for accessing trace thread information during p-code execution.
///
/// Ported from `ghidra.pcode.exec.trace.data.DefaultPcodeTraceThreadAccess`.
pub trait PcodeTraceThreadAccess: Send + Sync {
    /// Get the current thread key.
    fn current_thread_key(&self) -> Option<i64>;

    /// Get the current thread name.
    fn current_thread_name(&self) -> Option<String>;

    /// Get the current process key.
    fn current_process_key(&self) -> Option<i64>;

    /// Get all thread keys.
    fn thread_keys(&self) -> Vec<i64>;

    /// Get the current snap.
    fn current_snap(&self) -> i64;
}

// ---------------------------------------------------------------------------
// PcodeTraceDataAccess — combined access
// ---------------------------------------------------------------------------

/// Combined access to all trace data for p-code execution.
///
/// Ported from `ghidra.pcode.exec.trace.data.PcodeTraceDataAccess`.
pub trait PcodeTraceDataAccess: PcodeTraceAccess {
    /// Get the property access interface.
    fn get_property_access(&self) -> Box<dyn PcodeTracePropertyAccess>;

    /// Get the thread access interface.
    fn get_thread_access(&self) -> Box<dyn PcodeTraceThreadAccess>;

    /// Get the current snap.
    fn current_snap(&self) -> i64;

    /// Get the trace key.
    fn trace_key(&self) -> &str;

    /// Get the platform language ID.
    fn language_id(&self) -> &str;

    /// Get the platform compiler spec ID.
    fn compiler_spec_id(&self) -> &str;
}

// ---------------------------------------------------------------------------
// Default implementations
// ---------------------------------------------------------------------------

/// Default implementation of PcodeTraceMemoryAccess backed by an in-memory buffer.
#[derive(Debug, Default)]
pub struct DefaultPcodeTraceMemoryAccess {
    /// The space name (e.g., "ram", "register").
    space: String,
    /// Memory storage: address -> byte.
    storage: BTreeMap<u64, u8>,
    /// Memory state per address.
    states: BTreeMap<u64, TraceMemoryState>,
}

impl DefaultPcodeTraceMemoryAccess {
    /// Create a new memory access for the given space.
    pub fn new(space: impl Into<String>) -> Self {
        Self {
            space: space.into(),
            storage: BTreeMap::new(),
            states: BTreeMap::new(),
        }
    }

    /// Load bytes into the storage.
    pub fn load_bytes(&mut self, address: u64, data: &[u8]) {
        for (i, &byte) in data.iter().enumerate() {
            self.storage.insert(address + i as u64, byte);
            self.states.insert(address + i as u64, TraceMemoryState::Known);
        }
    }
}

impl PcodeTraceMemoryAccess for DefaultPcodeTraceMemoryAccess {
    fn read_memory(&self, address: u64, buffer: &mut [u8]) -> Result<usize, String> {
        let mut read = 0;
        for (i, slot) in buffer.iter_mut().enumerate() {
            if let Some(&byte) = self.storage.get(&(address + i as u64)) {
                *slot = byte;
                read += 1;
            } else {
                *slot = 0;
            }
        }
        Ok(read)
    }

    fn write_memory(&mut self, address: u64, data: &[u8]) -> Result<(), String> {
        for (i, &byte) in data.iter().enumerate() {
            self.storage.insert(address + i as u64, byte);
            self.states.insert(address + i as u64, TraceMemoryState::Known);
        }
        Ok(())
    }

    fn get_memory_state(&self, address: u64) -> TraceMemoryState {
        self.states.get(&address).copied().unwrap_or(TraceMemoryState::Unknown)
    }

    fn get_memory_state_range(&self, address: u64, length: usize) -> Vec<TraceMemoryState> {
        (0..length)
            .map(|i| self.get_memory_state(address + i as u64))
            .collect()
    }

    fn set_memory_state(&mut self, address: u64, state: TraceMemoryState) -> Result<(), String> {
        self.states.insert(address, state);
        Ok(())
    }

    fn is_valid_address(&self, address: u64) -> bool {
        self.storage.contains_key(&address) || !self.states.is_empty()
    }

    fn space_name(&self) -> &str {
        &self.space
    }
}

/// Default implementation of PcodeTraceRegistersAccess backed by an in-memory map.
#[derive(Debug, Default)]
pub struct DefaultPcodeTraceRegistersAccess {
    /// Register values: name -> bytes.
    registers: BTreeMap<String, Vec<u8>>,
    /// Register states: name -> state.
    states: BTreeMap<String, TraceMemoryState>,
    /// Program counter register name.
    pc_register: String,
}

impl DefaultPcodeTraceRegistersAccess {
    /// Create a new register access.
    pub fn new(pc_register: impl Into<String>) -> Self {
        Self {
            registers: BTreeMap::new(),
            states: BTreeMap::new(),
            pc_register: pc_register.into(),
        }
    }

    /// Load a register value.
    pub fn load_register(&mut self, name: impl Into<String>, value: Vec<u8>) {
        let name = name.into();
        self.registers.insert(name.clone(), value);
        self.states.insert(name, TraceMemoryState::Known);
    }
}

impl PcodeTraceRegistersAccess for DefaultPcodeTraceRegistersAccess {
    fn read_register(&self, register_name: &str) -> Option<Vec<u8>> {
        self.registers.get(register_name).cloned()
    }

    fn write_register(&mut self, register_name: &str, value: &[u8]) -> Result<(), String> {
        self.registers.insert(register_name.to_string(), value.to_vec());
        self.states.insert(register_name.to_string(), TraceMemoryState::Known);
        Ok(())
    }

    fn get_register_state(&self, register_name: &str) -> TraceMemoryState {
        self.states.get(register_name).copied().unwrap_or(TraceMemoryState::Unknown)
    }

    fn get_program_counter(&self) -> Option<u64> {
        self.read_register_u64(&self.pc_register.clone())
    }

    fn set_program_counter(&mut self, address: u64) -> Result<(), String> {
        self.write_register_u64(&self.pc_register.clone(), address, 8)
    }

    fn register_names(&self) -> Vec<String> {
        self.registers.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_memory_access_read_write() {
        let mut mem = DefaultPcodeTraceMemoryAccess::new("ram");
        mem.write_memory(0x1000, &[0xAA, 0xBB, 0xCC]).unwrap();

        let mut buf = [0u8; 3];
        let read = mem.read_memory(0x1000, &mut buf).unwrap();
        assert_eq!(read, 3);
        assert_eq!(buf, [0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_default_memory_access_state() {
        let mut mem = DefaultPcodeTraceMemoryAccess::new("ram");
        assert_eq!(mem.get_memory_state(0x1000), TraceMemoryState::Unknown);

        mem.write_memory(0x1000, &[0xFF]).unwrap();
        assert_eq!(mem.get_memory_state(0x1000), TraceMemoryState::Known);
    }

    #[test]
    fn test_default_memory_access_state_range() {
        let mut mem = DefaultPcodeTraceMemoryAccess::new("ram");
        mem.write_memory(0x1000, &[0xFF, 0xFE]).unwrap();

        let states = mem.get_memory_state_range(0x1000, 3);
        assert_eq!(states.len(), 3);
        assert_eq!(states[0], TraceMemoryState::Known);
        assert_eq!(states[1], TraceMemoryState::Known);
        assert_eq!(states[2], TraceMemoryState::Unknown);
    }

    #[test]
    fn test_default_memory_access_partial_read() {
        let mut mem = DefaultPcodeTraceMemoryAccess::new("ram");
        mem.write_memory(0x1000, &[0xAA]).unwrap();

        let mut buf = [0u8; 3];
        let read = mem.read_memory(0x1000, &mut buf).unwrap();
        assert_eq!(read, 1);
        assert_eq!(buf[0], 0xAA);
        assert_eq!(buf[1], 0); // Not written
    }

    #[test]
    fn test_default_memory_access_set_state() {
        let mut mem = DefaultPcodeTraceMemoryAccess::new("ram");
        mem.set_memory_state(0x1000, TraceMemoryState::Error).unwrap();
        assert_eq!(mem.get_memory_state(0x1000), TraceMemoryState::Error);
    }

    #[test]
    fn test_default_memory_access_space_name() {
        let mem = DefaultPcodeTraceMemoryAccess::new("register");
        assert_eq!(mem.space_name(), "register");
    }

    #[test]
    fn test_default_registers_access_read_write() {
        let mut regs = DefaultPcodeTraceRegistersAccess::new("RIP");
        regs.write_register("RAX", &[0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap();

        let val = regs.read_register("RAX").unwrap();
        assert_eq!(val, [0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        assert!(regs.read_register("NONEXISTENT").is_none());
    }

    #[test]
    fn test_default_registers_access_state() {
        let mut regs = DefaultPcodeTraceRegistersAccess::new("RIP");
        assert_eq!(regs.get_register_state("RAX"), TraceMemoryState::Unknown);

        regs.write_register("RAX", &[0x42]).unwrap();
        assert_eq!(regs.get_register_state("RAX"), TraceMemoryState::Known);
    }

    #[test]
    fn test_default_registers_access_pc() {
        let mut regs = DefaultPcodeTraceRegistersAccess::new("RIP");
        assert!(regs.get_program_counter().is_none());

        regs.write_register("RIP", &[0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap();
        let pc = regs.get_program_counter().unwrap();
        assert_eq!(pc, 0x00401000);
    }

    #[test]
    fn test_default_registers_access_u64() {
        let mut regs = DefaultPcodeTraceRegistersAccess::new("RIP");
        regs.write_register_u64("RAX", 0xDEADBEEF, 8).unwrap();

        let val = regs.read_register_u64("RAX").unwrap();
        assert_eq!(val, 0xDEADBEEF);
    }

    #[test]
    fn test_default_registers_access_names() {
        let mut regs = DefaultPcodeTraceRegistersAccess::new("RIP");
        regs.load_register("RAX", vec![0; 8]);
        regs.load_register("RBX", vec![0; 8]);

        let names = regs.register_names();
        assert!(names.contains(&"RAX".to_string()));
        assert!(names.contains(&"RBX".to_string()));
    }

    #[test]
    fn test_memory_access_default() {
        let mem = DefaultPcodeTraceMemoryAccess::default();
        assert_eq!(mem.space_name(), "");
    }

    #[test]
    fn test_registers_access_default() {
        let regs = DefaultPcodeTraceRegistersAccess::default();
        assert!(regs.register_names().is_empty());
        assert!(regs.pc_register.is_empty());
    }

    #[test]
    fn test_memory_access_write_overwrite() {
        let mut mem = DefaultPcodeTraceMemoryAccess::new("ram");
        mem.write_memory(0x1000, &[0xAA]).unwrap();
        mem.write_memory(0x1000, &[0xBB]).unwrap();

        let mut buf = [0u8; 1];
        mem.read_memory(0x1000, &mut buf).unwrap();
        assert_eq!(buf[0], 0xBB);
    }

    #[test]
    fn test_registers_access_set_pc() {
        let mut regs = DefaultPcodeTraceRegistersAccess::new("PC");
        regs.set_program_counter(0x400000).unwrap();

        let pc = regs.get_program_counter().unwrap();
        assert_eq!(pc, 0x400000);
    }
}
