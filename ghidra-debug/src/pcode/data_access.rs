//! Pcode trace data access interfaces.
//!
//! Ported from Ghidra's `ghidra.pcode.exec.trace.data` package:
//! - `PcodeTraceAccess`: Top-level access interface.
//! - `PcodeTraceDataAccess`: Data read/write access.
//! - `PcodeTraceMemoryAccess`: Memory state access.
//! - `PcodeTraceRegistersAccess`: Register state access.
//! - `PcodeTracePropertyAccess`: Property map access.
//! - `DefaultPcodeTraceAccess`: Default implementation.
//! - `DefaultPcodeTraceMemoryAccess`: Default memory access.
//! - `DefaultPcodeTraceRegistersAccess`: Default register access.
//! - `DefaultPcodeTracePropertyAccess`: Default property access.
//! - `InternalPcodeTraceDataAccess`: Internal data access.
//! - `AddressesReadTracePcodeExecutorStatePiece`: Tracks which addresses were read.

use std::collections::{BTreeMap, BTreeSet};


/// A varnode descriptor (space, offset, size).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VarnodeDescriptor {
    /// The address space name.
    pub space: String,
    /// The offset within the space.
    pub offset: u64,
    /// The size in bytes.
    pub size: u32,
}

impl VarnodeDescriptor {
    /// Create a new varnode descriptor.
    pub fn new(space: impl Into<String>, offset: u64, size: u32) -> Self {
        Self {
            space: space.into(),
            offset,
            size,
        }
    }
}

/// Top-level interface for pcode trace data access.
///
/// Provides unified access to memory, registers, and properties
/// within a trace at a specific snap/thread context.
pub trait PcodeTraceAccess {
    /// Get the current snap context.
    fn snap(&self) -> i64;

    /// Get the current thread context (0 for global).
    fn thread_id(&self) -> u64;

    /// Get the memory access interface.
    fn memory(&self) -> &dyn PcodeTraceMemoryAccess;

    /// Get a mutable memory access interface.
    fn memory_mut(&mut self) -> &mut dyn PcodeTraceMemoryAccess;

    /// Get the register access interface.
    fn registers(&self) -> &dyn PcodeTraceRegistersAccess;

    /// Get a mutable register access interface.
    fn registers_mut(&mut self) -> &mut dyn PcodeTraceRegistersAccess;
}

/// Interface for data-level trace access (combines memory + register + property).
pub trait PcodeTraceDataAccess: PcodeTraceAccess {
    /// Read bytes from the specified varnode.
    fn read_varnode(&self, varnode: &VarnodeDescriptor) -> Option<Vec<u8>>;

    /// Write bytes to the specified varnode.
    fn write_varnode(&mut self, varnode: &VarnodeDescriptor, bytes: &[u8]);

    /// Check if the specified varnode has known state.
    fn has_state(&self, varnode: &VarnodeDescriptor) -> bool;
}

/// Interface for pcode memory state access.
pub trait PcodeTraceMemoryAccess {
    /// Read bytes from memory.
    fn read_memory(&self, space: &str, offset: u64, len: u32) -> Option<Vec<u8>>;

    /// Write bytes to memory.
    fn write_memory(&mut self, space: &str, offset: u64, bytes: &[u8]);

    /// Check if memory at the given location has known state.
    fn has_memory_state(&self, space: &str, offset: u64, len: u32) -> bool;

    /// Get the memory state (known/unknown) for a range.
    fn memory_state(&self, space: &str, offset: u64, len: u32) -> MemoryState;
}

/// The state of a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryState {
    /// All bytes in the region are known.
    Known,
    /// Some bytes are known, some unknown.
    Partial,
    /// All bytes are unknown.
    Unknown,
}

/// Interface for register state access.
pub trait PcodeTraceRegistersAccess {
    /// Read a register value by name.
    fn read_register(&self, name: &str) -> Option<Vec<u8>>;

    /// Write a register value by name.
    fn write_register(&mut self, name: &str, bytes: &[u8]);

    /// Check if a register has known state.
    fn has_register_state(&self, name: &str) -> bool;

    /// Get all register names with known state.
    fn known_registers(&self) -> Vec<String>;
}

/// Interface for property map access.
pub trait PcodeTracePropertyAccess {
    /// Get a string property.
    fn get_string_property(&self, name: &str) -> Option<String>;

    /// Set a string property.
    fn set_string_property(&mut self, name: &str, value: &str);

    /// Get an integer property.
    fn get_int_property(&self, name: &str) -> Option<i64>;

    /// Set an integer property.
    fn set_int_property(&mut self, name: &str, value: i64);

    /// Get a boolean property.
    fn get_bool_property(&self, name: &str) -> Option<bool>;

    /// Set a boolean property.
    fn set_bool_property(&mut self, name: &str, value: bool);

    /// Remove a property.
    fn remove_property(&mut self, name: &str);
}

/// Default implementation of `PcodeTraceMemoryAccess`.
#[derive(Debug, Default)]
pub struct DefaultPcodeTraceMemoryAccess {
    /// Memory storage indexed by (space_name, offset).
    storage: BTreeMap<(String, u64), u8>,
    /// The snap context.
    #[allow(dead_code)]
    snap: i64,
}

impl DefaultPcodeTraceMemoryAccess {
    /// Create a new default memory access.
    pub fn new(snap: i64) -> Self {
        Self {
            storage: BTreeMap::new(),
            snap,
        }
    }
}

impl PcodeTraceMemoryAccess for DefaultPcodeTraceMemoryAccess {
    fn read_memory(&self, space: &str, offset: u64, len: u32) -> Option<Vec<u8>> {
        let mut result = Vec::with_capacity(len as usize);
        for i in 0..len as u64 {
            let key = (space.to_string(), offset + i);
            match self.storage.get(&key) {
                Some(&byte) => result.push(byte),
                None => return None,
            }
        }
        Some(result)
    }

    fn write_memory(&mut self, space: &str, offset: u64, bytes: &[u8]) {
        for (i, &byte) in bytes.iter().enumerate() {
            self.storage
                .insert((space.to_string(), offset + i as u64), byte);
        }
    }

    fn has_memory_state(&self, space: &str, offset: u64, len: u32) -> bool {
        for i in 0..len as u64 {
            if !self.storage.contains_key(&(space.to_string(), offset + i)) {
                return false;
            }
        }
        true
    }

    fn memory_state(&self, space: &str, offset: u64, len: u32) -> MemoryState {
        let mut known = 0u32;
        for i in 0..len as u64 {
            if self.storage.contains_key(&(space.to_string(), offset + i)) {
                known += 1;
            }
        }
        if known == 0 {
            MemoryState::Unknown
        } else if known == len {
            MemoryState::Known
        } else {
            MemoryState::Partial
        }
    }
}

/// Default implementation of `PcodeTraceRegistersAccess`.
#[derive(Debug, Default)]
pub struct DefaultPcodeTraceRegistersAccess {
    /// Register values indexed by name.
    registers: BTreeMap<String, Vec<u8>>,
    /// The snap context.
    #[allow(dead_code)]
    snap: i64,
}

impl DefaultPcodeTraceRegistersAccess {
    /// Create a new default register access.
    pub fn new(snap: i64) -> Self {
        Self {
            registers: BTreeMap::new(),
            snap,
        }
    }
}

impl PcodeTraceRegistersAccess for DefaultPcodeTraceRegistersAccess {
    fn read_register(&self, name: &str) -> Option<Vec<u8>> {
        self.registers.get(name).cloned()
    }

    fn write_register(&mut self, name: &str, bytes: &[u8]) {
        self.registers.insert(name.to_string(), bytes.to_vec());
    }

    fn has_register_state(&self, name: &str) -> bool {
        self.registers.contains_key(name)
    }

    fn known_registers(&self) -> Vec<String> {
        self.registers.keys().cloned().collect()
    }
}

/// Default implementation of `PcodeTracePropertyAccess`.
#[derive(Debug, Default)]
pub struct DefaultPcodeTracePropertyAccess {
    strings: BTreeMap<String, String>,
    ints: BTreeMap<String, i64>,
    bools: BTreeMap<String, bool>,
}

impl PcodeTracePropertyAccess for DefaultPcodeTracePropertyAccess {
    fn get_string_property(&self, name: &str) -> Option<String> {
        self.strings.get(name).cloned()
    }

    fn set_string_property(&mut self, name: &str, value: &str) {
        self.strings.insert(name.to_string(), value.to_string());
    }

    fn get_int_property(&self, name: &str) -> Option<i64> {
        self.ints.get(name).copied()
    }

    fn set_int_property(&mut self, name: &str, value: i64) {
        self.ints.insert(name.to_string(), value);
    }

    fn get_bool_property(&self, name: &str) -> Option<bool> {
        self.bools.get(name).copied()
    }

    fn set_bool_property(&mut self, name: &str, value: bool) {
        self.bools.insert(name.to_string(), value);
    }

    fn remove_property(&mut self, name: &str) {
        self.strings.remove(name);
        self.ints.remove(name);
        self.bools.remove(name);
    }
}

/// Default implementation combining all access interfaces.
pub struct DefaultPcodeTraceAccess {
    snap: i64,
    thread_id: u64,
    memory: DefaultPcodeTraceMemoryAccess,
    registers: DefaultPcodeTraceRegistersAccess,
}

impl DefaultPcodeTraceAccess {
    /// Create a new default pcode trace access.
    pub fn new(snap: i64, thread_id: u64) -> Self {
        Self {
            snap,
            thread_id,
            memory: DefaultPcodeTraceMemoryAccess::new(snap),
            registers: DefaultPcodeTraceRegistersAccess::new(snap),
        }
    }
}

impl PcodeTraceAccess for DefaultPcodeTraceAccess {
    fn snap(&self) -> i64 {
        self.snap
    }

    fn thread_id(&self) -> u64 {
        self.thread_id
    }

    fn memory(&self) -> &dyn PcodeTraceMemoryAccess {
        &self.memory
    }

    fn memory_mut(&mut self) -> &mut dyn PcodeTraceMemoryAccess {
        &mut self.memory
    }

    fn registers(&self) -> &dyn PcodeTraceRegistersAccess {
        &self.registers
    }

    fn registers_mut(&mut self) -> &mut dyn PcodeTraceRegistersAccess {
        &mut self.registers
    }
}

impl PcodeTraceDataAccess for DefaultPcodeTraceAccess {
    fn read_varnode(&self, varnode: &VarnodeDescriptor) -> Option<Vec<u8>> {
        if varnode.space == "register" {
            // Registers are addressed by offset, but we use name-based access
            // This is a simplification; real Ghidra uses register name lookup
            None
        } else {
            self.memory.read_memory(&varnode.space, varnode.offset, varnode.size)
        }
    }

    fn write_varnode(&mut self, varnode: &VarnodeDescriptor, bytes: &[u8]) {
        if varnode.space != "register" {
            self.memory.write_memory(&varnode.space, varnode.offset, bytes);
        }
    }

    fn has_state(&self, varnode: &VarnodeDescriptor) -> bool {
        if varnode.space == "register" {
            false
        } else {
            self.memory.has_memory_state(&varnode.space, varnode.offset, varnode.size)
        }
    }
}

/// Internal access interface for pcode trace data.
///
/// Extends the basic data access with internal database operations.
pub trait InternalPcodeTraceDataAccess: PcodeTraceDataAccess {
    /// Get the trace object key.
    fn trace_key(&self) -> i64;

    /// Get the database connection.
    fn is_valid(&self) -> bool;

    /// Flush pending writes to the database.
    fn flush(&mut self);
}

/// Tracks which addresses were read during pcode execution.
///
/// This is used to determine which memory regions a pcode program
/// actually accesses, which is essential for dependency analysis
/// and incremental re-execution.
///
/// Ported from Ghidra's `AddressesReadTracePcodeExecutorStatePiece`.
#[derive(Debug, Default)]
pub struct AddressesReadTracker {
    /// Set of (space, offset, size) varnodes that were read.
    read_addresses: BTreeSet<(String, u64, u32)>,
    /// Set of (space, offset) addresses that were written.
    written_addresses: BTreeSet<(String, u64)>,
}

impl AddressesReadTracker {
    /// Create a new tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a memory read.
    pub fn record_read(&mut self, space: &str, offset: u64, size: u32) {
        self.read_addresses
            .insert((space.to_string(), offset, size));
    }

    /// Record a register read.
    pub fn record_register_read(&mut self, name: &str, size: u32) {
        self.read_addresses
            .insert(("register".to_string(), name.len() as u64, size));
    }

    /// Record a memory write.
    pub fn record_write(&mut self, space: &str, offset: u64) {
        self.written_addresses
            .insert((space.to_string(), offset));
    }

    /// Get all addresses that were read.
    pub fn read_addresses(&self) -> &BTreeSet<(String, u64, u32)> {
        &self.read_addresses
    }

    /// Get all addresses that were written.
    pub fn written_addresses(&self) -> &BTreeSet<(String, u64)> {
        &self.written_addresses
    }

    /// Check if any address in the given range was read.
    pub fn was_any_read(&self, space: &str, offset: u64, len: u64) -> bool {
        self.read_addresses.iter().any(|(s, o, _sz)| {
            s == space && *o >= offset && *o < offset + len
        })
    }

    /// Clear all recorded accesses.
    pub fn clear(&mut self) {
        self.read_addresses.clear();
        self.written_addresses.clear();
    }

    /// Get the total number of recorded reads.
    pub fn read_count(&self) -> usize {
        self.read_addresses.len()
    }

    /// Get the total number of recorded writes.
    pub fn write_count(&self) -> usize {
        self.written_addresses.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varnode_descriptor() {
        let vn = VarnodeDescriptor::new("ram", 0x1000, 4);
        assert_eq!(vn.space, "ram");
        assert_eq!(vn.offset, 0x1000);
        assert_eq!(vn.size, 4);
    }

    #[test]
    fn test_default_memory_access() {
        let mut mem = DefaultPcodeTraceMemoryAccess::new(0);
        mem.write_memory("ram", 0x1000, &[0x90, 0xCC, 0xFF]);

        let bytes = mem.read_memory("ram", 0x1000, 3);
        assert_eq!(bytes, Some(vec![0x90, 0xCC, 0xFF]));

        assert!(mem.has_memory_state("ram", 0x1000, 3));
        assert!(!mem.has_memory_state("ram", 0x1000, 4));
        assert_eq!(mem.memory_state("ram", 0x1000, 3), MemoryState::Known);
        assert_eq!(mem.memory_state("ram", 0x2000, 1), MemoryState::Unknown);
    }

    #[test]
    fn test_default_register_access() {
        let mut regs = DefaultPcodeTraceRegistersAccess::new(0);
        regs.write_register("EAX", &[0x78, 0x56, 0x34, 0x12]);

        let val = regs.read_register("EAX");
        assert_eq!(val, Some(vec![0x78, 0x56, 0x34, 0x12]));

        assert!(regs.has_register_state("EAX"));
        assert!(!regs.has_register_state("EBX"));

        let known = regs.known_registers();
        assert!(known.contains(&"EAX".to_string()));
    }

    #[test]
    fn test_default_combined_access() {
        let mut access = DefaultPcodeTraceAccess::new(0, 1);
        assert_eq!(access.snap(), 0);
        assert_eq!(access.thread_id(), 1);

        access.memory_mut().write_memory("ram", 0x400000, &[0xEB, 0xFE]);
        let bytes = access.memory().read_memory("ram", 0x400000, 2);
        assert_eq!(bytes, Some(vec![0xEB, 0xFE]));
    }

    #[test]
    fn test_varnode_access() {
        let mut access = DefaultPcodeTraceAccess::new(0, 0);
        let vn = VarnodeDescriptor::new("ram", 0x1000, 4);
        access.write_varnode(&vn, &[0x01, 0x02, 0x03, 0x04]);

        let data = access.read_varnode(&vn);
        assert_eq!(data, Some(vec![0x01, 0x02, 0x03, 0x04]));
        assert!(access.has_state(&vn));
    }

    #[test]
    fn test_property_access() {
        let mut props = DefaultPcodeTracePropertyAccess::default();
        props.set_string_property("name", "test");
        props.set_int_property("count", 42);
        props.set_bool_property("active", true);

        assert_eq!(props.get_string_property("name"), Some("test".into()));
        assert_eq!(props.get_int_property("count"), Some(42));
        assert_eq!(props.get_bool_property("active"), Some(true));
        assert!(props.get_string_property("missing").is_none());

        props.remove_property("name");
        assert!(props.get_string_property("name").is_none());
    }

    #[test]
    fn test_addresses_read_tracker() {
        let mut tracker = AddressesReadTracker::new();
        tracker.record_read("ram", 0x1000, 4);
        tracker.record_read("ram", 0x1004, 4);
        tracker.record_write("ram", 0x2000);

        assert_eq!(tracker.read_count(), 2);
        assert_eq!(tracker.write_count(), 1);
        assert!(tracker.was_any_read("ram", 0x0FFF, 6));
        assert!(!tracker.was_any_read("ram", 0x2000, 1));

        tracker.clear();
        assert_eq!(tracker.read_count(), 0);
    }
}
