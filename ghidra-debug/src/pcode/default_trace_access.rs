//! DefaultPcodeTraceAccess - default implementations of p-code trace access.
//!
//! Ported from Ghidra's `DefaultPcodeTraceAccess`, `DefaultPcodeTraceMemoryAccess`,
//! `DefaultPcodeTraceRegistersAccess`, and related types in
//! `ghidra.pcode.exec.trace.data`.
//!
//! These provide default implementations of the trace data access interfaces
//! used during p-code emulation, providing the layer between the p-code
//! executor and the trace database.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// The type of data being accessed in a trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceDataKind {
    /// Memory data (code, stack, heap).
    Memory,
    /// Register data.
    Register,
    /// Property data (e.g., context register values).
    Property,
    /// Thread-local storage.
    ThreadLocal,
}

/// A single data access record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDataRecord {
    /// The address or offset.
    pub offset: u64,
    /// The size in bytes.
    pub size: u32,
    /// The value bytes.
    pub value: Vec<u8>,
    /// The data kind.
    pub kind: TraceDataKind,
    /// Whether this record was written (dirty).
    pub dirty: bool,
}

impl TraceDataRecord {
    /// Create a new data record.
    pub fn new(offset: u64, size: u32, value: Vec<u8>, kind: TraceDataKind) -> Self {
        Self {
            offset,
            size,
            value,
            kind,
            dirty: false,
        }
    }

    /// Create a memory read record.
    pub fn memory(offset: u64, value: Vec<u8>) -> Self {
        let size = value.len() as u32;
        Self::new(offset, size, value, TraceDataKind::Memory)
    }

    /// Create a register read record.
    pub fn register(offset: u64, value: Vec<u8>) -> Self {
        let size = value.len() as u32;
        Self::new(offset, size, value, TraceDataKind::Register)
    }

    /// Mark this record as dirty (modified).
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Get the end offset.
    pub fn end_offset(&self) -> u64 {
        self.offset + self.size as u64
    }

    /// Whether this record overlaps with a given range.
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.offset < end && start < self.end_offset()
    }
}

/// Default implementation of p-code trace memory access.
///
/// Ported from Ghidra's `DefaultPcodeTraceMemoryAccess`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefaultPcodeTraceMemoryAccess {
    /// Cached memory reads.
    pub cache: IndexMap<u64, TraceDataRecord>,
    /// The snap being accessed.
    pub snap: i64,
    /// Pending writes (not yet committed).
    pub pending_writes: Vec<TraceDataRecord>,
}

impl DefaultPcodeTraceMemoryAccess {
    /// Create a new memory access.
    pub fn new(snap: i64) -> Self {
        Self {
            cache: IndexMap::new(),
            snap,
            pending_writes: Vec::new(),
        }
    }

    /// Cache a memory read.
    pub fn cache_read(&mut self, record: TraceDataRecord) {
        self.cache.insert(record.offset, record);
    }

    /// Read from cache.
    pub fn cached_read(&self, offset: u64) -> Option<&TraceDataRecord> {
        self.cache.get(&offset)
    }

    /// Queue a write.
    pub fn queue_write(&mut self, mut record: TraceDataRecord) {
        record.mark_dirty();
        self.pending_writes.push(record);
    }

    /// Get the number of pending writes.
    pub fn pending_write_count(&self) -> usize {
        self.pending_writes.len()
    }

    /// Drain and return pending writes.
    pub fn drain_pending_writes(&mut self) -> Vec<TraceDataRecord> {
        std::mem::take(&mut self.pending_writes)
    }

    /// Clear the cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Cache size.
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

/// Default implementation of p-code trace registers access.
///
/// Ported from Ghidra's `DefaultPcodeTraceRegistersAccess`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefaultPcodeTraceRegistersAccess {
    /// Register values cached from the trace.
    pub register_cache: IndexMap<String, Vec<u8>>,
    /// The snap being accessed.
    pub snap: i64,
    /// The thread ID for this register context.
    pub thread_id: u64,
    /// The frame level.
    pub frame_level: u32,
    /// Dirty register values (pending writeback).
    pub dirty_registers: IndexMap<String, Vec<u8>>,
}

impl DefaultPcodeTraceRegistersAccess {
    /// Create a new register access.
    pub fn new(snap: i64, thread_id: u64, frame_level: u32) -> Self {
        Self {
            register_cache: IndexMap::new(),
            snap,
            thread_id,
            frame_level,
            dirty_registers: IndexMap::new(),
        }
    }

    /// Cache a register value.
    pub fn cache_register(&mut self, name: impl Into<String>, value: Vec<u8>) {
        self.register_cache.insert(name.into(), value);
    }

    /// Read a register from cache.
    pub fn read_register(&self, name: &str) -> Option<&[u8]> {
        self.register_cache.get(name).map(|v| v.as_slice())
    }

    /// Write a register value (marks as dirty).
    pub fn write_register(&mut self, name: impl Into<String>, value: Vec<u8>) {
        let name = name.into();
        self.register_cache.insert(name.clone(), value.clone());
        self.dirty_registers.insert(name, value);
    }

    /// Get dirty register names.
    pub fn dirty_names(&self) -> Vec<&str> {
        self.dirty_registers.keys().map(|s| s.as_str()).collect()
    }

    /// Drain dirty registers for writeback.
    pub fn drain_dirty(&mut self) -> IndexMap<String, Vec<u8>> {
        std::mem::take(&mut self.dirty_registers)
    }

    /// Clear all caches.
    pub fn clear(&mut self) {
        self.register_cache.clear();
        self.dirty_registers.clear();
    }
}

/// Combined default p-code trace access.
///
/// Ported from Ghidra's `DefaultPcodeTraceAccess`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultPcodeTraceAccess {
    /// Memory access.
    pub memory: DefaultPcodeTraceMemoryAccess,
    /// Register access.
    pub registers: DefaultPcodeTraceRegistersAccess,
}

impl DefaultPcodeTraceAccess {
    /// Create a new combined access.
    pub fn new(snap: i64, thread_id: u64, frame_level: u32) -> Self {
        Self {
            memory: DefaultPcodeTraceMemoryAccess::new(snap),
            registers: DefaultPcodeTraceRegistersAccess::new(snap, thread_id, frame_level),
        }
    }

    /// Get shared state access (memory).
    pub fn get_data_for_shared_state(&self) -> &DefaultPcodeTraceMemoryAccess {
        &self.memory
    }

    /// Get local state access (registers).
    pub fn get_data_for_local_state(&self) -> &DefaultPcodeTraceRegistersAccess {
        &self.registers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_data_record() {
        let record = TraceDataRecord::memory(0x1000, vec![0x90, 0x90]);
        assert_eq!(record.offset, 0x1000);
        assert_eq!(record.size, 2);
        assert!(!record.dirty);
        assert_eq!(record.end_offset(), 0x1002);
    }

    #[test]
    fn test_trace_data_record_overlaps() {
        let record = TraceDataRecord::memory(0x1000, vec![0; 4]);
        assert!(record.overlaps(0x1000, 0x1004));
        assert!(record.overlaps(0x1002, 0x1006));
        assert!(!record.overlaps(0x1004, 0x1008));
    }

    #[test]
    fn test_memory_access_cache() {
        let mut access = DefaultPcodeTraceMemoryAccess::new(5);
        access.cache_read(TraceDataRecord::memory(0x1000, vec![0x90]));
        assert_eq!(access.cache_size(), 1);

        let cached = access.cached_read(0x1000);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().value, vec![0x90]);
    }

    #[test]
    fn test_memory_access_writes() {
        let mut access = DefaultPcodeTraceMemoryAccess::new(5);
        access.queue_write(TraceDataRecord::memory(0x2000, vec![0xCC]));
        assert_eq!(access.pending_write_count(), 1);

        let writes = access.drain_pending_writes();
        assert_eq!(writes.len(), 1);
        assert!(writes[0].dirty);
        assert_eq!(access.pending_write_count(), 0);
    }

    #[test]
    fn test_register_access() {
        let mut access = DefaultPcodeTraceRegistersAccess::new(5, 1, 0);
        access.cache_register("RAX", vec![0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0]);

        let val = access.read_register("RAX").unwrap();
        assert_eq!(val.len(), 8);
        assert!(access.read_register("RBX").is_none());
    }

    #[test]
    fn test_register_write_dirty() {
        let mut access = DefaultPcodeTraceRegistersAccess::new(5, 1, 0);
        access.write_register("RAX", vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(access.dirty_names(), vec!["RAX"]);

        let dirty = access.drain_dirty();
        assert_eq!(dirty.len(), 1);
        assert!(access.dirty_names().is_empty());
    }

    #[test]
    fn test_combined_access() {
        let access = DefaultPcodeTraceAccess::new(5, 1, 0);
        assert_eq!(access.memory.snap, 5);
        assert_eq!(access.registers.thread_id, 1);
        assert_eq!(access.registers.frame_level, 0);
    }

    #[test]
    fn test_data_record_register() {
        let record = TraceDataRecord::register(0, vec![0xFF; 8]);
        assert_eq!(record.kind, TraceDataKind::Register);
        assert_eq!(record.size, 8);
    }

    #[test]
    fn test_data_record_mark_dirty() {
        let mut record = TraceDataRecord::memory(0x1000, vec![0]);
        assert!(!record.dirty);
        record.mark_dirty();
        assert!(record.dirty);
    }

    #[test]
    fn test_memory_access_clear_cache() {
        let mut access = DefaultPcodeTraceMemoryAccess::new(5);
        access.cache_read(TraceDataRecord::memory(0x1000, vec![0]));
        assert_eq!(access.cache_size(), 1);
        access.clear_cache();
        assert_eq!(access.cache_size(), 0);
    }

    #[test]
    fn test_register_access_clear() {
        let mut access = DefaultPcodeTraceRegistersAccess::new(5, 1, 0);
        access.write_register("RAX", vec![0; 8]);
        access.clear();
        assert!(access.dirty_names().is_empty());
        assert!(access.read_register("RAX").is_none());
    }
}
