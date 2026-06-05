//! Memory buffer types for the trace database.
//!
//! Ported from Ghidra's `DBTraceMemBuffer` and `DBTraceEmptyMemBuffer`.
//!
//! Provides memory buffer abstractions for reading bytes from trace memory
//! at specific addresses and snaps.

use crate::model::memory::TraceMemoryState;

/// A buffer for reading memory bytes from a trace.
///
/// Provides a view into trace memory at a specific address and snap,
/// allowing byte-level access to memory contents.
#[derive(Debug, Clone)]
pub struct DBTraceMemBuffer {
    /// The address space name.
    space_name: String,
    /// The starting offset.
    offset: u64,
    /// The snap (time) for this buffer.
    snap: i64,
    /// The buffer data.
    data: Vec<u8>,
    /// Memory state for each byte (known, unknown, etc.).
    states: Vec<TraceMemoryState>,
}

impl DBTraceMemBuffer {
    /// Create a new memory buffer.
    pub fn new(space_name: impl Into<String>, offset: u64, snap: i64) -> Self {
        Self {
            space_name: space_name.into(),
            offset,
            snap,
            data: Vec::new(),
            states: Vec::new(),
        }
    }

    /// Create a memory buffer with initial data.
    pub fn with_data(
        space_name: impl Into<String>,
        offset: u64,
        snap: i64,
        data: Vec<u8>,
    ) -> Self {
        let states = vec![TraceMemoryState::Known; data.len()];
        Self {
            space_name: space_name.into(),
            offset,
            snap,
            data,
            states,
        }
    }

    /// Get the address space name.
    pub fn space_name(&self) -> &str {
        &self.space_name
    }

    /// Get the starting offset.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Get the snap.
    pub fn snap(&self) -> i64 {
        self.snap
    }

    /// Get the data bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the memory states.
    pub fn states(&self) -> &[TraceMemoryState] {
        &self.states
    }

    /// Get the length of the buffer in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get a byte at the given relative offset.
    pub fn get_byte(&self, rel_offset: usize) -> Option<u8> {
        self.data.get(rel_offset).copied()
    }

    /// Get a byte's memory state at the given relative offset.
    pub fn get_state(&self, rel_offset: usize) -> Option<TraceMemoryState> {
        self.states.get(rel_offset).copied()
    }

    /// Set data in the buffer.
    pub fn set_data(&mut self, data: Vec<u8>) {
        self.states = vec![TraceMemoryState::Known; data.len()];
        self.data = data;
    }

    /// Set the state of a specific byte.
    pub fn set_state(&mut self, rel_offset: usize, state: TraceMemoryState) {
        if rel_offset < self.states.len() {
            self.states[rel_offset] = state;
        }
    }

    /// Read a u16 value (little-endian) at the given relative offset.
    pub fn read_u16_le(&self, rel_offset: usize) -> Option<u16> {
        if rel_offset + 2 <= self.data.len() {
            Some(u16::from_le_bytes([
                self.data[rel_offset],
                self.data[rel_offset + 1],
            ]))
        } else {
            None
        }
    }

    /// Read a u32 value (little-endian) at the given relative offset.
    pub fn read_u32_le(&self, rel_offset: usize) -> Option<u32> {
        if rel_offset + 4 <= self.data.len() {
            Some(u32::from_le_bytes([
                self.data[rel_offset],
                self.data[rel_offset + 1],
                self.data[rel_offset + 2],
                self.data[rel_offset + 3],
            ]))
        } else {
            None
        }
    }

    /// Read a u64 value (little-endian) at the given relative offset.
    pub fn read_u64_le(&self, rel_offset: usize) -> Option<u64> {
        if rel_offset + 8 <= self.data.len() {
            Some(u64::from_le_bytes([
                self.data[rel_offset],
                self.data[rel_offset + 1],
                self.data[rel_offset + 2],
                self.data[rel_offset + 3],
                self.data[rel_offset + 4],
                self.data[rel_offset + 5],
                self.data[rel_offset + 6],
                self.data[rel_offset + 7],
            ]))
        } else {
            None
        }
    }

    /// Read a u16 value (big-endian) at the given relative offset.
    pub fn read_u16_be(&self, rel_offset: usize) -> Option<u16> {
        if rel_offset + 2 <= self.data.len() {
            Some(u16::from_be_bytes([
                self.data[rel_offset],
                self.data[rel_offset + 1],
            ]))
        } else {
            None
        }
    }

    /// Read a u32 value (big-endian) at the given relative offset.
    pub fn read_u32_be(&self, rel_offset: usize) -> Option<u32> {
        if rel_offset + 4 <= self.data.len() {
            Some(u32::from_be_bytes([
                self.data[rel_offset],
                self.data[rel_offset + 1],
                self.data[rel_offset + 2],
                self.data[rel_offset + 3],
            ]))
        } else {
            None
        }
    }

    /// Read a u64 value (big-endian) at the given relative offset.
    pub fn read_u64_be(&self, rel_offset: usize) -> Option<u64> {
        if rel_offset + 8 <= self.data.len() {
            Some(u64::from_be_bytes([
                self.data[rel_offset],
                self.data[rel_offset + 1],
                self.data[rel_offset + 2],
                self.data[rel_offset + 3],
                self.data[rel_offset + 4],
                self.data[rel_offset + 5],
                self.data[rel_offset + 6],
                self.data[rel_offset + 7],
            ]))
        } else {
            None
        }
    }
}

/// An empty memory buffer.
///
/// Used when no memory data is available at a given address.
/// All reads return `None` and all states are `Unknown`.
#[derive(Debug, Clone)]
pub struct DBTraceEmptyMemBuffer {
    /// The address space name.
    space_name: String,
    /// The starting offset.
    offset: u64,
    /// The snap (time) for this buffer.
    snap: i64,
    /// The size of the empty buffer.
    size: usize,
}

impl DBTraceEmptyMemBuffer {
    /// Create a new empty memory buffer.
    pub fn new(space_name: impl Into<String>, offset: u64, snap: i64, size: usize) -> Self {
        Self {
            space_name: space_name.into(),
            offset,
            snap,
            size,
        }
    }

    /// Get the address space name.
    pub fn space_name(&self) -> &str {
        &self.space_name
    }

    /// Get the starting offset.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Get the snap.
    pub fn snap(&self) -> i64 {
        self.snap
    }

    /// Get the size.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get a byte (always returns None for empty buffers).
    pub fn get_byte(&self, _rel_offset: usize) -> Option<u8> {
        None
    }

    /// Get the state of a byte (always Unknown for empty buffers).
    pub fn get_state(&self, rel_offset: usize) -> TraceMemoryState {
        if rel_offset < self.size {
            TraceMemoryState::Unknown
        } else {
            TraceMemoryState::Unknown
        }
    }

    /// Convert to a filled memory buffer.
    pub fn to_mem_buffer(&self, data: Vec<u8>) -> DBTraceMemBuffer {
        DBTraceMemBuffer::with_data(&self.space_name, self.offset, self.snap, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mem_buffer_creation() {
        let buf = DBTraceMemBuffer::new("ram", 0x400000, 5);
        assert_eq!(buf.space_name(), "ram");
        assert_eq!(buf.offset(), 0x400000);
        assert_eq!(buf.snap(), 5);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_mem_buffer_with_data() {
        let buf = DBTraceMemBuffer::with_data("ram", 0x400000, 0, vec![0x55, 0xAA, 0xFF]);
        assert_eq!(buf.len(), 3);
        assert!(!buf.is_empty());
        assert_eq!(buf.get_byte(0), Some(0x55));
        assert_eq!(buf.get_byte(1), Some(0xAA));
        assert_eq!(buf.get_byte(2), Some(0xFF));
        assert_eq!(buf.get_byte(3), None);
    }

    #[test]
    fn test_mem_buffer_states() {
        let mut buf = DBTraceMemBuffer::with_data("ram", 0, 0, vec![0, 0, 0]);
        assert_eq!(buf.get_state(0), Some(TraceMemoryState::Known));
        buf.set_state(1, TraceMemoryState::Unknown);
        assert_eq!(buf.get_state(1), Some(TraceMemoryState::Unknown));
    }

    #[test]
    fn test_mem_buffer_read_le() {
        let buf = DBTraceMemBuffer::with_data("ram", 0, 0, vec![0x34, 0x12, 0x78, 0x56, 0xBC, 0x9A, 0xF0, 0xDE]);
        assert_eq!(buf.read_u16_le(0), Some(0x1234));
        assert_eq!(buf.read_u32_le(0), Some(0x56781234));
        assert_eq!(buf.read_u64_le(0), Some(0xDEF09ABC56781234));
        assert_eq!(buf.read_u32_le(5), None); // Not enough bytes
    }

    #[test]
    fn test_mem_buffer_read_be() {
        let buf = DBTraceMemBuffer::with_data("ram", 0, 0, vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]);
        assert_eq!(buf.read_u16_be(0), Some(0x1234));
        assert_eq!(buf.read_u32_be(0), Some(0x12345678));
        assert_eq!(buf.read_u64_be(0), Some(0x123456789ABCDEF0));
    }

    #[test]
    fn test_mem_buffer_set_data() {
        let mut buf = DBTraceMemBuffer::new("ram", 0, 0);
        assert!(buf.is_empty());
        buf.set_data(vec![1, 2, 3]);
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.data(), &[1, 2, 3]);
    }

    #[test]
    fn test_empty_mem_buffer() {
        let buf = DBTraceEmptyMemBuffer::new("ram", 0x400000, 5, 256);
        assert_eq!(buf.space_name(), "ram");
        assert_eq!(buf.offset(), 0x400000);
        assert_eq!(buf.snap(), 5);
        assert_eq!(buf.size(), 256);
        assert_eq!(buf.get_byte(0), None);
        assert_eq!(buf.get_state(0), TraceMemoryState::Unknown);
    }

    #[test]
    fn test_empty_mem_buffer_to_mem_buffer() {
        let empty = DBTraceEmptyMemBuffer::new("ram", 0x400000, 0, 4);
        let buf = empty.to_mem_buffer(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(buf.space_name(), "ram");
        assert_eq!(buf.offset(), 0x400000);
        assert_eq!(buf.data(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }
}
