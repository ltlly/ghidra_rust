//! Memory buffer and input stream abstractions for the trace model.
//!
//! Ported from Ghidra's `TraceMemorySpaceInputStream` and related types.
//!
//! Provides memory buffer abstractions used for reading bytes from
//! trace memory spaces, including support for reading across boundaries
//! and handling unknown memory states.

use crate::model::memory::TraceMemoryState;

/// A trait for reading bytes from a memory buffer.
pub trait MemBuffer: Send + Sync {
    /// Get the address space name.
    fn space_name(&self) -> &str;

    /// Get the starting offset of this buffer.
    fn offset(&self) -> u64;

    /// Get the snap (time) for this buffer.
    fn snap(&self) -> i64;

    /// Read a byte at the given relative offset.
    fn get_byte(&self, rel_offset: usize) -> Option<u8>;

    /// Get the memory state at the given relative offset.
    fn get_state(&self, rel_offset: usize) -> TraceMemoryState;

    /// Get the number of bytes in this buffer.
    fn len(&self) -> usize;

    /// Check if the buffer is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read multiple bytes starting at the given relative offset.
    fn get_bytes(&self, rel_offset: usize, count: usize) -> Vec<Option<u8>> {
        (0..count)
            .map(|i| self.get_byte(rel_offset + i))
            .collect()
    }

    /// Read all bytes that are available (known state).
    fn available_bytes(&self) -> Vec<u8> {
        (0..self.len())
            .filter_map(|i| {
                if self.get_state(i) == TraceMemoryState::Known {
                    self.get_byte(i)
                } else {
                    None
                }
            })
            .collect()
    }
}

/// A simple in-memory implementation of `MemBuffer`.
#[derive(Debug, Clone)]
pub struct SimpleMemBuffer {
    /// The address space name.
    space_name: String,
    /// The starting offset.
    offset: u64,
    /// The snap (time).
    snap: i64,
    /// The data bytes.
    data: Vec<u8>,
    /// The state of each byte.
    states: Vec<TraceMemoryState>,
}

impl SimpleMemBuffer {
    /// Create a new simple memory buffer with known data.
    pub fn new_known(
        space_name: impl Into<String>,
        offset: u64,
        snap: i64,
        data: Vec<u8>,
    ) -> Self {
        let len = data.len();
        Self {
            space_name: space_name.into(),
            offset,
            snap,
            data,
            states: vec![TraceMemoryState::Known; len],
        }
    }

    /// Create a new simple memory buffer with unknown data.
    pub fn new_unknown(
        space_name: impl Into<String>,
        offset: u64,
        snap: i64,
        size: usize,
    ) -> Self {
        Self {
            space_name: space_name.into(),
            offset,
            snap,
            data: vec![0; size],
            states: vec![TraceMemoryState::Unknown; size],
        }
    }

    /// Create a buffer with mixed states.
    pub fn new_mixed(
        space_name: impl Into<String>,
        offset: u64,
        snap: i64,
        data: Vec<u8>,
        states: Vec<TraceMemoryState>,
    ) -> Self {
        assert_eq!(data.len(), states.len(), "data and states must have same length");
        Self {
            space_name: space_name.into(),
            offset,
            snap,
            data,
            states,
        }
    }

    /// Set a byte at the given offset.
    pub fn set_byte(&mut self, rel_offset: usize, value: u8, state: TraceMemoryState) {
        if rel_offset < self.data.len() {
            self.data[rel_offset] = value;
            self.states[rel_offset] = state;
        }
    }
}

impl MemBuffer for SimpleMemBuffer {
    fn space_name(&self) -> &str {
        &self.space_name
    }

    fn offset(&self) -> u64 {
        self.offset
    }

    fn snap(&self) -> i64 {
        self.snap
    }

    fn get_byte(&self, rel_offset: usize) -> Option<u8> {
        self.data.get(rel_offset).copied()
    }

    fn get_state(&self, rel_offset: usize) -> TraceMemoryState {
        self.states
            .get(rel_offset)
            .copied()
            .unwrap_or(TraceMemoryState::Unknown)
    }

    fn len(&self) -> usize {
        self.data.len()
    }
}

/// A read-only memory buffer view that can be composed from multiple buffers.
#[derive(Debug, Clone)]
pub struct CompositeMemBuffer {
    /// The address space name.
    space_name: String,
    /// The starting offset.
    offset: u64,
    /// The snap (time).
    snap: i64,
    /// The underlying data and states.
    entries: Vec<(u64, u8, TraceMemoryState)>, // (absolute_offset, byte, state)
}

impl CompositeMemBuffer {
    /// Create a new composite memory buffer.
    pub fn new(space_name: impl Into<String>, offset: u64, snap: i64) -> Self {
        Self {
            space_name: space_name.into(),
            offset,
            snap,
            entries: Vec::new(),
        }
    }

    /// Add a byte at an absolute address.
    pub fn add_byte(&mut self, absolute_offset: u64, value: u8, state: TraceMemoryState) {
        self.entries.push((absolute_offset, value, state));
    }

    /// Sort entries by offset for efficient lookup.
    pub fn sort(&mut self) {
        self.entries.sort_by_key(|e| e.0);
    }
}

impl MemBuffer for CompositeMemBuffer {
    fn space_name(&self) -> &str {
        &self.space_name
    }

    fn offset(&self) -> u64 {
        self.offset
    }

    fn snap(&self) -> i64 {
        self.snap
    }

    fn get_byte(&self, rel_offset: usize) -> Option<u8> {
        let abs = self.offset + rel_offset as u64;
        self.entries.iter().find(|(o, _, _)| *o == abs).map(|(_, b, _)| *b)
    }

    fn get_state(&self, rel_offset: usize) -> TraceMemoryState {
        let abs = self.offset + rel_offset as u64;
        self.entries
            .iter()
            .find(|(o, _, _)| *o == abs)
            .map(|(_, _, s)| *s)
            .unwrap_or(TraceMemoryState::Unknown)
    }

    fn len(&self) -> usize {
        if self.entries.is_empty() {
            return 0;
        }
        let min = self.entries.iter().map(|e| e.0).min().unwrap_or(self.offset);
        let max = self.entries.iter().map(|e| e.0).max().unwrap_or(self.offset);
        (max - min + 1) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_mem_buffer_known() {
        let buf = SimpleMemBuffer::new_known("ram", 0x400000, 0, vec![0x55, 0xAA]);
        assert_eq!(buf.space_name(), "ram");
        assert_eq!(buf.offset(), 0x400000);
        assert_eq!(buf.snap(), 0);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.get_byte(0), Some(0x55));
        assert_eq!(buf.get_byte(1), Some(0xAA));
        assert_eq!(buf.get_byte(2), None);
        assert_eq!(buf.get_state(0), TraceMemoryState::Known);
    }

    #[test]
    fn test_simple_mem_buffer_unknown() {
        let buf = SimpleMemBuffer::new_unknown("ram", 0, 5, 4);
        assert_eq!(buf.len(), 4);
        assert_eq!(buf.get_state(0), TraceMemoryState::Unknown);
    }

    #[test]
    fn test_simple_mem_buffer_mixed() {
        let buf = SimpleMemBuffer::new_mixed(
            "ram",
            0,
            0,
            vec![0x90, 0x00, 0xFF],
            vec![
                TraceMemoryState::Known,
                TraceMemoryState::Unknown,
                TraceMemoryState::Known,
            ],
        );
        assert_eq!(buf.get_state(0), TraceMemoryState::Known);
        assert_eq!(buf.get_state(1), TraceMemoryState::Unknown);
        assert_eq!(buf.available_bytes(), vec![0x90, 0xFF]);
    }

    #[test]
    fn test_simple_mem_buffer_set_byte() {
        let mut buf = SimpleMemBuffer::new_known("ram", 0, 0, vec![0, 0, 0]);
        buf.set_byte(1, 0x42, TraceMemoryState::Known);
        assert_eq!(buf.get_byte(1), Some(0x42));
    }

    #[test]
    fn test_mem_buffer_get_bytes() {
        let buf = SimpleMemBuffer::new_known("ram", 0, 0, vec![1, 2, 3, 4, 5]);
        let bytes = buf.get_bytes(1, 3);
        assert_eq!(bytes, vec![Some(2), Some(3), Some(4)]);

        let bytes = buf.get_bytes(3, 5);
        assert_eq!(bytes.len(), 5);
        assert_eq!(bytes[0], Some(4));
        assert_eq!(bytes[1], Some(5));
        assert_eq!(bytes[2], None); // Out of bounds
    }

    #[test]
    fn test_composite_mem_buffer() {
        let mut buf = CompositeMemBuffer::new("ram", 0x400000, 0);
        buf.add_byte(0x400000, 0x90, TraceMemoryState::Known);
        buf.add_byte(0x400001, 0xEB, TraceMemoryState::Known);
        buf.add_byte(0x400002, 0xFE, TraceMemoryState::Unknown);
        buf.sort();

        assert_eq!(buf.len(), 3);
        assert_eq!(buf.get_byte(0), Some(0x90));
        assert_eq!(buf.get_byte(1), Some(0xEB));
        assert_eq!(buf.get_state(2), TraceMemoryState::Unknown);
    }

    #[test]
    fn test_composite_mem_buffer_empty() {
        let buf = CompositeMemBuffer::new("ram", 0, 0);
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
    }
}
