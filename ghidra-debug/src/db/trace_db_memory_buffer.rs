//! Memory buffer for reading trace memory at a specific snap.
//!
//! Ported from Ghidra's `DBTraceMemBuffer` and `DBTraceEmptyMemBuffer`
//! in `ghidra.trace.database.memory`. Provides the MemBuffer interface
//! for reading bytes from trace memory.

use crate::model::TraceMemoryState;

/// A memory buffer that reads from a trace memory space at a specific snap.
///
/// Ported from Ghidra's `DBTraceMemBuffer`.
#[derive(Debug)]
pub struct DbTraceMemBuffer {
    /// The address space name.
    pub space: String,
    /// The base address offset.
    pub base_offset: u64,
    /// Cached bytes read from memory.
    bytes: Vec<u8>,
    /// Start offset of the cached range.
    cache_start: u64,
}

impl DbTraceMemBuffer {
    /// Create a new memory buffer from raw bytes.
    pub fn new(space: impl Into<String>, base_offset: u64, bytes: Vec<u8>) -> Self {
        Self {
            space: space.into(),
            base_offset,
            cache_start: base_offset,
            bytes,
        }
    }

    /// Create an empty memory buffer (all unknown bytes).
    pub fn empty(space: impl Into<String>, base_offset: u64, size: usize) -> Self {
        Self {
            space: space.into(),
            base_offset,
            cache_start: base_offset,
            bytes: vec![0u8; size],
        }
    }

    /// Get a byte at the given offset relative to the base.
    pub fn get_byte(&self, offset: u64) -> Option<u8> {
        let idx = (offset - self.cache_start) as usize;
        self.bytes.get(idx).copied()
    }

    /// Get bytes starting at the given offset.
    pub fn get_bytes(&self, offset: u64, len: usize) -> Vec<u8> {
        let start = (offset - self.cache_start) as usize;
        let end = (start + len).min(self.bytes.len());
        if start >= self.bytes.len() {
            return vec![0u8; len];
        }
        self.bytes[start..end].to_vec()
    }

    /// Get the absolute address of a relative offset.
    pub fn absolute_address(&self, offset: u64) -> u64 {
        self.base_offset + offset
    }
}

/// An empty memory buffer that returns zeros for all reads.
///
/// Ported from Ghidra's `DBTraceEmptyMemBuffer`.
#[derive(Debug, Clone)]
pub struct DbTraceEmptyMemBuffer {
    /// The address space name.
    pub space: String,
    /// The base address offset.
    pub base_offset: u64,
}

impl DbTraceEmptyMemBuffer {
    /// Create a new empty memory buffer.
    pub fn new(space: impl Into<String>, base_offset: u64) -> Self {
        Self {
            space: space.into(),
            base_offset,
        }
    }

    /// Get a byte (always returns 0 for empty buffer).
    pub fn get_byte(&self, _offset: u64) -> u8 {
        0
    }

    /// Get bytes (always returns zeros).
    pub fn get_bytes(&self, _offset: u64, len: usize) -> Vec<u8> {
        vec![0u8; len]
    }
}

/// Memory state query result for a specific address.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryStateQueryResult {
    /// The memory state.
    pub state: TraceMemoryState,
    /// The snap range where this state applies.
    pub min_snap: i64,
    pub max_snap: i64,
    /// The address range where this state applies.
    pub min_offset: u64,
    pub max_offset: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mem_buffer_creation() {
        let buf = DbTraceMemBuffer::new("ram", 0x1000, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(buf.space, "ram");
        assert_eq!(buf.base_offset, 0x1000);
        assert_eq!(buf.get_byte(0x1000), Some(0xAA));
        assert_eq!(buf.get_byte(0x1001), Some(0xBB));
    }

    #[test]
    fn test_mem_buffer_empty() {
        let buf = DbTraceMemBuffer::empty("ram", 0x1000, 4);
        assert_eq!(buf.bytes.len(), 4);
        assert_eq!(buf.get_byte(0x1000), Some(0));
    }

    #[test]
    fn test_mem_buffer_get_bytes() {
        let buf = DbTraceMemBuffer::new("ram", 0x1000, vec![1, 2, 3, 4, 5]);
        let bytes = buf.get_bytes(0x1001, 3);
        assert_eq!(bytes, vec![2, 3, 4]);
    }

    #[test]
    fn test_empty_mem_buffer() {
        let buf = DbTraceEmptyMemBuffer::new("ram", 0x1000);
        assert_eq!(buf.get_byte(0x1000), 0);
        assert_eq!(buf.get_bytes(0x1000, 4), vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_mem_buffer_absolute_address() {
        let buf = DbTraceMemBuffer::new("ram", 0x1000, vec![0xAA]);
        assert_eq!(buf.absolute_address(0), 0x1000);
        assert_eq!(buf.absolute_address(5), 0x1005);
    }
}
