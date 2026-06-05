//! Memory space input stream for trace data.
//!
//! Ported from Ghidra's `TraceMemorySpaceInputStream` in
//! `ghidra.trace.model.memory`. Provides an InputStream-like
//! interface for reading bytes from a trace memory space at
//! a given snapshot.

use serde::{Deserialize, Serialize};

/// An input stream for reading bytes from a trace memory space.
///
/// Reads bytes sequentially from a starting address at a given snap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceMemorySpaceInputStream {
    /// The current read position.
    pub position: u64,
    /// The maximum address (exclusive limit).
    pub limit: u64,
    /// The snap to read from.
    pub snap: i64,
    /// The address space name.
    pub space: String,
    /// Buffered data for reads.
    buffer: Vec<u8>,
    /// Buffer base address.
    buffer_base: u64,
}

impl TraceMemorySpaceInputStream {
    /// Create a new input stream.
    pub fn new(space: impl Into<String>, snap: i64, start: u64, limit: u64) -> Self {
        Self {
            position: start,
            limit,
            snap,
            space: space.into(),
            buffer: Vec::new(),
            buffer_base: 0,
        }
    }

    /// Get the number of bytes available to read.
    pub fn available(&self) -> u64 {
        self.limit.saturating_sub(self.position)
    }

    /// Get the current position.
    pub fn position(&self) -> u64 {
        self.position
    }

    /// Set the buffer data for the current position.
    pub fn set_buffer(&mut self, base: u64, data: Vec<u8>) {
        self.buffer_base = base;
        self.buffer = data;
    }

    /// Read a single byte.
    pub fn read_byte(&mut self) -> Option<u8> {
        if self.position >= self.limit {
            return None;
        }
        let offset = (self.position - self.buffer_base) as usize;
        let byte = self.buffer.get(offset).copied();
        if byte.is_some() {
            self.position += 1;
        }
        byte
    }

    /// Read multiple bytes into a buffer.
    pub fn read_bytes(&mut self, count: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(count);
        for _ in 0..count {
            if let Some(byte) = self.read_byte() {
                result.push(byte);
            } else {
                break;
            }
        }
        result
    }

    /// Skip a number of bytes.
    pub fn skip(&mut self, count: u64) -> u64 {
        let available = self.available();
        let to_skip = count.min(available);
        self.position += to_skip;
        to_skip
    }

    /// Reset the position to the start.
    pub fn reset(&mut self, start: u64) {
        self.position = start;
    }

    /// Check if the stream has more data.
    pub fn has_more(&self) -> bool {
        self.position < self.limit
    }
}

/// A register value stream for reading register values from a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRegisterValueStream {
    /// The register name.
    pub register: String,
    /// The register size in bytes.
    pub size: usize,
    /// The snap to read from.
    pub snap: i64,
    /// The thread key.
    pub thread_key: Option<i64>,
}

impl TraceRegisterValueStream {
    /// Create a new register value stream.
    pub fn new(register: impl Into<String>, size: usize, snap: i64) -> Self {
        Self {
            register: register.into(),
            size,
            snap,
            thread_key: None,
        }
    }

    /// Set the thread context.
    pub fn with_thread(mut self, thread_key: i64) -> Self {
        self.thread_key = Some(thread_key);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_input_stream_new() {
        let stream = TraceMemorySpaceInputStream::new("ram", 0, 0x1000, 0x2000);
        assert_eq!(stream.available(), 0x1000);
        assert_eq!(stream.position(), 0x1000);
        assert!(stream.has_more());
    }

    #[test]
    fn test_input_stream_read_byte() {
        let mut stream = TraceMemorySpaceInputStream::new("ram", 0, 0x1000, 0x1004);
        stream.set_buffer(0x1000, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(stream.read_byte(), Some(0xAA));
        assert_eq!(stream.read_byte(), Some(0xBB));
        assert_eq!(stream.position(), 0x1002);
    }

    #[test]
    fn test_input_stream_read_bytes() {
        let mut stream = TraceMemorySpaceInputStream::new("ram", 0, 0, 10);
        stream.set_buffer(0, vec![1, 2, 3, 4, 5]);
        let data = stream.read_bytes(3);
        assert_eq!(data, vec![1, 2, 3]);
        assert_eq!(stream.position(), 3);
    }

    #[test]
    fn test_input_stream_exhausted() {
        let mut stream = TraceMemorySpaceInputStream::new("ram", 0, 0, 2);
        stream.set_buffer(0, vec![1, 2]);
        stream.read_byte();
        stream.read_byte();
        assert!(stream.read_byte().is_none());
        assert!(!stream.has_more());
        assert_eq!(stream.available(), 0);
    }

    #[test]
    fn test_input_stream_skip() {
        let mut stream = TraceMemorySpaceInputStream::new("ram", 0, 0, 100);
        let skipped = stream.skip(50);
        assert_eq!(skipped, 50);
        assert_eq!(stream.position(), 50);
    }

    #[test]
    fn test_input_stream_reset() {
        let mut stream = TraceMemorySpaceInputStream::new("ram", 0, 0x1000, 0x2000);
        stream.set_buffer(0x1000, vec![1]);
        stream.read_byte();
        stream.reset(0x1000);
        assert_eq!(stream.position(), 0x1000);
    }

    #[test]
    fn test_register_value_stream() {
        let rvs = TraceRegisterValueStream::new("rax", 8, 0).with_thread(1);
        assert_eq!(rvs.register, "rax");
        assert_eq!(rvs.size, 8);
        assert_eq!(rvs.thread_key, Some(1));
    }
}
