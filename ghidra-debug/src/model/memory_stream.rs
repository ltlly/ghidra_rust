//! Memory input stream for reading bytes from trace memory spaces.
//!
//! Ported from Ghidra's `TraceMemorySpaceInputStream` in
//! `ghidra.trace.model.memory`.
//!
//! Provides an `std::io::Read`-compatible interface for reading
//! sequential bytes from a trace memory space at a given snap.

use std::io::{self, Read};

/// An input stream that reads bytes from a trace memory space.
///
/// Ported from Ghidra's `TraceMemorySpaceInputStream`.
pub struct TraceMemorySpaceInputStream {
    /// The underlying byte buffer.
    buffer: Vec<u8>,
    /// Current read position.
    position: usize,
}

impl TraceMemorySpaceInputStream {
    /// Create a new memory input stream from a byte buffer.
    pub fn new(buffer: Vec<u8>) -> Self {
        Self {
            buffer,
            position: 0,
        }
    }

    /// Create a stream from a slice.
    pub fn from_slice(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }

    /// Create an empty stream.
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Get the total length of the buffer.
    pub fn total_len(&self) -> usize {
        self.buffer.len()
    }

    /// Get the number of remaining bytes.
    pub fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.position)
    }

    /// Get the current position.
    pub fn position(&self) -> usize {
        self.position
    }

    /// Whether the stream has been fully consumed.
    pub fn is_consumed(&self) -> bool {
        self.position >= self.buffer.len()
    }

    /// Read a fixed-size chunk from the stream.
    pub fn read_chunk(&mut self, size: usize) -> Option<&[u8]> {
        if self.position + size > self.buffer.len() {
            return None;
        }
        let start = self.position;
        self.position += size;
        Some(&self.buffer[start..self.position])
    }

    /// Read a null-terminated string from the stream.
    pub fn read_null_terminated_string(&mut self) -> Option<String> {
        let start = self.position;
        while self.position < self.buffer.len() {
            if self.buffer[self.position] == 0 {
                let s = String::from_utf8_lossy(&self.buffer[start..self.position]).to_string();
                self.position += 1; // skip null terminator
                return Some(s);
            }
            self.position += 1;
        }
        // No null terminator found; return what we have
        if start < self.buffer.len() {
            let s = String::from_utf8_lossy(&self.buffer[start..]).to_string();
            self.position = self.buffer.len();
            return Some(s);
        }
        None
    }

    /// Read a u8 value from the stream.
    pub fn read_u8(&mut self) -> Option<u8> {
        if self.position < self.buffer.len() {
            let val = self.buffer[self.position];
            self.position += 1;
            Some(val)
        } else {
            None
        }
    }

    /// Read a u16 (little-endian) value from the stream.
    pub fn read_u16_le(&mut self) -> Option<u16> {
        self.read_chunk(2).map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
    }

    /// Read a u32 (little-endian) value from the stream.
    pub fn read_u32_le(&mut self) -> Option<u32> {
        self.read_chunk(4).map(|chunk| {
            u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
        })
    }

    /// Read a u64 (little-endian) value from the stream.
    pub fn read_u64_le(&mut self) -> Option<u64> {
        self.read_chunk(8).map(|chunk| {
            u64::from_le_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3],
                chunk[4], chunk[5], chunk[6], chunk[7],
            ])
        })
    }

    /// Read all remaining bytes.
    pub fn read_remaining(&mut self) -> Vec<u8> {
        let remaining = self.buffer[self.position..].to_vec();
        self.position = self.buffer.len();
        remaining
    }

    /// Reset the read position to the beginning.
    pub fn reset(&mut self) {
        self.position = 0;
    }

    /// Seek to a specific position.
    pub fn seek(&mut self, position: usize) {
        self.position = position.min(self.buffer.len());
    }

    /// Skip a number of bytes.
    pub fn skip(&mut self, count: usize) {
        self.position = (self.position + count).min(self.buffer.len());
    }
}

impl Read for TraceMemorySpaceInputStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let available = &self.buffer[self.position..];
        let to_copy = buf.len().min(available.len());
        buf[..to_copy].copy_from_slice(&available[..to_copy]);
        self.position += to_copy;
        Ok(to_copy)
    }
}

/// A builder for creating memory input streams from sparse byte maps.
#[derive(Debug, Clone, Default)]
pub struct MemoryStreamBuilder {
    bytes: Vec<(u64, u8)>,
}

impl MemoryStreamBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a byte at an offset.
    pub fn set_byte(&mut self, offset: u64, value: u8) {
        self.bytes.push((offset, value));
    }

    /// Set multiple bytes starting at an offset.
    pub fn set_bytes(&mut self, start: u64, data: &[u8]) {
        for (i, &byte) in data.iter().enumerate() {
            self.bytes.push((start + i as u64, byte));
        }
    }

    /// Build the stream from the sparse byte map.
    ///
    /// Fills gaps with 0x00.
    pub fn build(&self) -> TraceMemorySpaceInputStream {
        if self.bytes.is_empty() {
            return TraceMemorySpaceInputStream::empty();
        }

        let min_addr = self.bytes.iter().map(|(a, _)| *a).min().unwrap_or(0);
        let max_addr = self.bytes.iter().map(|(a, _)| *a).max().unwrap_or(0);
        let size = (max_addr - min_addr + 1) as usize;

        let mut buffer = vec![0u8; size];
        for (addr, byte) in &self.bytes {
            let idx = (*addr - min_addr) as usize;
            if idx < buffer.len() {
                buffer[idx] = *byte;
            }
        }

        TraceMemorySpaceInputStream::new(buffer)
    }

    /// Whether the builder is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Get the number of bytes set.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

/// Register value conversion between different formats.
///
/// Ported from Ghidra's `RegisterValueConverter`.
#[derive(Debug, Clone)]
pub struct RegisterValueConverter {
    /// The register name.
    pub register_name: String,
    /// The register size in bytes.
    pub size_bytes: usize,
    /// The default value (all bits undefined).
    pub default_value: Option<Vec<u8>>,
}

impl RegisterValueConverter {
    /// Create a new converter for a register.
    pub fn new(register_name: impl Into<String>, size_bytes: usize) -> Self {
        Self {
            register_name: register_name.into(),
            size_bytes,
            default_value: None,
        }
    }

    /// Create with a default value.
    pub fn with_default(mut self, default: Vec<u8>) -> Self {
        self.default_value = Some(default);
        self
    }

    /// Convert a byte vector to a fixed-size register value.
    pub fn to_register_value(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        if bytes.len() >= self.size_bytes {
            Some(bytes[..self.size_bytes].to_vec())
        } else {
            None
        }
    }

    /// Convert from a u64 value to register bytes (little-endian).
    pub fn from_u64(&self, value: u64) -> Vec<u8> {
        let bytes = value.to_le_bytes();
        let mut result = bytes.to_vec();
        result.truncate(self.size_bytes);
        result.resize(self.size_bytes, 0);
        result
    }

    /// Convert register bytes to a u64 value (little-endian).
    pub fn to_u64(&self, bytes: &[u8]) -> u64 {
        let mut buf = [0u8; 8];
        let copy_len = bytes.len().min(8);
        buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
        u64::from_le_bytes(buf)
    }

    /// Get the default register value, or zeros if not set.
    pub fn get_default(&self) -> Vec<u8> {
        self.default_value
            .clone()
            .unwrap_or_else(|| vec![0u8; self.size_bytes])
    }

    /// Check if two register values are equivalent.
    pub fn values_equal(&self, a: &[u8], b: &[u8]) -> bool {
        let a_truncated = &a[..a.len().min(self.size_bytes)];
        let b_truncated = &b[..b.len().min(self.size_bytes)];
        a_truncated == b_truncated
    }

    /// Merge two register values, preferring defined bytes from either side.
    pub fn merge(&self, a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut result = vec![0u8; self.size_bytes];
        for i in 0..self.size_bytes {
            let a_byte = a.get(i).copied().unwrap_or(0);
            let b_byte = b.get(i).copied().unwrap_or(0);
            // Prefer non-zero byte (simplified merge)
            result[i] = if a_byte != 0 { a_byte } else { b_byte };
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_stream_basic_read() {
        let stream = TraceMemorySpaceInputStream::new(vec![0x48, 0x65, 0x6C, 0x6C, 0x6F]);
        let mut reader = stream;
        let mut buf = [0u8; 3];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(buf, [0x48, 0x65, 0x6C]);

        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], [0x6C, 0x6F]);
    }

    #[test]
    fn test_memory_stream_read_u32_le() {
        let stream = TraceMemorySpaceInputStream::new(vec![0x78, 0x56, 0x34, 0x12]);
        let mut reader = stream;
        assert_eq!(reader.read_u32_le(), Some(0x12345678));
        assert!(reader.read_u32_le().is_none());
    }

    #[test]
    fn test_memory_stream_null_terminated_string() {
        let data = b"hello\0world\0";
        let stream = TraceMemorySpaceInputStream::from_slice(data);
        let mut reader = stream;

        assert_eq!(reader.read_null_terminated_string(), Some("hello".into()));
        assert_eq!(reader.read_null_terminated_string(), Some("world".into()));
    }

    #[test]
    fn test_memory_stream_seek_and_skip() {
        let mut stream = TraceMemorySpaceInputStream::new(vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(stream.position(), 0);

        stream.skip(3);
        assert_eq!(stream.position(), 3);
        assert_eq!(stream.remaining(), 3);

        stream.seek(1);
        assert_eq!(stream.position(), 1);

        stream.seek(100); // beyond end
        assert!(stream.is_consumed());
    }

    #[test]
    fn test_memory_stream_read_chunk() {
        let mut stream = TraceMemorySpaceInputStream::new(vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let chunk = stream.read_chunk(2).unwrap();
        assert_eq!(chunk, &[0xAA, 0xBB]);

        assert!(stream.read_chunk(5).is_none()); // not enough bytes
    }

    #[test]
    fn test_memory_stream_builder() {
        let mut builder = MemoryStreamBuilder::new();
        builder.set_byte(0, 0x90); // NOP
        builder.set_bytes(1, &[0xC3]); // RET

        let mut stream = builder.build();
        assert_eq!(stream.read_u8(), Some(0x90));
        assert_eq!(stream.read_u8(), Some(0xC3));
    }

    #[test]
    fn test_register_value_converter() {
        let converter = RegisterValueConverter::new("EAX", 4);

        let bytes = converter.from_u64(0x12345678);
        assert_eq!(bytes, vec![0x78, 0x56, 0x34, 0x12]);

        let value = converter.to_u64(&bytes);
        assert_eq!(value, 0x12345678);

        let converted = converter.to_register_value(&bytes);
        assert!(converted.is_some());
        assert_eq!(converted.unwrap().len(), 4);
    }

    #[test]
    fn test_register_value_converter_with_default() {
        let converter = RegisterValueConverter::new("ESP", 4)
            .with_default(vec![0x00, 0x10, 0x00, 0x00]);

        let default = converter.get_default();
        assert_eq!(default, vec![0x00, 0x10, 0x00, 0x00]);

        assert!(converter.values_equal(&[0x00, 0x10, 0x00, 0x00], &[0x00, 0x10, 0x00, 0x00]));
        assert!(!converter.values_equal(&[0x00, 0x10, 0x00, 0x00], &[0x00, 0x20, 0x00, 0x00]));
    }

    #[test]
    fn test_register_value_merge() {
        let converter = RegisterValueConverter::new("RAX", 8);
        let a = vec![0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0];
        let b = vec![0, 0, 0, 0, 0xEF, 0xCD, 0xAB, 0x00];
        let merged = converter.merge(&a, &b);
        assert_eq!(
            merged,
            vec![0x78, 0x56, 0x34, 0x12, 0xEF, 0xCD, 0xAB, 0x00]
        );
    }
}
