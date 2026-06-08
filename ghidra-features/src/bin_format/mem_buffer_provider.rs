//! Memory buffer byte provider ported from Ghidra's
//! `ghidra.app.util.bin.MemBufferByteProvider`.
//!
//! Provides a [`ByteProvider`] implementation backed by a contiguous memory
//! buffer (`&[u8]` or `Vec<u8>`). This is useful when binary data has been
//! loaded into memory and random-access reads are needed without going through
//! a file.
//!
//! Unlike [`ByteArrayProvider`](super::byte_provider::ByteArrayProvider),
//! this provider is designed to wrap borrowed data and does not require
//! ownership. It reports its length as the buffer length (or
//! `u64::MAX` when the length is unknown, matching the Java behavior).

use std::io;
use std::sync::Mutex;

use super::byte_provider::ByteProvider;

// ---------------------------------------------------------------------------
// MemBufferByteProvider
// ---------------------------------------------------------------------------

/// A [`ByteProvider`] backed by a borrowed or owned memory buffer.
///
/// Ported from `ghidra.app.util.bin.MemBufferByteProvider`. Wraps a
/// contiguous byte slice and provides random-access reads.
///
/// # Example
///
/// ```
/// use ghidra_features::bin_format::mem_buffer_provider::MemBufferByteProvider;
/// use ghidra_features::bin_format::ByteProvider;
///
/// let data = vec![0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01];
/// let provider = MemBufferByteProvider::new(data.clone());
/// assert_eq!(provider.length(), 6);
/// assert_eq!(provider.read_u8(0).unwrap(), 0x7F);
/// assert_eq!(provider.read_u8(3).unwrap(), 0x46);
/// ```
pub struct MemBufferByteProvider {
    data: Vec<u8>,
    name: Option<String>,
}

impl MemBufferByteProvider {
    /// Create a new provider from an owned byte vector.
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self {
            data: data.into(),
            name: None,
        }
    }

    /// Create a new provider with a display name.
    pub fn with_name(data: impl Into<Vec<u8>>, name: impl Into<String>) -> Self {
        Self {
            data: data.into(),
            name: Some(name.into()),
        }
    }

    /// Get a reference to the underlying data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Consume the provider and return the underlying data.
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

impl ByteProvider for MemBufferByteProvider {
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn absolute_path(&self) -> Option<&str> {
        None
    }

    fn length(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_u8(&self, index: u64) -> io::Result<u8> {
        let idx = index as usize;
        if idx >= self.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("index {} out of range (len={})", index, self.data.len()),
            ));
        }
        Ok(self.data[idx])
    }

    fn read_bytes(&self, index: u64, buf: &mut [u8]) -> io::Result<usize> {
        let idx = index as usize;
        if idx >= self.data.len() {
            return Ok(0);
        }
        let available = self.data.len() - idx;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&self.data[idx..idx + to_read]);
        Ok(to_read)
    }
}

// ---------------------------------------------------------------------------
// BorrowedMemBufferProvider
// ---------------------------------------------------------------------------

/// A [`ByteProvider`] backed by shared borrowed data behind a `Mutex`.
///
/// Unlike `MemBufferByteProvider` which takes ownership, this variant holds
/// a shared reference (`Arc<Vec<u8>>`) and can be cloned cheaply. All reads
/// go through the shared data without copying.
///
/// This matches the use case in Ghidra where `MemBuffer` is a lightweight
/// view into program memory that does not own its data.
pub struct BorrowedMemBufferProvider {
    data: std::sync::Arc<Vec<u8>>,
    name: Option<String>,
}

impl BorrowedMemBufferProvider {
    /// Create a new provider from shared data.
    pub fn new(data: std::sync::Arc<Vec<u8>>) -> Self {
        Self { data, name: None }
    }

    /// Create with a display name.
    pub fn with_name(data: std::sync::Arc<Vec<u8>>, name: impl Into<String>) -> Self {
        Self {
            data,
            name: Some(name.into()),
        }
    }

    /// Returns the length of the buffer.
    pub fn buffer_length(&self) -> usize {
        self.data.len()
    }
}

impl Clone for BorrowedMemBufferProvider {
    fn clone(&self) -> Self {
        Self {
            data: std::sync::Arc::clone(&self.data),
            name: self.name.clone(),
        }
    }
}

impl ByteProvider for BorrowedMemBufferProvider {
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn absolute_path(&self) -> Option<&str> {
        None
    }

    fn length(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_u8(&self, index: u64) -> io::Result<u8> {
        let idx = index as usize;
        if idx >= self.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("index {} out of range (len={})", index, self.data.len()),
            ));
        }
        Ok(self.data[idx])
    }

    fn read_bytes(&self, index: u64, buf: &mut [u8]) -> io::Result<usize> {
        let idx = index as usize;
        if idx >= self.data.len() {
            return Ok(0);
        }
        let available = self.data.len() - idx;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&self.data[idx..idx + to_read]);
        Ok(to_read)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mem_buffer_provider_basic() {
        let data = vec![1, 2, 3, 4, 5];
        let provider = MemBufferByteProvider::new(data);
        assert_eq!(provider.length(), 5);
        assert_eq!(provider.read_u8(0).unwrap(), 1);
        assert_eq!(provider.read_u8(4).unwrap(), 5);
        assert!(provider.read_u8(5).is_err());
    }

    #[test]
    fn test_mem_buffer_provider_with_name() {
        let data = vec![0xAA, 0xBB];
        let provider = MemBufferByteProvider::with_name(data, "test.bin");
        assert_eq!(provider.name(), Some("test.bin"));
        assert_eq!(provider.absolute_path(), None);
        assert_eq!(provider.length(), 2);
    }

    #[test]
    fn test_mem_buffer_read_bytes() {
        let data: Vec<u8> = (0..20).collect();
        let provider = MemBufferByteProvider::new(data);

        let mut buf = [0u8; 5];
        let n = provider.read_bytes(10, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(buf, [10, 11, 12, 13, 14]);
    }

    #[test]
    fn test_mem_buffer_read_bytes_partial() {
        let data = vec![1, 2, 3];
        let provider = MemBufferByteProvider::new(data);

        let mut buf = [0u8; 10];
        let n = provider.read_bytes(1, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..n], &[2, 3]);
    }

    #[test]
    fn test_mem_buffer_read_bytes_past_end() {
        let data = vec![1, 2, 3];
        let provider = MemBufferByteProvider::new(data);

        let mut buf = [0u8; 5];
        let n = provider.read_bytes(10, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_mem_buffer_into_data() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let provider = MemBufferByteProvider::new(data.clone());
        let extracted = provider.into_data();
        assert_eq!(extracted, data);
    }

    #[test]
    fn test_mem_buffer_data_ref() {
        let data = vec![10, 20, 30];
        let provider = MemBufferByteProvider::new(data);
        assert_eq!(provider.data(), &[10, 20, 30]);
    }

    #[test]
    fn test_borrowed_mem_buffer_provider() {
        let data = std::sync::Arc::new(vec![1, 2, 3, 4, 5]);
        let provider = BorrowedMemBufferProvider::new(data);
        assert_eq!(provider.length(), 5);
        assert_eq!(provider.read_u8(2).unwrap(), 3);
    }

    #[test]
    fn test_borrowed_mem_buffer_clone() {
        let data = std::sync::Arc::new(vec![10, 20, 30]);
        let provider = BorrowedMemBufferProvider::with_name(data, "shared");
        let cloned = provider.clone();

        assert_eq!(provider.name(), Some("shared"));
        assert_eq!(cloned.name(), Some("shared"));
        assert_eq!(cloned.read_u8(0).unwrap(), 10);
        assert_eq!(cloned.read_u8(2).unwrap(), 30);
    }

    #[test]
    fn test_borrowed_mem_buffer_read_bytes() {
        let data = std::sync::Arc::new((0..100u8).collect::<Vec<_>>());
        let provider = BorrowedMemBufferProvider::new(data);

        let mut buf = [0u8; 10];
        let n = provider.read_bytes(50, &mut buf).unwrap();
        assert_eq!(n, 10);
        assert_eq!(buf, [50, 51, 52, 53, 54, 55, 56, 57, 58, 59]);
    }

    #[test]
    fn test_borrowed_mem_buffer_out_of_range() {
        let data = std::sync::Arc::new(vec![1, 2, 3]);
        let provider = BorrowedMemBufferProvider::new(data);

        let result = provider.read_u8(10);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_mem_buffer_empty() {
        let provider = MemBufferByteProvider::new(vec![]);
        assert_eq!(provider.length(), 0);
        assert!(provider.is_empty());
        assert!(!provider.is_valid_index(0));

        let result = provider.read_u8(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_borrowed_mem_buffer_length() {
        let data = std::sync::Arc::new(vec![1, 2, 3]);
        let provider = BorrowedMemBufferProvider::new(data);
        assert_eq!(provider.buffer_length(), 3);
    }
}
