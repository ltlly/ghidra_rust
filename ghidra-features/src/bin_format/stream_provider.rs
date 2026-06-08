//! Forward-only stream-based byte provider ported from Ghidra's
//! `ghidra.app.util.bin.InputStreamByteProvider`.
//!
//! Provides a [`ByteProvider`] implementation that wraps a `Read` stream,
//! allowing data to be read sequentially at ever-increasing offsets.
//! Random seeks backward are not supported and will return an error.
//!
//! Uses interior mutability (`Mutex`) to satisfy the `ByteProvider` trait's
//! `&self` read methods while maintaining mutable stream state.

use std::io::{self, Cursor, Read};
use std::sync::Mutex;

use super::byte_provider::ByteProvider;

// ---------------------------------------------------------------------------
// InputStreamByteProvider
// ---------------------------------------------------------------------------

/// A [`ByteProvider`] that wraps a `Read` stream for forward-only reading.
///
/// Ported from `ghidra.app.util.bin.InputStreamByteProvider`. This provider
/// can only be used to read data at ever-increasing offsets. Attempting to
/// read at an offset that has already been passed will result in an error.
///
/// # Limitations
///
/// - No backward seeking -- once bytes are consumed, they cannot be re-read
/// - The total length must be known at construction time
/// - No write support (read-only)
///
/// # Example
///
/// ```
/// use std::io::Cursor;
/// use ghidra_features::bin_format::stream_provider::InputStreamByteProvider;
/// use ghidra_features::bin_format::ByteProvider;
///
/// let data = vec![0x7F, 0x45, 0x4C, 0x46]; // ELF magic
/// let cursor = Cursor::new(data);
/// let provider = InputStreamByteProvider::new(Box::new(cursor), 4);
/// assert_eq!(provider.read_u8(0).unwrap(), 0x7F);
/// ```
pub struct InputStreamByteProvider {
    inner: Mutex<InputStreamProviderInner>,
    name: Option<String>,
}

struct InputStreamProviderInner {
    reader: Box<dyn Read + Send>,
    length: u64,
    current_index: u64,
}

impl InputStreamByteProvider {
    /// Creates a new stream-based byte provider.
    ///
    /// # Arguments
    ///
    /// * `reader` - The underlying `Read` source
    /// * `length` - The total number of bytes available in the stream
    pub fn new(reader: Box<dyn Read + Send>, length: u64) -> Self {
        Self {
            inner: Mutex::new(InputStreamProviderInner {
                reader,
                length,
                current_index: 0,
            }),
            name: None,
        }
    }

    /// Creates a new stream-based byte provider with a display name.
    pub fn with_name(reader: Box<dyn Read + Send>, length: u64, name: String) -> Self {
        Self {
            inner: Mutex::new(InputStreamProviderInner {
                reader,
                length,
                current_index: 0,
            }),
            name: Some(name),
        }
    }

    /// Creates a new stream-based byte provider from a `Vec<u8>`.
    ///
    /// This is a convenience constructor for in-memory data.
    pub fn from_bytes(data: Vec<u8>) -> Self {
        let length = data.len() as u64;
        Self {
            inner: Mutex::new(InputStreamProviderInner {
                reader: Box::new(Cursor::new(data)),
                length,
                current_index: 0,
            }),
            name: None,
        }
    }

    /// Returns the current read position in the stream.
    pub fn current_position(&self) -> u64 {
        self.inner.lock().unwrap().current_index
    }

    /// Advance the stream to the target index by skipping bytes.
    ///
    /// Returns `Ok(())` if the stream was advanced successfully,
    /// or an error if the target is behind the current position or
    /// if insufficient bytes were available.
    fn advance_to(
        &self,
        inner: &mut InputStreamProviderInner,
        target: u64,
    ) -> io::Result<()> {
        if target < inner.current_index {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Attempted to read byte at offset {} that was already read (current position: {})",
                    target, inner.current_index
                ),
            ));
        }

        if target > inner.current_index {
            let to_skip = target - inner.current_index;
            let mut remaining = to_skip;
            let mut skip_buf = [0u8; 8192];

            while remaining > 0 {
                let chunk = remaining.min(skip_buf.len() as u64) as usize;
                let n = inner.reader.read(&mut skip_buf[..chunk])?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "Not enough bytes to skip to offset {} (skipped {} of {})",
                            target, to_skip - remaining, to_skip
                        ),
                    ));
                }
                inner.current_index += n as u64;
                remaining -= n as u64;
            }
        }

        Ok(())
    }

    /// Internal single-byte read.
    fn read_byte_internal(&self, index: u64) -> io::Result<u8> {
        let mut inner = self.inner.lock().unwrap();

        if index >= inner.length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("index {} out of range (len={})", index, inner.length),
            ));
        }

        self.advance_to(&mut inner, index)?;

        let mut buf = [0u8; 1];
        let n = inner.reader.read(&mut buf)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
        }
        inner.current_index += 1;
        Ok(buf[0])
    }

    /// Internal multi-byte read.
    fn read_bytes_internal(&self, index: u64, buf: &mut [u8]) -> io::Result<usize> {
        let mut inner = self.inner.lock().unwrap();

        if index >= inner.length {
            return Ok(0);
        }

        self.advance_to(&mut inner, index)?;

        let max_readable = (inner.length - inner.current_index) as usize;
        let to_read = buf.len().min(max_readable);
        let n = inner.reader.read(&mut buf[..to_read])?;
        inner.current_index += n as u64;
        Ok(n)
    }
}

impl ByteProvider for InputStreamByteProvider {
    fn name(&self) -> Option<&str> {
        self.name.as_deref().or(Some("InputStreamByteProvider"))
    }

    fn absolute_path(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn length(&self) -> u64 {
        self.inner.lock().unwrap().length
    }

    fn is_valid_index(&self, index: u64) -> bool {
        let inner = self.inner.lock().unwrap();
        index < inner.length
    }

    fn read_u8(&self, index: u64) -> io::Result<u8> {
        self.read_byte_internal(index)
    }

    fn read_bytes(&self, index: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.read_bytes_internal(index, buf)
    }

    fn read_slice(&self, index: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let n = self.read_bytes_internal(index, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    fn close(&self) {
        // nothing to do for stream-based providers
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_bytes() {
        let data = vec![0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01];
        let provider = InputStreamByteProvider::from_bytes(data);
        assert_eq!(provider.length(), 6);
        assert!(provider.is_valid_index(0));
        assert!(provider.is_valid_index(5));
        assert!(!provider.is_valid_index(6));

        assert_eq!(provider.read_u8(0).unwrap(), 0x7F);
        assert_eq!(provider.read_u8(1).unwrap(), 0x45);
        assert_eq!(provider.read_u8(2).unwrap(), 0x4C);
    }

    #[test]
    fn test_forward_only_reading() {
        let data = vec![10, 20, 30, 40, 50];
        let provider = InputStreamByteProvider::from_bytes(data);

        // Reading forward works
        assert_eq!(provider.read_u8(2).unwrap(), 30);
        assert_eq!(provider.current_position(), 3);

        // Reading at current position works
        assert_eq!(provider.read_u8(3).unwrap(), 40);

        // Reading backward should fail
        let result = provider.read_u8(1);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(err.to_string().contains("already read"));
    }

    #[test]
    fn test_read_bytes() {
        let data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let provider = InputStreamByteProvider::from_bytes(data);

        let mut buf = [0u8; 4];
        let n = provider.read_bytes(3, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [3, 4, 5, 6]);
        assert_eq!(provider.current_position(), 7);
    }

    #[test]
    fn test_read_slice() {
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let provider = InputStreamByteProvider::from_bytes(data);

        let slice = provider.read_slice(1, 3).unwrap();
        assert_eq!(slice, vec![0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_out_of_range() {
        let data = vec![1, 2, 3];
        let provider = InputStreamByteProvider::from_bytes(data);

        let result = provider.read_u8(10);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_read_past_end_returns_partial() {
        let data = vec![1, 2, 3];
        let provider = InputStreamByteProvider::from_bytes(data);

        let mut buf = [0u8; 10];
        let n = provider.read_bytes(0, &mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf[..n], &[1, 2, 3]);
    }

    #[test]
    fn test_empty_provider() {
        let provider = InputStreamByteProvider::from_bytes(vec![]);
        assert_eq!(provider.length(), 0);
        assert!(!provider.is_valid_index(0));

        let result = provider.read_u8(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_sequential_skip_and_read() {
        let data = (0..100u8).collect::<Vec<_>>();
        let provider = InputStreamByteProvider::from_bytes(data);

        // Skip to position 50 by reading
        assert_eq!(provider.read_u8(50).unwrap(), 50);
        assert_eq!(provider.current_position(), 51);

        // Continue reading
        assert_eq!(provider.read_u8(51).unwrap(), 51);
        assert_eq!(provider.current_position(), 52);
    }

    #[test]
    fn test_with_name() {
        let data = vec![1, 2, 3];
        let provider = InputStreamByteProvider::with_name(
            Box::new(Cursor::new(data)),
            3,
            "test.bin".into(),
        );
        assert_eq!(provider.name(), Some("test.bin"));
        assert_eq!(provider.length(), 3);
    }

    #[test]
    fn test_cursor_based_reader() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let cursor = Cursor::new(data);
        let provider = InputStreamByteProvider::new(Box::new(cursor), 4);

        assert_eq!(provider.read_u8(0).unwrap(), 0xDE);
        assert_eq!(provider.read_u8(3).unwrap(), 0xEF);
    }

    #[test]
    fn test_is_valid_index() {
        let data = vec![1, 2, 3, 4, 5];
        let provider = InputStreamByteProvider::from_bytes(data);

        assert!(provider.is_valid_index(0));
        assert!(provider.is_valid_index(4));
        assert!(!provider.is_valid_index(5));
        assert!(!provider.is_valid_index(100));
    }
}
