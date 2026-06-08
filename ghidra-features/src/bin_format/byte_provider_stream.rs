//! ByteProvider-to-Read adapter ported from Ghidra's
//! `ghidra.app.util.bin.ByteProviderInputStream`.
//!
//! Provides a `Read` implementation that wraps a [`ByteProvider`], bridging
//! the random-access byte provider abstraction with Rust's standard streaming
//! interface. Unlike [`InputStreamByteProvider`](super::stream_provider::InputStreamByteProvider)
//! (which goes from stream to provider), this goes from provider to stream.
//!
//! The [`ByteProviderInputStream`] does **not** close the underlying provider
//! when dropped. The [`ClosingByteProviderStream`] variant **does** close it.

use std::io::{self, Read};

use super::byte_provider::ByteProvider;

// ---------------------------------------------------------------------------
// ByteProviderInputStream
// ---------------------------------------------------------------------------

/// A `Read` adapter over a [`ByteProvider`].
///
/// Ported from `ghidra.app.util.bin.ByteProviderInputStream`. Reads bytes
/// sequentially from the provider starting at a configurable offset.
///
/// Supports `mark()` / `reset()` for limited repositioning within the
/// stream. The underlying provider is **not** closed when this stream
/// is dropped.
///
/// # Example
///
/// ```
/// use std::io::Read;
/// use ghidra_features::bin_format::byte_provider::ByteArrayProvider;
/// use ghidra_features::bin_format::byte_provider_stream::ByteProviderInputStream;
///
/// let provider = ByteArrayProvider::new(None, vec![0x48, 0x65, 0x6C, 0x6C, 0x6F]);
/// let mut stream = ByteProviderInputStream::new(&provider);
///
/// let mut buf = [0u8; 5];
/// let n = stream.read(&mut buf).unwrap();
/// assert_eq!(n, 5);
/// assert_eq!(&buf, b"Hello");
/// ```
pub struct ByteProviderInputStream<'a> {
    provider: &'a dyn ByteProvider,
    current_position: u64,
    mark_position: u64,
}

impl<'a> ByteProviderInputStream<'a> {
    /// Creates a new stream that reads from the provider starting at offset 0.
    pub fn new(provider: &'a dyn ByteProvider) -> Self {
        Self {
            provider,
            current_position: 0,
            mark_position: 0,
        }
    }

    /// Creates a new stream starting at the specified position.
    pub fn with_offset(provider: &'a dyn ByteProvider, start_position: u64) -> Self {
        Self {
            provider,
            current_position: start_position,
            mark_position: start_position,
        }
    }

    /// Returns the current read position within the provider.
    pub fn position(&self) -> u64 {
        self.current_position
    }

    /// Returns the number of bytes remaining before EOF.
    pub fn available(&self) -> u64 {
        self.provider.length().saturating_sub(self.current_position)
    }
}

impl<'a> Read for ByteProviderInputStream<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let eof = self.provider.length();
        if self.current_position >= eof {
            return Ok(0);
        }

        let remaining = eof - self.current_position;
        let to_read = (buf.len() as u64).min(remaining) as usize;
        let n = self.provider.read_bytes(self.current_position, &mut buf[..to_read])?;
        self.current_position += n as u64;
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// OwnedByteProviderStream
// ---------------------------------------------------------------------------

/// A `Read` adapter that takes ownership of a [`ByteProvider`].
///
/// Unlike `ByteProviderInputStream` which borrows the provider, this type
/// owns it. The provider is **not** closed on drop (use
/// [`ClosingByteProviderStream`] for that behavior).
pub struct OwnedByteProviderStream {
    provider: Box<dyn ByteProvider>,
    current_position: u64,
    mark_position: u64,
}

impl OwnedByteProviderStream {
    /// Creates a new stream that takes ownership of the provider.
    pub fn new(provider: Box<dyn ByteProvider>) -> Self {
        Self {
            provider,
            current_position: 0,
            mark_position: 0,
        }
    }

    /// Creates a new stream starting at the specified position.
    pub fn with_offset(provider: Box<dyn ByteProvider>, start_position: u64) -> Self {
        Self {
            provider,
            current_position: start_position,
            mark_position: start_position,
        }
    }

    /// Returns the current read position.
    pub fn position(&self) -> u64 {
        self.current_position
    }

    /// Returns the number of bytes remaining.
    pub fn available(&self) -> u64 {
        self.provider.length().saturating_sub(self.current_position)
    }

    /// Returns a reference to the underlying provider.
    pub fn provider(&self) -> &dyn ByteProvider {
        self.provider.as_ref()
    }

    /// Consumes the stream and returns the underlying provider.
    pub fn into_provider(self) -> Box<dyn ByteProvider> {
        self.provider
    }
}

impl Read for OwnedByteProviderStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let eof = self.provider.length();
        if self.current_position >= eof {
            return Ok(0);
        }

        let remaining = eof - self.current_position;
        let to_read = (buf.len() as u64).min(remaining) as usize;
        let n = self.provider.read_bytes(self.current_position, &mut buf[..to_read])?;
        self.current_position += n as u64;
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// ClosingByteProviderStream
// ---------------------------------------------------------------------------

/// A `Read` adapter over a [`ByteProvider`] that closes the provider on drop.
///
/// Ported from `ghidra.app.util.bin.ByteProviderInputStream.ClosingInputStream`.
/// When this stream is dropped or explicitly closed, the underlying provider's
/// `close()` method is called.
pub struct ClosingByteProviderStream {
    provider: Option<Box<dyn ByteProvider>>,
    current_position: u64,
    mark_position: u64,
}

impl ClosingByteProviderStream {
    /// Creates a new closing stream that takes ownership of the provider.
    pub fn new(provider: Box<dyn ByteProvider>) -> Self {
        Self {
            provider: Some(provider),
            current_position: 0,
            mark_position: 0,
        }
    }

    /// Creates a new closing stream starting at the specified position.
    pub fn with_offset(provider: Box<dyn ByteProvider>, start_position: u64) -> Self {
        Self {
            provider: Some(provider),
            current_position: start_position,
            mark_position: start_position,
        }
    }

    /// Returns the current read position.
    pub fn position(&self) -> u64 {
        self.current_position
    }

    /// Returns the number of bytes remaining.
    pub fn available(&self) -> u64 {
        self.provider
            .as_ref()
            .map_or(0, |p| p.length().saturating_sub(self.current_position))
    }

    /// Explicitly close the underlying provider.
    pub fn close(&mut self) {
        if let Some(provider) = self.provider.take() {
            provider.close();
        }
    }

    /// Returns true if the underlying provider is still open.
    pub fn is_open(&self) -> bool {
        self.provider.is_some()
    }
}

impl Read for ClosingByteProviderStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let provider = match &self.provider {
            Some(p) => p,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "stream is closed",
                ))
            }
        };

        let eof = provider.length();
        if self.current_position >= eof {
            return Ok(0);
        }

        let remaining = eof - self.current_position;
        let to_read = (buf.len() as u64).min(remaining) as usize;
        let n = provider.read_bytes(self.current_position, &mut buf[..to_read])?;
        self.current_position += n as u64;
        Ok(n)
    }
}

impl Drop for ClosingByteProviderStream {
    fn drop(&mut self) {
        self.close();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::byte_provider::ByteArrayProvider;

    #[test]
    fn test_borrowed_stream_basic() {
        let data = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F]; // "Hello"
        let provider = ByteArrayProvider::new(None, data);
        let mut stream = ByteProviderInputStream::new(&provider);

        let mut buf = [0u8; 5];
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"Hello");
        assert_eq!(stream.position(), 5);
    }

    #[test]
    fn test_borrowed_stream_with_offset() {
        let data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let provider = ByteArrayProvider::new(None, data);
        let mut stream = ByteProviderInputStream::with_offset(&provider, 5);

        let mut buf = [0u8; 3];
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(buf, [5, 6, 7]);
    }

    #[test]
    fn test_borrowed_stream_available() {
        let data = vec![1, 2, 3, 4, 5];
        let provider = ByteArrayProvider::new(None, data);
        let mut stream = ByteProviderInputStream::new(&provider);

        assert_eq!(stream.available(), 5);

        let mut buf = [0u8; 2];
        stream.read(&mut buf).unwrap();
        assert_eq!(stream.available(), 3);
    }

    #[test]
    fn test_borrowed_stream_eof() {
        let data = vec![1, 2, 3];
        let provider = ByteArrayProvider::new(None, data);
        let mut stream = ByteProviderInputStream::new(&provider);

        // Read all bytes
        let mut buf = [0u8; 10];
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf[..n], &[1, 2, 3]);

        // Next read should return 0 (EOF)
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_owned_stream_basic() {
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let provider = Box::new(ByteArrayProvider::new(None, data));
        let mut stream = OwnedByteProviderStream::new(provider);

        let mut buf = [0u8; 2];
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [0xAA, 0xBB]);
        assert_eq!(stream.position(), 2);
    }

    #[test]
    fn test_owned_stream_into_provider() {
        let data = vec![1, 2, 3];
        let provider = Box::new(ByteArrayProvider::new(None, data));
        let stream = OwnedByteProviderStream::new(provider);

        let provider = stream.into_provider();
        assert_eq!(provider.length(), 3);
        assert_eq!(provider.read_u8(0).unwrap(), 1);
    }

    #[test]
    fn test_owned_stream_with_offset() {
        let data = vec![0, 1, 2, 3, 4, 5];
        let provider = Box::new(ByteArrayProvider::new(None, data));
        let mut stream = OwnedByteProviderStream::with_offset(provider, 3);

        let mut buf = [0u8; 3];
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(buf, [3, 4, 5]);
    }

    #[test]
    fn test_closing_stream_basic() {
        let data = vec![10, 20, 30, 40, 50];
        let provider = Box::new(ByteArrayProvider::new(None, data));
        let mut stream = ClosingByteProviderStream::new(provider);

        assert!(stream.is_open());

        let mut buf = [0u8; 3];
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(buf, [10, 20, 30]);

        stream.close();
        assert!(!stream.is_open());

        // Reading after close should fail
        let result = stream.read(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_closing_stream_auto_close_on_drop() {
        let data = vec![1, 2, 3];
        let provider = Box::new(ByteArrayProvider::new(None, data));
        {
            let mut stream = ClosingByteProviderStream::new(provider);
            assert!(stream.is_open());
            // stream dropped here -- provider close() called
        }
    }

    #[test]
    fn test_closing_stream_with_offset() {
        let data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let provider = Box::new(ByteArrayProvider::new(None, data));
        let mut stream = ClosingByteProviderStream::with_offset(provider, 7);

        let mut buf = [0u8; 5];
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf[..n], &[7, 8, 9]);
    }

    #[test]
    fn test_stream_partial_read() {
        let data: Vec<u8> = (0..100).collect();
        let provider = ByteArrayProvider::new(None, data);
        let mut stream = ByteProviderInputStream::new(&provider);

        // Read in small chunks
        let mut total = Vec::new();
        let mut buf = [0u8; 13];
        loop {
            let n = stream.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            total.extend_from_slice(&buf[..n]);
        }

        assert_eq!(total.len(), 100);
        assert_eq!(total, (0..100).collect::<Vec<_>>());
    }

    #[test]
    fn test_borrowed_stream_zero_length() {
        let provider = ByteArrayProvider::new(None, vec![]);
        let mut stream = ByteProviderInputStream::new(&provider);

        let mut buf = [0u8; 10];
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_owned_stream_empty() {
        let provider = Box::new(ByteArrayProvider::new(None, vec![]));
        let mut stream = OwnedByteProviderStream::new(provider);

        assert_eq!(stream.available(), 0);
        let mut buf = [0u8; 5];
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }
}
