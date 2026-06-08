//! Padded byte provider input stream ported from Ghidra's
//! `ghidra.app.util.bin.ByteProviderPaddedInputStream`.
//!
//! Wraps a [`ByteProvider`] and presents it as a byte stream with optional
//! zero-padding at the end. This is useful when a parser expects a certain
//! number of bytes but the underlying data is shorter -- the remaining bytes
//! will be returned as zeros instead of generating an error.
//!
//! # Example
//!
//! ```
//! use ghidra_features::bin_format::padded_stream::PaddedByteProvider;
//! use ghidra_features::bin_format::byte_provider::ByteArrayProvider;
//! use ghidra_features::bin_format::ByteProvider;
//!
//! let inner = ByteArrayProvider::new(None, vec![0x7F, 0x45, 0x4C, 0x46]);
//! let padded = PaddedByteProvider::new(Box::new(inner), 0, 4, 4);
//!
//! // Original data
//! assert_eq!(padded.read_u8(0).unwrap(), 0x7F);
//! assert_eq!(padded.read_u8(3).unwrap(), 0x46);
//!
//! // Padded region returns zeros
//! assert_eq!(padded.read_u8(4).unwrap(), 0x00);
//! assert_eq!(padded.read_u8(7).unwrap(), 0x00);
//!
//! // Past the padding returns error
//! assert!(padded.read_u8(8).is_err());
//! ```

use std::io;

use super::byte_provider::ByteProvider;

// ---------------------------------------------------------------------------
// PaddedByteProvider
// ---------------------------------------------------------------------------

/// A [`ByteProvider`] wrapper that extends the readable region with
/// zero-valued padding bytes.
///
/// Ported from `ghidra.app.util.bin.ByteProviderPaddedInputStream`. This
/// wraps an existing provider and extends its readable range by a fixed
/// number of zero bytes. Reads within the original data region are
/// forwarded to the inner provider; reads in the padding region return
/// zero bytes; reads past the padding region return an error.
///
/// # Layout
///
/// ```text
/// |<-- start_offset -->|<-- length -->|<-- pad_count -->|
/// |     (skipped)      |  real data   |  zero padding   |
/// ```
///
/// The total readable range is `length + pad_count` bytes, starting
/// at index 0 (which maps to `start_offset` in the inner provider).
pub struct PaddedByteProvider {
    inner: Box<dyn ByteProvider>,
    /// The offset in the inner provider where real data starts.
    start_offset: u64,
    /// The number of real data bytes from the inner provider.
    data_length: u64,
    /// The number of zero-padding bytes appended after the real data.
    pad_count: u64,
    /// Total readable length: data_length + pad_count.
    total_length: u64,
}

impl PaddedByteProvider {
    /// Create a new padded byte provider.
    ///
    /// # Arguments
    ///
    /// * `inner` - The underlying byte provider to read from
    /// * `start_offset` - The starting offset in `inner` where real data begins
    /// * `length` - The number of real data bytes to read from `inner`
    /// * `pad_count` - The number of zero bytes to append after the real data
    ///
    /// # Panics
    ///
    /// Panics if `length + pad_count` overflows `u64`.
    pub fn new(
        inner: Box<dyn ByteProvider>,
        start_offset: u64,
        length: u64,
        pad_count: u64,
    ) -> Self {
        let total_length = length.checked_add(pad_count).expect("length + pad_count overflow");
        Self {
            inner,
            start_offset,
            data_length: length,
            pad_count,
            total_length,
        }
    }

    /// Create a padded provider that wraps the entire inner provider.
    ///
    /// The data region covers the full inner provider, with the specified
    /// number of zero-padding bytes appended.
    pub fn with_full_range(inner: Box<dyn ByteProvider>, pad_count: u64) -> Self {
        let length = inner.length();
        Self::new(inner, 0, length, pad_count)
    }

    /// Returns the number of real data bytes (before padding).
    pub fn data_length(&self) -> u64 {
        self.data_length
    }

    /// Returns the number of zero-padding bytes.
    pub fn pad_count(&self) -> u64 {
        self.pad_count
    }

    /// Returns the start offset in the inner provider.
    pub fn start_offset(&self) -> u64 {
        self.start_offset
    }

    /// Returns true if the given index falls within the padding region.
    pub fn is_in_padding(&self, index: u64) -> bool {
        index >= self.data_length && index < self.total_length
    }

    /// Returns true if the given index falls within the real data region.
    pub fn is_in_data(&self, index: u64) -> bool {
        index < self.data_length
    }

    /// Returns the remaining readable bytes from the given index.
    ///
    /// This is equivalent to `available()` in the Java InputStream -- it
    /// returns how many bytes can be read starting from `index` before
    /// hitting the end of the padded region.
    pub fn remaining(&self, index: u64) -> u64 {
        if index >= self.total_length {
            0
        } else {
            self.total_length - index
        }
    }
}

impl ByteProvider for PaddedByteProvider {
    fn name(&self) -> Option<&str> {
        self.inner.name()
    }

    fn absolute_path(&self) -> Option<&str> {
        self.inner.absolute_path()
    }

    fn length(&self) -> u64 {
        self.total_length
    }

    fn is_valid_index(&self, index: u64) -> bool {
        index < self.total_length
    }

    fn read_u8(&self, index: u64) -> io::Result<u8> {
        if index >= self.total_length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "index {} out of range (total_length={})",
                    index, self.total_length
                ),
            ));
        }

        if index < self.data_length {
            // Real data region: forward to inner provider
            self.inner.read_u8(self.start_offset + index)
        } else {
            // Padding region: return zero
            Ok(0)
        }
    }

    fn read_bytes(&self, index: u64, buf: &mut [u8]) -> io::Result<usize> {
        if index >= self.total_length {
            return Ok(0);
        }

        let available = (self.total_length - index) as usize;
        let to_read = buf.len().min(available);

        if index >= self.data_length {
            // Entirely in padding region: fill with zeros
            for b in &mut buf[..to_read] {
                *b = 0;
            }
            return Ok(to_read);
        }

        let data_available = (self.data_length - index) as usize;
        if to_read <= data_available {
            // Entirely in real data region
            self.inner
                .read_bytes(self.start_offset + index, &mut buf[..to_read])
        } else {
            // Spans real data and padding
            let n = self
                .inner
                .read_bytes(self.start_offset + index, &mut buf[..data_available])?;
            // Fill the rest with zeros
            for b in &mut buf[n..to_read] {
                *b = 0;
            }
            Ok(to_read)
        }
    }

    fn close(&self) {
        // The inner provider is not closed, matching the Java behavior:
        // "the provider is not closed."
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bin_format::byte_provider::ByteArrayProvider;

    #[test]
    fn test_basic_padding() {
        let inner = ByteArrayProvider::new(None, vec![1, 2, 3, 4]);
        let padded = PaddedByteProvider::new(Box::new(inner), 0, 4, 4);

        assert_eq!(padded.length(), 8);
        assert_eq!(padded.data_length(), 4);
        assert_eq!(padded.pad_count(), 4);

        // Real data
        assert_eq!(padded.read_u8(0).unwrap(), 1);
        assert_eq!(padded.read_u8(3).unwrap(), 4);

        // Padding
        assert_eq!(padded.read_u8(4).unwrap(), 0);
        assert_eq!(padded.read_u8(7).unwrap(), 0);

        // Past padding
        assert!(padded.read_u8(8).is_err());
    }

    #[test]
    fn test_start_offset() {
        let inner = ByteArrayProvider::new(None, vec![0, 0, 0, 10, 20, 30]);
        let padded = PaddedByteProvider::new(Box::new(inner), 3, 3, 2);

        assert_eq!(padded.length(), 5);
        assert_eq!(padded.start_offset(), 3);

        // Reads from offset 3 in the inner provider
        assert_eq!(padded.read_u8(0).unwrap(), 10);
        assert_eq!(padded.read_u8(1).unwrap(), 20);
        assert_eq!(padded.read_u8(2).unwrap(), 30);

        // Padding
        assert_eq!(padded.read_u8(3).unwrap(), 0);
        assert_eq!(padded.read_u8(4).unwrap(), 0);
    }

    #[test]
    fn test_is_in_padding() {
        let inner = ByteArrayProvider::new(None, vec![1, 2, 3]);
        let padded = PaddedByteProvider::new(Box::new(inner), 0, 3, 3);

        assert!(!padded.is_in_padding(0));
        assert!(!padded.is_in_padding(2));
        assert!(padded.is_in_padding(3));
        assert!(padded.is_in_padding(5));
        assert!(!padded.is_in_padding(6));
    }

    #[test]
    fn test_is_in_data() {
        let inner = ByteArrayProvider::new(None, vec![1, 2, 3]);
        let padded = PaddedByteProvider::new(Box::new(inner), 0, 3, 3);

        assert!(padded.is_in_data(0));
        assert!(padded.is_in_data(2));
        assert!(!padded.is_in_data(3));
        assert!(!padded.is_in_data(5));
    }

    #[test]
    fn test_remaining() {
        let inner = ByteArrayProvider::new(None, vec![1, 2, 3]);
        let padded = PaddedByteProvider::new(Box::new(inner), 0, 3, 3);

        assert_eq!(padded.remaining(0), 6);
        assert_eq!(padded.remaining(3), 3);
        assert_eq!(padded.remaining(5), 1);
        assert_eq!(padded.remaining(6), 0);
        assert_eq!(padded.remaining(100), 0);
    }

    #[test]
    fn test_read_bytes_spanning_data_and_padding() {
        let inner = ByteArrayProvider::new(None, vec![0xAA, 0xBB, 0xCC]);
        let padded = PaddedByteProvider::new(Box::new(inner), 0, 3, 3);

        let mut buf = [0xFF; 5];
        let n = padded.read_bytes(1, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(buf, [0xBB, 0xCC, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_read_bytes_all_padding() {
        let inner = ByteArrayProvider::new(None, vec![1, 2]);
        let padded = PaddedByteProvider::new(Box::new(inner), 0, 2, 4);

        let mut buf = [0xFF; 4];
        let n = padded.read_bytes(2, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [0, 0, 0, 0]);
    }

    #[test]
    fn test_read_bytes_past_end() {
        let inner = ByteArrayProvider::new(None, vec![1, 2, 3]);
        let padded = PaddedByteProvider::new(Box::new(inner), 0, 3, 2);

        let mut buf = [0xFF; 4];
        let n = padded.read_bytes(4, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn test_read_bytes_beyond_total() {
        let inner = ByteArrayProvider::new(None, vec![1, 2, 3]);
        let padded = PaddedByteProvider::new(Box::new(inner), 0, 3, 2);

        let mut buf = [0xFF; 4];
        let n = padded.read_bytes(10, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_with_full_range() {
        let inner = ByteArrayProvider::new(Some("test.bin".into()), vec![10, 20, 30]);
        let padded = PaddedByteProvider::with_full_range(Box::new(inner), 5);

        assert_eq!(padded.length(), 8);
        assert_eq!(padded.data_length(), 3);
        assert_eq!(padded.pad_count(), 5);
        assert_eq!(padded.name(), Some("test.bin"));

        assert_eq!(padded.read_u8(2).unwrap(), 30);
        assert_eq!(padded.read_u8(3).unwrap(), 0);
        assert_eq!(padded.read_u8(7).unwrap(), 0);
    }

    #[test]
    fn test_zero_pad_count() {
        let inner = ByteArrayProvider::new(None, vec![1, 2, 3]);
        let padded = PaddedByteProvider::new(Box::new(inner), 0, 3, 0);

        assert_eq!(padded.length(), 3);
        assert_eq!(padded.read_u8(2).unwrap(), 3);
        assert!(padded.read_u8(3).is_err());
    }

    #[test]
    fn test_zero_data_length() {
        let inner = ByteArrayProvider::new(None, vec![1, 2, 3]);
        let padded = PaddedByteProvider::new(Box::new(inner), 0, 0, 4);

        assert_eq!(padded.length(), 4);
        assert_eq!(padded.read_u8(0).unwrap(), 0);
        assert_eq!(padded.read_u8(3).unwrap(), 0);
    }

    #[test]
    fn test_is_valid_index() {
        let inner = ByteArrayProvider::new(None, vec![1, 2]);
        let padded = PaddedByteProvider::new(Box::new(inner), 0, 2, 3);

        assert!(padded.is_valid_index(0));
        assert!(padded.is_valid_index(4));
        assert!(!padded.is_valid_index(5));
    }

    #[test]
    fn test_close_does_not_close_inner() {
        let inner = ByteArrayProvider::new(None, vec![1, 2, 3]);
        let padded = PaddedByteProvider::new(Box::new(inner), 0, 3, 3);

        // Close should not panic and should not affect reads
        padded.close();
        assert_eq!(padded.read_u8(0).unwrap(), 1);
        assert_eq!(padded.read_u8(5).unwrap(), 0);
    }
}
