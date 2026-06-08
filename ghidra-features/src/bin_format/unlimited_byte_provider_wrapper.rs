//! Unlimited byte provider wrapper ported from Ghidra's
//! `ghidra.app.util.bin.UnlimitedByteProviderWrapper`.
//!
//! Wraps a [`ByteProvider`] constrained to a sub-section, but unlike
//! [`ByteProviderWrapper`](super::byte_provider::ByteProviderWrapper),
//! reads beyond the specified sub-section are permitted and return zero
//! bytes. The [`length()`](ByteProvider::length) method still returns
//! the bounded sub-section length.
//!
//! This is useful for format parsers that speculatively read fields that
//! may extend past the end of a section -- the zeros act as a safe
//! default rather than triggering an error.
//!
//! # Example
//!
//! ```
//! use ghidra_features::bin_format::unlimited_byte_provider_wrapper::UnlimitedByteProviderWrapper;
//! use ghidra_features::bin_format::byte_provider::ByteArrayProvider;
//! use ghidra_features::bin_format::ByteProvider;
//!
//! let inner = ByteArrayProvider::new(None, vec![0x10, 0x20, 0x30, 0x40, 0x50]);
//! let wrapper = UnlimitedByteProviderWrapper::new(Box::new(inner), 1, 3);
//!
//! // Within the sub-section [1..4) -- reads real data
//! assert_eq!(wrapper.read_u8(0).unwrap(), 0x20);
//! assert_eq!(wrapper.read_u8(2).unwrap(), 0x40);
//!
//! // Beyond the sub-section -- returns zero
//! assert_eq!(wrapper.read_u8(3).unwrap(), 0x00);
//! assert_eq!(wrapper.read_u8(100).unwrap(), 0x00);
//!
//! // length() still returns the sub-section length
//! assert_eq!(wrapper.length(), 3);
//! ```

use std::io;

use super::byte_provider::ByteProvider;

// ---------------------------------------------------------------------------
// UnlimitedByteProviderWrapper
// ---------------------------------------------------------------------------

/// A [`ByteProvider`] wrapper that allows reading beyond the end of a
/// sub-section, returning zero bytes for out-of-range accesses.
///
/// Ported from `ghidra.app.util.bin.UnlimitedByteProviderWrapper`. This
/// extends `ByteProviderWrapper` behavior by:
///
/// - Allowing reads at any non-negative index
/// - Returning zero bytes for indices beyond the sub-section boundary
/// - Keeping `length()` returning the bounded sub-section length
/// - Keeping `is_valid_index()` accepting any non-negative index
///
/// The `name()` and `absolute_path()` methods delegate to the inner provider.
pub struct UnlimitedByteProviderWrapper {
    inner: Box<dyn ByteProvider>,
    /// The offset in the inner provider where the sub-section starts.
    sub_offset: u64,
    /// The length of the bounded sub-section.
    sub_length: u64,
}

impl UnlimitedByteProviderWrapper {
    /// Create a new unlimited wrapper around a sub-section of the inner provider.
    ///
    /// # Arguments
    ///
    /// * `inner` - The underlying byte provider
    /// * `sub_offset` - The starting offset within `inner`
    /// * `sub_length` - The length of the sub-section
    pub fn new(inner: Box<dyn ByteProvider>, sub_offset: u64, sub_length: u64) -> Self {
        Self {
            inner,
            sub_offset,
            sub_length,
        }
    }

    /// Create an unlimited wrapper covering the full range of the inner provider.
    ///
    /// Equivalent to `new UnlimimitedByteProviderWrapper(provider)` in Java.
    pub fn full_range(inner: Box<dyn ByteProvider>) -> Self {
        let length = inner.length();
        Self {
            inner,
            sub_offset: 0,
            sub_length: length,
        }
    }

    /// Returns the sub-section offset within the inner provider.
    pub fn sub_offset(&self) -> u64 {
        self.sub_offset
    }

    /// Returns the bounded sub-section length.
    pub fn sub_length(&self) -> u64 {
        self.sub_length
    }

    /// Returns a reference to the inner provider.
    pub fn inner(&self) -> &dyn ByteProvider {
        self.inner.as_ref()
    }

    /// Returns true if the given index falls within the real data region.
    pub fn is_in_data(&self, index: u64) -> bool {
        index < self.sub_length
    }

    /// Read a single byte, returning zero for out-of-bounds indices.
    ///
    /// Unlike `read_u8` from the `ByteProvider` trait, this method never
    /// returns an error for valid (non-negative) indices -- it returns
    /// zero for any index beyond the sub-section.
    fn read_byte_unlimited(&self, index: u64) -> u8 {
        if index >= self.sub_length {
            0
        } else {
            // Safe to unwrap: is_valid_index guarantees the inner read succeeds
            // for indices within the sub-section
            self.inner.read_u8(self.sub_offset + index).unwrap_or(0)
        }
    }
}

impl ByteProvider for UnlimitedByteProviderWrapper {
    fn name(&self) -> Option<&str> {
        self.inner.name()
    }

    fn absolute_path(&self) -> Option<&str> {
        self.inner.absolute_path()
    }

    /// Returns the bounded sub-section length.
    ///
    /// Note: this does NOT include the "unlimited" region. Callers should
    /// use `is_valid_index()` to check if reads will succeed with zeros.
    fn length(&self) -> u64 {
        self.sub_length
    }

    /// Returns true for any non-negative index.
    ///
    /// Unlike the standard `ByteProviderWrapper` which returns false for
    /// indices past the end, this wrapper accepts all indices since reads
    /// beyond the boundary return zeros.
    fn is_valid_index(&self, _index: u64) -> bool {
        true
    }

    fn read_u8(&self, index: u64) -> io::Result<u8> {
        Ok(self.read_byte_unlimited(index))
    }

    fn read_bytes(&self, index: u64, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if index >= self.sub_length {
            // Entire read is in the zero-padding region
            for b in buf.iter_mut() {
                *b = 0;
            }
            return Ok(buf.len());
        }

        let data_available = (self.sub_length - index) as usize;
        if buf.len() <= data_available {
            // Entire read is within real data
            self.inner
                .read_bytes(self.sub_offset + index, buf)
                .map(|n| n.min(buf.len()))
        } else {
            // Spans real data and zero region
            let n = self
                .inner
                .read_bytes(self.sub_offset + index, &mut buf[..data_available])
                .unwrap_or(0);
            // Fill remaining with zeros
            for b in &mut buf[n..] {
                *b = 0;
            }
            Ok(buf.len())
        }
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
    fn test_basic_unlimited_wrapper() {
        let inner = ByteArrayProvider::new(None, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let wrapper = UnlimitedByteProviderWrapper::new(Box::new(inner), 2, 5);

        assert_eq!(wrapper.length(), 5);
        assert_eq!(wrapper.sub_offset(), 2);
        assert_eq!(wrapper.sub_length(), 5);

        // Within sub-section [2..7)
        assert_eq!(wrapper.read_u8(0).unwrap(), 2);
        assert_eq!(wrapper.read_u8(1).unwrap(), 3);
        assert_eq!(wrapper.read_u8(4).unwrap(), 6);

        // Beyond sub-section -- returns zero
        assert_eq!(wrapper.read_u8(5).unwrap(), 0);
        assert_eq!(wrapper.read_u8(100).unwrap(), 0);
    }

    #[test]
    fn test_full_range() {
        let inner = ByteArrayProvider::new(Some("test.bin".into()), vec![10, 20, 30]);
        let wrapper = UnlimitedByteProviderWrapper::full_range(Box::new(inner));

        assert_eq!(wrapper.length(), 3);
        assert_eq!(wrapper.name(), Some("test.bin"));

        assert_eq!(wrapper.read_u8(0).unwrap(), 10);
        assert_eq!(wrapper.read_u8(2).unwrap(), 30);
        assert_eq!(wrapper.read_u8(3).unwrap(), 0);
        assert_eq!(wrapper.read_u8(999).unwrap(), 0);
    }

    #[test]
    fn test_is_valid_index_always_true() {
        let inner = ByteArrayProvider::new(None, vec![1, 2, 3]);
        let wrapper = UnlimitedByteProviderWrapper::new(Box::new(inner), 0, 3);

        assert!(wrapper.is_valid_index(0));
        assert!(wrapper.is_valid_index(3));
        assert!(wrapper.is_valid_index(1000));
        assert!(wrapper.is_valid_index(u64::MAX));
    }

    #[test]
    fn test_is_in_data() {
        let inner = ByteArrayProvider::new(None, vec![1, 2, 3, 4, 5]);
        let wrapper = UnlimitedByteProviderWrapper::new(Box::new(inner), 0, 3);

        assert!(wrapper.is_in_data(0));
        assert!(wrapper.is_in_data(2));
        assert!(!wrapper.is_in_data(3));
        assert!(!wrapper.is_in_data(100));
    }

    #[test]
    fn test_read_bytes_entirely_in_data() {
        let inner = ByteArrayProvider::new(None, vec![0, 10, 20, 30, 40]);
        let wrapper = UnlimitedByteProviderWrapper::new(Box::new(inner), 1, 3);

        let mut buf = [0xFF; 2];
        let n = wrapper.read_bytes(0, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [10, 20]);
    }

    #[test]
    fn test_read_bytes_spanning_boundary() {
        let inner = ByteArrayProvider::new(None, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let wrapper = UnlimitedByteProviderWrapper::new(Box::new(inner), 0, 3);

        let mut buf = [0xFF; 5];
        let n = wrapper.read_bytes(1, &mut buf).unwrap();
        assert_eq!(n, 5);
        // bytes 1-2 are real data, 3-4 are zero
        assert_eq!(buf, [0xBB, 0xCC, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_read_bytes_entirely_beyond() {
        let inner = ByteArrayProvider::new(None, vec![1, 2, 3]);
        let wrapper = UnlimitedByteProviderWrapper::new(Box::new(inner), 0, 3);

        let mut buf = [0xFF; 4];
        let n = wrapper.read_bytes(10, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [0, 0, 0, 0]);
    }

    #[test]
    fn test_read_bytes_empty_buf() {
        let inner = ByteArrayProvider::new(None, vec![1, 2, 3]);
        let wrapper = UnlimitedByteProviderWrapper::new(Box::new(inner), 0, 3);

        let mut buf = [];
        let n = wrapper.read_bytes(0, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_with_sub_offset() {
        let inner = ByteArrayProvider::new(None, vec![0, 0, 0, 100, 200]);
        let wrapper = UnlimitedByteProviderWrapper::new(Box::new(inner), 3, 2);

        assert_eq!(wrapper.read_u8(0).unwrap(), 100);
        assert_eq!(wrapper.read_u8(1).unwrap(), 200);
        assert_eq!(wrapper.read_u8(2).unwrap(), 0);
        assert_eq!(wrapper.read_u8(100).unwrap(), 0);
    }

    #[test]
    fn test_empty_subsection() {
        let inner = ByteArrayProvider::new(None, vec![1, 2, 3]);
        let wrapper = UnlimitedByteProviderWrapper::new(Box::new(inner), 0, 0);

        assert_eq!(wrapper.length(), 0);
        assert_eq!(wrapper.read_u8(0).unwrap(), 0);
        assert_eq!(wrapper.read_u8(100).unwrap(), 0);
    }

    #[test]
    fn test_absolute_path_delegates() {
        use std::path::PathBuf;
        let inner =
            ByteArrayProvider::with_path(None, PathBuf::from("/tmp/test.bin"), vec![1, 2, 3]);
        let wrapper = UnlimitedByteProviderWrapper::full_range(Box::new(inner));

        assert_eq!(wrapper.absolute_path(), Some("/tmp/test.bin"));
    }

    #[test]
    fn test_name_delegates() {
        let inner = ByteArrayProvider::new(Some("mylib.so".into()), vec![1, 2, 3]);
        let wrapper = UnlimitedByteProviderWrapper::full_range(Box::new(inner));

        assert_eq!(wrapper.name(), Some("mylib.so"));
    }
}
