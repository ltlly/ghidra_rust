//! Range-mapped sparse byte provider ported from Ghidra's
//! `ghidra.app.util.bin.RangeMappedByteProvider`.
//!
//! Provides a [`ByteProvider`] that is a concatenation of sub-ranges of
//! another `ByteProvider`, also allowing for non-initialized (sparse) regions
//! that return zero bytes.

use std::collections::BTreeMap;
use std::io;
use std::sync::Mutex;

use super::byte_provider::ByteProvider;

// ---------------------------------------------------------------------------
// RangeMappedByteProvider
// ---------------------------------------------------------------------------

/// A [`ByteProvider`] that presents a virtual concatenation of sub-ranges from
/// a delegate provider, with support for sparse (zero-filled) gaps.
///
/// Ported from `ghidra.app.util.bin.RangeMappedByteProvider`. This provider
/// allows constructing a virtual byte stream by mapping non-contiguous regions
/// of a source provider into a contiguous address space.
///
/// # Example
///
/// ```
/// use ghidra_features::bin_format::byte_provider::ByteArrayProvider;
/// use ghidra_features::bin_format::range_mapped_provider::RangeMappedByteProvider;
/// use ghidra_features::bin_format::ByteProvider;
///
/// // Source has 10 bytes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
/// let source = Box::new(ByteArrayProvider::new(None, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]));
/// let mut provider = RangeMappedByteProvider::new(source, Some("test".into()));
///
/// // Map bytes [2..5] from source, then 3 sparse bytes, then bytes [8..10]
/// provider.add_range(2, 3);       // source offset 2, length 3
/// provider.add_sparse_range(3);   // 3 zero bytes
/// provider.add_range(8, 2);       // source offset 8, length 2
///
/// assert_eq!(provider.length(), 8);
/// assert_eq!(provider.read_u8(0).unwrap(), 2);  // from source[2]
/// assert_eq!(provider.read_u8(3).unwrap(), 0);  // sparse
/// assert_eq!(provider.read_u8(6).unwrap(), 8);  // from source[8]
/// ```
pub struct RangeMappedByteProvider {
    inner: Mutex<RangeMappedInner>,
    name: Option<String>,
}

struct RangeMappedInner {
    delegate: Box<dyn ByteProvider>,
    /// Maps virtual-offset -> delegate-offset.
    /// Each range is defined by the gap between adjacent entries.
    /// The last entry is bounded by `total_length`.
    /// A delegate offset of `u64::MAX` indicates a sparse (zero-filled) range.
    offset_map: BTreeMap<u64, u64>,
    total_length: u64,
}

/// Sentinel value indicating a sparse (zero-filled) range in the offset map.
const SPARSE_OFFSET: u64 = u64::MAX;

impl RangeMappedByteProvider {
    /// Creates a new empty range-mapped byte provider.
    ///
    /// # Arguments
    ///
    /// * `delegate` - The underlying `ByteProvider` to read ranges from
    /// * `name` - Optional display name for this provider
    pub fn new(delegate: Box<dyn ByteProvider>, name: Option<String>) -> Self {
        Self {
            inner: Mutex::new(RangeMappedInner {
                delegate,
                offset_map: BTreeMap::new(),
                total_length: 0,
            }),
            name,
        }
    }

    /// Adds a range to the current end of this provider.
    ///
    /// If the new range immediately follows the previous range in the delegate
    /// provider, it is merged into the previous entry (no new map entry is created).
    ///
    /// # Arguments
    ///
    /// * `offset` - Byte offset in the delegate provider. Use `None` for sparse ranges.
    /// * `range_len` - Length of the range in bytes. Must be > 0.
    pub fn add_range(&self, offset: u64, range_len: u64) {
        if range_len == 0 {
            return;
        }

        let mut inner = self.inner.lock().unwrap();

        if let Some((&last_key, &last_delegate_offset)) = inner.offset_map.iter().next_back() {
            // Try to merge sparse ranges
            if offset == SPARSE_OFFSET && last_delegate_offset == SPARSE_OFFSET {
                inner.total_length += range_len;
                return;
            }

            // Try to merge this new range into the previous contiguous range
            // (only if the new range is not sparse)
            let last_range_len = inner.total_length - last_key;
            if offset != SPARSE_OFFSET
                && last_delegate_offset != SPARSE_OFFSET
                && last_delegate_offset + last_range_len == offset
            {
                inner.total_length += range_len;
                return;
            }
        }

        let current_length = inner.total_length;
        inner.offset_map.insert(current_length, offset);
        inner.total_length += range_len;
    }

    /// Adds a sparse (zero-filled) range to the current end of this provider.
    ///
    /// # Arguments
    ///
    /// * `range_len` - Length of the sparse range in bytes. Must be > 0.
    pub fn add_sparse_range(&self, range_len: u64) {
        self.add_range(SPARSE_OFFSET, range_len);
    }

    /// Returns the number of mapped ranges.
    ///
    /// Adjacent ranges that were merged will count as a single range.
    pub fn range_count(&self) -> usize {
        self.inner.lock().unwrap().offset_map.len()
    }

    /// Returns the delegate provider offset for a given virtual index.
    ///
    /// Returns `None` if the index falls in a sparse range.
    fn resolve_offset(&self, inner: &RangeMappedInner, index: u64) -> Option<u64> {
        // Find the entry with the largest key <= index
        let (&range_start, &delegate_start) = inner
            .offset_map
            .range(..=index)
            .next_back()?;

        if delegate_start == SPARSE_OFFSET {
            return None;
        }

        let range_offset = index - range_start;
        Some(delegate_start + range_offset)
    }

    /// Returns the end of the range containing the given virtual index.
    fn range_end(&self, inner: &RangeMappedInner, index: u64) -> u64 {
        // Find the next entry after the one containing index
        let (&range_start, _) = match inner.offset_map.range(..=index).next_back() {
            Some(entry) => entry,
            None => return inner.total_length,
        };

        inner
            .offset_map
            .range((range_start + 1)..)
            .next()
            .map(|(&k, _)| k)
            .unwrap_or(inner.total_length)
    }

    /// Read bytes across range boundaries, handling sparse gaps.
    fn read_bytes_cross_range(
        &self,
        inner: &RangeMappedInner,
        index: u64,
        buf: &mut [u8],
    ) -> io::Result<usize> {
        let mut total_read = 0;
        let mut current_index = index;
        let remaining = (inner.total_length.saturating_sub(index)) as usize;
        let to_read = buf.len().min(remaining);

        while total_read < to_read {
            let range_end = self.range_end(inner, current_index);
            let bytes_available = (range_end - current_index) as usize;
            let bytes_to_read = bytes_available.min(to_read - total_read);

            match self.resolve_offset(inner, current_index) {
                Some(delegate_offset) => {
                    let n = inner
                        .delegate
                        .read_bytes(delegate_offset, &mut buf[total_read..total_read + bytes_to_read])?;
                    total_read += n;
                    if n < bytes_to_read {
                        break;
                    }
                }
                None => {
                    // Sparse range -- fill with zeros
                    for b in &mut buf[total_read..total_read + bytes_to_read] {
                        *b = 0;
                    }
                    total_read += bytes_to_read;
                }
            }

            current_index += bytes_to_read as u64;
        }

        Ok(total_read)
    }
}

impl ByteProvider for RangeMappedByteProvider {
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn absolute_path(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn length(&self) -> u64 {
        self.inner.lock().unwrap().total_length
    }

    fn is_valid_index(&self, index: u64) -> bool {
        let inner = self.inner.lock().unwrap();
        index < inner.total_length
    }

    fn read_u8(&self, index: u64) -> io::Result<u8> {
        let inner = self.inner.lock().unwrap();

        if index >= inner.total_length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("index {} out of range (len={})", index, inner.total_length),
            ));
        }

        match self.resolve_offset(&inner, index) {
            Some(delegate_offset) => inner.delegate.read_u8(delegate_offset),
            None => Ok(0), // sparse range
        }
    }

    fn read_bytes(&self, index: u64, buf: &mut [u8]) -> io::Result<usize> {
        let inner = self.inner.lock().unwrap();

        if index >= inner.total_length {
            return Ok(0);
        }

        self.read_bytes_cross_range(&inner, index, buf)
    }

    fn close(&self) {
        // Do not close the delegate provider -- we don't own it.
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
    fn test_basic_range_mapping() {
        let source = Box::new(ByteArrayProvider::new(
            None,
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        ));
        let provider = RangeMappedByteProvider::new(source, None);

        // Map bytes [2..5] from source
        provider.add_range(2, 3);

        assert_eq!(provider.length(), 3);
        assert_eq!(provider.read_u8(0).unwrap(), 2);
        assert_eq!(provider.read_u8(1).unwrap(), 3);
        assert_eq!(provider.read_u8(2).unwrap(), 4);
    }

    #[test]
    fn test_sparse_range() {
        let source = Box::new(ByteArrayProvider::new(
            None,
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        ));
        let provider = RangeMappedByteProvider::new(source, None);

        provider.add_range(0, 2); // bytes [0, 1]
        provider.add_sparse_range(3); // 3 zero bytes
        provider.add_range(8, 2); // bytes [8, 9]

        assert_eq!(provider.length(), 7);
        assert_eq!(provider.read_u8(0).unwrap(), 0);
        assert_eq!(provider.read_u8(1).unwrap(), 1);
        assert_eq!(provider.read_u8(2).unwrap(), 0); // sparse
        assert_eq!(provider.read_u8(3).unwrap(), 0); // sparse
        assert_eq!(provider.read_u8(4).unwrap(), 0); // sparse
        assert_eq!(provider.read_u8(5).unwrap(), 8);
        assert_eq!(provider.read_u8(6).unwrap(), 9);
    }

    #[test]
    fn test_adjacent_ranges_merge() {
        let source = Box::new(ByteArrayProvider::new(
            None,
            vec![0, 1, 2, 3, 4, 5],
        ));
        let provider = RangeMappedByteProvider::new(source, None);

        provider.add_range(0, 3);
        provider.add_range(3, 3); // should merge with previous

        assert_eq!(provider.length(), 6);
        assert_eq!(provider.range_count(), 1); // merged into one range
        assert_eq!(provider.read_u8(0).unwrap(), 0);
        assert_eq!(provider.read_u8(5).unwrap(), 5);
    }

    #[test]
    fn test_sparse_ranges_merge() {
        let source = Box::new(ByteArrayProvider::new(None, vec![1, 2, 3]));
        let provider = RangeMappedByteProvider::new(source, None);

        provider.add_sparse_range(5);
        provider.add_sparse_range(3); // should merge

        assert_eq!(provider.length(), 8);
        assert_eq!(provider.range_count(), 1);

        // All should be zeros
        for i in 0..8 {
            assert_eq!(provider.read_u8(i).unwrap(), 0);
        }
    }

    #[test]
    fn test_read_bytes_cross_range() {
        let source = Box::new(ByteArrayProvider::new(
            None,
            vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
        ));
        let provider = RangeMappedByteProvider::new(source, None);

        provider.add_range(1, 2); // [0xBB, 0xCC]
        provider.add_sparse_range(2); // [0, 0]
        provider.add_range(4, 1); // [0xEE]

        let mut buf = [0u8; 5];
        let n = provider.read_bytes(0, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(buf, [0xBB, 0xCC, 0, 0, 0xEE]);
    }

    #[test]
    fn test_out_of_range() {
        let source = Box::new(ByteArrayProvider::new(None, vec![1, 2, 3]));
        let provider = RangeMappedByteProvider::new(source, None);
        provider.add_range(0, 3);

        let result = provider.read_u8(10);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_provider() {
        let source = Box::new(ByteArrayProvider::new(None, vec![1, 2, 3]));
        let provider = RangeMappedByteProvider::new(source, None);

        assert_eq!(provider.length(), 0);
        assert!(!provider.is_valid_index(0));
        assert_eq!(provider.range_count(), 0);
    }

    #[test]
    fn test_range_count() {
        let source = Box::new(ByteArrayProvider::new(
            None,
            (0..20u8).collect::<Vec<_>>(),
        ));
        let provider = RangeMappedByteProvider::new(source, None);

        provider.add_range(0, 3);   // range 1
        provider.add_range(10, 3);  // range 2 (gap in delegate, so not merged)
        provider.add_range(15, 2);  // range 3

        assert_eq!(provider.range_count(), 3);
    }

    #[test]
    fn test_read_bytes_partial() {
        let source = Box::new(ByteArrayProvider::new(None, vec![10, 20, 30, 40, 50]));
        let provider = RangeMappedByteProvider::new(source, None);
        provider.add_range(0, 5);

        let mut buf = [0u8; 3];
        let n = provider.read_bytes(2, &mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(buf, [30, 40, 50]);
    }

    #[test]
    fn test_is_valid_index() {
        let source = Box::new(ByteArrayProvider::new(None, vec![1, 2, 3]));
        let provider = RangeMappedByteProvider::new(source, None);
        provider.add_range(0, 3);

        assert!(provider.is_valid_index(0));
        assert!(provider.is_valid_index(2));
        assert!(!provider.is_valid_index(3));
    }
}
