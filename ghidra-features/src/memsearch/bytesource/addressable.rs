//! `AddressableByteSource` -- interface for reading bytes from a program.
//!
//! Ported from `ghidra.features.base.memsearch.bytesource.AddressableByteSource`.

use crate::memsearch::bytesource::SearchRegion;

/// Trait for reading bytes from a program address space.
///
/// Provides a level of indirection for reading program bytes, allowing
/// providers (e.g. a debugger) to refresh bytes before returning them.
///
/// Also provides methods for determining what memory regions can be
/// queried and what address sets are associated with those regions.
pub trait AddressableByteSource {
    /// Retrieves byte values for an address range.
    ///
    /// Returns the number of bytes actually retrieved.
    fn get_bytes(&self, address: u64, buffer: &mut [u8], length: usize) -> usize;

    /// Returns a list of memory regions where each region has an associated
    /// address set of valid addresses that can be read.
    fn get_searchable_regions(&self) -> Vec<Box<dyn SearchRegion>>;

    /// Invalidates any caching of byte values. Intended as a hint in
    /// debugging scenarios that we are about to re-request byte values
    /// to look for changes.
    fn invalidate(&self);

    /// Convert a byte source address to a canonical (static) offset.
    fn get_canonical_offset(&self, address: u64) -> u64 {
        address
    }

    /// Rebase a canonical offset back into this byte source's address space.
    fn rebase_from_canonical(&self, canonical_offset: u64) -> u64 {
        canonical_offset
    }
}

/// An [`AddressableByteSource`] backed by a contiguous byte buffer.
///
/// Useful for testing and for searching raw binary data.
#[derive(Debug, Clone)]
pub struct ByteBufferSource {
    data: Vec<u64>,
}

impl ByteBufferSource {
    /// Create a new byte buffer source from raw bytes.
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data: data.into_iter().map(|b| b as u64).collect(),
        }
    }

    /// Create a new byte buffer source with explicit address-to-byte mapping.
    pub fn with_addresses(entries: Vec<(u64, u8)>) -> Self {
        Self {
            data: entries.into_iter().map(|(addr, _)| addr).collect(),
        }
    }
}

impl AddressableByteSource for ByteBufferSource {
    fn get_bytes(&self, address: u64, buffer: &mut [u8], length: usize) -> usize {
        let start = address as usize;
        if start >= self.data.len() {
            return 0;
        }
        let count = length.min(self.data.len() - start).min(buffer.len());
        for i in 0..count {
            buffer[i] = self.data[start + i] as u8;
        }
        count
    }

    fn get_searchable_regions(&self) -> Vec<Box<dyn SearchRegion>> {
        Vec::new()
    }

    fn invalidate(&self) {}
}
