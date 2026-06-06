//! `EmptyByteSource` -- a no-op byte source.
//!
//! Ported from `ghidra.features.base.memsearch.bytesource.EmptyByteSource`.

use crate::memsearch::bytesource::addressable::AddressableByteSource;
use crate::memsearch::bytesource::search_region::SearchRegion;

/// A singleton empty byte source that always returns zero bytes.
///
/// Used as a placeholder when no program is loaded.
#[derive(Debug, Clone, Copy)]
pub struct EmptyByteSource;

impl AddressableByteSource for EmptyByteSource {
    fn get_bytes(&self, _address: u64, _buffer: &mut [u8], _length: usize) -> usize {
        0
    }

    fn get_searchable_regions(&self) -> Vec<Box<dyn SearchRegion>> {
        Vec::new()
    }

    fn invalidate(&self) {}

    fn get_canonical_offset(&self, address: u64) -> u64 {
        address
    }

    fn rebase_from_canonical(&self, canonical_offset: u64) -> u64 {
        canonical_offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_byte_source() {
        let source = EmptyByteSource;
        let mut buf = [0u8; 16];
        assert_eq!(source.get_bytes(0, &mut buf, 16), 0);
        assert!(source.get_searchable_regions().is_empty());
    }

    #[test]
    fn test_canonical_roundtrip() {
        let source = EmptyByteSource;
        assert_eq!(source.get_canonical_offset(0x401000), 0x401000);
        assert_eq!(source.rebase_from_canonical(0x401000), 0x401000);
    }
}
