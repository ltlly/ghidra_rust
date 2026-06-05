//! Byte caching utility for trace program views.
//!
//! Ported from Ghidra's `ByteCache` in `ghidra.trace.database.program`.
//! Provides a simple cache for memory bytes used by program views to
//! avoid repeated database lookups during listing/disassembly operations.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A cache for memory bytes indexed by address offset.
///
/// Used by `DBTraceProgramView` and related classes to cache bytes
/// fetched from the trace database. The cache is snap-scoped, meaning
/// each cache instance holds bytes from a single snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ByteCache {
    /// Cached byte entries keyed by (base_offset, byte_offset).
    entries: BTreeMap<u64, CachedPage>,
    /// Maximum number of pages to cache.
    max_pages: usize,
}

/// A single page of cached bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedPage {
    /// The base address of this page.
    pub base_address: u64,
    /// The raw bytes.
    pub bytes: Vec<u8>,
    /// The snap at which this data was read.
    pub snap: i64,
}

impl CachedPage {
    /// Create a new cached page.
    pub fn new(base_address: u64, bytes: Vec<u8>, snap: i64) -> Self {
        Self {
            base_address,
            bytes,
            snap,
        }
    }

    /// Get the byte at the given offset within this page.
    pub fn byte_at(&self, offset: u64) -> Option<u8> {
        let idx = offset.checked_sub(self.base_address)? as usize;
        self.bytes.get(idx).copied()
    }

    /// Get the length of this page.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if this page is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl ByteCache {
    /// Create a new byte cache with default settings.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            max_pages: 256,
        }
    }

    /// Create a new byte cache with a specified maximum page count.
    pub fn with_max_pages(max_pages: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            max_pages,
        }
    }

    /// Put a page into the cache.
    pub fn put_page(&mut self, base_address: u64, bytes: Vec<u8>, snap: i64) {
        if self.entries.len() >= self.max_pages {
            // Evict the oldest entry (first key in BTreeMap)
            if let Some(first_key) = self.entries.keys().next().copied() {
                self.entries.remove(&first_key);
            }
        }
        self.entries
            .insert(base_address, CachedPage::new(base_address, bytes, snap));
    }

    /// Get a cached byte at the given address.
    pub fn get_byte(&self, address: u64) -> Option<u8> {
        // Find the page that might contain this address
        for (_, page) in self.entries.range(..=address).rev().take(1) {
            if let Some(byte) = page.byte_at(address) {
                return Some(byte);
            }
        }
        None
    }

    /// Get a page by base address.
    pub fn get_page(&self, base_address: u64) -> Option<&CachedPage> {
        self.entries.get(&base_address)
    }

    /// Check if a byte is cached at the given address.
    pub fn has_byte(&self, address: u64) -> bool {
        self.get_byte(address).is_some()
    }

    /// Clear the entire cache.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Get the number of cached pages.
    pub fn page_count(&self) -> usize {
        self.entries.len()
    }

    /// Get the total number of cached bytes.
    pub fn total_bytes(&self) -> usize {
        self.entries.values().map(|p| p.len()).sum()
    }

    /// Invalidate all entries for a given snap.
    pub fn invalidate_snap(&mut self, snap: i64) {
        self.entries.retain(|_, page| page.snap != snap);
    }

    /// Get all cached addresses (sorted).
    pub fn cached_addresses(&self) -> Vec<u64> {
        self.entries.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_cache_new() {
        let cache = ByteCache::new();
        assert_eq!(cache.page_count(), 0);
        assert_eq!(cache.total_bytes(), 0);
    }

    #[test]
    fn test_byte_cache_put_and_get() {
        let mut cache = ByteCache::new();
        cache.put_page(0x1000, vec![0xAA, 0xBB, 0xCC], 0);
        assert_eq!(cache.get_byte(0x1000), Some(0xAA));
        assert_eq!(cache.get_byte(0x1001), Some(0xBB));
        assert_eq!(cache.get_byte(0x1002), Some(0xCC));
        assert_eq!(cache.get_byte(0x1003), None);
    }

    #[test]
    fn test_byte_cache_miss() {
        let cache = ByteCache::new();
        assert_eq!(cache.get_byte(0x1000), None);
    }

    #[test]
    fn test_byte_cache_multiple_pages() {
        let mut cache = ByteCache::new();
        cache.put_page(0x1000, vec![1, 2, 3], 0);
        cache.put_page(0x2000, vec![4, 5, 6], 0);
        assert_eq!(cache.get_byte(0x1001), Some(2));
        assert_eq!(cache.get_byte(0x2002), Some(6));
    }

    #[test]
    fn test_byte_cache_eviction() {
        let mut cache = ByteCache::with_max_pages(2);
        cache.put_page(0x1000, vec![1], 0);
        cache.put_page(0x2000, vec![2], 0);
        cache.put_page(0x3000, vec![3], 0);
        // First page should be evicted
        assert_eq!(cache.page_count(), 2);
        assert_eq!(cache.get_byte(0x1000), None);
        assert_eq!(cache.get_byte(0x2000), Some(2));
        assert_eq!(cache.get_byte(0x3000), Some(3));
    }

    #[test]
    fn test_byte_cache_clear() {
        let mut cache = ByteCache::new();
        cache.put_page(0x1000, vec![1, 2], 0);
        cache.clear();
        assert_eq!(cache.page_count(), 0);
    }

    #[test]
    fn test_byte_cache_invalidate_snap() {
        let mut cache = ByteCache::new();
        cache.put_page(0x1000, vec![1], 5);
        cache.put_page(0x2000, vec![2], 10);
        cache.invalidate_snap(5);
        assert_eq!(cache.page_count(), 1);
        assert!(cache.has_byte(0x2000));
        assert!(!cache.has_byte(0x1000));
    }

    #[test]
    fn test_cached_page_byte_at() {
        let page = CachedPage::new(0x100, vec![10, 20, 30], 0);
        assert_eq!(page.byte_at(0x100), Some(10));
        assert_eq!(page.byte_at(0x101), Some(20));
        assert_eq!(page.byte_at(0x102), Some(30));
        assert_eq!(page.byte_at(0x103), None);
        assert_eq!(page.byte_at(0x099), None);
    }

    #[test]
    fn test_byte_cache_total_bytes() {
        let mut cache = ByteCache::new();
        cache.put_page(0x1000, vec![1, 2, 3], 0);
        cache.put_page(0x2000, vec![4, 5], 0);
        assert_eq!(cache.total_bytes(), 5);
    }

    #[test]
    fn test_byte_cache_cached_addresses() {
        let mut cache = ByteCache::new();
        cache.put_page(0x3000, vec![1], 0);
        cache.put_page(0x1000, vec![2], 0);
        cache.put_page(0x2000, vec![3], 0);
        let addrs = cache.cached_addresses();
        assert_eq!(addrs, vec![0x1000, 0x2000, 0x3000]);
    }
}
