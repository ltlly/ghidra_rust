//! ByteCache - a cache for byte ranges.
//!
//! Ported from Ghidra's `ByteCache` from Framework-TraceModeling.

use std::collections::BTreeMap;

/// A cache that stores byte values indexed by offset.
///
/// Ported from Ghidra's `ByteCache`. Used to cache memory reads
/// during trace operations and emulation.
#[derive(Debug, Clone, Default)]
pub struct ByteCache {
    /// Stored bytes indexed by offset.
    entries: BTreeMap<u64, u8>,
}

impl ByteCache {
    /// Create a new empty byte cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a cache from a byte slice at a given base offset.
    pub fn from_bytes(base: u64, bytes: &[u8]) -> Self {
        let mut cache = Self::new();
        cache.put_bytes(base, bytes);
        cache
    }

    /// Put a single byte at the given offset.
    pub fn put(&mut self, offset: u64, byte: u8) {
        self.entries.insert(offset, byte);
    }

    /// Put multiple bytes starting at the given offset.
    pub fn put_bytes(&mut self, base: u64, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            self.entries.insert(base + i as u64, b);
        }
    }

    /// Get a single byte at the given offset.
    pub fn get(&self, offset: u64) -> Option<u8> {
        self.entries.get(&offset).copied()
    }

    /// Get a byte or return a default value.
    pub fn get_or(&self, offset: u64, default: u8) -> u8 {
        self.entries.get(&offset).copied().unwrap_or(default)
    }

    /// Read a range of bytes into a buffer. Returns the number of bytes read.
    /// Bytes not in the cache are left unchanged in the buffer.
    pub fn get_bytes(&self, base: u64, buf: &mut [u8]) -> usize {
        let mut count = 0;
        for (i, slot) in buf.iter_mut().enumerate() {
            if let Some(&b) = self.entries.get(&(base + i as u64)) {
                *slot = b;
                count += 1;
            }
        }
        count
    }

    /// Check if the cache contains a byte at the given offset.
    pub fn contains(&self, offset: u64) -> bool {
        self.entries.contains_key(&offset)
    }

    /// Remove a byte from the cache.
    pub fn remove(&mut self, offset: u64) -> Option<u8> {
        self.entries.remove(&offset)
    }

    /// Remove all bytes in a range.
    pub fn remove_range(&mut self, start: u64, end: u64) {
        let keys: Vec<u64> = self
            .entries
            .range(start..end)
            .map(|(&k, _)| k)
            .collect();
        for k in keys {
            self.entries.remove(&k);
        }
    }

    /// Clear the entire cache.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// The number of cached bytes.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the minimum offset in the cache.
    pub fn min_offset(&self) -> Option<u64> {
        self.entries.keys().next().copied()
    }

    /// Get the maximum offset in the cache.
    pub fn max_offset(&self) -> Option<u64> {
        self.entries.keys().next_back().copied()
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = (u64, u8)> + '_ {
        self.entries.iter().map(|(&k, &v)| (k, v))
    }

    /// Merge another cache into this one, overwriting existing entries.
    pub fn merge(&mut self, other: &ByteCache) {
        for (&k, &v) in &other.entries {
            self.entries.insert(k, v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_put_get() {
        let mut cache = ByteCache::new();
        cache.put(0x100, 0x90);
        assert_eq!(cache.get(0x100), Some(0x90));
        assert_eq!(cache.get(0x200), None);
    }

    #[test]
    fn test_put_bytes() {
        let mut cache = ByteCache::new();
        cache.put_bytes(0x1000, &[0xCC, 0x90, 0xEB]);
        assert_eq!(cache.get(0x1000), Some(0xCC));
        assert_eq!(cache.get(0x1001), Some(0x90));
        assert_eq!(cache.get(0x1002), Some(0xEB));
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn test_from_bytes() {
        let cache = ByteCache::from_bytes(0x400, &[1, 2, 3]);
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.get(0x401), Some(2));
    }

    #[test]
    fn test_get_bytes() {
        let mut cache = ByteCache::new();
        cache.put_bytes(0x100, &[0xAA, 0xBB, 0xCC]);
        let mut buf = [0u8; 4];
        let count = cache.get_bytes(0x100, &mut buf);
        assert_eq!(count, 3);
        assert_eq!(buf, [0xAA, 0xBB, 0xCC, 0x00]);
    }

    #[test]
    fn test_get_or() {
        let cache = ByteCache::new();
        assert_eq!(cache.get_or(0, 0xFF), 0xFF);
    }

    #[test]
    fn test_contains() {
        let mut cache = ByteCache::new();
        cache.put(5, 0);
        assert!(cache.contains(5));
        assert!(!cache.contains(6));
    }

    #[test]
    fn test_remove_range() {
        let mut cache = ByteCache::new();
        cache.put_bytes(0, &[0, 1, 2, 3, 4, 5]);
        cache.remove_range(2, 5);
        assert_eq!(cache.len(), 3);
        assert!(cache.contains(1));
        assert!(!cache.contains(2));
        assert!(cache.contains(5));
    }

    #[test]
    fn test_min_max() {
        let mut cache = ByteCache::new();
        assert!(cache.min_offset().is_none());
        cache.put_bytes(10, &[1, 2, 3]);
        assert_eq!(cache.min_offset(), Some(10));
        assert_eq!(cache.max_offset(), Some(12));
    }

    #[test]
    fn test_merge() {
        let mut a = ByteCache::from_bytes(0, &[1, 2, 3]);
        let b = ByteCache::from_bytes(2, &[9, 8]);
        a.merge(&b);
        assert_eq!(a.get(0), Some(1));
        assert_eq!(a.get(2), Some(9));
        assert_eq!(a.get(3), Some(8));
    }

    #[test]
    fn test_iter() {
        let cache = ByteCache::from_bytes(10, &[0xA, 0xB]);
        let items: Vec<_> = cache.iter().collect();
        assert_eq!(items, vec![(10, 0xA), (11, 0xB)]);
    }
}
