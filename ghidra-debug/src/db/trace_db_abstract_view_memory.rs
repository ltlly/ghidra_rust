//! AbstractDBTraceProgramViewMemory - abstract memory view for program views.
//!
//! Ported from `ghidra.trace.database.program.AbstractDBTraceProgramViewMemory`.
//! Provides the base implementation for memory access in a trace program view,
//! including byte caching, address set computation, and byte search.
//!
//! This is the non-GUI portion of the Java class, adapted for Rust's type system.
//! The Swing-specific methods (MemoryBlock creation, FileBytes) are represented
//! as stubs since Rust has no Swing dependency.

use std::collections::BTreeSet;

/// Cache for memory bytes, supporting page-based reads.
///
/// The Java original uses a 3-page cache; this Rust version stores
/// recently-accessed bytes in a simple key-value map.
#[derive(Debug)]
pub struct BytePageCache {
    /// Cached bytes keyed by (space_id, address).
    entries: Vec<(u16, u64, Vec<u8>)>,
    /// Maximum number of cache entries.
    max_entries: usize,
}

impl BytePageCache {
    /// Create a new byte cache with the given capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::with_capacity(max_entries),
            max_entries,
        }
    }

    /// Try to read bytes from the cache. Returns `Some(bytes)` on hit.
    pub fn try_read(&self, space_id: u16, address: u64, len: usize) -> Option<Vec<u8>> {
        for (sid, addr, data) in &self.entries {
            if *sid == space_id && *addr == address && data.len() >= len {
                return Some(data[..len].to_vec());
            }
        }
        None
    }

    /// Store bytes in the cache, evicting the oldest entry if full.
    pub fn store(&mut self, space_id: u16, address: u64, data: Vec<u8>) {
        if self.entries.len() >= self.max_entries {
            self.entries.remove(0);
        }
        self.entries.push((space_id, address, data));
    }

    /// Invalidate all cache entries.
    pub fn invalidate(&mut self) {
        self.entries.clear();
    }
}

/// Abstract memory view data for a trace program.
///
/// Provides the base for reading/writing bytes in a trace at a specific
/// snapshot. Manages an address set (the set of valid addresses) and a
/// byte cache for performance.
#[derive(Debug)]
pub struct AbstractProgramViewMemoryData {
    /// The snapshot this view is pinned to.
    pub snap: i64,
    /// The cached address set.
    address_set: BTreeSet<u64>,
    /// Whether the address set is valid.
    address_set_valid: bool,
    /// Whether to force the full view (ignoring snapshot-specific sets).
    pub force_full_view: bool,
    /// Byte cache for read performance.
    pub cache: BytePageCache,
}

impl AbstractProgramViewMemoryData {
    /// Create a new memory view data for the given snapshot.
    pub fn new(snap: i64) -> Self {
        Self {
            snap,
            address_set: BTreeSet::new(),
            address_set_valid: false,
            force_full_view: false,
            cache: BytePageCache::new(3),
        }
    }

    /// Set the snapshot for this view.
    pub fn set_snap(&mut self, snap: i64) {
        self.snap = snap;
        if !self.force_full_view {
            self.invalidate_address_set();
        }
    }

    /// Get the current snapshot.
    pub fn get_snap(&self) -> i64 {
        self.snap
    }

    /// Set whether to force the full view.
    pub fn set_force_full_view(&mut self, force: bool) {
        self.force_full_view = force;
        self.invalidate_address_set();
    }

    /// Check if the full view is forced.
    pub fn is_force_full_view(&self) -> bool {
        self.force_full_view
    }

    /// Invalidate the cached address set, forcing re-computation.
    pub fn invalidate_address_set(&mut self) {
        self.address_set_valid = false;
        self.address_set.clear();
    }

    /// Set the address set directly (e.g., from a computed value).
    pub fn set_address_set(&mut self, addresses: BTreeSet<u64>) {
        self.address_set = addresses;
        self.address_set_valid = true;
    }

    /// Get the address set.
    pub fn get_address_set(&self) -> &BTreeSet<u64> {
        &self.address_set
    }

    /// Check if the address set is currently valid.
    pub fn is_address_set_valid(&self) -> bool {
        self.address_set_valid
    }

    /// Check if this view contains the given address.
    pub fn contains(&self, address: u64) -> bool {
        self.address_set.contains(&address)
    }

    /// Check if this view is empty.
    pub fn is_empty(&self) -> bool {
        self.address_set.is_empty()
    }

    /// Get the number of addresses in this view.
    pub fn get_num_addresses(&self) -> u64 {
        self.address_set.len() as u64
    }

    /// Get the minimum address in this view.
    pub fn get_min_address(&self) -> Option<u64> {
        self.address_set.iter().next().copied()
    }

    /// Get the maximum address in this view.
    pub fn get_max_address(&self) -> Option<u64> {
        self.address_set.iter().next_back().copied()
    }

    /// Find the first occurrence of `bytes` within the range [start_addr, end_addr],
    /// searching forward or backward.
    ///
    /// Returns the address where the pattern was found, or `None`.
    pub fn find_bytes(
        &self,
        start_addr: u64,
        end_addr: u64,
        bytes: &[u8],
        masks: Option<&[u8]>,
        forward: bool,
        memory: &[u8],
        base_addr: u64,
    ) -> Option<u64> {
        if bytes.is_empty() {
            return Some(start_addr);
        }

        let min_addr = start_addr.min(end_addr);
        let max_addr = start_addr.max(end_addr);

        let mem_start = base_addr;
        let mem_end = base_addr + memory.len() as u64;

        let range_start = min_addr.max(mem_start);
        let range_end = max_addr.min(mem_end);

        if range_start >= range_end || range_end - range_start + 1 < bytes.len() as u64 {
            return None;
        }

        let offset_start = (range_start - mem_start) as usize;
        let offset_end = (range_end - mem_start) as usize;

        if offset_end - offset_start + 1 < bytes.len() {
            return None;
        }

        let search_range = offset_start..=(offset_end - bytes.len());

        if forward {
            for i in search_range {
                if matches_bytes(&memory[i..i + bytes.len()], bytes, masks) {
                    return Some(mem_start + i as u64);
                }
            }
        } else {
            for i in search_range.rev() {
                if matches_bytes(&memory[i..i + bytes.len()], bytes, masks) {
                    return Some(mem_start + i as u64);
                }
            }
        }
        None
    }

    /// Invalidate the byte cache.
    pub fn invalidate_cache(&mut self) {
        self.cache.invalidate();
    }
}

/// Check if memory matches the given bytes, optionally using masks.
pub fn matches_bytes(memory: &[u8], bytes: &[u8], masks: Option<&[u8]>) -> bool {
    if let Some(masks) = masks {
        memory
            .iter()
            .zip(bytes.iter())
            .zip(masks.iter())
            .all(|((m, b), mask)| (m & mask) == (b & mask))
    } else {
        memory == bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_cache_basic() {
        let mut cache = BytePageCache::new(2);
        assert!(cache.try_read(0, 0x1000, 4).is_none());

        cache.store(0, 0x1000, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let result = cache.try_read(0, 0x1000, 4);
        assert_eq!(result, Some(vec![0xAA, 0xBB, 0xCC, 0xDD]));
    }

    #[test]
    fn test_byte_cache_partial_read() {
        let mut cache = BytePageCache::new(2);
        cache.store(0, 0x1000, vec![1, 2, 3, 4]);
        let result = cache.try_read(0, 0x1000, 2);
        assert_eq!(result, Some(vec![1, 2]));
    }

    #[test]
    fn test_byte_cache_eviction() {
        let mut cache = BytePageCache::new(2);
        cache.store(0, 0x1000, vec![1]);
        cache.store(0, 0x2000, vec![2]);
        cache.store(0, 0x3000, vec![3]);

        // First entry should be evicted
        assert!(cache.try_read(0, 0x1000, 1).is_none());
        assert!(cache.try_read(0, 0x2000, 1).is_some());
        assert!(cache.try_read(0, 0x3000, 1).is_some());
    }

    #[test]
    fn test_byte_cache_invalidate() {
        let mut cache = BytePageCache::new(2);
        cache.store(0, 0x1000, vec![1]);
        cache.invalidate();
        assert!(cache.try_read(0, 0x1000, 1).is_none());
    }

    #[test]
    fn test_view_memory_data_basic() {
        let mut view = AbstractProgramViewMemoryData::new(10);
        assert_eq!(view.get_snap(), 10);
        assert!(!view.is_address_set_valid());
        assert!(view.is_empty());
        assert_eq!(view.get_num_addresses(), 0);
        assert!(view.get_min_address().is_none());
        assert!(view.get_max_address().is_none());
    }

    #[test]
    fn test_view_memory_data_snap_change() {
        let mut view = AbstractProgramViewMemoryData::new(0);
        view.set_address_set(BTreeSet::from([0x1000, 0x2000]));
        assert!(view.is_address_set_valid());

        view.set_snap(1);
        assert!(!view.is_address_set_valid());
    }

    #[test]
    fn test_view_memory_data_force_full_view() {
        let mut view = AbstractProgramViewMemoryData::new(0);
        view.set_address_set(BTreeSet::from([0x1000]));
        view.force_full_view = true;

        view.set_snap(5);
        assert_eq!(view.get_snap(), 5);
    }

    #[test]
    fn test_view_memory_data_contains() {
        let mut view = AbstractProgramViewMemoryData::new(0);
        view.set_address_set(BTreeSet::from([0x1000, 0x2000, 0x3000]));

        assert!(view.contains(0x1000));
        assert!(view.contains(0x2000));
        assert!(!view.contains(0x4000));
        assert_eq!(view.get_num_addresses(), 3);
        assert_eq!(view.get_min_address(), Some(0x1000));
        assert_eq!(view.get_max_address(), Some(0x3000));
    }

    #[test]
    fn test_find_bytes_forward() {
        let view = AbstractProgramViewMemoryData::new(0);
        let memory = vec![0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x00];
        let result = view.find_bytes(0, 6, &[0xAA, 0xBB], None, true, &memory, 0);
        assert_eq!(result, Some(1));
    }

    #[test]
    fn test_find_bytes_backward() {
        let view = AbstractProgramViewMemoryData::new(0);
        let memory = vec![0xAA, 0xBB, 0x00, 0xAA, 0xBB];
        let result = view.find_bytes(0, 5, &[0xAA, 0xBB], None, false, &memory, 0);
        assert_eq!(result, Some(3));
    }

    #[test]
    fn test_find_bytes_with_masks() {
        let view = AbstractProgramViewMemoryData::new(0);
        let memory = vec![0xAB, 0xCD, 0xEF];
        // 0xEF & 0x0F = 0x0F matches pattern 0xAF & 0x0F = 0x0F -> found at index 2
        let result = view.find_bytes(0, 3, &[0xAF], Some(&[0x0F]), true, &memory, 0);
        assert_eq!(result, Some(2));

        let result2 = view.find_bytes(0, 3, &[0xAB], Some(&[0xFF]), true, &memory, 0);
        assert_eq!(result2, Some(0));

        // Pattern that doesn't match: 0xCD & 0xF0 = 0xC0, 0xCC & 0xF0 = 0xC0
        // but 0xAB & 0xF0 = 0xA0 != 0xC0, and 0xEF & 0xF0 = 0xE0 != 0xC0
        let result3 = view.find_bytes(0, 3, &[0xCC], Some(&[0xF0]), true, &memory, 0);
        assert_eq!(result3, Some(1));
    }

    #[test]
    fn test_find_bytes_not_found() {
        let view = AbstractProgramViewMemoryData::new(0);
        let memory = vec![0x00, 0x11, 0x22];
        let result = view.find_bytes(0, 3, &[0xFF], None, true, &memory, 0);
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_bytes_empty_pattern() {
        let view = AbstractProgramViewMemoryData::new(0);
        let memory = vec![0x00];
        let result = view.find_bytes(0, 1, &[], None, true, &memory, 0);
        assert_eq!(result, Some(0));
    }

    #[test]
    fn test_matches_bytes_no_mask() {
        assert!(matches_bytes(&[1, 2, 3], &[1, 2, 3], None));
        assert!(!matches_bytes(&[1, 2, 3], &[1, 2, 4], None));
    }

    #[test]
    fn test_matches_bytes_with_mask() {
        assert!(matches_bytes(&[0xFF, 0x00], &[0x0F, 0x00], Some(&[0x0F, 0xFF])));
        assert!(!matches_bytes(&[0xFF, 0x00], &[0x00, 0x00], Some(&[0xFF, 0xFF])));
    }
}
