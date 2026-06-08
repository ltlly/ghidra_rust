//! Address map implementation for encoding/decoding database keys.
//!
//! Direct translation of `ghidra.program.model.address.AddressMapImpl`.
//!
//! Provides [`AddressMapImpl`] -- a stand-alone address map that encodes
//! addresses into 64-bit keys for database storage, and decodes them back.
//!
//! The key encoding layout is:
//!
//! ```text
//! [8-bit map ID][24-bit base index][32-bit offset]
//! ```
//!
//! An `AddressMapImpl` instance should only be used to decode keys which it
//! has generated. If the associated program's address map changes (e.g.,
//! removing or renaming overlay spaces), the map should be discarded.

use crate::addr::{Address, AddressSpace};
use crate::addr::key_range::KeyRange;
use std::collections::HashMap;

// Encoding constants (matching the Java implementation)
const ADDR_OFFSET_SIZE: u32 = 32;
const MAP_ID_SIZE: u32 = 8;
const MAX_OFFSET: u64 = (1u64 << ADDR_OFFSET_SIZE) - 1;
const ADDR_OFFSET_MASK: u64 = MAX_OFFSET;
const MAP_ID_MASK: u64 = u64::MAX << (64 - MAP_ID_SIZE);
const BASE_MASK: u64 = !ADDR_OFFSET_MASK;
const BASE_ID_SIZE: u32 = 64 - MAP_ID_SIZE - ADDR_OFFSET_SIZE;
const BASE_ID_MASK: u64 = (1u64 << BASE_ID_SIZE) - 1;
const STACK_SPACE_ID: u32 = u32::MAX >> MAP_ID_SIZE;

/// A stand-alone address map for encoding addresses into database keys.
///
/// Corresponds to `ghidra.program.model.address.AddressMapImpl`.
///
/// The map maintains a set of "base addresses" that identify the start of
/// each 4GB-aligned region. Each base address gets a unique index. The
/// encoding combines the map ID, the base index, and the low 32 bits of
/// the offset.
///
/// # Key encoding
///
/// A 64-bit key is structured as:
/// - Bits 63..56: map ID (8 bits)
/// - Bits 55..32: base index (24 bits)
/// - Bits 31..0:  offset within base (32 bits)
///
/// Special case: stack addresses use a reserved base index.
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::Address;
/// use ghidra_core::addr::address_map_impl::AddressMapImpl;
///
/// let mut map = AddressMapImpl::new();
/// let addr = Address::new(0x12345678);
/// let key = map.get_key(addr);
/// let decoded = map.decode_address(key);
/// assert_eq!(decoded.offset, addr.offset);
/// ```
#[derive(Debug)]
pub struct AddressMapImpl {
    /// Optional address factory for space lookups.
    addr_factory: Option<crate::addr::default_address_factory::DefaultAddressFactory>,
    /// Map from address space name to space (for validation/conflict detection).
    space_map: HashMap<String, AddressSpace>,
    /// The stack space, if any (special case -- only signed space supported).
    stack_space: Option<AddressSpace>,
    /// Ordered list of base addresses (insertion order preserved).
    base_addrs: Vec<Address>,
    /// Sorted copy of base_addrs for binary search.
    sorted_base_start_addrs: Vec<Address>,
    /// Corresponding end addresses for each sorted base start.
    sorted_base_end_addrs: Vec<Address>,
    /// Map from base address to its original index in base_addrs.
    addr_to_index_map: HashMap<u64, usize>,
    /// Cache of the last used base index for performance.
    last_base_index: isize,
    /// Pre-computed map ID bits for the upper 8 bits of encoded keys.
    map_id_bits: u64,
}

impl Default for AddressMapImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressMapImpl {
    /// Creates a new `AddressMapImpl` with a map ID of 0.
    pub fn new() -> Self {
        Self::with_map_id(0)
    }

    /// Creates a new `AddressMapImpl` with the specified 8-bit map ID.
    ///
    /// The `map_id` is placed in the upper 8 bits of every encoded key.
    pub fn with_map_id(map_id: u8) -> Self {
        let map_id_bits = (map_id as u64) << (64 - MAP_ID_SIZE);
        let mut map = Self {
            addr_factory: None,
            space_map: HashMap::new(),
            stack_space: None,
            base_addrs: Vec::new(),
            sorted_base_start_addrs: Vec::new(),
            sorted_base_end_addrs: Vec::new(),
            addr_to_index_map: HashMap::new(),
            last_base_index: -1,
            map_id_bits,
        };
        map.init();
        map
    }

    /// Set the address factory for this map.
    pub fn set_address_factory(&mut self, factory: crate::addr::default_address_factory::DefaultAddressFactory) {
        self.addr_factory = Some(factory);
    }

    /// Re-initialize the sorted arrays and index map from base_addrs.
    fn init(&mut self) {
        self.last_base_index = self.base_addrs.len() as isize - 1;

        // Create sorted copy
        let mut sorted: Vec<(Address, usize)> = self
            .base_addrs
            .iter()
            .enumerate()
            .map(|(i, a)| (*a, i))
            .collect();
        sorted.sort_by_key(|(a, _)| a.offset);

        self.sorted_base_start_addrs = sorted.iter().map(|(a, _)| *a).collect();
        self.sorted_base_end_addrs = sorted
            .iter()
            .map(|(addr, _)| {
                let max = MAX_OFFSET;
                let off = addr.offset | max;
                Address::new(off)
            })
            .collect();

        // Build addr-to-index map (first occurrence wins)
        self.addr_to_index_map.clear();
        for (i, addr) in self.base_addrs.iter().enumerate() {
            self.addr_to_index_map.entry(addr.offset).or_insert(i);
        }
    }

    /// Get the base address index for the given address.
    ///
    /// If the address's base region has not been seen before, a new base
    /// entry is created.
    fn get_base_address_index(&mut self, addr: Address) -> u32 {
        // Check if this is a stack space address
        // (In this simplified model, we don't have space-aware addresses,
        //  so stack detection is deferred. The encoding uses a special index.)

        let base_offset = addr.offset & BASE_MASK;

        // Check last used index (cache hit)
        if self.last_base_index >= 0 {
            let idx = self.last_base_index as usize;
            if idx < self.base_addrs.len() {
                let base = &self.base_addrs[idx];
                if base.offset == base_offset {
                    return idx as u32;
                }
            }
        }

        // Binary search in sorted base starts
        let search_result = self
            .sorted_base_start_addrs
            .binary_search_by_key(&base_offset, |a| a.offset);

        let search = match search_result {
            Ok(i) => i,
            Err(i) => {
                if i > 0 {
                    i - 1
                } else {
                    // No base found; create new
                    let index = self.base_addrs.len();
                    self.base_addrs.push(Address::new(base_offset));
                    self.init();
                    self.last_base_index = index as isize;
                    return index as u32;
                }
            }
        };

        if search < self.sorted_base_start_addrs.len() {
            let base = &self.sorted_base_start_addrs[search];
            if base.offset == base_offset {
                let index = self.addr_to_index_map[&base.offset];
                self.last_base_index = index as isize;
                return index as u32;
            }
        }

        // Not found; create new base
        let index = self.base_addrs.len();
        self.base_addrs.push(Address::new(base_offset));
        self.init();
        self.last_base_index = index as isize;
        index as u32
    }

    /// Decode a 64-bit key back into an address.
    ///
    /// Returns [`Address::NULL`] if the key's map ID does not match this map,
    /// or if the base index is out of range.
    pub fn decode_address(&self, value: u64) -> Address {
        // Check map ID
        if (value & MAP_ID_MASK) != self.map_id_bits {
            return Address::NULL;
        }

        let base_index = ((value >> ADDR_OFFSET_SIZE) & BASE_ID_MASK) as u32;
        let offset = value & ADDR_OFFSET_MASK;

        // Special case: stack space
        if base_index == STACK_SPACE_ID {
            // Stack addresses use raw offset
            return Address::new(offset);
        }

        if (base_index as usize) >= self.base_addrs.len() {
            return Address::NULL;
        }

        // Compute the address: base + offset
        let base = self.base_addrs[base_index as usize];
        Address::new(base.offset.wrapping_add(offset))
    }

    /// Generate a unique 64-bit key for the specified address.
    ///
    /// Only addresses from a single address space or single program should
    /// be passed to this method.
    pub fn get_key(&mut self, addr: Address) -> u64 {
        self.map_id_bits
            | ((self.get_base_address_index(addr) as u64) << ADDR_OFFSET_SIZE)
            | (addr.offset & ADDR_OFFSET_MASK)
    }

    /// Look up the key for an address without creating a new base entry.
    ///
    /// Returns `None` if the address's base region has not been registered.
    pub fn get_key_readonly(&self, addr: Address) -> Option<u64> {
        let base_offset = addr.offset & BASE_MASK;
        let base_index = self.addr_to_index_map.get(&base_offset)?;
        Some(
            self.map_id_bits
                | ((*base_index as u64) << ADDR_OFFSET_SIZE)
                | (addr.offset & ADDR_OFFSET_MASK),
        )
    }

    /// Find the key range in the given list that contains the address.
    ///
    /// Returns the index of the matching key range, or a negative insertion
    /// point if not found (following `binary_search` conventions).
    pub fn find_key_range(key_range_list: &[KeyRange], addr: Address) -> Result<usize, usize> {
        key_range_list.binary_search_by(|range| {
            let min_addr = Address::new(range.min_key & ADDR_OFFSET_MASK);
            let max_addr = Address::new(range.max_key & ADDR_OFFSET_MASK);
            if min_addr.offset > addr.offset {
                std::cmp::Ordering::Greater
            } else if max_addr.offset < addr.offset {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
    }

    /// Get the key ranges for a single address range [start, end].
    ///
    /// The start and end must be in the same address space, and
    /// start.offset <= end.offset.
    pub fn get_key_ranges_for_range(
        &mut self,
        start: Address,
        end: Address,
    ) -> Vec<KeyRange> {
        if start.offset > end.offset {
            return Vec::new();
        }

        let mut result = Vec::new();
        self.add_key_ranges(&mut result, start, end);
        result
    }

    /// Get the key ranges for an address set.
    ///
    /// If `set` is `None`, returns key ranges for all base addresses.
    pub fn get_key_ranges_for_set(&mut self, set: Option<&crate::addr::AddressSet>) -> Vec<KeyRange> {
        let mut result = Vec::new();
        match set {
            None => {
                // Return ranges for all base addresses
                let base_addrs = self.sorted_base_start_addrs.clone();
                for base in &base_addrs {
                    let start_key = self.get_key(*base);
                    let end_offset = base.offset | MAX_OFFSET;
                    let end_key = self.get_key(Address::new(end_offset));
                    result.push(KeyRange::new(start_key, end_key));
                }
            }
            Some(addr_set) => {
                for range in addr_set.iter() {
                    self.add_key_ranges(&mut result, range.start, range.end);
                }
            }
        }
        result
    }

    /// Helper: add key ranges for [start, end] into the result list.
    fn add_key_ranges(&mut self, result: &mut Vec<KeyRange>, start: Address, end: Address) {
        let start_offset = start.offset;

        // Find the first sorted base that could contain start
        let search = self
            .sorted_base_start_addrs
            .binary_search_by_key(&start_offset, |a| a.offset);
        let mut index = match search {
            Ok(i) => i,
            Err(i) => {
                if i > 0 {
                    i - 1
                } else {
                    0
                }
            }
        };

        while index < self.sorted_base_start_addrs.len() {
            let base_start = self.sorted_base_start_addrs[index];
            let base_end = self.sorted_base_end_addrs[index];

            // If the end address is before this base, stop
            if end.offset < base_start.offset {
                break;
            }

            // Compute intersection of [start, end] with [base_start, base_end]
            let addr1 = Address::new(start.offset.max(base_start.offset));
            let addr2 = Address::new(end.offset.min(base_end.offset));

            if addr1.offset <= addr2.offset {
                result.push(KeyRange::new(
                    self.get_key(addr1),
                    self.get_key(addr2),
                ));
            }

            index += 1;
        }
    }

    /// Reconcile address space changes.
    ///
    /// This method should be invoked following an undo/redo (if the
    /// associated address factory may have changed) or removal of an
    /// overlay memory block.
    pub fn reconcile(&mut self) {
        // In this simplified Rust model, reconciliation is a no-op
        // since we don't have overlay space management in the map yet.
        // The Java version handles ObsoleteOverlaySpace remapping here.
        if self.addr_factory.is_none() {
            return;
        }
        self.init();
    }

    /// Returns the number of base addresses currently tracked.
    pub fn num_base_addresses(&self) -> usize {
        self.base_addrs.len()
    }

    /// Returns the map ID bits.
    pub fn map_id_bits(&self) -> u64 {
        self.map_id_bits
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::AddressSet;

    #[test]
    fn test_encode_decode_basic() {
        let mut map = AddressMapImpl::new();
        let addr = Address::new(0x12345678);
        let key = map.get_key(addr);
        let decoded = map.decode_address(key);
        assert_eq!(decoded.offset, addr.offset);
    }

    #[test]
    fn test_encode_decode_zero() {
        let mut map = AddressMapImpl::new();
        let addr = Address::new(0);
        let key = map.get_key(addr);
        let decoded = map.decode_address(key);
        assert_eq!(decoded.offset, 0);
    }

    #[test]
    fn test_encode_decode_max_offset() {
        let mut map = AddressMapImpl::new();
        let addr = Address::new(MAX_OFFSET);
        let key = map.get_key(addr);
        let decoded = map.decode_address(key);
        assert_eq!(decoded.offset, MAX_OFFSET);
    }

    #[test]
    fn test_different_base_regions() {
        let mut map = AddressMapImpl::new();
        // Two addresses in different 4GB regions
        let addr1 = Address::new(0x0000_0000_1000_0000);
        let addr2 = Address::new(0x0000_0001_1000_0000);
        let key1 = map.get_key(addr1);
        let key2 = map.get_key(addr2);
        assert_ne!(key1, key2);
        assert_eq!(map.decode_address(key1).offset, addr1.offset);
        assert_eq!(map.decode_address(key2).offset, addr2.offset);
    }

    #[test]
    fn test_same_base_region() {
        let mut map = AddressMapImpl::new();
        let addr1 = Address::new(0x1000);
        let addr2 = Address::new(0x2000);
        let key1 = map.get_key(addr1);
        let key2 = map.get_key(addr2);
        // Same base index, different offsets
        assert_ne!(key1, key2);
        assert_eq!(map.decode_address(key1).offset, addr1.offset);
        assert_eq!(map.decode_address(key2).offset, addr2.offset);
    }

    #[test]
    fn test_wrong_map_id() {
        let mut map1 = AddressMapImpl::with_map_id(0);
        let map2 = AddressMapImpl::with_map_id(1);
        let addr = Address::new(0x1000);
        let key = map1.get_key(addr);
        // Decoding with a different map ID should return NULL
        assert_eq!(map2.decode_address(key), Address::NULL);
    }

    #[test]
    fn test_key_range_for_range() {
        let mut map = AddressMapImpl::new();
        // Register addresses first so base entries exist
        let _ = map.get_key(Address::new(0x1000));
        let _ = map.get_key(Address::new(0x2000));
        let start = Address::new(0x1000);
        let end = Address::new(0x2000);
        let ranges = map.get_key_ranges_for_range(start, end);
        assert!(!ranges.is_empty());
        // Verify all addresses in range can be decoded
        for range in &ranges {
            assert!(range.min_key <= range.max_key);
        }
    }

    #[test]
    fn test_key_range_for_set() {
        let mut map = AddressMapImpl::new();
        // Register addresses first so base entries exist
        let _ = map.get_key(Address::new(0x1000));
        let _ = map.get_key(Address::new(0x5000));
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x1000), Address::new(0x2000));
        set.add_range(Address::new(0x5000), Address::new(0x6000));
        let ranges = map.get_key_ranges_for_set(Some(&set));
        assert!(!ranges.is_empty());
    }

    #[test]
    fn test_key_range_for_none_set() {
        let mut map = AddressMapImpl::new();
        // Create a base address first
        let _ = map.get_key(Address::new(0x1000));
        let ranges = map.get_key_ranges_for_set(None);
        assert!(!ranges.is_empty());
    }

    #[test]
    fn test_find_key_range() {
        let mut map = AddressMapImpl::new();
        // Register addresses first so base entries exist
        let _ = map.get_key(Address::new(0x1000));
        let _ = map.get_key(Address::new(0x2000));
        let start = Address::new(0x1000);
        let end = Address::new(0x2000);
        let ranges = map.get_key_ranges_for_range(start, end);

        // Address within range should be found
        let addr_in_range = Address::new(0x1500);
        let result = AddressMapImpl::find_key_range(&ranges, addr_in_range);
        assert!(result.is_ok());

        // Address outside range should not be found
        let addr_outside = Address::new(0x5000);
        let result = AddressMapImpl::find_key_range(&ranges, addr_outside);
        assert!(result.is_err());
    }

    #[test]
    fn test_num_base_addresses() {
        let mut map = AddressMapImpl::new();
        assert_eq!(map.num_base_addresses(), 0);
        let _ = map.get_key(Address::new(0x1000));
        assert_eq!(map.num_base_addresses(), 1);
        // Same base region -> no new base
        let _ = map.get_key(Address::new(0x2000));
        assert_eq!(map.num_base_addresses(), 1);
        // Different base region -> new base
        let _ = map.get_key(Address::new(0x0000_0001_0000_0000));
        assert_eq!(map.num_base_addresses(), 2);
    }

    #[test]
    fn test_decode_out_of_range_base() {
        let map = AddressMapImpl::new();
        // Craft a key with an out-of-range base index
        let bad_key = map.map_id_bits | ((100u64) << ADDR_OFFSET_SIZE) | 0x1000;
        assert_eq!(map.decode_address(bad_key), Address::NULL);
    }

    #[test]
    fn test_repeated_encode_stable() {
        let mut map = AddressMapImpl::new();
        let addr = Address::new(0xABCD);
        let key1 = map.get_key(addr);
        let key2 = map.get_key(addr);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_empty_range() {
        let mut map = AddressMapImpl::new();
        let ranges = map.get_key_ranges_for_range(Address::new(0x2000), Address::new(0x1000));
        assert!(ranges.is_empty());
    }

    #[test]
    fn test_display() {
        let kr = KeyRange::new(100, 200);
        let s = format!("{}", kr);
        assert!(s.contains("100"));
        assert!(s.contains("200"));
    }
}
