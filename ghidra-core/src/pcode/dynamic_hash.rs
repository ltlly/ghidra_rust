//! DynamicHash -- hashing for Varnodes and PcodeOps.
//!
//! Ported from `ghidra.program.model.pcode.DynamicHash`. Provides a hash
//! table for quickly looking up Varnodes and PcodeOps by their address and
//! other properties.

use crate::addr::Address;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

// ============================================================================
// VarnodeKey -- hash key for a varnode lookup
// ============================================================================

/// A lookup key for a varnode in the dynamic hash table.
///
/// Uniquely identifies a varnode by its address space, offset, and size.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VarnodeKey {
    /// The address space ID.
    pub space_id: u32,
    /// The offset within the address space.
    pub offset: u64,
    /// The size in bytes.
    pub size: u32,
}

impl VarnodeKey {
    /// Create a new varnode key.
    pub fn new(space_id: u32, offset: u64, size: u32) -> Self {
        Self {
            space_id,
            offset,
            size,
        }
    }

    /// Create a key from an address and size.
    pub fn from_address(addr: Address, size: u32) -> Self {
        Self {
            space_id: 0, // default space
            offset: addr.offset,
            size,
        }
    }
}

// ============================================================================
// DynamicHash -- a hash table for varnodes and pcode ops
// ============================================================================

/// A hash table for quickly looking up Varnodes and PcodeOps.
///
/// Corresponds to Ghidra's `DynamicHash`. Uses address-based keys for
/// O(1) lookup of varnodes by their location.
#[derive(Debug, Clone)]
pub struct DynamicHash {
    /// Map from varnode key to the index in the varnode bank.
    varnode_map: HashMap<VarnodeKey, u32>,
    /// Map from (address, sequence_number) to the pcode op index.
    op_map: HashMap<(Address, u32), u32>,
}

impl DynamicHash {
    /// Create a new empty dynamic hash table.
    pub fn new() -> Self {
        Self {
            varnode_map: HashMap::new(),
            op_map: HashMap::new(),
        }
    }

    /// Create with a specified initial capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            varnode_map: HashMap::with_capacity(capacity),
            op_map: HashMap::with_capacity(capacity),
        }
    }

    // ---- Varnode operations ----

    /// Register a varnode with the given key.
    pub fn add_varnode(&mut self, key: VarnodeKey, index: u32) {
        self.varnode_map.insert(key, index);
    }

    /// Look up a varnode index by its key.
    pub fn find_varnode(&self, key: &VarnodeKey) -> Option<u32> {
        self.varnode_map.get(key).copied()
    }

    /// Look up a varnode by address and size.
    pub fn find_varnode_by_address(&self, addr: Address, size: u32) -> Option<u32> {
        let key = VarnodeKey::from_address(addr, size);
        self.find_varnode(&key)
    }

    /// Remove a varnode by key.
    pub fn remove_varnode(&mut self, key: &VarnodeKey) -> Option<u32> {
        self.varnode_map.remove(key)
    }

    /// Returns the number of registered varnodes.
    pub fn num_varnodes(&self) -> usize {
        self.varnode_map.len()
    }

    // ---- PcodeOp operations ----

    /// Register a pcode op at the given address and sequence number.
    pub fn add_op(&mut self, addr: Address, seq_num: u32, index: u32) {
        self.op_map.insert((addr, seq_num), index);
    }

    /// Look up a pcode op index by address and sequence number.
    pub fn find_op(&self, addr: Address, seq_num: u32) -> Option<u32> {
        self.op_map.get(&(addr, seq_num)).copied()
    }

    /// Remove a pcode op by address and sequence number.
    pub fn remove_op(&mut self, addr: Address, seq_num: u32) -> Option<u32> {
        self.op_map.remove(&(addr, seq_num))
    }

    /// Returns the number of registered pcode ops.
    pub fn num_ops(&self) -> usize {
        self.op_map.len()
    }

    // ---- Bulk operations ----

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.varnode_map.clear();
        self.op_map.clear();
    }

    /// Returns `true` if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.varnode_map.is_empty() && self.op_map.is_empty()
    }

    /// Returns the total number of entries.
    pub fn len(&self) -> usize {
        self.varnode_map.len() + self.op_map.len()
    }

    /// Iterate over all varnode keys.
    pub fn varnode_keys(&self) -> impl Iterator<Item = &VarnodeKey> {
        self.varnode_map.keys()
    }

    /// Iterate over all op addresses.
    pub fn op_keys(&self) -> impl Iterator<Item = &(Address, u32)> {
        self.op_map.keys()
    }
}

impl Default for DynamicHash {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varnode_key() {
        let k1 = VarnodeKey::new(1, 0x1000, 4);
        let k2 = VarnodeKey::new(1, 0x1000, 4);
        let k3 = VarnodeKey::new(1, 0x1000, 8);
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
    }

    #[test]
    fn test_varnode_key_from_address() {
        let k = VarnodeKey::from_address(Address::new(0x401000), 4);
        assert_eq!(k.offset, 0x401000);
        assert_eq!(k.size, 4);
    }

    #[test]
    fn test_dynamic_hash_varnode_ops() {
        let mut dh = DynamicHash::new();
        let k = VarnodeKey::new(1, 0x1000, 4);
        dh.add_varnode(k.clone(), 42);
        assert_eq!(dh.find_varnode(&k), Some(42));
        assert_eq!(dh.num_varnodes(), 1);

        let removed = dh.remove_varnode(&k);
        assert_eq!(removed, Some(42));
        assert_eq!(dh.find_varnode(&k), None);
        assert_eq!(dh.num_varnodes(), 0);
    }

    #[test]
    fn test_dynamic_hash_find_by_address() {
        let mut dh = DynamicHash::new();
        let addr = Address::new(0x401000);
        dh.add_varnode(VarnodeKey::from_address(addr, 4), 10);
        assert_eq!(dh.find_varnode_by_address(addr, 4), Some(10));
        assert_eq!(dh.find_varnode_by_address(addr, 8), None);
    }

    #[test]
    fn test_dynamic_hash_op_ops() {
        let mut dh = DynamicHash::new();
        let addr = Address::new(0x401000);
        dh.add_op(addr, 0, 100);
        dh.add_op(addr, 1, 101);
        assert_eq!(dh.find_op(addr, 0), Some(100));
        assert_eq!(dh.find_op(addr, 1), Some(101));
        assert_eq!(dh.num_ops(), 2);

        let removed = dh.remove_op(addr, 0);
        assert_eq!(removed, Some(100));
        assert_eq!(dh.num_ops(), 1);
    }

    #[test]
    fn test_dynamic_hash_not_found() {
        let dh = DynamicHash::new();
        assert_eq!(
            dh.find_varnode(&VarnodeKey::new(0, 0, 0)),
            None
        );
        assert_eq!(dh.find_op(Address::new(0), 0), None);
    }

    #[test]
    fn test_dynamic_hash_clear() {
        let mut dh = DynamicHash::new();
        dh.add_varnode(VarnodeKey::new(0, 0, 4), 0);
        dh.add_op(Address::new(0), 0, 0);
        assert!(!dh.is_empty());
        assert_eq!(dh.len(), 2);
        dh.clear();
        assert!(dh.is_empty());
        assert_eq!(dh.len(), 0);
    }

    #[test]
    fn test_dynamic_hash_with_capacity() {
        let dh = DynamicHash::with_capacity(100);
        assert!(dh.is_empty());
    }

    #[test]
    fn test_dynamic_hash_iterators() {
        let mut dh = DynamicHash::new();
        dh.add_varnode(VarnodeKey::new(1, 0x1000, 4), 0);
        dh.add_varnode(VarnodeKey::new(1, 0x2000, 4), 1);
        dh.add_op(Address::new(0x1000), 0, 10);
        dh.add_op(Address::new(0x2000), 0, 11);

        let vn_keys: Vec<_> = dh.varnode_keys().collect();
        assert_eq!(vn_keys.len(), 2);

        let op_keys: Vec<_> = dh.op_keys().collect();
        assert_eq!(op_keys.len(), 2);
    }
}
