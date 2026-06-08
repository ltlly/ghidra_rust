//! Program fragment types for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.listing.ProgramFragment`.
//!
//! A fragment is a leaf node in the program tree. It holds a set of addresses
//! and cannot contain children.

use crate::addr::Address;
use crate::listing::group::Group;
use std::collections::HashSet;

/// A fragment is a leaf node in the program tree.
///
/// It holds a set of addresses and cannot contain children. Fragments are
/// grouped into modules to form the hierarchical program tree.
///
/// Corresponds to Ghidra's `ProgramFragment` interface.
#[derive(Debug, Clone)]
pub struct ProgramFragment {
    /// The fragment name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional alias.
    pub alias: Option<String>,
    /// The tree name this fragment belongs to.
    pub tree_name: String,
    /// The set of addresses in this fragment.
    pub addresses: HashSet<Address>,
    /// Number of parent modules.
    pub num_parents: usize,
    /// Whether this fragment has been deleted.
    pub deleted: bool,
}

impl ProgramFragment {
    /// Create a new empty fragment.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comment: None,
            alias: None,
            tree_name: "Program Tree".to_string(),
            addresses: HashSet::new(),
            num_parents: 0,
            deleted: false,
        }
    }

    /// Create a new fragment in a specific tree.
    pub fn in_tree(name: impl Into<String>, tree_name: impl Into<String>) -> Self {
        Self {
            tree_name: tree_name.into(),
            ..Self::new(name)
        }
    }

    /// Add an address to this fragment.
    pub fn add_address(&mut self, addr: Address) {
        self.addresses.insert(addr);
    }

    /// Remove an address from this fragment.
    pub fn remove_address(&mut self, addr: &Address) -> bool {
        self.addresses.remove(addr)
    }

    /// Add multiple addresses to this fragment.
    pub fn add_addresses(&mut self, addrs: impl IntoIterator<Item = Address>) {
        for addr in addrs {
            self.addresses.insert(addr);
        }
    }

    /// Returns true if this fragment contains the given address.
    pub fn contains(&self, addr: &Address) -> bool {
        self.addresses.contains(addr)
    }

    /// Returns true if this fragment contains the given address.
    ///
    /// Alias for [`contains`](Self::contains).
    pub fn contains_address(&self, addr: &Address) -> bool {
        self.contains(addr)
    }

    /// The number of addresses in this fragment.
    pub fn num_addresses(&self) -> usize {
        self.addresses.len()
    }

    /// Returns all addresses in this fragment (unsorted).
    pub fn get_addresses(&self) -> &HashSet<Address> {
        &self.addresses
    }

    /// Move all addresses in the given range to a new base.
    pub fn move_addresses(&mut self, min_addr: Address, max_addr: Address, new_base: Address) {
        let delta = new_base.offset as i64 - min_addr.offset as i64;
        let to_move: Vec<Address> = self
            .addresses
            .iter()
            .filter(|a| a.offset >= min_addr.offset && a.offset <= max_addr.offset)
            .copied()
            .collect();
        for addr in to_move {
            self.addresses.remove(&addr);
            let new_addr = if delta >= 0 {
                addr.add(delta as u64)
            } else {
                addr.sub((-delta) as u64)
            };
            self.addresses.insert(new_addr);
        }
    }
}

impl Group for ProgramFragment {
    fn get_comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn is_deleted(&self) -> bool {
        self.deleted
    }

    fn get_min_address(&self) -> Option<Address> {
        self.addresses.iter().min_by_key(|a| a.offset).copied()
    }

    fn get_max_address(&self) -> Option<Address> {
        self.addresses.iter().max_by_key(|a| a.offset).copied()
    }

    fn get_num_parents(&self) -> usize {
        self.num_parents
    }

    fn get_tree_name(&self) -> &str {
        &self.tree_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_new() {
        let frag = ProgramFragment::new(".text");
        assert_eq!(frag.get_name(), ".text");
        assert!(frag.num_addresses() == 0);
        assert!(!frag.is_deleted());
    }

    #[test]
    fn test_fragment_add_address() {
        let mut frag = ProgramFragment::new(".text");
        frag.add_address(Address::new(0x1000));
        frag.add_address(Address::new(0x1001));
        assert_eq!(frag.num_addresses(), 2);
        assert!(frag.num_addresses() != 0);
        assert!(frag.contains(&Address::new(0x1000)));
    }

    #[test]
    fn test_fragment_address_range() {
        let mut frag = ProgramFragment::new(".text");
        frag.add_address(Address::new(0x1000));
        frag.add_address(Address::new(0x1001));
        frag.add_address(Address::new(0x1002));
        assert_eq!(frag.get_min_address(), Some(Address::new(0x1000)));
        assert_eq!(frag.get_max_address(), Some(Address::new(0x1002)));
    }

    #[test]
    fn test_fragment_remove_address() {
        let mut frag = ProgramFragment::new(".text");
        frag.add_address(Address::new(0x1000));
        assert!(frag.remove_address(&Address::new(0x1000)));
        assert!(frag.num_addresses() == 0);
        assert!(!frag.remove_address(&Address::new(0x1000)));
    }

    #[test]
    fn test_fragment_in_tree() {
        let frag = ProgramFragment::in_tree(".data", "MyTree");
        assert_eq!(frag.get_name(), ".data");
        assert_eq!(frag.get_tree_name(), "MyTree");
    }

    #[test]
    fn test_fragment_move_addresses() {
        let mut frag = ProgramFragment::new(".text");
        frag.add_address(Address::new(0x1000));
        frag.add_address(Address::new(0x1001));
        frag.add_address(Address::new(0x1002));
        frag.move_addresses(Address::new(0x1000), Address::new(0x1001), Address::new(0x2000));
        // 0x1000 -> 0x2000, 0x1001 -> 0x2001, 0x1002 stays
        assert!(frag.contains(&Address::new(0x2000)));
        assert!(frag.contains(&Address::new(0x2001)));
        assert!(frag.contains(&Address::new(0x1002)));
        assert!(!frag.contains(&Address::new(0x1000)));
    }

    #[test]
    fn test_fragment_contains_address() {
        let mut frag = ProgramFragment::new(".text");
        frag.add_addresses(vec![
            Address::new(0x1000),
            Address::new(0x1004),
            Address::new(0x1008),
        ]);
        assert!(frag.contains_address(&Address::new(0x1004)));
        assert!(!frag.contains_address(&Address::new(0x1002)));
    }
}
