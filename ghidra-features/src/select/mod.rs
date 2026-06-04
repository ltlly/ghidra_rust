//! Selection Plugin -- address range selection management.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.select` Java package.
//!
//! Provides logic for managing address range selections in a program,
//! including selecting by function, by flow, by reference, and more.

use ghidra_core::Address;
use std::collections::BTreeSet;

/// The type of selection operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionType {
    /// Select the current address.
    Address,
    /// Select the current function.
    Function,
    /// Select the current instruction.
    Instruction,
    /// Select by address range (user-specified).
    Range,
    /// Select all addresses in the program.
    All,
    /// Select by code flow from the current address.
    Flow,
    /// Select by references to the current address.
    References,
    /// Invert the current selection.
    Invert,
    /// Select by equate value.
    Equate,
}

/// An address set representing a selection.
#[derive(Debug, Clone, Default)]
pub struct AddressSet {
    /// The addresses in this set.
    addresses: BTreeSet<u64>,
}

impl AddressSet {
    /// Create a new empty address set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an address to the set.
    pub fn add(&mut self, address: Address) {
        self.addresses.insert(address.offset);
    }

    /// Add a range of addresses to the set.
    pub fn add_range(&mut self, start: Address, end: Address) {
        for addr in start.offset..=end.offset {
            self.addresses.insert(addr);
        }
    }

    /// Remove an address from the set.
    pub fn remove(&mut self, address: Address) {
        self.addresses.remove(&address.offset);
    }

    /// Check if the set contains an address.
    pub fn contains(&self, address: Address) -> bool {
        self.addresses.contains(&address.offset)
    }

    /// The number of addresses in the set.
    pub fn num_addresses(&self) -> usize {
        self.addresses.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Invert the selection within a range.
    pub fn invert(&mut self, min: Address, max: Address) {
        let mut new_set = BTreeSet::new();
        for addr in min.offset..=max.offset {
            if !self.addresses.contains(&addr) {
                new_set.insert(addr);
            }
        }
        self.addresses = new_set;
    }

    /// Get the minimum address in the set.
    pub fn min_address(&self) -> Option<Address> {
        self.addresses.iter().next().map(|&a| Address::new(a))
    }

    /// Get the maximum address in the set.
    pub fn max_address(&self) -> Option<Address> {
        self.addresses.iter().next_back().map(|&a| Address::new(a))
    }

    /// Get all addresses as a sorted vector.
    pub fn to_vec(&self) -> Vec<Address> {
        self.addresses.iter().map(|&a| Address::new(a)).collect()
    }
}

/// Selection model managing the current program selection.
#[derive(Debug, Default)]
pub struct SelectionModel {
    current: AddressSet,
}

impl SelectionModel {
    /// Create a new selection model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the current selection.
    pub fn set_selection(&mut self, selection: AddressSet) {
        self.current = selection;
    }

    /// Get the current selection.
    pub fn get_selection(&self) -> &AddressSet {
        &self.current
    }

    /// Clear the current selection.
    pub fn clear(&mut self) {
        self.current = AddressSet::new();
    }

    /// Whether there is an active selection.
    pub fn has_selection(&self) -> bool {
        !self.current.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_set_add_range() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x1000), Address::new(0x1009));
        assert_eq!(set.num_addresses(), 10);
    }

    #[test]
    fn test_address_set_contains() {
        let mut set = AddressSet::new();
        set.add(Address::new(0x1000));
        assert!(set.contains(Address::new(0x1000)));
        assert!(!set.contains(Address::new(0x1001)));
    }

    #[test]
    fn test_address_set_invert() {
        let mut set = AddressSet::new();
        set.add(Address::new(0x1002));
        set.invert(Address::new(0x1000), Address::new(0x1004));
        assert!(!set.contains(Address::new(0x1002)));
        assert!(set.contains(Address::new(0x1000)));
        assert!(set.contains(Address::new(0x1004)));
    }

    #[test]
    fn test_address_set_min_max() {
        let mut set = AddressSet::new();
        set.add(Address::new(0x3000));
        set.add(Address::new(0x1000));
        set.add(Address::new(0x2000));
        assert_eq!(set.min_address(), Some(Address::new(0x1000)));
        assert_eq!(set.max_address(), Some(Address::new(0x3000)));
    }

    #[test]
    fn test_selection_model() {
        let mut model = SelectionModel::new();
        assert!(!model.has_selection());
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x1000), Address::new(0x100F));
        model.set_selection(set);
        assert!(model.has_selection());
        model.clear();
        assert!(!model.has_selection());
    }
}
