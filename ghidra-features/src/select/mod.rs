//! Selection Plugin -- address range selection management.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.select` Java package.
//!
//! Provides logic for managing address range selections in a program,
//! including selecting by function, by flow, by reference, by bytes,
//! and more. Supports flow-based selection with forward, backward,
//! and subroutine-following strategies.
//!
//! # Key Types
//!
//! - [`SelectionType`] -- the kind of selection operation
//! - [`FlowSelectionType`] -- flow-based selection strategies
//! - [`AddressSet`] -- an ordered set of addresses representing a selection
//! - [`SelectionModel`] -- model managing the current program selection

use ghidra_core::Address;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// SelectionType
// ---------------------------------------------------------------------------

/// The type of selection operation.
///
/// Ported from the various selection plugins in `ghidra.app.plugin.core.select`.
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
    /// Select by bytes (user-specified count).
    Bytes,
    /// Select by program tree.
    ProgramTree,
    /// Select by qualified selection (function + address).
    Qualified,
}

// ---------------------------------------------------------------------------
// FlowSelectionType -- flow-based selection strategies
// ---------------------------------------------------------------------------

/// Flow-based selection strategies.
///
/// Ported from `SelectByFlowAction.selectionType` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowSelectionType {
    /// Select all flows FROM the current address/selection.
    AllFlowsFrom,
    /// Select limited flows FROM (respecting follow properties).
    LimitedFlowsFrom,
    /// Select all subroutines containing the current address.
    Subroutines,
    /// Select all flows TO the current address/selection.
    AllFlowsTo,
    /// Select limited flows TO (respecting follow properties).
    LimitedFlowsTo,
}

// ---------------------------------------------------------------------------
// ByteSelectionMethod
// ---------------------------------------------------------------------------

/// Method for byte-based selection.
///
/// Ported from `SelectBytesDialog` method radio buttons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteSelectionMethod {
    /// Select N bytes from the start of the program.
    FromStart,
    /// Select N bytes from the end of the program.
    FromEnd,
    /// Select N bytes forward from the current address.
    ForwardFromCurrent,
    /// Select N bytes backward from the current address.
    BackwardFromCurrent,
}

// ---------------------------------------------------------------------------
// AddressSet
// ---------------------------------------------------------------------------

/// An address set representing a selection.
///
/// Uses a BTreeSet for ordered address storage.
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

    /// Remove a range of addresses.
    pub fn remove_range(&mut self, start: Address, end: Address) {
        for addr in start.offset..=end.offset {
            self.addresses.remove(&addr);
        }
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

    /// Compute the union of two address sets.
    pub fn union(&self, other: &AddressSet) -> AddressSet {
        let mut result = self.clone();
        for &addr in &other.addresses {
            result.addresses.insert(addr);
        }
        result
    }

    /// Compute the intersection of two address sets.
    pub fn intersection(&self, other: &AddressSet) -> AddressSet {
        let addresses = self
            .addresses
            .intersection(&other.addresses)
            .copied()
            .collect();
        AddressSet { addresses }
    }

    /// Compute the difference (self minus other).
    pub fn difference(&self, other: &AddressSet) -> AddressSet {
        let addresses = self
            .addresses
            .difference(&other.addresses)
            .copied()
            .collect();
        AddressSet { addresses }
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

    /// Get contiguous ranges as (start, end) pairs.
    pub fn to_ranges(&self) -> Vec<(Address, Address)> {
        let mut ranges = Vec::new();
        let mut iter = self.addresses.iter();
        if let Some(&start) = iter.next() {
            let mut range_start = start;
            let mut range_end = start;
            for &addr in iter {
                if addr == range_end + 1 {
                    range_end = addr;
                } else {
                    ranges.push((Address::new(range_start), Address::new(range_end)));
                    range_start = addr;
                    range_end = addr;
                }
            }
            ranges.push((Address::new(range_start), Address::new(range_end)));
        }
        ranges
    }
}

// ---------------------------------------------------------------------------
// SelectionModel
// ---------------------------------------------------------------------------

/// Selection model managing the current program selection.
///
/// Supports undo by maintaining a selection history stack.
#[derive(Debug, Default)]
pub struct SelectionModel {
    current: AddressSet,
    /// Stack of previous selections for undo.
    history: Vec<AddressSet>,
}

impl SelectionModel {
    /// Create a new selection model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the current selection (pushes the previous selection to history).
    pub fn set_selection(&mut self, selection: AddressSet) {
        let old = std::mem::replace(&mut self.current, selection);
        self.history.push(old);
    }

    /// Get the current selection.
    pub fn get_selection(&self) -> &AddressSet {
        &self.current
    }

    /// Clear the current selection (pushes previous to history).
    pub fn clear(&mut self) {
        self.set_selection(AddressSet::new());
    }

    /// Whether there is an active selection.
    pub fn has_selection(&self) -> bool {
        !self.current.is_empty()
    }

    /// Undo the last selection change.
    pub fn undo(&mut self) -> bool {
        if let Some(previous) = self.history.pop() {
            self.current = previous;
            true
        } else {
            false
        }
    }

    /// Whether undo is available.
    pub fn can_undo(&self) -> bool {
        !self.history.is_empty()
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

    #[test]
    fn test_address_set_union() {
        let mut a = AddressSet::new();
        a.add(Address::new(0x1000));
        a.add(Address::new(0x2000));
        let mut b = AddressSet::new();
        b.add(Address::new(0x2000));
        b.add(Address::new(0x3000));
        let c = a.union(&b);
        assert_eq!(c.num_addresses(), 3);
        assert!(c.contains(Address::new(0x1000)));
        assert!(c.contains(Address::new(0x3000)));
    }

    #[test]
    fn test_address_set_intersection() {
        let mut a = AddressSet::new();
        a.add(Address::new(0x1000));
        a.add(Address::new(0x2000));
        let mut b = AddressSet::new();
        b.add(Address::new(0x2000));
        b.add(Address::new(0x3000));
        let c = a.intersection(&b);
        assert_eq!(c.num_addresses(), 1);
        assert!(c.contains(Address::new(0x2000)));
    }

    #[test]
    fn test_address_set_difference() {
        let mut a = AddressSet::new();
        a.add(Address::new(0x1000));
        a.add(Address::new(0x2000));
        let mut b = AddressSet::new();
        b.add(Address::new(0x2000));
        let c = a.difference(&b);
        assert_eq!(c.num_addresses(), 1);
        assert!(c.contains(Address::new(0x1000)));
    }

    #[test]
    fn test_address_set_remove_range() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x1000), Address::new(0x100F));
        set.remove_range(Address::new(0x1005), Address::new(0x100A));
        assert_eq!(set.num_addresses(), 10);
        assert!(!set.contains(Address::new(0x1007)));
        assert!(set.contains(Address::new(0x1004)));
        assert!(set.contains(Address::new(0x100B)));
    }

    #[test]
    fn test_address_set_to_ranges() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x1000), Address::new(0x1004));
        set.add_range(Address::new(0x2000), Address::new(0x2002));
        let ranges = set.to_ranges();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].0.offset, 0x1000);
        assert_eq!(ranges[0].1.offset, 0x1004);
        assert_eq!(ranges[1].0.offset, 0x2000);
        assert_eq!(ranges[1].1.offset, 0x2002);
    }

    #[test]
    fn test_selection_model_undo() {
        let mut model = SelectionModel::new();
        let mut set1 = AddressSet::new();
        set1.add(Address::new(0x1000));
        model.set_selection(set1);
        assert_eq!(model.get_selection().num_addresses(), 1);

        let mut set2 = AddressSet::new();
        set2.add(Address::new(0x2000));
        model.set_selection(set2);
        assert_eq!(model.get_selection().num_addresses(), 1);
        assert!(model.get_selection().contains(Address::new(0x2000)));

        assert!(model.can_undo());
        assert!(model.undo());
        assert!(model.get_selection().contains(Address::new(0x1000)));
        assert!(!model.get_selection().contains(Address::new(0x2000)));
    }

    #[test]
    fn test_selection_model_undo_empty() {
        let mut model = SelectionModel::new();
        assert!(!model.undo());
    }

    #[test]
    fn test_flow_selection_type() {
        let fst = FlowSelectionType::AllFlowsFrom;
        assert_eq!(fst, FlowSelectionType::AllFlowsFrom);
        assert_ne!(fst, FlowSelectionType::Subroutines);
    }

    #[test]
    fn test_byte_selection_method() {
        let method = ByteSelectionMethod::ForwardFromCurrent;
        assert_eq!(method, ByteSelectionMethod::ForwardFromCurrent);
    }
}
