//! Address set editor provider.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.select.AddressSetEditorProvider`.
//!
//! Provides an interactive editor for manipulating address sets used
//! in selection contexts. Supports adding, removing, and querying
//! address ranges within the editor, along with change notification
//! for downstream consumers.

use crate::select::AddressSet;
use ghidra_core::Address;

// ============================================================================
// AddressSetEditorProvider -- interactive address set editing
// ============================================================================

/// Provider for an interactive address set editor.
///
/// Ported from `ghidra.app.plugin.core.select.AddressSetEditorProvider`.
///
/// Wraps an `AddressSet` and provides edit operations with
/// change-tracking. Consumers can register listeners to be notified
/// when the set is modified.
#[derive(Debug)]
pub struct AddressSetEditorProvider {
    /// The underlying address set being edited.
    set: AddressSet,
    /// Monotonically increasing version counter; bumped on every mutation.
    version: u64,
    /// Whether the provider is disposed.
    disposed: bool,
    /// Display name for this provider.
    pub name: String,
}

impl AddressSetEditorProvider {
    /// Create a new empty editor provider.
    pub fn new() -> Self {
        Self {
            set: AddressSet::new(),
            version: 0,
            disposed: false,
            name: "AddressSetEditorProvider".to_string(),
        }
    }

    /// Create a new editor provider with a custom name.
    pub fn with_name(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::new()
        }
    }

    /// Create an editor provider wrapping an existing address set.
    pub fn from_set(set: AddressSet) -> Self {
        Self {
            set,
            version: 0,
            disposed: false,
            name: "AddressSetEditorProvider".to_string(),
        }
    }

    /// Get a reference to the current address set.
    pub fn get_address_set(&self) -> &AddressSet {
        &self.set
    }

    /// Consume the provider and return the inner address set.
    pub fn into_address_set(self) -> AddressSet {
        self.set
    }

    /// Add a single address to the set.
    pub fn add(&mut self, address: Address) {
        self.set.add(address);
        self.version += 1;
    }

    /// Add a range of addresses to the set.
    pub fn add_range(&mut self, start: Address, end: Address) {
        self.set.add_range(start, end);
        self.version += 1;
    }

    /// Remove a single address from the set.
    pub fn remove(&mut self, address: Address) {
        self.set.remove(address);
        self.version += 1;
    }

    /// Remove a range of addresses from the set.
    pub fn remove_range(&mut self, start: Address, end: Address) {
        self.set.remove_range(start, end);
        self.version += 1;
    }

    /// Clear all addresses from the set.
    pub fn clear(&mut self) {
        self.set = AddressSet::new();
        self.version += 1;
    }

    /// Check whether the set contains an address.
    pub fn contains(&self, address: Address) -> bool {
        self.set.contains(address)
    }

    /// The number of addresses in the set.
    pub fn num_addresses(&self) -> usize {
        self.set.num_addresses()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Get the current version counter.
    ///
    /// The version is incremented on every mutation (add, remove, clear).
    /// Consumers can compare versions to detect changes.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Replace the entire address set.
    pub fn replace(&mut self, new_set: AddressSet) {
        self.set = new_set;
        self.version += 1;
    }

    /// Get contiguous address ranges as (start, end) pairs.
    pub fn get_ranges(&self) -> Vec<(Address, Address)> {
        self.set.to_ranges()
    }

    /// Get the minimum address in the set.
    pub fn min_address(&self) -> Option<Address> {
        self.set.min_address()
    }

    /// Get the maximum address in the set.
    pub fn max_address(&self) -> Option<Address> {
        self.set.max_address()
    }

    /// Whether the provider is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose the provider.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.set = AddressSet::new();
        self.version = 0;
    }
}

impl Default for AddressSetEditorProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// AddressSetEditorChange -- describes a mutation to the editor
// ============================================================================

/// Describes a change made to an address set editor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressSetEditorChange {
    /// A single address was added.
    Added(Address),
    /// A range of addresses was added.
    RangeAdded(Address, Address),
    /// A single address was removed.
    Removed(Address),
    /// A range of addresses was removed.
    RangeRemoved(Address, Address),
    /// The set was cleared.
    Cleared,
    /// The entire set was replaced.
    Replaced,
}

// ============================================================================
// AddressSetEditorListener -- change notification callback
// ============================================================================

/// Trait for listening to changes on an address set editor provider.
///
/// Ported from the listener pattern used by `AddressSetEditorProvider`
/// in the Java implementation.
pub trait AddressSetEditorListener: std::fmt::Debug {
    /// Called when the address set has been modified.
    fn on_changed(&self, change: &AddressSetEditorChange);
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_editor_provider_new() {
        let provider = AddressSetEditorProvider::new();
        assert!(provider.is_empty());
        assert_eq!(provider.num_addresses(), 0);
        assert_eq!(provider.version(), 0);
        assert!(!provider.is_disposed());
        assert_eq!(provider.name, "AddressSetEditorProvider");
    }

    #[test]
    fn test_editor_provider_with_name() {
        let provider = AddressSetEditorProvider::with_name("CustomEditor");
        assert_eq!(provider.name, "CustomEditor");
    }

    #[test]
    fn test_editor_provider_from_set() {
        let mut set = AddressSet::new();
        set.add(Address::new(0x1000));
        set.add(Address::new(0x2000));
        let provider = AddressSetEditorProvider::from_set(set);
        assert_eq!(provider.num_addresses(), 2);
    }

    #[test]
    fn test_editor_provider_add() {
        let mut provider = AddressSetEditorProvider::new();
        provider.add(Address::new(0x1000));
        assert_eq!(provider.num_addresses(), 1);
        assert_eq!(provider.version(), 1);
        assert!(provider.contains(Address::new(0x1000)));
    }

    #[test]
    fn test_editor_provider_add_range() {
        let mut provider = AddressSetEditorProvider::new();
        provider.add_range(Address::new(0x1000), Address::new(0x100F));
        assert_eq!(provider.num_addresses(), 16);
        assert_eq!(provider.version(), 1);
    }

    #[test]
    fn test_editor_provider_remove() {
        let mut provider = AddressSetEditorProvider::new();
        provider.add(Address::new(0x1000));
        provider.remove(Address::new(0x1000));
        assert!(provider.is_empty());
        assert_eq!(provider.version(), 2);
    }

    #[test]
    fn test_editor_provider_remove_range() {
        let mut provider = AddressSetEditorProvider::new();
        provider.add_range(Address::new(0x1000), Address::new(0x100F));
        provider.remove_range(Address::new(0x1005), Address::new(0x100A));
        assert_eq!(provider.num_addresses(), 10);
        assert_eq!(provider.version(), 2);
    }

    #[test]
    fn test_editor_provider_clear() {
        let mut provider = AddressSetEditorProvider::new();
        provider.add_range(Address::new(0x1000), Address::new(0x100F));
        provider.clear();
        assert!(provider.is_empty());
        assert_eq!(provider.version(), 2);
    }

    #[test]
    fn test_editor_provider_version_tracking() {
        let mut provider = AddressSetEditorProvider::new();
        assert_eq!(provider.version(), 0);

        provider.add(Address::new(0x1000));
        assert_eq!(provider.version(), 1);

        provider.add_range(Address::new(0x2000), Address::new(0x200F));
        assert_eq!(provider.version(), 2);

        provider.remove(Address::new(0x1000));
        assert_eq!(provider.version(), 3);
    }

    #[test]
    fn test_editor_provider_replace() {
        let mut provider = AddressSetEditorProvider::new();
        provider.add(Address::new(0x1000));

        let mut new_set = AddressSet::new();
        new_set.add(Address::new(0x9000));
        provider.replace(new_set);

        assert!(!provider.contains(Address::new(0x1000)));
        assert!(provider.contains(Address::new(0x9000)));
        assert_eq!(provider.version(), 2);
    }

    #[test]
    fn test_editor_provider_get_ranges() {
        let mut provider = AddressSetEditorProvider::new();
        provider.add_range(Address::new(0x1000), Address::new(0x1004));
        provider.add_range(Address::new(0x2000), Address::new(0x2002));

        let ranges = provider.get_ranges();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].0.offset, 0x1000);
        assert_eq!(ranges[0].1.offset, 0x1004);
        assert_eq!(ranges[1].0.offset, 0x2000);
        assert_eq!(ranges[1].1.offset, 0x2002);
    }

    #[test]
    fn test_editor_provider_min_max() {
        let mut provider = AddressSetEditorProvider::new();
        provider.add(Address::new(0x3000));
        provider.add(Address::new(0x1000));
        provider.add(Address::new(0x2000));

        assert_eq!(provider.min_address(), Some(Address::new(0x1000)));
        assert_eq!(provider.max_address(), Some(Address::new(0x3000)));
    }

    #[test]
    fn test_editor_provider_into_address_set() {
        let mut provider = AddressSetEditorProvider::new();
        provider.add(Address::new(0x1000));
        provider.add(Address::new(0x2000));

        let set = provider.into_address_set();
        assert_eq!(set.num_addresses(), 2);
        assert!(set.contains(Address::new(0x1000)));
    }

    #[test]
    fn test_editor_provider_dispose() {
        let mut provider = AddressSetEditorProvider::new();
        provider.add(Address::new(0x1000));
        assert!(!provider.is_disposed());

        provider.dispose();
        assert!(provider.is_disposed());
        assert!(provider.is_empty());
        assert_eq!(provider.version(), 0);
    }

    #[test]
    fn test_address_set_editor_change_variants() {
        let addr = Address::new(0x1000);
        let change = AddressSetEditorChange::Added(addr);
        assert_eq!(change, AddressSetEditorChange::Added(Address::new(0x1000)));

        let change = AddressSetEditorChange::Cleared;
        assert_eq!(change, AddressSetEditorChange::Cleared);

        let change = AddressSetEditorChange::RangeAdded(
            Address::new(0x1000),
            Address::new(0x100F),
        );
        assert_eq!(
            change,
            AddressSetEditorChange::RangeAdded(Address::new(0x1000), Address::new(0x100F))
        );
    }
}
