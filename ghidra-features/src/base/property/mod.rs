//! Property management for Ghidra programs.
//!
//! This module ports Ghidra's `ghidra.app.plugin.debug.propertymanager`
//! and `ghidra.program.model.util.PropertyMap/PropertyMapManager` Java
//! packages to Rust. It provides:
//!
//! - [`PropertyValue`] -- a type-erased property value (string, int, long, etc.)
//! - [`PropertyMap`] -- a map from addresses to typed property values
//! - [`PropertyMapManager`] -- manages all named property maps for a program
//! - [`PropertyDeleteCmd`] -- a command that deletes properties over an address range
//! - [`PropertyManagerTableModel`] -- a tabular model for the property viewer UI
//! - [`PropertyManagerPlugin`] -- coordinates property viewing and marker display
//!
//! # Architecture
//!
//! The module separates the data layer ([`PropertyMap`], [`PropertyMapManager`])
//! from the command layer ([`PropertyDeleteCmd`]) and display layer
//! ([`PropertyManagerTableModel`], [`PropertyManagerPlugin`]). This mirrors
//! Ghidra's separation of concerns between `PropertyMapManager` (data model),
//! `Command<Program>` (mutations), and `ComponentProvider` (UI).

use ghidra_core::addr::{Address, AddressSet};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt;

// ---------------------------------------------------------------------------
// PropertyValue -- type-erased value stored in a property map
// ---------------------------------------------------------------------------

/// A type-erased property value.
///
/// Matches the various value types supported by Ghidra's `PropertyMap`
/// interface. In Ghidra, each `PropertyMap<T>` is parameterised by its
/// value type; here we unify them into a single enum for ergonomic
/// in-memory use.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PropertyValue {
    /// A string property (e.g., comments, labels).
    String(String),
    /// A boolean property.
    Bool(bool),
    /// A 32-bit integer property.
    Int(i32),
    /// A 64-bit long property.
    Long(i64),
    /// A 32-bit float property.
    Float(f32),
    /// A 64-bit double property.
    Double(f64),
    /// An arbitrary byte array property.
    Bytes(Vec<u8>),
    /// A void property (existence-only marker, no value).
    Void,
}

impl fmt::Display for PropertyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PropertyValue::String(s) => write!(f, "{}", s),
            PropertyValue::Bool(b) => write!(f, "{}", b),
            PropertyValue::Int(i) => write!(f, "{}", i),
            PropertyValue::Long(l) => write!(f, "{}", l),
            PropertyValue::Float(fl) => write!(f, "{}", fl),
            PropertyValue::Double(d) => write!(f, "{}", d),
            PropertyValue::Bytes(b) => write!(f, "<{} bytes>", b.len()),
            PropertyValue::Void => write!(f, "<void>"),
        }
    }
}

impl PropertyValue {
    /// Returns a short description of the value type.
    pub fn type_name(&self) -> &'static str {
        match self {
            PropertyValue::String(_) => "String",
            PropertyValue::Bool(_) => "Bool",
            PropertyValue::Int(_) => "Int",
            PropertyValue::Long(_) => "Long",
            PropertyValue::Float(_) => "Float",
            PropertyValue::Double(_) => "Double",
            PropertyValue::Bytes(_) => "Bytes",
            PropertyValue::Void => "Void",
        }
    }
}

// ---------------------------------------------------------------------------
// PropertyMap -- a named map from addresses to property values
// ---------------------------------------------------------------------------

/// A named map from addresses to property values.
///
/// Corresponds to Ghidra's `PropertyMap<T>`. Each map has a unique name
/// (e.g., `"COMMENT"`, `"EQUATE"`, `"USER_DEFINED"`) and stores at most
/// one value per address.
///
/// The map supports range-based removal, intersection testing, and
/// ordered iteration over stored addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyMap {
    /// The property name (e.g., `"COMMENT"`).
    name: String,
    /// Sorted map from addresses to values.
    entries: BTreeMap<u64, PropertyValue>,
}

impl PropertyMap {
    /// Create a new empty property map with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            entries: BTreeMap::new(),
        }
    }

    /// The name of this property map.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set a property value at an address. Returns the previous value, if any.
    pub fn set(&mut self, address: &Address, value: PropertyValue) -> Option<PropertyValue> {
        self.entries.insert(address.offset, value)
    }

    /// Get the property value at an address.
    pub fn get(&self, address: &Address) -> Option<&PropertyValue> {
        self.entries.get(&address.offset)
    }

    /// Remove the property at an address. Returns the removed value, if any.
    pub fn remove(&mut self, address: &Address) -> Option<PropertyValue> {
        self.entries.remove(&address.offset)
    }

    /// Remove all properties in the range `[min, max]` (inclusive).
    ///
    /// Corresponds to `PropertyMap.removeRange(Address, Address)`.
    pub fn remove_range(&mut self, min: &Address, max: &Address) {
        let lo = min.offset;
        let hi = max.offset;
        // Collect keys to remove, then remove them (BTreeMap doesn't support
        // range-removal in stable Rust without drain_filter).
        let keys_to_remove: Vec<u64> = self
            .entries
            .range(lo..=hi)
            .map(|(&k, _)| k)
            .collect();
        for k in keys_to_remove {
            self.entries.remove(&k);
        }
    }

    /// Whether this map has any entries in the given address set.
    ///
    /// Corresponds to `PropertyMap.intersects(AddressSetView)`.
    pub fn intersects(&self, addr_set: &AddressSet) -> bool {
        for range in addr_set.iter() {
            let lo = range.get_min_address().offset;
            let hi = range.get_max_address().offset;
            if self.entries.range(lo..=hi).next().is_some() {
                return true;
            }
        }
        false
    }

    /// Return all addresses that have a property in this map.
    pub fn addresses(&self) -> Vec<Address> {
        self.entries
            .keys()
            .map(|&offset| Address::new(offset))
            .collect()
    }

    /// Return all addresses in this map that fall within the given address set.
    pub fn addresses_in(&self, addr_set: &AddressSet) -> Vec<Address> {
        self.entries
            .range(
                addr_set.get_min_address().map(|a| a.offset).unwrap_or(0)
                    ..=addr_set.get_max_address().map(|a| a.offset).unwrap_or(u64::MAX),
            )
            .filter(|(&offset, _)| addr_set.contains(&Address::new(offset)))
            .map(|(&offset, _)| Address::new(offset))
            .collect()
    }

    /// Number of properties in this map.
    pub fn size(&self) -> usize {
        self.entries.len()
    }

    /// Whether this map is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return an iterator over (address, value) pairs in address order.
    pub fn iter(&self) -> impl Iterator<Item = (Address, &PropertyValue)> {
        self.entries
            .iter()
            .map(|(&offset, val)| (Address::new(offset), val))
    }

    /// Clear all entries from this map.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ---------------------------------------------------------------------------
// PropertyMapManager -- manages all named property maps
// ---------------------------------------------------------------------------

/// Manages all named property maps for a program.
///
/// Corresponds to Ghidra's `PropertyMapManager`. Programs have two
/// property managers: one for user properties and one for analysis
/// properties. This struct represents either.
#[derive(Debug, Clone)]
pub struct PropertyMapManager {
    /// All named property maps.
    maps: HashMap<String, PropertyMap>,
}

impl PropertyMapManager {
    /// Create a new empty property map manager.
    pub fn new() -> Self {
        Self {
            maps: HashMap::new(),
        }
    }

    /// Get or create a property map with the given name.
    ///
    /// If the map does not yet exist, it is created on demand (matching
    /// Ghidra's lazy-creation semantics).
    pub fn get_or_create_property_map(&mut self, name: &str) -> &mut PropertyMap {
        self.maps
            .entry(name.to_string())
            .or_insert_with(|| PropertyMap::new(name))
    }

    /// Get a property map by name, if it exists.
    pub fn get_property_map(&self, name: &str) -> Option<&PropertyMap> {
        self.maps.get(name)
    }

    /// Get a mutable property map by name, if it exists.
    pub fn get_property_map_mut(&mut self, name: &str) -> Option<&mut PropertyMap> {
        self.maps.get_mut(name)
    }

    /// Remove an entire property map by name.
    ///
    /// Returns the removed map, if any.
    pub fn remove_property_map(&mut self, name: &str) -> Option<PropertyMap> {
        self.maps.remove(name)
    }

    /// Return the names of all property maps.
    pub fn property_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.maps.keys().cloned().collect();
        names.sort();
        names
    }

    /// Return the names of property maps that have entries in the given
    /// address set. If the set is `None` or empty, return all names.
    pub fn property_names_in(&self, addr_set: Option<&AddressSet>) -> Vec<String> {
        let restricted = addr_set.map(|s| !s.is_empty()).unwrap_or(false);
        let mut names = Vec::new();
        for (name, map) in &self.maps {
            if map.is_empty() {
                continue;
            }
            if restricted {
                if let Some(set) = addr_set {
                    if map.intersects(set) {
                        names.push(name.clone());
                    }
                }
            } else {
                names.push(name.clone());
            }
        }
        names.sort();
        names
    }

    /// Total number of property maps.
    pub fn map_count(&self) -> usize {
        self.maps.len()
    }

    /// Total number of individual property entries across all maps.
    pub fn total_entry_count(&self) -> usize {
        self.maps.values().map(|m| m.size()).sum()
    }

    /// Whether any property maps exist.
    pub fn is_empty(&self) -> bool {
        self.maps.is_empty() || self.maps.values().all(|m| m.is_empty())
    }

    /// Clear all property maps.
    pub fn clear(&mut self) {
        self.maps.clear();
    }
}

impl Default for PropertyMapManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PropertyDeleteCmd -- delete properties (command pattern)
// ---------------------------------------------------------------------------

/// A command that deletes properties from a program.
///
/// Corresponds to Ghidra's `PropertyDeleteCmd`. When a restricted view
/// (address set) is provided, only properties within that set are removed.
/// Otherwise, the entire property map is removed.
#[derive(Debug, Clone)]
pub struct PropertyDeleteCmd {
    /// The name of the property to delete.
    property_name: String,
    /// Optional restricted address set. If `None` or empty, the entire
    /// property map is removed.
    restricted_view: Option<AddressSet>,
    /// Human-readable command name.
    cmd_name: String,
}

impl PropertyDeleteCmd {
    /// Create a new property delete command.
    ///
    /// * `property_name` -- name of the property map to affect.
    /// * `restricted_view` -- optional address set to restrict deletion.
    ///   If `None` or empty, all occurrences of the property are removed.
    pub fn new(property_name: impl Into<String>, restricted_view: Option<AddressSet>) -> Self {
        let prop_name = property_name.into();
        let cmd_name = format!("Delete {} Properties", prop_name);
        Self {
            property_name: prop_name,
            restricted_view,
            cmd_name,
        }
    }

    /// The command name.
    pub fn name(&self) -> &str {
        &self.cmd_name
    }

    /// Apply the delete command to the given property map manager.
    ///
    /// Returns `true` if the command succeeded.
    pub fn apply_to(&self, prop_mgr: &mut PropertyMapManager) -> bool {
        if let Some(ref view) = self.restricted_view {
            if !view.is_empty() {
                if let Some(map) = prop_mgr.get_property_map_mut(&self.property_name) {
                    for range in view.iter() {
                        map.remove_range(&range.get_min_address(), &range.get_max_address());
                    }
                }
                return true;
            }
        }
        prop_mgr.remove_property_map(&self.property_name);
        true
    }
}

// ---------------------------------------------------------------------------
// PropertyManagerTableModel -- tabular model for the property viewer
// ---------------------------------------------------------------------------

/// A tabular model for the property manager viewer.
///
/// Corresponds to Ghidra's `PropertyManagerTableModel`. This model
/// provides a sorted list of property names, optionally filtered by an
/// address set (restricted view).
#[derive(Debug, Clone)]
pub struct PropertyManagerTableModel {
    /// Sorted list of property names to display.
    property_names: Vec<String>,
}

impl PropertyManagerTableModel {
    /// Create a new empty table model.
    pub fn new() -> Self {
        Self {
            property_names: Vec::new(),
        }
    }

    /// Refresh the table model from the given property map manager.
    ///
    /// If `addr_set` is `Some` and non-empty, only property maps that
    /// intersect the address set are included (restricted view).
    pub fn update(&mut self, prop_mgr: &PropertyMapManager, addr_set: Option<&AddressSet>) {
        self.property_names = prop_mgr.property_names_in(addr_set);
    }

    /// The number of rows (property names).
    pub fn row_count(&self) -> usize {
        self.property_names.len()
    }

    /// Get the property name at a given row index.
    pub fn get_property_name(&self, row: usize) -> Option<&str> {
        self.property_names.get(row).map(|s| s.as_str())
    }

    /// Get all property names.
    pub fn property_names(&self) -> &[String] {
        &self.property_names
    }

    /// Remove a row by index. Returns the removed property name, if any.
    pub fn remove_row(&mut self, row: usize) -> Option<String> {
        if row < self.property_names.len() {
            Some(self.property_names.remove(row))
        } else {
            None
        }
    }

    /// Find the row index for a given property name.
    pub fn find_row(&self, name: &str) -> Option<usize> {
        self.property_names.iter().position(|n| n == name)
    }

    /// Clear the model.
    pub fn clear(&mut self) {
        self.property_names.clear();
    }
}

impl Default for PropertyManagerTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PropertyManagerPlugin -- coordinates property viewing and markers
// ---------------------------------------------------------------------------

/// A plugin that manages the property viewer and marker display.
///
/// Corresponds to Ghidra's `PropertyManagerPlugin`. This plugin
/// maintains a table model of available properties and a set of
/// marker addresses for the currently selected property.
#[derive(Debug)]
pub struct PropertyManagerPlugin {
    /// The table model displaying available property names.
    table_model: PropertyManagerTableModel,
    /// The property map manager (user properties).
    property_manager: PropertyMapManager,
    /// Marker addresses for the currently selected property.
    marker_addresses: Vec<Address>,
    /// Index of the currently selected property in the table, or `None`.
    selected_row: Option<usize>,
    /// Whether the provider is currently visible.
    visible: bool,
}

impl PropertyManagerPlugin {
    /// Create a new property manager plugin.
    pub fn new() -> Self {
        Self {
            table_model: PropertyManagerTableModel::new(),
            property_manager: PropertyMapManager::new(),
            marker_addresses: Vec::new(),
            selected_row: None,
            visible: false,
        }
    }

    /// Access the property map manager.
    pub fn property_manager(&self) -> &PropertyMapManager {
        &self.property_manager
    }

    /// Mutably access the property map manager.
    pub fn property_manager_mut(&mut self) -> &mut PropertyMapManager {
        &mut self.property_manager
    }

    /// Access the table model.
    pub fn table_model(&self) -> &PropertyManagerTableModel {
        &self.table_model
    }

    /// Refresh the table model from the property manager.
    pub fn refresh(&mut self, addr_set: Option<&AddressSet>) {
        self.table_model
            .update(&self.property_manager, addr_set);
    }

    /// Select a property by row index and update markers.
    pub fn select_row(&mut self, row: Option<usize>) {
        self.selected_row = row;
        self.refresh_markers();
    }

    /// Get the currently selected property name.
    pub fn selected_property(&self) -> Option<&str> {
        self.selected_row
            .and_then(|r| self.table_model.get_property_name(r))
    }

    /// Get the marker addresses for the currently selected property.
    pub fn marker_addresses(&self) -> &[Address] {
        &self.marker_addresses
    }

    /// Delete the property at the currently selected row.
    ///
    /// Returns `true` if the property was found and deleted.
    pub fn delete_selected(&mut self, addr_set: Option<&AddressSet>) -> bool {
        if let Some(row) = self.selected_row {
            if let Some(prop_name) = self.table_model.get_property_name(row).map(|s| s.to_string())
            {
                let cmd = PropertyDeleteCmd::new(prop_name, addr_set.cloned());
                let result = cmd.apply_to(&mut self.property_manager);
                self.refresh(addr_set);
                self.marker_addresses.clear();
                self.selected_row = None;
                return result;
            }
        }
        false
    }

    /// Set the provider visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    // -- internal --

    fn refresh_markers(&mut self) {
        self.marker_addresses.clear();
        if let Some(prop_name) = self.selected_property() {
            if let Some(map) = self.property_manager.get_property_map(prop_name) {
                self.marker_addresses = map.addresses();
            }
        }
    }
}

impl Default for PropertyManagerPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // PropertyValue
    // -----------------------------------------------------------------------

    #[test]
    fn test_property_value_display() {
        assert_eq!(PropertyValue::String("hello".into()).to_string(), "hello");
        assert_eq!(PropertyValue::Bool(true).to_string(), "true");
        assert_eq!(PropertyValue::Int(42).to_string(), "42");
        assert_eq!(PropertyValue::Long(-1).to_string(), "-1");
        assert_eq!(PropertyValue::Void.to_string(), "<void>");
    }

    #[test]
    fn test_property_value_type_name() {
        assert_eq!(PropertyValue::Bool(false).type_name(), "Bool");
        assert_eq!(PropertyValue::Bytes(vec![1, 2]).type_name(), "Bytes");
    }

    // -----------------------------------------------------------------------
    // PropertyMap
    // -----------------------------------------------------------------------

    #[test]
    fn test_property_map_set_get_remove() {
        let mut map = PropertyMap::new("TEST");
        assert!(map.is_empty());
        assert_eq!(map.size(), 0);

        let addr = Address::new(0x1000);
        assert!(map.get(&addr).is_none());

        let old = map.set(&addr, PropertyValue::Int(42));
        assert!(old.is_none());
        assert_eq!(map.size(), 1);
        assert_eq!(map.get(&addr), Some(&PropertyValue::Int(42)));

        let old = map.set(&addr, PropertyValue::Int(99));
        assert_eq!(old, Some(PropertyValue::Int(42)));
        assert_eq!(map.size(), 1);

        let removed = map.remove(&addr);
        assert_eq!(removed, Some(PropertyValue::Int(99)));
        assert!(map.is_empty());
    }

    #[test]
    fn test_property_map_name() {
        let map = PropertyMap::new("COMMENT");
        assert_eq!(map.name(), "COMMENT");
    }

    #[test]
    fn test_property_map_remove_range() {
        let mut map = PropertyMap::new("TEST");
        map.set(&Address::new(0x100), PropertyValue::Int(1));
        map.set(&Address::new(0x200), PropertyValue::Int(2));
        map.set(&Address::new(0x300), PropertyValue::Int(3));
        map.set(&Address::new(0x400), PropertyValue::Int(4));

        map.remove_range(&Address::new(0x100), &Address::new(0x200));
        assert_eq!(map.size(), 2);
        assert!(map.get(&Address::new(0x100)).is_none());
        assert!(map.get(&Address::new(0x200)).is_none());
        assert!(map.get(&Address::new(0x300)).is_some());
        assert!(map.get(&Address::new(0x400)).is_some());
    }

    #[test]
    fn test_property_map_addresses() {
        let mut map = PropertyMap::new("TEST");
        map.set(&Address::new(0x200), PropertyValue::Int(2));
        map.set(&Address::new(0x100), PropertyValue::Int(1));
        map.set(&Address::new(0x300), PropertyValue::Int(3));

        let addrs = map.addresses();
        assert_eq!(addrs.len(), 3);
        // BTreeMap iterates in sorted order
        assert_eq!(addrs[0], Address::new(0x100));
        assert_eq!(addrs[1], Address::new(0x200));
        assert_eq!(addrs[2], Address::new(0x300));
    }

    #[test]
    fn test_property_map_intersects() {
        let mut map = PropertyMap::new("TEST");
        map.set(&Address::new(0x1000), PropertyValue::Void);
        map.set(&Address::new(0x3000), PropertyValue::Void);

        let mut set = AddressSet::new();
        set.add_range(Address::new(0x500), Address::new(0x1500));
        assert!(map.intersects(&set));

        let mut set2 = AddressSet::new();
        set2.add_range(Address::new(0x5000), Address::new(0x6000));
        assert!(!map.intersects(&set2));
    }

    #[test]
    fn test_property_map_iter() {
        let mut map = PropertyMap::new("TEST");
        map.set(&Address::new(0x100), PropertyValue::String("a".into()));
        map.set(&Address::new(0x200), PropertyValue::String("b".into()));

        let items: Vec<_> = map.iter().collect();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].0, Address::new(0x100));
        assert_eq!(items[1].0, Address::new(0x200));
    }

    #[test]
    fn test_property_map_clear() {
        let mut map = PropertyMap::new("TEST");
        map.set(&Address::new(0x100), PropertyValue::Void);
        map.set(&Address::new(0x200), PropertyValue::Void);
        assert_eq!(map.size(), 2);

        map.clear();
        assert!(map.is_empty());
    }

    // -----------------------------------------------------------------------
    // PropertyMapManager
    // -----------------------------------------------------------------------

    #[test]
    fn test_property_map_manager_get_or_create() {
        let mut mgr = PropertyMapManager::new();
        assert!(mgr.is_empty());

        {
            let map = mgr.get_or_create_property_map("COMMENT");
            map.set(&Address::new(0x100), PropertyValue::String("test".into()));
        }

        assert_eq!(mgr.map_count(), 1);
        assert!(mgr.get_property_map("COMMENT").is_some());
        assert!(mgr.get_property_map("NONEXISTENT").is_none());
    }

    #[test]
    fn test_property_map_manager_remove_property_map() {
        let mut mgr = PropertyMapManager::new();
        mgr.get_or_create_property_map("TEST");
        assert_eq!(mgr.map_count(), 1);

        let removed = mgr.remove_property_map("TEST");
        assert!(removed.is_some());
        assert_eq!(mgr.map_count(), 0);
    }

    #[test]
    fn test_property_map_manager_property_names_sorted() {
        let mut mgr = PropertyMapManager::new();
        mgr.get_or_create_property_map("ZEBRA");
        mgr.get_or_create_property_map("ALPHA");
        mgr.get_or_create_property_map("MIDDLE");

        let names = mgr.property_names();
        assert_eq!(names, vec!["ALPHA", "MIDDLE", "ZEBRA"]);
    }

    #[test]
    fn test_property_map_manager_names_in_addr_set() {
        let mut mgr = PropertyMapManager::new();
        {
            let map = mgr.get_or_create_property_map("IN_RANGE");
            map.set(&Address::new(0x1000), PropertyValue::Void);
        }
        {
            let map = mgr.get_or_create_property_map("OUT_OF_RANGE");
            map.set(&Address::new(0x9000), PropertyValue::Void);
        }

        let mut set = AddressSet::new();
        set.add_range(Address::new(0x0500), Address::new(0x2000));

        let names = mgr.property_names_in(Some(&set));
        assert_eq!(names, vec!["IN_RANGE"]);
    }

    #[test]
    fn test_property_map_manager_total_entry_count() {
        let mut mgr = PropertyMapManager::new();
        {
            let map = mgr.get_or_create_property_map("A");
            map.set(&Address::new(0x100), PropertyValue::Void);
            map.set(&Address::new(0x200), PropertyValue::Void);
        }
        {
            let map = mgr.get_or_create_property_map("B");
            map.set(&Address::new(0x300), PropertyValue::Void);
        }

        assert_eq!(mgr.total_entry_count(), 3);
    }

    // -----------------------------------------------------------------------
    // PropertyDeleteCmd
    // -----------------------------------------------------------------------

    #[test]
    fn test_property_delete_cmd_full() {
        let mut mgr = PropertyMapManager::new();
        {
            let map = mgr.get_or_create_property_map("TEST");
            map.set(&Address::new(0x100), PropertyValue::Void);
            map.set(&Address::new(0x200), PropertyValue::Void);
        }

        let cmd = PropertyDeleteCmd::new("TEST", None);
        assert_eq!(cmd.name(), "Delete TEST Properties");

        assert!(cmd.apply_to(&mut mgr));
        assert_eq!(mgr.map_count(), 0);
    }

    #[test]
    fn test_property_delete_cmd_restricted() {
        let mut mgr = PropertyMapManager::new();
        {
            let map = mgr.get_or_create_property_map("TEST");
            map.set(&Address::new(0x100), PropertyValue::Int(1));
            map.set(&Address::new(0x200), PropertyValue::Int(2));
            map.set(&Address::new(0x300), PropertyValue::Int(3));
        }

        let mut set = AddressSet::new();
        set.add_range(Address::new(0x050), Address::new(0x200));

        let cmd = PropertyDeleteCmd::new("TEST", Some(set));
        assert!(cmd.apply_to(&mut mgr));

        // The map still exists but only has the entry at 0x300
        let map = mgr.get_property_map("TEST").unwrap();
        assert_eq!(map.size(), 1);
        assert!(map.get(&Address::new(0x300)).is_some());
    }

    // -----------------------------------------------------------------------
    // PropertyManagerTableModel
    // -----------------------------------------------------------------------

    #[test]
    fn test_table_model_empty() {
        let model = PropertyManagerTableModel::new();
        assert_eq!(model.row_count(), 0);
        assert!(model.get_property_name(0).is_none());
    }

    #[test]
    fn test_table_model_update() {
        let mut mgr = PropertyMapManager::new();
        {
            let map = mgr.get_or_create_property_map("BETA");
            map.set(&Address::new(0x100), PropertyValue::Void);
        }
        {
            let map = mgr.get_or_create_property_map("ALPHA");
            map.set(&Address::new(0x200), PropertyValue::Void);
        }

        let mut model = PropertyManagerTableModel::new();
        model.update(&mgr, None);

        assert_eq!(model.row_count(), 2);
        assert_eq!(model.get_property_name(0), Some("ALPHA"));
        assert_eq!(model.get_property_name(1), Some("BETA"));
    }

    #[test]
    fn test_table_model_find_and_remove_row() {
        let mut mgr = PropertyMapManager::new();
        {
            let map = mgr.get_or_create_property_map("TEST");
            map.set(&Address::new(0x100), PropertyValue::Void);
        }

        let mut model = PropertyManagerTableModel::new();
        model.update(&mgr, None);

        assert_eq!(model.find_row("TEST"), Some(0));
        assert_eq!(model.find_row("NONE"), None);

        let removed = model.remove_row(0);
        assert_eq!(removed, Some("TEST".to_string()));
        assert_eq!(model.row_count(), 0);
    }

    // -----------------------------------------------------------------------
    // PropertyManagerPlugin
    // -----------------------------------------------------------------------

    #[test]
    fn test_plugin_lifecycle() {
        let mut plugin = PropertyManagerPlugin::new();
        assert!(!plugin.is_visible());

        // Add a property
        {
            let map = plugin
                .property_manager_mut()
                .get_or_create_property_map("MY_PROP");
            map.set(&Address::new(0x1000), PropertyValue::String("hello".into()));
            map.set(&Address::new(0x2000), PropertyValue::String("world".into()));
        }

        // Refresh and check
        plugin.refresh(None);
        assert_eq!(plugin.table_model().row_count(), 1);
        assert_eq!(
            plugin.table_model().get_property_name(0),
            Some("MY_PROP")
        );

        // Select and check markers
        plugin.select_row(Some(0));
        assert_eq!(plugin.selected_property(), Some("MY_PROP"));
        assert_eq!(plugin.marker_addresses().len(), 2);

        // Visibility
        plugin.set_visible(true);
        assert!(plugin.is_visible());
    }

    #[test]
    fn test_plugin_delete_selected() {
        let mut plugin = PropertyManagerPlugin::new();
        {
            let map = plugin
                .property_manager_mut()
                .get_or_create_property_map("DELETE_ME");
            map.set(&Address::new(0x100), PropertyValue::Void);
        }
        {
            let map = plugin
                .property_manager_mut()
                .get_or_create_property_map("KEEP_ME");
            map.set(&Address::new(0x200), PropertyValue::Void);
        }

        plugin.refresh(None);
        plugin.select_row(Some(0)); // selects "DELETE_ME" (alphabetically first)

        assert!(plugin.delete_selected(None));
        assert_eq!(plugin.table_model().row_count(), 1);
        assert_eq!(
            plugin.table_model().get_property_name(0),
            Some("KEEP_ME")
        );
    }

    #[test]
    fn test_plugin_delete_no_selection() {
        let mut plugin = PropertyManagerPlugin::new();
        assert!(!plugin.delete_selected(None));
    }
}
