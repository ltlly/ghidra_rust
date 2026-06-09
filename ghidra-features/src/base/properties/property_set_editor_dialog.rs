//! Property set editor dialog model.
//!
//! Ports Ghidra's `PropertySetEditorDialog` pattern used in
//! `ghidra.app.plugin.core.property` for viewing and editing the set of
//! properties assigned to addresses within a program.
//!
//! # Overview
//!
//! In Ghidra, the PropertySetEditorDialog allows users to:
//!
//! - View all properties at a given address or address range
//! - Add new properties (with a name and typed value)
//! - Edit existing property values in-place
//! - Delete individual properties or clear all properties in a range
//! - Navigate between addresses that share a property
//!
//! This module provides the *data model* for such a dialog.  It does not
//! provide GUI widgets (those belong in the GUI crate) but instead supplies
//! the backing state machine, edit operations, and undo/redo support that a
//! dialog controller would drive.
//!
//! # Architecture
//!
//! The dialog model owns a snapshot of the property state for the addresses
//! under edit.  All modifications go through [`EditAction`]s that can be
//! undone.  The model integrates with [`PropertyChangeManager`] from the
//! sibling module to fire events when the user commits changes.

use ghidra_core::addr::{Address, AddressSet};

use super::property_change_manager::{
    PropertyChangeManager, PropertyChangeEvent,
    PropertyValue as EventPropertyValue,
};
use super::super::property::{PropertyMapManager, PropertyValue};

use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// PropertyEntry -- a single property at a single address
// ---------------------------------------------------------------------------

/// A property entry displayed in the editor.
///
/// Each entry represents one (address, property_name, value) triple.
#[derive(Debug, Clone, PartialEq)]
pub struct PropertyEntry {
    /// The address this property applies to.
    pub address: Address,
    /// The property name (e.g. `"COMMENT"`, `"EQUATE"`).
    pub property_name: String,
    /// The current value.
    pub value: PropertyValue,
    /// Whether the user has marked this entry for deletion.
    pub marked_for_deletion: bool,
}

impl PropertyEntry {
    /// Create a new property entry.
    pub fn new(
        address: Address,
        property_name: impl Into<String>,
        value: PropertyValue,
    ) -> Self {
        Self {
            address,
            property_name: property_name.into(),
            value,
            marked_for_deletion: false,
        }
    }

    /// Mark this entry for deletion.
    pub fn mark_for_deletion(&mut self) {
        self.marked_for_deletion = true;
    }

    /// Unmark this entry for deletion.
    pub fn unmark_for_deletion(&mut self) {
        self.marked_for_deletion = false;
    }
}

impl fmt::Display for PropertyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "0x{:X} {} = {}",
            self.address.offset, self.property_name, self.value
        )
    }
}

// ---------------------------------------------------------------------------
// EditAction -- undoable edit operations
// ---------------------------------------------------------------------------

/// An undoable edit action on the property set.
///
/// Each variant captures the information needed to both apply and reverse
/// a change.
#[derive(Debug, Clone)]
pub enum EditAction {
    /// Change the value of an existing property.
    ModifyValue {
        /// Index into the entries list.
        index: usize,
        /// The previous value.
        old_value: PropertyValue,
        /// The new value.
        new_value: PropertyValue,
    },
    /// Add a new property entry.
    Add {
        /// The entry that was added.
        entry: PropertyEntry,
    },
    /// Remove a property entry by index.
    Remove {
        /// Index into the entries list.
        index: usize,
        /// The entry that was removed (for undo).
        removed: PropertyEntry,
    },
    /// Toggle the deletion mark on an entry.
    ToggleDeletion {
        /// Index into the entries list.
        index: usize,
        /// The previous deletion mark state.
        was_marked: bool,
    },
}

// ---------------------------------------------------------------------------
// PropertySetEditorModel -- the dialog's backing state
// ---------------------------------------------------------------------------

/// The data model for the property set editor dialog.
///
/// Holds a mutable snapshot of properties for a set of addresses, supports
/// add/edit/delete operations with undo/redo, and fires change events via
/// a [`PropertyChangeManager`].
///
/// # Lifecycle
///
/// 1. Create a model from a `PropertyMapManager` and an `AddressSet`
/// 2. User edits entries (add, modify, delete)
/// 3. User commits -- the model applies changes back to the `PropertyMapManager`
///    and fires property change events
///
/// At any point the user can undo or discard all changes.
pub struct PropertySetEditorModel {
    /// The property entries being edited.
    entries: Vec<PropertyEntry>,
    /// Undo stack.
    undo_stack: Vec<EditAction>,
    /// Redo stack.
    redo_stack: Vec<EditAction>,
    /// Whether there are uncommitted changes.
    dirty: bool,
    /// The address set being edited (for context).
    address_set: AddressSet,
    /// Property change manager for firing events.
    change_manager: PropertyChangeManager,
}

impl PropertySetEditorModel {
    /// Create a new, empty editor model.
    pub fn new(address_set: AddressSet) -> Self {
        Self {
            entries: Vec::new(),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            dirty: false,
            address_set,
            change_manager: PropertyChangeManager::new(),
        }
    }

    /// Populate the model from a property map manager.
    ///
    /// Loads all properties that exist at addresses within the model's
    /// address set.
    pub fn load_from(&mut self, prop_mgr: &PropertyMapManager) {
        self.entries.clear();
        self.undo_stack.clear();
        self.redo_stack.clear();
        self.dirty = false;

        for name in prop_mgr.property_names_in(Some(&self.address_set)) {
            if let Some(map) = prop_mgr.get_property_map(&name) {
                for addr in map.addresses_in(&self.address_set) {
                    if let Some(value) = map.get(&addr) {
                        self.entries.push(PropertyEntry::new(addr, &name, value.clone()));
                    }
                }
            }
        }
    }

    // -- Queries --

    /// The number of entries in the model.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get an entry by index.
    pub fn entry(&self, index: usize) -> Option<&PropertyEntry> {
        self.entries.get(index)
    }

    /// Get a mutable entry by index.
    pub fn entry_mut(&mut self, index: usize) -> Option<&mut PropertyEntry> {
        self.entries.get_mut(index)
    }

    /// All entries (read-only).
    pub fn entries(&self) -> &[PropertyEntry] {
        &self.entries
    }

    /// Whether there are uncommitted changes.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// The address set being edited.
    pub fn address_set(&self) -> &AddressSet {
        &self.address_set
    }

    /// Access the property change manager.
    pub fn change_manager(&self) -> &PropertyChangeManager {
        &self.change_manager
    }

    /// Mutable access to the property change manager.
    pub fn change_manager_mut(&mut self) -> &mut PropertyChangeManager {
        &mut self.change_manager
    }

    /// Find the index of an entry matching the given address and property name.
    pub fn find_entry(&self, address: &Address, property_name: &str) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| &e.address == address && e.property_name == property_name)
    }

    /// Get all entries for a given address.
    pub fn entries_for_address(&self, address: &Address) -> Vec<&PropertyEntry> {
        self.entries.iter().filter(|e| &e.address == address).collect()
    }

    /// Get all entries for a given property name.
    pub fn entries_for_property(&self, property_name: &str) -> Vec<&PropertyEntry> {
        self.entries
            .iter()
            .filter(|e| e.property_name == property_name)
            .collect()
    }

    /// The set of distinct addresses that have entries.
    pub fn addresses(&self) -> Vec<Address> {
        let mut addrs: Vec<Address> = self.entries.iter().map(|e| e.address).collect();
        addrs.sort();
        addrs.dedup();
        addrs
    }

    /// The set of distinct property names in the model.
    pub fn property_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .entries
            .iter()
            .map(|e| e.property_name.clone())
            .collect();
        names.sort();
        names.dedup();
        names
    }

    // -- Mutations --

    /// Add a new property entry.
    ///
    /// Returns the index of the newly added entry.
    pub fn add_entry(
        &mut self,
        address: Address,
        property_name: impl Into<String>,
        value: PropertyValue,
    ) -> usize {
        let entry = PropertyEntry::new(address, property_name, value);
        let index = self.entries.len();
        self.undo_stack.push(EditAction::Add {
            entry: entry.clone(),
        });
        self.redo_stack.clear();
        self.entries.push(entry);
        self.dirty = true;
        index
    }

    /// Modify the value of an existing entry.
    ///
    /// Returns `true` if the entry was found and modified.
    pub fn modify_value(&mut self, index: usize, new_value: PropertyValue) -> bool {
        if let Some(entry) = self.entries.get_mut(index) {
            let old_value = entry.value.clone();
            self.undo_stack.push(EditAction::ModifyValue {
                index,
                old_value: old_value.clone(),
                new_value: new_value.clone(),
            });
            self.redo_stack.clear();
            entry.value = new_value;
            self.dirty = true;
            return true;
        }
        false
    }

    /// Remove an entry by index.
    ///
    /// Returns the removed entry, if any.
    pub fn remove_entry(&mut self, index: usize) -> Option<PropertyEntry> {
        if index < self.entries.len() {
            let removed = self.entries.remove(index);
            self.undo_stack.push(EditAction::Remove {
                index,
                removed: removed.clone(),
            });
            self.redo_stack.clear();
            self.dirty = true;
            Some(removed)
        } else {
            None
        }
    }

    /// Toggle the deletion mark on an entry.
    ///
    /// Returns `true` if the entry was found.
    pub fn toggle_deletion_mark(&mut self, index: usize) -> bool {
        if let Some(entry) = self.entries.get_mut(index) {
            let was_marked = entry.marked_for_deletion;
            self.undo_stack.push(EditAction::ToggleDeletion {
                index,
                was_marked,
            });
            self.redo_stack.clear();
            entry.marked_for_deletion = !was_marked;
            self.dirty = true;
            return true;
        }
        false
    }

    /// Remove all entries marked for deletion.
    ///
    /// Returns the number of entries removed.
    pub fn remove_marked(&mut self) -> usize {
        let mut count = 0;
        // Remove in reverse order to keep indices stable.
        for i in (0..self.entries.len()).rev() {
            if self.entries[i].marked_for_deletion {
                self.remove_entry(i);
                count += 1;
            }
        }
        count
    }

    /// Discard all pending changes and reload from the original state.
    ///
    /// This is a convenience method that clears the model.  The caller
    /// should re-invoke [`load_from`] with the original `PropertyMapManager`
    /// if they want to restore the original state.
    pub fn discard_all(&mut self) {
        self.entries.clear();
        self.undo_stack.clear();
        self.redo_stack.clear();
        self.dirty = false;
    }

    // -- Undo / Redo --

    /// Whether an undo operation is available.
    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    /// Whether a redo operation is available.
    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    /// Undo the last edit action.
    ///
    /// Returns `true` if an action was undone.
    pub fn undo(&mut self) -> bool {
        if let Some(action) = self.undo_stack.pop() {
            match &action {
                EditAction::ModifyValue {
                    index,
                    old_value,
                    new_value,
                } => {
                    if let Some(entry) = self.entries.get_mut(*index) {
                        entry.value = old_value.clone();
                    }
                    self.redo_stack.push(EditAction::ModifyValue {
                        index: *index,
                        old_value: old_value.clone(),
                        new_value: new_value.clone(),
                    });
                }
                EditAction::Add { entry } => {
                    // Undo an add = remove the last entry (which is the one we added).
                    if self.entries.last().map(|e| e.address == entry.address
                        && e.property_name == entry.property_name)
                        .unwrap_or(false)
                    {
                        self.entries.pop();
                    }
                    self.redo_stack.push(action);
                }
                EditAction::Remove { index, removed } => {
                    self.entries.insert(*index, removed.clone());
                    self.redo_stack.push(EditAction::Remove {
                        index: *index,
                        removed: removed.clone(),
                    });
                }
                EditAction::ToggleDeletion { index, was_marked } => {
                    if let Some(entry) = self.entries.get_mut(*index) {
                        entry.marked_for_deletion = *was_marked;
                    }
                    self.redo_stack.push(EditAction::ToggleDeletion {
                        index: *index,
                        was_marked: *was_marked,
                    });
                }
            }
            true
        } else {
            false
        }
    }

    /// Redo the last undone action.
    ///
    /// Returns `true` if an action was redone.
    pub fn redo(&mut self) -> bool {
        if let Some(action) = self.redo_stack.pop() {
            match &action {
                EditAction::ModifyValue {
                    index,
                    old_value,
                    new_value,
                } => {
                    if let Some(entry) = self.entries.get_mut(*index) {
                        entry.value = new_value.clone();
                    }
                    self.undo_stack.push(EditAction::ModifyValue {
                        index: *index,
                        old_value: old_value.clone(),
                        new_value: new_value.clone(),
                    });
                }
                EditAction::Add { entry } => {
                    self.entries.push(entry.clone());
                    self.undo_stack.push(EditAction::Add {
                        entry: entry.clone(),
                    });
                }
                EditAction::Remove { index, removed } => {
                    self.entries.remove(*index);
                    self.undo_stack.push(EditAction::Remove {
                        index: *index,
                        removed: removed.clone(),
                    });
                }
                EditAction::ToggleDeletion { index, was_marked } => {
                    if let Some(entry) = self.entries.get_mut(*index) {
                        entry.marked_for_deletion = !*was_marked;
                    }
                    self.undo_stack.push(EditAction::ToggleDeletion {
                        index: *index,
                        was_marked: *was_marked,
                    });
                }
            }
            true
        } else {
            false
        }
    }

    // -- Commit --

    /// Convert a `PropertyValue` (from the property module) to an
    /// `EventPropertyValue` (from the change manager module) for event firing.
    fn convert_to_event_value(pv: &PropertyValue) -> EventPropertyValue {
        match pv {
            PropertyValue::String(s) => EventPropertyValue::String(s.clone()),
            PropertyValue::Bool(b) => EventPropertyValue::Bool(*b),
            PropertyValue::Int(i) => EventPropertyValue::Int(*i as i64),
            PropertyValue::Long(l) => EventPropertyValue::Int(*l),
            PropertyValue::Float(f) => EventPropertyValue::Float(*f as f64),
            PropertyValue::Double(d) => EventPropertyValue::Float(*d),
            PropertyValue::Bytes(_) => EventPropertyValue::Void,
            PropertyValue::Void => EventPropertyValue::Void,
        }
    }

    /// Commit all changes back to a property map manager.
    ///
    /// This applies all add/modify/remove operations to the given manager
    /// and fires property change events.  After committing, the model is
    /// marked as clean.
    pub fn commit(&mut self, prop_mgr: &mut PropertyMapManager) {
        // Rebuild by iterating the original property names and applying changes.
        // For simplicity, we apply each entry as a set operation and then
        // remove properties that were deleted.
        //
        // First, collect what properties should exist after commit.
        let mut desired: BTreeMap<(u64, String), PropertyValue> = BTreeMap::new();
        for entry in &self.entries {
            if !entry.marked_for_deletion {
                desired.insert(
                    (entry.address.offset, entry.property_name.clone()),
                    entry.value.clone(),
                );
            }
        }

        // Apply to the property map manager.
        for ((offset, name), value) in &desired {
            let addr = Address::new(*offset);
            let map = prop_mgr.get_or_create_property_map(name);
            map.set(&addr, value.clone());
        }

        // Remove entries that were deleted.
        for entry in &self.entries {
            if entry.marked_for_deletion {
                if let Some(map) = prop_mgr.get_property_map_mut(&entry.property_name) {
                    map.remove(&entry.address);
                }
                self.change_manager.fire_property_changed(PropertyChangeEvent::for_address(
                    &entry.address,
                    &entry.property_name,
                    Some(Self::convert_to_event_value(&entry.value)),
                    None,
                ));
            }
        }

        self.dirty = false;
        self.undo_stack.clear();
        self.redo_stack.clear();
    }
}

impl fmt::Debug for PropertySetEditorModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PropertySetEditorModel")
            .field("entry_count", &self.entries.len())
            .field("dirty", &self.dirty)
            .field("undo_depth", &self.undo_stack.len())
            .field("redo_depth", &self.redo_stack.len())
            .finish()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn make_model_with_entries() -> (PropertySetEditorModel, PropertyMapManager) {
        let mut mgr = PropertyMapManager::new();
        {
            let map = mgr.get_or_create_property_map("COMMENT");
            map.set(&addr(0x100), PropertyValue::String("hello".into()));
            map.set(&addr(0x200), PropertyValue::String("world".into()));
        }
        {
            let map = mgr.get_or_create_property_map("EQUATE");
            map.set(&addr(0x100), PropertyValue::Int(42));
        }

        let mut set = AddressSet::new();
        set.add_range(addr(0x50), addr(0x300));

        let mut model = PropertySetEditorModel::new(set);
        model.load_from(&mgr);
        (model, mgr)
    }

    // -----------------------------------------------------------------------
    // PropertyEntry
    // -----------------------------------------------------------------------

    #[test]
    fn test_entry_display() {
        let entry = PropertyEntry::new(addr(0x100), "COMMENT", PropertyValue::String("hi".into()));
        let s = format!("{}", entry);
        assert!(s.contains("0x100"));
        assert!(s.contains("COMMENT"));
        assert!(s.contains("hi"));
    }

    #[test]
    fn test_entry_deletion_marks() {
        let mut entry =
            PropertyEntry::new(addr(0x100), "TEST", PropertyValue::Void);
        assert!(!entry.marked_for_deletion);

        entry.mark_for_deletion();
        assert!(entry.marked_for_deletion);

        entry.unmark_for_deletion();
        assert!(!entry.marked_for_deletion);
    }

    // -----------------------------------------------------------------------
    // PropertySetEditorModel -- load and query
    // -----------------------------------------------------------------------

    #[test]
    fn test_load_from() {
        let (model, _) = make_model_with_entries();
        assert_eq!(model.entry_count(), 3);
        assert!(model.is_dirty() == false);
    }

    #[test]
    fn test_entry() {
        let (model, _) = make_model_with_entries();
        assert!(model.entry(0).is_some());
        assert!(model.entry(99).is_none());
    }

    #[test]
    fn test_find_entry() {
        let (model, _) = make_model_with_entries();
        assert!(model.find_entry(&addr(0x100), "COMMENT").is_some());
        assert!(model.find_entry(&addr(0x100), "NONEXISTENT").is_none());
        assert!(model.find_entry(&addr(0x9999), "COMMENT").is_none());
    }

    #[test]
    fn test_entries_for_address() {
        let (model, _) = make_model_with_entries();
        let entries = model.entries_for_address(&addr(0x100));
        assert_eq!(entries.len(), 2); // COMMENT + EQUATE
    }

    #[test]
    fn test_entries_for_property() {
        let (model, _) = make_model_with_entries();
        let entries = model.entries_for_property("COMMENT");
        assert_eq!(entries.len(), 2); // 0x100 + 0x200
    }

    #[test]
    fn test_addresses() {
        let (model, _) = make_model_with_entries();
        let addrs = model.addresses();
        assert_eq!(addrs, vec![addr(0x100), addr(0x200)]);
    }

    #[test]
    fn test_property_names() {
        let (model, _) = make_model_with_entries();
        let names = model.property_names();
        assert_eq!(names, vec!["COMMENT", "EQUATE"]);
    }

    // -----------------------------------------------------------------------
    // PropertySetEditorModel -- mutations
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_entry() {
        let mut model = PropertySetEditorModel::new(AddressSet::new());
        assert_eq!(model.entry_count(), 0);

        let idx = model.add_entry(addr(0x100), "NEW_PROP", PropertyValue::Bool(true));
        assert_eq!(idx, 0);
        assert_eq!(model.entry_count(), 1);
        assert!(model.is_dirty());
    }

    #[test]
    fn test_modify_value() {
        let (mut model, _) = make_model_with_entries();
        assert!(model.modify_value(0, PropertyValue::String("changed".into())));
        assert_eq!(
            model.entry(0).unwrap().value,
            PropertyValue::String("changed".into())
        );
        assert!(model.is_dirty());
    }

    #[test]
    fn test_modify_value_out_of_bounds() {
        let (mut model, _) = make_model_with_entries();
        assert!(!model.modify_value(999, PropertyValue::Void));
    }

    #[test]
    fn test_remove_entry() {
        let (mut model, _) = make_model_with_entries();
        let count_before = model.entry_count();
        let removed = model.remove_entry(0);
        assert!(removed.is_some());
        assert_eq!(model.entry_count(), count_before - 1);
    }

    #[test]
    fn test_remove_entry_out_of_bounds() {
        let (mut model, _) = make_model_with_entries();
        assert!(model.remove_entry(999).is_none());
    }

    #[test]
    fn test_toggle_deletion_mark() {
        let (mut model, _) = make_model_with_entries();
        assert!(model.toggle_deletion_mark(0));
        assert!(model.entry(0).unwrap().marked_for_deletion);

        // Toggle back.
        assert!(model.toggle_deletion_mark(0));
        assert!(!model.entry(0).unwrap().marked_for_deletion);
    }

    #[test]
    fn test_remove_marked() {
        let (mut model, _) = make_model_with_entries();
        model.toggle_deletion_mark(0);
        model.toggle_deletion_mark(1);

        let removed = model.remove_marked();
        assert_eq!(removed, 2);
        assert_eq!(model.entry_count(), 1);
    }

    #[test]
    fn test_discard_all() {
        let (mut model, _) = make_model_with_entries();
        model.add_entry(addr(0x500), "NEW", PropertyValue::Void);
        assert!(model.is_dirty());

        model.discard_all();
        assert_eq!(model.entry_count(), 0);
        assert!(!model.is_dirty());
        assert!(!model.can_undo());
    }

    // -----------------------------------------------------------------------
    // PropertySetEditorModel -- undo / redo
    // -----------------------------------------------------------------------

    #[test]
    fn test_undo_redo_add() {
        let mut model = PropertySetEditorModel::new(AddressSet::new());
        model.add_entry(addr(0x100), "TEST", PropertyValue::Int(1));
        assert_eq!(model.entry_count(), 1);
        assert!(model.can_undo());

        assert!(model.undo());
        assert_eq!(model.entry_count(), 0);

        assert!(model.redo());
        assert_eq!(model.entry_count(), 1);
    }

    #[test]
    fn test_undo_redo_modify() {
        let (mut model, _) = make_model_with_entries();
        model.modify_value(0, PropertyValue::String("new".into()));

        assert!(model.undo());
        assert_eq!(
            model.entry(0).unwrap().value,
            PropertyValue::String("hello".into())
        );

        assert!(model.redo());
        assert_eq!(
            model.entry(0).unwrap().value,
            PropertyValue::String("new".into())
        );
    }

    #[test]
    fn test_undo_redo_remove() {
        let (mut model, _) = make_model_with_entries();
        let count = model.entry_count();
        model.remove_entry(0);
        assert_eq!(model.entry_count(), count - 1);

        assert!(model.undo());
        assert_eq!(model.entry_count(), count);

        assert!(model.redo());
        assert_eq!(model.entry_count(), count - 1);
    }

    #[test]
    fn test_undo_redo_toggle_deletion() {
        let (mut model, _) = make_model_with_entries();
        model.toggle_deletion_mark(0);
        assert!(model.entry(0).unwrap().marked_for_deletion);

        assert!(model.undo());
        assert!(!model.entry(0).unwrap().marked_for_deletion);

        assert!(model.redo());
        assert!(model.entry(0).unwrap().marked_for_deletion);
    }

    #[test]
    fn test_undo_empty() {
        let mut model = PropertySetEditorModel::new(AddressSet::new());
        assert!(!model.can_undo());
        assert!(!model.undo());
    }

    #[test]
    fn test_redo_empty() {
        let mut model = PropertySetEditorModel::new(AddressSet::new());
        assert!(!model.can_redo());
        assert!(!model.redo());
    }

    #[test]
    fn test_undo_clears_redo() {
        let mut model = PropertySetEditorModel::new(AddressSet::new());
        model.add_entry(addr(0x100), "TEST", PropertyValue::Int(1));
        model.undo();
        assert!(model.can_redo());

        // A new action should clear the redo stack.
        model.add_entry(addr(0x200), "TEST2", PropertyValue::Int(2));
        assert!(!model.can_redo());
    }

    // -----------------------------------------------------------------------
    // PropertySetEditorModel -- commit
    // -----------------------------------------------------------------------

    #[test]
    fn test_commit_adds() {
        let mut mgr = PropertyMapManager::new();
        let mut set = AddressSet::new();
        set.add_range(addr(0x50), addr(0x300));

        let mut model = PropertySetEditorModel::new(set);
        model.load_from(&mgr);

        model.add_entry(addr(0x100), "NEW_PROP", PropertyValue::Int(99));
        model.commit(&mut mgr);

        let map = mgr.get_property_map("NEW_PROP").unwrap();
        assert_eq!(map.get(&addr(0x100)), Some(&PropertyValue::Int(99)));
        assert!(!model.is_dirty());
    }

    #[test]
    fn test_commit_removes_deleted() {
        let (mut model, mut mgr) = make_model_with_entries();
        model.toggle_deletion_mark(0); // mark COMMENT at 0x100
        // Commit should remove entries marked for deletion from the property map.
        model.commit(&mut mgr);

        let map = mgr.get_property_map("COMMENT").unwrap();
        assert!(map.get(&addr(0x100)).is_none());
        assert!(map.get(&addr(0x200)).is_some());
    }

    #[test]
    fn test_commit_modifications() {
        let (mut model, mut mgr) = make_model_with_entries();
        model.modify_value(0, PropertyValue::String("modified".into()));
        model.commit(&mut mgr);

        let map = mgr.get_property_map("COMMENT").unwrap();
        assert_eq!(
            map.get(&addr(0x100)),
            Some(&PropertyValue::String("modified".into()))
        );
    }

    // -----------------------------------------------------------------------
    // Debug impl
    // -----------------------------------------------------------------------

    #[test]
    fn test_debug_impl() {
        let (model, _) = make_model_with_entries();
        let dbg = format!("{:?}", model);
        assert!(dbg.contains("PropertySetEditorModel"));
        assert!(dbg.contains("entry_count"));
    }
}
