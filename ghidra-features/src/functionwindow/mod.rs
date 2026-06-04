//! Function Window -- function list viewer.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.functionwindow` Java package.
//!
//! Provides a window that displays the list of functions in the current program.
//! Users can filter, sort, and navigate to functions. Integrates with the
//! function comparison service for side-by-side analysis.
//!
//! # Architecture
//!
//! - [`FunctionRowObject`] -- row wrapper for a function in the table.
//! - [`FunctionTableModel`] -- model that loads and manages function rows.
//! - [`FunctionWindowPlugin`] -- plugin that owns the provider and listens for
//!   domain-object changes.
//! - [`FunctionWindowProvider`] -- component provider that displays the table.
//! - Mapper types ([`FunctionRowObjectToAddressMapper`],
//!   [`FunctionRowObjectToFunctionMapper`], [`FunctionRowObjectToLocationMapper`],
//!   [`FunctionToAddressMapper`], [`FunctionToLocationMapper`]) -- convert rows
//!   to addresses, functions, or program locations for navigation and context.

use ghidra_core::Address;
use std::collections::{BTreeMap, HashSet};
use std::fmt;

// ===========================================================================
// FunctionRef -- lightweight function metadata
// ===========================================================================

/// Lightweight function reference used by the table model.
///
/// This mirrors the essential fields of `ghidra.program.model.listing.Function`
/// that the function window needs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FunctionRef {
    /// Unique function ID.
    pub id: u64,
    /// Function name.
    pub name: String,
    /// Entry point address.
    pub entry_point: Address,
    /// Full signature string (return type, calling convention, name, params).
    pub signature: String,
    /// Byte size of the function body.
    pub body_size: u64,
    /// Tag names attached to this function.
    pub tags: Vec<String>,
    /// Whether this function is inline.
    pub is_inline: bool,
    /// Whether this function is external (imported).
    pub is_external: bool,
    /// Whether this is a thunk function.
    pub is_thunk: bool,
}

impl FunctionRef {
    /// Create a new function reference.
    pub fn new(
        id: u64,
        name: impl Into<String>,
        entry_point: Address,
        signature: impl Into<String>,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            entry_point,
            signature: signature.into(),
            body_size: 0,
            tags: Vec::new(),
            is_inline: false,
            is_external: false,
            is_thunk: false,
        }
    }
}

impl PartialEq for FunctionRef {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for FunctionRef {}

impl std::hash::Hash for FunctionRef {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

// ===========================================================================
// FunctionRowObject -- row wrapper
// ===========================================================================

/// A row object in the function window table.
///
/// Wraps a [`FunctionRef`] and implements [`Ord`] based on function ID,
/// matching Java's `Comparable<FunctionRowObject>` on `Function.getID()`.
#[derive(Debug, Clone)]
pub struct FunctionRowObject {
    /// The underlying function reference.
    pub function: FunctionRef,
}

impl FunctionRowObject {
    /// Create a new row object from a function reference.
    pub fn new(function: FunctionRef) -> Self {
        Self { function }
    }

    /// Get the function ID key.
    pub fn key(&self) -> u64 {
        self.function.id
    }

    /// Get the function entry point.
    pub fn entry_point(&self) -> Address {
        self.function.entry_point
    }
}

impl PartialEq for FunctionRowObject {
    fn eq(&self, other: &Self) -> bool {
        self.function.id == other.function.id
    }
}
impl Eq for FunctionRowObject {}

impl std::hash::Hash for FunctionRowObject {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.function.id.hash(state);
    }
}

impl PartialOrd for FunctionRowObject {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FunctionRowObject {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.function.id.cmp(&other.function.id)
    }
}

impl fmt::Display for FunctionRowObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[id={}, name={}]",
            self.function.id, self.function.signature
        )
    }
}

// ===========================================================================
// FunctionTableModel -- table model
// ===========================================================================

/// Column index constants for the function table.
pub mod columns {
    /// Name column (index 0).
    pub const NAME: usize = 0;
    /// Location / address column (index 1).
    pub const LOCATION: usize = 1;
    /// Function prototype / signature column (index 2).
    pub const PROTOTYPE: usize = 2;
    /// Function body byte-size column (index 3, hidden by default).
    pub const BODY_SIZE: usize = 3;
    /// Tag column (index 4, hidden by default).
    pub const TAGS: usize = 4;
    /// Inline flag column (index 5, hidden by default).
    pub const IS_INLINE: usize = 5;
}

/// Model that backs the function window table.
///
/// Loads all non-external functions from a [`FunctionStore`] and provides
/// add/remove/update operations for live domain-object events.
///
/// Matches Ghidra's `FunctionTableModel extends AddressBasedTableModel`.
#[derive(Debug)]
pub struct FunctionTableModel {
    /// Human-readable model name.
    pub name: String,
    /// Program name (or empty when no program is loaded).
    pub program_name: String,
    /// Whether the model has been fully loaded.
    pub loaded: bool,
    /// Ordered rows by function ID.
    rows: BTreeMap<u64, FunctionRowObject>,
    /// The function store (program-level backing).
    store: Option<FunctionStore>,
}

impl FunctionTableModel {
    /// Create a new empty function table model.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            program_name: String::new(),
            loaded: false,
            rows: BTreeMap::new(),
            store: None,
        }
    }

    /// Reload the model from the given function store.
    ///
    /// Pass `None` to clear the model (equivalent to program closed).
    pub fn reload(&mut self, store: Option<FunctionStore>) {
        self.rows.clear();
        self.loaded = false;
        if let Some(ref s) = store {
            self.program_name = s.program_name.clone();
            for func in s.functions.values() {
                if !func.is_external {
                    self.rows
                        .insert(func.id, FunctionRowObject::new(func.clone()));
                }
            }
            self.loaded = true;
        } else {
            self.program_name.clear();
        }
        self.store = store;
    }

    /// Number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get a row by index (position in sorted order).
    pub fn get_row(&self, index: usize) -> Option<&FunctionRowObject> {
        self.rows.values().nth(index)
    }

    /// Get a row by function ID.
    pub fn get_row_by_key(&self, key: u64) -> Option<&FunctionRowObject> {
        self.rows.get(&key)
    }

    /// Get rows at the given indices.
    pub fn get_rows(&self, indices: &[usize]) -> Vec<&FunctionRowObject> {
        indices.iter().filter_map(|&i| self.get_row(i)).collect()
    }

    /// Get the entry-point address for a row.
    pub fn get_address(&self, index: usize) -> Option<Address> {
        self.get_row(index).map(|r| r.entry_point())
    }

    /// All rows as a slice-like iterator.
    pub fn all_rows(&self) -> impl Iterator<Item = &FunctionRowObject> {
        self.rows.values()
    }

    /// Get column value as a display string.
    pub fn get_column_value(&self, row: usize, col: usize) -> Option<String> {
        let r = self.get_row(row)?;
        Some(match col {
            columns::NAME => r.function.name.clone(),
            columns::LOCATION => format!("0x{:x}", r.function.entry_point.offset),
            columns::PROTOTYPE => r.function.signature.clone(),
            columns::BODY_SIZE => r.function.body_size.to_string(),
            columns::TAGS => r.function.tags.join(", "),
            columns::IS_INLINE => r.function.is_inline.to_string(),
            _ => String::new(),
        })
    }

    /// Notification: a function was added to the program.
    ///
    /// External functions are ignored (this model does not display them).
    pub fn function_added(&mut self, func: &FunctionRef) {
        if func.is_external {
            return;
        }
        self.rows
            .insert(func.id, FunctionRowObject::new(func.clone()));
    }

    /// Notification: a function was removed from the program.
    pub fn function_removed(&mut self, func: &FunctionRef) {
        self.rows.remove(&func.id);
    }

    /// Notification: a function was changed in the program.
    pub fn update(&mut self, func: &FunctionRef) {
        if func.is_external {
            // If it became external, remove it.
            self.rows.remove(&func.id);
        } else {
            self.rows
                .insert(func.id, FunctionRowObject::new(func.clone()));
        }
    }

    /// Find the index of the function containing the given address.
    pub fn find_by_address(&self, addr: Address) -> Option<usize> {
        self.rows
            .values()
            .position(|r| r.function.entry_point.offset == addr.offset)
    }

    /// Find the index of the function by ID.
    pub fn find_by_id(&self, id: u64) -> Option<usize> {
        self.rows.keys().position(|&k| k == id)
    }
}

// ===========================================================================
// FunctionStore -- program-level function backing
// ===========================================================================

/// A simple in-memory function store representing a program's function manager.
///
/// This is the Rust equivalent of `Program.getFunctionManager()`.
#[derive(Debug, Clone)]
pub struct FunctionStore {
    /// Program name.
    pub program_name: String,
    /// Functions keyed by ID.
    pub functions: BTreeMap<u64, FunctionRef>,
}

impl FunctionStore {
    /// Create a new empty function store.
    pub fn new(program_name: impl Into<String>) -> Self {
        Self {
            program_name: program_name.into(),
            functions: BTreeMap::new(),
        }
    }

    /// Add a function to the store.
    pub fn add_function(&mut self, func: FunctionRef) {
        self.functions.insert(func.id, func);
    }

    /// Remove a function by ID.
    pub fn remove_function(&mut self, id: u64) -> Option<FunctionRef> {
        self.functions.remove(&id)
    }

    /// Get a function by ID.
    pub fn get_function(&self, id: u64) -> Option<&FunctionRef> {
        self.functions.get(&id)
    }

    /// Get the function containing the given address.
    pub fn get_function_containing(&self, addr: Address) -> Option<&FunctionRef> {
        // Simple lookup by entry point; a real implementation would check body ranges.
        self.functions
            .values()
            .find(|f| f.entry_point.offset <= addr.offset && addr.offset < f.entry_point.offset + f.body_size)
            .or_else(|| {
                self.functions
                    .values()
                    .find(|f| f.entry_point.offset == addr.offset)
            })
    }

    /// Number of functions.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Get all non-external functions.
    pub fn non_external_functions(&self) -> impl Iterator<Item = &FunctionRef> {
        self.functions.values().filter(|f| !f.is_external)
    }

    /// Get all functions sorted by entry point.
    pub fn functions_sorted_by_address(&self) -> Vec<&FunctionRef> {
        let mut funcs: Vec<&FunctionRef> = self.functions.values().collect();
        funcs.sort_by_key(|f| f.entry_point.offset);
        funcs
    }
}

// ===========================================================================
// FunctionWindowPlugin -- plugin
// ===========================================================================

/// Plugin that provides the function list window.
///
/// Listens for domain-object events (function added/removed/changed, symbol
/// renamed, etc.) and forwards them to the provider for live table updates.
///
/// Matches Ghidra's `FunctionWindowPlugin extends ProgramPlugin`.
#[derive(Debug)]
pub struct FunctionWindowPlugin {
    /// Plugin name.
    pub name: String,
    /// The function table model.
    pub model: FunctionTableModel,
    /// Current program store, if any.
    pub current_program: Option<FunctionStore>,
    /// Whether the provider is visible.
    pub provider_visible: bool,
    /// Whether navigate-on-incoming is enabled.
    pub navigate_on_incoming: bool,
    /// Whether navigate-on-outgoing is enabled.
    pub navigate_on_outgoing: bool,
    /// Whether the comparison action is available.
    pub has_comparison_service: bool,
}

impl FunctionWindowPlugin {
    /// Create a new function window plugin.
    pub fn new() -> Self {
        Self {
            name: "FunctionWindow".into(),
            model: FunctionTableModel::new("Functions"),
            current_program: None,
            provider_visible: false,
            navigate_on_incoming: false,
            navigate_on_outgoing: false,
            has_comparison_service: false,
        }
    }

    /// Set the current program (activate).
    pub fn program_opened(&mut self, store: FunctionStore) {
        self.model.reload(Some(store.clone()));
        self.current_program = Some(store);
    }

    /// Clear the current program (deactivate).
    pub fn program_closed(&mut self) {
        self.model.reload(None);
        self.current_program = None;
    }

    /// Handle a function-added domain event.
    pub fn function_added(&mut self, func: &FunctionRef) {
        if self.provider_visible {
            self.model.function_added(func);
        }
    }

    /// Handle a function-removed domain event.
    pub fn function_removed(&mut self, func: &FunctionRef) {
        if self.provider_visible {
            self.model.function_removed(func);
        }
    }

    /// Handle a function-changed domain event.
    pub fn function_changed(&mut self, func: &FunctionRef) {
        if self.provider_visible {
            self.model.update(func);
        }
    }

    /// Handle a symbol-renamed domain event.
    ///
    /// Looks up the function at the given address and updates it.
    pub fn symbol_renamed(&mut self, addr: Address) {
        if !self.provider_visible {
            return;
        }
        if let Some(store) = &self.current_program {
            if let Some(func) = store.get_function_containing(addr) {
                let func_ref = func.clone();
                self.model.update(&func_ref);
            }
        }
    }

    /// Handle a location-changed event (select function at address).
    pub fn location_changed(&mut self, addr: Option<Address>) {
        if !self.provider_visible || !self.navigate_on_incoming {
            return;
        }
        // The model tracks which row is selected; this is a no-op at the model level
        // but signals that the UI should scroll to the function at addr.
        let _ = addr;
    }

    /// Reload the model from the current program.
    pub fn reload(&mut self) {
        if self.provider_visible {
            if let Some(store) = self.current_program.clone() {
                self.model.reload(Some(store));
            }
        }
    }

    /// Set provider visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.provider_visible = visible;
        if visible {
            self.reload();
        } else {
            self.model.reload(None);
        }
    }

    /// Simulate service-added callback for FunctionComparisonService.
    pub fn service_added_comparison(&mut self) {
        self.has_comparison_service = true;
    }

    /// Simulate service-removed callback for FunctionComparisonService.
    pub fn service_removed_comparison(&mut self) {
        self.has_comparison_service = false;
    }

    /// Read configuration state.
    pub fn read_config(&mut self, navigate_on_incoming: bool, navigate_on_outgoing: bool) {
        self.navigate_on_incoming = navigate_on_incoming;
        self.navigate_on_outgoing = navigate_on_outgoing;
    }

    /// Write configuration state.
    pub fn write_config(&self) -> (bool, bool) {
        (self.navigate_on_incoming, self.navigate_on_outgoing)
    }
}

impl Default for FunctionWindowPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// FunctionWindowProvider -- component provider
// ===========================================================================

/// Component provider that displays the function table.
///
/// Manages the table, filter panel, and navigation actions. This is the
/// model-level counterpart of Ghidra's `FunctionWindowProvider`.
#[derive(Debug)]
pub struct FunctionWindowProvider {
    /// Provider title.
    pub title: String,
    /// Whether the provider is visible.
    pub visible: bool,
    /// Selected function IDs.
    pub selected_ids: HashSet<u64>,
    /// Navigate-on-incoming toggle state.
    pub navigate_incoming: bool,
    /// Navigate-on-outgoing toggle state.
    pub navigate_outgoing: bool,
    /// Filter text.
    pub filter_text: String,
}

impl FunctionWindowProvider {
    /// Create a new function window provider.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            visible: false,
            selected_ids: HashSet::new(),
            navigate_incoming: false,
            navigate_outgoing: false,
            filter_text: String::new(),
        }
    }

    /// Show the provider.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Hide the provider.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Toggle visibility.
    pub fn toggle(&mut self) {
        self.visible = !self.visible;
    }

    /// Select a function by ID.
    pub fn select(&mut self, id: u64) {
        self.selected_ids.clear();
        self.selected_ids.insert(id);
    }

    /// Select multiple functions by ID.
    pub fn select_multiple(&mut self, ids: &[u64]) {
        self.selected_ids.clear();
        self.selected_ids.extend(ids.iter());
    }

    /// Clear selection.
    pub fn clear_selection(&mut self) {
        self.selected_ids.clear();
    }

    /// Apply a filter to narrow the function list.
    pub fn set_filter(&mut self, text: impl Into<String>) {
        self.filter_text = text.into();
    }

    /// Clear the filter.
    pub fn clear_filter(&mut self) {
        self.filter_text.clear();
    }

    /// Whether the provider has any selection.
    pub fn has_selection(&self) -> bool {
        !self.selected_ids.is_empty()
    }

    /// Read configuration state.
    pub fn read_config(&mut self, navigate_incoming: bool, navigate_outgoing: bool) {
        self.navigate_incoming = navigate_incoming;
        self.navigate_outgoing = navigate_outgoing;
    }

    /// Write configuration state.
    pub fn write_config(&self) -> (bool, bool) {
        (self.navigate_incoming, self.navigate_outgoing)
    }
}

impl Default for FunctionWindowProvider {
    fn default() -> Self {
        Self::new("Functions")
    }
}

// ===========================================================================
// Mapper types -- ProgramLocationTableRowMapper equivalents
// ===========================================================================

/// Maps a [`FunctionRowObject`] to its entry-point [`Address`].
///
/// Corresponds to Java's `FunctionRowObjectToAddressTableRowMapper`.
#[derive(Debug, Clone, Copy)]
pub struct FunctionRowObjectToAddressMapper;

impl FunctionRowObjectToAddressMapper {
    /// Map a row object to an address.
    pub fn map(row: &FunctionRowObject) -> Option<Address> {
        Some(row.function.entry_point)
    }
}

/// Maps a [`FunctionRowObject`] to a [`FunctionRef`].
///
/// Corresponds to Java's `FunctionRowObjectToFunctionTableRowMapper`.
#[derive(Debug, Clone, Copy)]
pub struct FunctionRowObjectToFunctionMapper;

impl FunctionRowObjectToFunctionMapper {
    /// Map a row object to its function reference.
    pub fn map(row: &FunctionRowObject) -> Option<&FunctionRef> {
        Some(&row.function)
    }
}

/// A program location for a function signature field.
///
/// Corresponds to Ghidra's `FunctionSignatureFieldLocation`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FunctionSignatureLocation {
    /// Program name.
    pub program_name: String,
    /// Entry point address.
    pub address: Address,
    /// The function signature string.
    pub signature: String,
}

/// Maps a [`FunctionRowObject`] to a [`FunctionSignatureLocation`].
///
/// Corresponds to Java's `FunctionRowObjectToProgramLocationTableRowMapper`.
#[derive(Debug, Clone, Copy)]
pub struct FunctionRowObjectToLocationMapper;

impl FunctionRowObjectToLocationMapper {
    /// Map a row object to a function signature location.
    pub fn map(row: &FunctionRowObject, program_name: &str) -> FunctionSignatureLocation {
        FunctionSignatureLocation {
            program_name: program_name.into(),
            address: row.function.entry_point,
            signature: row.function.signature.clone(),
        }
    }
}

/// Maps a [`FunctionRef`] to its entry-point [`Address`].
///
/// Corresponds to Java's `FunctionToAddressTableRowMapper`.
#[derive(Debug, Clone, Copy)]
pub struct FunctionToAddressMapper;

impl FunctionToAddressMapper {
    /// Map a function reference to an address.
    pub fn map(func: &FunctionRef) -> Address {
        func.entry_point
    }
}

/// Maps a [`FunctionRef`] to a [`FunctionSignatureLocation`].
///
/// Corresponds to Java's `FunctionToProgramLocationTableRowMapper`.
#[derive(Debug, Clone, Copy)]
pub struct FunctionToLocationMapper;

impl FunctionToLocationMapper {
    /// Map a function reference to a function signature location.
    pub fn map(func: &FunctionRef, program_name: &str) -> FunctionSignatureLocation {
        FunctionSignatureLocation {
            program_name: program_name.into(),
            address: func.entry_point,
            signature: func.signature.clone(),
        }
    }
}

// ===========================================================================
// FunctionSupplierContext -- action context
// ===========================================================================

/// Action context that provides access to selected functions.
///
/// Corresponds to Ghidra's `FunctionSupplierContext` interface combined
/// with `ProgramLocationSupplierContext`.
#[derive(Debug)]
pub struct FunctionActionContext {
    /// The selected function IDs.
    pub selected_function_ids: Vec<u64>,
    /// The selected row indices.
    pub selected_rows: Vec<usize>,
    /// Current location address, if any.
    pub location: Option<Address>,
}

impl FunctionActionContext {
    /// Create an empty action context.
    pub fn new() -> Self {
        Self {
            selected_function_ids: Vec::new(),
            selected_rows: Vec::new(),
            location: None,
        }
    }

    /// Whether any functions are selected.
    pub fn has_functions(&self) -> bool {
        !self.selected_function_ids.is_empty()
    }

    /// Get the selected function IDs.
    pub fn get_function_ids(&self) -> &[u64] {
        &self.selected_function_ids
    }

    /// Set the current location.
    pub fn set_location(&mut self, addr: Option<Address>) {
        self.location = addr;
    }
}

impl Default for FunctionActionContext {
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

    fn make_func(id: u64, name: &str, offset: u64) -> FunctionRef {
        FunctionRef::new(id, name, Address::new(offset), format!("void {}()", name))
    }

    fn make_store() -> FunctionStore {
        let mut store = FunctionStore::new("test.exe");
        store.add_function(make_func(1, "main", 0x401000));
        store.add_function(make_func(2, "foo", 0x402000));
        store.add_function(make_func(3, "bar", 0x403000));
        store.add_function(make_func(4, "ext_import", 0x0));
        store.functions.get_mut(&4).unwrap().is_external = true;
        store
    }

    // ----- FunctionRowObject tests -----

    #[test]
    fn test_row_object_equality() {
        let a = FunctionRowObject::new(make_func(1, "main", 0x1000));
        let b = FunctionRowObject::new(make_func(1, "renamed", 0x2000));
        assert_eq!(a, b); // same ID => equal
    }

    #[test]
    fn test_row_object_ordering() {
        let a = FunctionRowObject::new(make_func(1, "a", 0x1000));
        let b = FunctionRowObject::new(make_func(2, "b", 0x2000));
        assert!(a < b);
    }

    #[test]
    fn test_row_object_display() {
        let r = FunctionRowObject::new(make_func(42, "my_func", 0x1000));
        let s = r.to_string();
        assert!(s.contains("42"));
        assert!(s.contains("my_func"));
    }

    #[test]
    fn test_row_object_key() {
        let r = FunctionRowObject::new(make_func(99, "f", 0x1000));
        assert_eq!(r.key(), 99);
        assert_eq!(r.entry_point(), Address::new(0x1000));
    }

    // ----- FunctionTableModel tests -----

    #[test]
    fn test_model_empty() {
        let model = FunctionTableModel::new("test");
        assert_eq!(model.row_count(), 0);
        assert!(!model.loaded);
    }

    #[test]
    fn test_model_reload() {
        let mut model = FunctionTableModel::new("test");
        let store = make_store();
        model.reload(Some(store));
        assert_eq!(model.row_count(), 3); // external excluded
        assert!(model.loaded);
        assert_eq!(model.program_name, "test.exe");
    }

    #[test]
    fn test_model_reload_none_clears() {
        let mut model = FunctionTableModel::new("test");
        model.reload(Some(make_store()));
        assert_eq!(model.row_count(), 3);
        model.reload(None);
        assert_eq!(model.row_count(), 0);
        assert!(!model.loaded);
    }

    #[test]
    fn test_model_get_row() {
        let mut model = FunctionTableModel::new("test");
        model.reload(Some(make_store()));
        // BTreeMap sorts by key (function ID), so index 0 = id 1 = main
        let row = model.get_row(0).unwrap();
        assert_eq!(row.function.id, 1);
        assert_eq!(row.function.name, "main");
        // index 1 = id 2 = foo
        let row = model.get_row(1).unwrap();
        assert_eq!(row.function.id, 2);
        assert_eq!(row.function.name, "foo");
        // index 2 = id 3 = bar
        let row = model.get_row(2).unwrap();
        assert_eq!(row.function.id, 3);
        assert_eq!(row.function.name, "bar");
    }

    #[test]
    fn test_model_get_address() {
        let mut model = FunctionTableModel::new("test");
        model.reload(Some(make_store()));
        let addr = model.get_address(1).unwrap(); // id 2 = foo
        assert_eq!(addr.offset, 0x402000);
    }

    #[test]
    fn test_model_column_values() {
        let mut model = FunctionTableModel::new("test");
        model.reload(Some(make_store()));
        assert_eq!(
            model.get_column_value(0, columns::NAME).unwrap(),
            "main"
        );
        assert_eq!(
            model.get_column_value(0, columns::LOCATION).unwrap(),
            "0x401000"
        );
        assert_eq!(
            model.get_column_value(0, columns::PROTOTYPE).unwrap(),
            "void main()"
        );
    }

    #[test]
    fn test_model_function_added() {
        let mut model = FunctionTableModel::new("test");
        model.reload(Some(FunctionStore::new("test.exe")));
        assert_eq!(model.row_count(), 0);

        model.function_added(&make_func(10, "new_func", 0x500000));
        assert_eq!(model.row_count(), 1);
    }

    #[test]
    fn test_model_function_added_external_ignored() {
        let mut model = FunctionTableModel::new("test");
        model.reload(Some(FunctionStore::new("test.exe")));
        let mut ext = make_func(10, "ext", 0x0);
        ext.is_external = true;
        model.function_added(&ext);
        assert_eq!(model.row_count(), 0);
    }

    #[test]
    fn test_model_function_removed() {
        let mut model = FunctionTableModel::new("test");
        model.reload(Some(make_store()));
        let count_before = model.row_count();
        model.function_removed(&make_func(1, "main", 0x401000));
        assert_eq!(model.row_count(), count_before - 1);
    }

    #[test]
    fn test_model_update() {
        let mut model = FunctionTableModel::new("test");
        model.reload(Some(make_store()));
        let mut updated = make_func(1, "main_renamed", 0x401000);
        updated.body_size = 256;
        model.update(&updated);
        let row = model.get_row_by_key(1).unwrap();
        assert_eq!(row.function.name, "main_renamed");
        assert_eq!(row.function.body_size, 256);
    }

    #[test]
    fn test_model_update_makes_external_removes() {
        let mut model = FunctionTableModel::new("test");
        model.reload(Some(make_store()));
        assert!(model.get_row_by_key(1).is_some());
        let mut func = make_func(1, "main", 0x401000);
        func.is_external = true;
        model.update(&func);
        assert!(model.get_row_by_key(1).is_none());
    }

    #[test]
    fn test_model_find_by_address() {
        let mut model = FunctionTableModel::new("test");
        model.reload(Some(make_store()));
        let idx = model.find_by_address(Address::new(0x402000)).unwrap();
        let row = model.get_row(idx).unwrap();
        assert_eq!(row.function.name, "foo");
    }

    #[test]
    fn test_model_find_by_id() {
        let mut model = FunctionTableModel::new("test");
        model.reload(Some(make_store()));
        let idx = model.find_by_id(3).unwrap();
        let row = model.get_row(idx).unwrap();
        assert_eq!(row.function.name, "bar");
    }

    #[test]
    fn test_model_get_rows() {
        let mut model = FunctionTableModel::new("test");
        model.reload(Some(make_store()));
        let rows = model.get_rows(&[0, 2]);
        assert_eq!(rows.len(), 2);
    }

    // ----- FunctionStore tests -----

    #[test]
    fn test_store_add_remove() {
        let mut store = FunctionStore::new("prog");
        store.add_function(make_func(1, "f", 0x1000));
        assert_eq!(store.function_count(), 1);
        store.remove_function(1);
        assert_eq!(store.function_count(), 0);
    }

    #[test]
    fn test_store_get_function_containing() {
        let mut store = FunctionStore::new("prog");
        let mut f = make_func(1, "f", 0x1000);
        f.body_size = 0x100;
        store.add_function(f);
        let found = store.get_function_containing(Address::new(0x1050));
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "f");
    }

    #[test]
    fn test_store_non_external() {
        let store = make_store();
        let non_ext: Vec<_> = store.non_external_functions().collect();
        assert_eq!(non_ext.len(), 3);
    }

    #[test]
    fn test_store_sorted_by_address() {
        let store = make_store();
        let sorted = store.functions_sorted_by_address();
        assert_eq!(sorted[0].name, "ext_import");
        assert_eq!(sorted[1].name, "main");
        assert_eq!(sorted[2].name, "foo");
        assert_eq!(sorted[3].name, "bar");
    }

    // ----- FunctionWindowPlugin tests -----

    #[test]
    fn test_plugin_new() {
        let plugin = FunctionWindowPlugin::new();
        assert_eq!(plugin.name, "FunctionWindow");
        assert!(!plugin.provider_visible);
        assert!(plugin.current_program.is_none());
    }

    #[test]
    fn test_plugin_program_opened_closed() {
        let mut plugin = FunctionWindowPlugin::new();
        plugin.program_opened(make_store());
        assert_eq!(plugin.model.row_count(), 3);
        assert!(plugin.current_program.is_some());

        plugin.program_closed();
        assert_eq!(plugin.model.row_count(), 0);
        assert!(plugin.current_program.is_none());
    }

    #[test]
    fn test_plugin_function_events() {
        let mut plugin = FunctionWindowPlugin::new();
        plugin.provider_visible = true;
        plugin.program_opened(make_store());

        // Add
        plugin.function_added(&make_func(10, "new", 0x500000));
        assert!(plugin.model.get_row_by_key(10).is_some());

        // Change
        let mut changed = make_func(10, "new_renamed", 0x500000);
        changed.body_size = 128;
        plugin.function_changed(&changed);
        assert_eq!(plugin.model.get_row_by_key(10).unwrap().function.name, "new_renamed");

        // Remove
        plugin.function_removed(&make_func(10, "new_renamed", 0x500000));
        assert!(plugin.model.get_row_by_key(10).is_none());
    }

    #[test]
    fn test_plugin_events_ignored_when_hidden() {
        let mut plugin = FunctionWindowPlugin::new();
        plugin.provider_visible = false;
        plugin.program_opened(make_store());
        plugin.function_added(&make_func(10, "new", 0x500000));
        assert!(plugin.model.get_row_by_key(10).is_none());
    }

    #[test]
    fn test_plugin_symbol_renamed() {
        let mut plugin = FunctionWindowPlugin::new();
        plugin.provider_visible = true;
        let mut store = make_store();
        let mut f = make_func(5, "target", 0x600000);
        f.body_size = 0x100;
        store.add_function(f);
        plugin.program_opened(store);

        // Rename should update the function at that address
        plugin.symbol_renamed(Address::new(0x600000));
        // The function was already in the model; symbol_renamed just re-updates it
        assert!(plugin.model.get_row_by_key(5).is_some());
    }

    #[test]
    fn test_plugin_visibility() {
        let mut plugin = FunctionWindowPlugin::new();
        plugin.program_opened(make_store());

        plugin.set_visible(true);
        assert!(plugin.provider_visible);
        assert_eq!(plugin.model.row_count(), 3);

        plugin.set_visible(false);
        assert!(!plugin.provider_visible);
        assert_eq!(plugin.model.row_count(), 0);
    }

    #[test]
    fn test_plugin_config() {
        let mut plugin = FunctionWindowPlugin::new();
        plugin.read_config(true, false);
        assert!(plugin.navigate_on_incoming);
        assert!(!plugin.navigate_on_outgoing);
        let (inc, out) = plugin.write_config();
        assert!(inc);
        assert!(!out);
    }

    #[test]
    fn test_plugin_comparison_service() {
        let mut plugin = FunctionWindowPlugin::new();
        assert!(!plugin.has_comparison_service);
        plugin.service_added_comparison();
        assert!(plugin.has_comparison_service);
        plugin.service_removed_comparison();
        assert!(!plugin.has_comparison_service);
    }

    // ----- FunctionWindowProvider tests -----

    #[test]
    fn test_provider_new() {
        let provider = FunctionWindowProvider::new("Functions");
        assert_eq!(provider.title, "Functions");
        assert!(!provider.visible);
        assert!(provider.selected_ids.is_empty());
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = FunctionWindowProvider::new("F");
        provider.show();
        assert!(provider.visible);
        provider.hide();
        assert!(!provider.visible);
        provider.toggle();
        assert!(provider.visible);
    }

    #[test]
    fn test_provider_selection() {
        let mut provider = FunctionWindowProvider::new("F");
        provider.select(42);
        assert!(provider.has_selection());
        assert!(provider.selected_ids.contains(&42));

        provider.select_multiple(&[1, 2, 3]);
        assert_eq!(provider.selected_ids.len(), 3);

        provider.clear_selection();
        assert!(!provider.has_selection());
    }

    #[test]
    fn test_provider_filter() {
        let mut provider = FunctionWindowProvider::new("F");
        provider.set_filter("main");
        assert_eq!(provider.filter_text, "main");
        provider.clear_filter();
        assert!(provider.filter_text.is_empty());
    }

    #[test]
    fn test_provider_config() {
        let mut provider = FunctionWindowProvider::new("F");
        provider.read_config(true, true);
        assert!(provider.navigate_incoming);
        assert!(provider.navigate_outgoing);
        let (inc, out) = provider.write_config();
        assert!(inc);
        assert!(out);
    }

    // ----- Mapper tests -----

    #[test]
    fn test_row_to_address_mapper() {
        let row = FunctionRowObject::new(make_func(1, "f", 0x1000));
        let addr = FunctionRowObjectToAddressMapper::map(&row).unwrap();
        assert_eq!(addr.offset, 0x1000);
    }

    #[test]
    fn test_row_to_function_mapper() {
        let row = FunctionRowObject::new(make_func(1, "f", 0x1000));
        let func = FunctionRowObjectToFunctionMapper::map(&row).unwrap();
        assert_eq!(func.name, "f");
    }

    #[test]
    fn test_row_to_location_mapper() {
        let row = FunctionRowObject::new(make_func(1, "f", 0x1000));
        let loc = FunctionRowObjectToLocationMapper::map(&row, "test.exe");
        assert_eq!(loc.program_name, "test.exe");
        assert_eq!(loc.address.offset, 0x1000);
        assert_eq!(loc.signature, "void f()");
    }

    #[test]
    fn test_function_to_address_mapper() {
        let func = make_func(1, "f", 0x1000);
        let addr = FunctionToAddressMapper::map(&func);
        assert_eq!(addr.offset, 0x1000);
    }

    #[test]
    fn test_function_to_location_mapper() {
        let func = make_func(1, "f", 0x1000);
        let loc = FunctionToLocationMapper::map(&func, "prog");
        assert_eq!(loc.program_name, "prog");
        assert_eq!(loc.signature, "void f()");
    }

    // ----- FunctionActionContext tests -----

    #[test]
    fn test_action_context() {
        let mut ctx = FunctionActionContext::new();
        assert!(!ctx.has_functions());

        ctx.selected_function_ids = vec![1, 2, 3];
        assert!(ctx.has_functions());
        assert_eq!(ctx.get_function_ids(), &[1, 2, 3]);

        ctx.set_location(Some(Address::new(0x401000)));
        assert_eq!(ctx.location.unwrap().offset, 0x401000);
    }

    // ----- Integration tests -----

    #[test]
    fn test_full_workflow() {
        let mut plugin = FunctionWindowPlugin::new();

        // Open program
        plugin.program_opened(make_store());
        assert_eq!(plugin.model.row_count(), 3);

        // Make visible
        plugin.set_visible(true);
        assert!(plugin.provider_visible);

        // Simulate function addition
        plugin.function_added(&make_func(100, "dynamic_func", 0x800000));
        assert_eq!(plugin.model.row_count(), 4);

        // Navigate to it
        let idx = plugin.model.find_by_address(Address::new(0x800000)).unwrap();
        let row = plugin.model.get_row(idx).unwrap();
        assert_eq!(row.function.name, "dynamic_func");

        // Map to address for navigation
        let addr = FunctionRowObjectToAddressMapper::map(row).unwrap();
        assert_eq!(addr.offset, 0x800000);

        // Close program
        plugin.program_closed();
        assert_eq!(plugin.model.row_count(), 0);
    }

    #[test]
    fn test_filter_workflow() {
        let mut plugin = FunctionWindowPlugin::new();
        plugin.program_opened(make_store());
        plugin.set_visible(true);

        // Provider applies filter
        let mut provider = FunctionWindowProvider::new("Functions");
        provider.set_filter("foo");
        // In a real UI, the filter narrows the display; at the model level,
        // all rows are still present for filtering logic.
        assert_eq!(plugin.model.row_count(), 3);
        assert_eq!(provider.filter_text, "foo");
    }

    #[test]
    fn test_selection_context() {
        let mut plugin = FunctionWindowPlugin::new();
        plugin.program_opened(make_store());
        plugin.set_visible(true);

        let mut provider = FunctionWindowProvider::new("Functions");
        provider.select_multiple(&[1, 3]);

        let mut ctx = FunctionActionContext::new();
        ctx.selected_function_ids = provider.selected_ids.iter().copied().collect();
        assert!(ctx.has_functions());
        assert_eq!(ctx.selected_function_ids.len(), 2);
    }
}
