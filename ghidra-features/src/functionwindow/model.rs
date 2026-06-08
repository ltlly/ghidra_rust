//! Function table model.
//!
//! Ported from Ghidra's `FunctionTableModel extends AddressBasedTableModel`.
//!
//! Loads all non-external functions from a [`FunctionStore`] and provides
//! add/remove/update operations for live domain-object events. Supports
//! multiple columns including name, location, prototype, body size, tags,
//! and function attributes (inline, non-returning, varargs, custom storage).

use super::{FunctionRef, FunctionRowObject, FunctionStore};
use ghidra_core::Address;
use std::collections::BTreeMap;
use std::fmt;

// ===========================================================================
// Column definitions
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
    /// Non-returning flag column (index 6, hidden by default).
    pub const IS_NON_RETURNING: usize = 6;
    /// Varargs flag column (index 7, hidden by default).
    pub const IS_VARARGS: usize = 7;
    /// Custom storage flag column (index 8, hidden by default).
    pub const IS_CUSTOM_STORAGE: usize = 8;
    /// Local stack size column (index 9, hidden by default).
    pub const LOCAL_STACK_SIZE: usize = 9;
    /// Parameter stack size column (index 10, hidden by default).
    pub const PARAM_STACK_SIZE: usize = 10;
}

/// Preferred width for the location column (matching Java's LOCATION_COL_WIDTH).
pub const LOCATION_COL_WIDTH: usize = 50;

/// Column metadata for the function table.
#[derive(Debug, Clone)]
pub struct ColumnDef {
    /// Column index.
    pub index: usize,
    /// Column display name.
    pub name: &'static str,
    /// Whether the column is visible by default.
    pub visible_by_default: bool,
    /// Preferred width in pixels (None = auto).
    pub preferred_width: Option<usize>,
}

/// All available columns in order.
pub const ALL_COLUMNS: &[ColumnDef] = &[
    ColumnDef { index: columns::NAME, name: "Name", visible_by_default: true, preferred_width: None },
    ColumnDef { index: columns::LOCATION, name: "Location", visible_by_default: true, preferred_width: Some(LOCATION_COL_WIDTH) },
    ColumnDef { index: columns::PROTOTYPE, name: "Prototype", visible_by_default: true, preferred_width: None },
    ColumnDef { index: columns::BODY_SIZE, name: "Size", visible_by_default: true, preferred_width: None },
    ColumnDef { index: columns::TAGS, name: "Tags", visible_by_default: false, preferred_width: None },
    ColumnDef { index: columns::IS_INLINE, name: "Inline", visible_by_default: false, preferred_width: None },
    ColumnDef { index: columns::IS_NON_RETURNING, name: "No Return", visible_by_default: false, preferred_width: None },
    ColumnDef { index: columns::IS_VARARGS, name: "Varargs", visible_by_default: false, preferred_width: None },
    ColumnDef { index: columns::IS_CUSTOM_STORAGE, name: "Custom Storage", visible_by_default: false, preferred_width: None },
    ColumnDef { index: columns::LOCAL_STACK_SIZE, name: "Local Stack", visible_by_default: false, preferred_width: None },
    ColumnDef { index: columns::PARAM_STACK_SIZE, name: "Param Stack", visible_by_default: false, preferred_width: None },
];

// ===========================================================================
// FunctionTableModel
// ===========================================================================

/// Model that backs the function window table.
///
/// Loads all non-external functions from a [`FunctionStore`] and provides
/// add/remove/update operations for live domain-object events.
///
/// Matches Ghidra's `FunctionTableModel extends AddressBasedTableModel`.
///
/// # Column layout
///
/// The visible columns are: Name, Location, Prototype, Size.
/// Additional hidden columns (Tags, Inline, No Return, Varargs, etc.) can
/// be shown by the user.
///
/// # Example
///
/// ```ignore
/// let mut model = FunctionTableModel::new("Functions");
/// model.reload(Some(store));
/// assert_eq!(model.row_count(), 3);
/// let name = model.get_column_value(0, columns::NAME);
/// ```
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
    /// The set of visible column indices.
    visible_columns: Vec<usize>,
}

impl FunctionTableModel {
    /// Create a new empty function table model.
    pub fn new(name: impl Into<String>) -> Self {
        let visible_columns: Vec<usize> = ALL_COLUMNS
            .iter()
            .filter(|c| c.visible_by_default)
            .map(|c| c.index)
            .collect();

        Self {
            name: name.into(),
            program_name: String::new(),
            loaded: false,
            rows: BTreeMap::new(),
            store: None,
            visible_columns,
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
                    self.rows.insert(func.id, FunctionRowObject::new(func.clone()));
                }
            }
            self.loaded = true;
        } else {
            self.program_name.clear();
        }
        self.store = store;
    }

    /// Number of rows (non-external functions).
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

    /// Get the total count of functions in the store (including externals).
    ///
    /// This matches Java's `getKeyCount()` which returns
    /// `functionMgr.getFunctionCount()`.
    pub fn total_function_count(&self) -> usize {
        self.store
            .as_ref()
            .map(|s| s.function_count())
            .unwrap_or(0)
    }

    /// Get column value as a display string.
    ///
    /// Returns `None` if the row index is out of bounds.
    pub fn get_column_value(&self, row: usize, col: usize) -> Option<String> {
        let r = self.get_row(row)?;
        Some(match col {
            columns::NAME => r.function.name.clone(),
            columns::LOCATION => format!("0x{:x}", r.function.entry_point.offset),
            columns::PROTOTYPE => r.function.signature.clone(),
            columns::BODY_SIZE => r.function.body_size.to_string(),
            columns::TAGS => r.function.tags.join(", "),
            columns::IS_INLINE => r.function.is_inline.to_string(),
            columns::IS_NON_RETURNING => r.function.is_non_returning.to_string(),
            columns::IS_VARARGS => r.function.is_varargs.to_string(),
            columns::IS_CUSTOM_STORAGE => r.function.is_custom_storage.to_string(),
            columns::LOCAL_STACK_SIZE => r.function.local_stack_size.to_string(),
            columns::PARAM_STACK_SIZE => r.function.param_stack_size.to_string(),
            _ => String::new(),
        })
    }

    /// Get the column name for a given index.
    pub fn column_name(&self, col: usize) -> &'static str {
        ALL_COLUMNS
            .iter()
            .find(|c| c.index == col)
            .map(|c| c.name)
            .unwrap_or("")
    }

    /// Get the number of columns.
    pub fn column_count(&self) -> usize {
        ALL_COLUMNS.len()
    }

    /// Get the visible column indices.
    pub fn visible_columns(&self) -> &[usize] {
        &self.visible_columns
    }

    /// Set a column visible or hidden.
    pub fn set_column_visible(&mut self, col: usize, visible: bool) {
        self.visible_columns.retain(|&c| c != col);
        if visible {
            self.visible_columns.push(col);
            self.visible_columns.sort();
        }
    }

    /// Notification: a function was added to the program.
    ///
    /// External functions are ignored (this model does not display them).
    pub fn function_added(&mut self, func: &FunctionRef) {
        if func.is_external {
            return;
        }
        self.rows.insert(func.id, FunctionRowObject::new(func.clone()));
    }

    /// Notification: a function was removed from the program.
    pub fn function_removed(&mut self, func: &FunctionRef) {
        self.rows.remove(&func.id);
    }

    /// Notification: a function was changed in the program.
    ///
    /// If the function became external, it is removed from the model.
    pub fn update(&mut self, func: &FunctionRef) {
        if func.is_external {
            self.rows.remove(&func.id);
        } else {
            self.rows.insert(func.id, FunctionRowObject::new(func.clone()));
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

    /// Filter rows by name prefix (case-insensitive).
    ///
    /// Returns the indices of matching rows.
    pub fn filter_by_name(&self, prefix: &str) -> Vec<usize> {
        let lower = prefix.to_lowercase();
        self.rows
            .values()
            .enumerate()
            .filter(|(_, r)| r.function.name.to_lowercase().contains(&lower))
            .map(|(i, _)| i)
            .collect()
    }

    /// Get the underlying store reference.
    pub fn store(&self) -> Option<&FunctionStore> {
        self.store.as_ref()
    }
}

impl fmt::Display for FunctionTableModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.row_count();
        let total = self.total_function_count();
        if count == total {
            write!(f, "{} items", count)
        } else {
            write!(f, "{} items (of {})", count, total)
        }
    }
}

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

    #[test]
    fn test_model_empty() {
        let model = FunctionTableModel::new("test");
        assert_eq!(model.row_count(), 0);
        assert!(!model.loaded);
        assert_eq!(model.column_count(), 11);
    }

    #[test]
    fn test_model_reload() {
        let mut model = FunctionTableModel::new("test");
        let store = make_store();
        model.reload(Some(store));
        assert_eq!(model.row_count(), 3);
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
        let row = model.get_row(0).unwrap();
        assert_eq!(row.function.id, 1);
        assert_eq!(row.function.name, "main");
        let row = model.get_row(1).unwrap();
        assert_eq!(row.function.id, 2);
        assert_eq!(row.function.name, "foo");
    }

    #[test]
    fn test_model_get_address() {
        let mut model = FunctionTableModel::new("test");
        model.reload(Some(make_store()));
        let addr = model.get_address(1).unwrap();
        assert_eq!(addr.offset, 0x402000);
    }

    #[test]
    fn test_model_column_values() {
        let mut model = FunctionTableModel::new("test");
        model.reload(Some(make_store()));
        assert_eq!(model.get_column_value(0, columns::NAME).unwrap(), "main");
        assert_eq!(model.get_column_value(0, columns::LOCATION).unwrap(), "0x401000");
        assert_eq!(model.get_column_value(0, columns::PROTOTYPE).unwrap(), "void main()");
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

    #[test]
    fn test_model_total_function_count() {
        let mut model = FunctionTableModel::new("test");
        model.reload(Some(make_store()));
        assert_eq!(model.total_function_count(), 4); // includes external
        assert_eq!(model.row_count(), 3); // excludes external
    }

    #[test]
    fn test_model_column_name() {
        let model = FunctionTableModel::new("test");
        assert_eq!(model.column_name(columns::NAME), "Name");
        assert_eq!(model.column_name(columns::LOCATION), "Location");
        assert_eq!(model.column_name(columns::BODY_SIZE), "Size");
        assert_eq!(model.column_name(999), "");
    }

    #[test]
    fn test_model_column_visibility() {
        let mut model = FunctionTableModel::new("test");
        let initial = model.visible_columns().to_vec();
        assert!(initial.contains(&columns::NAME));
        assert!(!initial.contains(&columns::TAGS));

        model.set_column_visible(columns::TAGS, true);
        assert!(model.visible_columns().contains(&columns::TAGS));

        model.set_column_visible(columns::TAGS, false);
        assert!(!model.visible_columns().contains(&columns::TAGS));
    }

    #[test]
    fn test_model_filter_by_name() {
        let mut model = FunctionTableModel::new("test");
        model.reload(Some(make_store()));
        let indices = model.filter_by_name("foo");
        assert_eq!(indices.len(), 1);
        let row = model.get_row(indices[0]).unwrap();
        assert_eq!(row.function.name, "foo");

        // Case-insensitive
        let indices = model.filter_by_name("MAIN");
        assert_eq!(indices.len(), 1);
    }

    #[test]
    fn test_model_display() {
        let mut model = FunctionTableModel::new("test");
        model.reload(Some(make_store()));
        let s = model.to_string();
        assert!(s.contains("3 items"));
        assert!(s.contains("4")); // total including external
    }

    #[test]
    fn test_model_all_rows() {
        let mut model = FunctionTableModel::new("test");
        model.reload(Some(make_store()));
        let names: Vec<_> = model.all_rows().map(|r| r.function.name.as_str()).collect();
        assert_eq!(names, vec!["main", "foo", "bar"]);
    }

    #[test]
    fn test_model_store_ref() {
        let mut model = FunctionTableModel::new("test");
        assert!(model.store().is_none());
        model.reload(Some(make_store()));
        assert!(model.store().is_some());
        assert_eq!(model.store().unwrap().program_name, "test.exe");
    }

    #[test]
    fn test_all_columns_metadata() {
        assert_eq!(ALL_COLUMNS.len(), 11);
        assert!(ALL_COLUMNS[0].visible_by_default); // Name
        assert!(ALL_COLUMNS[1].visible_by_default); // Location
        assert!(ALL_COLUMNS[2].visible_by_default); // Prototype
        assert!(ALL_COLUMNS[3].visible_by_default); // Size
        assert!(!ALL_COLUMNS[4].visible_by_default); // Tags
        assert!(!ALL_COLUMNS[5].visible_by_default); // Inline
    }
}
