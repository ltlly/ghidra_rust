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
//! - [`FunctionRef`] -- lightweight function metadata (id, name, address, signature).
//! - [`FunctionRowObject`] -- row wrapper for a function in the table.
//! - [`FunctionStore`] -- program-level function backing (the "function manager").
//! - [`FunctionTableModel`] -- model that loads and manages function rows.
//! - [`FunctionWindowPlugin`] -- plugin that owns the provider and listens for
//!   domain-object changes.
//! - [`FunctionWindowProvider`] -- component provider that displays the table.
//! - [`events`] -- domain event types for function window events.
//! - [`mappers`] -- mapper types that convert rows to addresses, functions,
//!   or program locations for navigation and context.
//! - [`model`] -- the table model with column definitions.
//! - [`plugin`] -- the plugin implementation.
//! - [`provider`] -- the component provider.

pub mod events;
pub mod mappers;
pub mod model;
pub mod plugin;
pub mod provider;

use ghidra_core::Address;
use std::collections::BTreeMap;
use std::fmt;

// Re-export main types for convenience
pub use events::{EventQueue, FunctionWindowEvent};
pub use mappers::{
    FunctionActionContext, FunctionRowObjectToAddressMapper, FunctionRowObjectToFunctionMapper,
    FunctionRowObjectToLocationMapper, FunctionSignatureLocation, FunctionToAddressMapper,
    FunctionToLocationMapper,
};
pub use model::FunctionTableModel;
pub use plugin::FunctionWindowPlugin;
pub use provider::FunctionWindowProvider;

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
    /// Whether this function does not return.
    pub is_non_returning: bool,
    /// Whether this function uses varargs.
    pub is_varargs: bool,
    /// Whether this function uses custom storage.
    pub is_custom_storage: bool,
    /// Local stack frame size in bytes.
    pub local_stack_size: u32,
    /// Parameter stack size in bytes.
    pub param_stack_size: u32,
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
            is_non_returning: false,
            is_varargs: false,
            is_custom_storage: false,
            local_stack_size: 0,
            param_stack_size: 0,
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
        self.functions
            .values()
            .find(|f| {
                f.entry_point.offset <= addr.offset
                    && addr.offset < f.entry_point.offset + f.body_size
            })
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

    // ----- FunctionRef tests -----

    #[test]
    fn test_function_ref_new() {
        let f = FunctionRef::new(1, "main", Address::new(0x1000), "int main()");
        assert_eq!(f.id, 1);
        assert_eq!(f.name, "main");
        assert_eq!(f.entry_point.offset, 0x1000);
        assert_eq!(f.signature, "int main()");
        assert_eq!(f.body_size, 0);
        assert!(f.tags.is_empty());
        assert!(!f.is_inline);
        assert!(!f.is_external);
        assert!(!f.is_thunk);
        assert!(!f.is_non_returning);
        assert!(!f.is_varargs);
        assert!(!f.is_custom_storage);
        assert_eq!(f.local_stack_size, 0);
        assert_eq!(f.param_stack_size, 0);
    }

    #[test]
    fn test_function_ref_equality() {
        let a = FunctionRef::new(1, "a", Address::new(0x1000), "void a()");
        let b = FunctionRef::new(1, "b", Address::new(0x2000), "void b()");
        assert_eq!(a, b); // same ID => equal
    }

    #[test]
    fn test_function_ref_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(FunctionRef::new(1, "a", Address::new(0x1000), "void a()"));
        set.insert(FunctionRef::new(1, "b", Address::new(0x2000), "void b()"));
        assert_eq!(set.len(), 1); // same ID => same hash
    }

    // ----- FunctionRowObject tests -----

    #[test]
    fn test_row_object_equality() {
        let a = FunctionRowObject::new(make_func(1, "main", 0x1000));
        let b = FunctionRowObject::new(make_func(1, "renamed", 0x2000));
        assert_eq!(a, b);
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
}
