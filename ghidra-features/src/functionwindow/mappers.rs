//! Table row mappers for the function window.
//!
//! Ported from Ghidra's `ProgramLocationTableRowMapper` implementations in
//! the `ghidra.app.plugin.core.functionwindow` package.
//!
//! These mappers convert table row objects to addresses, functions, or
//! program locations for navigation and context actions.
//!
//! # Mappers
//!
//! - [`FunctionRowObjectToAddressMapper`] -- `FunctionRowObject` -> `Address`
//! - [`FunctionRowObjectToFunctionMapper`] -- `FunctionRowObject` -> `FunctionRef`
//! - [`FunctionRowObjectToLocationMapper`] -- `FunctionRowObject` -> `FunctionSignatureLocation`
//! - [`FunctionToAddressMapper`] -- `FunctionRef` -> `Address`
//! - [`FunctionToLocationMapper`] -- `FunctionRef` -> `FunctionSignatureLocation`

use super::{FunctionRef, FunctionRowObject};
use ghidra_core::Address;
use std::collections::HashSet;

// ===========================================================================
// FunctionSignatureLocation
// ===========================================================================

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

impl FunctionSignatureLocation {
    /// Create a new function signature location.
    pub fn new(
        program_name: impl Into<String>,
        address: Address,
        signature: impl Into<String>,
    ) -> Self {
        Self {
            program_name: program_name.into(),
            address,
            signature: signature.into(),
        }
    }
}

// ===========================================================================
// Mapper: FunctionRowObject -> Address
// ===========================================================================

/// Maps a [`FunctionRowObject`] to its entry-point [`Address`].
///
/// Corresponds to Java's `FunctionRowObjectToAddressTableRowMapper`:
///
/// ```java
/// public Address map(FunctionRowObject rowObject, ...) {
///     Function function = rowObject.getFunction();
///     if (function == null) return null;
///     return function.getEntryPoint();
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct FunctionRowObjectToAddressMapper;

impl FunctionRowObjectToAddressMapper {
    /// Map a row object to its entry-point address.
    pub fn map(row: &FunctionRowObject) -> Option<Address> {
        Some(row.function.entry_point)
    }
}

// ===========================================================================
// Mapper: FunctionRowObject -> FunctionRef
// ===========================================================================

/// Maps a [`FunctionRowObject`] to a [`FunctionRef`].
///
/// Corresponds to Java's `FunctionRowObjectToFunctionTableRowMapper`:
///
/// ```java
/// public Function map(FunctionRowObject rowObject, ...) {
///     Function function = rowObject.getFunction();
///     return function;
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct FunctionRowObjectToFunctionMapper;

impl FunctionRowObjectToFunctionMapper {
    /// Map a row object to its function reference.
    pub fn map(row: &FunctionRowObject) -> Option<&FunctionRef> {
        Some(&row.function)
    }
}

// ===========================================================================
// Mapper: FunctionRowObject -> ProgramLocation
// ===========================================================================

/// Maps a [`FunctionRowObject`] to a [`FunctionSignatureLocation`].
///
/// Corresponds to Java's `FunctionRowObjectToProgramLocationTableRowMapper`:
///
/// ```java
/// public ProgramLocation map(FunctionRowObject rowObject, ...) {
///     Function function = rowObject.getFunction();
///     if (function == null) return null;
///     return new FunctionSignatureFieldLocation(program,
///         function.getEntryPoint(), null, 0,
///         function.getPrototypeString(false, false));
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct FunctionRowObjectToLocationMapper;

impl FunctionRowObjectToLocationMapper {
    /// Map a row object to a function signature location.
    pub fn map(row: &FunctionRowObject, program_name: &str) -> FunctionSignatureLocation {
        FunctionSignatureLocation::new(
            program_name,
            row.function.entry_point,
            &row.function.signature,
        )
    }
}

// ===========================================================================
// Mapper: FunctionRef -> Address
// ===========================================================================

/// Maps a [`FunctionRef`] to its entry-point [`Address`].
///
/// Corresponds to Java's `FunctionToAddressTableRowMapper`:
///
/// ```java
/// public Address map(Function rowObject, ...) {
///     return rowObject.getEntryPoint();
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct FunctionToAddressMapper;

impl FunctionToAddressMapper {
    /// Map a function reference to its entry-point address.
    pub fn map(func: &FunctionRef) -> Address {
        func.entry_point
    }
}

// ===========================================================================
// Mapper: FunctionRef -> ProgramLocation
// ===========================================================================

/// Maps a [`FunctionRef`] to a [`FunctionSignatureLocation`].
///
/// Corresponds to Java's `FunctionToProgramLocationTableRowMapper`:
///
/// ```java
/// public ProgramLocation map(Function rowObject, ...) {
///     return new FunctionSignatureFieldLocation(program,
///         rowObject.getEntryPoint(), null, 0,
///         rowObject.getPrototypeString(false, false));
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct FunctionToLocationMapper;

impl FunctionToLocationMapper {
    /// Map a function reference to a function signature location.
    pub fn map(func: &FunctionRef, program_name: &str) -> FunctionSignatureLocation {
        FunctionSignatureLocation::new(program_name, func.entry_point, &func.signature)
    }
}

// ===========================================================================
// FunctionActionContext
// ===========================================================================

/// Action context that provides access to selected functions and the
/// current program location.
///
/// Corresponds to Ghidra's `FunctionWindowActionContext` which implements
/// both `FunctionSupplierContext` and `ProgramLocationSupplierContext`.
///
/// # Example
///
/// ```ignore
/// let mut ctx = FunctionActionContext::new();
/// ctx.selected_function_ids = vec![1, 2, 3];
/// assert!(ctx.has_functions());
/// assert_eq!(ctx.get_function_ids(), &[1, 2, 3]);
/// ```
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
    ///
    /// Corresponds to Java's `FunctionSupplierContext.hasFunctions()`.
    pub fn has_functions(&self) -> bool {
        !self.selected_function_ids.is_empty()
    }

    /// Get the selected function IDs.
    pub fn get_function_ids(&self) -> &[u64] {
        &self.selected_function_ids
    }

    /// Get the selected function IDs as a set.
    pub fn get_function_id_set(&self) -> HashSet<u64> {
        self.selected_function_ids.iter().copied().collect()
    }

    /// Set the current location.
    ///
    /// Corresponds to `ProgramLocationSupplierContext.getLocation()`.
    pub fn set_location(&mut self, addr: Option<Address>) {
        self.location = addr;
    }

    /// Build a context from selected rows in a model.
    pub fn from_selection(
        selected_rows: Vec<usize>,
        selected_function_ids: Vec<u64>,
        location: Option<Address>,
    ) -> Self {
        Self {
            selected_function_ids,
            selected_rows,
            location,
        }
    }
}

impl Default for FunctionActionContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_func(id: u64, name: &str, offset: u64) -> FunctionRef {
        FunctionRef::new(id, name, Address::new(offset), format!("void {}()", name))
    }

    // ----- FunctionRowObjectToAddressMapper tests -----

    #[test]
    fn test_row_to_address_mapper() {
        let row = FunctionRowObject::new(make_func(1, "f", 0x1000));
        let addr = FunctionRowObjectToAddressMapper::map(&row).unwrap();
        assert_eq!(addr.offset, 0x1000);
    }

    // ----- FunctionRowObjectToFunctionMapper tests -----

    #[test]
    fn test_row_to_function_mapper() {
        let row = FunctionRowObject::new(make_func(1, "f", 0x1000));
        let func = FunctionRowObjectToFunctionMapper::map(&row).unwrap();
        assert_eq!(func.name, "f");
    }

    // ----- FunctionRowObjectToLocationMapper tests -----

    #[test]
    fn test_row_to_location_mapper() {
        let row = FunctionRowObject::new(make_func(1, "f", 0x1000));
        let loc = FunctionRowObjectToLocationMapper::map(&row, "test.exe");
        assert_eq!(loc.program_name, "test.exe");
        assert_eq!(loc.address.offset, 0x1000);
        assert_eq!(loc.signature, "void f()");
    }

    // ----- FunctionToAddressMapper tests -----

    #[test]
    fn test_function_to_address_mapper() {
        let func = make_func(1, "f", 0x1000);
        let addr = FunctionToAddressMapper::map(&func);
        assert_eq!(addr.offset, 0x1000);
    }

    // ----- FunctionToLocationMapper tests -----

    #[test]
    fn test_function_to_location_mapper() {
        let func = make_func(1, "f", 0x1000);
        let loc = FunctionToLocationMapper::map(&func, "prog");
        assert_eq!(loc.program_name, "prog");
        assert_eq!(loc.signature, "void f()");
    }

    // ----- FunctionSignatureLocation tests -----

    #[test]
    fn test_signature_location_new() {
        let loc = FunctionSignatureLocation::new("prog", Address::new(0x401000), "int main()");
        assert_eq!(loc.program_name, "prog");
        assert_eq!(loc.address.offset, 0x401000);
        assert_eq!(loc.signature, "int main()");
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

    #[test]
    fn test_action_context_id_set() {
        let mut ctx = FunctionActionContext::new();
        ctx.selected_function_ids = vec![1, 2, 3];
        let set = ctx.get_function_id_set();
        assert_eq!(set.len(), 3);
        assert!(set.contains(&1));
        assert!(set.contains(&2));
        assert!(set.contains(&3));
    }

    #[test]
    fn test_action_context_from_selection() {
        let ctx = FunctionActionContext::from_selection(
            vec![0, 2],
            vec![1, 3],
            Some(Address::new(0x401000)),
        );
        assert!(ctx.has_functions());
        assert_eq!(ctx.selected_rows, vec![0, 2]);
        assert_eq!(ctx.selected_function_ids, vec![1, 3]);
        assert_eq!(ctx.location.unwrap().offset, 0x401000);
    }

    #[test]
    fn test_action_context_default() {
        let ctx = FunctionActionContext::default();
        assert!(!ctx.has_functions());
        assert!(ctx.selected_rows.is_empty());
        assert!(ctx.location.is_none());
    }
}
