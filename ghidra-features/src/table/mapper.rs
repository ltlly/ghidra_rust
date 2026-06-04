//! Row-object mappers for the table framework.
//!
//! This module provides the Rust analogues of Ghidra's
//! `ProgramLocationTableRowMapper` implementations for
//! `AddressableRowObject`.  Mappers convert a row object into
//! a specific navigational type (address, function, program location).

use ghidra_core::addr::Address;

use super::traits::AddressableRowObject;

// ---------------------------------------------------------------------------
// RowMapper trait
// ---------------------------------------------------------------------------

/// Maps an [`AddressableRowObject`] to a target type.
///
/// This is the Rust equivalent of Ghidra's
/// `ProgramLocationTableRowMapper<ROW_TYPE, TARGET_TYPE>`.
pub trait RowMapper<T>: Send + Sync {
    /// Maps the given row object to a value of type `T`.
    fn map(&self, row: &dyn AddressableRowObject) -> T;
}

// ---------------------------------------------------------------------------
// AddressTableRowMapper
// ---------------------------------------------------------------------------

/// Maps an [`AddressableRowObject`] to its [`Address`].
///
/// This is the Rust equivalent of
/// `AddressableRowObjectToAddressTableRowMapper`.
pub struct AddressTableRowMapper;

impl RowMapper<Address> for AddressTableRowMapper {
    fn map(&self, row: &dyn AddressableRowObject) -> Address {
        row.address()
    }
}

// ---------------------------------------------------------------------------
// ProgramLocation
// ---------------------------------------------------------------------------

/// A program location, consisting of an address and optional context.
///
/// This is the Rust equivalent of `ghidra.program.util.ProgramLocation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramLocation {
    /// The address in the program.
    pub address: Address,
    /// Optional program name.
    pub program_name: Option<String>,
}

impl ProgramLocation {
    /// Creates a new `ProgramLocation` with the given address.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            program_name: None,
        }
    }

    /// Creates a new `ProgramLocation` with address and program name.
    pub fn with_program(address: Address, program_name: impl Into<String>) -> Self {
        Self {
            address,
            program_name: Some(program_name.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// FunctionRef
// ---------------------------------------------------------------------------

/// A lightweight reference to a function at a given address.
///
/// This is the Rust equivalent of the result of looking up a
/// `Function` via `FunctionManager.getFunctionContaining(address)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionRef {
    /// The function entry address.
    pub entry: Address,
    /// The function name.
    pub name: String,
}

// ---------------------------------------------------------------------------
// ProgramLocationTableRowMapper
// ---------------------------------------------------------------------------

/// Maps an [`AddressableRowObject`] to a [`ProgramLocation`].
///
/// This is the Rust equivalent of
/// `AddressableRowObjectToProgramLocationTableRowMapper`.
pub struct ProgramLocationTableRowMapper;

impl RowMapper<ProgramLocation> for ProgramLocationTableRowMapper {
    fn map(&self, row: &dyn AddressableRowObject) -> ProgramLocation {
        ProgramLocation::new(row.address())
    }
}

// ---------------------------------------------------------------------------
// FunctionTableRowMapper
// ---------------------------------------------------------------------------

/// Maps an [`AddressableRowObject`] to the function containing its address.
///
/// This is the Rust equivalent of
/// `AddressableRowObjectToFunctionTableRowMapper`.
///
/// In the real Ghidra this looks up the function in the `FunctionManager`.
/// Here we provide a callback-based approach so that the mapper can be
/// used with any function-lookup mechanism.
pub struct FunctionTableRowMapper {
    lookup: Box<dyn Fn(Address) -> Option<FunctionRef> + Send + Sync>,
}

impl FunctionTableRowMapper {
    /// Creates a new mapper with the given function lookup callback.
    pub fn new(lookup: impl Fn(Address) -> Option<FunctionRef> + Send + Sync + 'static) -> Self {
        Self {
            lookup: Box::new(lookup),
        }
    }

    /// Creates a mapper that always returns `None` (no function found).
    pub fn null() -> Self {
        Self::new(|_| None)
    }
}

impl RowMapper<Option<FunctionRef>> for FunctionTableRowMapper {
    fn map(&self, row: &dyn AddressableRowObject) -> Option<FunctionRef> {
        (self.lookup)(row.address())
    }
}
