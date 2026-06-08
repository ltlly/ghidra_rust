//! Variable definition for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.listing.Variable`.
//!
//! Defines the [`Variable`] trait which describes an object that stores a
//! value of some specific data type within a function.

use crate::addr::Address;
use crate::symbol::SourceType;

/// Defines an object that stores a value of some specific data type.
///
/// Corresponds to `ghidra.program.model.listing.Variable`. A variable has
/// a name, type, size, storage location, and optional comment.
pub trait Variable {
    /// Returns the name of this variable, or `None` if not assigned.
    fn get_name(&self) -> Option<&str>;

    /// Returns the length of this variable in bytes.
    fn get_length(&self) -> usize;

    /// Returns `true` if the variable is valid (storage is valid and size
    /// matches the data type size).
    fn is_valid(&self) -> bool;

    /// Returns the source of this variable.
    fn get_source(&self) -> SourceType;

    /// Returns the comment for this variable.
    fn get_comment(&self) -> Option<&str>;

    /// Returns `true` if this is a stack variable.
    fn is_stack_variable(&self) -> bool;

    /// Returns `true` if this variable uses storage that contains a stack element.
    fn has_stack_storage(&self) -> bool;

    /// Returns `true` if this is a register variable.
    fn is_register_variable(&self) -> bool;

    /// Returns `true` if this is a memory variable.
    fn is_memory_variable(&self) -> bool;

    /// Returns `true` if this is a unique variable (identified by a hash value).
    fn is_unique_variable(&self) -> bool;

    /// Returns the stack offset if this is a stack variable.
    fn get_stack_offset(&self) -> Option<i64> {
        None
    }

    /// Returns the address of the first storage varnode.
    fn get_first_storage_address(&self) -> Option<Address> {
        None
    }

    /// Returns the size of the first storage element in bytes.
    fn get_first_storage_size(&self) -> Option<usize> {
        None
    }
}

/// Concrete variable data for serialization and storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableData {
    /// Variable name.
    pub name: Option<String>,
    /// Length in bytes.
    pub length: usize,
    /// Whether this variable is valid.
    pub valid: bool,
    /// Source type.
    pub source: SourceType,
    /// Optional comment.
    pub comment: Option<String>,
    /// Whether this is a stack variable.
    pub is_stack: bool,
    /// Whether this is a register variable.
    pub is_register: bool,
    /// Whether this is a memory variable.
    pub is_memory: bool,
    /// Whether this is a unique variable.
    pub is_unique: bool,
    /// Stack offset (if stack variable).
    pub stack_offset: Option<i64>,
    /// First storage address.
    pub first_storage_address: Option<Address>,
    /// First storage size.
    pub first_storage_size: Option<usize>,
}

impl VariableData {
    /// Create a new stack variable.
    pub fn new_stack(name: impl Into<String>, offset: i64, size: usize) -> Self {
        Self {
            name: Some(name.into()),
            length: size,
            valid: true,
            source: SourceType::Default,
            comment: None,
            is_stack: true,
            is_register: false,
            is_memory: false,
            is_unique: false,
            stack_offset: Some(offset),
            first_storage_address: None,
            first_storage_size: Some(size),
        }
    }

    /// Create a new register variable.
    pub fn new_register(name: impl Into<String>, address: Address, size: usize) -> Self {
        Self {
            name: Some(name.into()),
            length: size,
            valid: true,
            source: SourceType::Default,
            comment: None,
            is_stack: false,
            is_register: true,
            is_memory: false,
            is_unique: false,
            stack_offset: None,
            first_storage_address: Some(address),
            first_storage_size: Some(size),
        }
    }
}

impl Variable for VariableData {
    fn get_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn get_length(&self) -> usize {
        self.length
    }

    fn is_valid(&self) -> bool {
        self.valid
    }

    fn get_source(&self) -> SourceType {
        self.source
    }

    fn get_comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    fn is_stack_variable(&self) -> bool {
        self.is_stack
    }

    fn has_stack_storage(&self) -> bool {
        self.is_stack
    }

    fn is_register_variable(&self) -> bool {
        self.is_register
    }

    fn is_memory_variable(&self) -> bool {
        self.is_memory
    }

    fn is_unique_variable(&self) -> bool {
        self.is_unique
    }

    fn get_stack_offset(&self) -> Option<i64> {
        self.stack_offset
    }

    fn get_first_storage_address(&self) -> Option<Address> {
        self.first_storage_address
    }

    fn get_first_storage_size(&self) -> Option<usize> {
        self.first_storage_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_variable() {
        let var = VariableData::new_stack("local_1", -8, 4);
        assert_eq!(var.get_name(), Some("local_1"));
        assert_eq!(var.get_length(), 4);
        assert!(var.is_stack_variable());
        assert!(!var.is_register_variable());
        assert_eq!(var.get_stack_offset(), Some(-8));
    }

    #[test]
    fn test_register_variable() {
        let var = VariableData::new_register("saved_rbp", Address::new(0x20), 8);
        assert_eq!(var.get_name(), Some("saved_rbp"));
        assert_eq!(var.get_length(), 8);
        assert!(var.is_register_variable());
        assert!(!var.is_stack_variable());
    }

    #[test]
    fn test_variable_no_name() {
        let var = VariableData {
            name: None,
            length: 4,
            valid: true,
            source: SourceType::Default,
            comment: None,
            is_stack: true,
            is_register: false,
            is_memory: false,
            is_unique: false,
            stack_offset: Some(-4),
            first_storage_address: None,
            first_storage_size: Some(4),
        };
        assert!(var.get_name().is_none());
    }
}
