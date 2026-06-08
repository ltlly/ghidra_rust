//! Dynamic variable storage for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.lang.DynamicVariableStorage`.
//!
//! Provides [`DynamicVariableStorage`] for representing the storage location
//! of a variable that may move during analysis.

use crate::addr::Address;
use serde::{Deserialize, Serialize};
use std::fmt;

/// The kind of storage used by a dynamic variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DynamicStorageKind {
    /// Variable is stored in a register.
    Register,
    /// Variable is stored on the stack.
    Stack,
    /// Variable is stored in a register, then overflows to stack.
    RegisterThenStack,
    /// Variable is stored in memory at a fixed address.
    Memory,
    /// Variable has no physical storage (abstract/unresolved).
    Unresolved,
    /// Variable is stored in a hash-based temporary location.
    HashStorage,
}

/// Represents the storage location of a dynamic variable.
///
/// Corresponds to `ghidra.program.model.lang.DynamicVariableStorage`.
///
/// A dynamic variable's storage may change during analysis as the decompiler
/// refines its understanding of the function. This struct tracks the current
/// storage location, which may be a register, stack offset, memory address,
/// or a combination thereof.
///
/// # Examples
///
/// ```
/// use ghidra_core::program::dynamic_var::*;
/// use ghidra_core::addr::Address;
///
/// let storage = DynamicVariableStorage::register("RAX", 8);
/// assert_eq!(storage.kind(), DynamicStorageKind::Register);
/// assert_eq!(storage.register_name(), Some("RAX"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicVariableStorage {
    /// The kind of storage.
    kind: DynamicStorageKind,
    /// Primary register name (for Register, RegisterThenStack kinds).
    register: Option<String>,
    /// Stack offset (for Stack, RegisterThenStack kinds).
    stack_offset: Option<i64>,
    /// Memory address (for Memory kind).
    memory_address: Option<u64>,
    /// Size of the variable in bytes.
    size: usize,
    /// Hash value for HashStorage kind.
    hash: u64,
    /// Additional varnodes for compound storage.
    varnodes: Vec<VarnodeStorage>,
}

/// A single varnode storage descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VarnodeStorage {
    /// The address of this varnode.
    pub address: Address,
    /// The size of this varnode in bytes.
    pub size: usize,
}

impl DynamicVariableStorage {
    /// Create a register-based variable storage.
    pub fn register(name: impl Into<String>, size: usize) -> Self {
        Self {
            kind: DynamicStorageKind::Register,
            register: Some(name.into()),
            stack_offset: None,
            memory_address: None,
            size,
            hash: 0,
            varnodes: Vec::new(),
        }
    }

    /// Create a stack-based variable storage.
    pub fn stack(offset: i64, size: usize) -> Self {
        Self {
            kind: DynamicStorageKind::Stack,
            register: None,
            stack_offset: Some(offset),
            memory_address: None,
            size,
            hash: 0,
            varnodes: Vec::new(),
        }
    }

    /// Create a register-then-stack variable storage (register with stack overflow).
    pub fn register_then_stack(
        register: impl Into<String>,
        stack_offset: i64,
        size: usize,
    ) -> Self {
        Self {
            kind: DynamicStorageKind::RegisterThenStack,
            register: Some(register.into()),
            stack_offset: Some(stack_offset),
            memory_address: None,
            size,
            hash: 0,
            varnodes: Vec::new(),
        }
    }

    /// Create a memory-based variable storage.
    pub fn memory(address: u64, size: usize) -> Self {
        Self {
            kind: DynamicStorageKind::Memory,
            register: None,
            stack_offset: None,
            memory_address: Some(address),
            size,
            hash: 0,
            varnodes: Vec::new(),
        }
    }

    /// Create an unresolved variable storage.
    pub fn unresolved(size: usize) -> Self {
        Self {
            kind: DynamicStorageKind::Unresolved,
            register: None,
            stack_offset: None,
            memory_address: None,
            size,
            hash: 0,
            varnodes: Vec::new(),
        }
    }

    /// Create a hash-based storage location.
    pub fn hash_storage(hash: u64, size: usize) -> Self {
        Self {
            kind: DynamicStorageKind::HashStorage,
            register: None,
            stack_offset: None,
            memory_address: None,
            size,
            hash,
            varnodes: Vec::new(),
        }
    }

    /// Returns the storage kind.
    pub fn kind(&self) -> DynamicStorageKind {
        self.kind
    }

    /// Returns the register name, if this is a register-based storage.
    pub fn register_name(&self) -> Option<&str> {
        self.register.as_deref()
    }

    /// Returns the stack offset, if this is a stack-based storage.
    pub fn stack_offset(&self) -> Option<i64> {
        self.stack_offset
    }

    /// Returns the memory address, if this is a memory-based storage.
    pub fn memory_address(&self) -> Option<u64> {
        self.memory_address
    }

    /// Returns the size of the variable in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns the hash value for hash-based storage.
    pub fn hash(&self) -> u64 {
        self.hash
    }

    /// Returns true if this is register-based storage.
    pub fn is_register_storage(&self) -> bool {
        matches!(self.kind, DynamicStorageKind::Register | DynamicStorageKind::RegisterThenStack)
    }

    /// Returns true if this is stack-based storage.
    pub fn is_stack_storage(&self) -> bool {
        matches!(self.kind, DynamicStorageKind::Stack | DynamicStorageKind::RegisterThenStack)
    }

    /// Returns true if this is hash-based storage.
    pub fn is_hash_storage(&self) -> bool {
        self.kind == DynamicStorageKind::HashStorage
    }

    /// Returns true if this is unresolved storage.
    pub fn is_unresolved(&self) -> bool {
        self.kind == DynamicStorageKind::Unresolved
    }

    /// Returns true if this storage has a register component.
    pub fn has_register(&self) -> bool {
        self.register.is_some()
    }

    /// Returns true if this storage has a stack component.
    pub fn has_stack(&self) -> bool {
        self.stack_offset.is_some()
    }

    /// Add a varnode to this storage.
    pub fn add_varnode(&mut self, addr: Address, size: usize) {
        self.varnodes.push(VarnodeStorage {
            address: addr,
            size,
        });
    }

    /// Returns the varnodes in this storage.
    pub fn varnodes(&self) -> &[VarnodeStorage] {
        &self.varnodes
    }
}

impl fmt::Display for DynamicVariableStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            DynamicStorageKind::Register => {
                write!(f, "Reg({})", self.register.as_deref().unwrap_or("?"))
            }
            DynamicStorageKind::Stack => {
                write!(f, "Stack({})", self.stack_offset.unwrap_or(0))
            }
            DynamicStorageKind::RegisterThenStack => {
                write!(
                    f,
                    "RegStack({}, {})",
                    self.register.as_deref().unwrap_or("?"),
                    self.stack_offset.unwrap_or(0)
                )
            }
            DynamicStorageKind::Memory => {
                write!(f, "Mem(0x{:x})", self.memory_address.unwrap_or(0))
            }
            DynamicStorageKind::Unresolved => write!(f, "Unresolved"),
            DynamicStorageKind::HashStorage => {
                write!(f, "Hash(0x{:x})", self.hash)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register() {
        let s = DynamicVariableStorage::register("RAX", 8);
        assert_eq!(s.kind(), DynamicStorageKind::Register);
        assert_eq!(s.register_name(), Some("RAX"));
        assert_eq!(s.size(), 8);
        assert!(s.is_register_storage());
        assert!(!s.is_stack_storage());
    }

    #[test]
    fn test_stack() {
        let s = DynamicVariableStorage::stack(-8, 4);
        assert_eq!(s.kind(), DynamicStorageKind::Stack);
        assert_eq!(s.stack_offset(), Some(-8));
        assert!(s.is_stack_storage());
        assert!(!s.is_register_storage());
    }

    #[test]
    fn test_register_then_stack() {
        let s = DynamicVariableStorage::register_then_stack("RCX", -16, 8);
        assert_eq!(s.kind(), DynamicStorageKind::RegisterThenStack);
        assert_eq!(s.register_name(), Some("RCX"));
        assert_eq!(s.stack_offset(), Some(-16));
        assert!(s.is_register_storage());
        assert!(s.is_stack_storage());
    }

    #[test]
    fn test_memory() {
        let s = DynamicVariableStorage::memory(0x401000, 4);
        assert_eq!(s.kind(), DynamicStorageKind::Memory);
        assert_eq!(s.memory_address(), Some(0x401000));
    }

    #[test]
    fn test_unresolved() {
        let s = DynamicVariableStorage::unresolved(8);
        assert!(s.is_unresolved());
    }

    #[test]
    fn test_hash_storage() {
        let s = DynamicVariableStorage::hash_storage(0xDEAD, 4);
        assert!(s.is_hash_storage());
        assert_eq!(s.hash(), 0xDEAD);
    }

    #[test]
    fn test_add_varnode() {
        let mut s = DynamicVariableStorage::register("RAX", 8);
        s.add_varnode(Address::new(0x100), 4);
        assert_eq!(s.varnodes().len(), 1);
        assert_eq!(s.varnodes()[0].address.offset, 0x100);
        assert_eq!(s.varnodes()[0].size, 4);
    }

    #[test]
    fn test_display() {
        let s = DynamicVariableStorage::register("RAX", 8);
        assert_eq!(format!("{}", s), "Reg(RAX)");

        let s = DynamicVariableStorage::stack(-8, 4);
        assert_eq!(format!("{}", s), "Stack(-8)");

        let s = DynamicVariableStorage::hash_storage(0xDEAD, 4);
        assert_eq!(format!("{}", s), "Hash(0xdead)");
    }

    #[test]
    fn test_has_register() {
        let s = DynamicVariableStorage::register("RAX", 8);
        assert!(s.has_register());
        let s = DynamicVariableStorage::stack(-8, 4);
        assert!(!s.has_register());
    }

    #[test]
    fn test_has_stack() {
        let s = DynamicVariableStorage::stack(-8, 4);
        assert!(s.has_stack());
        let s = DynamicVariableStorage::register("RAX", 8);
        assert!(!s.has_stack());
    }

    #[test]
    fn test_clone() {
        let s = DynamicVariableStorage::register("RAX", 8);
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }
}
