//! Storage editor for function variables -- ported from
//! `StorageAddressEditorDialog.java`, `StorageAddressModel.java`,
//! `StorageTableCellEditor.java`, `VarnodeLocationCellEditor.java`,
//! and related classes.
//!
//! Provides model and editing support for variable storage locations
//! (register, stack, memory).

use serde::{Deserialize, Serialize};

use super::table_model::VarnodeType;

// ---------------------------------------------------------------------------
// StorageAddress -- a variable's storage location
// ---------------------------------------------------------------------------

/// Represents a variable's storage location.
///
/// Ported from `StorageAddressModel.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageAddress {
    /// The storage type.
    pub storage_type: VarnodeType,
    /// Register name (for register storage).
    pub register: Option<String>,
    /// Stack offset (for stack storage).
    pub stack_offset: Option<i64>,
    /// Memory address (for memory storage).
    pub address: Option<u64>,
    /// Size in bytes.
    pub size: usize,
}

impl StorageAddress {
    /// Create a register storage address.
    pub fn register(name: impl Into<String>, size: usize) -> Self {
        Self {
            storage_type: VarnodeType::Register,
            register: Some(name.into()),
            stack_offset: None,
            address: None,
            size,
        }
    }

    /// Create a stack storage address.
    pub fn stack(offset: i64, size: usize) -> Self {
        Self {
            storage_type: VarnodeType::Stack,
            register: None,
            stack_offset: Some(offset),
            address: None,
            size,
        }
    }

    /// Create a memory storage address.
    pub fn memory(addr: u64, size: usize) -> Self {
        Self {
            storage_type: VarnodeType::Memory,
            register: None,
            stack_offset: None,
            address: Some(addr),
            size,
        }
    }

    /// Display string for this storage address.
    pub fn display_string(&self) -> String {
        match self.storage_type {
            VarnodeType::Register => {
                format!(
                    "{}: {}",
                    self.register.as_deref().unwrap_or("??"),
                    self.size
                )
            }
            VarnodeType::Stack => {
                let offset = self.stack_offset.unwrap_or(0);
                if offset < 0 {
                    format!("Stack[0x{:x}]: {}", (-offset) as u64, self.size)
                } else {
                    format!("Stack[+0x{:x}]: {}", offset, self.size)
                }
            }
            VarnodeType::Memory => {
                format!(
                    "0x{:x}: {}",
                    self.address.unwrap_or(0),
                    self.size
                )
            }
            VarnodeType::Unknown => format!("Unknown: {}", self.size),
        }
    }
}

// ---------------------------------------------------------------------------
// StorageEditorState -- state for the storage editor dialog
// ---------------------------------------------------------------------------

/// State of the storage address editor.
///
/// Ported from `StorageAddressEditorDialog.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageEditorState {
    /// The current storage address being edited.
    pub current: StorageAddress,
    /// Available register names for the current language.
    pub available_registers: Vec<RegisterInfo>,
    /// The stack growth direction.
    pub stack_grows_negative: bool,
    /// The parameter offset.
    pub parameter_offset: i64,
    /// Whether editing is allowed.
    pub editable: bool,
}

impl StorageEditorState {
    /// Create a new storage editor state.
    pub fn new() -> Self {
        Self {
            current: StorageAddress::register("RAX", 8),
            available_registers: Vec::new(),
            stack_grows_negative: true,
            parameter_offset: 0,
            editable: true,
        }
    }
}

impl Default for StorageEditorState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RegisterInfo -- register metadata
// ---------------------------------------------------------------------------

/// Information about a register available for variable storage.
///
/// Ported from register-related storage model classes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterInfo {
    /// Register name (e.g., "RAX", "XMM0").
    pub name: String,
    /// Register size in bytes.
    pub size: usize,
    /// Register address (processor-specific ID).
    pub address: u64,
    /// Whether this is a hidden/compiler register.
    pub is_hidden: bool,
    /// Whether this register is a base pointer.
    pub is_base_pointer: bool,
}

impl RegisterInfo {
    /// Create a new register info.
    pub fn new(name: impl Into<String>, size: usize, address: u64) -> Self {
        Self {
            name: name.into(),
            size,
            address,
            is_hidden: false,
            is_base_pointer: false,
        }
    }
}

// ---------------------------------------------------------------------------
// StorageTableCellEditor -- trait for editing storage in table cells
// ---------------------------------------------------------------------------

/// Trait for editing storage values in table cells.
///
/// Ported from `StorageTableCellEditor.java`.
pub trait StorageTableCellEditor: Send + Sync {
    /// Get the current value from the editor.
    fn get_value(&self) -> StorageAddress;

    /// Set the value in the editor.
    fn set_value(&mut self, value: StorageAddress);

    /// Whether the current edit value is valid.
    fn is_valid(&self) -> bool;

    /// Stop editing and return the result.
    fn stop_editing(&mut self) -> Option<StorageAddress>;
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_address_register() {
        let sa = StorageAddress::register("RAX", 8);
        assert_eq!(sa.storage_type, VarnodeType::Register);
        assert_eq!(sa.register.as_deref(), Some("RAX"));
        assert_eq!(sa.size, 8);
        assert!(sa.display_string().contains("RAX"));
    }

    #[test]
    fn test_storage_address_stack() {
        let sa = StorageAddress::stack(-0x10, 4);
        assert_eq!(sa.storage_type, VarnodeType::Stack);
        assert_eq!(sa.stack_offset, Some(-0x10));
        assert!(sa.display_string().contains("Stack"));
    }

    #[test]
    fn test_storage_address_stack_positive() {
        let sa = StorageAddress::stack(0x10, 4);
        assert!(sa.display_string().contains("+0x10"));
    }

    #[test]
    fn test_storage_address_memory() {
        let sa = StorageAddress::memory(0x400000, 2);
        assert_eq!(sa.storage_type, VarnodeType::Memory);
        assert!(sa.display_string().contains("0x400000"));
    }

    #[test]
    fn test_storage_editor_state() {
        let state = StorageEditorState::default();
        assert!(state.editable);
        assert!(state.stack_grows_negative);
    }

    #[test]
    fn test_register_info() {
        let reg = RegisterInfo::new("XMM0", 16, 0x80);
        assert_eq!(reg.name, "XMM0");
        assert_eq!(reg.size, 16);
        assert!(!reg.is_hidden);
    }
}
