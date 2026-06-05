//! Extended reference actions -- additional actions beyond the core set.
//!
//! Ported from `DeleteReferencesAction.java`,
//! `CreateDefaultReferenceAction.java`, and `OffsetTablePlugin.java`
//! in Ghidra's `ghidra.app.plugin.core.references`.
//!
//! This module provides higher-level action models:
//! - [`DeleteAllReferencesAction`] -- removes all references from an operand
//!   with user confirmation
//! - [`ShowReferencesAction`] -- opens the references provider for an address
//! - [`AddReferenceAction`] -- adds a new reference with configurable type

use super::commands::{
    AddMemRefCmd, AddOffsetMemRefCmd, AddRegisterRefCmd, AddStackRefCmd, RemoveAllReferencesCmd,
};
use super::plugin::ReferencesPlugin;
use super::ReferenceClass;
use ghidra_core::Address;
use serde::{Deserialize, Serialize};

// ============================================================================
// DeleteAllReferencesAction
// ============================================================================

/// Action that removes all references from a specific operand.
///
/// Ported from Ghidra's `DeleteReferencesAction`.  This is the model
/// behind the "Delete All References" popup-menu action in the listing.
///
/// In Ghidra, the action checks:
/// - The context is a `ListingActionContext`
/// - There are references at the current address/operand
/// - The user confirms the deletion (via a confirmation dialog)
#[derive(Debug, Clone)]
pub struct DeleteAllReferencesAction {
    /// Whether the action is currently enabled.
    pub enabled: bool,
    /// The confirmation message shown to the user.
    pub confirmation_message: String,
    /// The menu path for this action.
    pub menu_path: Vec<String>,
}

impl DeleteAllReferencesAction {
    /// Creates a new delete-all-references action.
    pub fn new() -> Self {
        Self {
            enabled: true,
            confirmation_message: "Delete all references at this location?".to_string(),
            menu_path: vec!["References".to_string(), "Delete All References".to_string()],
        }
    }

    /// Checks whether the action should be enabled for the given context.
    ///
    /// Returns `true` if there are references from the given address/operand.
    pub fn is_enabled_for(&self, has_references: bool) -> bool {
        self.enabled && has_references
    }

    /// Builds a remove-all command for the given address and operand.
    pub fn build_command(&self, address: Address, op_index: i32) -> RemoveAllReferencesCmd {
        RemoveAllReferencesCmd::new(address, op_index)
    }
}

impl Default for DeleteAllReferencesAction {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ShowReferencesAction
// ============================================================================

/// Action that opens the references viewer for an address.
///
/// In Ghidra, this action is available from the listing context menu
/// under "References -> Show References To" (Ctrl+Shift+F).
#[derive(Debug, Clone)]
pub struct ShowReferencesAction {
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The menu path.
    pub menu_path: Vec<String>,
    /// Whether this action is for "to" (incoming) or "from" (outgoing) references.
    pub direction: ReferenceDirection,
}

/// Direction of references to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReferenceDirection {
    /// Show references TO this address (incoming).
    To,
    /// Show references FROM this address (outgoing).
    From,
}

impl ShowReferencesAction {
    /// Creates a new "show references to" action.
    pub fn show_to() -> Self {
        Self {
            enabled: true,
            menu_path: vec![
                "References".to_string(),
                "Show References To".to_string(),
            ],
            direction: ReferenceDirection::To,
        }
    }

    /// Creates a new "show references from" action.
    pub fn show_from() -> Self {
        Self {
            enabled: true,
            menu_path: vec![
                "References".to_string(),
                "Show References From".to_string(),
            ],
            direction: ReferenceDirection::From,
        }
    }
}

// ============================================================================
// AddReferenceAction
// ============================================================================

/// An action for adding a reference from the listing popup menu.
///
/// This model represents the "Add Memory Reference",
/// "Add Stack Reference", "Add Register Reference" actions.
#[derive(Debug, Clone)]
pub struct AddReferenceAction {
    /// The kind of reference to add.
    pub ref_class: ReferenceClass,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The display name.
    pub name: String,
    /// The menu path.
    pub menu_path: Vec<String>,
    /// Default key binding (virtual key code, 0 for none).
    pub key_code: u32,
}

impl AddReferenceAction {
    /// Creates an "Add Memory Reference" action.
    pub fn memory() -> Self {
        Self {
            ref_class: ReferenceClass::Memory,
            enabled: true,
            name: "Add Memory Reference".to_string(),
            menu_path: vec![
                "References".to_string(),
                "Add Memory Reference...".to_string(),
            ],
            key_code: 0x4D, // VK_M
        }
    }

    /// Creates an "Add Stack Reference" action.
    pub fn stack() -> Self {
        Self {
            ref_class: ReferenceClass::Stack,
            enabled: true,
            name: "Add Stack Reference".to_string(),
            menu_path: vec![
                "References".to_string(),
                "Add Stack Reference...".to_string(),
            ],
            key_code: 0,
        }
    }

    /// Creates an "Add Register Reference" action.
    pub fn register() -> Self {
        Self {
            ref_class: ReferenceClass::Register,
            enabled: true,
            name: "Add Register Reference".to_string(),
            menu_path: vec![
                "References".to_string(),
                "Add Register Reference...".to_string(),
            ],
            key_code: 0,
        }
    }
}

// ============================================================================
// OffsetTableAction
// ============================================================================

/// Action model for the "Create Offset Table" feature.
///
/// Ported from `OffsetTablePlugin.java`.  Takes a selection of data
/// items and creates offset references from a user-supplied base address.
#[derive(Debug, Clone)]
pub struct OffsetTableAction {
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The menu path.
    pub menu_path: Vec<String>,
}

impl OffsetTableAction {
    /// Creates a new offset table action.
    pub fn new() -> Self {
        Self {
            enabled: true,
            menu_path: vec![
                "References".to_string(),
                "Create Offset Table...".to_string(),
            ],
        }
    }
}

impl Default for OffsetTableAction {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delete_all_references_action_new() {
        let action = DeleteAllReferencesAction::new();
        assert!(action.enabled);
        assert!(action.confirmation_message.contains("Delete"));
        assert_eq!(action.menu_path.len(), 2);
    }

    #[test]
    fn test_delete_all_references_action_is_enabled() {
        let action = DeleteAllReferencesAction::new();
        assert!(action.is_enabled_for(true));
        assert!(!action.is_enabled_for(false));
    }

    #[test]
    fn test_delete_all_references_action_build_command() {
        let action = DeleteAllReferencesAction::new();
        let cmd = action.build_command(Address::new(0x1000), 0);
        // Command should have the right address (verify via Display)
        let display = format!("{}", cmd);
        assert!(display.contains("1000"));
    }

    #[test]
    fn test_delete_all_references_action_default() {
        let action = DeleteAllReferencesAction::default();
        assert!(action.enabled);
    }

    #[test]
    fn test_show_references_to() {
        let action = ShowReferencesAction::show_to();
        assert!(action.enabled);
        assert_eq!(action.direction, ReferenceDirection::To);
        assert!(action.menu_path.last().unwrap().contains("To"));
    }

    #[test]
    fn test_show_references_from() {
        let action = ShowReferencesAction::show_from();
        assert!(action.enabled);
        assert_eq!(action.direction, ReferenceDirection::From);
        assert!(action.menu_path.last().unwrap().contains("From"));
    }

    #[test]
    fn test_reference_direction_variants() {
        assert_ne!(ReferenceDirection::To, ReferenceDirection::From);
        assert_eq!(ReferenceDirection::To, ReferenceDirection::To);
    }

    #[test]
    fn test_add_reference_action_memory() {
        let action = AddReferenceAction::memory();
        assert_eq!(action.ref_class, ReferenceClass::Memory);
        assert!(action.enabled);
        assert!(action.name.contains("Memory"));
        assert_eq!(action.key_code, 0x4D);
    }

    #[test]
    fn test_add_reference_action_stack() {
        let action = AddReferenceAction::stack();
        assert_eq!(action.ref_class, ReferenceClass::Stack);
        assert!(action.name.contains("Stack"));
        assert_eq!(action.key_code, 0);
    }

    #[test]
    fn test_add_reference_action_register() {
        let action = AddReferenceAction::register();
        assert_eq!(action.ref_class, ReferenceClass::Register);
        assert!(action.name.contains("Register"));
    }

    #[test]
    fn test_offset_table_action_new() {
        let action = OffsetTableAction::new();
        assert!(action.enabled);
        assert!(action.menu_path.last().unwrap().contains("Offset"));
    }

    #[test]
    fn test_offset_table_action_default() {
        let action = OffsetTableAction::default();
        assert!(action.enabled);
    }

    #[test]
    fn test_add_reference_action_all_classes() {
        let memory = AddReferenceAction::memory();
        let stack = AddReferenceAction::stack();
        let register = AddReferenceAction::register();
        assert_ne!(memory.ref_class, stack.ref_class);
        assert_ne!(memory.ref_class, register.ref_class);
        assert_ne!(stack.ref_class, register.ref_class);
    }

    #[test]
    fn test_reference_direction_serialization() {
        let dir = ReferenceDirection::To;
        let json = serde_json::to_string(&dir).unwrap();
        let deserialized: ReferenceDirection = serde_json::from_str(&json).unwrap();
        assert_eq!(dir, deserialized);
    }

    #[test]
    fn test_show_references_actions_independent() {
        let to_action = ShowReferencesAction::show_to();
        let from_action = ShowReferencesAction::show_from();
        assert_eq!(to_action.direction, ReferenceDirection::To);
        assert_eq!(from_action.direction, ReferenceDirection::From);
    }

    #[test]
    fn test_add_memory_reference_menu_path() {
        let action = AddReferenceAction::memory();
        assert_eq!(action.menu_path[0], "References");
        assert!(action.menu_path[1].contains("Memory"));
    }
}
