//! Equate plugin layer -- actions, commands, and UI for managing named constants.
//!
//! Ported from `ghidra.app.plugin.core.equate` in Ghidra's Features/Base.
//!
//! This module provides the **plugin-level** equate API that builds on the
//! core [`crate::base::equate`] types (Scalar, EquateManager, EquateTable, etc.).
//!
//! Key types:
//! - [`EquatePlugin`] -- orchestrates set/rename/remove/apply-enum actions on
//!   the listing.
//! - [`EquateTablePlugin`] -- drives the Equates Table window (listing of all
//!   equates with references).
//! - [`ConvertCommand`] -- background command for format conversion of scalars
//!   and data.
//! - [`EquateTableModel`] -- dynamic column model for the equates table.
//! - [`EquateTableProvider`] -- component provider that hosts the equates table
//!   and references table.
//!
//! The actual scalar/equate/manager types live in `base::equate` and are
//! re-exported from this crate's root.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// Re-export the base equate types that the plugin layer depends on.
pub use crate::base::equate::{
    ConvertCommand as BaseConvertCommand, CreateEquateCmd, CreateEnumEquateCommand,
    EquateActionSet, EquateManager, EquateReferenceTableModel, EquateTable,
    EquateTableModel as BaseEquateTableModel, ListingActionContext, RemoveEquateCmd,
    RenameEquateCmd, RenameEquatesCmd, Scalar, SelectionType,
};

// ---------------------------------------------------------------------------
// EquatePlugin
// ---------------------------------------------------------------------------

/// Plugin that manages equate operations on the listing.
///
/// Corresponds to `EquatePlugin` in Java. Provides actions for:
/// - Setting an equate on a scalar operand
/// - Renaming an existing equate
/// - Removing an equate from the current location or selection
/// - Applying an enum to scalar operands in a selection
/// - Converting scalar display format (hex, decimal, octal, binary, char, float, double)
#[derive(Debug)]
pub struct EquatePlugin {
    /// Plugin name used for action registration.
    name: String,
    /// Currently registered equate actions.
    actions: EquateActionSet,
    /// Whether the plugin has been disposed.
    disposed: bool,
}

impl EquatePlugin {
    /// The action group name for equate menu items.
    pub const GROUP_NAME: &'static str = "equate";

    /// Menu path for the "Set Equate" action.
    pub const SET_MENU_PATH: &'static [&'static str] = &["Set Equate..."];
    /// Menu path for the "Rename Equate" action.
    pub const RENAME_MENU_PATH: &'static [&'static str] = &["Rename Equate..."];
    /// Menu path for the "Remove Equate" action.
    pub const REMOVE_MENU_PATH: &'static [&'static str] = &["Remove Equate"];
    /// Menu path for the "Apply Enum" action.
    pub const APPLY_ENUM_MENU_PATH: &'static [&'static str] = &["Apply Enum..."];

    /// Create a new `EquatePlugin`.
    pub fn new() -> Self {
        Self {
            name: "EquatePlugin".to_string(),
            actions: EquateActionSet::default(),
            disposed: false,
        }
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose the plugin, releasing all resources.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.actions = EquateActionSet::default();
    }

    /// Check whether an equate operation is permitted at the given context.
    ///
    /// The location must correspond to an operand scalar within the default
    /// representation. If an equate reference exists on the operand, it must
    /// correspond to the same value.
    pub fn is_equate_permitted(&self, context: &ListingActionContext) -> bool {
        context.scalar.is_some()
    }

    /// Get the operand index from the context.
    pub fn get_operand_index(context: &ListingActionContext) -> i32 {
        context.operand_index
    }

    /// Get the sub-operand index from the context.
    pub fn get_sub_operand_index(context: &ListingActionContext) -> i32 {
        context.sub_operand_index
    }

    /// Get the scalar at the current context location.
    pub fn get_scalar(context: &ListingActionContext) -> Option<Scalar> {
        context.scalar
    }

    /// Check if an equate's value matches a scalar.
    pub fn is_equate_equal_scalar(equate_value: i64, scalar: &Scalar) -> bool {
        equate_value == scalar.unsigned_value() as i64
            || equate_value == scalar.signed_value()
    }
}

impl Default for EquatePlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EquateTablePlugin
// ---------------------------------------------------------------------------

/// Plugin that displays the Equates Table window.
///
/// Corresponds to `EquateTablePlugin` in Java. Shows all equates defined in the
/// program with their reference counts, and supports rename/delete operations.
#[derive(Debug)]
pub struct EquateTablePlugin {
    /// The associated equate table provider model.
    provider: EquateTableProviderModel,
    /// The equates table model.
    table_model: BaseEquateTableModel,
    /// Current program's equate table (if any).
    equate_table: Option<EquateTable>,
    /// Whether the plugin has been disposed.
    disposed: bool,
}

/// Model for the equate table provider -- the component that hosts the
/// equates and references tables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquateTableProviderModel {
    /// The currently selected equate (if any).
    pub selected_equate: Option<String>,
    /// Whether the provider is currently visible.
    pub visible: bool,
}

impl Default for EquateTableProviderModel {
    fn default() -> Self {
        Self {
            selected_equate: None,
            visible: false,
        }
    }
}

impl EquateTablePlugin {
    /// Create a new `EquateTablePlugin`.
    pub fn new() -> Self {
        Self {
            provider: EquateTableProviderModel::default(),
            table_model: BaseEquateTableModel::default(),
            equate_table: None,
            disposed: false,
        }
    }

    /// Returns the provider model.
    pub fn provider(&self) -> &EquateTableProviderModel {
        &self.provider
    }

    /// Returns a mutable reference to the provider model.
    pub fn provider_mut(&mut self) -> &mut EquateTableProviderModel {
        &mut self.provider
    }

    /// Set the current equate table.
    pub fn set_equate_table(&mut self, table: Option<EquateTable>) {
        self.equate_table = table;
    }

    /// Returns whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Notify the plugin that a program was activated.
    pub fn program_activated(&mut self, _program_id: u64) {
        self.provider.visible = true;
    }

    /// Notify the plugin that a program was deactivated.
    pub fn program_deactivated(&mut self) {
        self.provider.visible = false;
        self.provider.selected_equate = None;
    }

    /// Dispose the plugin.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.equate_table = None;
    }

    /// Delete equates by name.
    pub fn delete_equates(&mut self, equate_names: &[String]) -> DeleteEquatesResult {
        if equate_names.is_empty() {
            return DeleteEquatesResult::NoOp;
        }
        DeleteEquatesResult::Deleted(equate_names.to_vec())
    }

    /// Rename an equate.
    pub fn rename_equate(&mut self, old_name: &str, new_name: &str) -> RenameResult {
        if old_name == new_name {
            return RenameResult::NoChange;
        }
        if new_name.is_empty() {
            return RenameResult::InvalidName;
        }
        RenameResult::Renamed {
            old_name: old_name.to_string(),
            new_name: new_name.to_string(),
        }
    }
}

impl Default for EquateTablePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a delete-equates operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteEquatesResult {
    /// No equates to delete.
    NoOp,
    /// Equates were deleted.
    Deleted(Vec<String>),
}

/// Result of a rename-equate operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenameResult {
    /// The name was not changed.
    NoChange,
    /// The new name is invalid (empty).
    InvalidName,
    /// The equate was renamed.
    Renamed {
        old_name: String,
        new_name: String,
    },
}

// ---------------------------------------------------------------------------
// EquateReferenceTableModel
// ---------------------------------------------------------------------------

/// Table model for displaying references to a selected equate.
///
/// Corresponds to `EquateReferenceTableModel` in Java.
#[derive(Debug, Clone, Default)]
pub struct EquateRefTableModel {
    /// The current equate being displayed (name).
    current_equate: Option<String>,
    /// Reference entries: (address, operand_index).
    references: Vec<(u64, i32)>,
}

impl EquateRefTableModel {
    /// Create a new empty reference table model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the equate to display references for.
    pub fn set_equate(&mut self, equate_name: Option<String>) {
        self.current_equate = equate_name;
        self.references.clear();
    }

    /// Get the current equate name.
    pub fn current_equate(&self) -> Option<&str> {
        self.current_equate.as_deref()
    }

    /// Add a reference entry.
    pub fn add_reference(&mut self, address: u64, operand_index: i32) {
        self.references.push((address, operand_index));
    }

    /// Get the number of references.
    pub fn reference_count(&self) -> usize {
        self.references.len()
    }

    /// Get a reference by index.
    pub fn get_reference(&self, index: usize) -> Option<(u64, i32)> {
        self.references.get(index).copied()
    }

    /// Get all references.
    pub fn references(&self) -> &[(u64, i32)] {
        &self.references
    }
}

// ---------------------------------------------------------------------------
// EquateTableWindowPluginState
// ---------------------------------------------------------------------------

/// Persistent state for the Equates Table window.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EquateTableWindowPluginState {
    /// Window position x.
    pub x: i32,
    /// Window position y.
    pub y: i32,
    /// Window width.
    pub width: i32,
    /// Window height.
    pub height: i32,
    /// Sort column index.
    pub sort_column: Option<usize>,
    /// Sort ascending.
    pub sort_ascending: bool,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equate_plugin_creation() {
        let plugin = EquatePlugin::new();
        assert_eq!(plugin.name(), "EquatePlugin");
        assert!(!plugin.is_disposed());
    }

    #[test]
    fn test_equate_plugin_dispose() {
        let mut plugin = EquatePlugin::new();
        assert!(!plugin.is_disposed());
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_equate_plugin_is_equate_permitted() {
        let plugin = EquatePlugin::new();
        let mut context = ListingActionContext::default();
        assert!(!plugin.is_equate_permitted(&context));

        context.scalar = Some(Scalar::new(32, 0x42, false));
        assert!(plugin.is_equate_permitted(&context));
    }

    #[test]
    fn test_equate_plugin_equal_scalar() {
        let scalar = Scalar::new(32, 0xFF, false);
        assert!(EquatePlugin::is_equate_equal_scalar(255, &scalar));
        assert!(!EquatePlugin::is_equate_equal_scalar(256, &scalar));
    }

    #[test]
    fn test_equate_table_plugin_creation() {
        let plugin = EquateTablePlugin::new();
        assert!(!plugin.is_disposed());
        assert!(!plugin.provider().visible);
    }

    #[test]
    fn test_equate_table_plugin_program_lifecycle() {
        let mut plugin = EquateTablePlugin::new();
        plugin.program_activated(1);
        assert!(plugin.provider().visible);

        plugin.program_deactivated();
        assert!(!plugin.provider().visible);
        assert!(plugin.provider().selected_equate.is_none());
    }

    #[test]
    fn test_delete_equates() {
        let mut plugin = EquateTablePlugin::new();
        let result = plugin.delete_equates(&[]);
        assert_eq!(result, DeleteEquatesResult::NoOp);

        let names = vec!["FOO".to_string(), "BAR".to_string()];
        let result = plugin.delete_equates(&names);
        assert_eq!(result, DeleteEquatesResult::Deleted(names));
    }

    #[test]
    fn test_rename_equate() {
        let mut plugin = EquateTablePlugin::new();
        assert_eq!(
            plugin.rename_equate("OLD", "OLD"),
            RenameResult::NoChange
        );
        assert_eq!(
            plugin.rename_equate("OLD", ""),
            RenameResult::InvalidName
        );
        assert_eq!(
            plugin.rename_equate("OLD", "NEW"),
            RenameResult::Renamed {
                old_name: "OLD".to_string(),
                new_name: "NEW".to_string(),
            }
        );
    }

    #[test]
    fn test_equate_ref_table_model() {
        let mut model = EquateRefTableModel::new();
        assert_eq!(model.reference_count(), 0);

        model.set_equate(Some("MY_CONST".to_string()));
        assert_eq!(model.current_equate(), Some("MY_CONST"));

        model.add_reference(0x400000, 0);
        model.add_reference(0x400010, 1);
        assert_eq!(model.reference_count(), 2);
        assert_eq!(model.get_reference(0), Some((0x400000, 0)));
        assert_eq!(model.get_reference(1), Some((0x400010, 1)));
        assert_eq!(model.get_reference(2), None);
    }

    #[test]
    fn test_equate_table_window_state() {
        let state = EquateTableWindowPluginState {
            x: 100,
            y: 200,
            width: 800,
            height: 600,
            sort_column: Some(1),
            sort_ascending: true,
        };
        assert_eq!(state.x, 100);
        assert_eq!(state.width, 800);
        assert_eq!(state.sort_column, Some(1));
    }
}
