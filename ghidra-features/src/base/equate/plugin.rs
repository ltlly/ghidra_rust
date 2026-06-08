//! EquatePlugin -- central orchestrator for equate operations.
//!
//! Ported from `ghidra.app.plugin.core.equate.EquatePlugin` and
//! `ghidra.app.plugin.core.equate.EquateTablePlugin` in Ghidra's
//! Features/Base.
//!
//! This module provides:
//! - [`EquatePlugin`] -- manages the lifecycle of equate actions,
//!   dispatches set/rename/remove/apply-enum operations, and resolves
//!   scalar values from code units and operand locations.
//! - [`EquateTablePluginState`] -- state for the Equates Table window
//!   (displaying all equates and their references).
//! - [`SelectionType`] -- scope for equate operations (single address,
//!   selection, or entire program).

use super::actions::{EquateActionSet, ListingActionContext};
use super::commands::Command;
use super::manager::EquateTable;
use super::Scalar;
use ghidra_core::Address;
use std::collections::HashSet;

// ============================================================================
// SelectionType -- scope for equate operations
// ============================================================================

/// The scope over which an equate operation is applied.
///
/// Corresponds to `SetEquateDialog.SelectionType` in Java.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelectionType {
    /// Apply only at the current address.
    CurrentAddress,
    /// Apply over the current selection.
    Selection,
    /// Apply over the entire program.
    EntireProgram,
}

impl Default for SelectionType {
    fn default() -> Self {
        SelectionType::CurrentAddress
    }
}

// ============================================================================
// EquateInfo -- lightweight info about an equate at a location
// ============================================================================

/// Lightweight info about an equate at a specific (address, op_index) location.
///
/// Used to pass equate information between the plugin and its actions/dialogs
/// without pulling in the full `EquateValue` struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquateInfo {
    /// The equate name.
    pub name: String,
    /// The equate's constant value.
    pub value: i64,
    /// Number of references to this equate.
    pub reference_count: usize,
    /// Whether this equate was created from an enum data type.
    pub is_enum_based: bool,
}

impl EquateInfo {
    /// Create an `EquateInfo` from an `EquateValue`.
    pub fn from_equate(eq: &super::EquateValue) -> Self {
        Self {
            name: eq.name.clone(),
            value: eq.value,
            reference_count: eq.reference_count(),
            is_enum_based: eq.is_enum_based,
        }
    }

    /// The display name (strips enum tags).
    pub fn display_name(&self) -> &str {
        if self.name.starts_with(super::manager::EquateManager::DATATYPE_TAG) {
            &self.name[super::manager::EquateManager::DATATYPE_TAG.len()..]
        } else {
            &self.name
        }
    }
}

impl std::fmt::Display for EquateInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} = 0x{:x}", self.name, self.value)
    }
}

// ============================================================================
// EquatePlugin -- the main equate plugin
// ============================================================================

/// The central equate plugin managing equate CRUD operations.
///
/// This mirrors Ghidra's `EquatePlugin` which handles set, rename, remove,
/// and apply-enum actions on the code listing. In the Rust port this is a
/// headless logic layer (no Swing UI) that orchestrates commands against an
/// [`EquateTable`].
///
/// # Usage
///
/// ```ignore
/// let mut plugin = EquatePlugin::new();
/// plugin.register_actions();
///
/// // Set an equate at a location
/// let ctx = ListingActionContext::with_scalar(addr(0x1000), 0, Scalar::unsigned(32, 0xFF));
/// plugin.set_equate(&ctx, "MY_CONST", false, &mut table);
/// ```
#[derive(Debug, Clone)]
pub struct EquatePlugin {
    /// The set of all equate actions.
    actions: EquateActionSet,
    /// The group name for menu grouping.
    group_name: String,
    /// History of executed command names (for debugging/testing).
    history: Vec<String>,
}

impl EquatePlugin {
    /// The action group name.
    pub const GROUP_NAME: &'static str = "equate";

    /// Create a new equate plugin.
    pub fn new() -> Self {
        Self {
            actions: EquateActionSet::new(),
            group_name: Self::GROUP_NAME.to_string(),
            history: Vec::new(),
        }
    }

    /// Get a reference to the action set.
    pub fn actions(&self) -> &EquateActionSet {
        &self.actions
    }

    /// Get the group name.
    pub fn group_name(&self) -> &str {
        &self.group_name
    }

    /// Get the execution history.
    pub fn history(&self) -> &[String] {
        &self.history
    }

    // -------------------------------------------------------------------
    // Scalar extraction from code units
    // -------------------------------------------------------------------

    /// Extract the scalar value from a code unit at the given operand and
    /// sub-operand indices.
    ///
    /// For data items, the scalar is returned directly. For instructions,
    /// the sub-operand representation list is scanned for a matching scalar.
    ///
    /// This mirrors `EquatePlugin.getScalar(CodeUnit, int, int)` in Java.
    ///
    /// # Parameters
    ///
    /// * `scalar_at_cursor` - The scalar value at the cursor position.
    /// * `op_scalars` - Scalars found in the operand at `op_index`.
    /// * `sub_op_index` - The sub-operand index.
    ///
    /// # Returns
    ///
    /// The matching scalar, or `None` if no match is found.
    pub fn resolve_scalar(
        scalar_at_cursor: &Scalar,
        op_scalars: &[Scalar],
        sub_op_index: i32,
    ) -> Option<Scalar> {
        // Direct match
        for s in op_scalars {
            if s == scalar_at_cursor {
                return Some(*s);
            }
        }

        // Scan forward from sub_op_index
        let start = sub_op_index.max(0) as usize;
        for s in op_scalars.iter().skip(start) {
            if s == scalar_at_cursor {
                return Some(*s);
            }
        }

        // Scan backward from sub_op_index
        if start > 0 {
            for s in op_scalars[..start].iter().rev() {
                if s == scalar_at_cursor {
                    return Some(*s);
                }
            }
        }

        None
    }

    /// Check whether an equate's value matches a scalar.
    ///
    /// Mirrors `EquatePlugin.isEquateEqualScalar()`.
    pub fn is_equate_equal_scalar(equate_value: i64, scalar: &Scalar) -> bool {
        equate_value == scalar.unsigned_value() as i64
            || equate_value == scalar.signed_value()
    }

    // -------------------------------------------------------------------
    // Set Equate
    // -------------------------------------------------------------------

    /// Execute the "Set Equate" operation.
    ///
    /// Creates equates for all locations in `ctx.locations` whose scalar
    /// operand matches the target value.
    ///
    /// # Returns
    ///
    /// A list of status messages (empty on success).
    pub fn set_equate(
        &mut self,
        ctx: &ListingActionContext,
        equate_name: &str,
        overwrite_existing: bool,
        table: &mut EquateTable,
    ) -> Vec<String> {
        self.history
            .push(format!("Set Equate: {}", equate_name));

        let mut cmd = self
            .actions
            .set_action
            .execute(ctx, equate_name, overwrite_existing);
        match cmd.apply(table) {
            Ok(()) => vec![],
            Err(msg) => vec![msg],
        }
    }

    /// Execute the "Set Equate" operation with an enum.
    pub fn set_equate_with_enum(
        &mut self,
        ctx: &ListingActionContext,
        enum_uuid: &str,
        overwrite_existing: bool,
        table: &mut EquateTable,
    ) -> Vec<String> {
        self.history
            .push(format!("Set Equate (enum): {}", enum_uuid));

        let mut cmd = self
            .actions
            .set_action
            .execute_with_enum(ctx, enum_uuid, overwrite_existing);
        match cmd.apply(table) {
            Ok(()) => vec![],
            Err(msg) => vec![msg],
        }
    }

    // -------------------------------------------------------------------
    // Rename Equate
    // -------------------------------------------------------------------

    /// Execute the "Rename Equate" operation at a single location.
    pub fn rename_equate(
        &mut self,
        old_name: &str,
        new_name: &str,
        addr: Address,
        op_index: i32,
        table: &mut EquateTable,
    ) -> Vec<String> {
        self.history.push(format!(
            "Rename Equate: {} -> {} at {:?}[{}]",
            old_name, new_name, addr, op_index
        ));

        let mut cmd = self
            .actions
            .rename_action
            .execute(old_name, new_name, addr, op_index);
        match cmd.apply(table) {
            Ok(()) => vec![],
            Err(msg) => vec![msg],
        }
    }

    /// Rename all references of an equate to a new name.
    ///
    /// Used by the Equate Table window.
    pub fn rename_equates(
        &mut self,
        old_name: &str,
        new_name: &str,
        table: &mut EquateTable,
    ) -> bool {
        // Validate: new name must not already exist with a different value.
        if let Some(existing) = table.get_equate(new_name) {
            if let Some(old_eq) = table.get_equate(old_name) {
                if existing.value != old_eq.value {
                    return false;
                }
            }
        }

        self.history
            .push(format!("Rename Equates: {} -> {}", old_name, new_name));

        let mut cmd = super::commands::RenameEquatesCmd::new(old_name, new_name);
        cmd.apply(table).is_ok()
    }

    // -------------------------------------------------------------------
    // Remove Equate
    // -------------------------------------------------------------------

    /// Execute the "Remove Equate" operation.
    pub fn remove_equate(
        &mut self,
        equate_name: &str,
        table: &mut EquateTable,
    ) -> bool {
        self.history
            .push(format!("Remove Equate: {}", equate_name));

        let mut cmd = self.actions.remove_action.execute(equate_name);
        cmd.apply(table).is_ok()
    }

    /// Remove multiple equates.
    pub fn remove_equates(
        &mut self,
        names: &[&str],
        table: &mut EquateTable,
    ) -> bool {
        self.history
            .push(format!("Remove Equates: {:?}", names));

        let mut cmd = self.actions.remove_action.execute_many(names.to_vec());
        cmd.apply(table).is_ok()
    }

    // -------------------------------------------------------------------
    // Apply Enum
    // -------------------------------------------------------------------

    /// Execute the "Apply Enum" operation over a set of locations.
    pub fn apply_enum(
        &mut self,
        ctx: &ListingActionContext,
        enum_uuid: &str,
        enum_values: HashSet<i64>,
        should_do_on_sub_ops: bool,
        table: &mut EquateTable,
    ) -> Vec<String> {
        self.history
            .push(format!("Apply Enum: {}", enum_uuid));

        let mut cmd = self.actions.apply_enum_action.execute(
            ctx,
            enum_uuid,
            enum_values,
            should_do_on_sub_ops,
        );
        match cmd.apply(table) {
            Ok(()) => vec![],
            Err(msg) => vec![msg],
        }
    }

    // -------------------------------------------------------------------
    // Convert (dispatch)
    // -------------------------------------------------------------------

    /// Execute a convert action.
    pub fn convert(
        &mut self,
        ctx: &ListingActionContext,
        kind: super::actions::ConvertActionKind,
        table: &mut EquateTable,
    ) -> Vec<String> {
        let action = match self.actions.get_convert_action(kind) {
            Some(a) => a,
            None => return vec!["Unknown convert action".to_string()],
        };

        if !action.is_enabled(ctx) {
            return vec!["Action not enabled for this context".to_string()];
        }

        self.history
            .push(format!("Convert: {}", action.name()));

        let mut cmd = action.execute(ctx);
        match cmd.apply(table) {
            Ok(()) => vec![],
            Err(msg) => vec![msg],
        }
    }

    // -------------------------------------------------------------------
    // Get equate info at a location
    // -------------------------------------------------------------------

    /// Get info about the equate at a specific (address, op_index, value).
    pub fn get_equate_at(
        &self,
        table: &EquateTable,
        addr: &Address,
        op_index: i32,
        value: i64,
    ) -> Option<EquateInfo> {
        table
            .get_equate_at(addr, op_index, value)
            .map(EquateInfo::from_equate)
    }

    /// Get all equates at a specific (address, op_index).
    pub fn get_equates_at(
        &self,
        table: &EquateTable,
        addr: &Address,
        op_index: i32,
    ) -> Vec<EquateInfo> {
        table
            .get_equates_at(addr, op_index)
            .iter()
            .map(|eq| EquateInfo::from_equate(eq))
            .collect()
    }

    /// Get all equates in the table.
    pub fn get_all_equates(&self, table: &EquateTable) -> Vec<EquateInfo> {
        table
            .get_all_equates()
            .iter()
            .map(|eq| EquateInfo::from_equate(eq))
            .collect()
    }
}

impl Default for EquatePlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// EquateTablePluginState -- state for the Equates Table window
// ============================================================================

/// State for the Equates Table window.
///
/// Corresponds to `EquateTablePlugin` and `EquateTableProvider` in Java.
/// Manages the display of all equates and their references.
#[derive(Debug, Clone)]
pub struct EquateTablePluginState {
    /// The currently selected equate, if any.
    selected_equate: Option<String>,
    /// The currently displayed references for the selected equate.
    displayed_references: Vec<(Address, i32)>,
    /// Whether the equates table view is visible.
    is_visible: bool,
}

impl EquateTablePluginState {
    /// Create a new state.
    pub fn new() -> Self {
        Self {
            selected_equate: None,
            displayed_references: Vec::new(),
            is_visible: false,
        }
    }

    /// Set the currently selected equate and populate references.
    pub fn select_equate(&mut self, table: &EquateTable, equate_name: Option<&str>) {
        self.selected_equate = equate_name.map(|s| s.to_string());
        self.displayed_references.clear();

        if let Some(name) = equate_name {
            if let Some(eq) = table.get_equate(name) {
                self.displayed_references = eq
                    .references
                    .iter()
                    .map(|r| (r.address, r.op_index))
                    .collect();
            }
        }
    }

    /// Get the selected equate name.
    pub fn selected_equate(&self) -> Option<&str> {
        self.selected_equate.as_deref()
    }

    /// Get the displayed references.
    pub fn displayed_references(&self) -> &[(Address, i32)] {
        &self.displayed_references
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.is_visible = visible;
    }

    /// Whether the view is visible.
    pub fn is_visible(&self) -> bool {
        self.is_visible
    }

    /// Delete the selected equates.
    ///
    /// Returns the names of equates that were removed.
    pub fn delete_equates(
        &mut self,
        names: &[&str],
        table: &mut EquateTable,
    ) -> Vec<String> {
        let mut removed = Vec::new();
        for name in names {
            if table.remove_equate(name) {
                removed.push(name.to_string());
            }
        }
        if removed.contains(&self.selected_equate.clone().unwrap_or_default()) {
            self.selected_equate = None;
            self.displayed_references.clear();
        }
        removed
    }
}

impl Default for EquateTablePluginState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::Scalar;

    fn make_table() -> EquateTable {
        EquateTable::new()
    }

    fn unsigned_scalar(val: u64) -> Scalar {
        Scalar::unsigned(32, val)
    }

    fn make_ctx(scalar: Option<Scalar>, is_data: bool) -> ListingActionContext {
        let s = scalar.unwrap_or_else(|| unsigned_scalar(0));
        let locations = scalar
            .as_ref()
            .map(|s| vec![(Address::new(0x1000), 0, s.value())])
            .unwrap_or_default();
        ListingActionContext {
            address: Address::new(0x1000),
            op_index: 0,
            sub_op_index: 0,
            has_selection: false,
            selection: vec![],
            scalar,
            is_data,
            is_defined_integer_data: is_data,
            is_in_composite_or_array: false,
            code_unit_length: 4,
            locations,
            current_equate_name: None,
        }
    }

    // ---------------------------------------------------------------
    // EquatePlugin tests
    // ---------------------------------------------------------------

    #[test]
    fn test_plugin_creation() {
        let plugin = EquatePlugin::new();
        assert_eq!(plugin.group_name(), "equate");
        assert!(plugin.history().is_empty());
    }

    #[test]
    fn test_plugin_set_equate() {
        let mut plugin = EquatePlugin::new();
        let ctx = make_ctx(Some(unsigned_scalar(0xFF)), false);
        let mut table = make_table();

        let errors = plugin.set_equate(&ctx, "BYTE_MAX", false, &mut table);
        assert!(errors.is_empty());

        let eq = table.get_equate("BYTE_MAX").unwrap();
        assert_eq!(eq.value, 0xFF);
        assert_eq!(eq.reference_count(), 1);
        assert_eq!(plugin.history().len(), 1);
    }

    #[test]
    fn test_plugin_set_equate_overwrite() {
        let mut plugin = EquatePlugin::new();
        let ctx = make_ctx(Some(unsigned_scalar(0xFF)), false);
        let mut table = make_table();

        // First set with one name
        plugin.set_equate(&ctx, "OLD_NAME", false, &mut table);
        assert!(table.get_equate("OLD_NAME").is_some());

        // Overwrite with a new name
        plugin.set_equate(&ctx, "NEW_NAME", true, &mut table);
        let eq = table.get_equate("NEW_NAME").unwrap();
        assert_eq!(eq.value, 0xFF);
    }

    #[test]
    fn test_plugin_set_equate_with_enum() {
        let mut plugin = EquatePlugin::new();
        let ctx = make_ctx(Some(unsigned_scalar(0xFF)), false);
        let mut table = make_table();

        let errors = plugin.set_equate_with_enum(&ctx, "my-uuid", false, &mut table);
        assert!(errors.is_empty());

        let expected_name =
            super::super::manager::EquateManager::format_name_for_equate("my-uuid", 0xFF);
        assert!(table.get_equate(&expected_name).is_some());
    }

    #[test]
    fn test_plugin_rename_equate() {
        let mut plugin = EquatePlugin::new();
        let mut table = make_table();
        table.create_equate("OLD", 10).unwrap();
        table.add_reference("OLD", Address::new(0x1000), 0);

        let errors = plugin.rename_equate("OLD", "NEW", Address::new(0x1000), 0, &mut table);
        assert!(errors.is_empty());
        assert!(table.get_equate("OLD").is_none());
        assert!(table.get_equate("NEW").is_some());
    }

    #[test]
    fn test_plugin_rename_equates() {
        let mut plugin = EquatePlugin::new();
        let mut table = make_table();
        table.create_equate("OLD", 5).unwrap();
        table.add_reference("OLD", Address::new(0x1000), 0);
        table.add_reference("OLD", Address::new(0x2000), 1);

        assert!(plugin.rename_equates("OLD", "NEW", &mut table));
        assert!(table.get_equate("OLD").is_none());
        let eq = table.get_equate("NEW").unwrap();
        assert_eq!(eq.value, 5);
        assert_eq!(eq.reference_count(), 2);
    }

    #[test]
    fn test_plugin_rename_equates_conflict() {
        let mut plugin = EquatePlugin::new();
        let mut table = make_table();
        table.create_equate("A", 1).unwrap();
        table.create_equate("B", 2).unwrap();

        // Should fail: "B" already exists with a different value.
        assert!(!plugin.rename_equates("A", "B", &mut table));
        assert!(table.get_equate("A").is_some());
    }

    #[test]
    fn test_plugin_remove_equate() {
        let mut plugin = EquatePlugin::new();
        let mut table = make_table();
        table.create_equate("MY_CONST", 42).unwrap();

        assert!(plugin.remove_equate("MY_CONST", &mut table));
        assert!(table.get_equate("MY_CONST").is_none());
    }

    #[test]
    fn test_plugin_remove_equates() {
        let mut plugin = EquatePlugin::new();
        let mut table = make_table();
        table.create_equate("A", 1).unwrap();
        table.create_equate("B", 2).unwrap();

        assert!(plugin.remove_equates(&["A", "B"], &mut table));
        assert!(table.is_empty());
    }

    #[test]
    fn test_plugin_apply_enum() {
        let mut plugin = EquatePlugin::new();
        let ctx = make_ctx(Some(unsigned_scalar(1)), false);
        let mut table = make_table();

        let mut enum_values = HashSet::new();
        enum_values.insert(1);
        enum_values.insert(2);

        let errors = plugin.apply_enum(&ctx, "enum-uuid", enum_values, false, &mut table);
        assert!(errors.is_empty());

        let expected =
            super::super::manager::EquateManager::format_name_for_equate("enum-uuid", 1);
        assert!(table.get_equate(&expected).is_some());
    }

    #[test]
    fn test_plugin_convert() {
        let mut plugin = EquatePlugin::new();
        let ctx = make_ctx(Some(unsigned_scalar(255)), false);
        let mut table = make_table();

        let errors = plugin.convert(
            &ctx,
            super::super::actions::ConvertActionKind::UnsignedDecimal,
            &mut table,
        );
        assert!(errors.is_empty());
        assert!(table.get_equate("255").is_some());
    }

    #[test]
    fn test_plugin_convert_disabled() {
        let mut plugin = EquatePlugin::new();
        let ctx = make_ctx(Some(unsigned_scalar(42)), false);
        let mut table = make_table();

        let errors = plugin.convert(
            &ctx,
            super::super::actions::ConvertActionKind::SignedHex,
            &mut table,
        );
        // SignedHex is disabled for positive values.
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_plugin_get_equate_at() {
        let plugin = EquatePlugin::new();
        let mut table = make_table();
        table.create_equate("MY_CONST", 42).unwrap();
        table.add_reference("MY_CONST", Address::new(0x1000), 0);

        let info = plugin.get_equate_at(&table, &Address::new(0x1000), 0, 42);
        assert!(info.is_some());
        assert_eq!(info.unwrap().name, "MY_CONST");
    }

    #[test]
    fn test_plugin_get_equates_at() {
        let plugin = EquatePlugin::new();
        let mut table = make_table();
        table.create_equate("A", 1).unwrap();
        table.create_equate("B", 2).unwrap();
        table.add_reference("A", Address::new(0x1000), 0);
        table.add_reference("B", Address::new(0x1000), 0);

        let infos = plugin.get_equates_at(&table, &Address::new(0x1000), 0);
        assert_eq!(infos.len(), 2);
    }

    #[test]
    fn test_plugin_get_all_equates() {
        let plugin = EquatePlugin::new();
        let mut table = make_table();
        table.create_equate("A", 1).unwrap();
        table.create_equate("B", 2).unwrap();

        let all = plugin.get_all_equates(&table);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_plugin_history() {
        let mut plugin = EquatePlugin::new();
        let ctx = make_ctx(Some(unsigned_scalar(0xFF)), false);
        let mut table = make_table();

        plugin.set_equate(&ctx, "X", false, &mut table);
        plugin.remove_equate("X", &mut table);

        assert_eq!(plugin.history().len(), 2);
        assert!(plugin.history()[0].contains("Set Equate"));
        assert!(plugin.history()[1].contains("Remove Equate"));
    }

    // ---------------------------------------------------------------
    // Scalar resolution tests
    // ---------------------------------------------------------------

    #[test]
    fn test_resolve_scalar_direct_match() {
        let cursor = unsigned_scalar(0xFF);
        let ops = vec![unsigned_scalar(0xFF), unsigned_scalar(0x42)];
        let result = EquatePlugin::resolve_scalar(&cursor, &ops, 0);
        assert!(result.is_some());
        assert_eq!(result.unwrap().unsigned_value(), 0xFF);
    }

    #[test]
    fn test_resolve_scalar_no_match() {
        let cursor = unsigned_scalar(0xFF);
        let ops = vec![unsigned_scalar(0x42)];
        let result = EquatePlugin::resolve_scalar(&cursor, &ops, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_scalar_backward_scan() {
        let cursor = unsigned_scalar(0xFF);
        let ops = vec![unsigned_scalar(0xFF), unsigned_scalar(0x42)];
        // sub_op_index = 1, cursor is at index 0 -- backward scan should find it.
        let result = EquatePlugin::resolve_scalar(&cursor, &ops, 1);
        assert!(result.is_some());
    }

    #[test]
    fn test_is_equate_equal_scalar() {
        let scalar = unsigned_scalar(0xFF);
        assert!(EquatePlugin::is_equate_equal_scalar(0xFF, &scalar));
        assert!(!EquatePlugin::is_equate_equal_scalar(0x42, &scalar));
    }

    #[test]
    fn test_is_equate_equal_scalar_signed() {
        let scalar = Scalar::signed(8, -1);
        // -1 as signed, 0xFF as unsigned
        assert!(EquatePlugin::is_equate_equal_scalar(-1, &scalar));
        assert!(EquatePlugin::is_equate_equal_scalar(0xFF, &scalar));
    }

    // ---------------------------------------------------------------
    // EquateInfo tests
    // ---------------------------------------------------------------

    #[test]
    fn test_equate_info_from_equate() {
        let mut eq = super::super::EquateValue::new("MY_CONST", 42);
        eq.add_reference(Address::new(0x1000), 0);
        let info = EquateInfo::from_equate(&eq);
        assert_eq!(info.name, "MY_CONST");
        assert_eq!(info.value, 42);
        assert_eq!(info.reference_count, 1);
        assert!(!info.is_enum_based);
    }

    #[test]
    fn test_equate_info_display_name() {
        let info = EquateInfo {
            name: "MY_CONST".to_string(),
            value: 42,
            reference_count: 0,
            is_enum_based: false,
        };
        assert_eq!(info.display_name(), "MY_CONST");
    }

    #[test]
    fn test_equate_info_display_name_strips_tag() {
        let info = EquateInfo {
            name: "dt_uuid_ff".to_string(),
            value: 255,
            reference_count: 0,
            is_enum_based: true,
        };
        assert_eq!(info.display_name(), "uuid_ff");
    }

    #[test]
    fn test_equate_info_display() {
        let info = EquateInfo {
            name: "TEST".to_string(),
            value: 0xFF,
            reference_count: 0,
            is_enum_based: false,
        };
        assert_eq!(format!("{}", info), "TEST = 0xff");
    }

    // ---------------------------------------------------------------
    // SelectionType tests
    // ---------------------------------------------------------------

    #[test]
    fn test_selection_type_default() {
        assert_eq!(SelectionType::default(), SelectionType::CurrentAddress);
    }

    #[test]
    fn test_selection_type_equality() {
        assert_eq!(SelectionType::Selection, SelectionType::Selection);
        assert_ne!(SelectionType::Selection, SelectionType::EntireProgram);
    }

    // ---------------------------------------------------------------
    // EquateTablePluginState tests
    // ---------------------------------------------------------------

    #[test]
    fn test_table_plugin_state_creation() {
        let state = EquateTablePluginState::new();
        assert!(state.selected_equate().is_none());
        assert!(state.displayed_references().is_empty());
        assert!(!state.is_visible());
    }

    #[test]
    fn test_table_plugin_state_select_equate() {
        let mut table = make_table();
        table.create_equate("X", 10).unwrap();
        table.add_reference("X", Address::new(0x1000), 0);
        table.add_reference("X", Address::new(0x2000), 1);

        let mut state = EquateTablePluginState::new();
        state.select_equate(&table, Some("X"));

        assert_eq!(state.selected_equate(), Some("X"));
        assert_eq!(state.displayed_references().len(), 2);
    }

    #[test]
    fn test_table_plugin_state_select_none() {
        let mut state = EquateTablePluginState::new();
        let table = make_table();
        state.select_equate(&table, None);
        assert!(state.selected_equate().is_none());
        assert!(state.displayed_references().is_empty());
    }

    #[test]
    fn test_table_plugin_state_visibility() {
        let mut state = EquateTablePluginState::new();
        state.set_visible(true);
        assert!(state.is_visible());
        state.set_visible(false);
        assert!(!state.is_visible());
    }

    #[test]
    fn test_table_plugin_state_delete_equates() {
        let mut table = make_table();
        table.create_equate("A", 1).unwrap();
        table.create_equate("B", 2).unwrap();

        let mut state = EquateTablePluginState::new();
        state.select_equate(&table, Some("A"));

        let removed = state.delete_equates(&["A", "B"], &mut table);
        assert_eq!(removed.len(), 2);
        assert!(table.is_empty());
        assert!(state.selected_equate().is_none());
    }
}
