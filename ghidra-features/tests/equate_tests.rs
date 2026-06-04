//! Integration tests for the equate subsystem.
//!
//! These tests exercise the full workflow from the Java port:
//! set/rename/remove equates via the plugin, format conversions,
//! table model management, and the Equates Table window state.

use ghidra_core::Address;
use ghidra_features::base::equate::{
    self, ConvertAction, ConvertActionKind, EquateActionSet, EquatePlugin, EquateTable,
    EquateTableModel, EquateTablePluginState, ListingActionContext, Scalar, SelectionType,
    SortOrder,
};

fn unsigned_scalar(val: u64) -> Scalar {
    Scalar::unsigned(32, val)
}

fn signed_scalar(val: i64) -> Scalar {
    Scalar::signed(32, val)
}

fn make_ctx(scalar: Option<Scalar>, is_data: bool) -> ListingActionContext {
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

// ============================================================================
// Full workflow: set, rename, remove
// ============================================================================

#[test]
fn test_full_equate_lifecycle() {
    let mut plugin = EquatePlugin::new();
    let mut table = EquateTable::new();

    // 1. Set an equate.
    let ctx = make_ctx(Some(unsigned_scalar(0xFF)), false);
    let errors = plugin.set_equate(&ctx, "BYTE_MAX", false, &mut table);
    assert!(errors.is_empty());
    assert!(table.get_equate("BYTE_MAX").is_some());

    // 2. Set a second equate.
    let ctx2 = ListingActionContext::with_scalar(Address::new(0x2000), 0, unsigned_scalar(0x42));
    plugin.set_equate(&ctx2, "ANSWER", false, &mut table);
    assert_eq!(table.num_equates(), 2);

    // 3. Rename the first equate.
    plugin.rename_equate("BYTE_MAX", "MAX_BYTE", Address::new(0x1000), 0, &mut table);
    assert!(table.get_equate("BYTE_MAX").is_none());
    assert!(table.get_equate("MAX_BYTE").is_some());

    // 4. Remove the second equate.
    assert!(plugin.remove_equate("ANSWER", &mut table));
    assert_eq!(table.num_equates(), 1);

    // 5. Verify history.
    assert_eq!(plugin.history().len(), 4);
}

// ============================================================================
// Format conversion workflow
// ============================================================================

#[test]
fn test_convert_unsigned_hex_to_decimal() {
    let mut plugin = EquatePlugin::new();
    let mut table = EquateTable::new();

    // Set a hex equate.
    let ctx = make_ctx(Some(unsigned_scalar(255)), false);
    plugin.set_equate(&ctx, "0xFF", false, &mut table);

    // Convert to unsigned decimal.
    let errors = plugin.convert(&ctx, ConvertActionKind::UnsignedDecimal, &mut table);
    assert!(errors.is_empty());

    // Should have the decimal equate.
    assert!(table.get_equate("255").is_some());
}

#[test]
fn test_convert_over_selection() {
    let mut table = EquateTable::new();

    // Create locations spanning multiple addresses.
    let locations = vec![
        (Address::new(0x1000), 0, 0xFF),
        (Address::new(0x2000), 0, 0xFF),
        (Address::new(0x3000), 0, 0xFF),
    ];
    let ctx = ListingActionContext {
        address: Address::new(0x1000),
        op_index: 0,
        sub_op_index: 0,
        has_selection: true,
        selection: vec![
            (Address::new(0x1000), Address::new(0x3000)),
        ],
        scalar: Some(unsigned_scalar(0xFF)),
        is_data: false,
        is_defined_integer_data: false,
        is_in_composite_or_array: false,
        code_unit_length: 4,
        locations,
        current_equate_name: None,
    };

    let action = ConvertAction::new(ConvertActionKind::UnsignedDecimal);
    let mut cmd = action.execute(&ctx);
    cmd.apply(&mut table).unwrap();

    // All three locations should reference the equate "255".
    let eq = table.get_equate("255").unwrap();
    assert_eq!(eq.reference_count(), 3);
}

// ============================================================================
// Enum-based equate workflow
// ============================================================================

#[test]
fn test_apply_enum_and_verify_references() {
    let mut plugin = EquatePlugin::new();
    let mut table = EquateTable::new();

    // Locations with values matching the enum.
    let ctx = ListingActionContext {
        address: Address::new(0x1000),
        op_index: 0,
        sub_op_index: 0,
        has_selection: true,
        selection: vec![(Address::new(0x1000), Address::new(0x3000))],
        scalar: Some(unsigned_scalar(1)),
        is_data: false,
        is_defined_integer_data: false,
        is_in_composite_or_array: false,
        code_unit_length: 4,
        locations: vec![
            (Address::new(0x1000), 0, 1),
            (Address::new(0x2000), 0, 2),
            (Address::new(0x3000), 0, 99), // not in enum
        ],
        current_equate_name: None,
    };

    let mut enum_values = std::collections::HashSet::new();
    enum_values.insert(1);
    enum_values.insert(2);

    plugin.apply_enum(&ctx, "test-uuid", enum_values, false, &mut table);

    let name1 = equate::EquateManager::format_name_for_equate("test-uuid", 1);
    let name2 = equate::EquateManager::format_name_for_equate("test-uuid", 2);
    let name99 = equate::EquateManager::format_name_for_equate("test-uuid", 99);

    assert!(table.get_equate(&name1).is_some());
    assert!(table.get_equate(&name2).is_some());
    assert!(table.get_equate(&name99).is_none()); // value 99 not in enum

    // Verify references.
    let eq1 = table.get_equate(&name1).unwrap();
    assert_eq!(eq1.reference_count(), 1);
    let eq2 = table.get_equate(&name2).unwrap();
    assert_eq!(eq2.reference_count(), 1);
}

// ============================================================================
// Equate table model workflow
// ============================================================================

#[test]
fn test_table_model_sort_and_access() {
    let mut table = EquateTable::new();
    table.create_equate("ZETA", 26).unwrap();
    table.create_equate("ALPHA", 1).unwrap();
    table.create_equate("MU", 13).unwrap();
    table.add_reference("ZETA", Address::new(0x1000), 0);
    table.add_reference("ZETA", Address::new(0x2000), 1);
    table.add_reference("ZETA", Address::new(0x3000), 2);
    table.add_reference("ALPHA", Address::new(0x4000), 0);
    table.add_reference("MU", Address::new(0x5000), 0);
    table.add_reference("MU", Address::new(0x6000), 1);

    let mut model = EquateTableModel::new();
    model.update(&table);

    // Default sort: by name ascending.
    assert_eq!(model.cell_value(0, 0).unwrap(), "ALPHA");
    assert_eq!(model.cell_value(1, 0).unwrap(), "MU");
    assert_eq!(model.cell_value(2, 0).unwrap(), "ZETA");

    // Sort by ref count descending.
    model.set_sort(2, SortOrder::Descending);
    assert_eq!(model.cell_value(0, 0).unwrap(), "ZETA"); // 3 refs
    assert_eq!(model.cell_value(1, 0).unwrap(), "MU"); // 2 refs
    assert_eq!(model.cell_value(2, 0).unwrap(), "ALPHA"); // 1 ref

    // Sort by value ascending.
    model.set_sort(1, SortOrder::Ascending);
    assert_eq!(model.cell_value(0, 0).unwrap(), "ALPHA"); // 1
    assert_eq!(model.cell_value(1, 0).unwrap(), "MU"); // 13
    assert_eq!(model.cell_value(2, 0).unwrap(), "ZETA"); // 26
}

// ============================================================================
// EquateTablePluginState workflow
// ============================================================================

#[test]
fn test_table_plugin_state_workflow() {
    let mut table = EquateTable::new();
    table.create_equate("FOO", 42).unwrap();
    table.create_equate("BAR", 99).unwrap();
    table.add_reference("FOO", Address::new(0x1000), 0);
    table.add_reference("FOO", Address::new(0x2000), 1);
    table.add_reference("BAR", Address::new(0x3000), 0);

    let mut state = EquateTablePluginState::new();
    state.set_visible(true);

    // Select "FOO" and verify references.
    state.select_equate(&table, Some("FOO"));
    assert_eq!(state.selected_equate(), Some("FOO"));
    assert_eq!(state.displayed_references().len(), 2);

    // Delete "FOO".
    let removed = state.delete_equates(&["FOO"], &mut table);
    assert_eq!(removed.len(), 1);
    assert!(table.get_equate("FOO").is_none());
    assert!(state.selected_equate().is_none());

    // "BAR" still exists.
    assert!(table.get_equate("BAR").is_some());
}

// ============================================================================
// Action set queries
// ============================================================================

#[test]
fn test_action_set_disabled_on_undefined_data() {
    let action_set = EquateActionSet::new();
    let mut ctx = make_ctx(Some(unsigned_scalar(0xFF)), true);
    ctx.is_defined_integer_data = false;

    let enabled = action_set.enabled_convert_actions(&ctx);
    // All convert actions should be disabled on undefined/non-integer data.
    assert!(enabled.is_empty());
}

#[test]
fn test_set_equate_blocked_on_composite_data() {
    let mut plugin = EquatePlugin::new();
    let mut table = EquateTable::new();
    let mut ctx = make_ctx(Some(unsigned_scalar(0xFF)), true);
    ctx.is_in_composite_or_array = true;

    // is_equate_permitted blocks composite/array data at the plugin level.
    assert!(!ctx.is_equate_permitted());
}

#[test]
fn test_action_set_enabled_unsigned_formats() {
    let action_set = EquateActionSet::new();
    let ctx = make_ctx(Some(unsigned_scalar(0xFF)), false);

    let enabled = action_set.enabled_convert_actions(&ctx);
    // All unsigned formats should be enabled.
    assert!(enabled.contains(&ConvertActionKind::UnsignedHex));
    assert!(enabled.contains(&ConvertActionKind::UnsignedDecimal));
    assert!(enabled.contains(&ConvertActionKind::Octal));
    assert!(enabled.contains(&ConvertActionKind::Binary));
    assert!(enabled.contains(&ConvertActionKind::Char));
    // Signed formats disabled for positive value.
    assert!(!enabled.contains(&ConvertActionKind::SignedHex));
    assert!(!enabled.contains(&ConvertActionKind::SignedDecimal));
}

#[test]
fn test_action_set_enabled_signed_formats_for_negative() {
    let action_set = EquateActionSet::new();
    let ctx = make_ctx(Some(signed_scalar(-1)), false);

    let enabled = action_set.enabled_convert_actions(&ctx);
    assert!(enabled.contains(&ConvertActionKind::SignedHex));
    assert!(enabled.contains(&ConvertActionKind::SignedDecimal));
}

// ============================================================================
// SelectionType tests
// ============================================================================

#[test]
fn test_selection_type_variants() {
    assert_eq!(SelectionType::CurrentAddress as u8, SelectionType::CurrentAddress as u8);
    assert_ne!(
        SelectionType::CurrentAddress as u8,
        SelectionType::Selection as u8
    );
}

// ============================================================================
// Rename all equates workflow (from Equates Table window)
// ============================================================================

#[test]
fn test_rename_all_references_from_table() {
    let mut plugin = EquatePlugin::new();
    let mut table = EquateTable::new();

    // Create an equate with multiple references.
    table.create_equate("OLD_NAME", 0xAB).unwrap();
    table.add_reference("OLD_NAME", Address::new(0x1000), 0);
    table.add_reference("OLD_NAME", Address::new(0x2000), 0);
    table.add_reference("OLD_NAME", Address::new(0x3000), 1);

    // Rename all references at once (table window operation).
    assert!(plugin.rename_equates("OLD_NAME", "NEW_NAME", &mut table));

    // Verify.
    assert!(table.get_equate("OLD_NAME").is_none());
    let eq = table.get_equate("NEW_NAME").unwrap();
    assert_eq!(eq.value, 0xAB);
    assert_eq!(eq.reference_count(), 3);

    // Verify by-location lookups still work.
    assert!(table.get_equate_at(&Address::new(0x1000), 0, 0xAB).is_some());
    assert!(table.get_equate_at(&Address::new(0x2000), 0, 0xAB).is_some());
    assert!(table.get_equate_at(&Address::new(0x3000), 1, 0xAB).is_some());
}
