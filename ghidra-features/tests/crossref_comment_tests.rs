//! Integration tests for cross-reference and comment management.
//!
//! These tests exercise the full workflow from the Java port:
//! cross-reference queries (direct, offcut, variable, thunk),
//! comment dialog lifecycle, comment history tracking, and action factory.

use ghidra_core::addr::Address;
use ghidra_core::program::listing::CommentType;
use ghidra_core::symbol::{DataRefType, RefType, Reference, ReferenceManager, SourceType, MNEMONIC};
use ghidra_features::base::comments::{
    CommentActionKind, CommentHistoryEntry, CommentHistoryStore, CommentUpdate,
    CommentsPlugin, CommentDeleteRequest,
    create_standard_actions, determine_comment_type, is_comment_allowed,
    popup_label_for_comment_type,
};
use ghidra_features::base::crossrefs::{
    self, CodeUnitXRef, CrossReferenceManager, ThunkReference, XRefDisplayRow,
    ALL_REFS,
};

fn addr(offset: u64) -> Address {
    Address::new(offset)
}

// ==========================================================================
// Cross-reference integration tests
// ==========================================================================

#[test]
fn test_xref_full_workflow() {
    let mut ref_mgr = ReferenceManager::new();

    // Simulate a binary: function at 0x1000 calls 0x2000, reads 0x3000.
    ref_mgr
        .add_reference(Reference::new(
            addr(0x1000),
            addr(0x2000),
            RefType::UNCONDITIONAL_CALL,
            MNEMONIC,
        ))
        .unwrap();
    ref_mgr
        .add_reference(Reference::new(
            addr(0x1004),
            addr(0x3000),
            RefType::Data(DataRefType::Read),
            0,
        ))
        .unwrap();
    ref_mgr
        .add_reference(Reference::new(
            addr(0x1008),
            addr(0x2000),
            RefType::Data(DataRefType::Read),
            1,
        ))
        .unwrap();

    // Query xrefs to 0x2000 (the called function).
    let cu = CodeUnitXRef::single_byte(addr(0x2000));
    let xrefs = crossrefs::get_xref_addresses(&ref_mgr, &cu);
    assert_eq!(xrefs.len(), 2);
    assert_eq!(xrefs[0], addr(0x1000));
    assert_eq!(xrefs[1], addr(0x1008));

    // Query xrefs to 0x3000 (data).
    let cu_data = CodeUnitXRef::single_byte(addr(0x3000));
    let data_xrefs = crossrefs::get_xref_addresses(&ref_mgr, &cu_data);
    assert_eq!(data_xrefs.len(), 1);
    assert_eq!(data_xrefs[0], addr(0x1004));
}

#[test]
fn test_xref_with_thunks() {
    let mut ref_mgr = ReferenceManager::new();
    ref_mgr
        .add_reference(Reference::new(
            addr(0x1000),
            addr(0x2000),
            RefType::UNCONDITIONAL_CALL,
            MNEMONIC,
        ))
        .unwrap();

    // A thunk function at 0x5000 wraps the function at 0x2000.
    let cu = CodeUnitXRef::single_byte(addr(0x2000))
        .with_thunk_entry_points(vec![addr(0x5000)]);

    let xrefs = crossrefs::get_x_references(&ref_mgr, &cu, ALL_REFS);
    assert_eq!(xrefs.len(), 2);

    // First should be the direct call reference.
    assert!(!xrefs[0].is_thunk());
    assert_eq!(*xrefs[0].from_address(), addr(0x1000));

    // Second should be the thunk.
    assert!(xrefs[1].is_thunk());
    assert_eq!(*xrefs[1].from_address(), addr(0x5000));
}

#[test]
fn test_cross_reference_manager_end_to_end() {
    let mut xrm = CrossReferenceManager::default();

    // Build a mini xref graph.
    xrm.add_memory_reference(
        addr(0x100),
        addr(0x200),
        RefType::UNCONDITIONAL_CALL,
        SourceType::Default,
        MNEMONIC,
    );
    xrm.add_memory_reference(
        addr(0x104),
        addr(0x200),
        RefType::Data(DataRefType::Read),
        SourceType::Analysis,
        0,
    );
    xrm.add_memory_reference(
        addr(0x108),
        addr(0x300),
        RefType::Data(DataRefType::Write),
        SourceType::UserDefined,
        1,
    );

    // Verify counts.
    assert_eq!(xrm.get_reference_count_to(&addr(0x200)), 2);
    assert_eq!(xrm.get_reference_count_to(&addr(0x300)), 1);
    assert!(xrm.has_references_to(&addr(0x200)));
    assert!(!xrm.has_references_to(&addr(0x999)));

    // Remove all refs from 0x100.
    xrm.remove_all_references_from(addr(0x100));
    assert_eq!(xrm.get_reference_count_to(&addr(0x200)), 1);

    // Get all xrefs to 0x200.
    let cu = CodeUnitXRef::single_byte(addr(0x200));
    let xrefs = xrm.get_all_xrefs(&cu);
    assert_eq!(xrefs.len(), 1);
    assert_eq!(*xrefs[0].from_address(), addr(0x104));
}

#[test]
fn test_xref_display_rows() {
    let r = Reference::new(
        addr(0x401000),
        addr(0x402000),
        RefType::UNCONDITIONAL_CALL,
        MNEMONIC,
    );
    let row = XRefDisplayRow::from_reference(&r);
    assert_eq!(row.address, addr(0x401000));
    assert_eq!(row.ref_type_label, "Call");

    let t = ThunkReference::new(addr(0x403000), addr(0x402000));
    let trow = XRefDisplayRow::from_thunk(&t);
    assert_eq!(trow.address, addr(0x403000));
    assert_eq!(trow.ref_type_label, "Thunk");
}

#[test]
fn test_variable_xrefs_split() {
    let var_addr = addr(0x50);
    let var = crossrefs::VariableXRef::new(Some(var_addr), 1, "argc");

    let refs = vec![
        Reference::new(addr(0x1000), addr(0x50), RefType::Data(DataRefType::Read), 0),
        Reference::new(addr(0x1100), addr(0x50), RefType::Data(DataRefType::Write), 0),
        Reference::new(addr(0x1200), addr(0x54), RefType::Data(DataRefType::Read), 1), // offcut
    ];

    let (direct, offcut) = crossrefs::get_variable_refs(&ReferenceManager::new(), &var, &refs);
    assert_eq!(direct.len(), 2);
    assert_eq!(offcut.len(), 1);
    assert_eq!(*offcut[0].get_to_address(), addr(0x54));
}

// ==========================================================================
// Comment management integration tests
// ==========================================================================

#[test]
fn test_comment_full_lifecycle() {
    let mut plugin = CommentsPlugin::new("analyst");

    // Open dialog with some existing comments.
    plugin.open_dialog(
        addr(0x401000),
        Some("return 0"),
        None,
        None,
        Some("main() entry"),
        None,
    );

    // Edit the EOL comment and add a pre-comment.
    {
        let dialog = plugin.dialog_mut().unwrap();
        dialog.set_comment_text(CommentType::Eol, "return EXIT_SUCCESS");
        dialog.set_comment_text(CommentType::Pre, "function entry point");
    }

    // Apply.
    let update = plugin.apply_dialog().expect("should have changes");
    assert_eq!(
        update.eol,
        Some("return EXIT_SUCCESS".to_string())
    );
    assert_eq!(
        update.pre,
        Some("function entry point".to_string())
    );
    assert_eq!(update.plate, Some("main() entry".to_string()));

    // Verify history was recorded.
    let eol_hist = plugin
        .history()
        .get_history(&addr(0x401000), CommentType::Eol);
    assert_eq!(eol_hist.len(), 1);
    assert_eq!(eol_hist[0].user_name, "analyst");
    assert_eq!(eol_hist[0].comment_text, "return EXIT_SUCCESS");

    // A second edit.
    plugin.open_dialog(
        addr(0x401000),
        Some("return EXIT_SUCCESS"),
        Some("function entry point"),
        None,
        Some("main() entry"),
        None,
    );
    plugin
        .dialog_mut()
        .unwrap()
        .set_comment_text(CommentType::Eol, "return 0");
    plugin.apply_dialog().unwrap();

    // Now there should be 2 history entries for EOL.
    let eol_hist = plugin
        .history()
        .get_history(&addr(0x401000), CommentType::Eol);
    assert_eq!(eol_hist.len(), 2);
}

#[test]
fn test_comment_cancel_workflow() {
    let mut plugin = CommentsPlugin::new("user1");

    plugin.open_dialog(addr(0x1000), Some("original"), None, None, None, None);
    plugin
        .dialog_mut()
        .unwrap()
        .set_comment_text(CommentType::Eol, "modified");

    // Cancel -- should revert.
    plugin.cancel_dialog();
    assert!(plugin.dialog().is_none());
    // No history recorded.
    assert_eq!(plugin.history().total_entries(), 0);
}

#[test]
fn test_comment_history_store_isolation() {
    let mut store = CommentHistoryStore::new();

    // Record changes at different addresses.
    store.record_change(
        &addr(0x1000),
        CommentType::Eol,
        CommentHistoryEntry::with_timestamp("user1", "2024-01-01 10:00", "addr1 eol v1"),
    );
    store.record_change(
        &addr(0x1000),
        CommentType::Eol,
        CommentHistoryEntry::with_timestamp("user1", "2024-01-02 10:00", "addr1 eol v2"),
    );
    store.record_change(
        &addr(0x1000),
        CommentType::Pre,
        CommentHistoryEntry::with_timestamp("user2", "2024-01-03 10:00", "addr1 pre"),
    );
    store.record_change(
        &addr(0x2000),
        CommentType::Eol,
        CommentHistoryEntry::with_timestamp("user1", "2024-01-04 10:00", "addr2 eol"),
    );

    // Verify isolation.
    assert_eq!(
        store.get_history(&addr(0x1000), CommentType::Eol).len(),
        2
    );
    assert_eq!(
        store.get_history(&addr(0x1000), CommentType::Pre).len(),
        1
    );
    assert_eq!(
        store.get_history(&addr(0x2000), CommentType::Eol).len(),
        1
    );
    assert!(store
        .get_history(&addr(0x2000), CommentType::Pre)
        .is_empty());
    assert_eq!(store.total_entries(), 4);

    // Verify formatted history text.
    let text = store.get_history_text(&addr(0x1000), CommentType::Eol);
    assert!(text.contains("addr1 eol v1"));
    assert!(text.contains("addr1 eol v2"));
    assert!(!text.contains("addr1 pre")); // Should not include Pre comments.
}

#[test]
fn test_comment_update_semantics() {
    // Empty -> None, non-empty -> Some.
    let update = CommentUpdate {
        address: addr(0x1000),
        pre: None,
        post: None,
        eol: Some("text".to_string()),
        plate: None,
        repeatable: Some("".to_string()), // treated as set (Some(""))
    };
    assert!(!update.is_empty());
    assert_eq!(update.changes().len(), 5);

    // All None -> empty.
    let empty_update = CommentUpdate {
        address: addr(0x1000),
        pre: None,
        post: None,
        eol: None,
        plate: None,
        repeatable: None,
    };
    assert!(empty_update.is_empty());
}

#[test]
fn test_comment_action_factory_standard_actions() {
    let actions = create_standard_actions();
    assert_eq!(actions.len(), 8);

    // Verify specific actions.
    let edit = actions.iter().find(|a| a.name == "Edit Comments").unwrap();
    assert_eq!(edit.kind, CommentActionKind::EditComments);
    assert_eq!(edit.menu_path, vec!["Comments", "Set..."]);

    let set_eol = actions
        .iter()
        .find(|a| a.name == "Set EOL Comment")
        .unwrap();
    assert_eq!(
        set_eol.kind,
        CommentActionKind::SetComment(CommentType::Eol)
    );

    let delete = actions.iter().find(|a| a.name == "Delete Comments").unwrap();
    assert_eq!(delete.kind, CommentActionKind::DeleteComment);

    let history = actions
        .iter()
        .find(|a| a.name == "Show Comment History")
        .unwrap();
    assert_eq!(history.kind, CommentActionKind::ShowHistory);
}

#[test]
fn test_comment_type_determination() {
    // On a specific comment field -> use that type.
    assert_eq!(
        determine_comment_type(true, Some(CommentType::Post), false),
        Some(CommentType::Post)
    );

    // At a function entry -> plate.
    assert_eq!(
        determine_comment_type(false, None, true),
        Some(CommentType::Plate)
    );

    // Default -> EOL.
    assert_eq!(
        determine_comment_type(false, None, false),
        Some(CommentType::Eol)
    );
}

#[test]
fn test_comment_allowed_check() {
    assert!(is_comment_allowed(true, false));
    assert!(!is_comment_allowed(true, true)); // variable location
    assert!(!is_comment_allowed(false, false)); // not a code unit
}

#[test]
fn test_popup_labels() {
    assert_eq!(
        popup_label_for_comment_type("Delete", CommentType::Eol),
        "Delete EOL Comment"
    );
    assert_eq!(
        popup_label_for_comment_type("Show History for", CommentType::Plate),
        "Show History for Plate Comment"
    );
    assert_eq!(
        popup_label_for_comment_type("Set", CommentType::Pre),
        "Set Pre-Comment"
    );
    assert_eq!(
        popup_label_for_comment_type("Set", CommentType::Repeatable),
        "Set Repeatable Comment"
    );
}

#[test]
fn test_delete_comment_request() {
    let req = CommentDeleteRequest::new(addr(0x401000), CommentType::Plate);
    assert_eq!(req.address, addr(0x401000));
    assert_eq!(req.comment_type, CommentType::Plate);
}

#[test]
fn test_dialog_model_no_op_apply() {
    let mut plugin = CommentsPlugin::new("user");
    plugin.open_dialog(addr(0x1000), None, None, None, None, None);

    // No changes made.
    let result = plugin.apply_dialog();
    assert!(result.is_none());
}

#[test]
fn test_dialog_model_revert_preserves_original() {
    let mut plugin = CommentsPlugin::new("user");
    plugin.open_dialog(addr(0x1000), Some("v1"), None, None, None, None);

    // Edit and revert multiple times.
    for i in 0..5 {
        plugin
            .dialog_mut()
            .unwrap()
            .set_comment_text(CommentType::Eol, format!("v{}", i + 2));
        plugin.dialog_mut().unwrap().revert();
    }

    // Original should still be there.
    assert_eq!(
        plugin
            .dialog()
            .unwrap()
            .get_comment_text(CommentType::Eol),
        "v1"
    );
}
