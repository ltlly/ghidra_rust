//! Integration tests for the remaining Features/Base plugin modules:
//! references, register, function, console, and cross-plugin workflows.
//!
//! These tests exercise the full data models, commands, actions, and
//! cross-module interactions ported from Ghidra's Java source.

use ghidra_core::Address;

// ============================================================================
// References module
// ============================================================================

mod references_tests {
    use super::*;
    use ghidra_features::base::references::{
        AddMemRefCmd, ExternalNameRow, ExternalReferencesProvider,
        OffsetTablePlugin, ParameterConflictException,
        ReferenceClass, ReferenceResult, ReferencesPlugin,
        RefTypeFactory, ReservedNameException,
    };
    use ghidra_core::symbol::{DataRefType, FlowType, RefType, SourceType};

    #[test]
    fn test_ref_type_factory_memory_types() {
        let types = RefTypeFactory::get_memory_ref_types();
        assert!(!types.is_empty());
        assert!(types.contains(&RefType::Flow(FlowType::UnconditionalJump)));
        assert!(types.contains(&RefType::Flow(FlowType::UnconditionalCall)));
        assert!(types.contains(&RefType::Data(DataRefType::Data)));
    }

    #[test]
    fn test_ref_type_factory_stack_types() {
        let types = RefTypeFactory::get_stack_ref_types();
        assert_eq!(types.len(), 3);
    }

    #[test]
    fn test_ref_type_factory_external_types() {
        let types = RefTypeFactory::get_external_ref_types();
        assert!(!types.is_empty());
    }

    #[test]
    fn test_default_memory_ref_type_for_data_unit() {
        let rt = RefTypeFactory::get_default_memory_ref_type(false, false, false);
        assert_eq!(rt, RefType::Data(DataRefType::Data));
    }

    #[test]
    fn test_default_memory_ref_type_for_call() {
        let rt = RefTypeFactory::get_default_memory_ref_type(true, false, true);
        assert_eq!(rt, RefType::Flow(FlowType::UnconditionalCall));
    }

    #[test]
    fn test_default_memory_ref_type_for_computed_jump() {
        let rt = RefTypeFactory::get_default_memory_ref_type(true, true, false);
        assert_eq!(rt, RefType::Flow(FlowType::ComputedJump));
    }

    #[test]
    fn test_allowed_ref_types_routing() {
        let types = RefTypeFactory::get_allowed_ref_types(false, true, false, false, false);
        assert_eq!(types, RefTypeFactory::get_stack_ref_types());

        let types = RefTypeFactory::get_allowed_ref_types(false, false, true, false, false);
        assert_eq!(types, RefTypeFactory::get_data_ref_types());

        let types = RefTypeFactory::get_allowed_ref_types(false, false, false, true, false);
        assert_eq!(types, RefTypeFactory::get_external_ref_types());
    }

    #[test]
    fn test_add_mem_ref_cmd_display() {
        let cmd = AddMemRefCmd::new(
            Address::new(0x1000),
            Address::new(0x2000),
            RefType::Flow(FlowType::UnconditionalJump),
            SourceType::Default,
            0,
            true,
        );
        assert!(format!("{}", cmd).contains("1000"));
        assert!(format!("{}", cmd).contains("2000"));
    }

    #[test]
    fn test_external_name_row_crud() {
        let mut row = ExternalNameRow::new("libc.so.6", Some("/lib/libc.so.6".to_string()));
        assert_eq!(row.name(), "libc.so.6");
        assert_eq!(row.path(), Some("/lib/libc.so.6"));

        row.set_path(Some("/usr/lib/libc.so.6".to_string()));
        assert_eq!(row.path(), Some("/usr/lib/libc.so.6"));

        row.set_name("libc");
        assert_eq!(row.name(), "libc");
    }

    #[test]
    fn test_external_name_row_display() {
        let row = ExternalNameRow::new("libm.so.6", None);
        assert_eq!(format!("{}", row), "libm.so.6");

        let row2 = ExternalNameRow::new("libm.so.6", Some("/lib/libm.so.6".into()));
        assert!(format!("{}", row2).contains("/lib/libm.so.6"));
    }

    #[test]
    fn test_external_references_provider_workflow() {
        let mut provider = ExternalReferencesProvider::new();
        assert_eq!(provider.row_count(), 0);

        let _ = provider.add_library("libc.so.6".to_string());
        let _ = provider.add_library("libm.so.6".to_string());
        assert_eq!(provider.row_count(), 2);

        assert_eq!(provider.find_by_name("libc.so.6"), Some(0));
        assert_eq!(provider.find_by_name("libm.so.6"), Some(1));
        assert_eq!(provider.find_by_name("libfoo"), None);

        provider.remove_library(0).unwrap();
        assert_eq!(provider.row_count(), 1);
        assert_eq!(provider.find_by_name("libm.so.6"), Some(0));
    }

    #[test]
    fn test_references_plugin_state_via_plugin() {
        let plugin = ReferencesPlugin::new();
        let _state = plugin.state();
        // State exists and the plugin is initialized
        assert_eq!(plugin.default_ref_class(), ReferenceClass::Unknown);
    }

    #[test]
    fn test_reference_class_variants() {
        let rc = ReferenceClass::default();
        assert_eq!(rc, ReferenceClass::Unknown);
        assert_ne!(ReferenceClass::Memory, ReferenceClass::Stack);
    }

    #[test]
    fn test_reference_result_variants() {
        let r = ReferenceResult::Success;
        assert_eq!(r, ReferenceResult::Success);
        assert_ne!(r, ReferenceResult::Cancelled);
    }

    #[test]
    fn test_parameter_conflict_exception() {
        let exc = ParameterConflictException::new("name conflict");
        assert!(exc.message().contains("name conflict"));
    }

    #[test]
    fn test_reserved_name_exception() {
        let exc = ReservedNameException::new("reserved", "conflict message");
        assert_eq!(exc.name(), "reserved");
        assert!(exc.message().contains("conflict"));
    }

    #[test]
    fn test_ref_type_factory_default_stack_ref() {
        let rt = RefTypeFactory::get_default_stack_ref_type();
        assert_eq!(rt, RefType::Data(DataRefType::Read));
    }

    #[test]
    fn test_ref_type_factory_default_register_ref() {
        let rt = RefTypeFactory::get_default_register_ref_type();
        assert_eq!(rt, RefType::Data(DataRefType::Write));
    }

    #[test]
    fn test_references_plugin_new() {
        let plugin = ReferencesPlugin::new();
        assert_eq!(plugin.default_ref_class(), ReferenceClass::Unknown);
        assert_eq!(plugin.default_stack_offset(), 0);
    }

    #[test]
    fn test_offset_table_plugin() {
        let mut plugin = OffsetTablePlugin::new();
        plugin.set_last_signed(true);
        assert!(plugin.last_signed());
        plugin.set_last_signed(false);
        assert!(!plugin.last_signed());
    }
}

// ============================================================================
// Register module
// ============================================================================

mod register_tests {
    use super::*;
    use ghidra_features::base::register::{
        RegisterManager, RegisterNode,
        RegisterTree, RegisterValueRange, SetRegisterValueCmd, SortDirection,
    };
    use ghidra_core::program::lang::{Register, RegisterTypeFlags};
    use std::collections::HashSet;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn make_register(name: &str, group: Option<&str>) -> Register {
        Register {
            name: name.to_string(),
            description: String::new(),
            group: group.map(|s| s.to_string()),
            parent: None,
            bit_length: 32,
            address: addr(0),
            num_bytes: 4,
            least_significant_bit: 0,
            big_endian: false,
            type_flags: RegisterTypeFlags::default(),
            aliases: HashSet::new(),
            child_registers: Vec::new(),
            base_register: None,
            least_significant_bit_in_base: 0,
            lane_sizes: 0,
        }
    }

    #[test]
    fn test_register_manager_new() {
        let mgr = RegisterManager::new();
        assert!(mgr.selected_register().is_none());
        assert!(mgr.value_ranges().is_empty());
    }

    #[test]
    fn test_register_manager_select_and_set_program() {
        let regs = vec![
            make_register("EAX", Some("General")),
            make_register("EBX", Some("General")),
            make_register("ECX", Some("General")),
        ];
        let mut mgr = RegisterManager::new();
        mgr.set_program_with_data(&regs, None);
        assert_eq!(mgr.tree().all_registers().len(), 3);

        mgr.select_register("EAX");
        assert_eq!(mgr.selected_register(), Some("EAX"));
    }

    #[test]
    fn test_register_manager_set_program_none_clears() {
        let regs = vec![make_register("RAX", None)];
        let mut mgr = RegisterManager::new();
        mgr.set_program_with_data(&regs, None);
        assert_eq!(mgr.tree().all_registers().len(), 1);

        mgr.set_program(None);
        assert!(mgr.tree().all_registers().is_empty());
    }

    #[test]
    fn test_register_manager_location_tracking() {
        let mut mgr = RegisterManager::new();
        mgr.set_location(Some("RIP"), addr(0x401000));
        assert_eq!(mgr.selected_register(), Some("RIP"));
    }

    #[test]
    fn test_register_manager_include_default_values() {
        let mut mgr = RegisterManager::new();
        assert!(!mgr.include_default_values());
        mgr.set_include_default_values(true, None);
        assert!(mgr.include_default_values());
    }

    #[test]
    fn test_register_value_range_contains() {
        let range = RegisterValueRange::from_range(addr(0x1000), addr(0x1FFF), 42);
        assert!(range.contains(&addr(0x1000)));
        assert!(range.contains(&addr(0x1500)));
        assert!(range.contains(&addr(0x1FFF)));
        assert!(!range.contains(&addr(0x0FFF)));
        assert!(!range.contains(&addr(0x2000)));
    }

    #[test]
    fn test_register_value_range_default() {
        let range = RegisterValueRange::default_range(addr(0x1000), addr(0x1FFF), 0);
        assert!(range.is_default());
        assert_eq!(range.value(), 0);

        let range2 = RegisterValueRange::from_range(addr(0x1000), addr(0x1FFF), 42);
        assert!(!range2.is_default());
    }

    #[test]
    fn test_register_tree_from_registers() {
        let regs = vec![
            make_register("EAX", Some("General")),
            make_register("EBX", Some("General")),
            make_register("ESP", Some("Stack")),
        ];
        let tree = RegisterTree::new(&regs);
        assert_eq!(tree.all_registers().len(), 3);
    }

    #[test]
    fn test_register_node_display_name() {
        let reg = make_register("EAX", Some("General"));
        let node = RegisterNode::new(reg, &[]);
        assert_eq!(node.name(), "EAX");
        assert_eq!(node.bit_length(), 32);
        assert!(node.display_name().contains("EAX"));
        assert!(node.display_name().contains("32"));
    }

    #[test]
    fn test_set_register_value_cmd_new() {
        let cmd = SetRegisterValueCmd::new("EAX", addr(0x1000), addr(0x1FFF), Some(42u64));
        assert_eq!(cmd.register_name(), "EAX");
        assert_eq!(cmd.value(), Some(42));
    }

    #[test]
    fn test_set_register_value_cmd_clear() {
        let cmd = SetRegisterValueCmd::clear("EAX", addr(0x1000), addr(0x1FFF));
        assert_eq!(cmd.register_name(), "EAX");
        assert_eq!(cmd.value(), None);
    }

    #[test]
    fn test_register_manager_build_set_value_command() {
        let mgr = RegisterManager::new();
        let ranges = vec![(addr(0x1000), addr(0x1FFF)), (addr(0x3000), addr(0x3FFF))];
        let cmd = mgr.build_set_value_command("ESP", 0x7FFF0000, &ranges);
        assert_eq!(cmd.len(), 2);
        assert_eq!(cmd.commands()[0].register_name(), "ESP");
        assert_eq!(cmd.commands()[0].value(), Some(0x7FFF0000));
    }

    #[test]
    fn test_register_manager_address_set_for_rows() {
        let mut mgr = RegisterManager::new();
        mgr.set_value_ranges(vec![
            RegisterValueRange::from_range(addr(0x1000), addr(0x1FFF), 1),
            RegisterValueRange::from_range(addr(0x2000), addr(0x2FFF), 2),
            RegisterValueRange::from_range(addr(0x3000), addr(0x3FFF), 3),
        ]);
        let set = mgr.get_address_set_for_rows(&[0, 2]);
        assert_eq!(set.len(), 2);
        assert_eq!(set[0], (addr(0x1000), addr(0x1FFF)));
        assert_eq!(set[1], (addr(0x3000), addr(0x3FFF)));
    }

    #[test]
    fn test_register_values_panel_sort_direction() {
        assert_ne!(SortDirection::Ascending, SortDirection::Descending);
    }
}

// ============================================================================
// Function module
// ============================================================================

mod function_tests {
    use super::*;
    use ghidra_features::base::function::{
        ActionContext, AnalyzeStackRefsAction, DeleteFunctionAction,
        EditFunctionPurgeAction, EditNameAction,
        EditThunkFunctionAction, FunctionPlugin, FunctionTag, FunctionTagManager,
        FunctionTagRowObject, FunctionTagTableModel, KeyBindingData, MenuData,
        RevertThunkFunctionAction, ThunkRelation, VariableCommentAction, VariableDeleteAction,
        detect_thunk_target,
        SetStackDepthChangeAction, RemoveStackDepthChangeAction,
    };

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_thunk_relation_new() {
        let rel = ThunkRelation::new(addr(0x1000), addr(0x2000), false);
        assert_eq!(rel.thunk_entry, addr(0x1000));
        assert_eq!(rel.thunked_entry, addr(0x2000));
        assert!(!rel.is_computed);
    }

    #[test]
    fn test_thunk_relation_self_referencing() {
        let rel = ThunkRelation::new(addr(0x1000), addr(0x1000), false);
        assert!(rel.is_self_referencing());

        let rel2 = ThunkRelation::new(addr(0x1000), addr(0x2000), false);
        assert!(!rel2.is_self_referencing());
    }

    #[test]
    fn test_detect_thunk_target() {
        let instructions = vec![
            (addr(0x1000), "JMP", vec![addr(0x2000)]),
            (addr(0x1004), "NOP", vec![]),
        ];
        let target = detect_thunk_target(&instructions, addr(0x1000));
        assert_eq!(target, Some(addr(0x2000)));
    }

    #[test]
    fn test_detect_thunk_target_call() {
        let instructions = vec![
            (addr(0x1000), "CALL", vec![addr(0x3000)]),
        ];
        let target = detect_thunk_target(&instructions, addr(0x1000));
        assert_eq!(target, Some(addr(0x3000)));
    }

    #[test]
    fn test_detect_thunk_target_no_jump() {
        let instructions = vec![
            (addr(0x1000), "NOP", vec![]),
        ];
        let target = detect_thunk_target(&instructions, addr(0x1000));
        assert_eq!(target, None);
    }

    #[test]
    fn test_function_tag_basic() {
        let mut tag = FunctionTag::new(1, "decompiled");
        assert_eq!(tag.id(), 1);
        assert_eq!(tag.name(), "decompiled");
        assert!(!tag.is_auto_set());

        tag.set_auto_set(true);
        assert!(tag.is_auto_set());
    }

    #[test]
    fn test_function_tag_description() {
        let mut tag = FunctionTag::new(1, "library");
        assert!(tag.description().is_none());

        tag.set_description("Library function");
        assert_eq!(tag.description(), Some("Library function"));
    }

    #[test]
    fn test_function_tag_display() {
        let tag = FunctionTag::new(1, "thunk");
        let s = format!("{}", tag);
        assert!(s.contains("thunk"));
    }

    #[test]
    fn test_function_tag_row_object() {
        let tag = FunctionTag::new(42, "dangerous");
        let row = FunctionTagRowObject::new(0x1000, "func_a", vec![tag]);
        assert_eq!(row.function_address(), 0x1000);
        assert_eq!(row.function_name(), "func_a");
        assert_eq!(row.tags().len(), 1);
    }

    #[test]
    fn test_function_tag_manager_create_and_list() {
        let mut mgr = FunctionTagManager::new();
        let id1 = mgr.create_tag("decompiled");
        let id2 = mgr.create_tag("library");
        let id3 = mgr.create_tag("thunk");

        assert_eq!(mgr.tag_count(), 3);
        assert!(mgr.get_tag(id1).is_some());
        assert!(mgr.get_tag(id2).is_some());
        assert!(mgr.get_tag(id3).is_some());
    }

    #[test]
    fn test_function_tag_manager_delete() {
        let mut mgr = FunctionTagManager::new();
        let id = mgr.create_tag("temp");
        assert!(mgr.get_tag(id).is_some());

        mgr.delete_tag(id);
        assert!(mgr.get_tag(id).is_none());
    }

    #[test]
    fn test_function_tag_manager_function_assignment() {
        let mut mgr = FunctionTagManager::new();
        let tag_id = mgr.create_tag("analyzed");
        mgr.add_tag_to_function(0x1000, tag_id);
        mgr.add_tag_to_function(0x2000, tag_id);

        let tags = mgr.tags_for_function(0x1000);
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].name(), "analyzed");
        assert_eq!(mgr.tagged_function_count(), 2);
    }

    #[test]
    fn test_function_tag_table_model() {
        let mut model = FunctionTagTableModel::new();
        model.add_row(FunctionTagRowObject::new(0x1000, "main", vec![
            FunctionTag::new(1, "tag_a"),
        ]));
        model.add_row(FunctionTagRowObject::new(0x2000, "helper", vec![
            FunctionTag::new(2, "tag_b"),
        ]));

        assert_eq!(model.row_count(), 2);
        let name = model.get_value_at(0, 0);
        assert!(name.is_some());
    }

    #[test]
    fn test_delete_function_action() {
        let action = DeleteFunctionAction::new();
        assert!(!action.name.is_empty());
    }

    #[test]
    fn test_edit_name_action() {
        let action = EditNameAction::new_for_function();
        assert!(action.name.contains("Name") || action.name.contains("Edit"));
    }

    #[test]
    fn test_thunk_actions() {
        let edit = EditThunkFunctionAction::new();
        assert!(edit.name.contains("Thunk"));

        let revert = RevertThunkFunctionAction::new();
        assert!(!revert.name.is_empty());
    }

    #[test]
    fn test_stack_actions() {
        let analyze = AnalyzeStackRefsAction::new();
        assert!(analyze.enabled);
        assert!(analyze.create_locals);
        assert!(analyze.create_params);

        let purge = EditFunctionPurgeAction::new();
        assert!(purge.enabled);

        let set_depth = SetStackDepthChangeAction::new();
        assert!(set_depth.enabled);

        let remove_depth = RemoveStackDepthChangeAction::new();
        assert!(remove_depth.enabled);
    }

    #[test]
    fn test_variable_actions() {
        let comment = VariableCommentAction::new();
        assert!(!comment.name.is_empty());

        let delete = VariableDeleteAction::new();
        assert!(!delete.name.is_empty());
    }

    #[test]
    fn test_action_context_listing() {
        let ctx = ActionContext::listing_at(addr(0x1000));
        match &ctx {
            ActionContext::Listing(lc) => {
                assert_eq!(lc.address, Some(addr(0x1000)));
                assert!(!lc.has_selection);
            }
            _ => panic!("Expected Listing context"),
        }
    }

    #[test]
    fn test_action_context_selection() {
        let ctx = ActionContext::listing_selection(addr(0x1000), addr(0x1FFF));
        assert!(ctx.has_selection());
    }

    #[test]
    fn test_function_plugin_new() {
        let plugin = FunctionPlugin::new();
        assert_eq!(plugin.name(), "FunctionPlugin");
    }

    #[test]
    fn test_menu_data() {
        let menu = MenuData::new(
            vec!["Edit".into(), "Rename".into()],
            "Edit",
            "function",
        );
        assert_eq!(menu.menu_path.len(), 2);
        assert_eq!(menu.menu_path[0], "Edit");
        assert_eq!(menu.menu_path[1], "Rename");
    }

    #[test]
    fn test_key_binding_data() {
        let kb = KeyBindingData::new(78, 0);
        assert_eq!(kb.key_code, 78);
    }
}

// ============================================================================
// Console module
// ============================================================================

mod console_tests {
    
    use ghidra_features::base::console::{
        CodeCompletion, ConsoleComponentProvider, ConsolePlugin, ConsoleService, ConsoleWord,
    };

    #[test]
    fn test_console_component_provider_basic() {
        let mut console = ConsoleComponentProvider::new("TestConsole");
        assert_eq!(console.name(), "TestConsole");

        ConsoleService::add_message(&mut console, "script", "Hello, world!");
        ConsoleService::add_message(&mut console, "script", "Line 2");

        let text = console.text();
        assert!(text.contains("Hello, world!"));
        assert!(text.contains("Line 2"));
    }

    #[test]
    fn test_console_component_provider_error_messages() {
        let mut console = ConsoleComponentProvider::new("TestConsole");
        ConsoleService::add_error_message(&mut console, "script", "Error occurred");
        ConsoleService::add_message(&mut console, "script", "Normal message");

        let text = console.text();
        assert!(text.contains("Error occurred"));
        assert!(text.contains("Normal message"));
    }

    #[test]
    fn test_console_component_provider_clear() {
        let mut console = ConsoleComponentProvider::new("TestConsole");
        ConsoleService::add_message(&mut console, "script", "Before clear");
        ConsoleService::clear_messages(&mut console);
        assert!(console.text().is_empty());
    }

    #[test]
    fn test_console_component_provider_find() {
        let mut console = ConsoleComponentProvider::new("TestConsole");
        ConsoleService::add_message(&mut console, "script", "The quick brown fox jumps over the lazy dog");
        ConsoleService::add_message(&mut console, "script", "Another line with fox");

        let results = console.find_all("fox");
        assert!(results.len() >= 2);
    }

    #[test]
    fn test_console_component_provider_text_length() {
        let mut console = ConsoleComponentProvider::new("TestConsole");
        ConsoleService::add_message(&mut console, "script", "abc");
        assert!(console.text_len() > 0);
        assert_eq!(console.get_text_length(), console.text_len());
    }

    #[test]
    fn test_console_word_extraction() {
        let word = ConsoleWord::new("0x1000", 0, 6);
        assert_eq!(word.word, "0x1000");
        assert_eq!(word.start_position, 0);
        assert_eq!(word.end_position, 6);
    }

    #[test]
    fn test_console_word_display() {
        let word = ConsoleWord::new("test", 10, 14);
        assert_eq!(format!("{}", word), "test(10,14)");
    }

    #[test]
    fn test_code_completion_basic() {
        let cc = CodeCompletion::new("getProgram", Some("getProgram"));
        assert_eq!(cc.description(), "getProgram");
        assert!(cc.is_valid());
    }

    #[test]
    fn test_code_completion_no_insertion() {
        let cc = CodeCompletion::new("desc", None::<&str>);
        assert_eq!(cc.description(), "desc");
        assert!(cc.insertion().is_none());
    }

    #[test]
    fn test_console_plugin_lifecycle() {
        let mut plugin = ConsolePlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");

        plugin.init();
        assert!(plugin.is_initialized());

        plugin.program_activated("test_program");
        ConsoleService::add_message(plugin.provider_mut(), "script", "Analysis started");
        ConsoleService::add_error_message(plugin.provider_mut(), "script", "Some error");

        let text = plugin.provider().text();
        assert!(text.contains("Analysis started"));
        assert!(text.contains("Some error"));

        plugin.program_deactivated("test_program");
        plugin.dispose();
    }

    #[test]
    fn test_console_plugin_state() {
        let mut plugin = ConsolePlugin::new("StateTest");
        plugin.init();
        assert!(plugin.is_initialized());
    }

    #[test]
    fn test_console_service_trait() {
        let mut console = ConsoleComponentProvider::new("ServiceTest");

        ConsoleService::add_message(&mut console, "test", "via trait");
        ConsoleService::add_error_message(&mut console, "test", "error via trait");

        let text = console.text();
        assert!(text.contains("via trait"));
        assert!(text.contains("error via trait"));
    }

    #[test]
    fn test_console_plugin_program_switch() {
        let mut plugin = ConsolePlugin::new("SwitchTest");
        plugin.init();

        plugin.program_activated("prog_a");
        plugin.program_activated("prog_b");

        assert_eq!(plugin.current_program(), Some("prog_b"));

        plugin.program_deactivated("prog_b");
        plugin.dispose();
    }

    #[test]
    fn test_console_partial_message() {
        let mut console = ConsoleComponentProvider::new("PartialTest");
        ConsoleService::print(&mut console, "Hello");
        ConsoleService::print(&mut console, " ");
        ConsoleService::println(&mut console, "World");

        let text = console.text();
        assert!(text.contains("Hello World"));
    }

    #[test]
    fn test_console_word_at_offset() {
        let mut console = ConsoleComponentProvider::new("WordTest");
        ConsoleService::add_message(&mut console, "script", "at 0x401000 there is a call");

        let word = console.word_at_offset(10);
        assert!(word.is_some());
    }
}

// ============================================================================
// Cross-plugin integration tests
// ============================================================================

mod cross_plugin_tests {
    use super::*;
    use ghidra_features::base::equate::{
        EquatePlugin, EquateTable, ListingActionContext, Scalar,
    };
    use ghidra_features::base::references::RefTypeFactory;
    use ghidra_features::base::register::{RegisterManager, RegisterValueRange};
    use ghidra_features::base::function::{
        FunctionTagManager, ThunkRelation,
    };
    use ghidra_features::base::console::{ConsolePlugin, ConsoleService};

    #[test]
    fn test_equate_with_register_workflow() {
        let mut equate_table = EquateTable::new();
        let mut equate_plugin = EquatePlugin::new();

        let scalar = Scalar::unsigned(32, 0x8048000);
        let ctx = ListingActionContext::with_scalar(Address::new(0x1000), 0, scalar);
        equate_plugin.set_equate(&ctx, "TEXT_BASE", false, &mut equate_table);

        assert!(equate_table.get_equate("TEXT_BASE").is_some());

        let mut reg_mgr = RegisterManager::new();
        reg_mgr.set_value_ranges(vec![
            RegisterValueRange::from_range(Address::new(0x1000), Address::new(0x1FFF), 0x8048000),
        ]);

        let eq = equate_table.get_equate("TEXT_BASE").unwrap();
        assert_eq!(eq.references[0].address, Address::new(0x1000));
        assert!(reg_mgr.value_ranges()[0].contains(&Address::new(0x1000)));
    }

    #[test]
    fn test_function_thunk_with_reference_types() {
        let thunk = ThunkRelation::new(Address::new(0x1000), Address::new(0x2000), false);

        let ref_type = RefTypeFactory::get_default_memory_ref_type(true, false, false);
        assert_eq!(
            ref_type,
            ghidra_core::symbol::RefType::Flow(ghidra_core::symbol::FlowType::UnconditionalJump)
        );

        assert_eq!(thunk.thunked_entry, Address::new(0x2000));
    }

    #[test]
    fn test_function_tags_with_console_output() {
        let mut tag_mgr = FunctionTagManager::new();
        tag_mgr.create_tag("decompiled");
        tag_mgr.create_tag("analyzed");

        let mut console = ConsolePlugin::new("TagConsole");
        console.init();

        for tag in tag_mgr.all_tags() {
            ConsoleService::add_message(console.provider_mut(), "tag_mgr", &format!("Tag: {}", tag.name()));
        }

        let text = console.provider().text();
        assert!(text.contains("decompiled"));
        assert!(text.contains("analyzed"));

        console.dispose();
    }

    #[test]
    fn test_ref_types_for_computed_thunk() {
        let thunk = ThunkRelation::new(Address::new(0x1000), Address::new(0x2000), true);
        assert!(thunk.is_computed);

        let ref_type = RefTypeFactory::get_default_memory_ref_type(true, true, true);
        assert_eq!(
            ref_type,
            ghidra_core::symbol::RefType::Flow(ghidra_core::symbol::FlowType::ComputedCall)
        );
    }

    #[test]
    fn test_equate_register_console_integration() {
        let mut table = EquateTable::new();
        let mut plugin = EquatePlugin::new();

        // Create equates for multiple constants
        let ctx1 = ListingActionContext::with_scalar(Address::new(0x1000), 0, Scalar::unsigned(8, 0xFF));
        plugin.set_equate(&ctx1, "MAX_BYTE", false, &mut table);

        let ctx2 = ListingActionContext::with_scalar(Address::new(0x2000), 0, Scalar::unsigned(16, 0xFFFF));
        plugin.set_equate(&ctx2, "MAX_WORD", false, &mut table);

        assert_eq!(table.num_equates(), 2);

        // Log to console
        let mut console = ConsolePlugin::new("EquateConsole");
        console.init();
        ConsoleService::add_message(
            console.provider_mut(),
            "analysis",
            &format!("Created {} equates", table.num_equates()),
        );
        assert!(console.provider().text().contains("Created 2 equates"));
        console.dispose();
    }
}
