//! Comprehensive integration tests for the four remaining Features/Base
//! plugin modules: console, function, references, and register.
//!
//! These tests exercise edge cases, full data model workflows, and
//! cross-module interactions, using only verified public APIs.

use ghidra_core::Address;

fn addr(offset: u64) -> Address {
    Address::new(offset)
}

// ============================================================================
// Console module
// ============================================================================

mod console_tests {
    
    use ghidra_features::base::console::{
        CodeCompletion, ConsoleComponentProvider, ConsolePlugin, ConsoleService, ConsoleWord,
    };

    #[test]
    fn test_console_multiple_origins() {
        let mut console = ConsoleComponentProvider::new("MultiOrigin");
        ConsoleService::add_message(&mut console, "script", "from script");
        ConsoleService::add_message(&mut console, "analysis", "from analysis");
        ConsoleService::add_error_message(&mut console, "compiler", "compile error");

        let text = console.text();
        assert!(text.contains("from script"));
        assert!(text.contains("from analysis"));
        assert!(text.contains("compile error"));
    }

    #[test]
    fn test_console_exception_display() {
        let mut console = ConsoleComponentProvider::new("ExcTest");
        ConsoleService::add_exception(&mut console, "script", "NullPointerException at line 42");
        // add_exception may store exceptions separately from main text
        // Verify the call succeeds without panic
        let _ = console.text();
    }

    #[test]
    fn test_console_stdout_stderr() {
        let console = ConsoleComponentProvider::new("WriterTest");
        let mut stdout = ConsoleService::get_stdout(&console);
        use std::io::Write;
        write!(stdout, "stdout output").unwrap();
        stdout.flush().unwrap();

        let mut stderr = ConsoleService::get_stderr(&console);
        write!(stderr, "stderr output").unwrap();
        stderr.flush().unwrap();
    }

    #[test]
    fn test_console_scroll_lock() {
        let mut console = ConsoleComponentProvider::new("ScrollTest");
        assert!(!console.is_scroll_locked());
        console.set_scroll_lock(true);
        assert!(console.is_scroll_locked());
        console.set_scroll_lock(false);
        assert!(!console.is_scroll_locked());
    }

    #[test]
    fn test_console_visibility() {
        let mut console = ConsoleComponentProvider::new("VisTest");
        console.set_visible(true);
        assert!(console.is_visible());
        console.set_visible(false);
        assert!(!console.is_visible());
    }

    #[test]
    fn test_console_word_at_cursor() {
        let mut console = ConsoleComponentProvider::new("CursorTest");
        ConsoleService::add_message(&mut console, "s", "mov eax, 0x401000");
        let w = console.word_at_offset(0);
        assert!(w.is_some());
    }

    #[test]
    fn test_console_word_display_format() {
        let w = ConsoleWord::new("0xDEADBEEF", 10, 20);
        assert_eq!(w.word, "0xDEADBEEF");
        assert_eq!(w.start_position, 10);
        assert_eq!(w.end_position, 20);
        let s = format!("{}", w);
        assert!(s.contains("0xDEADBEEF"));
    }

    #[test]
    fn test_console_code_completion_variants() {
        let cc1 = CodeCompletion::new("getAddressFactory", Some("getAddressFactory"));
        assert!(cc1.is_valid());
        assert_eq!(cc1.insertion(), Some("getAddressFactory"));

        let cc2 = CodeCompletion::new("description only", None::<&str>);
        assert!(cc2.insertion().is_none());
    }

    #[test]
    fn test_console_find_no_results() {
        let mut console = ConsoleComponentProvider::new("FindEmpty");
        ConsoleService::add_message(&mut console, "s", "hello world");
        let results = console.find_all("xyz");
        assert!(results.is_empty());
    }

    #[test]
    fn test_console_find_multiple() {
        let mut console = ConsoleComponentProvider::new("FindMulti");
        ConsoleService::add_message(&mut console, "s", "abcabcabc");
        let results = console.find_all("abc");
        assert!(results.len() >= 3);
    }

    #[test]
    fn test_console_plugin_info() {
        let plugin = ConsolePlugin::new("InfoTest");
        let info = plugin.info();
        assert_eq!(info.package_name, "Core");
        assert_eq!(info.category, "Common");
        assert_eq!(info.short_description, "I/O Console");
    }

    #[test]
    fn test_console_plugin_provider_ref() {
        let mut plugin = ConsolePlugin::new("RefTest");
        plugin.init();
        let _ = plugin.provider().name();
        plugin.dispose();
    }

    #[test]
    fn test_console_empty_and_long_messages() {
        let mut console = ConsoleComponentProvider::new("EdgeCases");
        ConsoleService::add_message(&mut console, "s", "");
        let _ = console.text();

        let long_msg = "A".repeat(10000);
        ConsoleService::add_message(&mut console, "s", &long_msg);
        let text = console.text();
        assert!(text.len() >= 10000);
    }

    #[test]
    fn test_console_partial_print_workflow() {
        let mut console = ConsoleComponentProvider::new("Partial");
        ConsoleService::print(&mut console, "Hello");
        ConsoleService::print(&mut console, " ");
        ConsoleService::println(&mut console, "World");
        let text = console.text();
        assert!(text.contains("Hello World"));
    }

    #[test]
    fn test_console_plugin_state_transitions() {
        let mut plugin = ConsolePlugin::new("StateTest");
        assert!(!plugin.is_initialized());
        plugin.init();
        assert!(plugin.is_initialized());
        plugin.program_activated("prog_a");
        assert_eq!(plugin.current_program(), Some("prog_a"));
        plugin.program_deactivated("prog_a");
        assert!(plugin.current_program().is_none());
        plugin.dispose();
        assert!(!plugin.is_initialized());
    }

    #[test]
    fn test_console_print_error_messages() {
        let mut console = ConsoleComponentProvider::new("ErrorTest");
        ConsoleService::print_error(&mut console, "error part ");
        ConsoleService::println_error(&mut console, "error end");
        let text = console.text();
        assert!(text.contains("error part") || text.contains("error end"));
    }

    #[test]
    fn test_console_clear_preserves_name() {
        let mut console = ConsoleComponentProvider::new("ClearTest");
        ConsoleService::add_message(&mut console, "s", "before");
        ConsoleService::clear_messages(&mut console);
        assert_eq!(console.name(), "ClearTest");
    }

    #[test]
    fn test_console_get_text_range() {
        let mut console = ConsoleComponentProvider::new("RangeTest");
        ConsoleService::add_message(&mut console, "s", "abcdefghij");
        let len = ConsoleService::get_text_length(&console);
        assert!(len > 0);
        let chunk = ConsoleService::get_text(&console, 0, 3);
        assert!(chunk.is_some());
    }
}

// ============================================================================
// Function module
// ============================================================================

mod function_tests {
    use super::*;
    use ghidra_features::base::function::{
        ActionContext, CreateFunctionAction, CreateMultipleFunctionsAction,
        DeleteFunctionAction, EditNameAction, FunctionPlugin,
        FunctionTag, FunctionTagManager, FunctionTagRowObject,
        FunctionTagTableModel, KeyBindingData, MenuData,
        SetStackDepthChangeAction, RemoveStackDepthChangeAction,
        StackDepthManager, ThunkRelation, detect_thunk_target,
    };
    use ghidra_features::base::function::stack_depth::{
        StackDepthChangeKind as SDKind,
        StackDepthChangeEvent as SDEvent,
    };
    use ghidra_features::base::function::variable_comment::{
        VariableCommentModel as VCModel,
        VariableCommentType as VCType,
    };
    use ghidra_features::base::function::editor::*;

    // -- StackDepth --

    #[test]
    fn test_stack_depth_change_event() {
        let event = SDEvent {
            address: addr(0x401000),
            kind: SDKind::Added,
            delta: 8,
            previous_delta: None,
        };
        assert_eq!(event.kind, SDKind::Added);
        assert_eq!(event.delta, 8);
    }

    #[test]
    fn test_stack_depth_kind_display() {
        assert_eq!(format!("{}", SDKind::Added), "Added");
        assert_eq!(format!("{}", SDKind::Modified), "Modified");
        assert_eq!(format!("{}", SDKind::Removed), "Removed");
    }

    #[test]
    fn test_stack_depth_manager_lifecycle() {
        let mut mgr = StackDepthManager::new();
        assert!(mgr.is_empty());

        let old = mgr.set_change(&addr(0x1000), 4);
        assert!(old.is_none());
        let old = mgr.set_change(&addr(0x2000), -8);
        assert!(old.is_none());
        assert_eq!(mgr.len(), 2);

        let c = mgr.get_change(&addr(0x1000));
        assert_eq!(c, Some(4));
        assert!(mgr.has_change(&addr(0x1000)));

        let removed = mgr.remove_change(&addr(0x1000));
        assert_eq!(removed, Some(4));
        assert!(mgr.get_change(&addr(0x1000)).is_none());
    }

    #[test]
    fn test_stack_depth_compute() {
        let mut mgr = StackDepthManager::new();
        mgr.set_change(&addr(0x1000), 8);
        let depth = mgr.compute_depth_at(&addr(0x1000), 0);
        assert_eq!(depth, 8);
    }

    #[test]
    fn test_stack_depth_all_changes() {
        let mut mgr = StackDepthManager::new();
        mgr.set_change(&addr(0x1000), 4);
        mgr.set_change(&addr(0x2000), -8);
        let changes = mgr.all_changes();
        assert_eq!(changes.len(), 2);
    }

    #[test]
    fn test_stack_depth_actions() {
        let set = SetStackDepthChangeAction::new();
        assert!(set.enabled);

        let remove = RemoveStackDepthChangeAction::new();
        assert!(remove.enabled);
    }

    // -- VariableComment --

    #[test]
    fn test_variable_comment_model() {
        let mut model = VCModel::with_variables(
            addr(0x1000),
            vec![("buf".into(), Some("".into()))],
        );
        assert_eq!(model.variable_count(), 1);
        assert!(!model.has_changes());

        model.set_comment("buf", "input buffer");
        assert_eq!(model.get_comment("buf"), Some("input buffer"));
        assert!(model.has_changes());
    }

    #[test]
    fn test_variable_comment_type_display() {
        assert_eq!(format!("{}", VCType::General), "General");
    }

    #[test]
    fn test_variable_comment_with_variables() {
        let mut model = VCModel::with_variables(
            addr(0x1000),
            vec![
                ("buf".into(), Some("input buffer".into())),
                ("len".into(), None),
            ],
        );
        assert_eq!(model.variable_count(), 2);
        assert_eq!(model.variable_name(0), Some("buf"));
        assert_eq!(model.get_comment("buf"), Some("input buffer"));

        model.set_comment("len", "1024");
        assert!(model.get_comment("len").is_some());
        assert!(model.has_changes());
    }

    #[test]
    fn test_variable_comment_update() {
        let model = VCModel::new(addr(0x1000));
        let update = model.build_update();
        assert!(update.is_empty());
    }

    // -- FunctionPlugin --

    #[test]
    fn test_function_plugin_new() {
        let mut plugin = FunctionPlugin::new();
        assert_eq!(plugin.name(), "FunctionPlugin");
        plugin.create_actions();
        assert!(plugin.action_count() > 0);
    }

    #[test]
    fn test_function_plugin_favorites() {
        let mut plugin = FunctionPlugin::new();
        assert_eq!(plugin.favorites_count(), 0);
        plugin.add_favorite("decompiled".to_string());
        plugin.add_favorite("library".to_string());
        assert_eq!(plugin.favorites_count(), 2);
        let removed = plugin.remove_favorite("decompiled");
        assert!(removed);
        assert_eq!(plugin.favorites_count(), 1);
    }

    #[test]
    fn test_create_function_action() {
        let action = CreateFunctionAction::new("Create Function", false, false);
        assert!(!action.name.is_empty());
        assert!(action.enabled);
    }

    #[test]
    fn test_create_multiple_functions_action() {
        let action = CreateMultipleFunctionsAction::new();
        assert!(!action.name.is_empty());
    }

    #[test]
    fn test_delete_function_action_context() {
        let action = DeleteFunctionAction::new();
        let ctx = ActionContext::listing_at(addr(0x1000));
        let _ = action.is_enabled_for_context(&ctx);
    }

    #[test]
    fn test_edit_name_action_variants() {
        let f = EditNameAction::new_for_function();
        let v = EditNameAction::new_for_variable();
        assert!(!f.name.is_empty());
        assert!(!v.name.is_empty());
    }

    // -- ThunkRelation --

    #[test]
    fn test_thunk_relation_computed() {
        let rel = ThunkRelation::new(addr(0x1000), addr(0x2000), true);
        assert!(rel.is_computed);
        assert!(!rel.is_self_referencing());
    }

    #[test]
    fn test_detect_thunk_target_branch() {
        let instructions = vec![(addr(0x1000), "JMP", vec![addr(0x3000)])];
        assert_eq!(detect_thunk_target(&instructions, addr(0x1000)), Some(addr(0x3000)));
    }

    #[test]
    fn test_detect_thunk_target_none() {
        let instructions = vec![(addr(0x1000), "NOP", vec![])];
        assert_eq!(detect_thunk_target(&instructions, addr(0x1000)), None);
    }

    // -- ActionContext --

    #[test]
    fn test_action_context_variants() {
        let listing = ActionContext::listing_at(addr(0x1000));
        assert!(!listing.has_selection());
        assert_eq!(listing.address(), Some(addr(0x1000)));

        let sel = ActionContext::listing_selection(addr(0x1000), addr(0x10FF));
        assert!(sel.has_selection());
    }

    // -- KeyBindingData / MenuData --

    #[test]
    fn test_key_binding_data() {
        let kb = KeyBindingData::new(0x4E, 2);
        let kb2 = kb.clone();
        assert_eq!(kb.key_code, kb2.key_code);
    }

    #[test]
    fn test_menu_data() {
        let menu = MenuData::new(
            vec!["Edit".into(), "Function".into(), "Rename".into()],
            "Edit",
            "function",
        );
        assert_eq!(menu.menu_path.len(), 3);
    }

    // -- FunctionEditorModel --

    #[test]
    fn test_editor_model_full_workflow() {
        let fd = FunctionData::new("main", "int", "__cdecl");
        let mut model = FunctionEditorModel::new(fd);
        assert!(!model.has_changes());

        model.set_name("main2");
        model.set_return_type("void");
        model.set_calling_convention("__stdcall");
        model.set_inline(true);
        model.set_no_return(true);
        assert!(model.has_changes());

        model.reset();
        assert!(!model.has_changes());
        assert_eq!(model.name(), "main");
    }

    #[test]
    fn test_editor_model_parameters() {
        let mut fd = FunctionData::new("func", "void", "__cdecl");
        fd.add_parameter(FunctionVariableData::parameter(
            Some("buf".into()), 0, "void *", VarnodeInfo::register("RDI", 8),
        ));
        fd.add_parameter(FunctionVariableData::auto_parameter(
            1, "long", VarnodeInfo::register("RSI", 8),
        ));

        let mut model = FunctionEditorModel::new(fd);
        assert_eq!(model.parameters().len(), 2);
        model.remove_parameter(0);
        assert_eq!(model.parameters().len(), 1);
    }

    // -- VarnodeInfo --

    #[test]
    fn test_varnode_info_display() {
        assert!(VarnodeInfo::register("RAX", 8).to_string().contains("Register"));
        assert!(VarnodeInfo::stack(-16, 4).to_string().contains("Stack"));
        assert!(VarnodeInfo::memory(0x401000, 2).to_string().contains("0x401000"));
    }

    #[test]
    fn test_varnode_type_display() {
        assert_eq!(VarnodeType::Register.to_string(), "Register");
        assert_eq!(VarnodeType::Stack.to_string(), "Stack");
        assert_eq!(VarnodeType::Memory.to_string(), "Memory");
    }

    // -- ParamInfo --

    #[test]
    fn test_param_info_forced_indirect() {
        let mut p = ParamInfo::new("hidden", "void *", VarnodeInfo::register("RDI", 8), 0);
        assert!(!p.is_forced_indirect());
        p.set_forced_indirect(true);
        assert!(p.is_forced_indirect());
    }

    #[test]
    fn test_param_info_storage_conflict() {
        let mut p = ParamInfo::new("x", "int", VarnodeInfo::register("RDI", 4), 0);
        p.set_has_storage_conflict(true);
        assert!(p.has_storage_conflict());
    }

    #[test]
    fn test_param_info_set_storage() {
        let mut p = ParamInfo::new("x", "int", VarnodeInfo::register("RDI", 4), 0);
        assert!(!p.is_custom_storage());
        p.set_storage(VarnodeInfo::stack(0, 4));
        assert!(p.is_custom_storage());
    }

    // -- StorageAddressModel --

    #[test]
    fn test_storage_address_model() {
        let mut model = StorageAddressModel::new(8);
        assert_eq!(model.required_size(), 8);
        assert!(!model.is_unconstrained());

        model.add_varnode(VarnodeInfo::register("RAX", 8));
        assert_eq!(model.varnode_count(), 1);

        let unconstrained = StorageAddressModel::new(0);
        assert!(unconstrained.is_unconstrained());
    }

    // -- ParameterTableModel --

    #[test]
    fn test_parameter_table_model_values() {
        let mut model = ParameterTableModel::new(true);
        model.add_parameter(ParamInfo::new("buf", "void *", VarnodeInfo::register("RDI", 8), 0));
        assert_eq!(model.len(), 1);
        assert_eq!(model.get_value_at(0, 1), Some("buf".into()));
    }

    // -- FunctionData --

    #[test]
    fn test_function_data_varargs_and_purge() {
        let mut fd = FunctionData::new("printf", "int", "__cdecl");
        fd.set_has_var_args(true);
        assert!(fd.has_var_args());
        fd.set_stack_purge_size(Some(8));
        assert_eq!(fd.stack_purge_size(), Some(8));
    }

    // -- FunctionVariableData --

    #[test]
    fn test_function_variable_data_setters() {
        let mut var = FunctionVariableData::parameter(
            Some("x".into()), 0, "int", VarnodeInfo::register("RDI", 4),
        );
        var.set_name(Some("y".into()));
        assert_eq!(var.name(), Some("y"));
        var.set_data_type("long");
        assert_eq!(var.data_type_name(), "long");
        var.set_storage(VarnodeInfo::stack(0, 8));
        assert!(var.is_custom_storage());
    }

    // -- Function tags --

    #[test]
    fn test_function_tag_manager_workflow() {
        let mut mgr = FunctionTagManager::new();
        let id1 = mgr.create_tag("decompiled");
        let id2 = mgr.create_tag("library");
        assert_eq!(mgr.tag_count(), 2);

        mgr.add_tag_to_function(0x1000, id1);
        mgr.add_tag_to_function(0x1000, id2);
        assert_eq!(mgr.tags_for_function(0x1000).len(), 2);

        mgr.delete_tag(id2);
        assert_eq!(mgr.tag_count(), 1);
    }

    #[test]
    fn test_function_tag_table_model() {
        let mut model = FunctionTagTableModel::new();
        model.add_row(FunctionTagRowObject::new(0x1000, "main", vec![
            FunctionTag::new(1, "tag_a"),
        ]));
        assert_eq!(model.row_count(), 1);
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
        assert!(row.has_tag(42));
        assert!(!row.has_tag(43));
    }

    #[test]
    fn test_function_tag_row_tag_names_display() {
        let row = FunctionTagRowObject::new(0x1000, "func", vec![
            FunctionTag::new(1, "a"),
            FunctionTag::new(2, "b"),
        ]);
        assert_eq!(row.tag_names_display(), "a, b");
    }
}

// ============================================================================
// References module
// ============================================================================

mod references_tests {
    use super::*;
    use ghidra_features::base::references::{
        AddMemRefCmd, AddOffsetMemRefCmd, AddStackRefCmd,
        DeleteAllReferencesAction, EditReferenceDialog, EditPanelType,
        EditReferencesModel, ExternalNameRow, ExternalReferencesProvider,
        InstructionOperandInfo, OffsetTablePlugin,
        ParameterConflictException, RefTypeFactory,
        ReferenceClass, ReferenceResult,
        ReferencesPlugin, ReferencesPluginState, ReservedNameException,
        SUBMENU_NAME, REFS_GROUP, SHOW_REFS_GROUP,
        EditReferencesProviderModel,
    };
    use ghidra_core::symbol::{DataRefType, FlowType, RefType, SourceType};

    // -- RefTypeFactory --

    #[test]
    fn test_ref_type_factory_all_categories() {
        assert!(!RefTypeFactory::get_memory_ref_types().is_empty());
        assert!(!RefTypeFactory::get_stack_ref_types().is_empty());
        assert!(!RefTypeFactory::get_external_ref_types().is_empty());
        assert!(!RefTypeFactory::get_data_ref_types().is_empty());
    }

    #[test]
    fn test_ref_type_factory_default_types() {
        assert_eq!(RefTypeFactory::get_default_stack_ref_type(), RefType::Data(DataRefType::Read));
        assert_eq!(RefTypeFactory::get_default_register_ref_type(), RefType::Data(DataRefType::Write));
        assert_eq!(
            RefTypeFactory::get_default_memory_ref_type(false, false, false),
            RefType::Data(DataRefType::Data)
        );
        assert_eq!(
            RefTypeFactory::get_default_memory_ref_type(true, false, true),
            RefType::Flow(FlowType::UnconditionalCall)
        );
        assert_eq!(
            RefTypeFactory::get_default_memory_ref_type(true, false, false),
            RefType::Flow(FlowType::UnconditionalJump)
        );
        assert_eq!(
            RefTypeFactory::get_default_memory_ref_type(true, true, false),
            RefType::Flow(FlowType::ComputedJump)
        );
        assert_eq!(
            RefTypeFactory::get_default_memory_ref_type(true, true, true),
            RefType::Flow(FlowType::ComputedCall)
        );
    }

    // -- Commands --

    #[test]
    fn test_add_mem_ref_cmd() {
        let cmd = AddMemRefCmd::new(
            addr(0x1000), addr(0x2000),
            RefType::Flow(FlowType::UnconditionalCall),
            SourceType::Default, 0, true,
        );
        let s = format!("{}", cmd);
        assert!(s.contains("1000") || s.contains("Memory"));
    }

    #[test]
    fn test_add_offset_mem_ref_cmd() {
        let cmd = AddOffsetMemRefCmd::new(
            addr(0x1000), addr(0x2000), false,
            RefType::Data(DataRefType::Data),
            SourceType::UserDefined, 0, 0x100,
        );
        assert!(format!("{}", cmd).contains("1000") || format!("{}", cmd).contains("Offset"));
    }

    #[test]
    fn test_add_stack_ref_cmd() {
        let cmd = AddStackRefCmd::new(
            addr(0x1000), 0, 8,
            RefType::Data(DataRefType::Read),
            SourceType::Default,
        );
        assert!(format!("{}", cmd).contains("1000") || format!("{}", cmd).contains("Stack"));
    }

    // -- EditReferenceDialog --

    #[test]
    fn test_edit_reference_dialog_lifecycle() {
        let mut dialog = EditReferenceDialog::new(addr(0x1000), addr(0x2000), 0);
        assert!(!dialog.is_confirmed());
        assert!(!dialog.is_modified());

        dialog.set_ref_type(RefType::Data(DataRefType::Read));
        assert!(dialog.is_modified());

        dialog.confirm();
        assert!(dialog.is_confirmed());
    }

    #[test]
    fn test_edit_panel_type_names() {
        assert_eq!(EditPanelType::Memory.name(), "MEM");
        assert_eq!(EditPanelType::Stack.name(), "STACK");
        assert_eq!(EditPanelType::Register.name(), "REG");
        assert_eq!(EditPanelType::External.name(), "EXT");
    }

    // -- EditReferencesModel --

    #[test]
    fn test_edit_references_model_basics() {
        let model = EditReferencesModel::new();
        assert_eq!(model.row_count(), 0);
    }

    // -- ExternalReferencesProvider --

    #[test]
    fn test_external_references_provider() {
        let mut provider = ExternalReferencesProvider::new();
        assert_eq!(provider.row_count(), 0);

        let _ = provider.add_library("libc.so.6".to_string());
        let _ = provider.add_library("libm.so.6".to_string());
        assert_eq!(provider.row_count(), 2);

        assert_eq!(provider.find_by_name("libc.so.6"), Some(0));
        assert_eq!(provider.find_by_name("libfoo"), None);

        provider.remove_library(0).unwrap();
        assert_eq!(provider.row_count(), 1);
    }

    #[test]
    fn test_external_name_row() {
        let row = ExternalNameRow::new("libc", Some("/lib/libc.so".into()));
        assert_eq!(row.name(), "libc");
        assert_eq!(row.path(), Some("/lib/libc.so"));

        let row2 = ExternalNameRow::new("libfoo", None);
        assert_eq!(row2.path(), None);
    }

    // -- ReferencesPlugin --

    #[test]
    fn test_references_plugin_lifecycle() {
        let plugin = ReferencesPlugin::new();
        assert_eq!(plugin.default_ref_class(), ReferenceClass::Unknown);
        assert_eq!(plugin.default_stack_offset(), 0);
        assert!(plugin.default_mem_addr().is_none());
        assert!(plugin.default_reg_addr().is_none());
        assert!(plugin.current_instr_info().is_none());
    }

    #[test]
    fn test_references_plugin_state_serialization() {
        let state = ReferencesPluginState::default();
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: ReferencesPluginState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.default_follow_on_location, false);
    }

    #[test]
    fn test_references_plugin_state_setting() {
        let mut plugin = ReferencesPlugin::new();
        let mut state = ReferencesPluginState::default();
        state.default_follow_on_location = true;
        plugin.set_state(state);
        assert!(plugin.state().default_follow_on_location);
    }

    // -- Constants --

    #[test]
    fn test_reference_constants() {
        assert_eq!(SUBMENU_NAME, "References");
        assert_eq!(REFS_GROUP, "references");
        assert_eq!(SHOW_REFS_GROUP, "ShowReferences");
    }

    // -- Action types --

    #[test]
    fn test_delete_all_references_action() {
        let action = DeleteAllReferencesAction::new();
        assert!(action.enabled);
        assert!(action.confirmation_message.contains("Delete"));
        assert!(action.is_enabled_for(true));
        assert!(!action.is_enabled_for(false));
    }

    // -- OffsetTablePlugin --

    #[test]
    fn test_offset_table_plugin() {
        let mut plugin = OffsetTablePlugin::new();
        plugin.set_last_signed(true);
        assert!(plugin.last_signed());
        plugin.set_last_signed(false);
        assert!(!plugin.last_signed());
    }

    // -- InstructionOperandInfo --

    #[test]
    fn test_instruction_operand_info() {
        let mut info = InstructionOperandInfo::new(addr(0x1000), "MOV", 2);
        assert_eq!(info.selected_operand_index(), -1);
        assert_eq!(info.selected_sub_operand_index(), -1);

        info.set_selected(0, 0);
        assert_eq!(info.selected_operand_index(), 0);
    }

    // -- Exception types --

    #[test]
    fn test_parameter_conflict_exception() {
        let exc = ParameterConflictException::new("name conflict");
        assert!(exc.message().contains("name conflict"));
    }

    #[test]
    fn test_reserved_name_exception() {
        let exc = ReservedNameException::new("reserved", "conflict");
        assert_eq!(exc.name(), "reserved");
        assert!(exc.message().contains("conflict"));
    }

    // -- ReferenceClass --

    #[test]
    fn test_reference_class_serialization() {
        let rc = ReferenceClass::Register;
        let json = serde_json::to_string(&rc).unwrap();
        let deserialized: ReferenceClass = serde_json::from_str(&json).unwrap();
        assert_eq!(rc, deserialized);
    }

    // -- ReferenceResult --

    #[test]
    fn test_reference_result_variants() {
        assert_ne!(ReferenceResult::Success, ReferenceResult::Cancelled);
        assert_ne!(
            ReferenceResult::Error("a".into()),
            ReferenceResult::Error("b".into())
        );
    }

    // -- EditReferencesProviderModel --

    #[test]
    fn test_edit_references_provider_model() {
        let model = EditReferencesProviderModel::new();
        assert_eq!(model.code_unit_address(), None);
        assert_eq!(model.program_name(), None);
    }
}

// ============================================================================
// Register module
// ============================================================================

mod register_tests {
    use super::*;
    use ghidra_features::base::register::{
        RegisterDialogError, RegisterDialogMode, RegisterManager,
        RegisterNode, RegisterPluginAction, RegisterPluginModel,
        RegisterActionType, RegisterTransitionInfo,
        RegisterTree, RegisterValueDialogModel, RegisterValueRange,
        RegisterValuesPanel, SetRegisterValueCmd, SortDirection,
    };
    use ghidra_core::program::lang::{Register, RegisterTypeFlags};
    use ghidra_features::base::function::actions::ActionContext;
    use std::collections::HashSet;

    fn make_reg(name: &str, bits: u32, group: &str) -> Register {
        Register {
            name: name.to_string(),
            description: String::new(),
            group: Some(group.to_string()),
            parent: None,
            bit_length: bits,
            address: addr(0),
            num_bytes: ((bits + 7) / 8) as usize,
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

    // -- RegisterTree --

    #[test]
    fn test_register_tree_find() {
        let regs = vec![
            make_reg("RAX", 64, "General"),
            make_reg("RBX", 64, "General"),
            make_reg("RIP", 64, "IP"),
        ];
        let tree = RegisterTree::new(&regs);
        assert!(tree.find_register("RAX").is_some());
        assert!(tree.find_register("RIP").is_some());
        assert!(tree.find_register("NONE").is_none());
    }

    #[test]
    fn test_register_tree_groups() {
        let regs = vec![
            make_reg("EAX", 32, "General"),
            make_reg("EBX", 32, "General"),
            make_reg("ST0", 80, "Float"),
        ];
        let tree = RegisterTree::new(&regs);
        assert!(tree.groups().len() >= 2);
    }

    #[test]
    fn test_register_tree_update() {
        let mut tree = RegisterTree::new(&[make_reg("EAX", 32, "General")]);
        assert_eq!(tree.all_registers().len(), 1);

        tree.update_registers(&[
            make_reg("EAX", 32, "General"),
            make_reg("EBX", 32, "General"),
            make_reg("ECX", 32, "General"),
        ]);
        assert_eq!(tree.all_registers().len(), 3);
    }

    // -- RegisterNode --

    #[test]
    fn test_register_node() {
        let reg = make_reg("RAX", 64, "General");
        let node = RegisterNode::new(reg, &[]);
        assert_eq!(node.name(), "RAX");
        assert_eq!(node.bit_length(), 64);
        assert!(node.display_name().contains("RAX"));
    }

    // -- RegisterValueRange --

    #[test]
    fn test_register_value_range_size() {
        let range = RegisterValueRange::from_range(addr(0x1000), addr(0x1FFF), 0xFF);
        assert_eq!(range.size(), 0x1000);
    }

    #[test]
    fn test_register_value_range_adjacency() {
        let r1 = RegisterValueRange::from_range(addr(0x1000), addr(0x1FFF), 0xAA);
        let r2 = RegisterValueRange::from_range(addr(0x2000), addr(0x2FFF), 0xAA);
        let r3 = RegisterValueRange::from_range(addr(0x2000), addr(0x2FFF), 0xBB);
        let r4 = RegisterValueRange::from_range(addr(0x3000), addr(0x3FFF), 0xAA);

        assert!(r1.is_adjacent_to(&r2));
        assert!(r1.can_merge_with(&r2));
        assert!(!r1.can_merge_with(&r3));
        assert!(!r1.is_adjacent_to(&r4));
    }

    // -- RegisterManager --

    #[test]
    fn test_register_manager_lifecycle() {
        let regs = vec![
            make_reg("RAX", 64, "General"),
            make_reg("RBX", 64, "General"),
            make_reg("RCX", 64, "General"),
        ];
        let mut mgr = RegisterManager::new();
        mgr.set_program_with_data(&regs, None);
        assert_eq!(mgr.tree().all_registers().len(), 3);

        mgr.select_register("RAX");
        assert_eq!(mgr.selected_register(), Some("RAX"));

        mgr.set_location(Some("RIP"), addr(0x401000));
        assert_eq!(mgr.selected_register(), Some("RIP"));

        assert!(!mgr.include_default_values());
        mgr.set_include_default_values(true, None);
        assert!(mgr.include_default_values());
    }

    #[test]
    fn test_register_manager_build_command() {
        let mgr = RegisterManager::new();
        let ranges = vec![
            (addr(0x1000), addr(0x1FFF)),
            (addr(0x3000), addr(0x3FFF)),
        ];
        let compound = mgr.build_set_value_command("ESP", 0x7FFF0000, &ranges);
        assert_eq!(compound.len(), 2);
        assert_eq!(compound.commands()[0].register_name(), "ESP");
    }

    #[test]
    fn test_register_manager_address_set() {
        let mut mgr = RegisterManager::new();
        mgr.set_value_ranges(vec![
            RegisterValueRange::from_range(addr(0x1000), addr(0x1FFF), 1),
            RegisterValueRange::from_range(addr(0x2000), addr(0x2FFF), 2),
            RegisterValueRange::from_range(addr(0x3000), addr(0x3FFF), 3),
        ]);
        let set = mgr.get_address_set_for_rows(&[0, 2]);
        assert_eq!(set.len(), 2);
    }

    // -- SetRegisterValueCmd --

    #[test]
    fn test_set_register_value_cmd() {
        let cmd = SetRegisterValueCmd::new("RAX", addr(0x1000), addr(0x1FFF), Some(0xFF));
        assert_eq!(cmd.register_name(), "RAX");
        assert_eq!(cmd.value(), Some(0xFF));
        let s = format!("{}", cmd);
        assert!(s.contains("RAX"));
    }

    #[test]
    fn test_set_register_value_cmd_clear() {
        let cmd = SetRegisterValueCmd::clear("RBX", addr(0x2000), addr(0x2FFF));
        assert_eq!(cmd.register_name(), "RBX");
        assert!(cmd.value().is_none());
    }

    // -- RegisterValueDialogModel --

    #[test]
    fn test_register_dialog_model_set() {
        let mut model = RegisterValueDialogModel::new(RegisterDialogMode::SetValue);
        assert_eq!(model.mode(), RegisterDialogMode::SetValue);
        model.set_value(0xDEADBEEF);
        assert_eq!(model.value(), Some(0xDEADBEEF));
    }

    #[test]
    fn test_register_dialog_model_clear() {
        let model = RegisterValueDialogModel::new(RegisterDialogMode::ClearValue);
        assert_eq!(model.mode(), RegisterDialogMode::ClearValue);
    }

    #[test]
    fn test_register_dialog_model_summary() {
        let model = RegisterValueDialogModel::new(RegisterDialogMode::SetValue);
        let summary = model.summary();
        assert!(!summary.is_empty());
    }

    // -- RegisterPluginModel --

    #[test]
    fn test_register_plugin_model() {
        let mut model = RegisterPluginModel::new();
        assert!(model.registers().is_empty());

        model.set_registers(vec!["RAX".into(), "RBX".into()]);
        assert_eq!(model.registers().len(), 2);

        assert!(!model.is_provider_visible());
        model.show_provider();
        assert!(model.is_provider_visible());
        model.toggle_provider();
        assert!(!model.is_provider_visible());
    }

    // -- RegisterPluginAction --

    #[test]
    fn test_register_plugin_action_all_types() {
        for action_type in [
            RegisterActionType::SetRegisterValues,
            RegisterActionType::DeleteRegisterRange,
            RegisterActionType::DeleteRegisterAtFunction,
            RegisterActionType::ClearRegister,
        ] {
            let action = RegisterPluginAction::new(action_type);
            assert!(action.enabled);
            assert!(!action.name.is_empty());
        }
    }

    #[test]
    fn test_register_plugin_action_context() {
        let action = RegisterPluginAction::new(RegisterActionType::SetRegisterValues);
        let listing_ctx = ActionContext::listing_at(addr(0x401000));
        assert!(action.is_enabled_for_context(&listing_ctx));
    }

    // -- RegisterTransitionInfo --

    #[test]
    fn test_register_transition_info_delta() {
        let info = RegisterTransitionInfo::with_old_value(
            0x401000, "RIP", 0x1000, 0x1010, 8,
        );
        assert_eq!(info.delta(), Some(0x10));

        let info2 = RegisterTransitionInfo::new(0x401000, "RIP", 0x1010, 8);
        assert!(info2.delta().is_none());
    }

    // -- RegisterValuesPanel --

    #[test]
    fn test_register_values_panel() {
        let mut panel = RegisterValuesPanel::new();
        assert_eq!(panel.row_count(), 0);
        assert!(panel.display_ranges().is_empty());
        assert_eq!(panel.sort_direction(), SortDirection::Ascending);

        assert!(!panel.shows_defaults());
        panel.set_show_defaults(true);
        assert!(panel.shows_defaults());
    }

    // -- RegisterDialogError --

    #[test]
    fn test_register_dialog_error_display() {
        let errs = vec![
            RegisterDialogError::NoRegisterSelected,
            RegisterDialogError::InvalidValue("abc".into()),
            RegisterDialogError::EmptyAddressRange,
            RegisterDialogError::InvalidRegister("RAX".into()),
            RegisterDialogError::ValueOverflow { bit_width: 8, value: 256 },
        ];
        for err in &errs {
            let s = format!("{}", err);
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn test_register_dialog_error_is_std_error() {
        let err: &dyn std::error::Error = &RegisterDialogError::NoRegisterSelected;
        assert!(!err.to_string().is_empty());
    }
}

// ============================================================================
// Cross-module integration tests
// ============================================================================

mod cross_module_tests {
    use super::*;
    use ghidra_features::base::console::{ConsolePlugin, ConsoleService};
    use ghidra_features::base::function::{FunctionTagManager, FunctionPlugin, ThunkRelation};
    use ghidra_features::base::references::{ReferenceClass, RefTypeFactory, ReferencesPlugin};
    use ghidra_features::base::register::{RegisterManager, RegisterValueRange, RegisterTree};
    use ghidra_core::symbol::{FlowType, RefType};
    use ghidra_core::program::lang::{Register, RegisterTypeFlags};
    use std::collections::HashSet;

    fn make_reg(name: &str, bits: u32, group: &str) -> Register {
        Register {
            name: name.to_string(),
            description: String::new(),
            group: Some(group.to_string()),
            parent: None,
            bit_length: bits,
            address: addr(0),
            num_bytes: ((bits + 7) / 8) as usize,
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
    fn test_function_tags_register_reference_integration() {
        let mut tag_mgr = FunctionTagManager::new();
        tag_mgr.create_tag("uses_registers");
        tag_mgr.add_tag_to_function(0x1000, 1);

        let mut reg_mgr = RegisterManager::new();
        reg_mgr.set_value_ranges(vec![
            RegisterValueRange::from_range(addr(0x1000), addr(0x1FFF), 0),
        ]);

        let plugin = ReferencesPlugin::new();
        assert_eq!(plugin.default_ref_class(), ReferenceClass::Unknown);

        let tags = tag_mgr.tags_for_function(0x1000);
        assert_eq!(tags.len(), 1);
        assert!(!reg_mgr.value_ranges().is_empty());
    }

    #[test]
    fn test_console_with_register_reference_workflow() {
        let mut console = ConsolePlugin::new("Integration");
        console.init();

        ConsoleService::add_message(
            console.provider_mut(),
            "register",
            "Set EAX = 0x42 at 0x401000..0x401FFF",
        );
        ConsoleService::add_message(
            console.provider_mut(),
            "references",
            "Added memory reference 0x401000 -> 0x402000 (Jump)",
        );

        let text = console.provider().text();
        assert!(text.contains("EAX"));
        assert!(text.contains("0x401000"));
        assert!(text.contains("0x402000"));

        console.dispose();
    }

    #[test]
    fn test_thunk_with_ref_types_and_register() {
        let thunk = ThunkRelation::new(addr(0x1000), addr(0x2000), false);
        let ref_type = RefTypeFactory::get_default_memory_ref_type(true, false, false);
        assert_eq!(ref_type, RefType::Flow(FlowType::UnconditionalJump));

        let mut reg_mgr = RegisterManager::new();
        reg_mgr.set_value_ranges(vec![
            RegisterValueRange::from_range(addr(0x2000), addr(0x2FFF), 0),
        ]);

        assert!(!thunk.is_self_referencing());
        assert!(!reg_mgr.value_ranges().is_empty());
    }

    #[test]
    fn test_register_tree_with_console_output() {
        let regs = vec![make_reg("RAX", 64, "General")];
        let tree = RegisterTree::new(&regs);

        let mut console = ConsolePlugin::new("RegTree");
        console.init();

        for reg in tree.all_registers() {
            ConsoleService::add_message(
                console.provider_mut(),
                "reg_tree",
                &format!("Register: {}", reg.name),
            );
        }

        let text = console.provider().text();
        assert!(text.contains("RAX"));
        console.dispose();
    }

    #[test]
    fn test_full_analysis_workflow() {
        let mut reg_mgr = RegisterManager::new();
        reg_mgr.set_value_ranges(vec![
            RegisterValueRange::from_range(addr(0x401000), addr(0x401FFF), 0),
        ]);

        let ref_plugin = ReferencesPlugin::new();
        assert_eq!(ref_plugin.default_ref_class(), ReferenceClass::Unknown);

        let mut tag_mgr = FunctionTagManager::new();
        tag_mgr.create_tag("analyzed");
        tag_mgr.add_tag_to_function(0x401000, 1);

        let mut console = ConsolePlugin::new("Analysis");
        console.init();
        ConsoleService::add_message(
            console.provider_mut(),
            "analysis",
            &format!("Analyzed {} registers, {} tags",
                reg_mgr.value_ranges().len(),
                tag_mgr.tagged_function_count()),
        );

        let text = console.provider().text();
        assert!(text.contains("1 registers"));
        assert!(text.contains("1 tags"));

        console.dispose();
    }

    #[test]
    fn test_function_plugin_with_reference_types() {
        let mut plugin = FunctionPlugin::new();
        plugin.create_actions();
        let ref_types = RefTypeFactory::get_memory_ref_types();
        assert!(!ref_types.is_empty());
        assert!(plugin.action_count() > 0);
    }
}
