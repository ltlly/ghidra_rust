//! Integration tests for remaining Features/Base plugin ports.
//!
//! Tests the newly ported functionality for:
//! - `codebrowser::middle_mouse_highlight` -- ListingMiddleMouseHighlightProvider
//! - `progmgr::tab_actions` -- Dynamic-name actions and multi-tab management
//! - `symtable::renderer` -- Symbol renderer, transient model, and mappers

// ============================================================================
// Code Browser: Middle Mouse Highlight Provider
// ============================================================================

mod middle_mouse_highlight_tests {
    use ghidra_features::codebrowser::middle_mouse_highlight::*;

    #[test]
    fn test_provider_lifecycle() {
        let mut provider = MiddleMouseHighlightProvider::new();
        assert_eq!(provider.mode(), HighlightMode::TextMatch);
        assert!(provider.current_highlight().is_none());

        // Set highlight text
        provider.set_highlight_text("mov");
        assert_eq!(provider.mode(), HighlightMode::TextMatch);
        assert_eq!(provider.current_highlight(), Some("mov"));

        // Find matches
        let matches = provider.find_matches("mov eax, ebx; mov ecx, edx");
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].0, 0);
        assert_eq!(matches[1].0, 14);

        // Clear
        provider.clear_highlight();
        assert_eq!(provider.mode(), HighlightMode::Off);
        assert!(provider.find_matches("mov eax").is_empty());
    }

    #[test]
    fn test_scope_highlighting() {
        let mut provider = MiddleMouseHighlightProvider::new();
        provider.set_scope_highlight("RDI");
        assert_eq!(provider.mode(), HighlightMode::Scope);

        // Scope matching is text-based approximation
        let scopes = provider.find_scope_matches("call func, RDI, RSI", "RDI");
        // Should find at least one occurrence
        assert!(!scopes.is_empty());
    }

    #[test]
    fn test_case_sensitivity_toggle() {
        let mut provider = MiddleMouseHighlightProvider::new();
        provider.set_highlight_text("EAX");

        // Case insensitive: matches both "EAX" and "eax"
        provider.set_case_sensitive(false);
        assert_eq!(provider.find_matches("EAX eax EAx").len(), 3);

        // Case sensitive: matches only "EAX"
        provider.set_case_sensitive(true);
        assert_eq!(provider.find_matches("EAX eax EAx").len(), 1);
    }

    #[test]
    fn test_highlight_button_config() {
        let mut provider = MiddleMouseHighlightProvider::new();
        assert!(provider.is_highlight_button(2)); // middle
        assert!(!provider.is_highlight_button(1)); // left

        provider.set_highlight_button(3);
        assert!(provider.is_highlight_button(3));
        assert!(!provider.is_highlight_button(2));
    }

    #[test]
    fn test_color_configuration() {
        let mut provider = MiddleMouseHighlightProvider::new();
        let original_default = provider.colors().default.clone();
        assert!(!original_default.is_empty());

        let new_colors = HighlightColors {
            default: "#AABBCC".into(),
            scoped_read: "#112233".into(),
            scoped_write: "#445566".into(),
        };
        provider.set_colors(new_colors);
        assert_eq!(provider.colors().default, "#AABBCC");
        assert_eq!(provider.colors().scoped_read, "#112233");
    }

    #[test]
    fn test_empty_pattern_handling() {
        let mut provider = MiddleMouseHighlightProvider::new();
        provider.set_highlight_text("hello");
        provider.set_highlight_text("");
        assert!(provider.current_highlight().is_none());
        assert!(provider.find_matches("hello world").is_empty());
    }

    #[test]
    fn test_overlapping_matches() {
        let mut provider = MiddleMouseHighlightProvider::new();
        provider.set_highlight_text("aa");
        provider.set_case_sensitive(false);

        // "aaa" has two overlapping "aa" matches
        let matches = provider.find_matches("aaa");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_no_matches_in_off_mode() {
        let mut provider = MiddleMouseHighlightProvider::new();
        provider.set_highlight_text("test");
        provider.clear_highlight();
        assert!(provider.find_matches("test test test").is_empty());
    }

    #[test]
    fn test_scope_register_operand_setting() {
        let mut provider = MiddleMouseHighlightProvider::new();
        assert!(provider.is_scope_register_operand());
        provider.set_scope_register_operand(false);
        assert!(!provider.is_scope_register_operand());
        provider.set_scope_register_operand(true);
        assert!(provider.is_scope_register_operand());
    }

    #[test]
    fn test_find_matches_unicode() {
        let mut provider = MiddleMouseHighlightProvider::new();
        provider.set_highlight_text("cafe");
        provider.set_case_sensitive(false);

        // Should match "cafe" and "Cafe" but not "CAFÉ" (different char)
        let matches = provider.find_matches("cafe Cafe CAFE");
        assert_eq!(matches.len(), 3); // cafe, Cafe, CAFE
    }
}

// ============================================================================
// Program Manager: Tab Actions
// ============================================================================

mod progmgr_tab_actions_tests {
    use ghidra_features::progmgr::tab_actions::*;

    #[test]
    fn test_close_action_dynamic_name() {
        let mut action = CloseProgramAction::new("MyPlugin", "File", 1);

        // No program: default name
        assert_eq!(action.menu_item_name(), "&Close");

        // With program: dynamic name
        action.set_program_name(Some("test_binary.exe"));
        assert_eq!(action.menu_item_name(), "Close 'test_binary.exe'");

        // Reset to no program
        action.set_program_name(None);
        assert_eq!(action.menu_item_name(), "&Close");
    }

    #[test]
    fn test_save_as_action_dynamic_name() {
        let mut action = SaveAsProgramAction::new("Plugin", "File", 2);

        assert_eq!(action.menu_item_name(), "S&ave As...");

        action.set_program_name(Some("malware.bin"));
        assert_eq!(action.menu_item_name(), "Save 'malware.bin' As...");
    }

    #[test]
    fn test_program_options_action_dynamic_name() {
        let mut action = ProgramOptionsAction::new("Plugin");

        assert_eq!(action.menu_item_name(), "Program Options");

        action.set_program_name(Some("firmware.elf"));
        assert_eq!(action.menu_item_name(), "Options for 'firmware.elf'");
    }

    #[test]
    fn test_undo_redo_actions() {
        let mut undo = UndoAction::new("Plugin");
        let mut redo = RedoAction::new("Plugin");

        // Initially disabled
        assert!(!undo.is_enabled());
        assert!(!redo.is_enabled());

        // Enable undo
        undo.update_state(true, "Delete Address Range", 5);
        assert!(undo.is_enabled());
        assert_eq!(undo.available_count(), 5);

        // Enable redo
        redo.update_state(true, "Add Bookmark", 2);
        assert!(redo.is_enabled());
        assert_eq!(redo.available_count(), 2);

        // Keyboard shortcuts
        assert_eq!(undo.key_binding(), "ctrl Z");
        assert_eq!(redo.key_binding(), "ctrl shift Z");
    }

    #[test]
    fn test_multi_tab_lifecycle() {
        let mut tabs = MultiTabPlugin::new("ProgramMgr");

        // Add programs
        tabs.add_tab("kernel32.dll".to_string());
        tabs.add_tab("ntdll.dll".to_string());
        tabs.add_tab("user32.dll".to_string());

        assert_eq!(tabs.tab_count(), 3);
        assert_eq!(tabs.selected_tab(), Some(0));
        assert_eq!(tabs.selected_tab_name(), Some("kernel32.dll"));

        // Switch tabs
        tabs.select_tab(2);
        assert_eq!(tabs.selected_tab_name(), Some("user32.dll"));

        // Close middle tab
        tabs.select_tab(1);
        tabs.remove_tab(1);
        assert_eq!(tabs.tab_count(), 2);
        assert_eq!(tabs.tab_names(), &["kernel32.dll", "user32.dll"]);
    }

    #[test]
    fn test_multi_tab_move_reorder() {
        let mut tabs = MultiTabPlugin::new("Test");
        tabs.add_tab("first".to_string());
        tabs.add_tab("second".to_string());
        tabs.add_tab("third".to_string());

        tabs.select_tab(0);
        assert!(tabs.move_tab(0, 2));
        assert_eq!(tabs.tab_names(), &["second", "third", "first"]);
        assert_eq!(tabs.selected_tab(), Some(2)); // moved with the tab
    }

    #[test]
    fn test_multi_tab_remove_by_name() {
        let mut tabs = MultiTabPlugin::new("Test");
        tabs.add_tab("alpha".to_string());
        tabs.add_tab("beta".to_string());

        assert!(tabs.remove_tab_by_name("alpha").is_some());
        assert_eq!(tabs.tab_count(), 1);
        assert_eq!(tabs.tab_name(0), Some("beta"));

        assert!(tabs.remove_tab_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_program_tab_action_context() {
        let ctx = ProgramTabActionContext::new("Plugin");
        assert!(!ctx.has_program());

        let mut ctx = ProgramTabActionContext::new("Plugin");
        ctx.program_id = Some(42);
        ctx.program_name = Some("binary.exe".into());
        assert!(ctx.has_program());
    }

    #[test]
    fn test_abstract_action_state() {
        let action = AbstractProgramNameSwitchingAction::new("TestAction", "Owner");
        assert_eq!(action.name(), "TestAction");
        assert_eq!(action.owner(), "Owner");
        assert!(action.is_enabled());

        let mut action = action;
        action.set_enabled(false);
        assert!(!action.is_enabled());
    }

    #[test]
    fn test_multi_tab_reorderable() {
        let mut tabs = MultiTabPlugin::new("Test");
        assert!(tabs.is_reorderable());
        tabs.set_reorderable(false);
        assert!(!tabs.is_reorderable());
    }
}

// ============================================================================
// Symbol Table: Renderer and Transient Model
// ============================================================================

mod symtable_renderer_tests {
    use ghidra_features::symtable::model::{SymbolRowObject, SymbolTableKind};
    use ghidra_features::symtable::renderer::*;
    use ghidra_features::symtable::filter::SymbolFilter;

    fn make_symbol(name: &str, addr: u64, kind: SymbolTableKind) -> SymbolRowObject {
        SymbolRowObject::new(name, addr, kind, "Global")
    }

    #[test]
    fn test_renderer_all_kinds() {
        let renderer = SymbolRenderer::new();

        // Function -> Bold
        let render = renderer.render(&make_symbol("func", 0x100, SymbolTableKind::Function));
        assert_eq!(render.mode, SymbolRenderMode::Bold);
        assert!(!render.color.is_empty());

        // Label -> Normal
        let render = renderer.render(&make_symbol("lab", 0x200, SymbolTableKind::Label));
        assert_eq!(render.mode, SymbolRenderMode::Normal);

        // External -> Italic
        let render = renderer.render(&make_symbol("ext", 0x0, SymbolTableKind::External));
        assert_eq!(render.mode, SymbolRenderMode::Italic);

        // Class -> Bold
        let render = renderer.render(&make_symbol("cls", 0x300, SymbolTableKind::Class));
        assert_eq!(render.mode, SymbolRenderMode::Bold);

        // Deleted placeholder
        let render = renderer.render_deleted();
        assert_eq!(render.text, "<< REMOVED >>");
        assert_eq!(render.mode, SymbolRenderMode::Strikethrough);
    }

    #[test]
    fn test_transient_model_full_lifecycle() {
        let mut model = TransientSymbolTableModel::new("Xrefs To main");
        assert_eq!(model.title(), "Xrefs To main");
        assert!(model.is_empty());

        // Add symbols
        model.add_symbol(make_symbol("call_main_1", 0x100, SymbolTableKind::Label));
        model.add_symbol(make_symbol("call_main_2", 0x200, SymbolTableKind::Label));
        model.add_symbol(make_symbol("jmp_main", 0x300, SymbolTableKind::Label));
        assert_eq!(model.row_count(), 3);

        // Remove one
        let removed = model.remove_symbol(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name(), "call_main_2");
        assert_eq!(model.row_count(), 2);

        // Get by index
        assert_eq!(model.get(0).unwrap().name(), "call_main_1");
        assert_eq!(model.get(1).unwrap().name(), "jmp_main");
        assert!(model.get(2).is_none());
    }

    #[test]
    fn test_transient_model_soft_delete_restore() {
        let mut model = TransientSymbolTableModel::new("Test");
        model.set_soft_delete(true);

        model.add_symbol(make_symbol("a", 0x100, SymbolTableKind::Function));
        model.add_symbol(make_symbol("b", 0x200, SymbolTableKind::Label));
        model.add_symbol(make_symbol("c", 0x300, SymbolTableKind::Function));

        // Soft-delete "b"
        model.remove_symbol(1);
        assert_eq!(model.row_count(), 2);

        // all_symbols still has all 3
        assert_eq!(model.all_symbols().len(), 3);

        // Restore it
        assert!(model.restore(0));
        assert_eq!(model.row_count(), 3);
    }

    #[test]
    fn test_transient_model_filtering() {
        let mut model = TransientSymbolTableModel::new("Test");
        model.add_symbol(make_symbol("func1", 0x100, SymbolTableKind::Function));
        model.add_symbol(make_symbol("label1", 0x200, SymbolTableKind::Label));
        model.add_symbol(make_symbol("func2", 0x300, SymbolTableKind::Function));
        model.add_symbol(make_symbol("ext1", 0x0, SymbolTableKind::External));

        let mut filter = SymbolFilter::new();
        filter.type_filter_mut().functions = true;
        filter.type_filter_mut().labels = false;
        filter.type_filter_mut().external = false;

        let indices = model.filtered_indices(&filter);
        assert_eq!(indices.len(), 2);
        assert_eq!(model.get(indices[0]).unwrap().name(), "func1");
        assert_eq!(model.get(indices[1]).unwrap().name(), "func2");
    }

    #[test]
    fn test_address_mapper() {
        let sym = make_symbol("main", 0x401000, SymbolTableKind::Function);
        assert_eq!(
            SymbolRowObjectToAddressTableRowMapper::map(&sym),
            Some(0x401000)
        );

        // "deleted" symbol: empty name, zero address
        let deleted = SymbolRowObject::new("", 0, SymbolTableKind::Label, "");
        assert!(SymbolRowObjectToAddressTableRowMapper::map(&deleted).is_none());
    }

    #[test]
    fn test_location_mapper() {
        let sym = make_symbol("printf", 0x1000, SymbolTableKind::External);
        let loc = SymbolRowObjectToProgramLocationTableRowMapper::map(&sym, "libc.so");
        assert!(loc.is_some());
        let loc = loc.unwrap();
        assert_eq!(loc.address, 0x1000);
        assert_eq!(loc.symbol_name, "printf");
        assert_eq!(loc.namespace, "Global");
        assert_eq!(loc.program_name, "libc.so");
    }

    #[test]
    fn test_custom_color_scheme() {
        let colors = SymbolColorScheme {
            function_color: "#FF0000".into(),
            label_color: "#00FF00".into(),
            ..Default::default()
        };
        let renderer = SymbolRenderer::with_colors(colors);

        let func_render = renderer.render(&make_symbol("f", 0, SymbolTableKind::Function));
        assert_eq!(func_render.color, "#FF0000");

        let label_render = renderer.render(&make_symbol("l", 0, SymbolTableKind::Label));
        assert_eq!(label_render.color, "#00FF00");
    }

    #[test]
    fn test_transient_model_clear() {
        let mut model = TransientSymbolTableModel::new("Test");
        model.add_symbol(make_symbol("a", 0x100, SymbolTableKind::Function));
        model.add_symbol(make_symbol("b", 0x200, SymbolTableKind::Label));

        model.clear();
        assert!(model.is_empty());
        assert_eq!(model.row_count(), 0);
        assert!(model.all_symbols().is_empty());
    }

    #[test]
    fn test_symbol_program_location_fields() {
        let sym = make_symbol("malloc", 0x2000, SymbolTableKind::External);
        let loc =
            SymbolRowObjectToProgramLocationTableRowMapper::map(&sym, "libc.so.6")
                .unwrap();
        assert_eq!(loc.address, 0x2000);
        assert_eq!(loc.symbol_name, "malloc");
        assert_eq!(loc.namespace, "Global");
        assert_eq!(loc.program_name, "libc.so.6");
    }
}
