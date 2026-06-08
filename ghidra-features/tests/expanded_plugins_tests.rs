//! Comprehensive integration tests for the expanded Features/Base plugin modules.
//!
//! These tests exercise the deepened action framework, factory system,
//! and cross-module workflows ported from Ghidra's Java source.


// ============================================================================
// Action framework tests
// ============================================================================

mod action_framework_tests {
    use ghidra_features::base::actions::{
        ActionContextType, ActionManager, CopyAction, CreateFunctionAction,
        DeleteAction, DisassembleAction, DockingAction, GoToAddressAction,
        KeyBinding, MenuData, PasteAction, RedoAction, RenameAction, SetEolCommentAction, SetPlateCommentAction,
        SetPostCommentAction, SetPreCommentAction,
        ToolBarData, UndoAction,
        edit_menu_data, file_menu_data, analysis_menu_data,
        function_menu_data, window_menu_data,
    };

    #[test]
    fn test_key_binding_serialization_roundtrip() {
        let kb = KeyBinding::ctrl_shift(90);
        let json = serde_json::to_string(&kb).unwrap();
        let deserialized: KeyBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(kb, deserialized);
        assert!(deserialized.has_ctrl());
        assert!(deserialized.has_shift());
    }

    #[test]
    fn test_key_binding_all_modifiers() {
        let kb = KeyBinding::new(65, 7); // Ctrl+Alt+Shift+A
        assert!(kb.has_ctrl());
        assert!(kb.has_shift());
        assert!(kb.has_alt());
        let display = kb.display_string();
        assert!(display.contains("Ctrl"));
        assert!(display.contains("Shift"));
        assert!(display.contains("Alt"));
    }

    #[test]
    fn test_menu_data_serialization() {
        let md = MenuData::new(
            vec!["File".into(), "Export...".into()],
            "ImportExport",
            "z",
        );
        let json = serde_json::to_string(&md).unwrap();
        let deserialized: MenuData = serde_json::from_str(&json).unwrap();
        assert_eq!(md, deserialized);
    }

    #[test]
    fn test_docking_action_full_builder_chain() {
        let action = DockingAction::new("MyAction", "MyPlugin")
            .with_key_binding(KeyBinding::ctrl(75))
            .with_menu_data(edit_menu_data("My Action"))
            .with_popup_menu_data(MenuData::new(
                vec!["Context".into(), "My Action".into()],
                "Context",
                "Actions",
            ))
            .with_tool_bar_data(ToolBarData::new("icon.png", "Group1"))
            .with_description("Performs my custom action")
            .with_help_topic("MyPlugin_MyAction");

        assert_eq!(action.name, "MyAction");
        assert_eq!(action.owner, "MyPlugin");
        assert!(action.key_binding.is_some());
        assert!(action.menu_data.is_some());
        assert!(action.popup_menu_data.is_some());
        assert!(action.tool_bar_data.is_some());
        assert!(!action.description.is_empty());
        assert!(action.help_topic.is_some());
    }

    #[test]
    fn test_action_manager_complex_workflow() {
        let mut mgr = ActionManager::new();

        // Register actions from multiple plugins
        let plugins = vec![
            ("CodeBrowser", vec!["Copy", "Paste", "Select All", "Undo", "Redo"]),
            ("DataPlugin", vec!["Define Array", "Create Structure", "Cycle"]),
            ("FunctionPlugin", vec!["Create Function", "Delete Function"]),
            ("NavigationPlugin", vec!["Next Bookmark", "Previous Bookmark"]),
        ];

        for (owner, names) in &plugins {
            for name in names {
                mgr.register(DockingAction::new(*name, *owner));
            }
        }

        assert_eq!(mgr.count(), 12);
        assert_eq!(mgr.actions_for_owner("CodeBrowser").len(), 5);
        assert_eq!(mgr.actions_for_owner("DataPlugin").len(), 3);

        // Disable specific actions
        mgr.set_enabled("CodeBrowser", "Undo", false);
        let undo = mgr.get("CodeBrowser", "Undo").unwrap();
        assert!(!undo.enabled);

        // Remove a plugin's actions
        mgr.remove_by_owner("NavigationPlugin");
        assert_eq!(mgr.count(), 10);
        assert!(mgr.actions_for_owner("NavigationPlugin").is_empty());
    }

    #[test]
    fn test_standard_actions_key_bindings() {
        let owner = "TestPlugin";
        let actions: Vec<(&str, u32)> = vec![
            ("copy", CopyAction::new(owner).key_binding.key_code),
            ("paste", PasteAction::new(owner).key_binding.key_code),
            ("undo", UndoAction::new(owner).key_binding.key_code),
            ("redo", RedoAction::new(owner).key_binding.key_code),
            ("delete", DeleteAction::new(owner).key_binding.key_code),
            ("rename", RenameAction::new(owner).key_binding.key_code),
            ("goto", GoToAddressAction::new(owner).key_binding.key_code),
            ("disasm", DisassembleAction::new(owner).key_binding.key_code),
            ("create_fn", CreateFunctionAction::new(owner).key_binding.key_code),
        ];

        // All actions should have distinct key codes
        let codes: Vec<u32> = actions.iter().map(|(_, c)| *c).collect();
        let mut sorted = codes.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(codes.len(), sorted.len(), "All actions should have unique key codes");
    }

    #[test]
    fn test_comment_actions_complete_set() {
        let owner = "CommentPlugin";

        let eol = SetEolCommentAction::new(owner);
        let pre = SetPreCommentAction::new(owner);
        let post = SetPostCommentAction::new(owner);
        let plate = SetPlateCommentAction::new(owner);

        // All should have unique key codes (with modifiers making them distinct)
        assert_eq!(eol.key_binding.key_code, 59); // plain semicolon
        assert!(pre.key_binding.has_ctrl()); // Ctrl+;
        assert!(post.key_binding.has_ctrl() && post.key_binding.has_shift()); // Ctrl+Shift+;
        assert_eq!(plate.key_binding.key_code, 80); // VK_P
    }

    #[test]
    fn test_action_context_type_completeness() {
        let types = vec![
            ActionContextType::Listing,
            ActionContextType::SymbolTree,
            ActionContextType::Table,
            ActionContextType::Decompiler,
            ActionContextType::Console,
            ActionContextType::FrontEnd,
            ActionContextType::DataTypeManager,
        ];
        assert_eq!(types.len(), 7);
        // All should be distinct
        for i in 0..types.len() {
            for j in (i + 1)..types.len() {
                assert_ne!(types[i], types[j]);
            }
        }
    }

    #[test]
    fn test_menu_helper_functions() {
        let edit = edit_menu_data("Copy");
        assert_eq!(edit.menu_path[0], "Edit");

        let file = file_menu_data("Save");
        assert_eq!(file.menu_path[0], "File");

        let analysis = analysis_menu_data("Auto Analysis");
        assert_eq!(analysis.menu_path[0], "Analysis");

        let func = function_menu_data("Create Function");
        assert_eq!(func.menu_path[0], "Function");

        let window = window_menu_data("Symbol Table");
        assert_eq!(window.menu_path[0], "Window");
    }
}

// ============================================================================
// Factory framework tests
// ============================================================================

mod factory_framework_tests {
    use ghidra_features::base::factory::{
        ComponentProviderDescription, DefaultComponentFactory, ComponentFactory,
        FactoryError, FactoryManager, FormatType,
    };

    #[test]
    fn test_format_type_all_variants() {
        let types = vec![
            FormatType::Table,
            FormatType::Tree,
            FormatType::Listing,
            FormatType::Graph,
            FormatType::Image,
            FormatType::Other,
        ];
        assert_eq!(types.len(), 6);
        for t in &types {
            let s = format!("{}", t);
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn test_provider_description_serialization() {
        let desc = ComponentProviderDescription::new("CodeViewer", "CBPlugin", FormatType::Listing)
            .with_multiple_instances(true)
            .with_help_topic("CodeViewer")
            .with_window_menu_group("Code");

        let json = serde_json::to_string(&desc).unwrap();
        let deserialized: ComponentProviderDescription = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "CodeViewer");
        assert_eq!(deserialized.format_type, FormatType::Listing);
        assert!(deserialized.supports_multiple_instances);
    }

    #[test]
    fn test_factory_error_variants() {
        let errors = vec![
            FactoryError::UnknownFactory("test".into()),
            FactoryError::UnsupportedProvider("test".into()),
            FactoryError::ToolNotAvailable,
            FactoryError::MissingService("test".into()),
            FactoryError::CreationFailed("test".into()),
        ];
        for err in &errors {
            let s = format!("{}", err);
            assert!(!s.is_empty());
            // Should implement std::error::Error
            let _: &dyn std::error::Error = err;
        }
    }

    #[test]
    fn test_factory_multi_provider_workflow() {
        let mut factory = DefaultComponentFactory::new("GhidraCoreFactory");

        // Register the standard Ghidra component providers
        let providers = vec![
            ComponentProviderDescription::new("CodeBrowser", "CodeBrowserPlugin", FormatType::Listing),
            ComponentProviderDescription::new("DataTypeManager", "DataTypeManagerPlugin", FormatType::Tree),
            ComponentProviderDescription::new("SymbolTable", "SymbolTablePlugin", FormatType::Table),
            ComponentProviderDescription::new("Console", "ConsolePlugin", FormatType::Listing),
            ComponentProviderDescription::new("Decompiler", "DecompilePlugin", FormatType::Listing),
            ComponentProviderDescription::new("ByteViewer", "ByteViewerPlugin", FormatType::Listing),
            ComponentProviderDescription::new("FunctionGraph", "FunctionGraphPlugin", FormatType::Graph),
            ComponentProviderDescription::new("Overview", "OverviewPlugin", FormatType::Image),
        ];

        for p in providers {
            factory.register_provider(p);
        }

        assert_eq!(factory.provider_count(), 8);
        assert_eq!(factory.supported_providers().len(), 8);

        // Create each provider
        let cb = factory.create_provider("CodeBrowser", "MainTool").unwrap();
        assert_eq!(cb.format_type, FormatType::Listing);

        let graph = factory.create_provider("FunctionGraph", "MainTool").unwrap();
        assert_eq!(graph.format_type, FormatType::Graph);

        let overview = factory.create_provider("Overview", "MainTool").unwrap();
        assert_eq!(overview.format_type, FormatType::Image);
    }

    #[test]
    fn test_factory_manager_multi_factory() {
        let mut mgr = FactoryManager::new();

        // Register multiple factories
        let mut f1 = DefaultComponentFactory::new("CoreFactory");
        f1.register_provider(
            ComponentProviderDescription::new("CodeBrowser", "CBPlugin", FormatType::Listing),
        );
        mgr.register(Box::new(f1));

        let mut f2 = DefaultComponentFactory::new("AnalysisFactory");
        f2.register_provider(
            ComponentProviderDescription::new("ByteViewer", "BVPlugin", FormatType::Listing),
        );
        f2.register_provider(
            ComponentProviderDescription::new("StringsTable", "StringsPlugin", FormatType::Table),
        );
        mgr.register(Box::new(f2));

        assert_eq!(mgr.count(), 2);
        assert!(mgr.has_factory("CoreFactory"));
        assert!(mgr.has_factory("AnalysisFactory"));

        // Cross-factory provider creation
        let cb = mgr.create_provider("CoreFactory", "CodeBrowser", "TestTool").unwrap();
        assert!(cb.name.contains("TestTool"));

        let bv = mgr.create_provider("AnalysisFactory", "ByteViewer", "TestTool").unwrap();
        assert!(bv.name.contains("TestTool"));

        // Wrong factory
        assert!(mgr.create_provider("CoreFactory", "ByteViewer", "t").is_err());

        // Unknown factory
        assert!(mgr.create_provider("NoFactory", "x", "t").is_err());
    }

    #[test]
    fn test_factory_format_type_resolution() {
        let mut factory = DefaultComponentFactory::new("TestFactory");
        factory.register_provider(
            ComponentProviderDescription::new("TableView", "P1", FormatType::Table),
        );
        factory.register_provider(
            ComponentProviderDescription::new("TreeView", "P2", FormatType::Tree),
        );
        factory.register_provider(
            ComponentProviderDescription::new("GraphView", "P3", FormatType::Graph),
        );

        assert_eq!(factory.format_type_for("TableView"), Some(FormatType::Table));
        assert_eq!(factory.format_type_for("TreeView"), Some(FormatType::Tree));
        assert_eq!(factory.format_type_for("GraphView"), Some(FormatType::Graph));
        assert_eq!(factory.format_type_for("NonExistent"), None);
    }
}

// ============================================================================
// Cross-module integration tests
// ============================================================================

mod cross_module_tests {
    use ghidra_features::base::actions::{
        ActionManager, DockingAction, KeyBinding, MenuData,
        edit_menu_data, window_menu_data,
    };
    use ghidra_features::base::factory::{
        ComponentProviderDescription, DefaultComponentFactory,
        FactoryManager, FormatType,
    };

    #[test]
    fn test_plugin_registration_with_actions_and_providers() {
        let mut action_mgr = ActionManager::new();
        let mut factory_mgr = FactoryManager::new();

        // Simulate registering a plugin that has both actions and component providers
        let plugin_name = "SymbolTablePlugin";

        // Register actions
        action_mgr.register(
            DockingAction::new("Filter Symbols", plugin_name)
                .with_menu_data(edit_menu_data("Filter Symbols..."))
                .with_key_binding(KeyBinding::ctrl(70)),
        );
        action_mgr.register(
            DockingAction::new("Show Symbol Table", plugin_name)
                .with_menu_data(window_menu_data("Symbol Table")),
        );

        // Register factory with providers
        let mut factory = DefaultComponentFactory::new(format!("{}Factory", plugin_name));
        factory.register_provider(
            ComponentProviderDescription::new("SymbolTable", plugin_name, FormatType::Table)
                .with_multiple_instances(true)
                .with_window_menu_group("Symbol"),
        );
        factory_mgr.register(Box::new(factory));

        // Verify both registrations
        assert_eq!(action_mgr.actions_for_owner(plugin_name).len(), 2);
        assert!(factory_mgr.has_factory(&format!("{}Factory", plugin_name)));

        // Create provider from factory
        let provider = factory_mgr
            .create_provider(
                &format!("{}Factory", plugin_name),
                "SymbolTable",
                "MainTool",
            )
            .unwrap();
        assert_eq!(provider.format_type, FormatType::Table);
        assert!(provider.supports_multiple_instances);
        assert_eq!(provider.window_menu_group.as_deref(), Some("Symbol"));
    }

    #[test]
    fn test_action_serialization_preserves_config() {
        // Simulate saving and restoring tool configuration
        let mut mgr = ActionManager::new();

        let action = DockingAction::new("Export Program", "ExporterPlugin")
            .with_key_binding(KeyBinding::ctrl(69)) // Ctrl+E
            .with_menu_data(MenuData::new(
                vec!["File".into(), "Export Program...".into()],
                "Import Export",
                "z",
            ))
            .with_description("Export the current program to a file");

        mgr.register(action);

        // Serialize the action
        let action_ref = mgr.get("ExporterPlugin", "Export Program").unwrap();
        let json = serde_json::to_string(action_ref).unwrap();

        // Verify serialization contains key fields
        assert!(json.contains("Export Program"));
        assert!(json.contains("ExporterPlugin"));
        assert!(json.contains("Import Export"));

        // Deserialize
        let restored: DockingAction = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.name, "Export Program");
        assert_eq!(restored.owner, "ExporterPlugin");
        assert!(restored.key_binding.is_some());
    }

    #[test]
    fn test_complete_ghidra_plugin_simulation() {
        // Simulate a complete Ghidra plugin: CodeBrowser
        let plugin_name = "CodeBrowserPlugin";
        let mut action_mgr = ActionManager::new();

        // Standard actions for a listing component provider
        let standard_actions = vec![
            DockingAction::new("Copy", plugin_name)
                .with_key_binding(KeyBinding::ctrl(67))
                .with_menu_data(edit_menu_data("Copy")),
            DockingAction::new("Paste", plugin_name)
                .with_key_binding(KeyBinding::ctrl(86))
                .with_menu_data(edit_menu_data("Paste")),
            DockingAction::new("Select All", plugin_name)
                .with_key_binding(KeyBinding::ctrl(65))
                .with_menu_data(edit_menu_data("Select All")),
            DockingAction::new("Undo", plugin_name)
                .with_key_binding(KeyBinding::ctrl(90))
                .with_menu_data(edit_menu_data("Undo")),
            DockingAction::new("Redo", plugin_name)
                .with_key_binding(KeyBinding::ctrl(89))
                .with_menu_data(edit_menu_data("Redo")),
            DockingAction::new("Define Array", plugin_name)
                .with_key_binding(KeyBinding::new(91, 0)) // VK_OPEN_BRACKET
                .with_menu_data(MenuData::new(
                    vec!["Data".into(), "Create Array...".into()],
                    "BasicData",
                    "Data",
                )),
            DockingAction::new("Set EOL Comment", plugin_name)
                .with_key_binding(KeyBinding::new(59, 0)) // semicolon
                .with_menu_data(edit_menu_data("EOL Comment")),
        ];

        for action in standard_actions {
            action_mgr.register(action);
        }

        assert_eq!(action_mgr.actions_for_owner(plugin_name).len(), 7);

        // Simulate disabling actions when no program is open
        action_mgr.set_enabled(plugin_name, "Copy", false);
        action_mgr.set_enabled(plugin_name, "Paste", false);
        action_mgr.set_enabled(plugin_name, "Undo", false);

        let copy = action_mgr.get(plugin_name, "Copy").unwrap();
        assert!(!copy.enabled);

        // Re-enable when a program is loaded
        action_mgr.set_enabled(plugin_name, "Copy", true);
        action_mgr.set_enabled(plugin_name, "Paste", true);
        action_mgr.set_enabled(plugin_name, "Undo", true);

        let copy = action_mgr.get(plugin_name, "Copy").unwrap();
        assert!(copy.enabled);
    }

    #[test]
    fn test_factory_and_action_coordination() {
        // Test that factories and actions can be coordinated for a plugin
        let mut action_mgr = ActionManager::new();
        let mut factory_mgr = FactoryManager::new();

        let plugin_name = "DataPlugin";

        // Actions
        action_mgr.register(
            DockingAction::new("Create Array", plugin_name)
                .with_key_binding(KeyBinding::new(91, 0)),
        );
        action_mgr.register(
            DockingAction::new("Create Structure", plugin_name),
        );

        // Component provider via factory
        let mut factory = DefaultComponentFactory::new("DataFactory");
        factory.register_provider(
            ComponentProviderDescription::new("DataWindow", plugin_name, FormatType::Tree),
        );
        factory_mgr.register(Box::new(factory));

        // Both should be accessible
        assert!(action_mgr.contains(plugin_name, "Create Array"));
        assert!(action_mgr.contains(plugin_name, "Create Structure"));

        let provider = factory_mgr
            .create_provider("DataFactory", "DataWindow", "TestTool")
            .unwrap();
        assert_eq!(provider.format_type, FormatType::Tree);

        // Simulate plugin disposal: remove actions
        action_mgr.remove_by_owner(plugin_name);
        assert_eq!(action_mgr.actions_for_owner(plugin_name).len(), 0);

        // Factory still exists (factories persist across plugin lifecycle)
        assert!(factory_mgr.has_factory("DataFactory"));
    }
}
