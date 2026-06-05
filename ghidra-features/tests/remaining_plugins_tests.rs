//! Integration tests for the remaining Features/Base plugin modules ported
//! from Ghidra's Java source.
//!
//! Covers:
//! - Symbol GTree widget model (expansion, drag-drop, snapshot)
//! - Additional location descriptor types (generic data type, composite,
//!   xref, function definition, parameter type, union)
//! - Location references highlighter and provider
//! - Row mapper types
//! - Hover plugin registry
//! - Function tag provider model integration

use ghidra_core::Address;

// ===========================================================================
// Symbol GTree integration
// ===========================================================================

mod gtree_integration {
    use super::*;
    use ghidra_features::symboltree::gtree::{
        DisconnectedSymbolTreeProvider, GTreeNodeData, SymbolGTree,
        SymbolGTreeDragNDropHandler,
    };
    use ghidra_features::symboltree::{SymbolCategory, SymbolDragDropAction, SymbolType};

    #[test]
    fn test_full_symbol_tree_lifecycle() {
        let mut tree = SymbolGTree::new();

        // Add category roots
        let funcs = tree.add_root_category(SymbolCategory::Functions);
        let labels = tree.add_root_category(SymbolCategory::Labels);
        let classes = tree.add_root_category(SymbolCategory::Classes);

        // Add functions
        for i in 0..5 {
            tree.add_child(
                funcs,
                format!("func_{}", i),
                GTreeNodeData::Symbol {
                    address: 0x401000 + i * 0x100,
                    namespace: String::new(),
                },
                Some(SymbolType::Function),
            );
        }

        // Add a namespace with methods
        let ns_id = tree
            .add_child(
                classes,
                "MyClass",
                GTreeNodeData::Organization {
                    prefix: "M".into(),
                },
                Some(SymbolType::Class),
            )
            .unwrap();
        for method in &["init", "process", "destroy"] {
            tree.add_child(
                ns_id,
                *method,
                GTreeNodeData::Symbol {
                    address: 0x500000,
                    namespace: "MyClass".into(),
                },
                Some(SymbolType::Function),
            );
        }

        assert_eq!(tree.node_count(), 12); // 3 roots + 5 funcs + 1 class + 3 methods

        // Expand the class node
        tree.expand_node(ns_id);
        assert!(tree.node(ns_id).unwrap().expanded);

        // Search for a function
        let func_2 = tree.find_child_by_name(funcs, "func_2");
        assert!(func_2.is_some());

        // Create snapshot
        let snapshot = tree.snapshot();
        assert!(snapshot.is_disconnected());
        assert_eq!(snapshot.node_count(), tree.node_count());

        // Drag-drop: move a function to labels
        let func_0 = tree.find_child_by_name(funcs, "func_0").unwrap();
        let handler = SymbolGTreeDragNDropHandler::new();
        assert!(handler.can_drop(&[func_0], labels, &tree));
        handler
            .drop(&mut tree, &[func_0], labels, SymbolDragDropAction::Move)
            .unwrap();
        // func_0 is removed from funcs
        assert!(tree.node(func_0).is_none());
        // labels now has one child
        assert_eq!(tree.node(labels).unwrap().children.len(), 1);

        // Path to a node
        let init_node = tree.find_child_by_name(ns_id, "init").unwrap();
        let path = tree.path_to_node(init_node);
        assert_eq!(path, vec!["Classes", "MyClass", "init"]);
    }

    #[test]
    fn test_disconnected_snapshot_preserves_structure() {
        let mut tree = SymbolGTree::new();
        let root = tree.add_root_category(SymbolCategory::Functions);
        tree.add_child(
            root,
            "main",
            GTreeNodeData::Symbol {
                address: 0x401000,
                namespace: String::new(),
            },
            Some(SymbolType::Function),
        );
        tree.add_child(
            root,
            "init",
            GTreeNodeData::Symbol {
                address: 0x402000,
                namespace: String::new(),
            },
            Some(SymbolType::Function),
        );

        let snapshot = DisconnectedSymbolTreeProvider::new(&tree, "program.exe");
        assert_eq!(snapshot.program_name(), "program.exe");
        assert_eq!(snapshot.node_count(), 3);

        // Mutate the original -- snapshot is unaffected
        tree.expand_node(root);
        assert!(!snapshot.tree().node(root).unwrap().expanded);
    }
}

// ===========================================================================
// Navigation location references integration
// ===========================================================================

mod location_references_integration {
    use super::*;
    use ghidra_features::navigation::locationreferences::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_find_references_workflow() {
        let mut plugin = LocationReferencesPlugin::new();
        plugin.set_program(Some("test.exe".into()));

        // Find references to an address
        let desc = plugin.find_references_to_address(addr(0x401000)).unwrap();
        assert_eq!(desc.kind(), &DescriptorKind::Address);

        // Find references to a label
        let desc = plugin.find_references_to_label("main", addr(0x401000)).unwrap();
        assert_eq!(desc.kind(), &DescriptorKind::Label);
        assert_eq!(desc.label(), "main");

        // Find references to a data type
        let desc = plugin.find_references_to_data_type("int", addr(0x1000)).unwrap();
        assert_eq!(desc.kind(), &DescriptorKind::DataType);

        // Verify events
        assert_eq!(plugin.events().len(), 3);
    }

    #[test]
    fn test_descriptor_factory_creates_all_types() {
        let factory = DescriptorFactory::new("program.exe");

        let desc = factory.create_for_address(addr(0x401000));
        assert_eq!(desc.kind(), &DescriptorKind::Address);

        let desc = factory.create_for_label("main", addr(0x401000));
        assert_eq!(desc.kind(), &DescriptorKind::Label);

        let desc = factory.create_for_data_type("int", addr(0x1000));
        assert_eq!(desc.kind(), &DescriptorKind::DataType);

        let desc = factory.create_for_mnemonic("MOV", addr(0x1000));
        assert_eq!(desc.kind(), &DescriptorKind::Mnemonic);

        let desc = factory.create_for_operand("[EAX+0x10]", addr(0x1000));
        assert_eq!(desc.kind(), &DescriptorKind::Operand);

        let desc = factory.create_for_function_definition("my_func", addr(0x1000));
        assert_eq!(desc.kind(), &DescriptorKind::FunctionDefinition);

        let desc = factory.create_for_function_parameter_type("int", "my_func", addr(0x1000));
        assert_eq!(desc.kind(), &DescriptorKind::FunctionParameterType);

        let desc = factory.create_for_union_member("MyUnion", "field", addr(0x1000));
        assert_eq!(desc.kind(), &DescriptorKind::UnionMember);
    }

    #[test]
    fn test_provider_show_and_close_lifecycle() {
        let mut provider = LocationReferencesProvider::new();
        assert!(!provider.is_visible());

        // Show references
        let desc = LocationDescriptor::new(
            DescriptorKind::Label,
            addr(0x401000),
            "main",
            "test.exe",
        );
        provider.show_references(desc, "test.exe");
        assert!(provider.is_visible());
        assert!(provider.title().contains("main"));
        assert!(provider.highlighter().is_active());
        assert!(provider.table_model().is_some());

        // Set references
        provider.set_references(vec![
            LocationReference::with_ref_type(addr(0x402000), "CALL", false),
            LocationReference::with_ref_type(addr(0x403000), "READ", false),
        ]);
        assert_eq!(provider.table_model().unwrap().row_count(), 2);

        // Close
        provider.close();
        assert!(!provider.is_visible());
        assert!(!provider.highlighter().is_active());
    }

    #[test]
    fn test_highlighter_with_references() {
        let mut hl = LocationReferencesHighlighter::new();
        hl.set_highlight_color("BLUE");

        let mut desc = LocationDescriptor::new(
            DescriptorKind::Label,
            addr(0x401000),
            "main",
            "test.exe",
        );
        desc.set_references(vec![
            LocationReference::new(addr(0x402000)),
            LocationReference::new(addr(0x403000)),
        ]);
        hl.set_descriptor(Some(desc));

        // Should highlight at matching address
        let ranges = hl.get_highlights("call main", &addr(0x402000), "main");
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].color, "BLUE");

        // Should not highlight at non-matching address
        let ranges = hl.get_highlights("call main", &addr(0x500000), "main");
        assert!(ranges.is_empty());

        // Deactivate
        hl.deactivate();
        let ranges = hl.get_highlights("call main", &addr(0x402000), "main");
        assert!(ranges.is_empty());
    }

    #[test]
    fn test_specific_descriptor_types() {
        // GenericDataTypeLocationDescriptor
        let desc = GenericDataTypeLocationDescriptor::new(
            "int", "/BuiltIn", addr(0x1000), "test.exe",
        );
        assert_eq!(desc.data_type_name(), "int");
        assert_eq!(desc.category_path(), "/BuiltIn");

        // GenericCompositeDataTypeLocationDescriptor
        let desc =
            GenericCompositeDataTypeLocationDescriptor::new("Point", true, addr(0x1000), "test.exe");
        assert!(desc.is_structure());
        assert_eq!(desc.composite_name(), "Point");

        let desc =
            GenericCompositeDataTypeLocationDescriptor::new("Value", false, addr(0x1000), "test.exe");
        assert!(!desc.is_structure());

        // XRefLocationDescriptor
        let desc = XRefLocationDescriptor::new("CALL", addr(0x2000), "test.exe");
        assert_eq!(desc.ref_type(), "CALL");
        assert!(desc.label().contains("CALL"));

        // FunctionDefinitionLocationDescriptor
        let desc = FunctionDefinitionLocationDescriptor::new(
            "printf", addr(0x3000), "test.exe",
        );
        assert_eq!(desc.function_name(), "printf");

        // FunctionParameterTypeDescriptor
        let desc = FunctionParameterTypeDescriptor::new(
            "char*", "printf", 0, addr(0x3000), "test.exe",
        );
        assert_eq!(desc.function_name(), "printf");
        assert_eq!(desc.parameter_type(), "char*");
        assert_eq!(desc.parameter_index(), 0);

        // UnionLocationDescriptor
        let desc = UnionLocationDescriptor::new(
            "MyUnion", "value", addr(0x4000), "test.exe",
        );
        assert_eq!(desc.union_name(), "MyUnion");
        assert_eq!(desc.field_name(), "value");
    }

    #[test]
    fn test_row_mappers() {
        let lr = LocationReference::with_ref_type(addr(0x401000), "CALL", false);

        assert_eq!(LocationReferenceToAddressMapper::get_value(&lr), addr(0x401000));

        assert_eq!(
            LocationReferenceToProgramLocationMapper::get_address(&lr),
            addr(0x401000)
        );
        assert_eq!(
            LocationReferenceToProgramLocationMapper::get_ref_type(&lr),
            "CALL"
        );
    }

    #[test]
    fn test_table_model_with_references() {
        let descriptor = LocationDescriptor::new(
            DescriptorKind::Address,
            addr(0x1000),
            "main",
            "test.exe",
        );
        let mut model = LocationReferencesTableModel::new(descriptor, "test.exe");

        model.set_references(vec![
            LocationReference::with_ref_type(addr(0x2000), "READ", false),
            LocationReference::with_ref_type(addr(0x3000), "WRITE", false),
            LocationReference::with_ref_type(addr(0x4000), "CALL", false),
        ]);

        assert_eq!(model.row_count(), 3);
        assert!(model.is_loaded());

        // Access by row
        assert_eq!(model.get_address_at_row(0), Some(addr(0x2000)));
        assert_eq!(model.get_address_at_row(1), Some(addr(0x3000)));
        assert_eq!(model.get_address_at_row(2), Some(addr(0x4000)));
        assert_eq!(model.get_address_at_row(3), None);

        // Reload
        model.request_reload();
        assert!(!model.is_loaded());
        assert_eq!(model.row_count(), 0);
    }
}

// ===========================================================================
// Hover service integration
// ===========================================================================

mod hover_integration {
    use ghidra_features::codebrowser::hover::*;

    #[test]
    fn test_hover_registry_workflow() {
        let mut registry = HoverServiceRegistry::new();
        assert!(registry.is_empty());

        // Register all hover services
        registry.register(Box::new(DataTypeListingHover));
        registry.register(Box::new(FunctionSignatureListingHover));
        registry.register(Box::new(LabelListingHover));
        registry.register(Box::new(ReferenceListingHover));
        registry.register(Box::new(ScalarOperandListingHover));
        registry.register(Box::new(TruncatedTextListingHover));
        registry.register(Box::new(ProgramAddressRelationshipListingHover));

        assert_eq!(registry.len(), 7);

        let names = registry.service_names();
        assert!(names.contains(&"DataTypeListingHover"));
        assert!(names.contains(&"TruncatedTextListingHover"));

        // Query with text context
        let ctx = HoverContext {
            text: Some("int main() { ... }".into()),
            ..Default::default()
        };
        // TruncatedTextListingHover returns the text
        let text = registry.get_hover_text(&ctx);
        assert_eq!(text, Some("int main() { ... }".into()));

        // Remove a service
        assert!(registry.remove("LabelListingHover"));
        assert_eq!(registry.len(), 6);
        assert!(!registry.remove("NonExistent"));
    }

    #[test]
    fn test_hover_context_fields() {
        let ctx = HoverContext {
            program: Some("test.exe".into()),
            address: Some("0x401000".into()),
            text: Some("MOV EAX, [EBP-0x8]".into()),
            cursor_text_offset: 4,
            field_name: Some("Operand".into()),
        };
        assert_eq!(ctx.program.as_deref(), Some("test.exe"));
        assert_eq!(ctx.cursor_text_offset, 4);
    }
}

// ===========================================================================
// Function tag provider integration
// ===========================================================================

mod function_tags_integration {
    use ghidra_features::base::function::tags::*;
    use ghidra_features::base::function::tags_ui::*;

    #[test]
    fn test_full_tag_workflow() {
        let mut manager = FunctionTagManager::new();

        // Create tags
        let decompiled_id = manager.create_tag("decompiled");
        let library_id = manager.create_tag("library");
        let dangerous_id = manager.create_tag("dangerous");

        // Assign tags to functions
        manager.add_tag_to_function(0x401000, decompiled_id);
        manager.add_tag_to_function(0x401000, library_id);
        manager.add_tag_to_function(0x402000, dangerous_id);

        // Verify
        let tags_401000 = manager.tags_for_function(0x401000);
        assert_eq!(tags_401000.len(), 2);

        let tags_402000 = manager.tags_for_function(0x402000);
        assert_eq!(tags_402000.len(), 1);
        assert_eq!(tags_402000[0].name(), "dangerous");

        // Create provider model
        let mut provider = FunctionTagProviderModel::new();
        provider.set_current_function(&manager, Some(0x401000));

        // Target panel should have decompiled and library
        assert_eq!(provider.target_panel.inner.tag_count(), 2);

        // Source panel should have dangerous
        assert_eq!(provider.source_panel.inner.tag_count(), 1);

        // Add source tag to function
        provider.source_panel.inner.set_selected_indices(vec![0]);
        provider.update_buttons();
        assert!(provider.button_panel.is_add_enabled());

        let added = provider
            .source_panel
            .add_selected_tags(&mut manager, 0x401000);
        assert_eq!(added, 1);

        // Now function has all 3 tags
        assert_eq!(manager.tags_for_function(0x401000).len(), 3);

        // Remove a tag
        provider.target_panel.inner.set_selected_indices(vec![0]);
        provider.update_buttons();
        assert!(provider.button_panel.is_remove_enabled());

        let removed = provider
            .target_panel
            .remove_selected_tags(&mut manager, 0x401000);
        assert_eq!(removed, 1);
    }

    #[test]
    fn test_function_tag_table_model_integration() {
        let mut model = FunctionTagTableModel::new();

        model.add_row(FunctionTagRowObject::new(
            0x401000,
            "main",
            vec![FunctionTag::new(1, "decompiled")],
        ));
        model.add_row(FunctionTagRowObject::new(
            0x402000,
            "init",
            vec![
                FunctionTag::new(1, "decompiled"),
                FunctionTag::new(2, "library"),
            ],
        ));

        assert_eq!(model.row_count(), 2);
        assert_eq!(model.get_value_at(0, 0), Some("main".into()));
        assert_eq!(model.get_value_at(1, 2), Some("decompiled, library".into()));

        // Remove a row
        model.remove_row(0);
        assert_eq!(model.row_count(), 1);
        assert_eq!(model.get_value_at(0, 0), Some("init".into()));
    }
}

// ===========================================================================
// Cross-module integration: location references + symbol tree
// ===========================================================================

mod cross_module_integration {
    use super::*;
    use ghidra_features::navigation::locationreferences::*;
    use ghidra_features::symboltree::gtree::{GTreeNodeData, SymbolGTree};
    use ghidra_features::symboltree::{SymbolCategory, SymbolType};

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_symbol_tree_with_location_references() {
        // Build a symbol tree
        let mut tree = SymbolGTree::new();
        let funcs = tree.add_root_category(SymbolCategory::Functions);
        let main_id = tree
            .add_child(
                funcs,
                "main",
                GTreeNodeData::Symbol {
                    address: 0x401000,
                    namespace: String::new(),
                },
                Some(SymbolType::Function),
            )
            .unwrap();

        // Create location reference for the symbol
        let mut plugin = LocationReferencesPlugin::new();
        plugin.set_program(Some("test.exe".into()));
        let desc = plugin
            .find_references_to_label("main", addr(0x401000))
            .unwrap();
        assert_eq!(desc.kind(), &DescriptorKind::Label);

        // The tree node and the descriptor refer to the same address
        let tree_node = tree.node(main_id).unwrap();
        match &tree_node.data {
            GTreeNodeData::Symbol { address, .. } => {
                assert_eq!(*address, desc.home_address().offset);
            }
            _ => panic!("Expected Symbol data"),
        }
    }
}
