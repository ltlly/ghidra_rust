//! Integration tests for the remaining Debug modules ported from Java.
//!
//! These tests exercise the new modules that were ported from:
//! - Debugger-api: TraceRmiConnection, MapEntry, MappedAddressRange, etc.
//! - Framework-TraceModeling model: equate ops, code ops, module ops,
//!   bookmark ops, reference ops, register context ops, symbol types
//! - Framework-TraceModeling db: equate space, visitors, address property
//!   manager, program view, value storage

#[cfg(test)]
mod tests {
    use crate::api::trace_rmi_connection::*;
    use crate::model::bookmark::TraceBookmarkType;
    use crate::model::bookmark_ops::*;
    use crate::model::code_ops::*;
    use crate::model::equate_ops::*;
    use crate::model::module_ops::*;
    use crate::model::reference_ops::*;
    use crate::model::register_context_ops::*;
    use crate::model::symbol::{TraceEquate, TraceEquateReference, TraceReferenceKind};
    use crate::model::symbol_types::*;
    use crate::model::Lifespan;
    use crate::db::trace_db_visitors::*;
    use crate::db::trace_db_value_storage::*;
    use crate::target::KeyPath;

    // === Debugger-api: TraceRmiConnection ===

    #[test]
    fn test_rmi_connection_lifecycle() {
        let mut conn = TraceRmiConnection::new("localhost:18001", "test-conn-1");
        assert!(!conn.is_connected());
        assert_eq!(conn.connection_id, "test-conn-1");

        conn.register_method(
            RemoteMethod::new("launch")
                .with_parameter(RemoteParameter::new("cmd", "string", true))
                .with_description("Launch a debug session"),
        );

        conn.set_connected(true);
        assert!(conn.is_connected());
        assert!(conn.get_method("launch").is_some());
        assert!(conn.get_method("nonexistent").is_none());
    }

    #[test]
    fn test_rmi_error_handling() {
        let err = TraceRmiError::new("ConnectionError", "Connection refused")
            .with_stack_trace("at DebugClient.connect:42");
        assert_eq!(err.error_type, "ConnectionError");
        assert!(err.stack_trace.is_some());
        assert!(format!("{}", err).contains("Connection refused"));
    }

    #[test]
    fn test_rmi_launch_offer() {
        let offer = TraceRmiLaunchOffer::new("GDB Remote", "gdb")
            .with_description("Connect to a GDB remote target")
            .with_parameter(RemoteParameter::new("host", "string", true))
            .with_parameter(
                RemoteParameter::new("port", "number", false)
                    .with_default(serde_json::json!(23946)),
            );

        assert_eq!(offer.scheme, "gdb");
        assert_eq!(offer.parameters.len(), 2);
        assert!(offer.parameters[0].required);
        assert!(!offer.parameters[1].required);
    }

    #[test]
    fn test_terminal_session() {
        let mut session = TerminalSession::new("gdb-session");
        session.set_active(true);
        session.add_to_history("break main");
        session.add_to_history("run");
        session.add_to_history("continue");

        assert_eq!(session.last_command(), Some("continue"));
        assert_eq!(session.history.len(), 3);
    }

    #[test]
    fn test_remote_method_registry() {
        let mut registry = RemoteMethodRegistry::new();
        registry.register(RemoteMethod::new("launch"));
        registry.register(RemoteMethod::new("resume"));
        registry.register(RemoteMethod::new("step"));

        assert_eq!(registry.len(), 3);
        assert!(!registry.is_empty());

        let mut names = registry.method_names();
        names.sort();
        assert_eq!(names, vec!["launch", "resume", "step"]);
    }

    // === Model: Equate Operations ===

    #[test]
    fn test_equate_space_full_workflow() {
        let mut space = TraceEquateSpace::new("ram");
        space.add_equate(TraceEquate::new(1, "EINVAL", 22, Lifespan::span(0, 100)));
        space.add_equate(TraceEquate::new(2, "ENOMEM", 12, Lifespan::span(0, 100)));

        // Add references
        space.add_reference(TraceEquateReference {
            equate_key: 1,
            address: 0x4000,
            operand_index: 0,
            lifespan: Lifespan::span(0, 50),
        });
        space.add_reference(TraceEquateReference {
            equate_key: 2,
            address: 0x4004,
            operand_index: 1,
            lifespan: Lifespan::span(0, 50),
        });

        assert_eq!(space.equate_count(), 2);
        assert_eq!(space.get_references_at(0x4000).len(), 1);
        assert_eq!(space.get_references_at_operand(0x4004, 1).len(), 1);

        // Clear references in range
        space.clear_references(&Lifespan::span(25, 30), &[0x4000]);
        assert_eq!(space.get_references_at(0x4000).len(), 0);
        assert_eq!(space.get_references_at(0x4004).len(), 1);
    }

    // === Model: Code Operations ===

    #[test]
    fn test_code_space_manager_multi_space() {
        let mut mgr = TraceCodeSpaceManager::new();

        mgr.add_unit(crate::model::TraceCodeUnit::instruction(
            1,
            0x1000,
            "ram",
            Lifespan::span(0, 100),
            4,
            "MOV",
            vec![0x89, 0xc3],
        ));
        mgr.add_unit(crate::model::TraceCodeUnit::data(
            2,
            0x2000,
            "ram",
            Lifespan::span(0, 100),
            8,
            "QWORD",
            vec![0; 8],
        ));
        mgr.add_unit(crate::model::TraceCodeUnit::instruction(
            3,
            0,
            "register",
            Lifespan::span(0, 100),
            4,
            "REG",
            vec![0; 4],
        ));

        assert!(mgr.get_space("ram").is_some());
        assert!(mgr.get_space("register").is_some());
        assert_eq!(mgr.get_space("ram").unwrap().len(), 2);
        assert_eq!(mgr.get_space("register").unwrap().len(), 1);
    }

    // === Model: Module Operations ===

    #[test]
    fn test_module_space_full_workflow() {
        let space = ModuleSpaceBuilder::new("ram")
            .add_module(
                "/usr/lib/libc.so.6",
                "libc.so.6",
                0x7f00_0000,
                0x7f02_0000,
                Lifespan::span(0, 100),
            )
            .add_section("/usr/lib/libc.so.6", ".text", 0x7f00_1000, 0x7f01_0000)
            .add_section("/usr/lib/libc.so.6", ".data", 0x7f01_1000, 0x7f01_8000)
            .add_section("/usr/lib/libc.so.6", ".bss", 0x7f01_9000, 0x7f02_0000)
            .add_module(
                "/usr/lib/libpthread.so.0",
                "libpthread.so.0",
                0x7f03_0000,
                0x7f04_0000,
                Lifespan::span(10, 100),
            )
            .add_section("/usr/lib/libpthread.so.0", ".text", 0x7f03_1000, 0x7f03_8000)
            .build();

        assert_eq!(space.get_all_modules().len(), 2);
        assert_eq!(space.get_loaded_modules(0).len(), 1);
        assert_eq!(space.get_loaded_modules(50).len(), 2);
        assert_eq!(space.sections_for_module(1).len(), 3);
        assert_eq!(space.sections_for_module(2).len(), 1);

        let ops: &dyn TraceModuleOperations = &space;
        assert_eq!(ops.get_modules_at(50, 0x7f01_0000).len(), 1);
    }

    // === Model: Bookmark Operations ===

    #[test]
    fn test_bookmark_space_manager_full_workflow() {
        let mut mgr = TraceBookmarkSpaceManager::new();
        mgr.add_bookmark(
            "ram",
            Lifespan::span(0, 50),
            0x4000,
            TraceBookmarkType::Note,
            "analysis",
            "Entry point",
        );
        mgr.add_bookmark(
            "ram",
            Lifespan::span(0, 50),
            0x4100,
            TraceBookmarkType::Warning,
            "warnings",
            "Unresolved symbol",
        );
        mgr.add_bookmark(
            "register",
            Lifespan::span(0, 50),
            0,
            TraceBookmarkType::Note,
            "reg",
            "PC bookmark",
        );

        assert_eq!(mgr.get_all_bookmarks().len(), 3);
        assert!(mgr.get_space("ram").is_some());
        assert!(mgr.get_space("register").is_some());

        let ram_space = mgr.get_space("ram").unwrap();
        assert_eq!(ram_space.get_bookmarks_at(25, 0x4000).len(), 1);
    }

    // === Model: Reference Operations ===

    #[test]
    fn test_reference_space_full_workflow() {
        let mut space = TraceReferenceSpace::new("ram");

        // Add memory references
        space.add_memory_reference(
            Lifespan::span(0, 100),
            0x4000,
            0x4100,
            0x4100,
            TraceReferenceKind::Memory,
            true,
            0,
        );
        space.add_memory_reference(
            Lifespan::span(0, 100),
            0x4004,
            0x4200,
            0x4200,
            TraceReferenceKind::Memory,
            false,
            0,
        );

        // Add stack reference
        space.add_stack_reference(
            Lifespan::span(0, 100),
            0x4008,
            -8,
            TraceReferenceKind::Stack,
            true,
            0,
        );

        // Add offset reference
        space.add_offset_reference(
            Lifespan::span(0, 100),
            0x4010,
            0x5000,
            true,
            0x10,
            TraceReferenceKind::Offset,
            false,
            0,
        );

        // Queries
        assert_eq!(space.get_references_from(50, 0x4000).len(), 1);
        assert!(space.has_references_from(50, 0x4000));
        assert!(!space.has_references_from(150, 0x4000));
        assert!(space.has_references_to(50, 0x4100));
        assert_eq!(space.get_reference_count_from(50, 0x4000), 1);

        // Sources and destinations (only memory references counted)
        let sources = space.get_reference_sources(&Lifespan::span(0, 100));
        assert_eq!(sources.len(), 2);
    }

    // === Model: Register Context Operations ===

    #[test]
    fn test_register_context_full_workflow() {
        let mut space = TraceRegisterContextSpace::new("ram");

        // Set context values
        space.set_value(
            Lifespan::span(0, 100),
            0x1000,
            0x2000,
            "TMode",
            1,
            1,
        );
        space.set_value(
            Lifespan::span(0, 100),
            0x1000,
            0x2000,
            "ISAMode",
            0,
            1,
        );

        // Query
        assert_eq!(space.get_value(50, 0x1500, "TMode"), Some(1));
        assert_eq!(space.get_value(50, 0x1500, "ISAMode"), Some(0));

        let values = space.get_all_values(50, 0x1500);
        assert_eq!(values.len(), 2);

        let mut names = space.register_names();
        names.sort();
        assert_eq!(names, vec!["ISAMode", "TMode"]);

        // Clear
        space.clear_value(&Lifespan::span(50, 60), 0x1500, 0x1800, "TMode");
        assert!(space.get_value(50, 0x1500, "TMode").is_none());
        assert_eq!(space.get_value(50, 0x1500, "ISAMode"), Some(0));
    }

    // === Model: Symbol Types ===

    #[test]
    fn test_symbol_hierarchy() {
        let mut global_ns = TraceNamespaceSymbol::new(1, "Global", None, Lifespan::span(0, 100));
        let mut libc_ns = TraceNamespaceSymbol::new(2, "libc", Some(1), Lifespan::span(0, 100));
        let class = TraceClassSymbol::new(3, "MyClass", Some(2), Lifespan::span(0, 100));
        let label = TraceLabelSymbol::new(4, "main", 0x4000, "ram", Lifespan::span(0, 100));

        global_ns.add_child(2);
        libc_ns.add_child(3);

        assert!(global_ns.is_global());
        assert!(!libc_ns.is_global());
        assert_eq!(global_ns.child_count(), 1);
        assert_eq!(libc_ns.child_count(), 1);
        assert_eq!(class.name(), "MyClass");
        assert_eq!(label.name(), "main");
        assert_eq!(label.address(), Some(0x4000));
    }

    // === DB: Visitors ===

    #[test]
    fn test_visitor_traversal_comprehensive() {
        let root = KeyPath::new(vec![]);
        let traversal = TreeTraversal::downward(root.clone());

        let children_map: std::collections::HashMap<KeyPath, Vec<KeyPath>> = vec![
            (
                root.clone(),
                vec![
                    KeyPath::of(&["process"]),
                    KeyPath::of(&["threads"]),
                ],
            ),
            (
                KeyPath::of(&["process"]),
                vec![
                    KeyPath::of(&["process", "memory"]),
                    KeyPath::of(&["process", "modules"]),
                ],
            ),
            (KeyPath::of(&["threads"]), vec![KeyPath::of(&["threads", "0"])]),
            (KeyPath::of(&["process", "memory"]), vec![]),
            (KeyPath::of(&["process", "modules"]), vec![]),
            (KeyPath::of(&["threads", "0"]), vec![]),
        ]
        .into_iter()
        .collect();

        let mut visitor = AllPathsVisitor::new();
        traversal.traverse(&mut visitor, |path| {
            children_map.get(path).cloned().unwrap_or_default()
        });
        let result = visitor.finish();
        assert_eq!(result.len(), 6);
    }

    // === DB: Value Storage ===

    #[test]
    fn test_value_storage_comprehensive() {
        let mut space = ValueSpace::<String>::new("ram");

        // Insert values
        space.insert(
            ImmutableValueShape::new("ram", 0x1000, 0x1000, Lifespan::span(0, 50)),
            "code".to_string(),
        );
        space.insert(
            ImmutableValueShape::new("ram", 0x2000, 0x2FFF, Lifespan::span(0, 50)),
            "data".to_string(),
        );

        assert_eq!(space.len(), 2);
        assert_eq!(space.get(0x1000, 25), Some(&"code".to_string()));
        assert_eq!(space.get(0x2000, 25), Some(&"data".to_string()));

        let results = space.get_intersecting(0x500, 0x2500, &Lifespan::span(0, 50));
        assert_eq!(results.len(), 2);

        // Remove overlapping
        space.remove_overlapping(&ImmutableValueShape::new(
            "ram",
            0x1000,
            0x1500,
            Lifespan::span(25, 75),
        ));
        assert_eq!(space.len(), 1);
    }

    #[test]
    fn test_value_triple_commit_workflow() {
        let shape = ImmutableValueShape::point("ram", 0x4000, 10);
        let mut triple = ValueTriple::new(shape, "original".to_string());

        assert_eq!(triple.latest(), Some(&"original".to_string()));
        assert!(!triple.is_dirty());

        // Simulate a write-behind cache update
        triple.cached = Some("modified".to_string());
        assert!(triple.is_dirty());
        assert_eq!(triple.latest(), Some(&"modified".to_string()));

        // Commit
        triple.commit();
        assert!(!triple.is_dirty());
        assert_eq!(triple.committed, Some("modified".to_string()));
        assert!(triple.cached.is_none());
    }

    // === Cross-module integration test ===

    #[test]
    fn test_cross_module_integration() {
        // Create a trace-like structure using multiple modules

        // 1. Code listing
        let mut code_space = TraceCodeSpace::new("ram");
        code_space.add_unit(crate::model::TraceCodeUnit::instruction(
            1,
            0x4000,
            "ram",
            Lifespan::span(0, 100),
            5,
            "CALL",
            vec![0xe8, 0x00, 0x00, 0x00, 0x00],
        ));

        // 2. References
        let mut ref_space = TraceReferenceSpace::new("ram");
        ref_space.add_memory_reference(
            Lifespan::span(0, 100),
            0x4000,
            0x4100,
            0x4100,
            TraceReferenceKind::Memory,
            true,
            0,
        );

        // 3. Equates
        let mut equate_space = TraceEquateSpace::new("ram");
        equate_space.add_equate(TraceEquate::new(1, "MY_FUNC", 0x4100, Lifespan::span(0, 100)));
        equate_space.add_reference(TraceEquateReference {
            equate_key: 1,
            address: 0x4000,
            operand_index: 0,
            lifespan: Lifespan::span(0, 100),
        });

        // 4. Bookmarks
        let mut bm_space = TraceBookmarkSpace::new("ram");
        bm_space.add_bookmark(
            Lifespan::span(0, 100),
            0x4000,
            TraceBookmarkType::Note,
            "analysis",
            "Important call",
        );

        // 5. Modules
        let mod_space = ModuleSpaceBuilder::new("ram")
            .add_module(
                "/bin/app",
                "app",
                0x4000,
                0x5000,
                Lifespan::span(0, 100),
            )
            .add_section("/bin/app", ".text", 0x4000, 0x4800)
            .build();

        // Verify everything is connected
        assert_eq!(code_space.len(), 1);
        assert_eq!(ref_space.get_references_from(50, 0x4000).len(), 1);
        assert!(equate_space.get_equate_by_name("MY_FUNC").is_some());
        assert_eq!(bm_space.get_bookmarks_at(50, 0x4000).len(), 1);
        assert_eq!(mod_space.get_all_modules().len(), 1);
        assert_eq!(mod_space.sections.len(), 1);

        // Cross-reference: find the call target
        let refs = ref_space.get_references_from(50, 0x4000);
        assert_eq!(refs[0].to_address, 0x4100);

        // Check if the target is in the module
        let modules = mod_space.get_modules_at(50, 0x4100);
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].module_name, "app");
    }
}
