//! Integration tests for the newly ported call tree node types and
//! query/table panel abstractions.
//!
//! These tests verify the Rust port of the following Java types that were
//! previously missing:
//!
//! - `TraceCallTreeCallNode` (gui/tracecalltree)
//! - `TraceCallTreeExternalNode` (gui/tracecalltree)
//! - `TraceCallTreeReturnNode` (gui/tracecalltree)
//! - `TraceCallTreeTailCallNode` (gui/tracecalltree)
//! - `AbstractObjectsTableBasedPanel` (gui/model)
//! - `AbstractQueryTablePanel` (gui/model)
//!
//! The call tree nodes represent different kinds of entries in Ghidra's call
//! tree view. The table panel models provide the data model for the
//! query-driven tables used throughout the debugger GUI.

#[cfg(test)]
mod tests {
    use crate::plugin::gui_calltree_ext::{
        AnyCallTreeNode, CallTreeNodeKind, ParamNameToBytes, TraceCallTreeCallNode,
        TraceCallTreeExternalNode, TraceCallTreeModel, TraceCallTreeNode,
        TraceCallTreeReturnNode, TraceCallTreeTailCallNode,
    };
    use crate::plugin::gui_panel_models::{
        DebuggerCoordinates,
        ObjectValueRef, ObjectsTableBasedPanelModel, QueryTablePanelModel,
    };

    // ========================================================================
    // End-to-end call tree workflow
    // ========================================================================

    #[test]
    fn test_full_call_tree_workflow() {
        // Simulate a call tree from a trace:
        //   main() -> printf() [external] -> return printf -> return main
        let mut model = TraceCallTreeModel::new();

        // Step 1: main calls printf
        let main_node = TraceCallTreeCallNode::new(
            "main", "a.out", 0,
            vec![ParamNameToBytes::new("argc", vec![0x01, 0x00, 0x00, 0x00])],
            None,
        );
        let main_tree = TraceCallTreeNode::new(
            0, CallTreeNodeKind::Call, &main_node.name, 0x400000, 0, 0,
        );
        let main_id = model.add_root(main_tree);
        assert_eq!(model.roots().len(), 1);

        // Step 2: printf is external
        let ext_node = TraceCallTreeExternalNode::new(
            "printf", "libc.so.6", 1,
            vec![
                ParamNameToBytes::new("fmt", vec![0x48, 0x65, 0x6C, 0x6C, 0x6F]),
                ParamNameToBytes::new("arg1", vec![0x57, 0x6F, 0x72, 0x6C, 0x64]),
            ],
            Some(vec![0x05, 0x00, 0x00, 0x00]),
        );
        assert_eq!(ext_node.tree_data(), "External: printf");
        assert_eq!(ext_node.parameter_count(), 2);
        assert_eq!(ext_node.return_val_string(), "Return: 05000000");

        let ext_tree = TraceCallTreeNode::new(
            0, CallTreeNodeKind::External, ext_node.tree_data(), 0x7FFE0000, 1, 0,
        );
        let ext_id = model.add_child(main_id, ext_tree).unwrap();

        // Step 3: Return from printf
        let ret_node = TraceCallTreeReturnNode::new(
            "printf", "libc.so.6", 2, vec![], Some(vec![0x05]),
        );
        assert_eq!(ret_node.tree_data(), "Return: printf");

        let ret_tree = TraceCallTreeNode::new(
            0, CallTreeNodeKind::Return, ret_node.tree_data(), 0x7FFE0000, 1, 0,
        );
        model.add_child(ext_id, ret_tree);

        // Verify the tree structure
        assert_eq!(model.node_count(), 3);
        assert_eq!(model.max_depth(), 1);

        let main = model.get_node(main_id).unwrap();
        assert_eq!(main.function_name, "main");
        assert_eq!(main.child_count(), 1);
        assert!(!main.is_leaf());
        assert!(main.parent_id.is_none());

        let ext = model.get_node(ext_id).unwrap();
        assert!(ext.function_name.starts_with("External:"));
        assert_eq!(ext.parent_id, Some(main_id));
    }

    #[test]
    fn test_tail_call_in_call_tree() {
        let mut model = TraceCallTreeModel::new();

        // A function does a tail call to another
        let caller = TraceCallTreeCallNode::new("process_request", "server", 0, vec![], None);
        let caller_tree = TraceCallTreeNode::new(
            0, CallTreeNodeKind::Call, &caller.name, 0x10000, 0, 0,
        );
        let caller_id = model.add_root(caller_tree);

        let tail = TraceCallTreeTailCallNode::new(
            "handle_response", "server", 1,
            vec![ParamNameToBytes::new("req", vec![0xFF, 0xFE])],
            None,
        );
        assert_eq!(tail.tree_data(), "Tail Call: handle_response");
        assert_eq!(tail.parameter_count(), 1);
        assert_eq!(tail.parameter_string(0), "req: fffe");

        let tail_tree = TraceCallTreeNode::new(
            0, CallTreeNodeKind::TailCall, tail.tree_data(), 0x10100, 1, 0,
        );
        let tail_id = model.add_child(caller_id, tail_tree).unwrap();

        assert_eq!(model.node_count(), 2);
        let tail_get = model.get_node(tail_id).unwrap();
        assert!(tail_get.function_name.starts_with("Tail Call:"));
    }

    // ========================================================================
    // AnyCallTreeNode enum dispatch
    // ========================================================================

    #[test]
    fn test_any_call_node_dispatch_all_variants() {
        let nodes = vec![
            AnyCallTreeNode::Call(TraceCallTreeCallNode::new("f1", "m1", 0, vec![], None)),
            AnyCallTreeNode::External(TraceCallTreeExternalNode::new("f2", "m2", 1, vec![], None)),
            AnyCallTreeNode::Return(TraceCallTreeReturnNode::new("f3", "m3", 2, vec![], None)),
            AnyCallTreeNode::TailCall(TraceCallTreeTailCallNode::new("f4", "m4", 3, vec![], None)),
        ];

        let kinds = [
            CallTreeNodeKind::Call,
            CallTreeNodeKind::External,
            CallTreeNodeKind::Return,
            CallTreeNodeKind::TailCall,
        ];

        for (i, node) in nodes.iter().enumerate() {
            assert_eq!(node.name(), format!("f{}", i + 1));
            assert_eq!(node.module(), format!("m{}", i + 1));
            assert_eq!(node.snap_key(), i as i64);
            assert_eq!(node.kind(), kinds[i]);
        }
    }

    #[test]
    fn test_any_call_node_tree_data_format() {
        assert_eq!(
            AnyCallTreeNode::Call(TraceCallTreeCallNode::new("foo", "m", 0, vec![], None))
                .tree_data(),
            "foo"
        );
        assert_eq!(
            AnyCallTreeNode::External(TraceCallTreeExternalNode::new("bar", "m", 0, vec![], None))
                .tree_data(),
            "External: bar"
        );
        assert_eq!(
            AnyCallTreeNode::Return(TraceCallTreeReturnNode::new("baz", "m", 0, vec![], None))
                .tree_data(),
            "Return: baz"
        );
        assert_eq!(
            AnyCallTreeNode::TailCall(TraceCallTreeTailCallNode::new("qux", "m", 0, vec![], None))
                .tree_data(),
            "Tail Call: qux"
        );
    }

    #[test]
    fn test_any_call_node_return_val_formatting() {
        // With return value
        let with_ret = AnyCallTreeNode::Call(TraceCallTreeCallNode::new(
            "malloc", "libc", 0, vec![], Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        ));
        assert_eq!(with_ret.return_val_string(), "Return: deadbeef");

        // Without return value
        let no_ret = AnyCallTreeNode::External(TraceCallTreeExternalNode::new(
            "puts", "libc", 0, vec![], None,
        ));
        assert_eq!(no_ret.return_val_string(), "");
    }

    // ========================================================================
    // ParamNameToBytes comprehensive tests
    // ========================================================================

    #[test]
    fn test_param_bytes_various_sizes() {
        let p1 = ParamNameToBytes::new("byte", vec![0xFF]);
        assert_eq!(p1.display_string(), "byte: ff");

        let p4 = ParamNameToBytes::new("dword", vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(p4.display_string(), "dword: 01020304");

        let p8 = ParamNameToBytes::new("qword", vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(p8.display_string(), "qword: 0000000000000001");

        let p0 = ParamNameToBytes::new("void", vec![]);
        assert_eq!(p0.display_string(), "void: ");
    }

    #[test]
    fn test_param_bytes_clone() {
        let original = ParamNameToBytes::new("x", vec![1, 2, 3]);
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    // ========================================================================
    // DebuggerCoordinates tests
    // ========================================================================

    #[test]
    fn test_coordinates_lifecycle() {
        // Start with nowhere
        let mut coords = DebuggerCoordinates::nowhere();
        assert!(!coords.is_valid());

        // Navigate to a trace
        coords = DebuggerCoordinates {
            trace_key: Some(1),
            snap: 0,
            thread_key: None,
            process_key: None,
        };
        assert!(coords.is_valid());

        // Select a thread
        coords.thread_key = Some(5);
        assert_eq!(coords.thread_key, Some(5));

        // Advance time
        coords.snap = 10;
        assert_eq!(coords.snap, 10);
    }

    // ========================================================================
    // QueryTablePanelModel comprehensive tests
    // ========================================================================

    #[test]
    fn test_query_table_model_full_workflow() {
        let mut model = QueryTablePanelModel::new();

        // Populate with data
        model.set_rows(vec![
            "libc.so".to_string(),
            "libpthread.so".to_string(),
            "a.out".to_string(),
            "ld-linux.so".to_string(),
        ]);
        assert_eq!(model.visible_count(), 4);

        // Filter by "lib"
        model.set_filter("lib".to_string());
        assert_eq!(model.visible_count(), 2);
        assert_eq!(model.visible_row(0), Some(&"libc.so".to_string()));
        assert_eq!(model.visible_row(1), Some(&"libpthread.so".to_string()));

        // Change coordinates
        model.set_coordinates(DebuggerCoordinates {
            trace_key: Some(1),
            snap: 5,
            thread_key: Some(2),
            process_key: Some(10),
        });
        assert!(model.current.is_valid());
        assert_eq!(model.current.snap, 5);

        // Clear filter
        model.set_filter(String::new());
        assert_eq!(model.visible_count(), 4);

        // Set rows again (e.g., after trace update)
        model.set_rows(vec!["new_lib.so".to_string()]);
        assert_eq!(model.visible_count(), 1);
        assert_eq!(model.rows.len(), 1);
    }

    #[test]
    fn test_query_table_model_filter_case_insensitive() {
        let mut model = QueryTablePanelModel::new();
        model.set_rows(vec![
            "Alpha".to_string(),
            "BETA".to_string(),
            "gamma".to_string(),
        ]);

        model.set_filter("alpha".to_string());
        assert_eq!(model.visible_count(), 1);

        model.set_filter("BETA".to_string());
        assert_eq!(model.visible_count(), 1);

        model.set_filter("Gamma".to_string());
        assert_eq!(model.visible_count(), 1);
    }

    // ====================================================================
    // ObjectsTableBasedPanelModel comprehensive tests
    // ====================================================================

    #[test]
    fn test_objects_table_panel_full_workflow() {
        let mut model = ObjectsTableBasedPanelModel::<String>::new(Some("Thread".into()));

        // Verify initial state
        assert!(!model.has_selection());
        assert_eq!(model.obj_type_filter, Some("Thread".into()));
        assert!(model.limit_to_snap);
        assert!(!model.show_hidden);

        // Add some selections
        model.set_selected_objects(vec![
            ObjectValueRef::new(vec!["Threads".into(), "1".into()], true, "Thread"),
            ObjectValueRef::new(vec!["Threads".into(), "2".into()], true, "Thread"),
            ObjectValueRef::new(vec!["Processes".into(), "1".into()], true, "Process"),
        ]);

        assert!(model.has_selection());

        // Filter by type
        let matching = model.selected_matching_type();
        assert_eq!(matching.len(), 2);
        assert!(matching.iter().all(|r| r.type_name == "Thread"));

        // Change filter
        model.set_type_filter(Some("Process".into()));
        let matching = model.selected_matching_type();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].type_name, "Process");

        // Remove filter
        model.set_type_filter(None);
        let matching = model.selected_matching_type();
        assert_eq!(matching.len(), 3); // All is_object=true entries
    }

    #[test]
    fn test_objects_table_panel_non_object_values_filtered() {
        let mut model = ObjectsTableBasedPanelModel::<String>::new(None);
        model.set_selected_objects(vec![
            ObjectValueRef::new(vec!["val".into()], false, "int"),
            ObjectValueRef::new(vec!["obj".into()], true, "Thread"),
        ]);

        // Non-object values are filtered out
        let matching = model.selected_matching_type();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].type_name, "Thread");
    }

    #[test]
    fn test_object_value_ref_various_types() {
        let types = ["Process", "Thread", "Module", "MemoryRegion", "StackFrame"];
        for t in &types {
            let obj_ref = ObjectValueRef::new(vec!["root".into()], true, *t);
            assert_eq!(obj_ref.type_name, *t);
            assert!(obj_ref.is_object);
        }
    }

    // ====================================================================
    // Cross-module integration: call tree + panel model
    // ====================================================================

    #[test]
    fn test_call_tree_panel_integration() {
        // Build a call tree model
        let mut tree_model = TraceCallTreeModel::new();

        let main = TraceCallTreeNode::new(0, CallTreeNodeKind::Call, "main", 0x400000, 0, 0);
        let main_id = tree_model.add_root(main);

        let ext = TraceCallTreeNode::new(
            0, CallTreeNodeKind::External, "External: printf", 0x7FFF0000, 1, 0,
        );
        let ext_id = tree_model.add_child(main_id, ext).unwrap();

        let tail = TraceCallTreeNode::new(
            0, CallTreeNodeKind::TailCall, "Tail Call: optimized", 0x7FFE0000, 1, 0,
        );
        tree_model.add_child(main_id, tail);

        let ret = TraceCallTreeNode::new(
            0, CallTreeNodeKind::Return, "Return: printf", 0x7FFF0000, 1, 0,
        );
        tree_model.add_child(ext_id, ret);

        // Use query panel to display tree nodes as rows
        let mut panel: QueryTablePanelModel<String> = QueryTablePanelModel::new();
        let rows: Vec<String> = tree_model
            .all_nodes()
            .iter()
            .map(|n| format!("[{:?}] {}", n.kind, n.function_name))
            .collect();
        panel.set_rows(rows);
        assert_eq!(panel.visible_count(), 4);

        // Filter for external calls only
        panel.set_filter("External".to_string());
        assert_eq!(panel.visible_count(), 1);
    }

    #[test]
    fn test_objects_panel_with_coordinates() {
        let mut panel = ObjectsTableBasedPanelModel::<String>::new(None);

        // Set coordinates (simulating trace navigation)
        panel.table.set_coordinates(DebuggerCoordinates {
            trace_key: Some(1),
            snap: 0,
            thread_key: Some(1),
            process_key: Some(100),
        });
        assert!(panel.table.current.is_valid());

        // Add some rows
        panel.table.set_rows(vec![
            "Thread[1]".to_string(),
            "Thread[2]".to_string(),
            "Process[100]".to_string(),
        ]);
        assert_eq!(panel.table.visible_count(), 3);

        // Advance snap
        panel.table.current.snap = 5;
        assert_eq!(panel.table.current.snap, 5);
    }
}
