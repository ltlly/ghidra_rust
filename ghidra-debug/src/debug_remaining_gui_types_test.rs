//! Integration tests for the remaining GUI data model types ported from
//! Ghidra's Debugger module.
//!
//! These tests verify the Rust port of the following Java types:
//!
//! - `EvaluationException`, `UnwindException` (stack exceptions)
//! - `UnwindAnalysis`, `AnalysisForPC`, `BlockGraph`, `BlockVertex`, `BlockEdge`
//! - `UniqueRow`, `UniqueRefType`, `UniqueTableModel` (pcode unique display)
//! - `VariableValueRowKind`, `VariableRowKey`, `VariableValueRowSet` (stack vars)
//! - `CellType` (breakpoint time overview)
//! - `SavedSettings` / `SavedWatchSettings` (watch panel settings)

#[cfg(test)]
mod tests {
    // ========================================================================
    // Stack exception types
    // ========================================================================
    use crate::stack::{EvaluationException, UnwindException};

    #[test]
    fn test_evaluation_exception_display() {
        let exc = EvaluationException::new("Cannot evaluate variable");
        let msg = format!("{}", exc);
        assert!(msg.contains("Cannot evaluate variable"));
        assert!(msg.contains("EvaluationException"));
    }

    #[test]
    fn test_evaluation_exception_is_error() {
        let exc = EvaluationException::new("test");
        let err: &dyn std::error::Error = &exc;
        assert_eq!(err.to_string(), "EvaluationException: test");
    }

    #[test]
    fn test_unwind_exception_no_cause() {
        let exc = UnwindException::new("No function at address");
        let msg = format!("{}", exc);
        assert!(msg.contains("No function at address"));
        assert!(!msg.contains("caused by"));
    }

    #[test]
    fn test_unwind_exception_with_cause() {
        let exc = UnwindException::with_cause("Cannot unwind", "missing frame info");
        let msg = format!("{}", exc);
        assert!(msg.contains("Cannot unwind"));
        assert!(msg.contains("missing frame info"));
        assert!(msg.contains("caused by"));
    }

    // ========================================================================
    // UnwindAnalysis types
    // ========================================================================
    use crate::stack::unwind_analysis::{
        BlockEdge, BlockGraph, BlockVertex, UnwindAnalysis,
    };

    #[test]
    fn test_block_vertex_creation() {
        let v = BlockVertex::new(0x400000, 0x400010);
        assert_eq!(v.start, 0x400000);
        assert_eq!(v.end, 0x400010);
    }

    #[test]
    fn test_block_edge_methods() {
        let edge = BlockEdge {
            source_start: 0x400000,
            source_end: 0x400010,
            dest_start: 0x400100,
            dest_end: 0x400110,
            is_call: false,
        };
        assert_eq!(edge.source().start, 0x400000);
        assert_eq!(edge.dest().start, 0x400100);
        assert!(!edge.is_call);
    }

    #[test]
    fn test_block_graph_construction() {
        let mut graph = BlockGraph::new();
        graph.add_edge(BlockEdge {
            source_start: 0x400000,
            source_end: 0x400010,
            dest_start: 0x400020,
            dest_end: 0x400030,
            is_call: false,
        });
        assert_eq!(graph.vertex_count(), 2);
    }

    #[test]
    fn test_block_graph_path_finding() {
        let mut graph = BlockGraph::new();
        // Linear: A -> B -> C -> D
        for i in 0..3 {
            graph.add_edge(BlockEdge {
                source_start: 0x400000 + i * 0x100,
                source_end: 0x400000 + i * 0x100 + 0x10,
                dest_start: 0x400000 + (i + 1) * 0x100,
                dest_end: 0x400000 + (i + 1) * 0x100 + 0x10,
                is_call: false,
            });
        }

        let path = graph.shortest_path(
            &BlockVertex::new(0x400000, 0x400010),
            &BlockVertex::new(0x400300, 0x400310),
        );
        assert_eq!(path.len(), 4); // A -> B -> C -> D
    }

    #[test]
    fn test_block_graph_no_path() {
        let mut graph = BlockGraph::new();
        graph.add_vertex(BlockVertex::new(0x400000, 0x400010));
        graph.add_vertex(BlockVertex::new(0x500000, 0x500010));

        let path = graph.shortest_path(
            &BlockVertex::new(0x400000, 0x400010),
            &BlockVertex::new(0x500000, 0x500010),
        );
        assert!(path.is_empty());
    }

    #[test]
    fn test_block_graph_terminal_vertices() {
        let mut graph = BlockGraph::new();
        graph.add_edge(BlockEdge {
            source_start: 0x400000,
            source_end: 0x400010,
            dest_start: 0x400100,
            dest_end: 0x400110,
            is_call: false,
        });
        graph.add_edge(BlockEdge {
            source_start: 0x400000,
            source_end: 0x400010,
            dest_start: 0x400200,
            dest_end: 0x400210,
            is_call: false,
        });

        let terminals = graph.terminal_vertices();
        assert_eq!(terminals.len(), 2);
    }

    #[test]
    fn test_unwind_analysis_basic() {
        let mut graph = BlockGraph::new();
        graph.add_edge(BlockEdge {
            source_start: 0x400000,
            source_end: 0x400010,
            dest_start: 0x400100,
            dest_end: 0x400110,
            is_call: false,
        });

        let mut entries = std::collections::HashMap::new();
        entries.insert(0x400000u64, 0x400000u64);

        let mut analysis = UnwindAnalysis::new(graph, entries);
        let info = analysis.get_unwind_info(0x400100);
        assert!(info.is_some());
    }

    #[test]
    fn test_unwind_analysis_not_found() {
        let graph = BlockGraph::new();
        let entries = std::collections::HashMap::new();
        let mut analysis = UnwindAnalysis::new(graph, entries);
        assert!(analysis.get_unwind_info(0x999999).is_none());
    }

    #[test]
    fn test_block_graph_vertex_containing() {
        let mut graph = BlockGraph::new();
        graph.add_vertex(BlockVertex::new(0x400000, 0x400020));

        assert!(graph.find_vertex_containing(0x400010).is_some());
        assert!(graph.find_vertex_containing(0x400000).is_some());
        assert!(graph.find_vertex_containing(0x400020).is_some());
        assert!(graph.find_vertex_containing(0x400021).is_none());
    }

    // ========================================================================
    // UniqueRow types
    // ========================================================================
    use crate::plugin::{
        UniqueRefType, UniqueRow, UniqueTableModel,
    };

    #[test]
    fn test_unique_ref_type_from_rw() {
        assert_eq!(UniqueRefType::from_rw(true, true), UniqueRefType::ReadWrite);
        assert_eq!(UniqueRefType::from_rw(true, false), UniqueRefType::Read);
        assert_eq!(UniqueRefType::from_rw(false, true), UniqueRefType::Write);
        assert_eq!(UniqueRefType::from_rw(false, false), UniqueRefType::None);
    }

    #[test]
    fn test_unique_row_full_workflow() {
        let mut model = UniqueTableModel::new();

        let row1 = UniqueRow::new(0x7fff0000, 4)
            .with_bytes(vec![0xde, 0xad, 0xbe, 0xef])
            .with_ref_type(UniqueRefType::Read);
        let row2 = UniqueRow::new(0x7fff0004, 8)
            .with_bytes(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
            .with_ref_type(UniqueRefType::Write);

        model.add_row(row1);
        model.add_row(row2);

        assert_eq!(model.len(), 2);

        let found = model.find_by_varnode(0x7fff0000, 4);
        assert!(found.is_some());
        assert_eq!(found.unwrap().ref_type, UniqueRefType::Read);
    }

    #[test]
    fn test_unique_row_overlaps() {
        let row = UniqueRow::new(0x100, 8);
        assert!(row.overlaps(0x100, 4));  // Same start, smaller
        assert!(row.overlaps(0x104, 8));  // Overlapping
        assert!(row.overlaps(0x107, 4));  // Just barely overlapping
        assert!(!row.overlaps(0x108, 4)); // Adjacent, no overlap
        assert!(!row.overlaps(0x200, 8)); // Far away
    }

    #[test]
    fn test_unique_row_value_as_u64() {
        let row = UniqueRow::new(0x100, 4).with_bytes(vec![0x42, 0x00, 0x00, 0x00]);
        assert_eq!(row.value_as_u64(), Some(0x42));

        let row2 = UniqueRow::new(0x100, 8)
            .with_bytes(vec![0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(row2.value_as_u64(), Some(0xff));

        let row3 = UniqueRow::new(0x100, 4); // No bytes
        assert_eq!(row3.value_as_u64(), None);
    }

    #[test]
    fn test_unique_row_bytes_display_not_concrete() {
        let row = UniqueRow::new(0x100, 4);
        assert_eq!(row.bytes_display(), "(not concrete)");
    }

    // ========================================================================
    // VariableValueRowKind types
    // ========================================================================
    use crate::plugin::{
        VariableRowKey, VariableValueRowKind, VariableValueRowSet,
    };
    use crate::model::memory::TraceMemoryState;

    #[test]
    fn test_all_row_kinds_have_correct_keys() {
        let kinds = vec![
            VariableValueRowKind::Name { name: "test".into() },
            VariableValueRowKind::Frame { description: "f0".into(), level: 0 },
            VariableValueRowKind::Storage { storage: "RAX".into() },
            VariableValueRowKind::Type { type_name: "long".into() },
            VariableValueRowKind::Instruction { mnemonic: "nop".into(), address: 0x400000 },
            VariableValueRowKind::Location { location: None },
            VariableValueRowKind::Bytes { bytes: vec![], state: TraceMemoryState::Known, big_endian: false },
            VariableValueRowKind::Integer { bytes: vec![], state: TraceMemoryState::Known, big_endian: false },
            VariableValueRowKind::Value { value: "0".into(), state: TraceMemoryState::Known },
            VariableValueRowKind::Status { status: "ok".into() },
            VariableValueRowKind::Warnings { warnings: vec![] },
            VariableValueRowKind::Error { error: "err".into() },
        ];

        let expected_keys = vec![
            VariableRowKey::Name,
            VariableRowKey::Frame,
            VariableRowKey::Storage,
            VariableRowKey::Type,
            VariableRowKey::Instruction,
            VariableRowKey::Location,
            VariableRowKey::Bytes,
            VariableRowKey::Integer,
            VariableRowKey::Value,
            VariableRowKey::Status,
            VariableRowKey::Warnings,
            VariableRowKey::Error,
        ];

        for (kind, expected) in kinds.iter().zip(expected_keys.iter()) {
            assert_eq!(kind.key(), *expected);
        }
    }

    #[test]
    fn test_variable_value_row_set_sort_order() {
        let mut set = VariableValueRowSet::new();
        set.push(VariableValueRowKind::Error { error: "e".into() });
        set.push(VariableValueRowKind::Warnings { warnings: vec!["w".into()] });
        set.push(VariableValueRowKind::Status { status: "s".into() });
        set.push(VariableValueRowKind::Value { value: "v".into(), state: TraceMemoryState::Known });
        set.push(VariableValueRowKind::Integer { bytes: vec![1], state: TraceMemoryState::Known, big_endian: false });
        set.push(VariableValueRowKind::Bytes { bytes: vec![1], state: TraceMemoryState::Known, big_endian: false });
        set.push(VariableValueRowKind::Location { location: None });
        set.push(VariableValueRowKind::Instruction { mnemonic: "i".into(), address: 0 });
        set.push(VariableValueRowKind::Type { type_name: "t".into() });
        set.push(VariableValueRowKind::Storage { storage: "s".into() });
        set.push(VariableValueRowKind::Frame { description: "f".into(), level: 0 });
        set.push(VariableValueRowKind::Name { name: "n".into() });

        set.sort_by_key();

        // Verify ordering: Name < Frame < ... < Error
        let keys: Vec<_> = set.rows.iter().map(|r| r.key()).collect();
        for i in 0..keys.len() - 1 {
            assert!(keys[i] <= keys[i + 1], "Key {:?} should be <= {:?}", keys[i], keys[i + 1]);
        }
    }

    #[test]
    fn test_variable_value_row_set_error_detection() {
        let mut set = VariableValueRowSet::new();
        assert!(!set.has_error());
        set.push(VariableValueRowKind::Error { error: "fail".into() });
        assert!(set.has_error());
    }

    #[test]
    fn test_variable_value_row_set_warning_detection() {
        let mut set = VariableValueRowSet::new();
        assert!(!set.has_warnings());
        set.push(VariableValueRowKind::Warnings { warnings: vec!["w".into()] });
        assert!(set.has_warnings());
    }

    #[test]
    fn test_variable_value_row_complete_hover() {
        let mut set = VariableValueRowSet::new();
        set.push(VariableValueRowKind::Name { name: "RAX".into() });
        set.push(VariableValueRowKind::Storage { storage: "RAX:8".into() });
        set.push(VariableValueRowKind::Type { type_name: "unsigned long long".into() });
        set.push(VariableValueRowKind::Bytes {
            bytes: vec![0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            state: TraceMemoryState::Known,
            big_endian: false,
        });
        set.push(VariableValueRowKind::Integer {
            bytes: vec![0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            state: TraceMemoryState::Known,
            big_endian: false,
        });
        set.push(VariableValueRowKind::Value { value: "0x42".into(), state: TraceMemoryState::Known });

        assert_eq!(set.len(), 6);
        assert!(!set.has_error());
        assert!(!set.has_warnings());

        set.sort_by_key();
        assert_eq!(set.rows[0].key(), VariableRowKey::Name);
        assert_eq!(set.rows[1].key(), VariableRowKey::Storage);
        assert_eq!(set.rows[2].key(), VariableRowKey::Type);
    }

    #[test]
    fn test_stale_bytes_row() {
        let kind = VariableValueRowKind::Bytes {
            bytes: vec![0x42],
            state: TraceMemoryState::Unknown,
            big_endian: false,
        };
        let val = kind.value_to_string();
        assert!(val.contains("Unknown"));
    }

    #[test]
    fn test_variable_value_row_set_serde_roundtrip() {
        let mut set = VariableValueRowSet::new();
        set.push(VariableValueRowKind::Name { name: "RBX".into() });
        set.push(VariableValueRowKind::Value {
            value: "0xdeadbeef".into(),
            state: TraceMemoryState::Known,
        });
        set.push(VariableValueRowKind::Warnings {
            warnings: vec!["No return path".into()],
        });

        let json = serde_json::to_string(&set).unwrap();
        let back: VariableValueRowSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 3);
        assert!(back.has_warnings());
    }

    // ========================================================================
    // CellType enum
    // ========================================================================
    use crate::plugin::CellType;

    #[test]
    fn test_cell_type_colors() {
        assert_eq!(CellType::None.color(), 0x00_000000);
        assert_eq!(CellType::Active.color(), 0xff_ff0000);
        assert_eq!(CellType::Disabled.color(), 0xff_808080);
        assert_eq!(CellType::Hit.color(), 0xff_ff00ff);
    }

    #[test]
    fn test_cell_type_equality() {
        assert_eq!(CellType::Active, CellType::Active);
        assert_ne!(CellType::Active, CellType::Disabled);
    }

    // ========================================================================
    // SavedWatchSettings
    // ========================================================================
    use crate::plugin::{SavedWatchSettings, WatchFormat};

    #[test]
    fn test_saved_watch_settings_default() {
        let settings = SavedWatchSettings::default();
        assert_eq!(settings.format, WatchFormat::Hex);
        assert_eq!(settings.element_count, 1);
        assert!(!settings.show_as_array);
        assert!(settings.auto_update);
    }

    #[test]
    fn test_saved_watch_settings_serde() {
        let settings = SavedWatchSettings {
            format: WatchFormat::Decimal,
            element_count: 4,
            show_as_array: true,
            auto_update: false,
        };
        let json = serde_json::to_string(&settings).unwrap();
        let back: SavedWatchSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(back.format, WatchFormat::Decimal);
        assert_eq!(back.element_count, 4);
        assert!(back.show_as_array);
        assert!(!back.auto_update);
    }

    // ========================================================================
    // Cross-module integration: combining stack + GUI types
    // ========================================================================
    use crate::stack::{UnwindWarningSet, UnwindInfo, ReturnLocation};

    #[test]
    fn test_full_variable_hover_with_unwind_info() {
        // Simulate building a complete variable hover from unwind analysis results
        let mut warnings = UnwindWarningSet::new();
        warnings.add(crate::stack::UnwindWarning::custom("Stack depth uncertain"));

        let info = UnwindInfo {
            function_name: Some("main".into()),
            depth: Some(128),
            adjust: Some(136),
            return_location: ReturnLocation::Stack { offset: -8, size: 8 },
            return_mask: u64::MAX,
            saved_registers: {
                let mut m = std::collections::HashMap::new();
                m.insert("RBP".to_string(), -16i64);
                m.insert("RBX".to_string(), -24i64);
                m
            },
            warnings: warnings.clone(),
            error: None,
        };

        // Build the variable value row set from unwind info
        let mut set = VariableValueRowSet::new();
        set.push(VariableValueRowKind::Name { name: "local_var".into() });
        set.push(VariableValueRowKind::Frame {
            description: format!("Frame 0 in {}", info.function_name.as_deref().unwrap_or("?")),
            level: 0,
        });
        if let Some(depth) = info.depth {
            set.push(VariableValueRowKind::Location {
                location: Some(format!("Stack[-0x{:x}]", depth - 8)),
            });
        }
        set.push(VariableValueRowKind::Bytes {
            bytes: vec![0xca, 0xfe, 0xba, 0xbe],
            state: TraceMemoryState::Known,
            big_endian: false,
        });
        set.push(VariableValueRowKind::Value {
            value: "0xcafebabe".into(),
            state: TraceMemoryState::Known,
        });

        assert_eq!(set.len(), 5);
        assert!(!set.has_error());
        assert!(!set.has_warnings());

        set.sort_by_key();
        assert_eq!(set.rows[0].key(), VariableRowKey::Name);
        assert_eq!(set.rows[1].key(), VariableRowKey::Frame);
        assert_eq!(set.rows[2].key(), VariableRowKey::Location);
        assert_eq!(set.rows[3].key(), VariableRowKey::Bytes);
        assert_eq!(set.rows[4].key(), VariableRowKey::Value);
    }
}
