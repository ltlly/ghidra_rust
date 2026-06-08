//! Comprehensive tests for the remaining Debug modules ported from Java.
//!
//! These tests cover key types from all three Java source directories:
//! - Framework-TraceModeling: schema, paths, visitors, memory, lifespan, breakpoints
//! - Debugger-api: action names, ValStr, breakpoints, RMI, control modes
//! - Debugger: services, platform mapper, watch, coordinates

#[cfg(test)]
mod tests {
    use crate::model::{
        breakpoint::{BreakpointKindSet, TraceBreakpointKind},
        breakpoint_spec::{TraceBreakpointSpec, TraceBreakpointLocation, TraceBreakpointCommon},
        guest::TracePlatformManager,
        lifespan::Lifespan,
        memory::TraceMemoryState,
        symbol::{TraceReference, TraceSymbolManager},
    };
    use crate::target::{
        key_path::KeyPath,
        path_matcher::PathMatcher,
        path_pattern::PathPattern,
    };

    // ========================================================================
    // Framework-TraceModeling: KeyPath
    // ========================================================================

    #[test]
    fn test_key_path_root() {
        let root = KeyPath::ROOT;
        assert!(root.is_root());
        assert_eq!(root.size(), 0);
    }

    #[test]
    fn test_key_path_extend() {
        let base = KeyPath::of(&["Processes"]);
        let extended = base.extend("Threads");
        assert_eq!(extended.size(), 2);
        assert_eq!(extended.get(0), Some("Processes"));
        assert_eq!(extended.get(1), Some("Threads"));
    }

    #[test]
    fn test_key_path_parent() {
        let path = KeyPath::of(&["Processes", "42", "Threads"]);
        let parent = path.parent();
        assert_eq!(parent.size(), 2);
        assert_eq!(parent.get(1), Some("42"));
    }

    #[test]
    fn test_key_path_is_ancestor() {
        let ancestor = KeyPath::of(&["Processes"]);
        let descendant = KeyPath::of(&["Processes", "42", "Threads"]);
        assert!(ancestor.is_ancestor(&descendant));
        assert!(!descendant.is_ancestor(&ancestor));
    }

    #[test]
    fn test_key_path_extend_path() {
        let base = KeyPath::of(&["Processes"]);
        let sub = KeyPath::of(&["42", "Threads"]);
        let extended = base.extend_path(&sub);
        assert_eq!(extended.size(), 3);
        assert_eq!(extended.get(2), Some("Threads"));
    }

    #[test]
    fn test_key_path_display() {
        let path = KeyPath::of(&["Processes", "42", "Threads"]);
        let display = format!("{}", path);
        assert!(display.contains("Processes"));
    }

    // ========================================================================
    // Framework-TraceModeling: Path Filter and Pattern
    // ========================================================================

    #[test]
    fn test_path_pattern_exact() {
        let pattern = PathPattern::new(KeyPath::of(&["Processes", "42"]));
        assert!(pattern.matches(&KeyPath::of(&["Processes", "42"])));
        assert!(!pattern.matches(&KeyPath::of(&["Processes", "43"])));
    }

    #[test]
    fn test_path_matcher_from_patterns() {
        let p1 = PathPattern::new(KeyPath::of(&["Processes"]));
        let p2 = PathPattern::new(KeyPath::of(&["Threads"]));
        let matcher = PathMatcher::from_patterns(&[p1, p2]);

        assert!(matcher.matches(&KeyPath::of(&["Processes"])));
        assert!(matcher.matches(&KeyPath::of(&["Threads"])));
        assert!(!matcher.matches(&KeyPath::of(&["Modules"])));
    }

    // ========================================================================
    // Framework-TraceModeling: Memory State
    // ========================================================================

    #[test]
    fn test_memory_state_variants() {
        assert!(!TraceMemoryState::Known.implied_by_null());
        assert!(TraceMemoryState::Unknown.implied_by_null());
    }

    #[test]
    fn test_memory_state_or_implied() {
        assert_eq!(TraceMemoryState::or_implied(Some(TraceMemoryState::Known)), TraceMemoryState::Known);
        assert_eq!(TraceMemoryState::or_implied(None), TraceMemoryState::Unknown);
    }

    // ========================================================================
    // Framework-TraceModeling: Lifespan
    // ========================================================================

    #[test]
    fn test_lifespan_creation() {
        let span = Lifespan::span(0, 100);
        assert_eq!(span.lmin(), 0);
        assert_eq!(span.lmax(), 100);
        assert!(!span.is_empty());
    }

    #[test]
    fn test_lifespan_intersection() {
        let a = Lifespan::span(0, 50);
        let b = Lifespan::span(25, 75);
        let c = a.intersect(&b);
        assert_eq!(c.lmin(), 25);
        assert_eq!(c.lmax(), 50);
    }

    #[test]
    fn test_lifespan_disjoint() {
        let a = Lifespan::span(0, 10);
        let b = Lifespan::span(20, 30);
        let c = a.intersect(&b);
        assert!(c.is_empty());
    }

    #[test]
    fn test_lifespan_contains() {
        let span = Lifespan::span(10, 20);
        assert!(span.contains(10));
        assert!(span.contains(15));
        assert!(span.contains(20));
        assert!(!span.contains(9));
        assert!(!span.contains(21));
    }

    // ========================================================================
    // Framework-TraceModeling: Breakpoint Types
    // ========================================================================

    #[test]
    fn test_breakpoint_common_name_time_travel() {
        let mut bp = TraceBreakpointCommon::new("t1", "bp[0]", Lifespan::span(0, 200));
        bp.set_name(0, "initial");
        bp.set_name(50, "renamed");
        bp.set_name(150, "final");
        assert_eq!(bp.get_name(0), "initial");
        assert_eq!(bp.get_name(49), "initial");
        assert_eq!(bp.get_name(50), "renamed");
        assert_eq!(bp.get_name(150), "final");
    }

    #[test]
    fn test_breakpoint_common_enabled_toggle() {
        let mut bp = TraceBreakpointCommon::new("t1", "bp[0]", Lifespan::span(0, 100));
        assert!(bp.is_enabled(0));
        bp.set_enabled(Lifespan::span(10, 20), false);
        bp.set_enabled(Lifespan::span(30, 40), false);
        assert!(bp.is_enabled(5));
        assert!(!bp.is_enabled(15));
        assert!(bp.is_enabled(25));
        assert!(!bp.is_enabled(35));
        assert!(bp.is_enabled(45));
    }

    #[test]
    fn test_breakpoint_spec_lifecycle() {
        let mut spec = TraceBreakpointSpec::new("t1", "specs[0]", Lifespan::span(0, 100));
        spec.set_expression(0, "main");
        spec.common.set_name(0, "Main breakpoint");
        spec.common.set_enabled(Lifespan::span(0, 100), true);

        let mut kinds = BreakpointKindSet::new();
        kinds.insert(TraceBreakpointKind::SwExecute);
        spec.set_kinds(0, kinds);

        assert_eq!(spec.get_expression(0), Some("main"));
        assert_eq!(spec.common.get_name(0), "Main breakpoint");
        assert!(spec.common.is_enabled(50));
        assert!(spec.get_kinds(0).is_some());
    }

    #[test]
    fn test_breakpoint_location_coverage() {
        let loc = TraceBreakpointLocation::new(
            "t1", "l[0]", Lifespan::span(0, 100), 0x400000, 16, "ram",
        );
        assert!(loc.covers_address("ram", 0x400000));
        assert!(loc.covers_address("ram", 0x40000F));
        assert!(!loc.covers_address("ram", 0x400010));
        assert!(!loc.covers_address("stack", 0x400000));
    }

    #[test]
    fn test_breakpoint_kind_set_roundtrip() {
        let mut kinds = BreakpointKindSet::new();
        kinds.insert(TraceBreakpointKind::Read);
        kinds.insert(TraceBreakpointKind::Write);

        let json = serde_json::to_string(&kinds).unwrap();
        let deser: BreakpointKindSet = serde_json::from_str(&json).unwrap();
        assert!(deser.contains(&TraceBreakpointKind::Read));
        assert!(deser.contains(&TraceBreakpointKind::Write));
        assert!(!deser.contains(&TraceBreakpointKind::SwExecute));
    }

    #[test]
    fn test_breakpoint_kind_encoding() {
        assert_eq!(TraceBreakpointKind::SwExecute.encoding_char(), 'x');
        assert_eq!(TraceBreakpointKind::Read.encoding_char(), 'R');
        assert_eq!(TraceBreakpointKind::Write.encoding_char(), 'W');
        assert_eq!(TraceBreakpointKind::HwExecute.encoding_char(), 'X');
    }

    // ========================================================================
    // Framework-TraceModeling: Symbol Management
    // ========================================================================

    #[test]
    fn test_full_symbol_lifecycle() {
        let mut sym_mgr = TraceSymbolManager::new();
        let _main_key = sym_mgr.create_label("main", 0x400000, "ram", Lifespan::now_on(0));
        let _printf_key = sym_mgr.create_label("printf", 0x500000, "ram", Lifespan::now_on(0));
        let _ns_key = sym_mgr.create_namespace("libc", None, Lifespan::ALL);

        let call_ref = TraceReference::memory(0, 0x400010, 0x500000, Lifespan::now_on(0))
            .with_primary(true);
        sym_mgr.add_reference(call_ref);

        assert_eq!(sym_mgr.symbol_count(), 3);
        let main_syms = sym_mgr.get_symbols_at(0x400000, "ram", 5);
        assert_eq!(main_syms.len(), 1);
        assert_eq!(main_syms[0].name, "main");
    }

    #[test]
    fn test_reference_queries() {
        let mut sym_mgr = TraceSymbolManager::new();
        sym_mgr.create_label("target", 0x500000, "ram", Lifespan::now_on(0));
        sym_mgr.add_reference(TraceReference::memory(0, 0x400000, 0x500000, Lifespan::now_on(0)));
        sym_mgr.add_reference(TraceReference::memory(0, 0x400010, 0x500000, Lifespan::now_on(0)));

        let to_target = sym_mgr.references_to(0x500000, 5);
        assert_eq!(to_target.len(), 2);
    }

    // ========================================================================
    // Framework-TraceModeling: Platform Management
    // ========================================================================

    #[test]
    fn test_platform_management() {
        let mut plat_mgr = TracePlatformManager::new();

        let host_key = plat_mgr.add_platform("x86:LE:64:default", "default");
        plat_mgr.set_native_platform(host_key);

        let _guest_key = plat_mgr.add_platform("ARM:LE:32:v8", "default");

        assert!(plat_mgr.platforms().len() >= 2);
    }

    // ========================================================================
    // Debugger-api: Action Names
    // ========================================================================

    use crate::api::action_name::ActionName;

    #[test]
    fn test_action_name_variants() {
        let actions = vec![
            ActionName::StepInto,
            ActionName::StepOver,
            ActionName::StepOut,
            ActionName::Continue,
            ActionName::Kill,
            ActionName::Disconnect,
        ];
        for action in &actions {
            assert!(!action.to_string().is_empty());
        }
    }

    #[test]
    fn test_action_name_display() {
        assert_eq!(ActionName::StepInto.to_string(), "Step Into");
        assert_eq!(ActionName::StepOver.to_string(), "Step Over");
        assert_eq!(ActionName::Continue.to_string(), "Continue");
    }

    // ========================================================================
    // Debugger-api: ValStr
    // ========================================================================

    use crate::api::val_str::ValStr;

    #[test]
    fn test_val_str_from_value() {
        let vs = ValStr::from_value(42u64);
        assert!(vs.has_value());
        assert_eq!(vs.value(), Some(&42));
    }

    #[test]
    fn test_val_str_from_string() {
        let vs: ValStr<u64> = ValStr::from_string("unknown");
        assert!(!vs.has_value());
        assert_eq!(vs.string(), "unknown");
    }

    #[test]
    fn test_val_str_new() {
        let vs = ValStr::new(42u64, "42");
        assert_eq!(vs.value(), Some(&42));
        assert_eq!(vs.string(), "42");
    }

    // ========================================================================
    // Debugger-api: Watch
    // ========================================================================

    use crate::api::watch::WatchRow;

    #[test]
    fn test_watch_row_creation() {
        let row = WatchRow::new("RAX");
        assert_eq!(row.expression, "RAX");
        assert!(row.value.is_none());
        assert!(!row.expanded);
    }

    #[test]
    fn test_watch_row_with_value() {
        let row = WatchRow::new("RAX").with_value(vec![0x42, 0x00, 0x00, 0x00]);
        assert!(row.value.is_some());
        assert_eq!(row.value.unwrap(), vec![0x42, 0x00, 0x00, 0x00]);
    }

    // ========================================================================
    // Debugger-api: RMI Connection
    // ========================================================================

    use crate::api::trace_rmi_connection::TraceRmiConnection;
    use crate::api::tracermi::TerminalSession;

    #[test]
    fn test_rmi_connection_lifecycle() {
        let mut conn = TraceRmiConnection::new("localhost:18001", "test-conn");
        assert!(!conn.is_connected());
        assert_eq!(conn.connection_id, "test-conn");

        conn.set_connected(true);
        assert!(conn.is_connected());
    }

    #[test]
    fn test_terminal_session_creation() {
        let session = TerminalSession::new("gdb-session");
        assert_eq!(session.id, "gdb-session");
    }

    // ========================================================================
    // Debugger/src: Control Mode
    // ========================================================================

    use crate::api::control_mode::ControlMode;

    #[test]
    fn test_control_mode_variants() {
        // Verify all variants exist and have display strings
        let modes = [
            ControlMode::RoTarget,
            ControlMode::RwTarget,
            ControlMode::RoTrace,
            ControlMode::RwTrace,
            ControlMode::RwEmulator,
        ];
        for mode in &modes {
            assert!(!mode.to_string().is_empty());
        }
    }

    #[test]
    fn test_control_mode_is_target() {
        assert!(ControlMode::RoTarget.is_target());
        assert!(ControlMode::RwTarget.is_target());
        assert!(!ControlMode::RoTrace.is_target());
        assert!(!ControlMode::RwTrace.is_target());
        assert!(!ControlMode::RwEmulator.is_target());
    }

    // ========================================================================
    // Debugger/src: Platform Mapper
    // ========================================================================

    use crate::api::platform_mapper::{DisassemblyResult, RegisterMapping};

    #[test]
    fn test_disassembly_result_creation() {
        let result = DisassemblyResult::new("INC EAX", "INC EAX\n; increment", 4);
        assert_eq!(result.mnemonic, "INC EAX");
        assert_eq!(result.length, 4);
    }

    #[test]
    fn test_disassembly_result_with_options() {
        let result = DisassemblyResult::new("JMP", "JMP 0x400000", 5)
            .with_branch(true)
            .with_call(false);
        assert!(result.is_branch);
        assert!(!result.is_call);
    }

    #[test]
    fn test_register_mapping_creation() {
        let mapping = RegisterMapping::new("RAX", "EAX", 64);
        assert_eq!(mapping.target_register, "RAX");
        assert_eq!(mapping.ghidra_register, "EAX");
        assert_eq!(mapping.bit_size, 64);
    }

    // ========================================================================
    // Debugger/src: Coordinates
    // ========================================================================

    use crate::util::coordinates::DebuggerCoordinates;

    #[test]
    fn test_coordinates_nowhere() {
        let coords = DebuggerCoordinates::nowhere();
        assert!(coords.is_nowhere());
        assert!(!coords.has_trace());
    }

    #[test]
    fn test_coordinates_with_trace() {
        let coords = DebuggerCoordinates::at_trace("trace-1");
        assert!(coords.has_trace());
        assert_eq!(coords.trace_id(), "trace-1");
    }

    #[test]
    fn test_coordinates_with_snap() {
        let coords = DebuggerCoordinates::at_trace("trace-1").with_snap(42);
        assert_eq!(coords.thread_key(), None);
    }

    // ========================================================================
    // Cross-module Integration Tests
    // ========================================================================

    #[test]
    fn test_lifespan_and_breakpoint_integration() {
        let _bp_span = Lifespan::span(0, 100);

        let mut spec = TraceBreakpointSpec::new("t1", "specs[0]", Lifespan::span(0, 100));
        spec.set_expression(0, "main");
        spec.common.set_enabled(Lifespan::span(0, 100), true);

        let loc = TraceBreakpointLocation::new(
            "t1", "l[0]", Lifespan::span(0, 100), 0x400000, 1, "ram",
        );

        assert_eq!(spec.get_expression(0), Some("main"));
        assert!(spec.common.is_enabled(50));
        assert!(loc.covers_address("ram", 0x400000));
        assert!(!loc.covers_address("register", 0x400000));
    }

    #[test]
    fn test_memory_state_tracking() {
        let mut states: std::collections::HashMap<u64, TraceMemoryState> = std::collections::HashMap::new();
        states.insert(0x1000, TraceMemoryState::Known);
        states.insert(0x1004, TraceMemoryState::Known);
        states.insert(0x1008, TraceMemoryState::Unknown);

        assert_eq!(states.get(&0x1000), Some(&TraceMemoryState::Known));
        assert_eq!(states.get(&0x1008), Some(&TraceMemoryState::Unknown));
        assert!(states.get(&0x100C).is_none());
    }

    #[test]
    fn test_filter_integration() {
        let p1 = PathPattern::new(KeyPath::of(&["Processes"]));
        let p2 = PathPattern::new(KeyPath::of(&["Threads"]));
        let filter = PathMatcher::from_patterns(&[p1, p2]);

        assert!(filter.matches(&KeyPath::of(&["Processes"])));
        assert!(filter.matches(&KeyPath::of(&["Threads"])));
        assert!(!filter.matches(&KeyPath::of(&["Modules"])));
    }

    #[test]
    fn test_schema_context_integration() {
        use crate::model::target_schema::{SchemaContext, TraceObjectSchemaDef};

        let mut ctx = SchemaContext::new();
        let session = TraceObjectSchemaDef::new("SESSION", "TraceObject")
            .with_interface("TraceEnvironment")
            .as_canonical_container();
        let process = TraceObjectSchemaDef::new("PROCESS", "TraceObject")
            .with_interface("TraceProcess")
            .as_canonical_container();
        let thread = TraceObjectSchemaDef::new("THREAD", "TraceObject")
            .with_interface("TraceThread");

        ctx.register(session);
        ctx.register(process);
        ctx.register(thread);

        assert!(ctx.has_schema("SESSION"));
        assert!(ctx.has_schema("PROCESS"));
        assert!(ctx.has_schema("THREAD"));
        assert!(!ctx.has_schema("MODULE"));
        assert_eq!(ctx.schema_count(), 3);
    }

    #[test]
    fn test_symbol_reference_integration() {
        let mut sym_mgr = TraceSymbolManager::new();
        sym_mgr.create_label("target", 0x500000, "ram", Lifespan::now_on(0));
        sym_mgr.add_reference(
            TraceReference::memory(0, 0x400000, 0x500000, Lifespan::now_on(0))
                .with_primary(true),
        );
        sym_mgr.add_reference(
            TraceReference::memory(0, 0x400004, 0x500000, Lifespan::now_on(0)),
        );

        let to_target = sym_mgr.references_to(0x500000, 5);
        assert_eq!(to_target.len(), 2);
        assert!(to_target.iter().any(|r| r.is_primary));
    }

    #[test]
    fn test_breakpoint_serialization_roundtrip() {
        let mut spec = TraceBreakpointSpec::new("t1", "specs[0]", Lifespan::span(0, 100));
        spec.set_expression(0, "malloc");
        let json = serde_json::to_string(&spec).unwrap();
        let deser: TraceBreakpointSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.get_expression(0), Some("malloc"));
    }

    #[test]
    fn test_breakpoint_location_zero_length() {
        let loc = TraceBreakpointLocation::new(
            "t1", "l[0]", Lifespan::span(0, 100), 0x400000, 0, "ram",
        );
        assert!(loc.covers_address("ram", 0x400000));
        assert!(loc.covers_address("ram", 0xFFFFFFFF));
    }

    #[test]
    fn test_lifespan_serialization_roundtrip() {
        let span = Lifespan::span(0, 100);
        let json = serde_json::to_string(&span).unwrap();
        let deser: Lifespan = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.lmin(), 0);
        assert_eq!(deser.lmax(), 100);
    }

    #[test]
    fn test_key_path_serialization_roundtrip() {
        let path = KeyPath::of(&["Processes", "42", "Threads"]);
        let json = serde_json::to_string(&path).unwrap();
        let deser: KeyPath = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.size(), 3);
        assert_eq!(deser.get(0), Some("Processes"));
    }

    #[test]
    fn test_full_debug_session_workflow() {
        // 1. Create symbol manager
        let mut sym_mgr = TraceSymbolManager::new();
        sym_mgr.create_label("main", 0x400000, "ram", Lifespan::now_on(0));

        // 2. Create breakpoint
        let mut spec = TraceBreakpointSpec::new("t1", "bp[0]", Lifespan::span(0, 100));
        spec.set_expression(0, "main");
        spec.common.set_enabled(Lifespan::span(0, 100), true);

        // 3. Create platform manager
        let mut plat_mgr = TracePlatformManager::new();
        let host_key = plat_mgr.add_platform("x86:LE:64:default", "default");
        plat_mgr.set_native_platform(host_key);

        // 4. Verify all components work together
        assert_eq!(sym_mgr.symbol_count(), 1);
        assert_eq!(spec.get_expression(0), Some("main"));
        assert!(plat_mgr.platforms().len() >= 1);
    }
}
