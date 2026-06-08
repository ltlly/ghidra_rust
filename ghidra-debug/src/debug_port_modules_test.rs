//! Comprehensive integration tests for the remaining Debug modules ported
//! from Ghidra's Java source:
//!
//! - Framework-TraceModeling: `ghidra.trace.model.target` (TraceObjectValue,
//!   ValueChangeEvent, TargetTreeSnapshot, TraceObjectChangeListener),
//!   `ghidra.trace.model.time` (TraceEvent, TraceEventType, TraceLogEntry),
//!   `ghidra.trace.database.target.iface` (DbObjectEventScope, DbObjectMethod).
//!
//! - Debugger-api: action types, module mapping, watch, platform, RMI.
//!
//! These tests verify that the Rust port faithfully represents the
//! structures and behaviors from the Java originals.

#[cfg(test)]
mod tests {
    use crate::db::{
        DbEventScopeManager, DbMethodManager, DbObjectEventScope, DbObjectMethod,
    };
    use crate::model::{
        ChangeCollector, Lifespan, LogLevel, TargetTreeSnapshot, Trace, TraceEvent,
        TraceEventManager, TraceEventType, TraceLogEntry, TraceLogManager, TraceObjectChangeListener,
        ValueChangeEvent, ValueChangeKind,
    };
    

    // ========================================================================
    // Framework-TraceModeling: ghidra.trace.model.target supplementary types
    // ========================================================================

    #[test]
    fn test_value_change_event_integration() {
        // Simulate inserting a thread object into the target tree
        let event = ValueChangeEvent::new(
            ValueChangeKind::Inserted,
            100, // Processes container key
            "Threads[0]",
            0,
            100,
        )
        .with_child_key(200); // The thread object key

        assert_eq!(event.kind, ValueChangeKind::Inserted);
        assert_eq!(event.parent_key, 100);
        assert_eq!(event.entry_key, "Threads[0]");
        assert_eq!(event.child_object_key, Some(200));
        assert_eq!(event.lifespan(), Lifespan::span(0, 100));
    }

    #[test]
    fn test_target_tree_snapshot_navigation() {
        // Build a snapshot of a typical debug session tree
        let mut snap = TargetTreeSnapshot::new(0);

        // Root -> Processes
        snap.add_entry(0, "Processes", Some(1));
        snap.add_entry(0, "Environment", Some(2));

        // Processes -> Threads
        snap.add_entry(1, "Threads", Some(3));
        snap.add_entry(1, "Memory", Some(4));
        snap.add_entry(1, "Modules", Some(5));

        // Threads -> individual threads
        snap.add_entry(3, "[0]", Some(10));
        snap.add_entry(3, "[1]", Some(11));

        // Verify tree structure
        assert!(snap.has_entry(0, "Processes"));
        assert!(snap.has_entry(0, "Environment"));
        assert!(!snap.has_entry(0, "NonExistent"));

        let root_children = snap.children_of(0);
        assert_eq!(root_children.len(), 2);

        let process_children = snap.children_of(1);
        assert_eq!(process_children.len(), 3);

        let thread_entries = snap.children_of(3);
        assert_eq!(thread_entries.len(), 2);
    }

    #[test]
    fn test_change_collector_full_lifecycle() {
        let mut collector = ChangeCollector::new();

        // Insert process
        let insert_process = ValueChangeEvent::new(
            ValueChangeKind::Inserted,
            0,
            "Processes[0]",
            0,
            100,
        );
        collector.value_inserted(&insert_process);

        // Insert thread under process
        let insert_thread = ValueChangeEvent::new(
            ValueChangeKind::Inserted,
            100,
            "Threads[0]",
            0,
            100,
        );
        collector.value_inserted(&insert_thread);

        // Mutate thread state
        let mutate_thread = ValueChangeEvent::new(
            ValueChangeKind::Mutated,
            200,
            "_state",
            5,
            10,
        );
        collector.value_mutated(&mutate_thread);

        // Delete thread
        let delete_thread = ValueChangeEvent::new(
            ValueChangeKind::Deleted,
            100,
            "Threads[0]",
            50,
            100,
        );
        collector.value_deleted(&delete_thread);

        assert_eq!(collector.events.len(), 4);
        assert_eq!(collector.events[0].kind, ValueChangeKind::Inserted);
        assert_eq!(collector.events[1].kind, ValueChangeKind::Inserted);
        assert_eq!(collector.events[2].kind, ValueChangeKind::Mutated);
        assert_eq!(collector.events[3].kind, ValueChangeKind::Deleted);

        collector.clear();
        assert!(collector.events.is_empty());
    }

    #[test]
    fn test_value_change_kind_properties() {
        // Verify the three change kinds are distinct
        let kinds = [
            ValueChangeKind::Inserted,
            ValueChangeKind::Mutated,
            ValueChangeKind::Deleted,
        ];
        for i in 0..kinds.len() {
            for j in 0..kinds.len() {
                if i == j {
                    assert_eq!(kinds[i], kinds[j]);
                } else {
                    assert_ne!(kinds[i], kinds[j]);
                }
            }
        }

        assert_eq!(ValueChangeKind::Inserted.to_string(), "inserted");
        assert_eq!(ValueChangeKind::Mutated.to_string(), "mutated");
        assert_eq!(ValueChangeKind::Deleted.to_string(), "deleted");
    }

    // ========================================================================
    // Framework-TraceModeling: ghidra.trace.model.time events
    // ========================================================================

    #[test]
    fn test_trace_event_full_scenario() {
        let mut mgr = TraceEventManager::new();

        // Simulate a debug session
        mgr.record_event(0, TraceEventType::ProcessCreated, "attached to PID 1234");
        mgr.record_event(1, TraceEventType::ThreadCreated, "main thread started");
        mgr.record_event(2, TraceEventType::ModuleLoaded, "libc.so loaded");
        mgr.record_event(5, TraceEventType::BreakpointHit, "hit bp at main");
        mgr.record_event(5, TraceEventType::Signal, "SIGTRAP");
        mgr.record_event(10, TraceEventType::StepCompleted, "single step");
        mgr.record_event(
            15,
            TraceEventType::BreakpointHit,
            "hit bp at printf",
        );
        mgr.record_event(
            20,
            TraceEventType::ThreadDestroyed,
            "thread terminated",
        );
        mgr.record_event(
            25,
            TraceEventType::ProcessDestroyed,
            "process exited",
        );

        assert_eq!(mgr.len(), 9);

        // Events at specific snaps
        assert_eq!(mgr.events_at_snap(5).len(), 2);
        assert_eq!(mgr.events_at_snap(0).len(), 1);

        // Filter by event type
        assert_eq!(
            mgr.events_of_type(&TraceEventType::BreakpointHit).len(),
            2
        );
        assert_eq!(mgr.events_of_type(&TraceEventType::Signal).len(), 1);
    }

    #[test]
    fn test_trace_event_type_classification() {
        // Stop events: debugger should pause
        let stop_events = [
            TraceEventType::BreakpointHit,
            TraceEventType::WatchpointHit,
            TraceEventType::Signal,
            TraceEventType::StepCompleted,
        ];
        for evt in &stop_events {
            assert!(evt.is_stop_event(), "{:?} should be stop event", evt);
            assert!(!evt.is_lifecycle(), "{:?} should not be lifecycle", evt);
        }

        // Lifecycle events: structural changes
        let lifecycle_events = [
            TraceEventType::ThreadCreated,
            TraceEventType::ThreadDestroyed,
            TraceEventType::ProcessCreated,
            TraceEventType::ProcessDestroyed,
            TraceEventType::ModuleLoaded,
            TraceEventType::ModuleUnloaded,
        ];
        for evt in &lifecycle_events {
            assert!(evt.is_lifecycle(), "{:?} should be lifecycle", evt);
            assert!(!evt.is_stop_event(), "{:?} should not be stop", evt);
        }

        // Custom event
        let custom = TraceEventType::Custom("my-event".into());
        assert!(!custom.is_stop_event());
        assert!(!custom.is_lifecycle());
        assert_eq!(custom.label(), "my-event");
    }

    #[test]
    fn test_trace_log_manager_severity_filtering() {
        let mut mgr = TraceLogManager::new();

        mgr.log(TraceLogEntry::new(0, LogLevel::Trace, "trace msg"));
        mgr.log(TraceLogEntry::new(0, LogLevel::Debug, "debug msg"));
        mgr.log(TraceLogEntry::new(0, LogLevel::Info, "info msg"));
        mgr.log(
            TraceLogEntry::new(1, LogLevel::Warn, "warn msg").with_category("gdb"),
        );
        mgr.error(1, "error msg");

        assert_eq!(mgr.len(), 5);

        // Filter by severity
        assert_eq!(mgr.entries_at_level(LogLevel::Info).len(), 3);
        assert_eq!(mgr.entries_at_level(LogLevel::Warn).len(), 2);
        assert_eq!(mgr.entries_at_level(LogLevel::Error).len(), 1);

        // Filter by snap
        assert_eq!(mgr.entries_at_snap(0).len(), 3);
        assert_eq!(mgr.entries_at_snap(1).len(), 2);
    }

    #[test]
    fn test_trace_log_level_ordering() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);

        // Verify display
        assert_eq!(LogLevel::Trace.to_string(), "TRACE");
        assert_eq!(LogLevel::Debug.to_string(), "DEBUG");
        assert_eq!(LogLevel::Info.to_string(), "INFO");
        assert_eq!(LogLevel::Warn.to_string(), "WARN");
        assert_eq!(LogLevel::Error.to_string(), "ERROR");
    }

    // ========================================================================
    // Framework-TraceModeling: ghidra.trace.database.target.iface
    // ========================================================================

    #[test]
    fn test_event_scope_hierarchical() {
        let mut mgr = DbEventScopeManager::new();

        // Process-level scope (handles all events)
        mgr.register(DbObjectEventScope::new(1));

        // Thread-level scope (only breakpoint events)
        let mut thread_scope = DbObjectEventScope::new(2).with_parent(1);
        thread_scope.add_handled_event("breakpoint-hit");
        thread_scope.add_handled_event("watchpoint-hit");
        mgr.register(thread_scope);

        // Deactivated scope
        let mut inactive = DbObjectEventScope::new(3);
        inactive.deactivate(10);
        mgr.register(inactive);

        // Verify scoping behavior
        assert_eq!(mgr.len(), 3);
        assert_eq!(mgr.active_scopes().len(), 2);

        // Process scope handles everything
        let process_scope = mgr.find_by_object(1).unwrap();
        assert!(process_scope.handles("breakpoint-hit"));
        assert!(process_scope.handles("signal"));
        assert!(process_scope.handles_all());

        // Thread scope handles only breakpoints
        let thread_scope = mgr.find_by_object(2).unwrap();
        assert!(thread_scope.handles("breakpoint-hit"));
        assert!(!thread_scope.handles("signal"));

        // Find scopes that handle breakpoint-hit
        let bp_scopes = mgr.scopes_for_event("breakpoint-hit");
        assert_eq!(bp_scopes.len(), 2);
    }

    #[test]
    fn test_method_manager_realistic() {
        let mut mgr = DbMethodManager::new();

        // Add main()
        let main = DbObjectMethod::new(1, "main", 0x400000, Lifespan::now_on(0))
            .with_size(0x200)
            .with_return_type("int")
            .with_calling_convention("cdecl")
            .with_namespace("MyApp");
        mgr.add_method(main);

        // Add helper()
        let mut helper = DbObjectMethod::new(2, "helper", 0x400200, Lifespan::now_on(0))
            .with_size(0x100)
            .with_return_type("void");
        helper.add_parameter(crate::db::trace_db_method::MethodParameter::new(
            "x", "int", 0,
        ));
        helper.add_parameter(
            crate::db::trace_db_method::MethodParameter::new("y", "int", 1),
        );
        mgr.add_method(helper);

        // Add library function
        let printf = DbObjectMethod::new(3, "printf", 0x7f000000, Lifespan::now_on(0))
            .with_size(0x50)
            .as_library();
        mgr.add_method(printf);

        assert_eq!(mgr.len(), 3);

        // Lookup by entry point
        let found = mgr.find_by_entry(0x400000).unwrap();
        assert_eq!(found.name, "main");
        assert_eq!(found.qualified_name(), "MyApp::main");

        // Lookup by name
        let found_by_name = mgr.find_by_name("helper");
        assert_eq!(found_by_name.len(), 1);
        assert_eq!(found_by_name[0].parameter_count(), 2);

        // Lookup containing address
        let at_0x400050 = mgr.find_containing(0x400050, 0).unwrap();
        assert_eq!(at_0x400050.name, "main");

        let at_0x400250 = mgr.find_containing(0x400250, 0).unwrap();
        assert_eq!(at_0x400250.name, "helper");

        // Library function check
        let lib = mgr.find_by_entry(0x7f000000).unwrap();
        assert!(lib.is_library);
    }

    #[test]
    fn test_method_address_containment() {
        let m = DbObjectMethod::new(1, "func", 0x400000, Lifespan::now_on(0))
            .with_size(0x100);

        assert!(m.contains_address(0x400000)); // start
        assert!(m.contains_address(0x4000FF)); // last byte
        assert!(!m.contains_address(0x400100)); // one past end
        assert!(!m.contains_address(0x3FFFFF)); // before start
        assert!(!m.contains_address(0x500000)); // way past

        // Unknown size: only entry point matches
        let m2 = DbObjectMethod::new(2, "stub", 0x500000, Lifespan::now_on(0));
        assert!(m2.contains_address(0x500000));
        assert!(!m2.contains_address(0x500001));
    }

    #[test]
    fn test_method_namespace_qualified_name() {
        let m1 = DbObjectMethod::new(1, "func", 0x100, Lifespan::now_on(0));
        assert_eq!(m1.qualified_name(), "func");

        let m2 = DbObjectMethod::new(2, "func", 0x200, Lifespan::now_on(0))
            .with_namespace("std::vector");
        assert_eq!(m2.qualified_name(), "std::vector::func");

        let m3 = DbObjectMethod::new(3, "func", 0x300, Lifespan::now_on(0))
            .with_namespace("A::B::C");
        assert_eq!(m3.qualified_name(), "A::B::C::func");
    }

    // ========================================================================
    // Cross-module integration: Trace + Events + Methods
    // ========================================================================

    #[test]
    fn test_trace_with_events_and_methods() {
        let mut trace = Trace::new("integration-test");

        // Create some snapshots
        trace.create_snapshot_with_desc("initial state");
        trace.create_snapshot_with_desc("breakpoint hit");

        assert_eq!(trace.snap_count(), 2);

        // Create event manager (would normally be part of the trace)
        let mut events = TraceEventManager::new();
        events.record_event(0, TraceEventType::ProcessCreated, "attached");
        events.record_event(1, TraceEventType::BreakpointHit, "hit at main");

        assert_eq!(events.len(), 2);

        // Create method manager
        let mut methods = DbMethodManager::new();
        methods.add_method(
            DbObjectMethod::new(1, "main", 0x400000, Lifespan::now_on(0)).with_size(0x100),
        );

        // Simulate: breakpoint hit event references a method
        let bp_event = &events.events()[1];
        assert_eq!(bp_event.event_type, TraceEventType::BreakpointHit);

        let method = methods.find_by_entry(0x400000).unwrap();
        assert_eq!(method.name, "main");
        assert!(method.contains_address(0x400050));
    }

    #[test]
    fn test_event_scope_with_breakpoint_events() {
        let mut mgr = DbEventScopeManager::new();

        // Session scope handles everything
        mgr.register(DbObjectEventScope::new(1));

        // Thread scope handles only breakpoint-related events
        let mut thread_scope = DbObjectEventScope::new(2).with_parent(1);
        thread_scope.add_handled_event("breakpoint-hit");
        thread_scope.add_handled_event("watchpoint-hit");
        mgr.register(thread_scope);

        // When a breakpoint-hit event occurs, find which scopes should be notified
        let bp_scopes = mgr.scopes_for_event("breakpoint-hit");
        assert_eq!(bp_scopes.len(), 2); // both session and thread scopes

        // When a signal event occurs, only the session scope is notified
        let sig_scopes = mgr.scopes_for_event("signal");
        assert_eq!(sig_scopes.len(), 1); // only session scope

        // Deactivate thread scope
        if let Some(scope) = mgr.find_by_object_mut(2) {
            scope.deactivate(100);
        }

        let bp_scopes_after = mgr.scopes_for_event("breakpoint-hit");
        assert_eq!(bp_scopes_after.len(), 1); // only session scope
    }

    #[test]
    fn test_log_entry_with_metadata() {
        let entry = TraceLogEntry::new(5, LogLevel::Info, "Breakpoint set")
            .with_category("gdb")
            .with_timestamp(1700000000000);

        assert_eq!(entry.snap, 5);
        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.message, "Breakpoint set");
        assert_eq!(entry.category, "gdb");
        assert_eq!(entry.timestamp_ms, Some(1700000000000));
    }

    #[test]
    fn test_serde_roundtrip_all_new_types() {
        // ValueChangeEvent
        let event = ValueChangeEvent::new(ValueChangeKind::Inserted, 1, "test", 0, 5);
        let json = serde_json::to_string(&event).unwrap();
        let back: ValueChangeEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, ValueChangeKind::Inserted);

        // TargetTreeSnapshot
        let mut snap = TargetTreeSnapshot::new(0);
        snap.add_entry(1, "key", Some(10));
        let json = serde_json::to_string(&snap).unwrap();
        let back: TargetTreeSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);

        // TraceEvent
        let event = TraceEvent::new(1, 0, TraceEventType::BreakpointHit, "hit");
        let json = serde_json::to_string(&event).unwrap();
        let back: TraceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.event_type, TraceEventType::BreakpointHit);

        // TraceLogEntry
        let entry = TraceLogEntry::new(0, LogLevel::Error, "oops");
        let json = serde_json::to_string(&entry).unwrap();
        let back: TraceLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.level, LogLevel::Error);

        // DbObjectEventScope
        let scope = DbObjectEventScope::new(1).with_parent(10);
        let json = serde_json::to_string(&scope).unwrap();
        let back: DbObjectEventScope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.parent_scope_key, Some(10));

        // DbObjectMethod
        let method = DbObjectMethod::new(1, "main", 0x400000, Lifespan::now_on(0))
            .with_size(0x100)
            .with_namespace("MyApp");
        let json = serde_json::to_string(&method).unwrap();
        let back: DbObjectMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "main");
        assert_eq!(back.qualified_name(), "MyApp::main");
    }

    #[test]
    fn test_custom_event_type() {
        let custom = TraceEventType::Custom("process-injected".into());
        assert_eq!(custom.label(), "process-injected");
        assert_eq!(custom.to_string(), "process-injected");
        assert!(!custom.is_stop_event());
        assert!(!custom.is_lifecycle());

        // Can be used in event manager
        let mut mgr = TraceEventManager::new();
        mgr.record_event(0, custom, "DLL injected into process");
        assert_eq!(mgr.len(), 1);
    }
}
