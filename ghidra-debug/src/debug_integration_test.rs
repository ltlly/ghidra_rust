//! Integration tests for the Debug module.
//!
//! Tests the end-to-end flow of trace data management, including:
//! - Creating traces with threads, processes, and memory
//! - Symbol and reference management
//! - Platform management (host and guest)
//! - Data settings management
//! - Data type management
//! - Pcode trace data access
//! - Target object tree operations
//! - Change tracking

#[cfg(test)]
mod tests {
    use crate::db::{
        trace_db_data_settings::{DataSettingsAdapter, DataSettingsOperations, SettingsValue},
        trace_db_data_type_mgr::{DataTypeConflictHandler, TraceDataTypeManager},
        trace_db_symbol::TraceSymbolDbExt,
    };
    use crate::model::{
        guest::{TraceGuestPlatformMappedRange, TracePlatformManager},
        lifespan::Lifespan,
        memory::TraceMemoryRegion,
        symbol::{TraceReference, TraceSymbol, TraceSymbolManager},
        target_builtin, TraceMemoryState, TraceObjectInterfaceRegistry,
    };
    use crate::pcode::{
        data_access::{
            DefaultPcodeTraceAccess, DefaultPcodeTraceMemoryAccess, DefaultPcodeTraceRegistersAccess,
            PcodeTraceAccess as PcodeAccessTrait,
            PcodeTraceMemoryAccess,
        },
        memory_state::{TraceMemoryStateArithmetic, TraceMemoryStatePiece},
        sleigh_utils::TraceSleighUtils,
    };
    use crate::target::{
        key_path::KeyPath,
        path_matcher::{NoneFilter, PathFilter},
        path_pattern::PathPattern,
    };

    #[test]
    fn test_full_trace_lifecycle() {
        // 1. Create symbol manager and add symbols
        let mut sym_mgr = TraceSymbolManager::new();
        let _main_key = sym_mgr.create_label("main", 0x400000, "ram", Lifespan::now_on(0));
        let _printf_key = sym_mgr.create_label("printf", 0x500000, "ram", Lifespan::now_on(0));
        let _ns_key = sym_mgr.create_namespace("libc", None, Lifespan::ALL);

        // 2. Add references
        let call_ref = TraceReference::memory(0, 0x400010, 0x500000, Lifespan::now_on(0))
            .with_primary(true);
        sym_mgr.add_reference(call_ref);

        // 3. Verify symbol queries
        assert_eq!(sym_mgr.symbol_count(), 3);
        let main_syms = sym_mgr.get_symbols_at(0x400000, "ram", 5);
        assert_eq!(main_syms.len(), 1);
        assert_eq!(main_syms[0].name, "main");

        // 4. Verify reference queries
        let from_main = sym_mgr.references_from(0x400010, 5);
        assert_eq!(from_main.len(), 1);
        assert!(from_main[0].is_primary);

        let to_printf = sym_mgr.references_to(0x500000, 5);
        assert_eq!(to_printf.len(), 1);
    }

    #[test]
    fn test_platform_and_guest_management() {
        let mut plat_mgr = TracePlatformManager::new();

        // Add host platform
        let host_key = plat_mgr.add_platform("x86:LE:64:default", "default");
        plat_mgr.set_native_platform(host_key);

        // Add guest platform (ARM)
        let guest_key = plat_mgr.add_platform("ARM:LE:32:v8", "default");

        // Map guest addresses to host
        plat_mgr.add_guest_range(TraceGuestPlatformMappedRange::new(
            guest_key,
            0x1000, 0x1fff,
            0x7f0000,
            Lifespan::ALL,
        ));

        // Verify guest-to-host translation
        assert_eq!(plat_mgr.guest_to_host(guest_key, 0x1500, 0), Some(0x7f0500));
        assert_eq!(plat_mgr.host_to_guest(guest_key, 0x7f0500, 0), Some(0x1500));

        // Verify out-of-range returns None
        assert_eq!(plat_mgr.guest_to_host(guest_key, 0x2000, 0), None);
    }

    #[test]
    fn test_pcode_trace_execution_flow() {
        // Create a trace access with memory and register state
        let mut access = DefaultPcodeTraceAccess::new(5, 42);

        // Write memory
        access.memory_mut().write_memory("ram", 0x400000, &[0xEB, 0xFE, 0x90, 0xCC]);
        access.memory_mut().write_memory("ram", 0x400010, &[0x48, 0x89, 0xE5]);

        // Write registers
        access
            .registers_mut()
            .write_register("RAX", &[0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        access
            .registers_mut()
            .write_register("RSP", &[0x00, 0xE0, 0xFF, 0x7F, 0x00, 0x00, 0x00, 0x00]);

        // Verify reads
        let code = access.memory().read_memory("ram", 0x400000, 4);
        assert_eq!(code, Some(vec![0xEB, 0xFE, 0x90, 0xCC]));

        let rax = access.registers().read_register("RAX");
        assert_eq!(
            rax,
            Some(vec![0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        );

        // Verify known/unknown state
        assert_eq!(
            access.memory().memory_state("ram", 0x400000, 4),
            crate::pcode::data_access::MemoryState::Known
        );
        assert_eq!(
            access.memory().memory_state("ram", 0x600000, 4),
            crate::pcode::data_access::MemoryState::Unknown
        );
    }

    #[test]
    fn test_pcode_expression_evaluation() {
        let mut mem = DefaultPcodeTraceMemoryAccess::new(0);
        mem.write_memory("ram", 0x400000, &[0xEB, 0xFE, 0x90, 0xCC]);
        let regs = DefaultPcodeTraceRegistersAccess::new(0);

        // Evaluate bytes
        let result = TraceSleighUtils::evaluate_bytes(
            "read", false, &mem, &regs, "ram", 0x400000, 4,
        );
        assert_eq!(result, Some(vec![0xEB, 0xFE, 0x90, 0xCC]));

        // Evaluate with state (known)
        let (bytes, state) = TraceSleighUtils::evaluate_with_state("ram", 0x400000, 2, &mem);
        assert_eq!(bytes, Some(vec![0xEB, 0xFE]));
        assert_eq!(state, crate::pcode::data_access::MemoryState::Known);

        // Evaluate with state (unknown)
        let (bytes, state) = TraceSleighUtils::evaluate_with_state("ram", 0x500000, 4, &mem);
        assert_eq!(bytes, None);
        assert_eq!(state, crate::pcode::data_access::MemoryState::Unknown);

        // Generate expression
        let expr = TraceSleighUtils::generate_expression_for_range("ram", true, 0x400000, 4, 8);
        assert_eq!(expr, "*:4 0x00400000:8");

        let expr_named =
            TraceSleighUtils::generate_expression_for_range("stack", false, 0x100, 8, 4);
        assert_eq!(expr_named, "*[stack]:8 0x00000100:4");
    }

    #[test]
    fn test_memory_state_taint_propagation() {
        let mut piece = TraceMemoryStatePiece::new("test");

        // Set some regions as known
        piece.set_in_space("ram", 0x400000, 0x100, TraceMemoryState::Known);
        piece.set_in_space("ram", 0x500000, 0x100, TraceMemoryState::Known);

        // Check known regions
        assert_eq!(
            piece.get_composite("ram", 0x400000, 0x100),
            TraceMemoryState::Known
        );

        // Check unknown region
        assert_eq!(
            piece.get_composite("ram", 0x600000, 0x100),
            TraceMemoryState::Unknown
        );

        // Fork and verify isolation
        let mut forked = piece.fork();
        forked.set_in_space("ram", 0x600000, 0x100, TraceMemoryState::Known);
        assert_eq!(
            forked.get_composite("ram", 0x600000, 0x100),
            TraceMemoryState::Known
        );
        assert_eq!(
            piece.get_composite("ram", 0x600000, 0x100),
            TraceMemoryState::Unknown
        );
    }

    #[test]
    fn test_state_arithmetic_combine() {
        assert_eq!(
            TraceMemoryStateArithmetic::combine(TraceMemoryState::Known, TraceMemoryState::Known),
            TraceMemoryState::Known
        );
        assert_eq!(
            TraceMemoryStateArithmetic::combine(
                TraceMemoryState::Known,
                TraceMemoryState::Unknown
            ),
            TraceMemoryState::Unknown
        );
        assert_eq!(
            TraceMemoryStateArithmetic::combine_all(&[
                TraceMemoryState::Known,
                TraceMemoryState::Known,
                TraceMemoryState::Known
            ]),
            TraceMemoryState::Known
        );
        assert_eq!(
            TraceMemoryStateArithmetic::combine_all(&[
                TraceMemoryState::Known,
                TraceMemoryState::Unknown,
                TraceMemoryState::Known
            ]),
            TraceMemoryState::Unknown
        );
    }

    #[test]
    fn test_target_path_filtering() {
        // Create path patterns
        let processes_pattern = PathPattern::new(KeyPath::of(&["Processes", "[]"]));
        let threads_pattern = PathPattern::new(KeyPath::of(&["Processes", "[]", "Threads", "[]"]));

        // Test matching
        assert!(processes_pattern.matches(&KeyPath::of(&["Processes", "[5]"])));
        assert!(!processes_pattern.matches(&KeyPath::of(&["Processes", "name"])));
        assert!(threads_pattern.matches(&KeyPath::of(&["Processes", "[5]", "Threads", "[3]"])));

        // Test successor matching
        assert!(threads_pattern.successor_could_match(
            &KeyPath::of(&["Processes", "[5]"]),
            false
        ));
        assert!(!threads_pattern.successor_could_match(
            &KeyPath::of(&["Processes", "[5]", "Threads", "[3]"]),
            true
        ));

        // Test PathFilter trait
        let filter: &dyn PathFilter = &processes_pattern;
        assert!(filter.matches(&KeyPath::of(&["Processes", "[5]"])));
        assert!(!filter.is_none());

        let none_filter = NoneFilter;
        assert!(none_filter.is_none());
    }

    #[test]
    fn test_target_object_interface_registry() {
        let mut registry = TraceObjectInterfaceRegistry::new();

        // Register all built-in types
        for info in target_builtin::all_builtins() {
            registry.register(info);
        }

        // Verify key types are registered
        assert!(registry.get("Process").is_some());
        assert!(registry.get("Thread").is_some());
        assert!(registry.get("Module").is_some());
        assert!(registry.get("Environment").is_some());
        assert!(registry.get("Activatable").is_some());
        assert!(registry.get("Method").is_some());
        assert!(registry.get("Togglable").is_some());

        // Verify type counts
        assert!(registry.len() >= 20);
    }

    #[test]
    fn test_memory_region_operations() {
        let region = TraceMemoryRegion::new(0x400000, 0x400fff, TraceMemoryState::Known);

        assert_eq!(region.min_offset, 0x400000);
        assert_eq!(region.max_offset, 0x400fff);
        assert_eq!(region.size(), 0x1000);
        assert_eq!(region.state, TraceMemoryState::Known);
    }

    #[test]
    fn test_thread_types() {
        use crate::model::thread::{TraceProcess, TraceThread};
        use crate::model::execution_state::TraceExecutionState;

        let proc = TraceProcess {
            key: 1,
            path: "Processes[1]".into(),
            name: "my_program".into(),
            pid: Some(1234),
            lifespan: Lifespan::now_on(0),
        };
        assert_eq!(proc.pid, Some(1234));
        assert_eq!(proc.name, "my_program");

        let thread = TraceThread {
            key: 1,
            path: "Processes[1]/Threads[1001]".into(),
            name: "main".into(),
            tid: Some(1001),
            comment: None,
            lifespan: Lifespan::now_on(0),
            execution_state: TraceExecutionState::Running,
        };
        assert_eq!(thread.tid, Some(1001));
        assert_eq!(thread.name, "main");
    }

    #[test]
    fn test_db_symbol_operations() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.create_symbol_tables().unwrap();

        // Insert symbols
        let sym1 = TraceSymbol::label(1, "main", 0x400000, "ram", Lifespan::now_on(0));
        let sym2 = TraceSymbol::function(2, "printf", 0x500000, "ram", None, Lifespan::now_on(0));
        conn.insert_symbol(&sym1).unwrap();
        conn.insert_symbol(&sym2).unwrap();

        // Query by name
        let found = conn.get_symbols_by_name("main", 5).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].address, Some(0x400000));

        // Query by address
        let at_addr = conn.get_symbols_at(0x500000, "ram", 5).unwrap();
        assert_eq!(at_addr.len(), 1);
        assert_eq!(at_addr[0].name, "printf");

        // Insert references
        let r = TraceReference::memory(1, 0x400010, 0x500000, Lifespan::now_on(0));
        conn.insert_reference(&r).unwrap();

        let from = conn.get_references_from(0x400010, 5).unwrap();
        assert_eq!(from.len(), 1);
        assert_eq!(from[0].to_address, 0x500000);
    }

    #[test]
    fn test_data_settings_flow() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let adapter = DataSettingsAdapter::new(&conn).unwrap();

        // Set various types of settings
        let lifespan = Lifespan::span(0, 100);

        adapter.set_long("ram", 0x400000, "width", 4, lifespan).unwrap();
        adapter
            .set_string("ram", 0x400000, "label", "entry_point", lifespan)
            .unwrap();
        adapter
            .set_bytes("ram", 0x400000, "patch", &[0x90, 0x90], lifespan)
            .unwrap();

        // Retrieve settings
        let width = adapter.get_value("ram", 0x400000, "width", 50).unwrap();
        assert_eq!(width, Some(SettingsValue::Long(4)));

        let label = adapter.get_value("ram", 0x400000, "label", 50).unwrap();
        assert_eq!(
            label,
            Some(SettingsValue::String("entry_point".into()))
        );

        let patch = adapter.get_value("ram", 0x400000, "patch", 50).unwrap();
        assert_eq!(patch, Some(SettingsValue::Bytes(vec![0x90, 0x90])));

        // Get all settings at address
        let all = adapter.get_all_at("ram", 0x400000, 50).unwrap();
        assert_eq!(all.len(), 3);

        // Outside snap range
        let outside = adapter.get_value("ram", 0x400000, "width", 200).unwrap();
        assert_eq!(outside, None);
    }

    #[test]
    fn test_data_type_management() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let mgr = TraceDataTypeManager::new(&conn).unwrap();
        let root_id = mgr.root_category_id().unwrap();

        // Create categories
        let builtin_cat = mgr.create_category(root_id, "builtin").unwrap();
        let struct_cat = mgr.create_category(root_id, "structs").unwrap();
        let net_cat = mgr.create_category(struct_cat, "network").unwrap();

        // Add data types
        mgr.add_data_type(builtin_cat, "int", 4, true, DataTypeConflictHandler::default())
            .unwrap();
        mgr.add_data_type(builtin_cat, "long", 8, true, DataTypeConflictHandler::default())
            .unwrap();
        mgr.add_data_type(struct_cat, "point", 8, false, DataTypeConflictHandler::default())
            .unwrap();
        mgr.add_data_type(net_cat, "ip_header", 20, false, DataTypeConflictHandler::default())
            .unwrap();

        // Verify types
        assert_eq!(mgr.data_type_count().unwrap(), 4);
        assert!(mgr.get_data_type_by_path("/builtin/int").unwrap().is_some());
        assert!(mgr.get_data_type_by_path("/structs/network/ip_header").unwrap().is_some());

        // Verify categories
        let cats = mgr.list_categories().unwrap();
        assert_eq!(cats.len(), 4); // root + builtin + structs + network
    }

    #[test]
    fn test_data_type_conflict_resolution() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let mgr = TraceDataTypeManager::new(&conn).unwrap();
        let root_id = mgr.root_category_id().unwrap();

        // Add type with KeepExisting
        let id1 = mgr
            .add_data_type(root_id, "mytype", 4, false, DataTypeConflictHandler::KeepExisting)
            .unwrap();
        let id2 = mgr
            .add_data_type(root_id, "mytype", 8, false, DataTypeConflictHandler::KeepExisting)
            .unwrap();
        assert_eq!(id1, id2);

        // Add type with ReplaceExisting
        mgr.add_data_type(root_id, "other", 4, false, DataTypeConflictHandler::ReplaceExisting)
            .unwrap();
        let _id = mgr
            .add_data_type(root_id, "other", 8, false, DataTypeConflictHandler::ReplaceExisting)
            .unwrap();
        let dt = mgr.get_data_type_by_path("/other").unwrap().unwrap();
        assert_eq!(dt.size, 8);

        // Add type with RenameNew
        let id_a = mgr
            .add_data_type(root_id, "unique", 4, false, DataTypeConflictHandler::RenameNew)
            .unwrap();
        let id_b = mgr
            .add_data_type(root_id, "unique", 8, false, DataTypeConflictHandler::RenameNew)
            .unwrap();
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn test_guest_platform_isolation() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();

        // Host manager
        let host_mgr = TraceDataTypeManager::new(&conn).unwrap();
        let host_root = host_mgr.root_category_id().unwrap();
        host_mgr
            .add_data_type(host_root, "host_int", 4, true, DataTypeConflictHandler::default())
            .unwrap();

        // Guest manager (ARM)
        let guest_mgr = TraceDataTypeManager::new_for_guest(&conn, 1).unwrap();
        let guest_root = guest_mgr.root_category_id().unwrap();
        guest_mgr
            .add_data_type(guest_root, "arm_word", 4, true, DataTypeConflictHandler::default())
            .unwrap();

        // Host should only see its own types
        assert!(host_mgr.get_data_type_by_path("/host_int").unwrap().is_some());
        assert!(host_mgr.get_data_type_by_path("/arm_word").unwrap().is_none());

        // Guest should only see its own types
        assert!(guest_mgr.get_data_type_by_path("/arm_word").unwrap().is_some());
        assert!(guest_mgr.get_data_type_by_path("/host_int").unwrap().is_none());
    }

    #[test]
    fn test_change_tracking() {
        let mut cs = crate::model::changeset::TraceChangeSet::new();

        // Record various changes
        cs.record(crate::model::changeset::TraceChangeRecord::new(
            crate::model::changeset::ChangeType::Added,
            "thread",
            "Threads[1]",
        ));
        cs.record(crate::model::changeset::TraceChangeRecord::new(
            crate::model::changeset::ChangeType::Modified,
            "memory",
            "0x400000",
        ));
        cs.record(crate::model::changeset::TraceChangeRecord::new(
            crate::model::changeset::ChangeType::Removed,
            "bookmark",
            "mark1",
        ));

        assert!(cs.has_changes());
        assert!(cs.is_memory_changed());
        assert_eq!(cs.len(), 3);

        // Mark snaps dirty
        cs.mark_snap_dirty(0);
        cs.mark_snap_dirty(5);
        assert_eq!(cs.dirty_snaps().len(), 2);

        // Clear
        cs.clear();
        assert!(!cs.has_changes());
    }

    #[test]
    fn test_breakpoint_kinds() {
        use crate::model::breakpoint::TraceBreakpointKind as BpKind;

        assert_eq!(BpKind::SwExecute.encoding_char(), 'x');
        assert_eq!(BpKind::HwExecute.encoding_char(), 'X');
        assert_eq!(BpKind::Read.encoding_char(), 'R');
        assert_eq!(BpKind::Write.encoding_char(), 'W');
    }

    #[test]
    fn test_state_span_map_operations() {
        use crate::pcode::memory_state::StateSpanMap;

        let mut map = StateSpanMap::new();

        // Set known state for a range
        map.set(0, 100, TraceMemoryState::Known);
        assert_eq!(map.get(0, 100), TraceMemoryState::Known);
        assert_eq!(map.get(0, 200), TraceMemoryState::Unknown);

        // Split range
        map.set(50, 50, TraceMemoryState::Unknown);
        assert_eq!(map.get(0, 50), TraceMemoryState::Known);
        assert_eq!(map.get(50, 50), TraceMemoryState::Unknown);
    }

    #[test]
    fn test_lifespan_operations() {
        let ls1 = Lifespan::now_on(0);
        assert!(ls1.contains(0));
        assert!(ls1.contains(100));

        let ls2 = Lifespan::span(5, 10);
        assert!(!ls2.contains(4));
        assert!(ls2.contains(5));
        assert!(ls2.contains(10));
        assert!(!ls2.contains(11));

        // Test ALL lifespan
        assert!(Lifespan::ALL.contains(0));
        assert!(Lifespan::ALL.contains(i64::MAX));
    }

    #[test]
    fn test_address_translator() {
        let mut plat_mgr = TracePlatformManager::new();
        let host_key = plat_mgr.add_platform("x86:LE:64:default", "default");
        let guest_key = plat_mgr.add_platform("ARM:LE:32:v8", "default");
        plat_mgr.set_native_platform(host_key);

        plat_mgr.add_guest_range(TraceGuestPlatformMappedRange::new(
            guest_key,
            0x1000, 0x1fff,
            0x7f0000,
            Lifespan::ALL,
        ));

        // Translate guest -> host
        let host_addr = plat_mgr.guest_to_host(guest_key, 0x1500, 0);
        assert_eq!(host_addr, Some(0x7f0500));

        // Translate host -> guest
        let guest_addr = plat_mgr.host_to_guest(guest_key, 0x7f0500, 0);
        assert_eq!(guest_addr, Some(0x1500));
    }

    #[test]
    fn test_full_pcode_state_piece() {
        let mut piece = TraceMemoryStatePiece::new("test_trace");

        // Configure unique space
        piece.set_unique(0x100, 8, TraceMemoryState::Known);
        assert_eq!(piece.get_unique(0x100, 8), TraceMemoryState::Known);

        // Configure named spaces
        piece.set_in_space("ram", 0x400000, 0x1000, TraceMemoryState::Known);
        piece.set_in_space("register", 0, 0x100, TraceMemoryState::Known);

        // Check composites
        assert_eq!(
            piece.get_composite("unique", 0x100, 8),
            TraceMemoryState::Known
        );
        assert_eq!(
            piece.get_composite("ram", 0x400000, 0x1000),
            TraceMemoryState::Known
        );
        assert_eq!(
            piece.get_composite("register", 0, 0x100),
            TraceMemoryState::Known
        );

        // Unknown regions
        assert_eq!(
            piece.get_composite("ram", 0x600000, 4),
            TraceMemoryState::Unknown
        );
    }

    #[test]
    fn test_key_path_operations() {
        let path = KeyPath::of(&["Processes", "[5]", "Threads", "[3]"]);
        assert_eq!(path.size(), 4);
        assert_eq!(path.get(0), Some("Processes"));
        assert_eq!(path.get(1), Some("[5]"));
        assert!(KeyPath::is_index_str("[5]"));
        assert!(!KeyPath::is_index_str("name"));

        // Root path
        assert_eq!(KeyPath::ROOT.size(), 0);
    }

    // ===== New modules: db::trace_db_changeset =====

    #[test]
    fn test_changeset_undo_redo_integration() {
        let mut cs = crate::db::trace_db_changeset::DbTraceChangeSet::new();

        // Transaction 1: insert thread
        cs.start_transaction();
        cs.record(crate::db::trace_db_changeset::ChangeRecord::new(
            crate::db::trace_db_changeset::ChangeOperation::Insert,
            "threads", 1, "new thread",
        ));
        cs.end_transaction(true);

        // Transaction 2: write memory
        cs.start_transaction();
        cs.record(crate::db::trace_db_changeset::ChangeRecord::new(
            crate::db::trace_db_changeset::ChangeOperation::Update,
            "memory", 0x400000, "write bytes",
        ));
        cs.end_transaction(true);

        assert_eq!(cs.undo_depth(), 2);
        assert!(cs.can_undo());
        assert!(!cs.can_redo());

        // Undo transaction 2
        let undone = cs.undo().unwrap();
        assert_eq!(undone.len(), 1);
        assert_eq!(undone[0].table, "memory");

        // Redo
        let redone = cs.redo().unwrap();
        assert_eq!(redone[0].table, "memory");
    }

    // ===== New modules: db::trace_db_direct_listener =====

    #[test]
    fn test_direct_listener_integration() {
        use crate::db::trace_db_direct_listener::*;
        use std::sync::atomic::{AtomicU32, Ordering};

        struct CountingListener {
            count: AtomicU32,
        }
        impl DirectChangeListener for CountingListener {
            fn on_change(&self, _event: &DirectChangeEvent) {
                self.count.fetch_add(1, Ordering::SeqCst);
            }
        }

        let mut set = DirectChangeListenerSet::new();
        set.add(Box::new(CountingListener { count: AtomicU32::new(0) }));
        set.add(Box::new(CountingListener { count: AtomicU32::new(0) }));

        // Notify
        let event = DirectChangeEvent::new(DirectChangeKind::MemoryBytesChanged, 5)
            .with_space("ram")
            .with_range(0x1000, 0x1fff);
        set.notify(&event);
        assert_eq!(set.len(), 2);

        // Various event kinds
        let snap_event = DirectChangeEvent::new(DirectChangeKind::SnapAdded, 10);
        set.notify(&snap_event);
    }

    // ===== New modules: db::trace_db_user_data =====

    #[test]
    fn test_user_data_integration() {
        use crate::db::trace_db_user_data::*;

        let mut data = DbTraceUserData::new();

        // Store some preferences
        data.put(UserDataEntry::new("theme", "dark"));
        data.put(UserDataEntry::new("font_size", "14").with_namespace("editor"));
        data.put(UserDataEntry::new("tab_width", "4").with_namespace("editor"));
        data.put(UserDataEntry::new("recent_files", "/tmp/test.c"));

        assert_eq!(data.len(), 4);
        assert_eq!(data.get_string("theme", None), Some("dark"));
        assert_eq!(data.get_string("font_size", Some("editor")), Some("14"));

        // Namespace isolation
        let editor_entries = data.entries_in_namespace("editor");
        assert_eq!(editor_entries.len(), 2);

        // Remove
        data.remove("recent_files", None);
        assert_eq!(data.len(), 3);

        // Persistence filter
        data.put(UserDataEntry::new("temp", "val").with_persistent(false));
        assert_eq!(data.persistent_entries().len(), 3); // temp is not persistent
    }

    // ===== New modules: db::trace_db_utils =====

    #[test]
    fn test_trace_db_utils_integration() {
        use crate::db::trace_db_utils::*;

        // Address space helpers
        assert!(TraceDbUtils::is_register_space("register"));
        assert!(TraceDbUtils::is_memory_space("ram"));
        assert!(TraceDbUtils::is_stack_space("stack"));

        // Snap formatting
        assert_eq!(TraceDbUtils::format_snap(5), "snap:5");
        assert_eq!(TraceDbUtils::parse_snap("snap:5"), Some(5));
        assert_eq!(TraceDbUtils::parse_snap("scratch"), Some(-1));

        // Range overlap
        assert_eq!(TraceDbUtils::range_overlap(0, 100, 50, 150), Some((50, 100)));
        assert_eq!(TraceDbUtils::range_overlap(0, 100, 200, 300), None);

        // Alignment
        assert_eq!(TraceDbUtils::align_down(0x1234, 0x1000), 0x1000);
        assert_eq!(TraceDbUtils::align_up(0x1234, 0x1000), 0x2000);

        // Database info
        let info = TraceDatabaseInfo::new(
            "my_trace", "x86:LE:64:default", "default",
        )
        .with_platform("linux")
        .with_executable_path("/bin/test");
        assert_eq!(info.platform, Some("linux".into()));
    }

    // ===== New target interface types =====

    #[test]
    fn test_target_interfaces_integration() {
        use crate::model::target_iface::*;

        // Process
        let mut proc = TraceTargetProcess::new(
            KeyPath::parse("Processes[0]"), 1234, "test",
        );
        assert!(proc.is_alive());
        proc.state = ExecutionState::Stopped;
        assert!(proc.is_alive());
        proc.state = ExecutionState::Terminated;
        assert!(!proc.is_alive());

        // Stack
        let mut stack = TraceTargetStack::new(KeyPath::parse("Stack"), 1);
        stack.push_frame(TraceTargetStackFrame::new(
            KeyPath::parse("F[0]"), 0, 0x401000, 0x7fff0000,
        ));
        assert_eq!(stack.depth(), 1);

        // Region
        let region = TraceRegion::new(
            KeyPath::parse("R[0]"), "stack", 0x7fff0000, 0x7fffffff,
            true, true, false,
        );
        assert!(region.contains(0x7fff5000));
        assert_eq!(region.length(), 0x10000);

        // Register value
        let rv = TraceTargetRegisterValue::new(
            "RAX", vec![0x42, 0, 0, 0, 0, 0, 0, 0], 64,
        );
        assert_eq!(rv.as_u64_le(), Some(0x42));

        // Target event
        let event = TraceTargetEvent::new(
            KeyPath::parse("Events[0]"), "breakpoint-hit",
        )
        .with_thread_id(1)
        .with_detail("type", "hardware");
        assert_eq!(event.details.get("type").unwrap(), "hardware");
    }

    // ===== New event types =====

    #[test]
    fn test_new_event_types() {
        use crate::plugin::event::*;

        // TraceOpenedEvent
        let opened = TraceOpenedEvent::new("trace1");
        assert_eq!(opened.trace_id, "trace1");

        // TraceLocationEvent
        let location = TraceLocationEvent::new("trace1", 0x400000).with_space("ram");
        assert_eq!(location.offset, 0x400000);

        // TraceSelectionEvent
        let selection = TraceSelectionEvent::new("trace1", vec![(0x1000, 0x1fff)]);
        assert_eq!(selection.selected_size(), 0x1000);
        assert!(!selection.is_empty());

        // ActivationCause
        assert_ne!(ActivationCause::Navigate, ActivationCause::Opened);

        // DebuggerPluginEvent variants
        let events = vec![
            DebuggerPluginEvent::TraceOpened(TraceOpenedEvent::new("t1")),
            DebuggerPluginEvent::TraceLocation(TraceLocationEvent::new("t1", 0)),
            DebuggerPluginEvent::TraceSelection(TraceSelectionEvent::new("t1", vec![])),
        ];
        assert_eq!(events.len(), 3);
    }

    // ===== New API modules types =====

    #[test]
    fn test_new_api_modules_types() {
        use crate::api::modules::*;

        // RegionMapProposal
        let region = RegionMapProposal::new(".text", 0x1000, 0x2000, 0x400000, 0x401000, Lifespan::now_on(0));
        let entry = region.to_map_entry("trace1");
        assert_eq!(entry.from_min, 0x1000);
        assert_eq!(entry.to_min, 0x400000);

        // DebuggerMissingModuleActionContext
        let missing = DebuggerMissingModuleActionContext::new("trace1", "libc.so.6")
            .with_load_address(0x7f0000);
        assert_eq!(missing.module_name, "libc.so.6");
        assert_eq!(missing.load_address, Some(0x7f0000));

        // DebuggerOpenProgramActionContext
        let open = DebuggerOpenProgramActionContext::new("trace1", "/usr/lib/libc.so", 5);
        assert_eq!(open.snap, 5);

        // DebuggerMissingProgramActionContext
        let missing_prog = DebuggerMissingProgramActionContext::new(
            "trace1", "/usr/lib/libc.so", 0x7f000000, 0x7f001000,
        );
        assert_eq!(missing_prog.trace_min, 0x7f000000);
    }
}
