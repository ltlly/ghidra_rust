//! Integration tests for the newly ported Debug modules.
//!
//! Tests the end-to-end flow of the following newly ported types:
//! - Domain object listeners (from Framework-TraceModeling/model)
//! - Trace emulation integration (from Framework-TraceModeling/model)
//! - Memory buffer types (from Framework-TraceModeling)
//! - Trace RMI acceptor and launch offers (from Debugger-api)
//! - Platform mapper and disassembly results (from Debugger-api)
//! - Static mapping change listeners (from Debugger-api)
//! - DB Trace link content handler (from Framework-TraceModeling/database)
//! - DB Trace overlay space adapter (from Framework-TraceModeling/database)
//! - DB Trace equate manager (from Framework-TraceModeling/database)
//! - DB Trace class/label/namespace symbols (from Framework-TraceModeling/database)
//! - DB Trace memory buffers (from Framework-TraceModeling/database)
//! - DB Trace program view fragments and functions (from Framework-TraceModeling/database)
//! - Program emulation utilities (from Debugger plugin)

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use crate::api::platform_mapper::{DisassemblyResult, RegisterMapping};
    use crate::api::static_mapping::StaticMappingEntry;
    use crate::api::trace_rmi_acceptor::TraceRmiLaunchOffer;
    use crate::db::trace_db_class_symbol::{
        NamespaceKind, TraceClassSymbol, TraceClassSymbolView,
        TraceLabelSymbol, TraceLabelSymbolView,
    };
    use crate::db::trace_db_equate::{DBTraceEquateManager, TraceEquateReference};
    use crate::db::trace_db_fragment::{
        CallingConvention, DBTraceProgramViewFunctionManager,
        DBTraceProgramViewFragmentManager, FunctionType,
    };
    use crate::db::trace_db_link_content::{ContentLink, DBTraceLinkContentHandler, LinkType};
    use crate::db::trace_db_mem_buffer::{DBTraceEmptyMemBuffer, DBTraceMemBuffer};
    use crate::db::trace_db_overlay::DBTraceOverlaySpaceAdapter;
    use crate::model::domain_object_listener::{
        DomainObjectChangeRecord, DomainObjectChangedEvent, DomainObjectEvent,
        TraceDomainObjectListener,
    };
    use crate::model::mem_buffer::{MemBuffer, SimpleMemBuffer};
    use crate::model::trace_emulation::{
        EmulationMode, EmulationStateSnapshot, EmulationStatus, TraceEmulationIntegration,
        UnknownStatePcodeExecutionException,
    };
    use crate::model::memory::TraceMemoryState;
    use crate::model::Lifespan;
    use crate::plugin::program_emulation::{
        EmulationConfig, EmulationInitType, MemoryPermissions, MemoryRegionMapping,
        ProgramEmulationUtils,
    };

    /// Test that the domain object listener dispatches events correctly.
    #[test]
    fn test_domain_object_listener_integration() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let mut listener = TraceDomainObjectListener::new();
        listener.add_handler(
            DomainObjectEvent::PropertyChanged,
            Box::new(move |_| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            }),
        );

        // Dispatch multiple events
        for _ in 0..5 {
            let event = DomainObjectChangedEvent::new(vec![
                DomainObjectChangeRecord::new(DomainObjectEvent::PropertyChanged, 1),
            ]);
            listener.domain_object_changed(&event);
        }
        assert_eq!(counter.load(Ordering::SeqCst), 5);
    }

    /// Test that trace emulation integration works end-to-end.
    #[test]
    fn test_trace_emulation_integration_e2e() {
        let mut integration = TraceEmulationIntegration::new(EmulationMode::Record)
            .with_max_snapshots(100);

        // Start emulation
        integration.set_status(EmulationStatus::Running);
        assert!(integration.is_active());

        // Record state snapshots
        for i in 0..10 {
            let mut snap = EmulationStateSnapshot::new(i, 0x400000 + (i as u64 * 4), 1);
            snap.add_register("RAX", vec![i as u8; 8]);
            snap.add_modified_memory(0x400000 + (i as u64 * 4), vec![0x90]);
            integration.record_snapshot(snap);
        }

        assert_eq!(integration.snapshot_count(), 10);
        assert_eq!(integration.last_snapshot().unwrap().snap, 9);

        // Complete emulation
        integration.set_status(EmulationStatus::Completed);
        assert!(!integration.is_active());
        assert!(integration.is_finished());
    }

    /// Test that memory buffers correctly provide byte access.
    #[test]
    fn test_memory_buffer_integration() {
        let data = vec![0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10];
        let buf = SimpleMemBuffer::new_known("ram", 0x400000, 0, data);

        assert_eq!(buf.len(), 8);
        assert_eq!(buf.get_byte(0), Some(0x55)); // push rbp
        assert_eq!(buf.get_byte(1), Some(0x48)); // REX.W prefix
        assert_eq!(buf.get_state(0), TraceMemoryState::Known);

        // All bytes are known
        let available = buf.available_bytes();
        assert_eq!(available.len(), 8);
    }

    /// Test that DB trace memory buffers support LE/BE reads.
    #[test]
    fn test_db_mem_buffer_endian_reads() {
        let data = vec![0x78, 0x56, 0x34, 0x12, 0xF0, 0xDE, 0xBC, 0x9A];
        let buf = DBTraceMemBuffer::with_data("ram", 0x400000, 0, data);

        // Little-endian
        assert_eq!(buf.read_u32_le(0), Some(0x12345678));
        assert_eq!(buf.read_u64_le(0), Some(0x9ABCDEF012345678));

        // Big-endian
        assert_eq!(buf.read_u32_be(0), Some(0x78563412));
    }

    /// Test that empty memory buffers return unknown states.
    #[test]
    fn test_empty_mem_buffer_integration() {
        let empty = DBTraceEmptyMemBuffer::new("ram", 0x100000, 0, 256);
        assert_eq!(empty.size(), 256);
        assert_eq!(empty.get_byte(0), None);
        assert_eq!(empty.get_state(0), TraceMemoryState::Unknown);

        // Convert to filled buffer
        let buf = empty.to_mem_buffer(vec![0xFF; 256]);
        assert_eq!(buf.data().len(), 256);
        assert_eq!(buf.data()[0], 0xFF);
    }

    /// Test that disassembly results are created correctly.
    #[test]
    fn test_disassembly_result_integration() {
        let result = DisassemblyResult::new("PUSH", "PUSH RBP", 1)
            .with_bytes(vec![0x55])
            .with_language("x86:LE:64:default", "default");

        assert_eq!(result.mnemonic, "PUSH");
        assert_eq!(result.length, 1);
        assert_eq!(result.bytes, vec![0x55]);
        assert_eq!(result.language_id, "x86:LE:64:default");
    }

    /// Test that register mappings work for x86-64 sub-registers.
    #[test]
    fn test_register_mapping_integration() {
        let mappings = vec![
            RegisterMapping::new("rax", "RAX", 64),
            RegisterMapping::new("eax", "RAX", 32).with_offset(0),
            RegisterMapping::new("ax", "RAX", 16).with_offset(0),
            RegisterMapping::new("al", "RAX", 8).with_offset(0),
            RegisterMapping::new("ah", "RAX", 8).with_offset(8),
        ];

        assert_eq!(mappings.len(), 5);
        assert_eq!(mappings[0].bit_size, 64);
        assert_eq!(mappings[4].bit_offset, 8); // ah offset
    }

    /// Test that static mapping entries support address translation.
    #[test]
    fn test_static_mapping_translation() {
        let entry = StaticMappingEntry::new(
            "file:///program.exe",
            0x400000,
            0x401000,
            0,
            0x1000,
            0,
            i64::MAX,
        );

        // Bidirectional mapping
        assert_eq!(entry.map_to_trace(0x400500), Some(0x500));
        assert_eq!(entry.map_to_program(0x500), Some(0x400500));
        assert!(entry.contains_snap(0));
        assert!(entry.contains_snap(i64::MAX));
    }

    /// Test that the equate manager supports creating and querying equates.
    #[test]
    fn test_equate_manager_integration() {
        let mut mgr = DBTraceEquateManager::new();

        // Create equates in different spaces
        let ram_space = mgr.get_or_create_space("ram");
        let flag_id = ram_space.create_equate("FLAG_READ", 0x01);
        let _write_id = ram_space.create_equate("FLAG_WRITE", 0x02);

        ram_space.add_reference(TraceEquateReference::new(
            flag_id,
            0x400000,
            "ram",
            0,
            0,
            Lifespan::ALL,
        ));

        assert_eq!(mgr.total_equate_count(), 2);
        assert_eq!(mgr.space_names().len(), 1);

        let ram_space = mgr.get_space("ram").unwrap();
        assert_eq!(ram_space.get_references_at(0x400000).len(), 1);
    }

    /// Test that the class symbol view supports namespace hierarchy.
    #[test]
    fn test_class_symbol_hierarchy() {
        let mut view = TraceClassSymbolView::new();

        // Create global -> library -> class hierarchy
        view.add(TraceClassSymbol::new(0, "Global", NamespaceKind::Global, None, Lifespan::ALL));
        view.add(TraceClassSymbol::new(1, "libc", NamespaceKind::Library, Some(0), Lifespan::ALL));
        view.add(TraceClassSymbol::new(2, "stdio", NamespaceKind::Class, Some(1), Lifespan::ALL));
        view.add(TraceClassSymbol::new(3, "string", NamespaceKind::Class, Some(1), Lifespan::ALL));

        assert_eq!(view.children_of(0).len(), 1); // libc
        assert_eq!(view.children_of(1).len(), 2); // stdio, string
        assert_eq!(view.children_of(2).len(), 0); // leaf
    }

    /// Test that the label symbol view supports address lookups.
    #[test]
    fn test_label_symbol_view_integration() {
        let mut view = TraceLabelSymbolView::new();
        view.add(TraceLabelSymbol::new(1, "main", 0x400000, "ram", Lifespan::ALL));
        view.add(TraceLabelSymbol::new(2, "loop", 0x400010, "ram", Lifespan::ALL));
        view.add(TraceLabelSymbol::new(3, "exit", 0x400020, "ram", Lifespan::span(5, 10)));

        // All labels at snap 0
        assert_eq!(view.at_address("ram", 0x400000, 0).len(), 1);

        // exit label is only active between snap 5-10
        assert!(view.at_address("ram", 0x400020, 0).is_empty());
        assert_eq!(view.at_address("ram", 0x400020, 7).len(), 1);
    }

    /// Test that overlay spaces support address translation.
    #[test]
    fn test_overlay_space_integration() {
        let mut adapter = DBTraceOverlaySpaceAdapter::new();

        // Create a ROM overlay
        let rom_id = adapter.create_overlay("ROM", 1, 0, 0xFFFF);
        assert!(rom_id >= 0x8000_0000);

        // Translate overlay -> base
        let base = adapter.overlay_to_base(rom_id, 0x1000);
        assert_eq!(base, Some((1, 0x1000)));

        // Translate base -> overlay
        let overlay = adapter.base_to_overlay(1, 0x1000);
        assert_eq!(overlay, Some((rom_id, 0x1000)));
    }

    /// Test that link content handler supports chain resolution.
    #[test]
    fn test_link_content_handler_integration() {
        let mut handler = DBTraceLinkContentHandler::with_max_depth(8);

        handler.add_link(ContentLink::new(LinkType::Direct, "/traces/main", 0, 4096));
        handler.add_link(ContentLink::new(LinkType::Shared, "/traces/shared", 0, 1024));

        assert_eq!(handler.link_count(), 2);
        assert!(handler.resolve_link(0).is_ok());

        // Find links to a target
        let links = handler.find_links_to("/traces/main");
        assert_eq!(links.len(), 1);
    }

    /// Test that program view fragment manager supports hierarchy.
    #[test]
    fn test_fragment_manager_integration() {
        let mut mgr = DBTraceProgramViewFragmentManager::new("Program");

        let root = mgr.root_id();
        let _text = mgr.create_fragment(".text", "ram", 0x400000, 0x401000, root);
        let data = mgr.create_fragment(".data", "ram", 0x600000, 0x601000, root);
        let _bss = mgr.create_fragment(".bss", "ram", 0x601000, 0x602000, root);

        assert_eq!(mgr.fragment_count(), 4); // root + 3 children
        assert_eq!(mgr.child_fragments(root).len(), 3);

        // Find fragment at an address
        let found = mgr.find_fragment_at("ram", 0x400500);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, ".text");

        // Delete a fragment
        assert!(mgr.delete_fragment(data));
        assert_eq!(mgr.fragment_count(), 3);
    }

    /// Test that function manager supports entry-point lookups.
    #[test]
    fn test_function_manager_integration() {
        let mut mgr = DBTraceProgramViewFunctionManager::new();

        let main_id = mgr.create_function("main", 0x400000, "ram");
        let helper_id = mgr.create_function("helper", 0x400100, "ram");

        // Add body ranges
        if let Some(func) = mgr.get_function_mut(main_id) {
            func.add_body_range(0x400000, 0x4000FF);
            func.function_type = FunctionType::Regular;
            func.calling_convention = CallingConvention::SystemV;
        }
        if let Some(func) = mgr.get_function_mut(helper_id) {
            func.add_body_range(0x400100, 0x40017F);
            func.function_type = FunctionType::Inline;
        }

        assert_eq!(mgr.function_count(), 2);

        // Entry-point lookup
        let main = mgr.get_function_at("ram", 0x400000).unwrap();
        assert_eq!(main.name, "main");
        assert_eq!(main.function_type, FunctionType::Regular);

        // Containing lookup
        let funcs = mgr.find_functions_containing("ram", 0x400120);
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "helper");
    }

    /// Test that program emulation config builds correctly.
    #[test]
    fn test_program_emulation_config_integration() {
        let config = EmulationConfig::new(EmulationInitType::FromProgram)
            .with_snap(0)
            .with_thread(1)
            .with_register("RAX", vec![0; 8])
            .with_register("RSP", vec![0, 0, 0xF0, 0x7F, 0, 0, 0, 0])
            .with_memory_region(
                MemoryRegionMapping::new("ram", 0x400000, 0x1000, MemoryPermissions::RX)
                    .with_name(".text"),
            )
            .with_memory_region(
                MemoryRegionMapping::new("ram", 0x600000, 0x1000, MemoryPermissions::RW)
                    .with_name(".data"),
            )
            .with_max_steps(5000);

        let result = ProgramEmulationUtils::setup_from_program("test.exe", &config);
        assert!(result.warnings.is_empty());
        assert_eq!(result.mapped_regions.len(), 2);
        assert_eq!(result.initialized_registers.len(), 2);

        // Stack and code region helpers
        let stack = ProgramEmulationUtils::create_stack_region("ram", 0x7FFF0000, 0x10000);
        assert_eq!(stack.name, "Stack");
        assert!(stack.permissions.write);
    }

    /// Test that the RMI launch offer types work correctly.
    #[test]
    fn test_rmi_launch_offer_integration() {
        let gdb_offer = TraceRmiLaunchOffer::new("gdb", "GNU Debugger")
            .with_command(vec!["gdb".into(), "--interpreter=mi2".into()])
            .with_available(true);

        let lldb_offer = TraceRmiLaunchOffer::new("lldb", "LLDB Debugger")
            .with_command(vec!["lldb-server".into(), "gdbserver".into()])
            .with_available(false);

        assert!(gdb_offer.available);
        assert!(!lldb_offer.available);
        assert_eq!(gdb_offer.command.len(), 2);
    }

    /// Test that the unknown state exception captures context.
    #[test]
    fn test_unknown_state_exception_integration() {
        let exc = UnknownStatePcodeExecutionException::new(
            "register value unknown at address",
        )
        .with_address(0xDEADBEEF)
        .with_snap(42);

        assert!(exc.message.contains("unknown"));
        assert_eq!(exc.address, Some(0xDEADBEEF));
        assert_eq!(exc.snap, Some(42));
    }

    /// Test that equate space supports duplicate detection.
    #[test]
    fn test_equate_duplicate_detection() {
        let mut mgr = DBTraceEquateManager::new();
        let space = mgr.get_or_create_space("ram");

        let id1 = space.create_equate("MY_CONST", 42);
        let id2 = space.create_equate("MY_CONST", 42);
        assert_eq!(id1, id2); // Same name -> same ID
        assert_eq!(space.equate_count(), 1);
    }

    /// Comprehensive test: trace lifecycle with multiple subsystems.
    #[test]
    fn test_comprehensive_trace_lifecycle() {
        // 1. Set up domain object listener
        let change_count = Arc::new(AtomicUsize::new(0));
        let count_clone = change_count.clone();
        let mut listener = TraceDomainObjectListener::new();
        listener.add_handler(
            DomainObjectEvent::PropertyChanged,
            Box::new(move |_| {
                count_clone.fetch_add(1, Ordering::SeqCst);
            }),
        );

        // 2. Set up equate manager
        let mut equates = DBTraceEquateManager::new();
        let eq_id = equates.get_or_create_space("ram").create_equate("SYS_READ", 0);
        equates.get_or_create_space("ram").add_reference(TraceEquateReference::new(
            eq_id, 0x400000, "ram", 0, 0, Lifespan::ALL,
        ));

        // 3. Set up symbol views
        let mut labels = TraceLabelSymbolView::new();
        labels.add(TraceLabelSymbol::new(1, "main", 0x400000, "ram", Lifespan::ALL));

        // 4. Set up function manager
        let mut funcs = DBTraceProgramViewFunctionManager::new();
        let main_id = funcs.create_function("main", 0x400000, "ram");
        funcs.get_function_mut(main_id).unwrap().add_body_range(0x400000, 0x400100);

        // 5. Set up memory buffer
        let buf = DBTraceMemBuffer::with_data("ram", 0x400000, 0, vec![0x55, 0x48, 0x89, 0xE5]);
        assert_eq!(buf.read_u32_le(0), Some(0xE5894855));

        // 6. Set up emulation
        let mut emu = TraceEmulationIntegration::new(EmulationMode::Record);
        emu.set_status(EmulationStatus::Running);
        emu.record_snapshot(EmulationStateSnapshot::new(0, 0x400000, 1));

        // 7. Fire domain object change
        let event = DomainObjectChangedEvent::new(vec![
            DomainObjectChangeRecord::new(DomainObjectEvent::PropertyChanged, 1),
        ]);
        listener.domain_object_changed(&event);

        // Verify everything worked together
        assert_eq!(change_count.load(Ordering::SeqCst), 1);
        assert_eq!(equates.total_equate_count(), 1);
        assert_eq!(labels.len(), 1);
        assert_eq!(funcs.function_count(), 1);
        assert!(emu.is_active());
        assert_eq!(emu.snapshot_count(), 1);
    }
}
