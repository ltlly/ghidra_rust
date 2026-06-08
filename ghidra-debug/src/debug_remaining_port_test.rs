//! Integration tests for the remaining Debug module ports.
//!
//! These tests exercise the modules ported from:
//! - Framework-TraceModeling: space-based managers, property maps,
//!   address-snap maps, static mappings, content handlers, memory ops
//! - Debugger-api: viewport types
//! - Debugger: service interfaces

#[cfg(test)]
mod tests {
    use crate::db::{
        AddressSnapPropertyMap, DbTraceAddressPropertyManager,
        DbTraceStaticMappingManager, LinkContentHandler, PropertyMapValue,
        RangeQuery, SpaceBasedManager, TraceContentMetadata, TraceContentType,
        TracePropertyMap, known_properties,
    };
    use crate::db::trace_db_addr_snap_map::AddressSnapRange;
    use crate::model::{
        InMemoryTraceMemory, Lifespan, MemoryRegionInfo, TraceMemoryOperations,
        memory::TraceMemoryState, trace_memory_ops::TraceMemoryStateExt,
    };
    use crate::services::{SingleSnapViewport, ServiceTraceTimeViewport};

    // =========================================================================
    // Space-based manager integration
    // =========================================================================

    #[test]
    fn test_space_manager_with_property_maps() {
        let mut space_mgr: SpaceBasedManager<TracePropertyMap> = SpaceBasedManager::new("props");

        // Create per-space property maps
        space_mgr.get_or_create_space("ram", |_| TracePropertyMap::new("instructions"));
        space_mgr.get_or_create_space("register", |_| TracePropertyMap::new("reg_state"));

        // Set properties in each space
        if let Some(map) = space_mgr.get_for_space_mut("ram") {
            map.set(0x400000, PropertyMapValue::Bool(true));
            map.set(0x400001, PropertyMapValue::Bool(true));
        }
        if let Some(map) = space_mgr.get_for_space_mut("register") {
            map.set(0, PropertyMapValue::String("RAX".to_string()));
        }

        // Verify
        let ram_map = space_mgr.get_for_space("ram").unwrap();
        assert_eq!(ram_map.len(), 2);
        assert!(ram_map.contains(0x400000));

        let reg_map = space_mgr.get_for_space("register").unwrap();
        assert_eq!(reg_map.len(), 1);
    }

    // Helper: add get_for_space_mut method for tests
    trait SpaceBasedManagerMutExt<S> {
        fn get_for_space_mut(&mut self, name: &str) -> Option<&mut S>;
    }

    impl<S> SpaceBasedManagerMutExt<S> for SpaceBasedManager<S> {
        fn get_for_space_mut(&mut self, name: &str) -> Option<&mut S> {
            self.spaces.get_mut(name)
        }
    }

    // =========================================================================
    // Property manager integration
    // =========================================================================

    #[test]
    fn test_property_manager_known_properties() {
        let mut mgr = DbTraceAddressPropertyManager::new();

        // Set instruction start markers
        mgr.set_bool("ram", known_properties::INSTRUCTION_START, 0x400000, true);
        mgr.set_bool("ram", known_properties::INSTRUCTION_START, 0x400004, true);
        mgr.set_bool("ram", known_properties::INSTRUCTION_START, 0x400008, true);

        // Set a comment
        mgr.set_string("ram", known_properties::EOL_COMMENT, 0x400000, "entry point");

        // Set entry point marker
        mgr.set_void("ram", known_properties::ENTRY_POINT, 0x400000);

        // Query
        let instr_map = mgr.get_map("ram", known_properties::INSTRUCTION_START).unwrap();
        assert_eq!(instr_map.len(), 3);

        let comment_map = mgr.get_map("ram", known_properties::EOL_COMMENT).unwrap();
        assert_eq!(comment_map.len(), 1);
        assert_eq!(
            comment_map.get(0x400000),
            Some(&PropertyMapValue::String("entry point".to_string()))
        );

        let entry_map = mgr.get_map("ram", known_properties::ENTRY_POINT).unwrap();
        assert!(entry_map.contains(0x400000));

        // List maps
        let maps = mgr.map_names("ram");
        assert!(maps.contains(&known_properties::INSTRUCTION_START));
        assert!(maps.contains(&known_properties::EOL_COMMENT));
        assert!(maps.contains(&known_properties::ENTRY_POINT));
    }

    #[test]
    fn test_property_map_range_queries() {
        let mut map = TracePropertyMap::new("instructions");
        // Set instruction markers every 4 bytes
        for i in 0..10 {
            map.set(0x400000 + i * 4, PropertyMapValue::Bool(true));
        }

        // Query a range (0x400004, 0x400008, 0x40000C, 0x400010 = 4 entries)
        let entries: Vec<_> = map.range(0x400004, 0x400010).collect();
        assert_eq!(entries.len(), 4);

        // Navigation
        assert_eq!(map.next_address(0x400000), Some(0x400004));
        assert_eq!(map.prev_address(0x400024), Some(0x400020));
    }

    // =========================================================================
    // Address-snap map integration
    // =========================================================================

    #[test]
    fn test_addr_snap_map_memory_regions() {
        let mut map = AddressSnapPropertyMap::new("ram_regions");

        // Insert memory region entries
        map.insert(
            AddressSnapRange::new(0x400000, 0x400FFF, 0, i64::MAX),
            ".text".to_string(),
        );
        map.insert(
            AddressSnapRange::new(0x600000, 0x600FFF, 0, i64::MAX),
            ".data".to_string(),
        );
        map.insert(
            AddressSnapRange::new(0x400000, 0x400FFF, -10, -1),
            ".text_scratch".to_string(),
        );

        // Query by point in persistent space
        let results = map.get_at_point(0x400100, 50);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, ".text");

        // Query by point in scratch space
        let results = map.get_at_point(0x400100, -5);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, ".text_scratch");

        // Range query covering both regions
        let query = RangeQuery::new(0x300000, 0x700000, 0, 100);
        let results = map.get_in_range(&query);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_addr_snap_map_temporal_queries() {
        let mut map = AddressSnapPropertyMap::new("reg_values");

        // Memory values at different addresses at snap 0
        map.insert(AddressSnapRange::snap(0x100, 0), "val_a".to_string());
        map.insert(AddressSnapRange::snap(0x200, 0), "val_b".to_string());
        // Value changes at address 0x100 at snap 5
        map.insert(AddressSnapRange::snap(0x100, 5), "val_a_v2".to_string());

        // At snap 0, address 0x100
        let at_0 = map.get_at_point(0x100, 0);
        assert_eq!(at_0.len(), 1);
        assert_eq!(at_0[0].value, "val_a");

        // At snap 5, address 0x100 - the new value is visible
        let at_5 = map.get_at_point(0x100, 5);
        assert_eq!(at_5.len(), 1);
        assert_eq!(at_5[0].value, "val_a_v2");

        // At snap 0, address 0x200
        let at_200 = map.get_at_point(0x200, 0);
        assert_eq!(at_200.len(), 1);
        assert_eq!(at_200[0].value, "val_b");
    }

    // =========================================================================
    // Static mapping integration
    // =========================================================================

    #[test]
    fn test_static_mapping_program_trace_translation() {
        let mut mgr = DbTraceStaticMappingManager::new();

        // Map two modules
        mgr.add_mapping(
            "/usr/bin/main",
            0x400000,
            0x400FFF,
            0x7FFF0000,
            0x7FFF0FFF,
            Lifespan::span(0, i64::MAX),
        );
        mgr.add_mapping(
            "/usr/lib/libc.so",
            0x7F000000,
            0x7F00FFFF,
            0x7FFE0000,
            0x7FFEFFFF,
            Lifespan::span(0, i64::MAX),
        );

        // Translate main program address
        let trace_addr = mgr.program_to_trace("/usr/bin/main", 0x400100, 0);
        assert_eq!(trace_addr, Some(0x7FFF0100));

        // Translate library address
        let trace_addr = mgr.program_to_trace("/usr/lib/libc.so", 0x7F000100, 0);
        assert_eq!(trace_addr, Some(0x7FFE0100));

        // Reverse translate
        let result = mgr.trace_to_program(0x7FFF0200, 0);
        assert_eq!(result, Some(("/usr/bin/main".to_string(), 0x400200)));

        // Address not in any mapping
        let result = mgr.trace_to_program(0x80000000, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_static_mapping_lifespan_scoped() {
        let mut mgr = DbTraceStaticMappingManager::new();

        // Module loaded from snap 10 to snap 20
        mgr.add_mapping(
            "module.exe",
            0x400000,
            0x400FFF,
            0x7FFF0000,
            0x7FFF0FFF,
            Lifespan::span(10, 20),
        );

        // Before load
        assert!(mgr.program_to_trace("module.exe", 0x400100, 5).is_none());

        // While loaded
        assert_eq!(mgr.program_to_trace("module.exe", 0x400100, 15), Some(0x7FFF0100));

        // After unload
        assert!(mgr.program_to_trace("module.exe", 0x400100, 25).is_none());
    }

    // =========================================================================
    // Content handler integration
    // =========================================================================

    #[test]
    fn test_content_handler_trace_creation() {
        let meta = TraceContentMetadata::new_database("my_trace")
            .with_language("x86:LE:64:default", "default")
            .with_executable_path("/usr/bin/test");

        assert_eq!(meta.content_type, TraceContentType::Database);
        assert_eq!(meta.name, "my_trace");
        assert_eq!(meta.language_id.as_deref(), Some("x86:LE:64:default"));
        assert_eq!(meta.compiler_spec_id.as_deref(), Some("default"));
        assert_eq!(meta.executable_path.as_deref(), Some("/usr/bin/test"));
    }

    #[test]
    fn test_content_handler_link() {
        let handler = LinkContentHandler::new("remote_trace", "tcp://debugger:1234");
        assert_eq!(handler.metadata.content_type, TraceContentType::Link);
        assert_eq!(handler.link_url, "tcp://debugger:1234");
    }

    // =========================================================================
    // Memory operations integration
    // =========================================================================

    #[test]
    fn test_memory_ops_full_workflow() {
        let mut mem = InMemoryTraceMemory::new();

        // Add a .text region
        mem.add_region(
            MemoryRegionInfo::new(0x400000, 0x400FFF, Lifespan::span(0, i64::MAX), ".text")
                .with_permissions(true, false, true),
        );

        // Add a .data region
        mem.add_region(
            MemoryRegionInfo::new(0x600000, 0x600FFF, Lifespan::span(0, i64::MAX), ".data")
                .with_permissions(true, true, false),
        );

        // Write some code
        mem.put_bytes(0, 0x400000, &[0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10]);

        // Verify code was written
        let states = mem.get_states(0, 0x400000, 8);
        assert!(states.iter().all(|s| s.is_known()));

        // Read back
        let mut buf = [0u8; 8];
        let count = mem.get_bytes(0, 0x400000, &mut buf);
        assert_eq!(count, 8);
        assert_eq!(buf[0], 0x55); // push rbp
        assert_eq!(buf[1], 0x48); // REX.W prefix

        // Check unknown area
        let unknown_states = mem.get_states(0, 0x500000, 4);
        assert!(unknown_states.iter().all(|s| s.is_unknown()));

        // Get regions
        let regions = mem.get_regions(0);
        assert_eq!(regions.len(), 2);
        let text = regions.iter().find(|r| r.name == ".text").unwrap();
        assert!(text.executable);
        assert!(!text.writable);

        let data = regions.iter().find(|r| r.name == ".data").unwrap();
        assert!(!data.executable);
        assert!(data.writable);
    }

    #[test]
    fn test_memory_ops_set_states() {
        let mut mem = InMemoryTraceMemory::new();

        // Set a range to KNOWN
        mem.set_states(0, 0x400000, 4096, TraceMemoryState::Known);

        // Verify
        assert!(mem.is_state_entirely(0, 0x400000, 0x400FFF, TraceMemoryState::Known));

        // Set some to ERROR
        mem.set_states(0, 0x400800, 2048, TraceMemoryState::Error);

        // Verify mixed
        assert!(!mem.is_state_entirely(0, 0x400000, 0x400FFF, TraceMemoryState::Known));
        assert!(mem.is_state_entirely(0, 0x400800, 0x400FFF, TraceMemoryState::Error));
    }

    // =========================================================================
    // Viewport integration
    // =========================================================================

    #[test]
    fn test_viewport_debugger_workflow() {
        let mut vp = ServiceTraceTimeViewport::new();

        // Initial state
        assert_eq!(vp.current_snap(), 0);

        // User clicks on snap 5
        vp.set_snap(5);
        assert_eq!(vp.current_snap(), 5);
        assert!(vp.is_snap_visible(5));
        assert!(!vp.is_snap_visible(4));

        // User selects a range for comparison
        vp.set_range(3, 8);
        assert!(vp.is_range_view());
        for snap in 3..=8 {
            assert!(vp.is_snap_visible(snap), "snap {} should be visible", snap);
        }
        assert!(!vp.is_snap_visible(2));
        assert!(!vp.is_snap_visible(9));
    }

    #[test]
    fn test_viewport_thread_specific_snaps() {
        let mut vp = ServiceTraceTimeViewport::new();
        vp.set_snap(0);

        // Thread 1 is at snap 10, thread 2 is at snap 20
        vp.set_thread_snap(1, 10);
        vp.set_thread_snap(2, 20);

        // Default view uses global snap
        assert_eq!(vp.snap_for_thread(0), 0);

        // Thread-specific snaps
        assert_eq!(vp.snap_for_thread(1), 10);
        assert_eq!(vp.snap_for_thread(2), 20);

        // Clear thread 1 override
        vp.clear_thread_snap(1);
        assert_eq!(vp.snap_for_thread(1), 0); // Falls back to global
    }

    #[test]
    fn test_single_snap_viewport() {
        let vp = SingleSnapViewport::new(100);
        assert_eq!(vp.snap, 100);
        assert!(!vp.is_thread_specific());
        assert_eq!(vp.thread_key, -1);

        let vp_thread = SingleSnapViewport::for_thread(100, 5);
        assert!(vp_thread.is_thread_specific());
    }

    // =========================================================================
    // Cross-module integration
    // =========================================================================

    #[test]
    fn test_full_trace_workflow() {
        // 1. Create content metadata
        let meta = TraceContentMetadata::new_database("debug_session")
            .with_language("x86:LE:64:default", "default")
            .with_executable_path("/usr/bin/target");

        assert_eq!(meta.language_id.as_deref(), Some("x86:LE:64:default"));

        // 2. Set up memory
        let mut mem = InMemoryTraceMemory::new();
        mem.add_region(
            MemoryRegionInfo::new(0x400000, 0x400FFF, Lifespan::span(0, i64::MAX), ".text")
                .with_permissions(true, false, true),
        );
        mem.put_bytes(0, 0x400000, &[0x55, 0x48, 0x89, 0xE5]);

        // 3. Set up property maps
        let mut props = DbTraceAddressPropertyManager::new();
        props.set_bool("ram", known_properties::INSTRUCTION_START, 0x400000, true);
        props.set_bool("ram", known_properties::ENTRY_POINT, 0x400000, true);
        props.set_string("ram", known_properties::EOL_COMMENT, 0x400000, "push rbp");

        // 4. Set up static mappings
        let mut mappings = DbTraceStaticMappingManager::new();
        mappings.add_mapping(
            "/usr/bin/target",
            0x400000,
            0x400FFF,
            0x7FFF0000,
            0x7FFF0FFF,
            Lifespan::span(0, i64::MAX),
        );

        // 5. Set up time viewport
        let mut vp = ServiceTraceTimeViewport::new();
        vp.set_snap(0);

        // 6. Verify end-to-end
        assert!(mem.get_states(0, 0x400000, 3).iter().all(|s| s.is_known()));
        assert!(props.get_map("ram", known_properties::INSTRUCTION_START).unwrap().contains(0x400000));
        assert!(mappings.program_to_trace("/usr/bin/target", 0x400000, 0).is_some());
        assert!(vp.is_snap_visible(0));
    }

    #[test]
    fn test_multiple_snaps_memory_evolution() {
        let mut mem = InMemoryTraceMemory::new();

        // Snap 0: initial state
        mem.put_bytes(0, 0x400000, &[0x55, 0x48, 0x89, 0xE5]);
        assert!(mem.is_state_entirely(0, 0x400000, 0x400003, TraceMemoryState::Known));

        // Snap 1: memory changed (self-modifying code or patch)
        mem.put_bytes(1, 0x400000, &[0x90, 0x90, 0x90, 0x90]); // NOPs
        let mut buf = [0u8; 4];
        mem.get_bytes(1, 0x400000, &mut buf);
        assert_eq!(buf, [0x90, 0x90, 0x90, 0x90]);

        // Snap 0 still has original bytes
        mem.get_bytes(0, 0x400000, &mut buf);
        assert_eq!(buf, [0x55, 0x48, 0x89, 0xE5]);
    }

    #[test]
    fn test_property_map_across_spaces() {
        let mut mgr = DbTraceAddressPropertyManager::new();

        // RAM space
        mgr.set_bool("ram", "instructions", 0x400000, true);
        mgr.set_bool("ram", "instructions", 0x400004, true);

        // Register space
        mgr.set_string("register", "reg_name", 0, "RAX".to_string());
        mgr.set_string("register", "reg_name", 1, "RBX".to_string());

        // Verify isolation
        let ram_names = mgr.map_names("ram");
        assert_eq!(ram_names, vec!["instructions"]);

        let reg_names = mgr.map_names("register");
        assert_eq!(reg_names, vec!["reg_name"]);

        // Verify values
        let instr = mgr.get_map("ram", "instructions").unwrap();
        assert_eq!(instr.len(), 2);

        let regs = mgr.get_map("register", "reg_name").unwrap();
        assert_eq!(regs.len(), 2);
    }
}
