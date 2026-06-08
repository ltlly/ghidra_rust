//! Final integration tests for the Debug module port.
//!
//! These tests exercise the modules ported from:
//! - Debugger-api: TraceRmiServiceListener, ConnectMode, CompositeTraceRmiServiceListener
//! - Framework-TraceModeling model: TraceAddressSnapSpace, AddressSnapRange
//! - Framework-TraceModeling db: DBTraceFieldCodec, RStarTree, SpatialRect
//! - Debugger services: ProgramModuleIndexer, ModuleRegionMatcher
//! - Debugger plugin: ProgramUrl, EventDebouncer
//! - Framework: RStarTreeDiagnostics

#[cfg(test)]
mod tests {
    use crate::api::tracermi_listener::*;
    use crate::api::trace_rmi_connection::TraceRmiConnection;
    use crate::db::trace_db_field_codec::*;
    use crate::db::trace_db_spatial_tree::*;
    use crate::model::trace_address_snap_space::*;
    use crate::framework::rstar_diagnostics::*;
    use crate::services::program_indexer::*;
    use crate::services::module_region_matcher::*;
    use crate::plugin::utils_extras::*;

    // === TraceAddressSnapSpace tests ===

    #[test]
    fn test_address_snap_space_full_workflow() {
        let space = TraceAddressSnapSpace::with_bounds("ram", 0, 0xFFFF_FFFF, 0, 10000);

        // Compare operations
        assert_eq!(space.compare_x(100, 200), std::cmp::Ordering::Less);
        assert_eq!(space.compare_y(0, 100), std::cmp::Ordering::Less);

        // Distance calculations
        let dx = space.dist_x(0x1000, 0x2000);
        assert!((dx - 0x1000 as f64).abs() < f64::EPSILON);

        let dy = space.dist_y(0, 100);
        assert!((dy - 100.0).abs() < f64::EPSILON);

        // Midpoint calculations
        assert_eq!(space.mid_x(0x1000, 0x2000), 0x1800);
        assert_eq!(space.mid_y(0, 100), 50);

        // 2D operations
        let d = space.dist_2d(0, 0, 3, 4);
        assert!((d - 5.0).abs() < 1e-10);

        let (mx, my) = space.mid_2d(100, 0, 200, 100);
        assert_eq!(mx, 150);
        assert_eq!(my, 50);

        // Full range
        let full = space.get_full();
        assert_eq!(full.min_addr, 0);
        assert_eq!(full.max_addr, 0xFFFF_FFFF);
    }

    #[test]
    fn test_address_snap_space_cache_consistency() {
        let s1 = for_address_space("ram");
        let s2 = for_address_space("ram");
        let s3 = for_address_space("register");

        // Same name -> same cache entry
        assert_eq!(s1.space_name, s2.space_name);
        // Different name -> different cache entry
        assert_ne!(s1.space_name, s3.space_name);
    }

    #[test]
    fn test_address_snap_range_containment() {
        let range = AddressSnapRange::new(0x1000, 0x2000, 0, 100);

        // Contains points
        assert!(range.contains_point(0x1500, 50));
        assert!(range.contains_point(0x1000, 0));
        assert!(range.contains_point(0x2000, 100));
        assert!(!range.contains_point(0x2001, 50));

        // Size calculations
        assert_eq!(range.address_size(), 0x1000);
        assert_eq!(range.snap_size(), 100);

        // Point detection
        let point = AddressSnapRange::point(0x4000, 5);
        assert!(point.is_point());
        assert!(!range.is_point());
    }

    // === RStarTree tests ===

    #[test]
    fn test_rstar_tree_comprehensive() {
        let mut tree = RStarTree::<String>::new();

        // Insert entries representing memory regions
        tree.insert(RStarEntry::new(
            SpatialRect::new(0x400000, 0x401000, 0, 1000),
            "libc.text".to_string(),
        ));
        tree.insert(RStarEntry::new(
            SpatialRect::new(0x401000, 0x402000, 0, 1000),
            "libc.data".to_string(),
        ));
        tree.insert(RStarEntry::new(
            SpatialRect::new(0x7f000000, 0x7f020000, 500, 1500),
            "libm.text".to_string(),
        ));

        assert_eq!(tree.len(), 3);

        // Query by point
        let results = tree.query_containing_point(0x400500, 500);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key, "libc.text");

        // Query by intersection
        let query = SpatialRect::new(0x400500, 0x401500, 0, 1000);
        let results = tree.query_intersecting(&query);
        assert_eq!(results.len(), 2);

        // Smallest containing
        tree.insert(RStarEntry::new(
            SpatialRect::new(0x400100, 0x400900, 100, 900),
            "libc.text.inner".to_string(),
        ));
        let smallest = tree.query_smallest_containing(0x400500, 500);
        assert!(smallest.is_some());
        assert_eq!(smallest.unwrap().key, "libc.text.inner");

        // Bounds
        let bounds = tree.bounds().unwrap();
        assert_eq!(bounds.min_addr, 0x400000);
        assert_eq!(bounds.max_addr, 0x7f020000);
    }

    #[test]
    fn test_spatial_rect_operations() {
        let r1 = SpatialRect::new(0, 100, 0, 100);
        let r2 = SpatialRect::new(50, 150, 50, 150);

        // Intersection
        let inter = r1.intersection(&r2).unwrap();
        assert_eq!(inter.min_addr, 50);
        assert_eq!(inter.max_addr, 100);
        assert_eq!(inter.min_snap, 50);
        assert_eq!(inter.max_snap, 100);

        // Merge
        let merged = r1.merge(&r2);
        assert_eq!(merged.min_addr, 0);
        assert_eq!(merged.max_addr, 150);

        // Enlargement
        let enlargement = r1.enlargement_area(&r2);
        assert!(enlargement > 0);

        // Non-intersecting
        let r3 = SpatialRect::new(200, 300, 200, 300);
        assert!(r1.intersection(&r3).is_none());
    }

    // === DB Field Codec tests ===

    #[test]
    fn test_field_codec_full_workflow() {
        let mut codec_set = TraceObjectFieldCodecSet::new("trace_objects");

        codec_set.add_codec(
            DBTraceFieldCodec::new("id", FieldDataType::Long, 0).as_primary_key(),
        );
        codec_set.add_codec(
            DBTraceFieldCodec::new("name", FieldDataType::String, 1)
                .not_null()
                .with_default("unnamed"),
        );
        codec_set.add_codec(DBTraceFieldCodec::new("data", FieldDataType::Blob, 2));
        codec_set.add_codec(DBTraceFieldCodec::new("enabled", FieldDataType::Boolean, 3));

        assert_eq!(codec_set.len(), 4);
        assert_eq!(codec_set.primary_key_codecs().len(), 1);

        // Encode values
        let name_codec = codec_set.get_codec("name").unwrap();
        let encoded = name_codec.encode_string("test_object");
        assert_eq!(encoded.value.as_string(), Some("test_object"));

        let id_codec = codec_set.get_codec("id").unwrap();
        let encoded = id_codec.encode_long(42);
        assert_eq!(encoded.value.as_long(), Some(42));

        // Generate SQL
        let sql = codec_set.build_create_table_sql();
        assert!(sql.contains("CREATE TABLE trace_objects"));
        assert!(sql.contains("id INTEGER PRIMARY KEY"));
        assert!(sql.contains("name TEXT NOT NULL"));
    }

    #[test]
    fn test_field_value_types() {
        let string_val = FieldValue::String("hello".to_string());
        assert_eq!(string_val.data_type(), FieldDataType::String);
        assert_eq!(string_val.as_string(), Some("hello"));

        let long_val = FieldValue::Long(-42);
        assert_eq!(long_val.data_type(), FieldDataType::Long);
        assert_eq!(long_val.as_long(), Some(-42));

        let ulong_val = FieldValue::ULong(0xDEADBEEF);
        assert_eq!(ulong_val.data_type(), FieldDataType::ULong);
        assert_eq!(ulong_val.as_ulong(), Some(0xDEADBEEF));

        let bool_val = FieldValue::Boolean(true);
        assert_eq!(bool_val.as_boolean(), Some(true));

        let blob_val = FieldValue::Blob(vec![0x90, 0xC3, 0x00]);
        assert_eq!(blob_val.as_blob(), Some(&[0x90u8, 0xC3, 0x00][..]));

        let null_val = FieldValue::Null;
        assert!(null_val.is_null());
        assert!(null_val.as_string().is_none());
    }

    // === TraceRmiServiceListener tests ===

    #[test]
    fn test_service_listener_comprehensive() {
        let mut composite = CompositeTraceRmiServiceListener::new();

        let _rec1 = RecordingServiceListener::new();
        let _rec2 = RecordingServiceListener::new();

        composite.add_listener(Box::new(RecordingServiceListener::new()));

        // Verify composite behavior
        composite.server_started("localhost:18001");
        composite.server_stopped();
        assert_eq!(composite.len(), 1);
    }

    #[test]
    fn test_connect_mode_variants() {
        assert_ne!(ConnectMode::Connect, ConnectMode::AcceptOne);
        assert_ne!(ConnectMode::Connect, ConnectMode::Server);
        assert_ne!(ConnectMode::AcceptOne, ConnectMode::Server);

        // Serialization roundtrip
        for mode in [ConnectMode::Connect, ConnectMode::AcceptOne, ConnectMode::Server] {
            let json = serde_json::to_string(&mode).unwrap();
            let deserialized: ConnectMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, deserialized);
        }
    }

    #[test]
    fn test_recording_listener_full() {
        let rec = RecordingServiceListener::new();

        // Server events
        rec.server_started("localhost:18001");
        rec.server_stopped();
        assert_eq!(rec.event_count(), 2);

        // Accept events
        rec.waiting_accept("acc-1");
        rec.accept_cancelled("acc-1");
        rec.accept_failed("acc-2", "timeout");
        assert_eq!(rec.event_count(), 5);

        // Transaction events
        let conn = TraceRmiConnection::new("localhost:18001", "conn-1");
        rec.transaction_opened(&conn, "target-1");
        rec.transaction_closed(&conn, "target-1", false);
        assert_eq!(rec.event_count(), 7);

        // Verify events
        let events = rec.recorded_events();
        assert!(matches!(&events[0], TraceRmiServiceEvent::ServerStarted { .. }));
        assert!(matches!(&events[1], TraceRmiServiceEvent::ServerStopped));
        assert!(matches!(&events[2], TraceRmiServiceEvent::WaitingAccept { .. }));
        assert!(matches!(&events[3], TraceRmiServiceEvent::AcceptCancelled { .. }));
        assert!(matches!(&events[4], TraceRmiServiceEvent::AcceptFailed { .. }));
        assert!(matches!(&events[5], TraceRmiServiceEvent::TransactionOpened { .. }));
        assert!(matches!(&events[6], TraceRmiServiceEvent::TransactionClosed { aborted, .. } if !aborted));

        rec.clear();
        assert_eq!(rec.event_count(), 0);
    }

    // === ProgramModuleIndexer and ModuleRegionMatcher tests ===

    #[test]
    fn test_program_indexer_full_workflow() {
        let mut indexer = ProgramModuleIndexer::new_with_config("file:///app", "x86:LE:64:default");

        // Add modules
        let mut libc = IndexedModule::new("libc.so.6", "/usr/lib/libc.so.6", 0x7f000000, 0x20000);
        libc.add_section(IndexedSection::new(".text", 0x7f001000, 0x7f010000).executable());
        libc.add_section(IndexedSection::new(".data", 0x7f011000, 0x7f018000).writable());
        libc.add_section(IndexedSection::new(".bss", 0x7f019000, 0x7f020000));
        indexer.add_module(libc);

        let mut app = IndexedModule::new("app", "/bin/app", 0x400000, 0x10000);
        app.add_section(IndexedSection::new(".text", 0x401000, 0x409000).executable());
        app.add_section(IndexedSection::new(".rodata", 0x40a000, 0x40b000));
        indexer.add_module(app);

        assert_eq!(indexer.module_count(), 2);

        // Find module at address
        let module = indexer.module_at(0x7f005000);
        assert!(module.is_some());
        assert_eq!(module.unwrap().name, "libc.so.6");

        // Find overlapping modules
        let overlapping = indexer.modules_overlapping(0x400000, 0x410000);
        assert_eq!(overlapping.len(), 1);
        assert_eq!(overlapping[0].name, "app");
    }

    #[test]
    fn test_module_region_matcher_comprehensive() {
        let mut indexer = ProgramModuleIndexer::new_with_config("file:///app", "x86:LE:64:default");
        indexer.add_module(IndexedModule::new("libc.so.6", "/usr/lib/libc.so.6", 0x7f000000, 0x20000));
        indexer.add_module(IndexedModule::new("libpthread.so.0", "/usr/lib/libpthread.so.0", 0x7f030000, 0x10000));

        let matcher = ModuleRegionMatcher::with_indexer(indexer);

        // Exact match
        let results = matcher.match_by_name("app", &vec!["app", "other"]);
        assert!(!results.is_empty());
        assert_eq!(results[0].confidence, 1.0);

        // Prefix match
        let results = matcher.match_by_name("libc.so.6", &vec!["libc.so.6-extra", "other"]);
        assert!(!results.is_empty());
        assert!(results[0].confidence > 0.5);

        // Base name heuristic
        let results = matcher.match_by_name("libc.so.6", &vec!["libc-2.31.so", "other"]);
        assert!(!results.is_empty());
        assert!(results[0].confidence >= 0.5);

        // No match
        let results = matcher.match_by_name("libc.so.6", &vec!["libpthread", "libm"]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_indexed_section_properties() {
        let section = IndexedSection::new(".text", 0x1000, 0x2000)
            .executable()
            .writable();

        assert!(section.executable);
        assert!(section.writable);
        assert!(section.readable);
        assert_eq!(section.size(), 0x1001);
        assert!(section.contains_address(0x1500));
        assert!(!section.contains_address(0x2001));
        assert!(section.overlaps(0x500, 0x1500));
        assert!(!section.overlaps(0x3000, 0x4000));
    }

    // === ProgramUrl tests ===

    #[test]
    fn test_program_url_comprehensive() {
        // Parse and reconstruct
        let url = ProgramUrl::parse("file:///home/user/prog#0x400000").unwrap();
        assert_eq!(url.scheme, "file");
        assert_eq!(url.path, "/home/user/prog");
        assert_eq!(url.fragment_address(), Some(0x400000));
        assert_eq!(url.to_url(), "file:///home/user/prog#0x400000");

        // Ghidra URL
        let url = ProgramUrl::parse("ghidra://server/trace#0x1000").unwrap();
        assert_eq!(url.scheme, "ghidra");
        assert_eq!(url.authority, "server");
        assert_eq!(url.fragment_address(), Some(0x1000));

        // Helper functions
        assert!(is_program_url("file:///prog"));
        assert!(is_program_url("ghidra://server/trace"));
        assert!(!is_program_url("http://example.com"));

        let name = extract_program_name("file:///home/user/my_program").unwrap();
        assert_eq!(name, "my_program");

        let url = make_program_url("file", "home/user/prog", Some(0x400000));
        assert_eq!(url, "file:///home/user/prog#0x400000");
    }

    #[test]
    fn test_program_location_ref() {
        let loc = ProgramLocationRef::new("file:///prog", 0x400000)
            .with_space("ram");
        assert_eq!(loc.display_string(), "prog:ram:0x400000");

        let loc = ProgramLocationRef::new("file:///prog", 0x400000);
        assert_eq!(loc.display_string(), "prog:0x400000");
    }

    // === EventDebouncer tests ===

    #[test]
    fn test_event_debouncer_workflow() {
        let mut debouncer = EventDebouncer::<String>::new(5);

        // First event should be immediate
        assert!(debouncer.submit("event1".to_string()));
        assert!(!debouncer.has_pending());

        // Rapid events should be coalesced
        assert!(!debouncer.submit("event2".to_string()));
        assert!(!debouncer.submit("event3".to_string()));
        assert!(debouncer.has_pending());

        // Flush the pending event
        let flushed = debouncer.flush();
        assert!(flushed.is_some());
        assert!(!debouncer.has_pending());
    }

    #[test]
    fn test_event_debouncer_no_pending_flush() {
        let mut debouncer = EventDebouncer::<String>::new(5);
        assert!(debouncer.flush().is_none());
    }

    // === RStarTreeDiagnostics tests ===

    #[test]
    fn test_rstar_diagnostics_comprehensive() {
        let mut diag = RStarTreeDiagnostics::new("ram", 25, 8);
        diag.stats.total_entries = 1000;
        diag.stats.leaf_count = 50;
        diag.stats.internal_count = 10;
        diag.stats.fill_factor = 0.5;
        diag.stats.max_depth = 8;
        diag.stats.avg_entries_per_leaf = 20.0;

        // Record queries
        diag.stats.record_overlap_query(10.0);
        diag.stats.record_overlap_query(20.0);
        diag.stats.record_point_query(5.0);

        assert_eq!(diag.stats.total_queries(), 3);
        assert_eq!(diag.stats.total_nodes(), 60);
        assert!(diag.stats.is_healthy());

        // Run diagnostics (no warnings)
        diag.run_diagnostics();
        assert!(!diag.has_warnings());
    }

    #[test]
    fn test_rstar_diagnostics_warnings() {
        let mut diag = RStarTreeDiagnostics::new("ram", 25, 8);
        diag.stats.fill_factor = 0.1; // Low
        diag.stats.max_depth = 20;     // High
        diag.stats.avg_entries_per_leaf = 0.5; // Sparse

        diag.run_diagnostics();
        assert!(diag.has_warnings());
        assert_eq!(diag.warnings.len(), 3); // All three warnings
    }

    // === Cross-module integration test ===

    #[test]
    fn test_cross_module_full_integration() {
        // 1. Create a trace address snap space
        let _space = TraceAddressSnapSpace::with_bounds("ram", 0, 0xFFFF_FFFF, 0, 10000);

        // 2. Build an R*-tree for spatial indexing
        let mut tree = RStarTree::<String>::new();

        // 3. Add indexed modules to the tree
        let mut indexer = ProgramModuleIndexer::new_with_config("file:///app", "x86:LE:64:default");

        let libc = IndexedModule::new("libc.so.6", "/usr/lib/libc.so.6", 0x7f000000, 0x20000);
        indexer.add_module(libc.clone());

        let app = IndexedModule::new("app", "/bin/app", 0x400000, 0x10000);
        indexer.add_module(app.clone());

        // Add entries to the tree
        tree.insert(RStarEntry::new(
            SpatialRect::new(libc.base_address(), libc.end_address(), 0, 10000),
            "libc.so.6".to_string(),
        ));
        tree.insert(RStarEntry::new(
            SpatialRect::new(app.base_address(), app.end_address(), 0, 10000),
            "app".to_string(),
        ));

        // 4. Create field codecs for the trace objects
        let mut codec_set = TraceObjectFieldCodecSet::new("modules");
        codec_set.add_codec(
            DBTraceFieldCodec::new("name", FieldDataType::String, 0).as_primary_key(),
        );
        codec_set.add_codec(DBTraceFieldCodec::new("base", FieldDataType::ULong, 1));
        codec_set.add_codec(DBTraceFieldCodec::new("length", FieldDataType::ULong, 2));

        // 5. Encode module data
        let name_codec = codec_set.get_codec("name").unwrap();
        let base_codec = codec_set.get_codec("base").unwrap();

        let encoded_name = name_codec.encode_string("libc.so.6");
        let encoded_base = base_codec.encode_ulong(0x7f000000);

        assert_eq!(encoded_name.value.as_string(), Some("libc.so.6"));
        assert_eq!(encoded_base.value.as_ulong(), Some(0x7f000000));

        // 6. Query the tree
        let results = tree.query_containing_point(0x7f005000, 5000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key, "libc.so.6");

        // 7. Match modules
        let matcher = ModuleRegionMatcher::with_indexer(indexer);
        let matches = matcher.match_by_name("app", &vec!["app", "other"]);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].confidence, 1.0);

        // 8. Test RMI listener
        let rec = RecordingServiceListener::new();
        rec.server_started("localhost:18001");
        assert_eq!(rec.event_count(), 1);

        // 9. Generate SQL
        let sql = codec_set.build_create_table_sql();
        assert!(sql.contains("CREATE TABLE modules"));
        assert!(sql.contains("name TEXT PRIMARY KEY"));

        // 10. R*-tree diagnostics
        let mut diag = RStarTreeDiagnostics::new("ram", 25, 8);
        diag.stats.total_entries = tree.len();
        diag.stats.fill_factor = 0.5;
        diag.stats.max_depth = 5;
        diag.stats.avg_entries_per_leaf = 10.0;
        diag.run_diagnostics();
        assert!(!diag.has_warnings());
    }
}
