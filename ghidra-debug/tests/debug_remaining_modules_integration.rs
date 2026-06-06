//! Integration tests for the remaining Debug modules ported from Java.
//!
//! Tests the comprehensive port of modules from:
//! - Framework-TraceModeling (DBTraceUtils deep types, model operations)
//! - Debugger-api (action source, mapping proposals, control modes)
//! - Debugger (GUI data models, service implementations, breakpoint timeline)

use ghidra_debug::db::{
    OffsetSnap, OffsetThenSnapKey, SnapThenOffsetKey, TraceDatabaseInfo, TraceDbUtils,
    compute_diffs_ranges, decode_string, encode_compiler_spec_id, encode_language_id,
    encode_string, encode_url, hash_bytes, table_name, EncodedRefType,
};
use ghidra_debug::model::Lifespan;
use ghidra_debug::plugin::gui::pcode::pcode_row_types::{
    BranchPcodeRow, OpPcodeRow, PcodeRowKind, UniqueRefType, UniqueRowData, VarnodeDisplay,
};
use ghidra_debug::plugin::gui::breakpoint::breakpoint_timeline::{
    BreakpointHitEvent, BreakpointTimelineEntry, BreakpointTimelineFilter,
    BreakpointTimelineModel, TimelineColors, TimelineViewport,
};
use ghidra_debug::services::module_map_proposal_impl::{
    ModuleMapEntry, ModuleMapProposalResult, BLOCK_MASK, quantize_range,
};
use ghidra_debug::services::region_map_proposal_impl::{
    RegionMapEntry, RegionMapProposalResult, region_name_matches_block,
};
use ghidra_debug::services::section_map_proposal_impl::{
    SectionMapEntry, SectionMapProposalResult,
};
use ghidra_debug::framework::domain_object_event_queues::{
    DomainChangeEvent, DomainObjectEventQueues, FnListener,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

// ===== DBTraceUtils deep types tests =====

#[test]
fn test_offset_snap_full_workflow() {
    let os = OffsetSnap::new(0xDEADBEEF, 42);
    assert!(!os.is_scratch());
    assert_eq!(format!("{}", os), "42,deadbeef");

    let encoded = os.encode();
    assert_eq!(encoded.len(), 16);
    let decoded = OffsetSnap::decode(&encoded).unwrap();
    assert_eq!(decoded, os);
}

#[test]
fn test_offset_snap_scratch_space() {
    let scratch = OffsetSnap::new(0, -1);
    assert!(scratch.is_scratch());
    assert_eq!(format!("{}", scratch), "-1,00000000");
}

#[test]
fn test_offset_then_snap_key_sorting() {
    let mut keys = vec![
        OffsetThenSnapKey::new(100, 3),
        OffsetThenSnapKey::new(50, 1),
        OffsetThenSnapKey::new(100, 1),
        OffsetThenSnapKey::new(50, 5),
    ];
    keys.sort();

    assert_eq!(keys[0].offset, 50);
    assert_eq!(keys[0].snap, 1);
    assert_eq!(keys[1].offset, 50);
    assert_eq!(keys[1].snap, 5);
    assert_eq!(keys[2].offset, 100);
    assert_eq!(keys[2].snap, 1);
    assert_eq!(keys[3].offset, 100);
    assert_eq!(keys[3].snap, 3);
}

#[test]
fn test_snap_then_offset_key_sorting() {
    let mut keys = vec![
        SnapThenOffsetKey::new(3, 100),
        SnapThenOffsetKey::new(1, 50),
        SnapThenOffsetKey::new(1, 100),
        SnapThenOffsetKey::new(3, 50),
    ];
    keys.sort();

    assert_eq!(keys[0].snap, 1);
    assert_eq!(keys[0].offset, 50);
    assert_eq!(keys[1].snap, 1);
    assert_eq!(keys[1].offset, 100);
    assert_eq!(keys[2].snap, 3);
    assert_eq!(keys[2].offset, 50);
    assert_eq!(keys[3].snap, 3);
    assert_eq!(keys[3].offset, 100);
}

#[test]
fn test_table_name_generation() {
    assert_eq!(table_name("MemoryBlocks", "ram"), "MemoryBlocks_ram");
    assert_eq!(table_name("Regs", "register"), "Regs_register");
    assert_eq!(table_name("Symbols", "unique"), "Symbols_unique");
}

#[test]
fn test_string_codec_roundtrip() {
    let test_cases = vec!["", "hello", "special chars: !@#$%^&*()", "unicode: \u{1F600}"];
    for original in test_cases {
        let encoded = encode_string(original);
        let decoded = decode_string(&encoded).unwrap();
        assert_eq!(decoded, original, "Failed for: {}", original);
    }
}

#[test]
fn test_compute_diffs_comprehensive() {
    // Two identical arrays: no diffs
    let a = vec![0u8; 100];
    let b = vec![0u8; 100];
    assert!(compute_diffs_ranges(&a, &b).is_empty());

    // Single byte difference
    let mut b2 = vec![0u8; 100];
    b2[50] = 0xFF;
    let diffs = compute_diffs_ranges(&a, &b2);
    assert_eq!(diffs, vec![(50, 50)]);

    // Multiple ranges
    let mut b3 = vec![0u8; 100];
    for i in 10..20 { b3[i] = 0xFF; }
    for i in 50..60 { b3[i] = 0xFF; }
    let diffs = compute_diffs_ranges(&a, &b3);
    assert_eq!(diffs, vec![(10, 19), (50, 59)]);
}

#[test]
fn test_hash_bytes_consistency() {
    let data = b"consistent test data";
    let h1 = hash_bytes(data);
    let h2 = hash_bytes(data);
    assert_eq!(h1, h2);

    // Different data should hash differently (probabilistic)
    let h3 = hash_bytes(b"different data");
    assert_ne!(h1, h3);
}

#[test]
fn test_encoded_ref_type_codec() {
    let rt = EncodedRefType::new(0xDEADBEEF);
    let encoded = rt.encode();
    let decoded = EncodedRefType::decode(&encoded).unwrap();
    assert_eq!(decoded.type_id, 0xDEADBEEF);
}

#[test]
fn test_db_utils_comprehensive() {
    assert!(TraceDbUtils::is_register_space("register"));
    assert!(TraceDbUtils::is_register_space("REGISTERS"));
    assert!(TraceDbUtils::is_memory_space("ram"));
    assert!(TraceDbUtils::is_memory_space("RAM"));
    assert!(TraceDbUtils::is_stack_space("stack"));
    assert!(TraceDbUtils::is_stack_space("STACK"));

    assert_eq!(TraceDbUtils::format_snap(0), "snap:0");
    assert_eq!(TraceDbUtils::format_snap(-1), "scratch");
    assert_eq!(TraceDbUtils::format_snap(i64::MAX), format!("snap:{}", i64::MAX));
}

// ===== Module map proposal tests =====

#[test]
fn test_module_map_proposal_full_workflow() {
    let mut proposal = ModuleMapProposalResult::new("libc.so", "libc_static");

    let entry = ModuleMapEntry::new("libc.so", 0x7F000000, 0x400000, 0x100000)
        .with_lifespan(Lifespan::at(0));
    proposal.add_entry(entry);

    assert_eq!(proposal.entry_count(), 1);
    assert!(!proposal.is_empty());
}

#[test]
fn test_quantize_range_comprehensive() {
    let (min, max) = quantize_range(0x1234, 0x5678);
    assert_eq!(min & BLOCK_MASK, min); // min is aligned
    assert!(min <= 0x1234);
    assert!(max >= 0x5678);
    assert_eq!(min, 0x1000);
    assert_eq!(max, 0x5FFF);
}

#[test]
fn test_module_map_entry_block_inclusion() {
    assert!(ModuleMapEntry::should_include_block(
        0x401000, 0x401FFF, 0x400000, true, false, false
    ));
    assert!(!ModuleMapEntry::should_include_block(
        0x300000, 0x300FFF, 0x400000, true, false, false
    ));
    assert!(!ModuleMapEntry::should_include_block(
        0x401000, 0x401FFF, 0x400000, false, false, false
    ));
    assert!(!ModuleMapEntry::should_include_block(
        0x401000, 0x401FFF, 0x400000, true, true, false
    ));
    assert!(!ModuleMapEntry::should_include_block(
        0x401000, 0x401FFF, 0x400000, true, false, true
    ));
}

// ===== Region map proposal tests =====

#[test]
fn test_region_map_proposal_full_workflow() {
    let mut proposal = RegionMapProposalResult::new("test_trace");

    proposal.add_entry(RegionMapEntry::new(
        ".text", 0x400000, 0x400FFF,
        ".text", 0x400000, 0x400FFF,
    ));
    proposal.add_entry(RegionMapEntry::new(
        ".data", 0x500000, 0x500FFF,
        ".bss", 0x500000, 0x500FFF,
    ));
    proposal.add_entry(RegionMapEntry::new(
        ".rodata", 0x600000, 0x600FFF,
        ".rodata", 0x700000, 0x700FFF,
    ));

    assert_eq!(proposal.entry_count(), 3);
    // All 3 have either name or address match
    assert_eq!(proposal.good_matches().len(), 3);
    assert_eq!(proposal.name_matches().len(), 2); // .text and .rodata
}

#[test]
fn test_region_name_matching_comprehensive() {
    assert!(region_name_matches_block(".text", ".text"));
    assert!(region_name_matches_block("TEXT", "text"));
    assert!(region_name_matches_block(".data", ".data"));
    assert!(region_name_matches_block(".text_main", "text_main"));
    assert!(!region_name_matches_block(".text", ".data"));
    assert!(!region_name_matches_block(".bss", ".rodata"));
}

// ===== Section map proposal tests =====

#[test]
fn test_section_map_proposal_full_workflow() {
    let mut proposal = SectionMapProposalResult::new("libc", "libc_static");

    proposal.add_entry(SectionMapEntry::new(
        "libc", ".text", 0x0, 0xFFF,
        ".text", 0x400000, 0x400FFF,
    ));
    proposal.add_entry(SectionMapEntry::new(
        "libc", ".data", 0x1000, 0x1FFF,
        ".data", 0x500000, 0x500FFF,
    ));

    assert_eq!(proposal.entry_count(), 2);
    let sorted = proposal.sorted_by_score();
    assert!(sorted[0].match_score() >= sorted[1].match_score());
}

#[test]
fn test_section_map_entry_match_scoring() {
    let perfect = SectionMapEntry::new(
        "mod", ".text", 0x400000, 0x400FFF,
        ".text", 0x400000, 0x400FFF,
    );
    assert_eq!(perfect.match_score(), 17); // name + addr + size

    let name_only = SectionMapEntry::new(
        "mod", ".text", 0x0, 0xFFF,
        ".text", 0x400000, 0x400FFF,
    );
    assert_eq!(name_only.match_score(), 12); // name + size

    let no_match = SectionMapEntry::new(
        "mod", ".text", 0x0, 0x7FF,
        ".data", 0x500000, 0x500FFF,
    );
    assert_eq!(no_match.match_score(), 0);
}

// ===== Breakpoint timeline tests =====

#[test]
fn test_breakpoint_timeline_full_workflow() {
    let mut model = BreakpointTimelineModel::new(0, 1000);
    model.filter = BreakpointTimelineFilter::new().with_snap_range(100, 500);

    let mut entry1 = BreakpointTimelineEntry::new(1, 0x400000);
    entry1.expression = Some("main+0x10".into());
    entry1.record_hit(BreakpointHitEvent::new(100, 1, 1, false));
    entry1.record_hit(BreakpointHitEvent::new(200, 2, 1, true));
    entry1.record_hit(BreakpointHitEvent::new(300, 1, 1, false));
    model.add_entry(entry1);

    let entry2 = BreakpointTimelineEntry::new(2, 0x500000);
    model.add_entry(entry2);

    assert_eq!(model.hit_entries().len(), 1);
    assert_eq!(model.total_hit_count(), 3);

    let visible = model.visible_hits();
    assert_eq!(visible.len(), 3);

    // Narrow filter
    model.filter = BreakpointTimelineFilter::new()
        .with_snap_range(150, 250)
        .with_thread(2);
    let visible = model.visible_hits();
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].snap, 200);
}

#[test]
fn test_timeline_viewport_navigation() {
    let mut vp = TimelineViewport::new(0, 1000);
    assert_eq!(vp.visible_snap_count(), 1001);
    assert!(vp.is_visible(500));
    assert!(!vp.is_visible(1500));

    vp.zoom_in(10.0);
    assert_eq!(vp.zoom, 10.0);
    vp.zoom_out(2.0);
    assert_eq!(vp.zoom, 5.0);

    vp.pan(100);
    assert_eq!(vp.min_snap, 100);
    assert_eq!(vp.max_snap, 1100);
}

// ===== Pcode row types tests =====

#[test]
fn test_pcode_row_types_full_workflow() {
    let op_row = OpPcodeRow {
        op_index: 0,
        opcode: "INT_ADD".into(),
        output: Some(VarnodeDisplay::register("RAX", 0, 8)),
        inputs: vec![
            VarnodeDisplay::register("RBX", 8, 8),
            VarnodeDisplay::constant(0x10, 8),
        ],
        label: "RAX = RBX + 0x10".into(),
    };
    assert_eq!(op_row.opcode, "INT_ADD");

    let branch_row = BranchPcodeRow {
        op_index: 5,
        target: 0x401000,
        is_conditional: true,
        condition: Some(VarnodeDisplay::register("ZF", 0x38, 1)),
        label: "CBRANCH 0x401000".into(),
    };
    assert!(branch_row.is_conditional);

    let unique_row = UniqueRowData {
        offset: 0x100,
        size: 8,
        ref_type: UniqueRefType::ReadWrite,
        value: Some(42),
        label: "unique:100".into(),
    };
    assert_eq!(unique_row.ref_type, UniqueRefType::ReadWrite);
}

#[test]
fn test_varnode_display_types() {
    let reg = VarnodeDisplay::register("RAX", 0, 8);
    assert_eq!(reg.space, "register");
    assert_eq!(reg.display, "RAX");

    let cst = VarnodeDisplay::constant(0xDEADBEEF, 4);
    assert_eq!(cst.space, "const");
    assert!(cst.display.contains("deadbeef"));

    let unique = VarnodeDisplay::unique(0x200, 8);
    assert_eq!(unique.space, "unique");
    assert!(unique.display.contains("200"));
}

// ===== DomainObjectEventQueues tests =====

#[test]
fn test_event_queues_full_workflow() {
    let queues = DomainObjectEventQueues::new(Duration::from_millis(100));
    let counter = Arc::new(AtomicUsize::new(0));
    let counter2 = counter.clone();

    let listener = Arc::new(FnListener::new(move |_| {
        counter2.fetch_add(1, Ordering::SeqCst);
    }));
    queues.add_listener(listener);

    for i in 0..10 {
        queues.fire_event(DomainChangeEvent::new("TEST", format!("event {}", i)));
    }
    assert_eq!(counter.load(Ordering::SeqCst), 10);

    // Disable and re-enable
    queues.set_events_enabled(false);
    queues.fire_event(DomainChangeEvent::new("TEST", "should be dropped"));
    assert_eq!(counter.load(Ordering::SeqCst), 10); // No increment

    queues.set_events_enabled(true);
    assert_eq!(counter.load(Ordering::SeqCst), 11); // RESTORED event
}

#[test]
fn test_event_queues_private_queues() {
    let queues = DomainObjectEventQueues::new(Duration::from_millis(100));

    let c1 = Arc::new(AtomicUsize::new(0));
    let c2 = Arc::new(AtomicUsize::new(0));
    let c1c = c1.clone();
    let c2c = c2.clone();

    let l1 = Arc::new(FnListener::new(move |_| { c1c.fetch_add(1, Ordering::SeqCst); }));
    let l2 = Arc::new(FnListener::new(move |_| { c2c.fetch_add(1, Ordering::SeqCst); }));

    queues.add_listener(l1);
    let qid = queues.create_private_queue(l2);

    queues.fire_event(DomainChangeEvent::new("TEST", "test"));
    assert_eq!(c1.load(Ordering::SeqCst), 1);
    assert_eq!(c2.load(Ordering::SeqCst), 1);

    queues.remove_private_queue(qid);
    queues.fire_event(DomainChangeEvent::new("TEST", "test2"));
    assert_eq!(c1.load(Ordering::SeqCst), 2);
    assert_eq!(c2.load(Ordering::SeqCst), 1); // Private queue removed
}

// ===== Cross-module integration =====

#[test]
fn test_cross_module_mapping_workflow() {
    // Create a module map proposal
    let mut module_proposal = ModuleMapProposalResult::new("libc.so", "libc");
    module_proposal.add_entry(ModuleMapEntry::new(
        "libc.so", 0x7F000000, 0x400000, 0x100000,
    ));

    // Create a region map proposal for the same module
    let mut region_proposal = RegionMapProposalResult::new("trace");
    region_proposal.add_entry(RegionMapEntry::new(
        ".text", 0x7F000000, 0x7F0FFFFF,
        ".text", 0x400000, 0x4FFFFF,
    ));
    region_proposal.add_entry(RegionMapEntry::new(
        ".data", 0x7F100000, 0x7F1FFFFF,
        ".data", 0x500000, 0x5FFFFF,
    ));

    // Create a section map proposal
    let mut section_proposal = SectionMapProposalResult::new("libc.so", "libc");
    section_proposal.add_entry(SectionMapEntry::new(
        "libc.so", ".text", 0x0, 0xFFFFF,
        ".text", 0x400000, 0x4FFFFF,
    ));

    // Verify the proposals work together
    assert_eq!(module_proposal.entry_count(), 1);
    assert_eq!(region_proposal.good_matches().len(), 2);
    assert_eq!(section_proposal.sorted_by_score().len(), 1);

    // Create a breakpoint timeline that references the same addresses
    let mut timeline = BreakpointTimelineModel::new(0, 1000);
    let mut entry = BreakpointTimelineEntry::new(1, 0x400000);
    entry.record_hit(BreakpointHitEvent::new(5, 1, 1, false));
    timeline.add_entry(entry);

    assert_eq!(timeline.total_hit_count(), 1);
}

#[test]
fn test_cross_module_event_and_data_flow() {
    // Set up event queues
    let queues = DomainObjectEventQueues::new(Duration::from_millis(100));
    let received = Arc::new(std::sync::Mutex::new(Vec::new()));
    let received_clone = received.clone();

    let listener = Arc::new(FnListener::new(move |event| {
        received_clone.lock().unwrap().push(event.event_type.clone());
    }));
    queues.add_listener(listener);

    // Fire events corresponding to mapping operations
    queues.fire_event(DomainChangeEvent::new("MAPPING_ADDED", "new mapping"));
    queues.fire_event(DomainChangeEvent::new("MODULE_LOADED", "libc loaded"));
    queues.fire_event(DomainChangeEvent::new("BREAKPOINT_HIT", "bp at 0x400000"));

    let events = received.lock().unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0], "MAPPING_ADDED");
    assert_eq!(events[1], "MODULE_LOADED");
    assert_eq!(events[2], "BREAKPOINT_HIT");
}

#[test]
fn test_lifespan_integration_with_proposals() {
    let lifespan = Lifespan::span(5, 50);
    let entry = ModuleMapEntry::new("test", 0, 0, 100)
        .with_lifespan(lifespan);
    assert_eq!(entry.lifespan.lmin(), 5);
    assert_eq!(entry.lifespan.lmax(), 50);

    // OffsetSnap with same snap
    let os = OffsetSnap::new(0x1000, 5);
    assert!(!os.is_scratch());
    assert_eq!(os.snap, 5);
}

#[test]
fn test_full_trace_data_pipeline() {
    // Simulate a full trace data pipeline using all the new types

    // 1. Create trace database info
    let info = TraceDatabaseInfo::new("test_trace", "x86:LE:64:default", "default")
        .with_platform("linux")
        .with_executable_path("/usr/bin/test");

    // 2. Create offset-snap keys for database entries
    let mut keys = vec![
        OffsetThenSnapKey::new(0x400000, 0),
        OffsetThenSnapKey::new(0x401000, 0),
        OffsetThenSnapKey::new(0x400000, 1),
    ];
    keys.sort();

    // 3. Create memory entries with offset-snap tuples
    let entries: Vec<OffsetSnap> = keys.iter().map(|k| OffsetSnap::new(k.offset, k.snap)).collect();

    // 4. Compute diffs between snapshots
    let snap0_mem = vec![0u8; 0x1000];
    let mut snap1_mem = vec![0u8; 0x1000];
    snap1_mem[0x100] = 0xFF;
    let diffs = compute_diffs_ranges(&snap0_mem, &snap1_mem);
    assert_eq!(diffs, vec![(0x100, 0x100)]);

    // 5. Hash the memory for caching
    let h = hash_bytes(&snap0_mem);
    assert_ne!(h, 0);

    // 6. Verify everything
    assert_eq!(info.name, "test_trace");
    assert_eq!(entries.len(), 3);
    assert!(entries.iter().all(|e| !e.is_scratch()));
}

// ===========================================================================
// Query Cache Tests (ported from DBTraceCacheForContainingQueries / SequenceQueries)
// ===========================================================================
#[cfg(test)]
mod query_cache_tests {
    use ghidra_debug::db::trace_db_query_cache::*;
    use ghidra_debug::model::Lifespan;

    #[test]
    fn test_containing_cache_add_and_query() {
        let mut cache = ContainingQueryCache::<String>::new(10, 0x1000, 100);
        assert!(cache.is_empty());

        cache.add_entry(CachedRangeEntry {
            min_offset: 0x1000,
            max_offset: 0x2000,
            lifespan: Lifespan::span(0, 100),
            value: "region_a".to_string(),
        });
        cache.add_entry(CachedRangeEntry {
            min_offset: 0x3000,
            max_offset: 0x4000,
            lifespan: Lifespan::span(0, 100),
            value: "region_b".to_string(),
        });
        assert_eq!(cache.len(), 2);

        let results = cache.get_all_containing(&CachePointKey::new(50, 0x1500));
        assert_eq!(results.len(), 1);
        assert_eq!(*results[0], "region_a");

        let results = cache.get_all_containing(&CachePointKey::new(50, 0x3500));
        assert_eq!(results.len(), 1);
        assert_eq!(*results[0], "region_b");

        let results = cache.get_all_containing(&CachePointKey::new(50, 0x2500));
        assert!(results.is_empty());
    }

    #[test]
    fn test_containing_cache_snap_out_of_range() {
        let mut cache = ContainingQueryCache::<i32>::new(10, 0x1000, 100);
        cache.add_entry(CachedRangeEntry {
            min_offset: 0x1000,
            max_offset: 0x2000,
            lifespan: Lifespan::span(0, 100),
            value: 42,
        });

        assert_eq!(cache.get_first_containing(&CachePointKey::new(50, 0x1500)), Some(&42));
        assert_eq!(cache.get_first_containing(&CachePointKey::new(200, 0x1500)), None);
    }

    #[test]
    fn test_containing_cache_invalidation() {
        let mut cache = ContainingQueryCache::<String>::new(10, 0x1000, 100);
        cache.add_entry(CachedRangeEntry {
            min_offset: 0x1000,
            max_offset: 0x2000,
            lifespan: Lifespan::span(0, 100),
            value: "test".to_string(),
        });
        cache.notify_entry_removed();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_containing_cache_compute_ranges() {
        let cache = ContainingQueryCache::<i32>::new(10, 0x1000, 100);
        let (smin, smax) = cache.compute_snap_range(50);
        assert_eq!(smin, 40);
        assert_eq!(smax, 60);
        let (amin, amax) = cache.compute_addr_range(0x5000);
        assert_eq!(amin, 0x4000);
        assert_eq!(amax, 0x6000);
    }

    #[test]
    fn test_sequence_cache_basic() {
        let mut cache = SequenceQueryCache::<String>::new(5, 0x1000);
        {
            let region = cache.ensure_in_cache(0, 0x1004);
            region.load(vec![
                (0x1000, "nop".to_string()),
                (0x1004, "mov".to_string()),
                (0x1008, "add".to_string()),
            ]);
        }

        assert_eq!(cache.get_floor(0, 0x1005).map(|s| s.as_str()), Some("mov"));
        assert_eq!(cache.get_ceiling(0, 0x1005).map(|s| s.as_str()), Some("add"));
    }

    #[test]
    fn test_sequence_cache_lru_eviction() {
        let mut cache = SequenceQueryCache::<i32>::new(2, 0x100);

        { let r = cache.ensure_in_cache(0, 0x100); r.load(vec![(0x100, 1)]); }
        { let r = cache.ensure_in_cache(0, 0x200); r.load(vec![(0x200, 2)]); }
        assert_eq!(cache.region_count(), 2);

        { let r = cache.ensure_in_cache(0, 0x300); r.load(vec![(0x300, 3)]); }
        assert_eq!(cache.region_count(), 2); // evicted one
    }

    #[test]
    fn test_sequence_cache_invalidation() {
        let mut cache = SequenceQueryCache::<i32>::new(3, 0x100);
        { let r = cache.ensure_in_cache(0, 0x100); r.load(vec![(0x100, 1)]); }
        assert_eq!(cache.region_count(), 1);
        cache.invalidate();
        assert_eq!(cache.region_count(), 0);
    }

    #[test]
    fn test_cached_range_entry_contains() {
        let entry = CachedRangeEntry {
            min_offset: 0x1000,
            max_offset: 0x2000,
            lifespan: Lifespan::span(5, 15),
            value: "test",
        };
        assert!(entry.contains(&CachePointKey::new(10, 0x1500)));
        assert!(!entry.contains(&CachePointKey::new(20, 0x1500)));
        assert!(!entry.contains(&CachePointKey::new(10, 0x3000)));
    }

    #[test]
    fn test_point_key_hash_and_eq() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(CachePointKey::new(1, 100));
        set.insert(CachePointKey::new(1, 100));
        set.insert(CachePointKey::new(2, 100));
        assert_eq!(set.len(), 2);
    }
}

// ===========================================================================
// Trace Utility Tests (ported from ghidra.trace.util)
// ===========================================================================
#[cfg(test)]
mod trace_util_tests {
    use ghidra_debug::util::trace_util_extras::*;
    use ghidra_debug::model::Lifespan;

    #[test]
    fn test_overlapping_object_iterator() {
        let items = vec![1, 2, 3, 4, 5];
        let collected: Vec<_> = OverlappingObjectIterator::new(items).collect();
        assert_eq!(collected, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_viewport_span_iterator_partial() {
        let lifespans = vec![Lifespan::span(0, 10), Lifespan::span(20, 30)];
        let spans: Vec<_> = ViewportSpanIterator::new(5, 25, lifespans).collect();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0], Lifespan::span(5, 10));
        assert_eq!(spans[1], Lifespan::span(20, 25));
    }

    #[test]
    fn test_viewport_span_iterator_no_intersection() {
        let lifespans = vec![Lifespan::span(0, 5), Lifespan::span(10, 15)];
        let spans: Vec<_> = ViewportSpanIterator::new(6, 9, lifespans).collect();
        assert!(spans.is_empty());
    }

    #[test]
    fn test_byte_array_utils() {
        assert!(ByteArrayUtils::equals(&[1, 2, 3], &[1, 2, 3]));
        assert!(!ByteArrayUtils::equals(&[1, 2], &[1, 2, 3]));

        let mut dest = [0u8; 4];
        ByteArrayUtils::xor(&[0xFF, 0x00, 0xAA, 0x55], &[0xFF, 0xFF, 0xFF, 0xFF], &mut dest);
        assert_eq!(dest, [0x00, 0xFF, 0x55, 0xAA]);

        assert_ne!(ByteArrayUtils::hash(&[1, 2, 3]), 0);
    }

    #[test]
    fn test_method_protector() {
        let mut protector = MethodProtector::new();
        assert!(!protector.is_active());
        assert!(protector.enter());
        assert!(protector.is_active());
        assert!(!protector.enter()); // reentrant guard
        protector.leave();
        assert!(!protector.is_active());
        assert!(protector.enter());
    }

    #[test]
    fn test_copy_on_write_lifecycle() {
        let mut cow = CopyOnWrite::new(vec![10, 20, 30]);
        assert!(!cow.is_dirty());
        cow.get_mut().push(40);
        assert!(cow.is_dirty());
        assert_eq!(cow.get().len(), 4);
        cow.mark_clean();
        assert_eq!(cow.into_inner(), vec![10, 20, 30, 40]);
    }
}

// ===========================================================================
// Platform Connector Tests
// ===========================================================================
#[cfg(test)]
mod platform_connector_tests {
    use ghidra_debug::plugin::platform_connectors::*;
    use ghidra_debug::services::platform_impl::Endian;

    #[test]
    fn test_builtin_providers_count() {
        let providers = builtin_opinion_providers();
        assert!(providers.len() >= 5); // GDB, LLDB, Frida, DbgEng, JDI, Host, Override
    }

    #[test]
    fn test_gdb_x86_64_linux() {
        let offers = query_opinions(Some("gdb"), "x86_64", "Linux", Some(Endian::Little), false);
        assert!(!offers.is_empty());
        for i in 1..offers.len() {
            assert!(offers[i - 1].confidence >= offers[i].confidence);
        }
    }

    #[test]
    fn test_lldb_aarch64_darwin() {
        let offers = query_opinions(Some("lldb"), "aarch64", "Darwin", Some(Endian::Little), false);
        assert!(!offers.is_empty());
    }

    #[test]
    fn test_host_fallback() {
        let offers = query_opinions(None, "x86_64", "Linux", None, false);
        assert!(!offers.is_empty());
    }
}

// ===========================================================================
// API Types Tests
// ===========================================================================
#[cfg(test)]
mod api_type_tests {
    use ghidra_debug::api::action_name::ActionName;
    use ghidra_debug::api::breakpoint::LogicalBreakpoint;
    use ghidra_debug::api::control_mode::ControlMode;

    #[test]
    fn test_action_name_variants() {
        let _ = ActionName::Continue;
        let _ = ActionName::StepInto;
        let _ = ActionName::StepOver;
        let _ = ActionName::StepOut;
        let _ = ActionName::Kill;
        let _ = ActionName::Detach;
    }

    #[test]
    fn test_logical_breakpoint_lifecycle() {
        let bp = LogicalBreakpoint::new(0x401000, "main");
        assert_eq!(bp.offset, 0x401000);
        assert!(bp.is_enabled());
    }

    #[test]
    fn test_control_mode_variants() {
        let _ = ControlMode::RoTarget;
        let _ = ControlMode::RwTarget;
    }
}

// ===========================================================================
// Pcode Trace Emulation Tests
// ===========================================================================
#[cfg(test)]
mod pcode_trace_tests {
    use ghidra_debug::pcode::trace_emu::unknown_state_exception::UnknownStatePcodeExecutionException;

    #[test]
    fn test_unknown_state_exception() {
        let exc = UnknownStatePcodeExecutionException::new(
            0x1000,
            "Read of uninitialized memory at 0x1000",
        );
        assert_eq!(exc.address, 0x1000);
        assert!(exc.message.contains("0x1000"));
    }

    #[test]
    fn test_unknown_state_exception_display() {
        let exc = UnknownStatePcodeExecutionException::new(0x2000, "test error");
        let display = format!("{}", exc);
        assert!(display.contains("test error"));
    }
}

// ===========================================================================
// Emulation Integration Tests
// ===========================================================================
#[cfg(test)]
mod emulation_integration_tests {
    use ghidra_debug::services::emulation_integration_ext::*;

    #[test]
    fn test_write_modes() {
        assert!(TargetWriteMode::Rw.can_write());
        assert!(!TargetWriteMode::Ro.can_write());
    }

    #[test]
    fn test_writer_configs() {
        let delayed = EmulationWriterConfig::delayed_write_trace();
        assert!(!delayed.mode.can_write());
        assert!(delayed.log_writes);

        let immediate = EmulationWriterConfig::immediate_write_target();
        assert!(immediate.mode.can_write());
        assert!(immediate.immediate_write_target);

        let trace_only = EmulationWriterConfig::trace_only();
        assert!(!trace_only.mode.can_write());
        assert!(!trace_only.redirect_reads_to_target);
    }
}
