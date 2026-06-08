//! Integration tests for newly ported Debug modules.
//!
//! These tests exercise the modules ported from:
//! - `model/data`: TraceBasedDataTypeManager trait and InMemoryTraceDataTypeManager
//! - `services/mapping_proposals`: Default mapping proposals for modules/sections/regions
//! - `services/mapping_utils`: Static mapping utility functions
//! - `services/emulation_extras`: Emulation mode, utilities, integration
//! - `services/save_trace_tasks`: Save trace task implementations
//! - `services/progress_extras`: Closeable task monitors and progress tracking

#[cfg(test)]
mod tests {
    // =========================================================================
    // model::data tests
    // =========================================================================

    use crate::model::data::{
        DataTypeId, DataTypeConflictHandler,
        InMemoryTraceDataTypeManager, TraceBasedDataTypeManager, TraceDataType,
    };

    #[test]
    fn test_data_trait_resolve_keep() {
        let mut mgr = InMemoryTraceDataTypeManager::new("dtm", "t1", "x86:LE:64");
        let dt = TraceDataType::new(DataTypeId(0), "uint32", 4);
        let first = mgr.resolve(dt, DataTypeConflictHandler::Replace).unwrap();
        let first_id = first.id;

        let dt2 = TraceDataType::new(DataTypeId(0), "uint32", 8);
        let kept = mgr.resolve(dt2, DataTypeConflictHandler::Keep).unwrap();
        assert_eq!(kept.id, first_id);
        assert_eq!(kept.size, 4); // kept the original
    }

    #[test]
    fn test_data_trait_add_types() {
        let mut mgr = InMemoryTraceDataTypeManager::new("dtm", "t1", "arm:LE:32");
        for name in &["u8", "u16", "u32", "u64"] {
            let size = name[1..].parse::<usize>().unwrap();
            let dt = TraceDataType::new(DataTypeId(0), *name, size / 8);
            mgr.add_data_type(dt, DataTypeConflictHandler::Replace).unwrap();
        }
        assert_eq!(mgr.data_type_count(), 4);
        assert!(mgr.get_data_type_by_name("u32").is_some());
        assert!(mgr.get_data_type_by_name("u128").is_none());
    }

    #[test]
    fn test_data_trait_platform_info() {
        let mgr = InMemoryTraceDataTypeManager::new("MyDTM", "trace-42", "mips:BE:32");
        assert_eq!(mgr.name(), "MyDTM");
        assert_eq!(mgr.trace_id(), "trace-42");
        assert_eq!(mgr.platform_name(), "mips:BE:32");
    }

    #[test]
    fn test_data_type_full_name_with_category() {
        let dt = TraceDataType::new(DataTypeId(1), "my_struct", 16)
            .with_category("/project/types");
        assert_eq!(dt.full_name(), "/project/types/my_struct");
    }

    #[test]
    fn test_data_type_serde_roundtrip() {
        let dt = TraceDataType::new(DataTypeId(99), "pointer_t", 8)
            .with_category("/pointers")
            .as_builtin();
        let json = serde_json::to_string(&dt).unwrap();
        let back: TraceDataType = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "pointer_t");
        assert!(back.builtin);
        assert_eq!(back.category_path, "/pointers");
    }

    // =========================================================================
    // services::mapping_proposals tests
    // =========================================================================

    use crate::services::mapping_proposals::{
        compute_name_score, compute_size_score, quantize_range,
        DefaultModuleMapProposal, DefaultRegionMapProposal, DefaultSectionMapProposal,
        ProgramModuleEntry, ProgramModuleIndex,
    };

    #[test]
    fn test_module_proposal_scoring() {
        let mut proposal = DefaultModuleMapProposal::new(
            "t1", "libc.so", 0x7f000000, 0x7f100000, 0, "libc.so",
            0x7f000000, 0x7f100000,
        );
        // Add a block-region pair at offset 0x1000 from bases
        proposal.add_program_block(0x1000, 0x7f001000, 0x7f001fff, 0x1000);
        proposal.add_trace_region(0x1000, 0x7f001000, 0x7f001fff, 0x1000);

        let score = proposal.compute_score();
        assert!(score >= 13.0); // offset match + size match

        let entries = proposal.compute_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].from_name, "libc.so");
    }

    #[test]
    fn test_section_proposal_matching() {
        let mut proposal = DefaultSectionMapProposal::new("t1", "elf", 0, "elf");
        proposal.add_section(".text", 0x401000, 0x401fff);
        proposal.add_section(".rodata", 0x402000, 0x402fff);
        proposal.add_section(".data", 0x403000, 0x403fff);

        let blocks = vec![
            (".text".into(), 0x401000u64, 0x401fffu64),
            (".rodata".into(), 0x402000u64, 0x402fffu64),
            (".data".into(), 0x403000u64, 0x403fffu64),
            (".bss".into(), 0x404000u64, 0x4047ffu64),
        ];
        proposal.match_blocks(&blocks);

        let score = proposal.compute_score();
        assert!(score > 5.0); // Should have good name+size matches

        let entries = proposal.compute_entries();
        assert_eq!(entries.len(), 3); // Only 3 sections, not .bss
    }

    #[test]
    fn test_region_proposal_full_pipeline() {
        let mut proposal = DefaultRegionMapProposal::new("t1", 0, "prog", 0x400000);
        proposal.add_region(".text", 0x7fff0000, 0x7fff0fff);
        proposal.add_region(".data", 0x7fff1000, 0x7fff1fff);
        proposal.add_block(".text", 0x400000, 0x400fff);
        proposal.add_block(".data", 0x401000, 0x401fff);

        proposal.process();
        let entries = proposal.compute_entries();
        assert_eq!(entries.len(), 2);

        // Verify translation
        let text_entry = entries.iter().find(|e| e.from_name == ".text").unwrap();
        assert_eq!(text_entry.translate_from_to(0x7fff0000), Some(0x400000));
    }

    #[test]
    fn test_quantize_edge_cases() {
        // Already aligned
        let (min, max) = quantize_range(0x400000, 0x400fff);
        assert_eq!(min, 0x400000);
        assert_eq!(max, 0x400fff);

        // Single byte range
        let (min, max) = quantize_range(0x401234, 0x401234);
        assert_eq!(min, 0x401000);
        assert_eq!(max, 0x401fff);
    }

    #[test]
    fn test_name_score_variants() {
        assert_eq!(compute_name_score("hello", "hello"), 10.0);
        assert_eq!(compute_name_score(".text", "text"), 9.0);
        assert!(compute_name_score(".text_segment", ".text") > 5.0);
        assert!(compute_name_score(".text", ".data") < 3.0);
        assert!(compute_name_score("", "") >= 0.0);
    }

    #[test]
    fn test_size_score_variants() {
        assert_eq!(compute_size_score(100, 100), 10.0);
        assert!(compute_size_score(100, 200) > 0.0);
        assert_eq!(compute_size_score(0, 100), 0.0);
    }

    #[test]
    fn test_program_module_index_full() {
        let mut idx = ProgramModuleIndex::new("app.exe");

        let mut m1 = ProgramModuleEntry::new("main.exe", 0x400000, 0x20000);
        m1.add_section(".text", 0x401000, 0x409fff);
        m1.add_section(".data", 0x410000, 0x41ffff);
        idx.add_module(m1);

        let mut m2 = ProgramModuleEntry::new("libssl.so", 0x7f000000, 0x100000);
        m2.add_section(".text", 0x7f001000, 0x7f07ffff);
        idx.add_module(m2);

        assert_eq!(idx.module_count(), 2);
        assert!(idx.find_best_match("libssl.so", 0).is_some());
        assert!(idx.find_best_match("unknown", 0x400000).is_some());
    }

    // =========================================================================
    // services::mapping_utils tests
    // =========================================================================

    use crate::services::mapping_utils::{
        compute_module_short_name, compute_mapped_files, get_image_name,
        Extrema, is_real_block, MappingInfo,
    };
    use crate::model::Lifespan;

    #[test]
    fn test_mapping_utils_short_names() {
        assert_eq!(compute_module_short_name("/usr/bin/prog"), "prog");
        assert_eq!(compute_module_short_name("C:\\Windows\\ntdll.dll"), "ntdll.dll");
        assert_eq!(compute_module_short_name("simple"), "simple");
    }

    #[test]
    fn test_mapping_utils_image_names() {
        assert_eq!(get_image_name("file:///home/user/lib.so"), "lib.so");
        assert_eq!(get_image_name("simple"), "simple");
    }

    #[test]
    fn test_mapping_utils_no_mappings() {
        assert!(compute_mapped_files(&[], 0, 0, 0).is_empty());
    }

    #[test]
    fn test_mapping_utils_single_full_coverage() {
        let mappings = vec![MappingInfo::new(
            0x1000, 0x3000, Lifespan::at(5),
            "file:///prog.exe", "0x400000", 0x2001,
        )];
        assert_eq!(compute_mapped_files(&mappings, 5, 0x1000, 0x3000), "prog.exe");
    }

    #[test]
    fn test_mapping_utils_partial_coverage() {
        let mappings = vec![MappingInfo::new(
            0x1000, 0x2000, Lifespan::at(0),
            "file:///prog.exe", "0x400000", 0x1001,
        )];
        assert_eq!(compute_mapped_files(&mappings, 0, 0x1000, 0x4000), "prog.exe*");
    }

    #[test]
    fn test_mapping_utils_wrong_snap() {
        let mappings = vec![MappingInfo::new(
            0x1000, 0x2000, Lifespan::at(5),
            "file:///prog.exe", "0x400000", 0x1001,
        )];
        assert!(compute_mapped_files(&mappings, 10, 0x1000, 0x2000).is_empty());
    }

    #[test]
    fn test_extrema_full() {
        let mut e = Extrema::new();
        e.consider_range(0x1000, 0x2000);
        e.consider_range(0x500, 0x3000);
        e.consider(0x4000);
        assert_eq!(e.range(), Some((0x500, 0x4000)));
        assert_eq!(e.length(), 0x3B01);
    }

    #[test]
    fn test_extrema_empty() {
        let e = Extrema::new();
        assert!(e.range().is_none());
        assert_eq!(e.length(), 0);
    }

    #[test]
    fn test_is_real_block_variants() {
        assert!(is_real_block(true, false, false));
        assert!(!is_real_block(false, false, false));
        assert!(!is_real_block(true, true, false));
        assert!(!is_real_block(true, false, true));
    }

    #[test]
    fn test_mapping_info_translation() {
        let m = MappingInfo::new(
            0x7fff0000, 0x7fff0fff, Lifespan::at(0),
            "file:///prog", "0x400000", 0x1000,
        );
        assert_eq!(m.trace_to_program_offset(0x7fff0100), Some(0x100));
        assert!(m.contains(0x7fff0500, 0));
        assert!(!m.contains(0x7fff0500, 10)); // snap 10 not in Lifespan::at(0)
        assert!(m.overlaps(0x7fff0800, 0x7fff1800, 0));
    }

    // =========================================================================
    // services::emulation_extras tests
    // =========================================================================

    use crate::services::emulation_extras::{
        DebuggerEmulationIntegration, EmulationMode, EmulationSessionConfig,
        EmulatorOutOfMemoryException, ProgramEmulationUtils,
    };

    #[test]
    fn test_emulation_mode_variants() {
        assert_eq!(EmulationMode::default(), EmulationMode::SingleStep);
        assert_eq!(EmulationMode::SingleInstruction.to_string(), "Single Instruction");
        assert_eq!(EmulationMode::FixedSteps.to_string(), "Fixed Steps");
    }

    #[test]
    fn test_emulator_oom() {
        let err = EmulatorOutOfMemoryException::new("Exceeded limit")
            .with_memory_info(1024 * 1024, 512 * 1024);
        let s = format!("{}", err);
        assert!(s.contains("Exceeded limit"));
        assert!(s.contains("requested"));
    }

    #[test]
    fn test_program_emu_utils_range() {
        let blocks = vec![
            (".text".into(), 0x400000u64, 0x400fffu64, true),
            (".data".into(), 0x401000u64, 0x401fffu64, false),
            (".init".into(), 0x3f0000u64, 0x3fffffu64, true),
        ];
        let range = ProgramEmulationUtils::compute_emulation_memory_range(&blocks);
        assert_eq!(range, Some((0x3f0000, 0x400fff)));
    }

    #[test]
    fn test_program_emu_utils_estimate() {
        let blocks = vec![
            (".text".into(), 0x400000u64, 0x400fffu64),
            (".data".into(), 0x401000u64, 0x4017ffu64),
        ];
        assert_eq!(
            ProgramEmulationUtils::estimate_memory_required(&blocks),
            0x1000 + 0x800
        );
    }

    #[test]
    fn test_program_emu_validate_ok() {
        let blocks = vec![
            (".text".into(), 0x400000u64, 0x400fffu64, true),
            (".data".into(), 0x401000u64, 0x401fffu64, false),
        ];
        assert!(ProgramEmulationUtils::validate_emulation_layout(&blocks).is_ok());
    }

    #[test]
    fn test_program_emu_validate_overlap() {
        let blocks = vec![
            (".text".into(), 0x400000u64, 0x401fffu64, true),
            (".rodata".into(), 0x401000u64, 0x402fffu64, true),
        ];
        assert!(ProgramEmulationUtils::validate_emulation_layout(&blocks).is_err());
    }

    #[test]
    fn test_emu_integration_find_block() {
        let blocks = vec![
            (".text".into(), 0x400000u64, 0x400fffu64, true),
            (".data".into(), 0x401000u64, 0x401fffu64, false),
        ];
        let block = DebuggerEmulationIntegration::find_containing_block(0x400500, &blocks);
        assert!(block.is_some());
        assert_eq!(block.unwrap().0, ".text");
        assert!(DebuggerEmulationIntegration::find_containing_block(0x500000, &blocks).is_none());
    }

    #[test]
    fn test_emu_integration_emulatable() {
        let blocks = vec![
            (".text".into(), 0x400000u64, 0x400fffu64, true),
            (".data".into(), 0x401000u64, 0x401fffu64, false),
        ];
        assert!(DebuggerEmulationIntegration::is_emulatable_address(0x400500, &blocks));
        assert!(!DebuggerEmulationIntegration::is_emulatable_address(0x401500, &blocks));
    }

    #[test]
    fn test_emulation_session_config_presets() {
        let c = EmulationSessionConfig::single_step();
        assert_eq!(c.mode, EmulationMode::SingleStep);

        let c = EmulationSessionConfig::run_until_address(0xDEAD);
        assert_eq!(c.target_address, Some(0xDEAD));

        let c = EmulationSessionConfig::fixed_steps(42);
        assert_eq!(c.max_steps, 42);

        let json = serde_json::to_string(&c).unwrap();
        let back: EmulationSessionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_steps, 42);
    }

    // =========================================================================
    // services::save_trace_tasks tests
    // =========================================================================

    use crate::services::save_trace_tasks::{
        SaveNewTraceTask, SaveOutcome, SaveTraceAsTask, SaveTraceTask, TraceFileDescriptor,
    };

    #[test]
    fn test_save_task_lifecycle() {
        let mut task = SaveTraceTask::new("t1", "/tmp/trace.gzf");
        assert!(!task.is_complete());
        let outcome = task.execute();
        assert_eq!(outcome, SaveOutcome::Success);
        assert!(task.is_complete());
    }

    #[test]
    fn test_save_task_empty_path_fails() {
        let mut task = SaveTraceTask::new("t1", "");
        assert_eq!(task.execute(), SaveOutcome::Failed("Empty save path".into()));
    }

    #[test]
    fn test_save_as_task() {
        let mut task = SaveTraceAsTask::new("t1", "/tmp/new.gzf", "new_trace");
        assert_eq!(task.new_name(), "new_trace");
        assert_eq!(task.execute(), SaveOutcome::Success);
    }

    #[test]
    fn test_save_new_task() {
        let mut task = SaveNewTraceTask::new("t1", "/project/traces", "debug.gzf");
        assert_eq!(task.execute(), SaveOutcome::Success);
    }

    #[test]
    fn test_trace_file_descriptor() {
        let mut d = TraceFileDescriptor::new("/path/file.gzf", "file", "t1");
        assert!(!d.is_dirty);
        d.set_dirty(true);
        assert!(d.is_dirty);
        assert_eq!(d.extension(), Some("gzf"));
    }

    #[test]
    fn test_save_outcome_display() {
        assert_eq!(format!("{}", SaveOutcome::Success), "Success");
        assert_eq!(format!("{}", SaveOutcome::Cancelled), "Cancelled");
        assert_eq!(
            format!("{}", SaveOutcome::Failed("err".into())),
            "Failed: err"
        );
    }

    #[test]
    fn test_save_task_serde() {
        let d = TraceFileDescriptor::new("/p/f.gzf", "f", "t1");
        let json = serde_json::to_string(&d).unwrap();
        let back: TraceFileDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(back.path, "/p/f.gzf");
    }

    // =========================================================================
    // services::progress_extras tests
    // =========================================================================

    use crate::services::progress_extras::{
        CloseableTaskMonitor, MonitorReceiver, ProgressEvent, ProgressEventType, ProgressHistory,
    };

    #[test]
    fn test_closeable_monitor_full_lifecycle() {
        let mut m = CloseableTaskMonitor::new(1, "Processing", 200);
        assert!(!m.is_finished());

        m.set_progress(100);
        assert!((m.progress_fraction() - 0.5).abs() < 0.001);

        m.increment_progress(100);
        assert!(m.is_finished());

        m.close();
        assert!(m.is_closed());
        // Can't set progress after close
        m.set_progress(50);
        assert_eq!(m.current_progress, 200);
    }

    #[test]
    fn test_closeable_monitor_indeterminate() {
        let m = CloseableTaskMonitor::new_indeterminate(1, "Waiting");
        assert!(m.indeterminate);
        assert_eq!(m.progress_fraction(), 0.0);
    }

    #[test]
    fn test_monitor_receiver_full_workflow() {
        let mut r = MonitorReceiver::new();

        let id1 = r.create_task("Load", 100);
        let id2 = r.create_indeterminate_task("Fetch");

        assert_eq!(r.active_count(), 2);
        assert!(r.has_active_tasks());

        r.update_progress(id1, 100);
        assert_eq!(r.get_monitor(id1).unwrap().current_progress, 100);

        r.cancel_task(id2);
        assert!(r.get_monitor(id2).unwrap().is_cancelled());

        r.close_task(id1);
        assert!(r.get_monitor(id1).is_none());

        // active_count counts non-closed, non-finished
        // id2 is cancelled but not closed/finished, so still "active"
        assert_eq!(r.active_count(), 1);
    }

    #[test]
    fn test_progress_history_full() {
        let mut h = ProgressHistory::new();

        h.record(ProgressEvent {
            task_id: 1,
            event_type: ProgressEventType::Created,
            timestamp_secs: 0.0,
            progress: 0.0,
            message: "Start".into(),
        });
        h.record(ProgressEvent {
            task_id: 1,
            event_type: ProgressEventType::Updated,
            timestamp_secs: 1.0,
            progress: 0.5,
            message: "Half".into(),
        });
        h.record(ProgressEvent {
            task_id: 1,
            event_type: ProgressEventType::Completed,
            timestamp_secs: 2.0,
            progress: 1.0,
            message: "Done".into(),
        });

        assert_eq!(h.count(), 3);
        assert_eq!(h.events_for_task(1).len(), 3);
        assert_eq!(h.events_for_task(99).len(), 0);

        h.clear();
        assert_eq!(h.count(), 0);
    }

    #[test]
    fn test_monitor_receiver_cleanup() {
        let mut r = MonitorReceiver::new();
        r.create_task("A", 10);
        r.create_task("B", 20);
        assert_eq!(r.total_count(), 2);
        r.cleanup(); // nothing closed, nothing removed
        assert_eq!(r.total_count(), 2);
    }

    // =========================================================================
    // Cross-module integration tests
    // =========================================================================

    #[test]
    fn test_full_module_mapping_workflow() {
        // Simulate a complete workflow: index program, propose mappings, translate

        // 1. Index program modules
        let mut index = ProgramModuleIndex::new("test.elf");
        let mut m = ProgramModuleEntry::new("test.elf", 0x400000, 0x10000);
        m.add_section(".text", 0x401000, 0x404fff);
        m.add_section(".data", 0x405000, 0x405fff);
        index.add_module(m);

        // 2. Find best match
        let matched = index.find_best_match("test.elf", 0);
        assert!(matched.is_some());

        // 3. Create a module map proposal
        let mut proposal = DefaultModuleMapProposal::new(
            "trace1", "test.elf", 0x7f000000, 0x7f010000, 0,
            "test.elf", 0x400000, 0x410000,
        );
        proposal.add_program_block(0, 0x400000, 0x400fff, 0x1000);
        proposal.add_trace_region(0, 0x7f000000, 0x7f000fff, 0x1000);

        let entries = proposal.compute_entries();
        assert!(!entries.is_empty());

        // 4. Translate an address
        let translated = entries[0].translate_from_to(0x7f000100);
        assert!(translated.is_some());

        // 5. Track the mapping
        let mut progress = MonitorReceiver::new();
        let task_id = progress.create_task("Mapping", 1);
        progress.update_progress(task_id, 1);
        assert!(progress.get_monitor(task_id).unwrap().is_finished());
    }

    #[test]
    fn test_data_type_and_emulation_integration() {
        // Create a data type manager for an emulated program
        let mut dtm = InMemoryTraceDataTypeManager::new("emu_dtm", "emu_trace", "x86:LE:64");

        // Add some types needed for emulation
        let u8_type = TraceDataType::new(DataTypeId(0), "uint8", 1);
        dtm.add_data_type(u8_type, DataTypeConflictHandler::Replace).unwrap();

        let reg_type = TraceDataType::new(DataTypeId(0), "register64", 8);
        dtm.add_data_type(reg_type, DataTypeConflictHandler::Replace).unwrap();

        // Set up emulation config
        let config = EmulationSessionConfig::single_step();
        assert_eq!(config.mode, EmulationMode::SingleStep);
        assert!(config.trace_registers);

        // Verify data types are available for emulation
        assert!(dtm.get_data_type_by_name("register64").is_some());
        assert_eq!(dtm.get_data_type_by_name("register64").unwrap().size, 8);
    }

    #[test]
    fn test_save_and_track_workflow() {
        // Simulate saving a trace while tracking progress
        let mut receiver = MonitorReceiver::new();
        let task_id = receiver.create_task("Saving trace", 3);

        // Step 1: Prepare
        receiver.set_message(task_id, "Preparing...");
        receiver.update_progress(task_id, 1);

        // Step 2: Write
        receiver.set_message(task_id, "Writing...");
        receiver.update_progress(task_id, 2);

        // Step 3: Finalize
        let mut save_task = SaveTraceTask::new("trace1", "/tmp/out.gzf");
        let outcome = save_task.execute();
        assert_eq!(outcome, SaveOutcome::Success);

        receiver.update_progress(task_id, 3);
        assert!(receiver.get_monitor(task_id).unwrap().is_finished());
    }

    #[test]
    fn test_mapping_and_static_utils_integration() {
        // Create some mapping info - a single mapping that fully covers a range
        let mappings = vec![
            MappingInfo::new(0x7f000000, 0x7f001fff, Lifespan::at(0), "file:///libc.so", "0x0", 0x2000),
        ];

        // Compute mapped files for a range within the mapping
        let result = compute_mapped_files(&mappings, 0, 0x7f000000, 0x7f001fff);
        assert_eq!(result, "libc.so"); // Single image, full coverage

        // Compute for partial coverage (range extends beyond mapping)
        let result = compute_mapped_files(&mappings, 0, 0x7f000000, 0x7f003fff);
        assert_eq!(result, "libc.so*"); // Single image, partial

        // Two mappings from same image, different ranges
        let mappings2 = vec![
            MappingInfo::new(0x7f000000, 0x7f000fff, Lifespan::at(0), "file:///libc.so", "0x0", 0x1000),
            MappingInfo::new(0x7f001000, 0x7f001fff, Lifespan::at(0), "file:///libc.so", "0x1000", 0x1000),
        ];
        let result = compute_mapped_files(&mappings2, 0, 0x7f000000, 0x7f001fff);
        assert_eq!(result, "libc.so*"); // Two overlapping entries, same image, partial

        // Short name extraction
        assert_eq!(compute_module_short_name("/lib/x86_64-linux-gnu/libc.so.6"), "libc.so.6");
    }
}
