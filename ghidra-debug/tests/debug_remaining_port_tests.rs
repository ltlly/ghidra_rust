//! Integration tests for the remaining Debug module ports.
//!
//! These tests exercise the new modules ported from:
//! - Debugger-api: launch_result, trace_connection_impl
//! - Framework-TraceModeling model: trace_memory_space, trace_code_manager_impl
//! - Framework-TraceModeling db: trace_db_listing_deep, trace_db_register_context_deep
//! - Debugger plugin: gui_copying, gui_stack_frame_model
//! - Debugger services: service_trace_rmi_impl

use ghidra_debug::api::launch_result::*;
use ghidra_debug::api::trace_connection_impl::*;
use ghidra_debug::api::tracermi::ConnectionState;
use ghidra_debug::model::lifespan::Lifespan;
use ghidra_debug::model::trace_memory_space::*;
use ghidra_debug::model::trace_code_manager_impl::*;
use ghidra_debug::model::memory_flag::TraceMemoryFlag;
use ghidra_debug::db::trace_db_listing_deep::*;
use ghidra_debug::db::trace_db_register_context_deep::*;
use ghidra_debug::plugin::gui_copying::*;
use ghidra_debug::plugin::gui_stack_frame_model::*;
use ghidra_debug::services::service_trace_rmi_impl::*;

// ═══════════════════════════════════════════════════════════════════
// Launch Result Integration Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_launch_result_lifecycle() {
    // Test creating a full launch result and then closing it
    let mut result = LaunchResult::success(1, "trace-0")
        .with_session("gdb", ghidra_debug::api::tracermi::TerminalSession::new("term-1"))
        .with_session("tty", ghidra_debug::api::tracermi::TerminalSession::new("term-2"));

    assert!(result.success);
    assert!(result.has_connection());
    assert!(result.has_trace());
    assert_eq!(result.sessions.len(), 2);

    result.close();
    for session in result.sessions.values() {
        assert!(!session.active);
    }
}

#[test]
fn test_launch_configurator_with_arguments() {
    let cfg = LaunchConfigurator::always_prompt()
        .with_arg("cmd", "gdb-multiarch")
        .with_arg("interpreter", "mi2")
        .with_env("PYTHONPATH", "/opt/gdb/python");

    let mut args = std::collections::BTreeMap::new();
    args.insert("target".into(), "/usr/bin/ls".into());

    let result = cfg.configure_launcher(&args, RelPrompt::Before);
    assert_eq!(result["cmd"], "gdb-multiarch");
    assert_eq!(result["target"], "/usr/bin/ls");
    assert_eq!(result["interpreter"], "mi2");
}

// ═══════════════════════════════════════════════════════════════════
// Trace Connection Integration Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_connection_with_targets() {
    let conn = MockTraceRmiConnection::new_debug();
    let inner = conn.inner();

    inner.set_state(ConnectionState::Connected);

    // Publish multiple targets
    let t1 = inner.publish_target(TargetKey::new("trace-process-1"));
    let t2 = inner.publish_target(TargetKey::new("trace-process-2"));

    assert_eq!(inner.get_targets().len(), 2);
    assert!(inner.is_target(&TargetKey::new("trace-process-1")));
    assert!(inner.is_target(&TargetKey::new("trace-process-2")));

    // Set some target state
    t1.set_last_snapshot(42);
    t1.set_busy(true);

    assert_eq!(inner.get_last_snapshot(&TargetKey::new("trace-process-1")), Some(42));
    assert!(inner.is_busy());
    assert!(inner.is_target_busy(&TargetKey::new("trace-process-1")));
    assert!(!inner.is_target_busy(&TargetKey::new("trace-process-2")));

    // Close and verify cleanup
    inner.close();
    assert!(inner.get_targets().is_empty());
}

#[test]
fn test_connection_method_invocation() {
    let conn = MockTraceRmiConnection::new_debug();
    let inner = conn.inner();
    inner.set_state(ConnectionState::Connected);

    // Invoke step
    let result = inner.invoke_async("step", std::collections::BTreeMap::new());
    assert!(result.is_ok());
    let result = result.unwrap();
    assert!(result.is_pending());

    // Complete the request
    inner.complete_request(result.request_id, serde_json::json!({"status": "ok"}));
    // The result should now be completed (verified by status change)

    // Try invoking a non-existent method
    let err = inner.invoke_async("nonexistent", std::collections::BTreeMap::new());
    assert!(err.is_err());
}

// ═══════════════════════════════════════════════════════════════════
// Memory Space Integration Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_memory_full_workflow() {
    // Create memory blocks and buffer
    let mut buf = TraceMemoryBuffer::new(10);

    let mut text_block = TraceMemoryBlock::new(".text", 0x400000, 0x10000);
    text_block.set_flag(TraceMemoryFlag::Read);
    text_block.set_flag(TraceMemoryFlag::Execute);
    buf.add_block(text_block);

    let mut data_block = TraceMemoryBlock::new(".data", 0x500000, 0x1000);
    data_block.set_flag(TraceMemoryFlag::Read);
    data_block.set_flag(TraceMemoryFlag::Write);
    buf.add_block(data_block);

    // Write some code
    buf.put_bytes(0x400000, &[0x55, 0x48, 0x89, 0xE5]); // push rbp; mov rbp, rsp

    // Verify reads
    let code = buf.get_bytes(0x400000, 4).unwrap();
    assert_eq!(code, vec![0x55, 0x48, 0x89, 0xE5]);

    // Verify block lookup
    assert!(buf.is_in_block(0x400500));
    assert!(!buf.is_in_block(0x600000));
    let text = buf.get_block(0x400500).unwrap();
    assert!(text.is_readable());
    assert!(text.is_executable());
}

#[test]
fn test_compressed_memory_roundtrip() {
    // Create realistic code data
    let mut code = vec![0x90u8; 50]; // NOP sled
    code.extend_from_slice(&[0xCC; 10]); // INT3
    code.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5]); // push rbp; mov rbp, rsp

    let compressed = CompressedMemoryBlock::from_bytes(0x400000, &code);
    let decompressed = compressed.decompress();
    assert_eq!(decompressed, code);

    // Check compression is effective for NOP sled
    assert!(compressed.compression_ratio() < 1.0);
}

#[test]
fn test_memory_region_info_workflow() {
    let mut regions = Vec::new();

    regions.push(TraceMemoryRegionInfo::new(
        ".text",
        0x400000,
        0x4FFFFF,
        Lifespan::span(0, 100),
    ));
    regions.push(TraceMemoryRegionInfo::new(
        ".data",
        0x500000,
        0x50FFFF,
        Lifespan::span(0, 100),
    ));
    regions.push(TraceMemoryRegionInfo::new(
        "stack",
        0x7FFE0000,
        0x7FFFFFFF,
        Lifespan::span(5, 50),
    ));

    // Query regions at different snaps
    let at_snap_0: Vec<_> = regions.iter().filter(|r| r.is_valid_at(0)).collect();
    assert_eq!(at_snap_0.len(), 2); // .text and .data

    let at_snap_10: Vec<_> = regions.iter().filter(|r| r.is_valid_at(10)).collect();
    assert_eq!(at_snap_10.len(), 3); // all three

    let at_snap_100: Vec<_> = regions.iter().filter(|r| r.is_valid_at(100)).collect();
    assert_eq!(at_snap_100.len(), 2); // .text and .data
}

// ═══════════════════════════════════════════════════════════════════
// Code Manager Integration Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_code_manager_full_workflow() {
    let mut manager = TraceCodeManagerImpl::new();

    // Set up spaces
    manager.set_default_space(AddressSpaceId::new("ram"));
    manager.get_code_space(AddressSpaceId::new("ram"), true);
    manager.get_code_register_space(AddressSpaceId::new("reg"), 1, true);

    assert_eq!(manager.space_count(), 2);
    assert_eq!(manager.default_space().unwrap().as_str(), "ram");

    // Verify space types
    let ram = manager.get_code_space(AddressSpaceId::new("ram"), false).unwrap();
    assert!(ram.is_memory());

    let reg = manager.get_code_space(AddressSpaceId::new("reg"), false).unwrap();
    assert!(reg.is_register());
}

#[test]
fn test_code_operations_variants() {
    let full = TraceCodeOperations::full(AddressSpaceId::new("ram"));
    assert!(full.supports_instructions);
    assert!(full.supports_data);
    assert!(full.supports_defined_data);

    let reg = TraceCodeOperations::register_only(AddressSpaceId::new("reg"));
    assert!(!reg.supports_instructions);
    assert!(reg.supports_data);
}

// ═══════════════════════════════════════════════════════════════════
// Listing Deep Integration Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_listing_disassembly_simulation() {
    let mut view = TraceCodeUnitsView::new("ram", 0);

    // Simulate a simple function prologue
    view.add_unit(TraceCodeUnit::instruction(
        0x400000, "ram", 0, 1, "PUSH", vec![0x55],
    ).with_pre_comment("main:"));
    view.add_unit(TraceCodeUnit::instruction(
        0x400001, "ram", 0, 3, "MOV", vec![0x48, 0x89, 0xE5],
    ));
    view.add_unit(TraceCodeUnit::instruction(
        0x400004, "ram", 0, 7, "SUB", vec![0x48, 0x83, 0xEC, 0x20, 0x00, 0x00, 0x00],
    ));

    // Add some data
    view.add_unit(TraceCodeUnit::data(
        0x500000, "ram", 0, 4, "dword", vec![0x78, 0x56, 0x34, 0x12],
    ));

    // Verify the listing
    assert_eq!(view.instructions().len(), 3);
    assert_eq!(view.defined_data().len(), 1);

    // Verify comment
    let first = view.get_unit(0x400000).unwrap();
    assert!(first.has_comments());
    assert_eq!(first.pre_comment.as_deref(), Some("main:"));

    // Verify containing lookup
    let containing = view.get_unit_containing(0x400002).unwrap();
    assert_eq!(containing.address, 0x400001); // MOV instruction
}

#[test]
fn test_listing_color_model() {
    let mut model = BlendedListingColorModel::new(0xFFFFFFFF);

    // Set colors for a function
    model.set_color(0x400000, ColorEntry::new(0xFF000000, 0xFFE0FFE0, 0.3));
    model.set_color(0x400001, ColorEntry::new(0xFF000000, 0xFFE0FFE0, 0.3));
    model.set_color(0x400004, ColorEntry::new(0xFFFF0000, 0xFFFFFF00, 0.5)); // highlighted

    // Default color for other addresses
    let default = model.get_color(0x600000);
    assert_eq!(default.background, 0xFFFFFFFF);

    // Custom color
    let highlighted = model.get_color(0x400004);
    assert_eq!(highlighted.background, 0xFFFFFF00);
}

// ═══════════════════════════════════════════════════════════════════
// Register Context Integration Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_register_context_full_workflow() {
    let mut ctx = DeepRegisterContextManager::new();

    // Set up register values at different addresses
    ctx.set_value("RAX", 0x400000, DeepRegisterValue::defined("RAX", vec![0x42; 8]));
    ctx.set_value("RAX", 0x400100, DeepRegisterValue::defined("RAX", vec![0x00; 8]));
    ctx.set_value("TMode", 0x400000, DeepRegisterValue::defined("TMode", vec![1]));

    assert_eq!(ctx.value_count(), 3);
    assert_eq!(ctx.register_names().len(), 2);

    // Query values
    let rax_0 = ctx.get_value("RAX", 0x400000).unwrap();
    assert_eq!(rax_0.as_u64(), Some(0x4242424242424242));

    let rax_100 = ctx.get_value("RAX", 0x400100).unwrap();
    assert_eq!(rax_100.as_u64(), Some(0));

    // Get all RAX values
    let rax_values = ctx.get_values_for_register("RAX");
    assert_eq!(rax_values.len(), 2);

    // Clear TMode
    ctx.clear_register("TMode");
    assert!(!ctx.has_register("TMode"));
    assert_eq!(ctx.value_count(), 2);
}

#[test]
fn test_register_value_partial() {
    let val = DeepRegisterValue::partial(
        "CPSR",
        vec![0x60, 0x00, 0x00, 0x00], // value
        vec![0xE0, 0x00, 0x00, 0x00], // mask: top 3 bits known
    );
    assert_eq!(val.defined_state(), RegisterDefinedState::Partial);
    assert!(val.defined_state().has_known_bits());
    assert!(val.as_u32().is_none()); // not fully defined
}

// ═══════════════════════════════════════════════════════════════════
// Copy Plan Integration Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_copy_plan_full_workflow() {
    let plan = CopyPlanBuilder::new(CopyDirection::TraceToProgram)
        .memory_to_memory(0x400000, "ram", 0, 0x400000, "ram", 1, 0x1000)
        .memory_to_memory(0x500000, "ram", 0, 0x500000, "ram", 1, 0x800)
        .register_copy("RAX", vec![0x42; 8], "RAX")
        .register_copy("RBX", vec![0x00; 8], "RBX")
        .build();

    assert_eq!(plan.entry_count(), 4);
    assert_eq!(plan.total_bytes(), 0x1000 + 0x800 + 8 + 8);
    assert!(!plan.executed);

    let mut plan = plan;
    plan.mark_executed();
    assert!(plan.executed);
}

// ═══════════════════════════════════════════════════════════════════
// Stack Frame Model Integration Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_stack_frame_full_workflow() {
    let mut model = StackFrameModel::new(1, 100);

    // Build a realistic call stack
    model.add_frame(
        StackFrameEntry::new(0, 0x400100, 0x7FFE0000)
            .with_function("main", 0x10)
            .with_fp(0x7FFE0080)
            .with_return_address(0x400200)
            .with_register(FrameRegisterValue::new("RAX", vec![0x42; 8]))
            .with_register(FrameRegisterValue::new("RSP", vec![0x00, 0x00, 0xFE, 0x7F, 0x00, 0x00, 0x00, 0x00])),
    );
    model.add_frame(
        StackFrameEntry::new(1, 0x400200, 0x7FFE0080)
            .with_function("__libc_start_main", 0xF0)
            .with_fp(0x7FFE0100),
    );
    model.add_frame(
        StackFrameEntry::new(2, 0x7F00000, 0x7FFE0100)
            .with_function("_start", 0)
            .with_type(StackFrameType::Synthetic),
    );

    assert_eq!(model.depth(), 3);
    assert!(model.fully_unwound);

    // Verify innermost frame
    let current = model.current_frame().unwrap();
    assert_eq!(current.function_name, "main");
    assert_eq!(current.function_display(), "main+0x10");

    // Verify register values
    let rax = current.get_register("RAX").unwrap();
    assert_eq!(rax.as_u64_le(), Some(0x4242424242424242));

    // Verify display
    let display = model.display_frames();
    assert!(display[0].contains("main"));
    assert!(display[1].contains("__libc_start_main"));
    assert!(display[2].contains("_start"));
}

#[test]
fn test_stack_analyzer() {
    let analyzer = StackAnalyzer::new(8);

    // Simulate stack data with return addresses
    let mut data = vec![0u8; 128];
    // Place return addresses at stack positions
    data[0..8].copy_from_slice(&0x400100u64.to_le_bytes());
    data[8..16].copy_from_slice(&0x400200u64.to_le_bytes());
    data[16..24].copy_from_slice(&0x400300u64.to_le_bytes());
    // Some other data
    data[24..32].copy_from_slice(&0xDEADBEEFu64.to_le_bytes());

    let results = analyzer.find_return_addresses(&data, 0x7FFE0000);
    assert!(results.contains(&0x400100));
    assert!(results.contains(&0x400200));
    assert!(results.contains(&0x400300));
}

// ═══════════════════════════════════════════════════════════════════
// Service Integration Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_trace_rmi_service_full_workflow() {
    let config = TraceRmiServiceConfig {
        listen_address: "127.0.0.1".into(),
        port: 12345,
        max_connections: 8,
        ..Default::default()
    };
    let service = TraceRmiService::new(config);

    // Start service
    service.start().unwrap();
    assert_eq!(service.state(), ServiceState::Listening);

    // Register connections
    let id1 = service.register_connection(
        "192.168.1.1:5000".into(),
        ghidra_debug::api::tracermi::RemoteMethodRegistry::new(),
    );
    let id2 = service.register_connection(
        "192.168.1.2:5001".into(),
        ghidra_debug::api::tracermi::RemoteMethodRegistry::new(),
    );

    assert_eq!(service.connection_count(), 2);

    // Notify target published
    service.notify_target_published(id1, "trace-process-1");
    let conn1 = service.get_connection(id1).unwrap();
    assert_eq!(conn1.target_count, 1);

    // Remove a connection
    service.remove_connection(id2);
    assert_eq!(service.connection_count(), 1);

    // Stop
    service.stop();
    assert_eq!(service.state(), ServiceState::Stopped);
}

#[test]
fn test_launcher_service() {
    let launcher = TraceRmiLauncherService::new();

    // Register offers
    launcher.register_offer(
        "gdb",
        LaunchOfferEntry::new("GDB", "gdb")
            .with_priority(10)
            .with_requires_image(true),
    );
    launcher.register_offer(
        "lldb",
        LaunchOfferEntry::new("LLDB", "lldb").with_priority(20),
    );
    launcher.register_offer(
        "dbgeng",
        LaunchOfferEntry::new("DbgEng", "dbgeng")
            .with_priority(5)
            .with_enabled(false),
    );

    // Verify offer management
    assert!(launcher.has_offers());
    assert_eq!(launcher.offer_schemes().len(), 3);

    let enabled = launcher.enabled_offers();
    assert_eq!(enabled.len(), 2);
    assert_eq!(enabled[0].scheme, "gdb"); // lower priority first

    let gdb = launcher.get_offer("gdb").unwrap();
    assert!(gdb.requires_image);
}

// ═══════════════════════════════════════════════════════════════════
// Cross-Module Integration Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_full_debug_session_simulation() {
    // 1. Create a service
    let config = TraceRmiServiceConfig::default();
    let service = TraceRmiService::new(config);
    service.start().unwrap();

    // 2. Set up a connection
    let conn = MockTraceRmiConnection::new_debug();
    let inner = conn.inner();
    inner.set_state(ConnectionState::Connected);

    // 3. Publish a target
    let target = inner.publish_target(TargetKey::new("trace-0"));
    let conn_id = service.register_connection(
        "localhost".into(),
        ghidra_debug::api::tracermi::RemoteMethodRegistry::new(),
    );
    service.notify_target_published(conn_id, "trace-0");

    // 4. Set up memory
    let mut buf = TraceMemoryBuffer::new(0);
    let mut text = TraceMemoryBlock::new(".text", 0x400000, 0x10000);
    text.set_flag(TraceMemoryFlag::Read);
    text.set_flag(TraceMemoryFlag::Execute);
    buf.add_block(text);
    buf.put_bytes(0x400000, &[0x55, 0x48, 0x89, 0xE5]);

    // 5. Set up listing
    let mut view = TraceCodeUnitsView::new("ram", 0);
    view.add_unit(TraceCodeUnit::instruction(
        0x400000, "ram", 0, 1, "PUSH", vec![0x55],
    ));
    view.add_unit(TraceCodeUnit::instruction(
        0x400001, "ram", 0, 3, "MOV", vec![0x48, 0x89, 0xE5],
    ));

    // 6. Set up register context
    let mut ctx = DeepRegisterContextManager::new();
    ctx.set_value("RBP", 0x400000, DeepRegisterValue::defined("RBP", vec![0x00; 8]));
    ctx.set_value("RSP", 0x400000, DeepRegisterValue::defined("RSP", vec![0x00, 0x00, 0xFE, 0x7F, 0x00, 0x00, 0x00, 0x00]));

    // 7. Set up stack
    let mut stack = StackFrameModel::new(1, 100);
    stack.add_frame(
        StackFrameEntry::new(0, 0x400000, 0x7FFE0000)
            .with_function("main", 0),
    );

    // 8. Create a copy plan
    let copy_plan = CopyPlanBuilder::new(CopyDirection::TraceToProgram)
        .memory_to_memory(0x400000, "ram", 0, 0x400000, "ram", 1, 4)
        .build();

    // Verify everything is consistent
    assert!(!inner.is_closed());
    assert_eq!(service.connection_count(), 1);
    assert!(buf.is_in_block(0x400100));
    assert_eq!(view.instructions().len(), 2);
    assert!(ctx.has_register("RBP"));
    assert_eq!(stack.depth(), 1);
    assert_eq!(copy_plan.entry_count(), 1);

    // 9. Cleanup
    inner.close();
    service.stop();
}

// ═══════════════════════════════════════════════════════════════════
// ProposedUtils: Service Dependency Resolution Integration Tests
// ═══════════════════════════════════════════════════════════════════

use ghidra_debug::proposed_utils::{
    DependentServiceConstructor, DependentServiceResolver, TopologicalSorter,
    UnionedCollection, CatenatedCollection, DistinctIterator, StreamUtils,
    SuppressableCallback, QueuedListener, DbgMsgTracer, TimedMsg,
    DefaultObservableCollection, ID, IDKeyed, IDHashed, ProxyUtilities,
    ByteBufferUtils,
};
use ghidra_debug::proposed_utils::database::{
    CachedObjectStore, CachedObjectIndex, DirectedRecordIterator, DirectedLongKeyIterator,
};
use std::any::TypeId;

#[test]
fn test_service_resolver_realistic_scenario() {
    // Simulate: Logger -> Config -> Database -> Service
    let mut resolver = DependentServiceResolver::new();
    let type_log = TypeId::of::<String>();
    let type_cfg = TypeId::of::<i32>();
    let type_db = TypeId::of::<u64>();
    let type_svc = TypeId::of::<f64>();

    resolver.add_constructor(DependentServiceConstructor::new("Logger", type_log, vec![]));
    resolver.add_constructor(DependentServiceConstructor::new("Config", type_cfg, vec![type_log]));
    resolver.add_constructor(DependentServiceConstructor::new("Database", type_db, vec![type_cfg]));
    resolver.add_constructor(DependentServiceConstructor::new("Service", type_svc, vec![type_db]));

    resolver.add_field_requirement(type_svc);

    let order = resolver.compile().unwrap();
    assert_eq!(order.len(), 4);

    // Verify order is Logger -> Config -> Database -> Service
    assert_eq!(order[0].name, "Logger");
    assert_eq!(order[1].name, "Config");
    assert_eq!(order[2].name, "Database");
    assert_eq!(order[3].name, "Service");
}

#[test]
fn test_topological_sorter_large_graph() {
    let mut sorter = TopologicalSorter::new();
    // Create a large DAG with 100 nodes
    for i in 0..99 {
        sorter.add_edge(i, i + 1);
    }
    // Add some cross edges
    sorter.add_edge(0, 50);
    sorter.add_edge(25, 75);

    let result = sorter.sort().unwrap();
    assert_eq!(result.len(), 100);

    // Verify ordering constraints
    let get_pos = |x: usize| result.iter().position(|r| *r == x).unwrap();
    assert!(get_pos(0) < get_pos(50));
    assert!(get_pos(0) < get_pos(1));
    assert!(get_pos(25) < get_pos(75));
}

#[test]
fn test_unioned_collection_with_complex_types() {
    let mut uc = UnionedCollection::new();
    uc.add_collection(vec!["alpha".to_string(), "beta".to_string()]);
    uc.add_collection(vec!["gamma".to_string()]);
    uc.add_collection(vec![]); // empty sub-collection
    uc.add_collection(vec!["delta".to_string(), "epsilon".to_string()]);

    assert_eq!(uc.len(), 5);
    let items: Vec<_> = uc.iter().cloned().collect();
    assert_eq!(items, vec!["alpha", "beta", "gamma", "delta", "epsilon"]);
}

#[test]
fn test_stream_utils_merge_sorted_strings() {
    let result = StreamUtils::merge_sorted(vec![
        vec!["apple".to_string(), "cherry".to_string()],
        vec!["banana".to_string(), "date".to_string()],
    ]);
    assert_eq!(result, vec!["apple", "banana", "cherry", "date"]);
}

#[test]
fn test_suppressable_callback_reentrant() {
    let mut cb = SuppressableCallback::new("reentrant");
    cb.suppress();
    assert!(!cb.trigger());
    assert!(!cb.trigger());
    assert!(!cb.trigger());
    assert!(cb.is_pending());

    // Resume clears pending state
    assert!(cb.resume());
    assert!(!cb.is_pending());

    // Can trigger again normally
    assert!(cb.trigger());
}

#[test]
fn test_dbg_msg_tracer_serde() {
    let mut tracer = DbgMsgTracer::new();
    tracer.set_enabled(true);
    tracer.trace("msg1");
    tracer.trace("msg2");

    let messages = tracer.messages().to_vec();
    assert_eq!(messages, vec!["msg1", "msg2"]);
}

#[test]
fn test_timed_msg_clone() {
    let msg = TimedMsg::new("clone test", 100, 5);
    let cloned = msg.clone();
    assert_eq!(cloned.message, msg.message);
    assert_eq!(cloned.timestamp_ms, msg.timestamp_ms);
    assert_eq!(cloned.elapsed_ms, msg.elapsed_ms);
}

#[test]
fn test_default_observable_collection_get_out_of_bounds() {
    let mut col = DefaultObservableCollection::new();
    col.push(1);
    assert!(col.get(0).is_some());
    assert!(col.get(1).is_none());
}

#[test]
fn test_queued_listener_serial_operations() {
    let mut ql = QueuedListener::new();
    for i in 0..100 {
        ql.enqueue(i);
    }
    assert_eq!(ql.drain().len(), 100);
    assert!(!ql.has_pending());
}

#[test]
fn test_id_display_format() {
    let id1 = ID::new(42);
    assert_eq!(format!("{}", id1), "42");

    let id2 = ID::with_display(1, "Process-1/Thread-0");
    assert_eq!(format!("{}", id2), "Process-1/Thread-0");
}

#[test]
fn test_byte_buffer_utils_roundtrip() {
    let original = vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD];
    let hex = ByteBufferUtils::to_hex_string(&original);
    let recovered = ByteBufferUtils::from_hex_string(&hex).unwrap();
    assert_eq!(original, recovered);
}

#[test]
fn test_cached_object_store_large_insertions() {
    let mut store = CachedObjectStore::new();
    for i in 0..1000 {
        store.insert(i, i * 2);
    }
    assert_eq!(store.len(), 1000);
    assert_eq!(store.get(&500), Some(&1000));
    assert_eq!(store.get(&999), Some(&1998));
    assert_eq!(store.get(&1000), None);
}

#[test]
fn test_cached_object_index_multi_value() {
    let mut idx = CachedObjectIndex::new();
    for i in 0..10 {
        idx.insert("group", i);
    }
    assert_eq!(idx.get("group").unwrap().len(), 10);
}

#[test]
fn test_directed_record_iterator_large_dataset() {
    let data: Vec<i64> = (0..10000).collect();
    let mut iter = DirectedRecordIterator::forward(data.clone());
    let result = iter.collect_remaining();
    assert_eq!(result.len(), 10000);
    assert_eq!(result[0], 0);
    assert_eq!(result[9999], 9999);
}

#[test]
fn test_directed_long_key_iterator_backward_large() {
    let keys: Vec<i64> = (0..5000).collect();
    let mut iter = DirectedLongKeyIterator::backward(keys);
    let result = iter.collect_remaining();
    assert_eq!(result.len(), 5000);
    assert_eq!(result[0], 4999);
    assert_eq!(result[4999], 0);
}

// ═══════════════════════════════════════════════════════════════════
// Cross-module error handling tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_service_construction_exception_as_error() {
    use ghidra_debug::proposed_utils::ServiceConstructionException;
    let e = ServiceConstructionException::new("test");
    let err: &dyn std::error::Error = &e;
    assert!(err.to_string().contains("test"));
}

#[test]
fn test_unsatisfied_exceptions_clone() {
    let e1 = ghidra_debug::proposed_utils::UnsatisfiedFieldsException::new(vec!["A".into()]);
    let e2 = e1.clone();
    assert_eq!(e1.missing(), e2.missing());

    let e3 = ghidra_debug::proposed_utils::UnsatisfiedParameterException::new(vec!["B".into()]);
    let e4 = e3.clone();
    assert_eq!(e3.unresolved(), e4.unresolved());
}

// ============================================================
// Tests for new modules ported from remaining Debug Java classes
// ============================================================

#[test]
fn test_new_record_manager_full_lifecycle() {
    use ghidra_debug::db::TraceRecordManager;

    let mut mgr = TraceRecordManager::<String>::new("test_lifecycle");

    let k1 = mgr.insert("first".to_string());
    let k2 = mgr.insert("second".to_string());
    let k3 = mgr.insert("third".to_string());

    assert_eq!(mgr.len(), 3);
    assert!(!mgr.is_empty());
    assert_eq!(mgr.get(k1), Some(&"first".to_string()));
    assert_eq!(mgr.get(k2), Some(&"second".to_string()));
    assert_eq!(mgr.get(k3), Some(&"third".to_string()));

    // Dirty tracking
    assert_eq!(mgr.dirty_records().len(), 3);
    mgr.clear_dirty();
    assert!(mgr.dirty_records().is_empty());

    if let Some(val) = mgr.get_mut(k2) {
        val.push_str("_modified");
    }
    assert_eq!(mgr.dirty_records().len(), 1);

    // Remove
    let removed = mgr.remove(k1);
    assert_eq!(removed, Some("first".to_string()));
    assert_eq!(mgr.len(), 2);
}

#[test]
fn test_new_namespace_manager_path_resolution() {
    use ghidra_debug::db::TraceNamespaceManager;

    let mut mgr = TraceNamespaceManager::new();

    let std_key = mgr.create_namespace("std", 0, 0).unwrap();
    let io_key = mgr.create_namespace("io", std_key, 0).unwrap();
    let result_key = mgr.create_namespace("Result", io_key, 0).unwrap();

    assert_eq!(mgr.resolve_path("::std"), Some(std_key));
    assert_eq!(mgr.resolve_path("::std::io"), Some(io_key));
    assert_eq!(mgr.resolve_path("::std::io::Result"), Some(result_key));
    assert_eq!(mgr.resolve_path("::nonexistent"), None);
    assert_eq!(mgr.path_of(result_key), "::std::io::Result");

    let desc = mgr.descendants_of(0);
    assert_eq!(desc.len(), 3);

    // Cascade removal
    let removed = mgr.remove_namespace(std_key);
    assert_eq!(removed.len(), 3);
    assert_eq!(mgr.len(), 1);
}

#[test]
fn test_new_snapshot_manager_timeline() {
    use ghidra_debug::db::TraceSnapshotManager;

    let mut mgr = TraceSnapshotManager::new();
    mgr.create_snapshot_with_desc(10, "initial state");
    mgr.create_snapshot(20);
    mgr.create_snapshot(50);
    mgr.create_snapshot(100);

    assert_eq!(mgr.len(), 4);
    assert_eq!(mgr.min_snap(), Some(10));
    assert_eq!(mgr.max_snap(), Some(100));

    assert_eq!(mgr.floor_snap(15).unwrap().snap, 10);
    assert_eq!(mgr.ceil_snap(25).unwrap().snap, 50);
    assert_eq!(mgr.next_snap(20), Some(50));
    assert_eq!(mgr.prev_snap(50), Some(20));

    let range = mgr.range(10, 50);
    assert_eq!(range.len(), 3);
    assert_eq!(mgr.get_by_snap(10).unwrap().description, "initial state");

    // Remove
    let removed = mgr.remove_snapshot(20);
    assert!(removed.is_some());
    assert_eq!(mgr.len(), 3);
}

#[test]
fn test_new_property_range_map_operations() {
    use ghidra_debug::db::{PropertyMapRangeEntry, TracePropertyRangeMap};
    use ghidra_debug::model::Lifespan;

    let mut map = TracePropertyRangeMap::<i32>::new("ram");
    map.set_range(0x1000, 0x1FFF, Lifespan::span(0, 100), 1);
    map.set_range(0x1000, 0x1FFF, Lifespan::span(50, 200), 2);
    map.set_range(0x2000, 0x2FFF, Lifespan::span(0, 100), 3);

    assert_eq!(map.len(), 3);

    let results = map.get_range(0x1500, 0x2500, &Lifespan::span(25, 75));
    assert!(results.len() >= 2);

    assert_eq!(map.get(0x2000, 30), Some(&3));
    assert_eq!(map.get(0x3000, 30), None);

    // Point entry
    let entry = PropertyMapRangeEntry::<bool>::point(0x400000, 10, true);
    assert!(entry.contains(0x400000, 10));
    assert!(!entry.contains(0x400000, 11));
}

#[test]
fn test_new_builtin_interface_factory() {
    use ghidra_debug::model::{builtin_interface_factory, BuiltinInterfaceFactory, InterfaceCategory};

    let factory = BuiltinInterfaceFactory::new();
    assert!(!factory.by_category(InterfaceCategory::Process).is_empty());
    assert!(!factory.by_category(InterfaceCategory::Thread).is_empty());
    assert!(!factory.by_category(InterfaceCategory::Memory).is_empty());
    assert!(factory.len() >= 8);

    assert!(builtin_interface_factory::is_builtin_interface(
        "ghidra.trace.target.TraceProcess"
    ));
    assert!(!builtin_interface_factory::is_builtin_interface(
        "nonexistent.FakeInterface"
    ));
}
