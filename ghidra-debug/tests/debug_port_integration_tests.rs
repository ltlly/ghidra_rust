//! Comprehensive integration tests for the ghidra-debug crate.
//!
//! Tests the key modules ported from Ghidra's three Debug source directories:
//! - Debugger-api
//! - Framework-TraceModeling
//! - Debugger

use ghidra_debug::api::action_name::ActionName;
use ghidra_debug::api::val_str::ValStr;
use ghidra_debug::api::watch::WatchRow;
use ghidra_debug::model::breakpoint::TraceBreakpointKind;
use ghidra_debug::model::changeset::ChangeType;
use ghidra_debug::model::execution_state::TraceExecutionState;
use ghidra_debug::model::lifespan::Lifespan;
use ghidra_debug::model::symbol::TraceSymbolKind;
use ghidra_debug::model::time::TraceSnapshot;
use ghidra_debug::model::thread::TraceThread;
use ghidra_debug::plugin::gui_action_contexts::{
    BreakpointLocationEntry, BreakpointLocationsActionContext,
    CallTreeActionNode, CallTreeActionNodeKind,
    DebuggerListingActionContext, DebuggerModuleActionContext,
    DebuggerProviderModel, DebuggerSnapActionContext,
    DebuggerWatchActionContext, InvokeActionEntry,
    LogicalBreakpointEntry, LogicalBreakpointsActionContext,
    ModuleActionEntry, SaveBehavior, RegisterActionEntry,
    WatchActionEntry, TraceCallTreeActionContext,
};
use ghidra_debug::plugin::gui_search_region::{
    DefaultEmulatorFactory, SearchRegion, SearchRegionFilter,
    ALL_SEARCH_REGION_FILTERS, create_search_regions,
};
use ghidra_debug::plugin::gui_sleigh_dialog::{
    PlaceBreakpointDialogResult, SleighInputConfig, SleighInputResult, SleighInputType,
};
use ghidra_debug::plugin::debugger_resources::{ActionGroup, DebuggerIcon};
use ghidra_debug::services::emulation_extras::{EmulationMode, EmulatorOutOfMemoryException};
use ghidra_debug::util::coordinates::DebuggerCoordinates;

// ── Test: API Module Types ───────────────────────────────────────────

#[test]
fn test_action_names() {
    let actions = vec![
        ActionName::StepInto,
        ActionName::StepOver,
        ActionName::StepOut,
        ActionName::Continue,
        ActionName::Kill,
        ActionName::Disconnect,
    ];
    assert_eq!(actions.len(), 6);
    for a in &actions {
        assert!(!a.to_string().is_empty());
    }
}

#[test]
fn test_val_str() {
    let vs = ValStr::from_value(42u64);
    assert_eq!(vs.val, Some(42));
    assert_eq!(vs.str, "42");

    let vs_none: ValStr<u64> = ValStr::from_string("unknown");
    assert!(vs_none.val.is_none());
    assert_eq!(vs_none.str, "unknown");
}

#[test]
fn test_watch_row() {
    let row = WatchRow::new("RAX");
    assert_eq!(row.expression, "RAX");
    assert!(row.value.is_none());
    assert!(!row.expanded);
}

// ── Test: Model Module Types ─────────────────────────────────────────

#[test]
fn test_lifespan() {
    let lifespan = Lifespan::span(5, 10);
    assert!(lifespan.contains(7));
    assert!(!lifespan.contains(3));
    assert!(!lifespan.contains(11));
}

#[test]
fn test_trace_snapshot() {
    let snap = TraceSnapshot::new(0);
    assert_eq!(snap.key, 0);
}

#[test]
fn test_trace_thread() {
    let thread = TraceThread::new(1, "Threads[0]", "main", 0);
    assert_eq!(thread.key, 1);
    assert_eq!(thread.name, "main");
}

#[test]
fn test_breakpoint_kind_variants() {
    let kinds = vec![
        TraceBreakpointKind::SwExecute,
        TraceBreakpointKind::HwExecute,
        TraceBreakpointKind::Read,
        TraceBreakpointKind::Write,
    ];
    assert_eq!(kinds.len(), 4);
    assert_eq!(TraceBreakpointKind::SwExecute.encoding_char(), 'x');
    assert_eq!(TraceBreakpointKind::HwExecute.encoding_char(), 'X');
    assert_eq!(TraceBreakpointKind::Read.encoding_char(), 'R');
    assert_eq!(TraceBreakpointKind::Write.encoding_char(), 'W');
}

#[test]
fn test_trace_execution_state() {
    let states = vec![
        TraceExecutionState::Stopped,
        TraceExecutionState::Running,
        TraceExecutionState::Terminated,
    ];
    assert_eq!(states.len(), 3);
}

#[test]
fn test_change_type_variants() {
    let types = vec![
        ChangeType::Added,
        ChangeType::Removed,
        ChangeType::Modified,
    ];
    assert_eq!(types.len(), 3);
}

#[test]
fn test_trace_symbol_kind() {
    let kinds = vec![
        TraceSymbolKind::Label,
        TraceSymbolKind::Function,
        TraceSymbolKind::Namespace,
        TraceSymbolKind::Class,
    ];
    assert_eq!(kinds.len(), 4);
}

// ── Test: Plugin Module Types ────────────────────────────────────────

#[test]
fn test_debugger_provider_model() {
    let model = DebuggerProviderModel::new("Breakpoints")
        .with_window_group("debugger")
        .with_multiple();
    assert_eq!(model.title, "Breakpoints");
    assert!(model.supports_multiple);
}

#[test]
fn test_snap_action_context() {
    let coords = DebuggerCoordinates::default();
    let ctx = DebuggerSnapActionContext::new(coords, 100);
    assert_eq!(ctx.snap, 100);
    assert!(!ctx.scratch);
}

#[test]
fn test_listing_action_context() {
    let coords = DebuggerCoordinates::default();
    let ctx = DebuggerListingActionContext::new(coords)
        .with_address(0x401000)
        .with_space("ram");
    assert_eq!(ctx.address, Some(0x401000));
    assert_eq!(ctx.space_name.as_deref(), Some("ram"));
}

#[test]
fn test_module_action_context() {
    let coords = DebuggerCoordinates::default();
    let modules = vec![
        ModuleActionEntry {
            name: "libc.so".to_string(),
            base: 0x7f0000,
            length: 0x200000,
            mapped_program: Some("/usr/lib/libc.so".to_string()),
            mapping: None,
        },
        ModuleActionEntry {
            name: "main".to_string(),
            base: 0x401000,
            length: 0x1000,
            mapped_program: None,
            mapping: None,
        },
    ];
    let ctx = DebuggerModuleActionContext {
        coordinates: coords,
        modules,
        has_proposals: true,
    };
    assert_eq!(ctx.modules.len(), 2);
    assert_eq!(ctx.modules[0].name, "libc.so");
}

#[test]
fn test_watch_action_context() {
    let coords = DebuggerCoordinates::default();
    let watches = vec![
        WatchActionEntry {
            expression: "RAX".to_string(),
            value: Some(vec![0x42; 8]),
            error: None,
            editable: true,
        },
    ];
    let ctx = DebuggerWatchActionContext {
        coordinates: coords,
        watches,
        any_errors: false,
    };
    assert!(!ctx.any_errors);
    assert!(ctx.watches[0].value.is_some());
}

#[test]
fn test_call_tree_action() {
    let coords = DebuggerCoordinates::default();
    let nodes = vec![
        CallTreeActionNode {
            function_name: "main".to_string(),
            call_address: 0x401000,
            return_address: Some(0x401050),
            kind: CallTreeActionNodeKind::Call,
            depth: 0,
        },
    ];
    let ctx = TraceCallTreeActionContext {
        coordinates: coords,
        nodes,
    };
    assert_eq!(ctx.nodes[0].kind, CallTreeActionNodeKind::Call);
    assert_eq!(ctx.nodes[0].depth, 0);
}

#[test]
fn test_invoke_action_entry() {
    let entry = InvokeActionEntry {
        action: ActionName::StepInto,
        display_name: "Step Into".to_string(),
        description: "Step into the instruction".to_string(),
        enabled: true,
        shortcut: Some("F7".to_string()),
    };
    assert_eq!(entry.action, ActionName::StepInto);
    assert!(entry.enabled);
}

#[test]
fn test_save_behavior_default() {
    assert_eq!(SaveBehavior::default(), SaveBehavior::NotApplicable);
    assert_ne!(SaveBehavior::SaveAll, SaveBehavior::SaveCurrent);
}

#[test]
fn test_breakpoint_location_context() {
    let coords = DebuggerCoordinates::default();
    let locations = vec![
        BreakpointLocationEntry {
            address: 0x401000,
            space_name: "ram".to_string(),
            length: 1,
            enabled: true,
            kinds: vec![TraceBreakpointKind::SwExecute],
            expression: None,
        },
    ];
    let ctx = BreakpointLocationsActionContext {
        coordinates: coords,
        locations,
        all_enabled: true,
        has_pending: false,
    };
    assert!(ctx.all_enabled);
    assert!(!ctx.has_pending);
}

#[test]
fn test_logical_breakpoint_context() {
    let coords = DebuggerCoordinates::default();
    let breakpoints = vec![
        LogicalBreakpointEntry {
            id: 1,
            address: Some(0x401000),
            expression: None,
            enabled: true,
            effective: true,
            trace_breakpoint_count: 1,
            emu_breakpoint_count: 0,
        },
    ];
    let ctx = LogicalBreakpointsActionContext {
        coordinates: coords,
        breakpoints,
        all_enabled: true,
        any_effective: true,
    };
    assert!(ctx.all_enabled);
    assert!(ctx.any_effective);
}

#[test]
fn test_register_action_entry() {
    let entry = RegisterActionEntry {
        name: "RAX".to_string(),
        value: Some(vec![0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00]),
        changed: true,
        editable: true,
    };
    assert!(entry.changed);
    assert_eq!(entry.value.as_ref().unwrap().len(), 8);
}

// ── Test: Search Region ──────────────────────────────────────────────

#[test]
fn test_search_region_filter_all_variants() {
    let filters = ALL_SEARCH_REGION_FILTERS;
    assert_eq!(filters.len(), 4);
    for &f in filters {
        assert!(!f.to_string().is_empty());
        assert!(!f.description().is_empty());
    }
}

#[test]
fn test_search_region_filter_matches() {
    assert!(SearchRegionFilter::FullSpace.matches(false, false, false));
    assert!(SearchRegionFilter::Readable.matches(true, false, false));
    assert!(!SearchRegionFilter::Readable.matches(false, true, false));
    assert!(SearchRegionFilter::Writable.matches(false, true, false));
    assert!(SearchRegionFilter::Executable.matches(false, false, true));
}

#[test]
fn test_search_region_with_space() {
    let region = SearchRegion::new(SearchRegionFilter::Executable)
        .with_space("ram");
    assert_eq!(region.name(), "Executable Addresses (ram)");
}

#[test]
fn test_create_search_regions_multiple_spaces() {
    let spaces = vec!["ram".to_string(), "register".to_string(), "stack".to_string()];
    let regions = create_search_regions(&spaces);
    assert_eq!(regions.len(), 16);
}

// ── Test: Sleigh Dialog ──────────────────────────────────────────────

#[test]
fn test_sleigh_input_types() {
    assert_eq!(SleighInputType::BreakpointExpression.to_string(), "Breakpoint Expression");
    assert_eq!(SleighInputType::default(), SleighInputType::BreakpointExpression);
}

#[test]
fn test_place_breakpoint_software() {
    let result = PlaceBreakpointDialogResult::software("0x401000");
    assert!(result.software);
    assert!(!result.hardware);
    assert_eq!(result.kind_flags(), 0x01);
}

#[test]
fn test_place_breakpoint_with_condition() {
    let result = PlaceBreakpointDialogResult::hardware("RIP")
        .with_size(8)
        .with_condition("RAX == 0x42");
    assert!(result.hardware);
    assert_eq!(result.size, 8);
    assert_eq!(result.condition.as_deref(), Some("RAX == 0x42"));
}

#[test]
fn test_sleigh_input_result_validation() {
    let result = SleighInputResult::new("RAX == 0x42", SleighInputType::SemanticCondition)
        .with_validated();
    assert!(result.validated);
    assert!(result.validation_error.is_none());
}

#[test]
fn test_sleigh_input_config() {
    let config = SleighInputConfig::breakpoint_expression("Add Breakpoint")
        .with_default("0x401000");
    assert_eq!(config.title, "Add Breakpoint");
    assert_eq!(config.default_value.as_deref(), Some("0x401000"));
}

// ── Test: Emulation Service ──────────────────────────────────────────

#[test]
fn test_emulation_mode() {
    let modes = [
        EmulationMode::SingleInstruction,
        EmulationMode::SingleStep,
        EmulationMode::RunUntilBreak,
        EmulationMode::RunUntilAddress,
        EmulationMode::FixedSteps,
    ];
    assert_eq!(EmulationMode::default(), EmulationMode::SingleStep);
    for mode in &modes {
        assert!(!mode.to_string().is_empty());
    }
}

#[test]
fn test_emulator_out_of_memory() {
    let err = EmulatorOutOfMemoryException::new("Cannot allocate stack");
    assert_eq!(err.message, "Cannot allocate stack");
    assert!(err.requested_bytes.is_none());

    let err = err.with_memory_info(0x4000, 0x1000);
    assert_eq!(err.requested_bytes, Some(0x4000));
    assert_eq!(err.available_bytes, Some(0x1000));
}

// ── Test: Plugin Resources ───────────────────────────────────────────

#[test]
fn test_debugger_icons() {
    let icons = vec![
        DebuggerIcon::Resume,
        DebuggerIcon::StepInto,
        DebuggerIcon::StepOver,
        DebuggerIcon::StepOut,
        DebuggerIcon::Suspend,
        DebuggerIcon::Disconnect,
    ];
    assert_eq!(icons.len(), 6);
}

#[test]
fn test_action_groups() {
    let groups = vec![
        ActionGroup::Connection,
        ActionGroup::Control,
        ActionGroup::Breakpoints,
        ActionGroup::Navigation,
    ];
    assert_eq!(groups.len(), 4);
}

// ── Test: Util Module Types ──────────────────────────────────────────

#[test]
fn test_debugger_coordinates() {
    let coords = DebuggerCoordinates::default();
    assert_eq!(coords.snap, 0);
}

#[test]
fn test_debugger_coordinates_with_snap() {
    let coords = DebuggerCoordinates::default().with_snap(42);
    assert_eq!(coords.snap, 42);
}

// ── Test: Default Emulator Factory ───────────────────────────────────

#[test]
fn test_default_emulator_factory_title() {
    let factory = DefaultEmulatorFactory::default();
    assert_eq!(factory.title, "Default Concrete P-code Emulator");
}

// ── Test: Serialization Roundtrips ───────────────────────────────────

#[test]
fn test_serialization_roundtrip_search_region() {
    let region = SearchRegion::new(SearchRegionFilter::Writable).with_space("stack");
    let json = serde_json::to_string(&region).unwrap();
    let deserialized: SearchRegion = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.filter, SearchRegionFilter::Writable);
    assert_eq!(deserialized.space_name.as_deref(), Some("stack"));
}

#[test]
fn test_serialization_roundtrip_action_contexts() {
    let ctx = DebuggerMemoryBytesActionContext {
        coordinates: DebuggerCoordinates::default(),
        address: 0x401000,
        selection: Some((0x401000, 0x4010ff)),
        known: true,
    };
    let json = serde_json::to_string(&ctx).unwrap();
    let deserialized: DebuggerMemoryBytesActionContext = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.address, 0x401000);
}

use ghidra_debug::plugin::gui_action_contexts::DebuggerMemoryBytesActionContext;
