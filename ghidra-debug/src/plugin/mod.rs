//! Debugger plugin framework and events.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug` package in the Debugger module.
//! Provides the event types and plugin infrastructure for the debugger UI.
//!
//! Sub-modules:
//! - `event`: Plugin event types.
//! - `disassemble`: Trace disassembly actions.
//! - `export`: Trace view exporters (ASCII, binary, HTML, Intel HEX, XML).
//! - `taint`: Taint analysis types for emulated execution.
//! - `mapping`: Static mapping plugin types.
//! - `gui`: GUI provider data model types (breakpoints, registers, threads, stack frames).
//! - `gui_colors`: Color management for the debugger GUI.
//! - `gui_diff`: Trace diff data model types.
//! - `gui_listing`: Listing integration data model types.
//! - `gui_memory`: Memory regions panel data model types.
//! - `gui_modules`: Module/section panel data model types.
//! - `gui_register`: Register panel data model types.
//! - `gui_thread`: Thread panel data model types.
//! - `gui_time`: Snapshot/time panel data model types.
//! - `gui_timeoverview`: Time overview panel data model types.
//! - `gui_tracecalltree`: Call tree panel data model types.
//! - `gui_watch`: Watch panel data model types.
//! - `stack`: Stack analysis and call stack types.
//! - `utils`: Memory range, register value, and alignment utilities.
//! - `platform_opinion`: Platform opinion framework for debugger backends.
//! - `platform_gdb`: GDB platform opinion provider.
//! - `platform_lldb`: LLDB platform opinion provider.
//! - `platform_frida`: Frida platform opinion provider.
//! - `platform_jdi`: JDI (Java) platform opinion provider.
//! - `breakpoint_actions`: Breakpoint action items for the debugger plugin.
//! - `location_tracking`: Location tracking specifications (PC, SP, etc.).
//! - `auto_map`: Auto-mapping specifications for dynamic-to-static mapping.

pub mod abstract_plugin;
pub mod action_specs;
pub mod auto_map;
pub mod control_actions;
pub mod debugger_go_to;
pub mod debugger_resources;
pub mod debugger_regions;
pub mod disconnect_task;
pub mod disassembly_actions_ext;
pub mod gui_copying;
pub mod gui_model_columns_ext;
pub mod gui_stack_frame_model;
pub mod pcode_stepper;
pub mod save_settings;
pub mod service_plugins;
pub mod stack_unwind;
pub mod variable_value_hover;
pub mod background_utils;
pub mod breakpoint_actions;
pub mod disassemble;
pub mod disassembly_actions;
pub mod disassembly_inject;
pub mod event;
pub mod events_extra;
pub mod experiments;
pub mod export;
pub mod gui;
pub mod gui_breakpoint;
pub mod gui_stack_vars_ext;
pub mod gui_timeoverview_actions;
pub mod gui_model;
pub mod gui_model_columns;
pub mod gui_program_location;
pub mod gui_breakpoint_timeline;
pub mod gui_colors;
pub mod gui_console;
pub mod gui_control;
pub mod gui_copy;
pub mod gui_diff;
pub mod gui_internal;
pub mod gui_listing;
pub mod gui_memory;
pub mod gui_memview;
pub mod gui_modules;
pub mod gui_pcode;
pub mod gui_platform;
pub mod gui_register;
pub mod gui_stack_vars;
pub mod gui_thread;
pub mod gui_time;
pub mod gui_timetype;
pub mod gui_timeoverview;
pub mod gui_trace;
pub mod gui_tracecalltree;
pub mod gui_watch;
pub mod location_tracking;
pub mod managed_domain_object;
pub mod mapping;
pub mod platform_arm;
pub mod transaction_coalescer;
pub mod platform_dbgeng;
pub mod platform_frida;
pub mod platform_gdb;
pub mod platform_jdi;
pub mod platform_lldb;
pub mod platform_opinion;
pub mod platform_override;
pub mod program_emulation;
pub mod stack;
pub mod taint;
pub mod trace_exporters;
pub mod trace_export_formats;
pub mod trace_plugin_events;
pub mod utils;
pub mod utils_extras;

// New modules from Debugger service/plugin port
pub mod service_breakpoint_impl;
pub mod service_control_ext;
pub mod service_modules_ext;
pub mod service_platform_ext;
pub mod service_tracemgr_ext;
pub mod gui_calltree_ext;
pub mod gui_memview_ext;
pub mod gui_pcode_ext;

// Listener data models ported from Debugger
pub mod gui_memview_listener;
pub mod gui_timeoverview_listener;

// Platform mapper implementations
pub mod platform_mapper_impls;
pub mod mapped_memory_visitor;

pub use abstract_plugin::{
    DebuggerPluginPackage, ExtensionPointId, PluginLifecycleEvent, PluginPhase,
};
pub use auto_map::*;
pub use breakpoint_actions::*;
pub use debugger_go_to::{AddressKind, GoToResult, GoToTarget, SelectionRange};
pub use debugger_regions::{
    DebuggerRegion, DebuggerRegionsModel, RegionPermissions, SearchRegionQuery, SearchRegionScope,
};
pub use debugger_resources::{ActionGroup, DebuggerIcon, ToolActionCategory};
pub use disconnect_task::{DisconnectMode, DisconnectResult, DisconnectTask, DisconnectTaskConfig};
pub use pcode_stepper::{
    PcodeStepperEntry, PcodeStepperExecutionModel, PcodeStepperOpType, StepperState,
};
pub use save_settings::{SavedSettings, SettingValue};
pub use variable_value_hover::{
    HoverConfig, ValueFormat, VariableValueEntry, VariableValueHoverModel,
};
pub use disassemble::*;
pub use event::{
    ActivationCause, DebuggerPlatformEvent, DebuggerPluginEvent,
    TraceActivatedEvent, TraceClosedEvent, TraceHighlightEvent,
    TraceInactiveCoordinatesEvent, TraceLocationEvent, TraceOpenedEvent,
    TraceSelectionEvent, TransactionCoalescer,
};
pub use export::*;
pub use experiments::*;
pub use gui::*;
pub use gui_breakpoint::{
    BreakpointActionContext, BreakpointDisplayState, BreakpointKindSet,
    BreakpointMarkerData, LogicalBreakpointActionContext,
    MakeBreakpointsEffectiveContext, SleighBreakpointInput,
};
pub use gui_breakpoint_timeline::{
    BreakpointHitEvent, BreakpointTimelineFilter, BreakpointTimelineModel, CachedTimelineIndex,
    TimelineColors, TimelineViewport,
};
pub use gui_colors::{DebugColor, DebugColorScheme};
pub use gui_console::{
    ConsoleAction, ConsoleColumn, ConsoleModel, ConsoleSortState, LogLevel, LogRow, LogRowActionContext,
    MonitorRow, MonitorRowActionContext, ProgressReceiver, SortDirection,
};
pub use gui_control::{ControlAction, ControlActionBuilder, ControlActionKind, ControlActionTarget, SnapshotNavigation};
pub use gui_copy::{CopyDirection, CopyEndpoint, CopyEntry, CopyPlan};
pub use gui_internal::{RStarTreeDiagnosticsModel, RStarTreeNode, RStarTreeStats};
pub use gui_memview::{MemviewBoxType, MemviewMap, MemviewModel, MemoryBox, MemviewZoomAction, MemviewServiceImpl};
pub use gui_model::{
    AttributeValue, DisplaysModified, ModelQuery, ModelValue, ModelValueEntry,
    ObjectModelRow, PathModelRow, TreeState, ValueDisplay,
};
pub use gui_model_columns::{
    ColumnDescriptor, ColumnKind, ColumnRenderConfig, EditableColumn, ModelColumn,
};
pub use gui_pcode::{
    PcodeRow, PcodeRowKind, PcodeStepperModel, PcodeVarnode, UniqueRefType, UniqueRow,
    UniqueTableModel,
};
pub use gui_program_location::{
    AutoReadMemorySpec, GoToAction, GoToContext, LocationTracker, ProgramLocationContext,
};
pub use gui_platform::{
    DisassemblyResult, Endianness, PlatformChangedEvent, PlatformDisplayInfo, PlatformMapperData,
    PlatformProviderModel, RegisterMappingEntry,
};
pub use gui_diff::{DiffKind, MemoryDiffEntry, RegisterDiffEntry, TraceDiffResult};
pub use gui_listing::{BlendedListingColorModel, DebuggerListingLocation};
pub use gui_memory::{CachedBytePage, MemoryRegionRow, MemoryRegionTableModel};
pub use gui_modules::{
    ModuleColumn, ModuleRow, ModuleTableModel, SectionRow, StaticMappingRow,
};
pub use gui_register::{
    AvailableRegisterRow, RegisterColumn, RegisterRow, RegisterTableModel,
};
pub use gui_stack_vars::{
    VariableRowKey, VariableValueHoverConfig, VariableValueRow, VariableValueRowKind,
    VariableValueRowSet, VariableValueTableModel, VariableValueUtils,
};
pub use gui_thread::{ThreadColumn, ThreadRow, ThreadTableModel};
pub use gui_time::{SnapshotRow, SnapshotTableModel};
pub use gui_timeoverview::{
    BreakpointOverviewType, BreakTypeLegendEntry, CellType, TimeOverviewColorEntry,
    TimeOverviewColorService, TimeSelectionRange, TimeType, TimeTypeLegendEntry,
};
pub use gui_trace::{
    TimeRadix, TraceTabActionContext, TraceTabEntry, TraceTabEvent, TraceTabPanelModel,
};
pub use gui_tracecalltree::{
    CallTreeNodeKind, TraceCallTreeLogContext, TraceCallTreeNode, TraceCallTreeModel,
};
pub use gui_watch::{DefaultWatchRow, SavedWatchSettings, WatchColumn, WatchFormat, WatchTableModel};
pub use location_tracking::*;
pub use mapping::*;
pub use platform_arm::{ArmDisassemblyInject, ArmPlatformOpinion, ARM_LANG_IDS, THUMB_BIT};
pub use platform_dbgeng::{
    DbgengMode, DbgengPlatformOpinion, DbgengX64DisassemblyInject, PeMachineType, PeModuleInfo,
    COMP_ID_WINDOWS, DBGENG_TOOL, LANG_ID_X86, LANG_ID_X86_64, LANG_ID_X86_64_32,
};
pub use platform_frida::*;
pub use platform_gdb::*;
pub use platform_jdi::*;
pub use platform_lldb::*;
pub use platform_opinion::*;
pub use platform_override::*;
pub use stack::*;
pub use taint::*;
pub use utils::*;

// Re-exports from new service/plugin modules
pub use service_breakpoint_impl::{
    BreakpointActionItem, BreakpointActionKind, BreakpointActionSet,
    LogicalBreakpointInternal, LoneLogicalBreakpoint, ProgramBreakpoint,
    TraceBreakpointEntry, TraceBreakpointSet, TrackedTooSoonException,
};
pub use service_control_ext::{
    ControlConnectionState, ControlMode, ControlServiceData, ControlTarget,
};
pub use service_modules_ext::{
    MapProposalEntry, MappingChangeKind, MappingEntry,
    InfoPerProgram, InfoPerTrace, StaticMappingContext, StaticMappingProposals,
};
pub use service_platform_ext::{
    PlatformOffer, PlatformOpinion, PlatformServiceData,
};
pub use service_tracemgr_ext::{
    SaveKind, SaveTaskManager, SaveTraceTask,
};
// Additional service plugin implementations
pub mod service_plugin_impls;
pub use service_plugin_impls::{
    BreakpointServicePluginData, ControlServiceMode, ControlServicePluginData,
    DebuggerServicePluginDataContainer, EmulationServicePluginData,
    PlatformServicePluginData, ServicePluginPhase, ServicePluginConfig,
    StaticMappingServicePluginData, TargetServicePluginData, TraceManagerServicePluginData,
};

pub use gui_calltree_ext::*;
pub use gui_pcode_ext::*;

// Re-exports from listener modules
pub use gui_memview_listener::{MemviewTraceEvent, MemviewTraceListener};
pub use gui_timeoverview_listener::{TimeOverviewEntry, TimeOverviewListener};

// Re-exports from action_specs module
pub use action_specs::{
    BasicAutoReadMemorySpec, ByModuleAutoMapSpec, ByRegionAutoMapSpec, BySectionAutoMapSpec,
    NoneAutoMapSpec, NoneAutoReadMemorySpec, NoneLocationTrackingSpec, OneToOneAutoMapSpec,
    PcByRegisterLocationTrackingSpec, PcByStackLocationTrackingSpec, PcLocationTrackingSpec,
    RegisterLocationTrackingSpec, SpLocationTrackingSpec, WatchLocationTrackingSpec,
    builtin_location_tracking_specs, register_builtin_auto_map_specs,
    register_builtin_auto_read_specs,
};

// New modules from remaining Debug module ports
pub mod trace_disassembly_ext;
pub mod trace_export_ext;
pub mod platform_mapper_ext;
pub mod stack_analysis_ext;
pub mod debugger_utils_ext;
pub mod platform_override_ext;
pub mod gui_model_ext;

// Dynamic-static synchronization
pub mod dynamic_static_sync;

// Remaining Debugger module ports (GUI control actions, concrete disassembly,
// panel data models, export background command, extended action specs)
pub mod gui_control_actions;
pub mod disassembly_actions_concrete;
pub mod gui_panel_models;
pub mod export_background_cmd;
pub mod gui_action_specs_ext;

pub use gui_control_actions::{
    ControlExecutionState as ControlExecState, DebuggerControlMode as DbgControlMode,
    SnapNavigationEntry,
};
pub use disassembly_actions_concrete::{
    AbstractTraceDisassembleAction, CurrentPlatformTracePatchInstructionAction,
    FixedPlatformTracePatchInstructionAction, PlatformMode,
};
pub use gui_panel_models::{
    CallTreeNode as GuiCallTreeNode, DebouncedTableModel,
    DebuggerCoordinates as GuiDebuggerCoordinates,
    DebuggerObjectActionContext as GuiObjectActionContext,
    FrameVariable as GuiFrameVariable, GuiColumnType as GuiColumnKind, GuiTableColumn,
    ListingActionContext as GuiListingActionContext,
    MemoryRegionEntry as GuiMemoryRegionEntry, ModuleEntry as GuiModuleEntry,
    MultiProviderSaveBehavior, ObjectValueRef as GuiObjectValueRef,
    ObjectsTableBasedPanelModel, QueryTablePanelModel,
    RegisterEntry as GuiRegisterEntry,
    SectionEntry as GuiSectionEntry, SnapshotEntry as GuiSnapshotEntry,
    StackFrameEntry as GuiStackFrameEntry, ThreadEntry as GuiThreadEntry,
    ThreadState as GuiThreadState, WatchEntry as GuiWatchEntry,
};
pub use export_background_cmd::{ExportTraceBackgroundCmd, TraceExportFormat};
pub use gui_action_specs_ext::{
    AutoReadMemorySpecResult, AutoReadMode, BasicAutoReadMemorySpecFactory,
    BasicLocationTrackingSpecFactory, DebuggerReadsMemoryTrait, DebuggerTrackLocationTrait,
    LocationTrackingSpecResult, LocationTrackingStrategy, WatchLocationTrackingSpecFactory,
};

// New modules ported from remaining Debugger GUI types
pub mod gui_action_contexts;
pub mod gui_sleigh_dialog;
pub mod gui_search_region;

pub use gui_action_contexts::{
    AvailableRegisterEntry, BreakpointLocationEntry, BreakpointLocationsActionContext,
    CallTreeActionNode, CallTreeActionNodeKind, DebuggerAvailableRegistersActionContext,
    DebuggerListingActionContext, DebuggerMemoryBytesActionContext, DebuggerModuleActionContext,
    DebuggerProviderModel, DebuggerRegisterActionContext, DebuggerRegionActionContext,
    DebuggerSectionActionContext, DebuggerSnapActionContext, DebuggerStaticMappingActionContext,
    DebuggerTraceFileActionContext, DebuggerWatchActionContext, InvokeActionEntry,
    LogicalBreakpointEntry, LogicalBreakpointsActionContext, ModuleActionEntry,
    SaveBehavior, RegionActionEntry, RegisterActionEntry,
    SectionActionEntry, StaticMappingActionEntry, TraceCallTreeActionContext, WatchActionEntry,
};
pub use gui_sleigh_dialog::{
    PlaceBreakpointDialogResult, SleighInputConfig, SleighInputResult, SleighInputType,
};
pub use gui_search_region::{
    DefaultEmulatorFactory, SearchRegion, SearchRegionFilter,
    ALL_SEARCH_REGION_FILTERS, create_search_regions,
};

// Remaining GUI data-model types from the final Debug port
pub mod gui_remaining;

// Debugger plugin event types from Framework-TraceModeling/Debugger
pub mod debugger_events;

// Trace diff plugin for snapshot comparison
pub mod trace_diff_plugin;
pub use trace_diff_plugin::{
    compare_bytes, DiffAddressSet, DiffRange, DiffSessionState,
    SnapshotDiffResult, TraceDiffPluginConfig,
};

// Extended action context types from Debugger-api / Debugger
pub mod gui_action_contexts_ext;
pub use gui_action_contexts_ext::DebuggerObjectPathActionContext;

pub mod platform_impl;
pub mod platform_opinion_framework;
pub mod mapping_context;
pub mod platform_connectors;
pub mod debugger_utils;

// New modules ported from remaining Debugger source files
pub mod target_actions;
pub mod trace_call_tree_types;
pub mod register_types;
pub mod memview_types;

pub use target_actions::{
    ActionEntry as TargetActionEntry, ActionTaskState, ControlExecutionState,
    ControlModeAction, ControlModeActionState, SnapshotNavState,
    TargetActionKind, TargetActionTask,
    disconnect_action_entry, interrupt_action_entry, kill_action_entry, resume_action_entry,
    snap_backward_action_entry, snap_forward_action_entry, step_into_action_entry,
    step_out_action_entry, step_over_action_entry,
};
pub use trace_call_tree_types::{
    CallTreeNodeData, TraceCallTreeCallNode as CallTreeNode, TraceCallTreeExternalNode as ExternalTreeNode,
    TraceCallTreeLogContext as CallTreeLogContext, TraceCallTreeModel as CallTreeModel,
    TraceCallTreeReturnNode as ReturnTreeNode,
    TraceCallTreeTailCallNode as TailCallTreeNode,
};
pub use register_types::{
    RegisterActionContext, RegisterDisplayFormat, RegisterTableModel as RegisterPanelModel,
    RegisterRow as RegisterPanelRow, AvailableRegisterRow as AvailableRegister,
};
pub use memview_types::{
    MemviewAddressFormat, MemviewColorScheme, MemviewMap as MemviewPanelMap,
    MemviewModel as MemviewPanelModel, MemviewServiceImpl as MemviewPanelService,
    MemviewPanelZoomAction, MemoryBox as MemviewMemoryBox, MemviewBoxType as MemviewBoxKind,
};
