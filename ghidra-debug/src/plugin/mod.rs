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

pub mod auto_map;
pub mod breakpoint_actions;
pub mod disassemble;
pub mod event;
pub mod export;
pub mod gui;
pub mod gui_breakpoint;
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
pub mod gui_timeoverview;
pub mod gui_trace;
pub mod gui_tracecalltree;
pub mod gui_watch;
pub mod location_tracking;
pub mod mapping;
pub mod platform_arm;
pub mod platform_dbgeng;
pub mod platform_frida;
pub mod platform_gdb;
pub mod platform_jdi;
pub mod platform_lldb;
pub mod platform_opinion;
pub mod stack;
pub mod taint;
pub mod utils;

pub use auto_map::*;
pub use breakpoint_actions::*;
pub use disassemble::*;
pub use event::*;
pub use export::*;
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
pub use gui_memview::{MemviewBoxType, MemviewMap, MemviewModel, MemoryBox};
pub use gui_pcode::{PcodeRow, PcodeRowKind, PcodeStepperModel, PcodeVarnode};
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
    VariableValueHoverConfig, VariableValueRow, VariableValueTableModel, VariableValueUtils,
};
pub use gui_thread::{ThreadColumn, ThreadRow, ThreadTableModel};
pub use gui_time::{SnapshotRow, SnapshotTableModel};
pub use gui_timeoverview::{
    BreakpointOverviewType, TimeOverviewColorEntry, TimeOverviewColorService, TimeType,
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
pub use stack::*;
pub use taint::*;
pub use utils::*;
