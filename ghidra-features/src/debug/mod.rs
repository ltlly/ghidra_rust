//! Ghidra Debug Framework -- Rust port.
//!
//! This module provides the core debugger infrastructure ported from Ghidra's
//! `ghidra.debug` and `ghidra.trace.model` Java packages. It includes:
//!
//! - **Core types**: [`Lifespan`], [`AddressSnap`], [`TraceSpan`], [`TraceExecutionState`]
//! - **Trace**: [`Trace`] -- the main domain object coordinating all managers
//! - **Trace model**: [`TraceSnapshot`], [`TraceSchedule`], [`TraceAddressSnapRange`]
//! - **Thread model**: [`TraceThread`], [`TraceProcess`], [`TraceThreadManager`]
//! - **Breakpoint model**: [`TraceBreakpointKind`], [`BreakpointSpec`], [`BreakpointLocation`], [`BreakpointManager`]
//! - **Memory model**: [`TraceMemoryState`], [`TraceMemoryRegion`], [`TraceMemoryBlock`], [`TraceMemoryManager`]
//! - **Module model**: [`TraceModule`], [`TraceSection`], [`TraceModuleManager`]
//! - **Listing model**: [`TraceCodeUnit`], [`TraceCodeManager`], [`TraceCodeSpace`], [`CommentType`]
//! - **Symbol model**: [`TraceSymbol`], [`TraceSymbolManager`], [`TraceReference`], [`TraceEquate`]
//! - **Stack model**: [`TraceStack`], [`TraceStackFrame`], [`TraceStackManager`]
//! - **Bookmark model**: [`TraceBookmark`], [`TraceBookmarkType`], [`TraceBookmarkManager`]
//! - **Static mappings**: [`TraceStaticMapping`], [`TraceStaticMappingManager`]
//! - **Property maps**: [`TracePropertyMap`], [`TraceAddressPropertyManager`]
//! - **Target objects**: [`TraceObject`], [`TraceObjectSchema`], [`SchemaContext`], [`KeyPath`]
//! - **Change tracking**: [`TraceChangeSet`]
//! - **Target API**: [`Target`] trait, [`ActionName`], [`ControlMode`]
//! - **Time model**: [`TraceSchedule`], [`TraceSnapshot`], [`ScheduleForm`]
//! - **RMI**: [`TraceRmiConnection`] trait (via [`Target`])

pub mod action_name;
pub mod bookmark;
pub mod breakpoint;
pub mod change_set;
pub mod control_mode;
pub mod core_types;
pub mod db_viewer;
pub mod debug_plugin;
pub mod debug_service;
pub mod listing;
pub mod memory;
pub mod modules;
pub mod property;
pub mod stack;
pub mod static_mapping;
pub mod symbol;
pub mod target;
pub mod thread;
pub mod time;
pub mod trace;
pub mod trace_object;

// Re-export core types
pub use action_name::ActionName;
pub use bookmark::{TraceBookmark, TraceBookmarkManager, TraceBookmarkType};
pub use breakpoint::{BreakpointKindSet, BreakpointLocation, BreakpointManager, BreakpointSpec, TraceBreakpointKind};
pub use change_set::TraceChangeSet;
pub use control_mode::ControlMode;
pub use core_types::{AddressSnap, Lifespan, TraceAddressSnapRange, TraceExecutionState, TraceSpan, SNAP_MAX, SNAP_MIN};
pub use db_viewer::{DatabaseHandle, DatabaseKind, DatabaseRecord, DbTable, DbViewer, DbViewerState, TableStatistics, TableStatisticsCache};
pub use debug_plugin::{
    DebugPluginAction, DebugPluginActionRegistry, DebugPluginConfig, DebugPluginDependency,
    DebugPluginEvent, DebugPluginLoadResult, DebugPluginLoader, DebugPluginMetrics,
    DebugPluginPackage, DebugPluginPriority, DebugPluginRegistration, DebugPluginRegistry,
    DebugPluginSession, DebugPluginSessionState, DebugPluginState, DebugPluginStatus,
    DebugPluginToolAdapter, DebugPluginUiState, MenuEntry, ToolbarEntry, standard_plugins,
};
pub use debug_service::{
    AutoMapMode, AutoMappingEntry, AutoMappingProposal, BreakpointInfo, BreakpointKind,
    ConsoleEntry, ConsoleLevel, DebugAutoMappingService, DebugBreakpointService,
    DebugConsoleService, DebugControlService, DebugCoordinates, DebugEmulationService,
    DebugListingService, DebugMappingService, DebugMemoryService, DebugModelService,
    DebugPlatformService, DebugProcessService, DebugRegisterService, DebugServiceContainer,
    DebugServiceError, DebugServiceResult, DebugSnapService, DebugSourceService,
    DebugStackService, DebugTargetService, DebugTraceManagerService, DebugVariableService,
    DebugWatchesService, EmulationResult, ExecutionState, MemoryRegionInfo, ModelSchema,
    PlatformOffer, PlatformOpinion, ProcessInfo, RegisterInfo, SnapInfo, SourceLocation,
    StackFrameInfo, StaticMappingEntry, ThreadInfo, VariableInfo, VariableStorage,
    WatchExpression, WatchFormat,
};
pub use listing::{CodeUnitType, CommentType, TraceCodeManager, TraceCodeSpace, TraceCodeUnit, TraceComment};
pub use memory::{TraceMemoryBlock, TraceMemoryFlag, TraceMemoryManager, TraceMemoryRegion, TraceMemoryState};
pub use modules::{TraceModule, TraceModuleManager, TraceSection};
pub use property::{TraceAddressPropertyManager, TracePropertyMap};
pub use stack::{TraceStack, TraceStackFrame, TraceStackManager};
pub use static_mapping::{TraceStaticMapping, TraceStaticMappingManager};
pub use symbol::{ReferenceType, TraceEquate, TraceReference, TraceSymbol, TraceSymbolKind, TraceSymbolManager};
pub use target::{ActionEntry, ActionResult, ObjectArgumentPolicy, Target, TargetError};
pub use thread::{TraceProcess, TraceThread, TraceThreadManager};
pub use time::{PatchStep, ScheduleForm, TraceSchedule, TraceSnapshot, TraceTimeManager};
pub use trace::{Trace, TraceLanguageInfo};
pub use trace_object::{AttributeSchemaDesc, KeyPath, PathFilter, SchemaContext, TraceObject, TraceObjectManager, TraceObjectSchema, TraceObjectValue};
