//! Debug API types ported from Ghidra's Debugger-api.
//!
//! This module provides the high-level abstractions for interacting with
//! debug targets, including action names, control modes, breakpoints,
//! the Target trait, debugger coordinates, watch expressions, the
//! flat (scripting) API, and platform descriptions.

pub mod action;
pub mod action_ext;
pub mod action_name;
pub mod address_translator;
pub mod breakpoint;
pub mod control_mode;
pub mod coordinates_enhanced;
pub mod emulation;
pub mod emulator_factory;
pub mod flat_api;
pub mod flat_api_rmi;
pub mod launch_parameter;
pub mod launch_result;
pub mod listing;
pub mod location_tracker;
pub mod model_context;
pub mod modules;
pub mod monitor_receiver;
pub mod pcode_debugger_access;
pub mod platform;
pub mod platform_mapper;
pub mod progress;
pub mod remote_async_result;
pub mod rmi_types;
pub mod static_mapping;
pub mod target;
pub mod target_enhanced;
pub mod trace_connection_impl;
pub mod trace_rmi_acceptor;
pub mod val_str;
pub mod trace_rmi_connection;
pub mod tracermi_listener;
pub mod tracemgr;
pub mod tracermi;
pub mod watch;
pub mod model;
pub mod target_listener;
pub mod trace_address_snap_range;
pub mod tracermi_connection;
pub mod platform_mapper_api;

pub use action::{
    ActionSource, AutoMapSpec, AutoMapSpecRegistry, AutoReadMemorySpec, AutoReadMemorySpecRegistry,
    GoToInput, InstanceUtils, LocationTracker, LocationTrackingSpec, TrackingEvent,
};
pub use action_name::ActionName;
pub use address_translator::{AddressTranslator, StaticMappingEntry, TranslatedAddress};
pub use breakpoint::{
    BreakpointConsistency, BreakpointMode, BreakpointState, LogicalBreakpoint,
};
pub use control_mode::ControlMode;
pub use flat_api::{CommonBreakpointSet, FlatApiError, FlatApiResult, FlatDebuggerApi, ProgramLocation};
pub use modules::{
    DebuggerAddressTranslator, DebuggerMissingModuleActionContext,
    DebuggerMissingProgramActionContext, DebuggerOpenProgramActionContext,
    MapEntry, MappedAddressRange, MapProposal, MappingChangeKind, MappingChangeEvent,
    ModuleMapProposal, RegionMapProposal, SectionMapProposal,
};
pub use pcode_debugger_access::{
    AccessScope, PcodeDebuggerAccess, PcodeMemoryAccess, PcodeRegistersAccess,
    PcodeTraceCoordinates,
};
pub use platform::{DebuggerConnection, PlatformDescription, ProcessDescriptor};
pub use target::{ActionEntry, ActionResult, ObjectArgumentPolicy, Target};
pub use tracemgr::DebuggerCoordinates;
pub use trace_rmi_connection::{
    RemoteMethod, RemoteMethodRegistry, RemoteParameter, TerminalSession, TraceRmiConnection,
    TraceRmiError, TraceRmiLaunchOffer,
};
pub use watch::{ValStr, ValueFormat, WatchRow};
pub use tracermi_listener::{
    CompositeTraceRmiServiceListener, ConnectMode, RecordingServiceListener,
    TraceRmiServiceEvent, TraceRmiServiceListener,
};

// Re-exports from new tracermi_connection module
pub use tracermi_connection::{
    ConnectionStatus, LaunchParameter, LaunchParameterType, RemoteMethodResult,
    TraceRmiConnectionInfo, TraceRmiTarget,
};

// Re-exports from new platform_mapper_api module
pub use platform_mapper_api::{
    AddressSpaceDesc, DisassemblyResult, Endianness, FlowType, PlatformMapperConfig,
    PlatformOffer, PlatformOpinionConfig, RegisterMappingEntry,
};

// Factory modules from remaining Debugger-api port
pub use action::factories::{
    AutoReadMemorySpecConfig, AutoReadMemorySpecFactory,
    LocationTrackingSpecConfig, LocationTrackingSpecFactory,
};
