//! Debug API types ported from Ghidra's Debugger-api.
//!
//! This module provides the high-level abstractions for interacting with
//! debug targets, including action names, control modes, breakpoints,
//! the Target trait, debugger coordinates, watch expressions, the
//! flat (scripting) API, and platform descriptions.

pub mod action;
pub mod action_name;
pub mod address_translator;
pub mod breakpoint;
pub mod control_mode;
pub mod emulation;
pub mod emulator_factory;
pub mod flat_api;
pub mod flat_api_rmi;
pub mod launch_parameter;
pub mod listing;
pub mod location_tracker;
pub mod model_context;
pub mod modules;
pub mod monitor_receiver;
pub mod platform;
pub mod progress;
pub mod remote_async_result;
pub mod rmi_types;
pub mod target;
pub mod tracemgr;
pub mod tracermi;
pub mod watch;

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
pub use modules::{MapEntry, MappedAddressRange, MapProposal, MappingChangeKind, MappingChangeEvent, ModuleMapProposal, SectionMapProposal};
pub use platform::{DebuggerConnection, PlatformDescription, ProcessDescriptor};
pub use target::{ActionEntry, ActionResult, ObjectArgumentPolicy, Target};
pub use tracemgr::DebuggerCoordinates;
pub use watch::{ValStr, ValueFormat, WatchRow};
