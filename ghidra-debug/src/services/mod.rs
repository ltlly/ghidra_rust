//! Service interfaces for the debugger framework.
//!
//! Ported from Ghidra's debugger service interfaces in `ghidra.app.services`.
//! Each service trait defines an interface that plugin components can
//! implement and register.
//!
//! Implementation modules:
//! - `breakpoint_impl`: Breakpoint action items and logical breakpoint internals.
//! - `platform_impl`: Platform opinions, offers, and built-in connectors.
//! - `tracemgr_impl`: Trace manager service implementation.
//! - `control_impl`: Debugger control service implementation.
//! - `modules_impl`: Modules/mapping service implementation.
//! - `emulation_impl`: Emulation service implementation with p-code data access.
//! - `progress_impl`: Progress service implementation.
//! - `target_impl`: Target service implementation.
//! - `console_impl`: Console service implementation.

pub mod auto_map_impl;
pub mod breakpoint_impl;
pub mod console_extras;
pub mod console_impl;
pub mod control_impl;
pub mod debugger_service_impls;
pub mod emulation_extras;
pub mod emulation_impl;
pub mod emulation_utils;
pub mod listing_impl;
pub mod mapping_proposals;
pub mod mapping_utils;
pub mod modules_impl;
pub mod platform_impl;
pub mod progress_extras;
pub mod progress_impl;
pub mod save_trace_tasks;
pub mod service_interfaces;
pub mod service_trace_rmi_impl;
pub mod target_impl;
pub mod tracemgr_impl;
pub mod url_impl;
pub mod watches_impl;
pub mod program_indexer;
pub mod breakpoint_extras;
pub mod trace_data_viewport_impl;
pub mod sync_service;

// New modules from remaining Debug module ports
pub mod static_mapping_utils;
pub mod module_region_matcher;
pub mod map_background_commands;
pub mod progress_monitor_impl;
pub mod breakpoint_lifecycle_impl;

// Emulation data access and integration
pub mod emulation_data_access;
pub mod emulation_integration_ext;

pub use service_interfaces::{
    ActivationCause as ServiceActivationCause, ConsoleEntry, ConsoleLevel,
    DebuggerAutoMappingService as AutoMappingServiceExt,
    DebuggerConsoleService as ConsoleServiceExt,
    DebuggerEmulationService as EmulationServiceExt,
    DebuggerListingService as ListingServiceExt,
    DebuggerLogicalBreakpointService as LogicalBreakpointServiceExt,
    DebuggerPlatformService as PlatformServiceExt,
    DebuggerStaticMappingService as StaticMappingServiceExt,
    DebuggerTargetService as TargetServiceExt,
    DebuggerTraceManagerService as TraceManagerServiceExt,
    DebuggerWatchesService as WatchesServiceExt,
    EmulationDefiniteResult, EmulationRunResult,
    EmulatorStateListener, LaunchOffer, LaunchParameter, LogicalBreakpointsChangeListener,
    StateEditor as StateEditorExt, StaticMappingChangeListener, StaticMappingEntry,
    TargetPublicationListener, TraceRmiLauncherService, TraceRmiService as TraceRmiServiceExt,
};
// The comprehensive service_interfaces module provides extended versions of each
// service trait that match the full Java API surface. The simpler trait definitions
// below are retained for backward compatibility with existing code.

// Re-exports from emulation_utils module
pub use emulation_utils::{
    DefaultEmulatorFactory, DefaultPcodeDebuggerMemoryAccess, DefaultPcodeDebuggerRegistersAccess,
    EmulationMode, EmulatorOutOfMemoryException, ProgramEmulationUtils, BLOCK_NAME_STACK,
    EMULATION_STARTED_AT, EMU_CTX_XML,
};

// Re-exports from breakpoint extras module
pub use breakpoint_extras::{
    BreakpointActionEntry, BreakpointActionKind, BreakpointActionSet,
    BreakpointKindEntry, LoneLogicalBreakpoint, MappedLogicalBreakpoint,
    ProgramBreakpoint, TraceBreakpointMode, TrackedTooSoonException,
};

// Re-exports from trace data viewport module
pub use trace_data_viewport_impl::{
    SingleSnapViewport, TraceTimeViewport as ServiceTraceTimeViewport,
};

use crate::api::breakpoint::LogicalBreakpoint;
use crate::model::Lifespan;

/// Service for managing the lifecycle of open traces.
pub trait TraceManagerService {
    /// Get the currently active trace, if any.
    fn active_trace(&self) -> Option<&dyn TraceInfo>;

    /// Open a trace for viewing.
    fn open_trace(&mut self, trace_key: i64) -> Result<(), String>;

    /// Close a trace.
    fn close_trace(&mut self, trace_key: i64) -> Result<(), String>;

    /// Activate (bring to focus) a trace.
    fn activate_trace(&mut self, trace_key: i64) -> Result<(), String>;

    /// Get all open traces.
    fn open_traces(&self) -> Vec<&dyn TraceInfo>;
}

/// Minimal info about a trace for service communication.
pub trait TraceInfo {
    /// A unique key for this trace.
    fn key(&self) -> i64;

    /// The name of the trace.
    fn name(&self) -> &str;

    /// Whether the trace is currently active.
    fn is_active(&self) -> bool;
}

/// Service for managing static mappings between programs and traces.
pub trait StaticMappingService {
    /// Map a program address range to a trace address range.
    fn add_mapping(
        &mut self,
        program_url: &str,
        program_min: u64,
        program_max: u64,
        trace_min: u64,
        trace_max: u64,
        lifespan: Lifespan,
    ) -> Result<(), String>;

    /// Get the trace address for a program address.
    fn get_trace_address(&self, program_url: &str, program_addr: u64) -> Option<u64>;

    /// Get the program address for a trace address.
    fn get_program_address(&self, trace_addr: u64) -> Option<(String, u64)>;
}

/// Service for managing logical breakpoints.
pub trait LogicalBreakpointService {
    /// Get all logical breakpoints.
    fn breakpoints(&self) -> Vec<&LogicalBreakpoint>;

    /// Get a breakpoint at the given address.
    fn breakpoint_at(&self, offset: u64) -> Option<&LogicalBreakpoint>;

    /// Add a breakpoint.
    fn add_breakpoint(&mut self, bp: LogicalBreakpoint) -> Result<(), String>;

    /// Delete a breakpoint at the given address.
    fn delete_breakpoint(&mut self, offset: u64) -> Result<(), String>;

    /// Toggle a breakpoint enabled/disabled.
    fn toggle_breakpoint(&mut self, offset: u64, enabled: bool) -> Result<(), String>;
}

/// Service for managing emulation.
pub trait EmulationService {
    /// Start emulating from the current state.
    fn start_emulation(&mut self, trace_key: i64) -> Result<(), String>;

    /// Stop emulation.
    fn stop_emulation(&mut self, trace_key: i64) -> Result<(), String>;

    /// Whether emulation is active for the given trace.
    fn is_emulating(&self, trace_key: i64) -> bool;

    /// Step emulation by one step.
    fn step_emulation(&mut self, trace_key: i64, num_steps: u64) -> Result<(), String>;
}

/// Service for platform management.
pub trait PlatformService {
    /// Get the name of the current platform.
    fn platform_name(&self) -> &str;

    /// Get the language ID.
    fn language_id(&self) -> &str;

    /// Get the compiler spec ID.
    fn compiler_spec_id(&self) -> &str;
}

/// Service for listing (code view) integration.
pub trait ListingService {
    /// Go to the given address in the listing.
    fn go_to(&mut self, offset: u64);

    /// Get the current cursor address.
    fn current_address(&self) -> Option<u64>;
}

/// Service for watch (variable watch) integration.
pub trait WatchService {
    /// Add a watch expression.
    fn add_watch(&mut self, expression: String);

    /// Remove a watch expression.
    fn remove_watch(&mut self, index: usize);

    /// Get all watch expressions.
    fn watches(&self) -> &[String];
}

/// Service for the debug console.
pub trait ConsoleService {
    /// Print a message to the console.
    fn print(&mut self, message: &str);

    /// Print an error message to the console.
    fn print_error(&mut self, message: &str);
}

/// Service for reporting progress.
pub trait ProgressService {
    /// Start a new task with the given name.
    fn start_task(&mut self, name: &str) -> i64;

    /// Update progress on a task.
    fn update_progress(&mut self, task_id: i64, progress: f64);

    /// Finish a task.
    fn finish_task(&mut self, task_id: i64);
}

/// Service for debugger control (connect, disconnect, etc.).
pub trait DebuggerControlService {
    /// Get the currently active target.
    fn active_target(&self) -> Option<i64>;

    /// Connect to a target.
    fn connect(&mut self, target_key: i64) -> Result<(), String>;

    /// Disconnect from the current target.
    fn disconnect(&mut self) -> Result<(), String>;

    /// Whether a target is currently connected.
    fn is_connected(&self) -> bool;
}

/// Service for managing memory region mapping.
pub trait AutoMappingService {
    /// Automatically map a program to a trace.
    fn auto_map(
        &mut self,
        program_url: &str,
        trace_key: i64,
        lifespan: Lifespan,
    ) -> Result<(), String>;

    /// Get the proposed mapping for a program.
    fn propose_mapping(
        &self,
        program_url: &str,
        trace_key: i64,
    ) -> Vec<MappingProposal>;
}

/// A proposed mapping between a program region and a trace region.
#[derive(Debug, Clone)]
pub struct MappingProposal {
    /// Program address range start.
    pub program_min: u64,
    /// Program address range end.
    pub program_max: u64,
    /// Trace address range start.
    pub trace_min: u64,
    /// Trace address range end.
    pub trace_max: u64,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
}

/// Service for target management.
pub trait TargetService {
    /// Get all available targets.
    fn targets(&self) -> Vec<TargetInfo>;

    /// Launch a target.
    fn launch(&mut self, target_type: &str, params: &[String]) -> Result<i64, String>;

    /// Attach to an existing process.
    fn attach(&mut self, target_type: &str, pid: i64) -> Result<i64, String>;
}

/// Information about a debug target type.
#[derive(Debug, Clone)]
pub struct TargetInfo {
    /// The target type identifier.
    pub target_type: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Whether this target supports launch.
    pub supports_launch: bool,
    /// Whether this target supports attach.
    pub supports_attach: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTraceInfo {
        key_val: i64,
        name_val: String,
        active: bool,
    }

    impl TraceInfo for MockTraceInfo {
        fn key(&self) -> i64 {
            self.key_val
        }
        fn name(&self) -> &str {
            &self.name_val
        }
        fn is_active(&self) -> bool {
            self.active
        }
    }

    struct MockBreakpointService {
        bps: Vec<LogicalBreakpoint>,
    }

    impl MockBreakpointService {
        fn new() -> Self {
            Self { bps: Vec::new() }
        }
    }

    impl LogicalBreakpointService for MockBreakpointService {
        fn breakpoints(&self) -> Vec<&LogicalBreakpoint> {
            self.bps.iter().collect()
        }

        fn breakpoint_at(&self, offset: u64) -> Option<&LogicalBreakpoint> {
            self.bps.iter().find(|bp| bp.offset == offset)
        }

        fn add_breakpoint(&mut self, bp: LogicalBreakpoint) -> Result<(), String> {
            self.bps.push(bp);
            Ok(())
        }

        fn delete_breakpoint(&mut self, offset: u64) -> Result<(), String> {
            let before = self.bps.len();
            self.bps.retain(|bp| bp.offset != offset);
            if self.bps.len() < before {
                Ok(())
            } else {
                Err("Breakpoint not found".into())
            }
        }

        fn toggle_breakpoint(&mut self, offset: u64, enabled: bool) -> Result<(), String> {
            if let Some(bp) = self.bps.iter_mut().find(|bp| bp.offset == offset) {
                bp.state.mode = Some(if enabled {
                    crate::api::breakpoint::BreakpointMode::Enabled
                } else {
                    crate::api::breakpoint::BreakpointMode::Disabled
                });
                Ok(())
            } else {
                Err("Breakpoint not found".into())
            }
        }
    }

    struct MockEmulationService {
        emulating: bool,
    }

    impl MockEmulationService {
        fn new() -> Self {
            Self { emulating: false }
        }
    }

    impl EmulationService for MockEmulationService {
        fn start_emulation(&mut self, _trace_key: i64) -> Result<(), String> {
            self.emulating = true;
            Ok(())
        }

        fn stop_emulation(&mut self, _trace_key: i64) -> Result<(), String> {
            self.emulating = false;
            Ok(())
        }

        fn is_emulating(&self, _trace_key: i64) -> bool {
            self.emulating
        }

        fn step_emulation(&mut self, _trace_key: i64, _num_steps: u64) -> Result<(), String> {
            if !self.emulating {
                return Err("Not emulating".into());
            }
            Ok(())
        }
    }

    struct MockControlService {
        connected: bool,
    }

    impl MockControlService {
        fn new() -> Self {
            Self { connected: false }
        }
    }

    impl DebuggerControlService for MockControlService {
        fn active_target(&self) -> Option<i64> {
            if self.connected { Some(1) } else { None }
        }

        fn connect(&mut self, _target_key: i64) -> Result<(), String> {
            self.connected = true;
            Ok(())
        }

        fn disconnect(&mut self) -> Result<(), String> {
            self.connected = false;
            Ok(())
        }

        fn is_connected(&self) -> bool {
            self.connected
        }
    }

    #[test]
    fn test_trace_info() {
        let info = MockTraceInfo {
            key_val: 1,
            name_val: "test".into(),
            active: true,
        };
        assert_eq!(info.key(), 1);
        assert_eq!(info.name(), "test");
        assert!(info.is_active());
    }

    #[test]
    fn test_breakpoint_service() {
        let mut svc = MockBreakpointService::new();
        svc.add_breakpoint(LogicalBreakpoint::new(0x400000, "0x400000"))
            .unwrap();
        assert_eq!(svc.breakpoints().len(), 1);
        assert!(svc.breakpoint_at(0x400000).is_some());
        assert!(svc.breakpoint_at(0x500000).is_none());

        svc.toggle_breakpoint(0x400000, false).unwrap();
        assert!(!svc.breakpoint_at(0x400000).unwrap().is_enabled());

        svc.delete_breakpoint(0x400000).unwrap();
        assert!(svc.breakpoints().is_empty());
    }

    #[test]
    fn test_emulation_service() {
        let mut svc = MockEmulationService::new();
        assert!(!svc.is_emulating(0));

        svc.start_emulation(0).unwrap();
        assert!(svc.is_emulating(0));

        svc.step_emulation(0, 1).unwrap();

        svc.stop_emulation(0).unwrap();
        assert!(!svc.is_emulating(0));
    }

    #[test]
    fn test_emulation_service_step_when_stopped() {
        let mut svc = MockEmulationService::new();
        assert!(svc.step_emulation(0, 1).is_err());
    }

    #[test]
    fn test_control_service() {
        let mut svc = MockControlService::new();
        assert!(!svc.is_connected());
        assert!(svc.active_target().is_none());

        svc.connect(1).unwrap();
        assert!(svc.is_connected());
        assert_eq!(svc.active_target(), Some(1));

        svc.disconnect().unwrap();
        assert!(!svc.is_connected());
    }

    #[test]
    fn test_mapping_proposal() {
        let proposal = MappingProposal {
            program_min: 0,
            program_max: 0x1000,
            trace_min: 0x400000,
            trace_max: 0x401000,
            confidence: 0.95,
        };
        assert_eq!(proposal.confidence, 0.95);
    }

    #[test]
    fn test_target_info() {
        let info = TargetInfo {
            target_type: "gdb".into(),
            display_name: "GDB".into(),
            supports_launch: true,
            supports_attach: true,
        };
        assert!(info.supports_launch);
    }
}
