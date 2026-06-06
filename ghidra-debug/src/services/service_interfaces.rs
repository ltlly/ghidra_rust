//! Comprehensive debugger service interfaces ported from Ghidra's `ghidra.app.services`.
//!
//! These traits define the full API surface for each debugger service, matching the
//! Java interfaces in `Debugger-api/src/main/java/ghidra/app/services/`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use crate::api::breakpoint::LogicalBreakpoint;
use crate::api::control_mode::ControlMode;
use crate::api::tracermi::TraceRmiServiceListener;
use crate::api::watch::WatchRow;

// ---------------------------------------------------------------------------
// ActivationCause — why coordinates were activated
// ---------------------------------------------------------------------------

/// The reason coordinates were activated in the trace manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActivationCause {
    /// The change was driven by the user.
    User,
    /// The request was driven by the user, but via an alternative view
    /// (e.g., to compare snapshots).
    UserAlt,
    /// A trace was activated because a target was published or withdrawn.
    TargetUpdated,
    /// The change was driven by the model activation, possibly indirectly
    /// by the user.
    SyncModel,
    /// The change was driven by the recorder advancing a snapshot.
    FollowPresent,
    /// The tool is activating scratch coordinates to display an emulator state.
    EmulatorStateChanged,
}

// ---------------------------------------------------------------------------
// DebuggerTraceManagerService
// ---------------------------------------------------------------------------

/// The interface for managing open traces and navigating among them and their contents.
///
/// Ported from `ghidra.app.services.DebuggerTraceManagerService`.
pub trait DebuggerTraceManagerService: Send + Sync {
    /// Get the currently active trace, if any.
    fn active_trace(&self) -> Option<String>;

    /// Get the current coordinates.
    fn current_coordinates(&self) -> String;

    /// Get the active thread, if any.
    fn current_thread(&self) -> Option<String>;

    /// Get the active platform, if any.
    fn current_platform(&self) -> Option<String>;

    /// Get the active view.
    fn current_view(&self) -> Option<String>;

    /// Activate the given coordinates with a cause.
    fn activate(&mut self, coordinates: &str, cause: ActivationCause);

    /// Resolve coordinates for the given trace using the manager's best judgment.
    fn resolve_trace(&self, trace_key: &str) -> String;

    /// Activate the given trace.
    fn activate_trace(&mut self, trace_key: &str);

    /// Open a trace for viewing.
    fn open_trace(&mut self, trace_key: &str) -> Result<(), String>;

    /// Close a trace.
    fn close_trace(&mut self, trace_key: &str) -> Result<(), String>;

    /// Close all traces.
    fn close_all_traces(&mut self);

    /// Close all traces except the given one.
    fn close_other_traces(&mut self, keep: &str);

    /// Get all open traces.
    fn open_traces(&self) -> Vec<String>;

    /// Materialize coordinates to a snapshot (may trigger emulation).
    fn materialize(&mut self, coordinates: &str) -> Pin<Box<dyn Future<Output = Result<i64, String>> + Send>>;
}

// ---------------------------------------------------------------------------
// DebuggerControlService
// ---------------------------------------------------------------------------

/// State editor for modifying machine state.
///
/// Ported from `DebuggerControlService.StateEditor`.
pub trait StateEditor: Send + Sync {
    /// Whether the variable at the given address and length is editable.
    fn is_variable_editable(&self, address: u64, length: usize) -> bool;

    /// Whether the given register is editable.
    fn is_register_editable(&self, register_name: &str) -> bool {
        // Default: editable
        let _ = register_name;
        true
    }

    /// Set a variable's value at the given address.
    fn set_variable(&mut self, address: u64, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;

    /// Set a register's value.
    fn set_register(&mut self, register_name: &str, value: &[u8]) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;
}

/// Listener for control mode changes.
pub trait ControlModeChangeListener: Send + Sync {
    /// Called when the control mode changes for a trace.
    fn mode_changed(&self, trace_key: &str, mode: ControlMode);
}

/// Centralized service for modifying machine states.
///
/// Ported from `ghidra.app.services.DebuggerControlService`.
pub trait DebuggerControlService: Send + Sync {
    /// Get the current control mode for the given trace.
    fn get_current_mode(&self, trace_key: &str) -> ControlMode;

    /// Set the current control mode for the given trace.
    fn set_current_mode(&mut self, trace_key: &str, mode: ControlMode);

    /// Add a listener for control mode changes.
    fn add_mode_listener(&mut self, listener: Box<dyn ControlModeChangeListener>);

    /// Remove a listener for control mode changes.
    fn remove_mode_listener(&mut self, listener_id: usize);

    /// Create a state editor for the given coordinates.
    fn create_state_editor(&mut self, coordinates: &str) -> Box<dyn StateEditor>;
}

// ---------------------------------------------------------------------------
// DebuggerEmulationService
// ---------------------------------------------------------------------------

/// Result of letting the emulator "run free".
#[derive(Debug, Clone)]
pub struct EmulationRunResult {
    /// The (scratch) snapshot where the emulated state is stored.
    pub snapshot: i64,
    /// The schedule at which emulation stopped.
    pub stopped_at: String,
    /// Whether emulation was interrupted.
    pub interrupted: bool,
    /// Error message, if any.
    pub error: Option<String>,
}

/// Result of definite emulation.
#[derive(Debug, Clone)]
pub struct EmulationDefiniteResult {
    /// The (scratch) snapshot where the emulated state is stored.
    pub snapshot: i64,
}

/// Listener for emulator state changes.
pub trait EmulatorStateListener: Send + Sync {
    /// Called when the emulator state changes.
    fn state_changed(&self, trace_key: &str, emulating: bool);
}

/// Service for managing emulators.
///
/// Ported from `ghidra.app.services.DebuggerEmulationService`.
pub trait DebuggerEmulationService: Send + Sync {
    /// Emulate for a definite number of steps.
    fn emulate(
        &mut self,
        trace_key: &str,
        schedule: &str,
    ) -> Pin<Box<dyn Future<Output = Result<EmulationDefiniteResult, String>> + Send>>;

    /// Allow the emulator to "run free" until interrupted or error.
    fn run(
        &mut self,
        trace_key: &str,
        from_schedule: &str,
    ) -> Pin<Box<dyn Future<Output = Result<EmulationRunResult, String>> + Send>>;

    /// Background emulate for a definite number of steps.
    fn background_emulate(
        &mut self,
        trace_key: &str,
        schedule: &str,
    ) -> Pin<Box<dyn Future<Output = Result<i64, String>> + Send>>;

    /// Background run (indefinite emulation).
    fn background_run(
        &mut self,
        trace_key: &str,
        from_schedule: &str,
    ) -> Pin<Box<dyn Future<Output = Result<EmulationRunResult, String>> + Send>>;

    /// Add a listener for emulator state changes.
    fn add_state_listener(&mut self, listener: Box<dyn EmulatorStateListener>);

    /// Remove a listener for emulator state changes.
    fn remove_state_listener(&mut self, listener_id: usize);
}

// ---------------------------------------------------------------------------
// DebuggerLogicalBreakpointService
// ---------------------------------------------------------------------------

/// Listener for logical breakpoint changes.
///
/// Ported from `ghidra.debug.api.breakpoint.LogicalBreakpointsChangeListener`.
pub trait LogicalBreakpointsChangeListener: Send + Sync {
    /// A logical breakpoint was added.
    fn breakpoint_added(&self, _added: &LogicalBreakpoint) {}
    /// Multiple logical breakpoints were added.
    fn breakpoints_added(&self, added: &[LogicalBreakpoint]) {
        for bp in added {
            self.breakpoint_added(bp);
        }
    }
    /// A logical breakpoint was updated.
    fn breakpoint_updated(&self, _updated: &LogicalBreakpoint) {}
    /// Multiple logical breakpoints were updated.
    fn breakpoints_updated(&self, updated: &[LogicalBreakpoint]) {
        for bp in updated {
            self.breakpoint_updated(bp);
        }
    }
    /// A logical breakpoint was removed.
    fn breakpoint_removed(&self, _removed: &LogicalBreakpoint) {}
    /// Multiple logical breakpoints were removed.
    fn breakpoints_removed(&self, removed: &[LogicalBreakpoint]) {
        for bp in removed {
            self.breakpoint_removed(bp);
        }
    }
}

/// Service for managing logical breakpoints.
///
/// Ported from `ghidra.app.services.DebuggerLogicalBreakpointService`.
pub trait DebuggerLogicalBreakpointService: Send + Sync {
    /// Get all logical breakpoints known to the tool.
    fn get_all_breakpoints(&self) -> BTreeSet<LogicalBreakpoint>;

    /// Get breakpoints for a given program (by URL).
    fn get_breakpoints_for_program(&self, program_url: &str) -> BTreeMap<u64, BTreeSet<LogicalBreakpoint>>;

    /// Get breakpoints for a given trace.
    fn get_breakpoints_for_trace(&self, trace_key: &str) -> BTreeMap<u64, BTreeSet<LogicalBreakpoint>>;

    /// Get breakpoints at a given program address.
    fn get_breakpoints_at(&self, program_url: &str, address: u64) -> BTreeSet<LogicalBreakpoint>;

    /// Add a change listener.
    fn add_change_listener(&mut self, listener: Box<dyn LogicalBreakpointsChangeListener>);

    /// Remove a change listener.
    fn remove_change_listener(&mut self, listener_id: usize);

    /// Place a breakpoint.
    fn place_breakpoint(
        &mut self,
        program_url: &str,
        address: u64,
        kinds: u32,
    ) -> Pin<Box<dyn Future<Output = Result<LogicalBreakpoint, String>> + Send>>;

    /// Delete breakpoints.
    fn delete_breakpoints(
        &mut self,
        breakpoints: &[LogicalBreakpoint],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;

    /// Enable breakpoints.
    fn enable_breakpoints(
        &mut self,
        breakpoints: &[LogicalBreakpoint],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;

    /// Disable breakpoints.
    fn disable_breakpoints(
        &mut self,
        breakpoints: &[LogicalBreakpoint],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;

    /// Generate an informational message about enabling the given breakpoints.
    fn generate_status_enable(&self, breakpoints: &[LogicalBreakpoint], trace_key: Option<&str>) -> Option<String>;

    /// Toggle breakpoints at the given location.
    fn toggle_breakpoints_at(
        &mut self,
        program_url: &str,
        address: u64,
    ) -> Pin<Box<dyn Future<Output = Result<BTreeSet<LogicalBreakpoint>, String>> + Send>>;
}

// ---------------------------------------------------------------------------
// DebuggerPlatformService
// ---------------------------------------------------------------------------

/// Service for platform management.
///
/// Ported from `ghidra.app.services.DebuggerPlatformService`.
pub trait DebuggerPlatformService: Send + Sync {
    /// Get the current mapper for the given trace.
    fn get_current_mapper_for(&self, trace_key: &str) -> Option<String>;

    /// Get a mapper applicable to the given object.
    fn get_mapper(&self, trace_key: &str, object_path: &str, snap: i64) -> Option<String>;

    /// Get a new mapper for the given object, ignoring current.
    fn get_new_mapper(&self, trace_key: &str, object_path: &str, snap: i64) -> Option<String>;

    /// Set the current mapper for the trace.
    fn set_current_mapper_for(
        &mut self,
        trace_key: &str,
        focus_path: &str,
        mapper: &str,
        snap: i64,
    );
}

// ---------------------------------------------------------------------------
// DebuggerListingService
// ---------------------------------------------------------------------------

/// Service for listing (code view) integration.
///
/// Ported from `ghidra.app.services.DebuggerListingService`.
pub trait DebuggerListingService: Send + Sync {
    /// Go to the given address in the listing.
    fn go_to(&mut self, address: u64);

    /// Get the current cursor address.
    fn current_address(&self) -> Option<u64>;

    /// Add a location listener.
    fn add_location_listener(&mut self, listener_id: usize, callback: String);

    /// Remove a location listener.
    fn remove_location_listener(&mut self, listener_id: usize);
}

// ---------------------------------------------------------------------------
// DebuggerWatchesService
// ---------------------------------------------------------------------------

/// Service for managing watch expressions.
///
/// Ported from `ghidra.app.services.DebuggerWatchesService`.
pub trait DebuggerWatchesService: Send + Sync {
    /// Add a watch expression.
    fn add_watch(&mut self, expression: &str) -> WatchRow;

    /// Remove a watch.
    fn remove_watch(&mut self, watch: &WatchRow);

    /// Get the current watches.
    fn get_watches(&self) -> Vec<WatchRow>;
}

// ---------------------------------------------------------------------------
// DebuggerConsoleService
// ---------------------------------------------------------------------------

/// Service for the debug console.
///
/// Ported from `ghidra.app.services.DebuggerConsoleService`.
pub trait DebuggerConsoleService: Send + Sync {
    /// Print a message to the console.
    fn print(&mut self, message: &str);

    /// Print an informational message.
    fn print_info(&mut self, message: &str);

    /// Print a warning message.
    fn print_warning(&mut self, message: &str);

    /// Print an error message.
    fn print_error(&mut self, message: &str);

    /// Get recent console entries.
    fn get_recent_entries(&self, count: usize) -> Vec<ConsoleEntry>;
}

/// A console log entry.
#[derive(Debug, Clone)]
pub struct ConsoleEntry {
    /// The message text.
    pub message: String,
    /// The log level.
    pub level: ConsoleLevel,
    /// Timestamp (millis since epoch).
    pub timestamp: i64,
}

/// Console log level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConsoleLevel {
    Info,
    Warning,
    Error,
    StdOut,
    StdErr,
}

// ---------------------------------------------------------------------------
// DebuggerTargetService
// ---------------------------------------------------------------------------

/// Listener for target publication events.
///
/// Ported from `ghidra.debug.api.target.TargetPublicationListener`.
pub trait TargetPublicationListener: Send + Sync {
    /// A target was published.
    fn target_published(&self, target_key: &str);
    /// A target was withdrawn.
    fn target_withdrawn(&self, target_key: &str);
}

/// Service for managing published targets.
///
/// Ported from `ghidra.app.services.DebuggerTargetService`.
pub trait DebuggerTargetService: Send + Sync {
    /// Publish a target to the service and its listeners.
    fn publish_target(&mut self, target_key: &str);

    /// Withdraw a target from the service.
    fn withdraw_target(&mut self, target_key: &str);

    /// Get all published targets.
    fn get_published_targets(&self) -> Vec<String>;

    /// Get the target for the given trace.
    fn get_target_for_trace(&self, trace_key: &str) -> Option<String>;

    /// Add a listener for target publication events.
    fn add_target_publication_listener(&mut self, listener: Box<dyn TargetPublicationListener>);

    /// Remove a listener for target publication events.
    fn remove_target_publication_listener(&mut self, listener_id: usize);
}

// ---------------------------------------------------------------------------
// ProgressService
// ---------------------------------------------------------------------------

/// Service for reporting progress.
///
/// Ported from `ghidra.app.services.ProgressService`.
pub trait ProgressService: Send + Sync {
    /// Start a new task.
    fn start_task(&mut self, name: &str) -> i64;

    /// Update progress on a task (0.0 to 1.0).
    fn update_progress(&mut self, task_id: i64, progress: f64);

    /// Set the message for a task.
    fn set_message(&mut self, task_id: i64, message: &str);

    /// Cancel a task.
    fn cancel_task(&mut self, task_id: i64);

    /// Finish a task.
    fn finish_task(&mut self, task_id: i64);

    /// Whether a task was cancelled.
    fn is_cancelled(&self, task_id: i64) -> bool;
}

// ---------------------------------------------------------------------------
// DebuggerAutoMappingService
// ---------------------------------------------------------------------------

/// Service for querying auto-map settings.
///
/// Ported from `ghidra.app.services.DebuggerAutoMappingService`.
pub trait DebuggerAutoMappingService: Send + Sync {
    /// Set the current auto-map specification.
    fn set_auto_map_spec(&mut self, spec: &str);

    /// Get the auto-map setting currently active.
    fn get_auto_map_spec(&self) -> String;

    /// Get the auto-map setting for the given trace.
    fn get_auto_map_spec_for_trace(&self, trace_key: &str) -> String;
}

// ---------------------------------------------------------------------------
// DebuggerStaticMappingService
// ---------------------------------------------------------------------------

/// Listener for static mapping changes.
///
/// Ported from `ghidra.debug.api.modules.DebuggerStaticMappingChangeListener`.
pub trait StaticMappingChangeListener: Send + Sync {
    /// The mappings among programs and traces have changed.
    fn mappings_changed(&self, affected_traces: &HashSet<String>, affected_programs: &HashSet<String>);
}

/// Service for managing static mappings between traces and programs.
///
/// Ported from `ghidra.app.services.DebuggerStaticMappingService`.
pub trait DebuggerStaticMappingService: Send + Sync {
    /// Add a static mapping from trace to program.
    fn add_mapping(
        &mut self,
        trace_key: &str,
        trace_min: u64,
        trace_max: u64,
        snap_start: i64,
        snap_end: i64,
        program_url: &str,
        program_min: u64,
        program_max: u64,
        truncate_existing: bool,
    ) -> Result<(), String>;

    /// Remove a mapping.
    fn remove_mapping(&mut self, mapping_id: i64) -> Result<(), String>;

    /// Get all mappings for a trace.
    fn get_mappings_for_trace(&self, trace_key: &str) -> Vec<StaticMappingEntry>;

    /// Get all mappings for a program.
    fn get_mappings_for_program(&self, program_url: &str) -> Vec<StaticMappingEntry>;

    /// Add a change listener.
    fn add_change_listener(&mut self, listener: Box<dyn StaticMappingChangeListener>);

    /// Remove a change listener.
    fn remove_change_listener(&mut self, listener_id: usize);

    /// Propose a module map.
    fn propose_module_map(
        &self,
        module_key: &str,
        snap: i64,
        program_url: &str,
    ) -> Option<String>;

    /// Propose a region map.
    fn propose_region_map(
        &self,
        region_keys: &[String],
        snap: i64,
        program_url: &str,
    ) -> Option<String>;
}

/// A static mapping entry.
#[derive(Debug, Clone)]
pub struct StaticMappingEntry {
    /// Unique ID.
    pub id: i64,
    /// Trace key.
    pub trace_key: String,
    /// Trace address range min.
    pub trace_min: u64,
    /// Trace address range max.
    pub trace_max: u64,
    /// Start snap.
    pub snap_start: i64,
    /// End snap.
    pub snap_end: i64,
    /// Program URL.
    pub program_url: String,
    /// Program address range min.
    pub program_min: u64,
    /// Program address range max.
    pub program_max: u64,
}

// ---------------------------------------------------------------------------
// TraceRmiService
// ---------------------------------------------------------------------------

/// Service for Trace RMI connections.
///
/// Ported from `ghidra.app.services.TraceRmiService`.
pub trait TraceRmiService: Send + Sync {
    /// Get the server address.
    fn get_server_address(&self) -> Option<SocketAddr>;

    /// Set the server address.
    fn set_server_address(&mut self, address: Option<SocketAddr>);

    /// Start the Trace RMI server.
    fn start_server(&mut self) -> Result<(), String>;

    /// Stop the Trace RMI server.
    fn stop_server(&mut self) -> Result<(), String>;

    /// Connect to a back-end debugger at the given address.
    fn connect(&mut self, address: SocketAddr) -> Result<String, String>;

    /// Accept one inbound connection at the given address.
    fn accept_one(&mut self, address: SocketAddr) -> Result<String, String>;

    /// Get all connections.
    fn get_connections(&self) -> Vec<String>;

    /// Get all targets.
    fn get_targets(&self) -> Vec<String>;

    /// Add a service listener.
    fn add_service_listener(&mut self, listener: Box<dyn TraceRmiServiceListener>);

    /// Remove a service listener.
    fn remove_service_listener(&mut self, listener_id: usize);
}

// ---------------------------------------------------------------------------
// TraceRmiLauncherService
// ---------------------------------------------------------------------------

/// Service for launching programs via Trace RMI.
///
/// Ported from `ghidra.app.services.TraceRmiLauncherService`.
pub trait TraceRmiLauncherService: Send + Sync {
    /// Get available launch offers for the given program.
    fn get_offers(&self, program_url: &str) -> Vec<LaunchOffer>;

    /// Launch a program with the given offer.
    fn launch(
        &mut self,
        offer_id: &str,
        program_url: &str,
        params: &HashMap<String, String>,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>>;
}

/// A launch offer for a program.
#[derive(Debug, Clone)]
pub struct LaunchOffer {
    /// Unique offer ID.
    pub id: String,
    /// Display name.
    pub display_name: String,
    /// Description.
    pub description: String,
    /// Whether this offer is available.
    pub available: bool,
    /// Parameters.
    pub parameters: Vec<LaunchParameter>,
}

/// A launch parameter.
#[derive(Debug, Clone)]
pub struct LaunchParameter {
    /// Parameter name.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// Parameter type (string, int, bool, etc.).
    pub param_type: String,
    /// Default value.
    pub default_value: Option<String>,
    /// Whether the parameter is required.
    pub required: bool,
    /// Description.
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_activation_cause_variants() {
        let causes = [
            ActivationCause::User,
            ActivationCause::UserAlt,
            ActivationCause::TargetUpdated,
            ActivationCause::SyncModel,
            ActivationCause::FollowPresent,
            ActivationCause::EmulatorStateChanged,
        ];
        assert_eq!(causes.len(), 6);
        assert_ne!(ActivationCause::User, ActivationCause::UserAlt);
    }

    #[test]
    fn test_emulation_run_result() {
        let result = EmulationRunResult {
            snapshot: 42,
            stopped_at: "snap=42:tick=10".into(),
            interrupted: true,
            error: None,
        };
        assert_eq!(result.snapshot, 42);
        assert!(result.interrupted);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_emulation_definite_result() {
        let result = EmulationDefiniteResult { snapshot: 7 };
        assert_eq!(result.snapshot, 7);
    }

    #[test]
    fn test_console_level_variants() {
        let levels = [
            ConsoleLevel::Info,
            ConsoleLevel::Warning,
            ConsoleLevel::Error,
            ConsoleLevel::StdOut,
            ConsoleLevel::StdErr,
        ];
        assert_eq!(levels.len(), 5);
        assert_eq!(ConsoleLevel::Info, ConsoleLevel::Info);
        assert_ne!(ConsoleLevel::Info, ConsoleLevel::Error);
    }

    #[test]
    fn test_console_entry() {
        let entry = ConsoleEntry {
            message: "test".into(),
            level: ConsoleLevel::Info,
            timestamp: 1234567890,
        };
        assert_eq!(entry.message, "test");
        assert_eq!(entry.level, ConsoleLevel::Info);
    }

    #[test]
    fn test_static_mapping_entry() {
        let entry = StaticMappingEntry {
            id: 1,
            trace_key: "trace1".into(),
            trace_min: 0x1000,
            trace_max: 0x2000,
            snap_start: 0,
            snap_end: i64::MAX,
            program_url: "file:///test.gzf".into(),
            program_min: 0x401000,
            program_max: 0x402000,
        };
        assert_eq!(entry.id, 1);
        assert_eq!(entry.trace_max - entry.trace_min, 0x1000);
        assert_eq!(entry.program_max - entry.program_min, 0x1000);
    }

    #[test]
    fn test_launch_offer() {
        let offer = LaunchOffer {
            id: "gdb-local".into(),
            display_name: "GDB Local".into(),
            description: "Launch via GDB locally".into(),
            available: true,
            parameters: vec![
                LaunchParameter {
                    name: "executable".into(),
                    display_name: "Executable".into(),
                    param_type: "string".into(),
                    default_value: None,
                    required: true,
                    description: "Path to executable".into(),
                },
            ],
        };
        assert!(offer.available);
        assert_eq!(offer.parameters.len(), 1);
        assert!(offer.parameters[0].required);
    }

    #[test]
    fn test_launch_parameter_defaults() {
        let param = LaunchParameter {
            name: "port".into(),
            display_name: "Port".into(),
            param_type: "int".into(),
            default_value: Some("23946".into()),
            required: false,
            description: "GDB port".into(),
        };
        assert_eq!(param.default_value.as_deref(), Some("23946"));
        assert!(!param.required);
    }
}
