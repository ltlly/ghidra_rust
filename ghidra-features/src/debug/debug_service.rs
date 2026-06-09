//! Debug Service -- Ghidra Features Debug Service Interfaces.
//!
//! Ported from Ghidra's `ghidra.app.services` (Debugger-api) Java package.
//!
//! Provides the service interface layer for the debugger features module:
//! - [`DebugService`]: Central debug service trait.
//! - [`DebugTargetService`]: Target management service.
//! - [`DebugControlService`]: Execution control service.
//! - [`DebugBreakpointService`]: Breakpoint management service.
//! - [`DebugTraceManagerService`]: Trace lifecycle service.
//! - [`DebugMemoryService`]: Memory read/write service.
//! - [`DebugRegisterService`]: Register read/write service.
//! - [`DebugListingService`]: Listing integration service.
//! - [`DebugMappingService`]: Static mapping service.
//! - [`DebugConsoleService`]: Debug console service.
//! - [`DebugEmulationService`]: Emulation service.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------
// Debug Service Error
// ---------------------------------------------------------------------------

/// Errors that can occur in debug services.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebugServiceError {
    /// The target is not connected.
    NotConnected,
    /// The trace is not active.
    NoActiveTrace,
    /// The operation was cancelled.
    Cancelled,
    /// An invalid argument was provided.
    InvalidArgument(String),
    /// A backend error occurred.
    BackendError(String),
    /// The operation timed out.
    Timeout,
    /// The resource was not found.
    NotFound(String),
    /// The operation is not supported.
    NotSupported(String),
}

impl std::fmt::Display for DebugServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConnected => write!(f, "Not connected to target"),
            Self::NoActiveTrace => write!(f, "No active trace"),
            Self::Cancelled => write!(f, "Operation cancelled"),
            Self::InvalidArgument(msg) => write!(f, "Invalid argument: {}", msg),
            Self::BackendError(msg) => write!(f, "Backend error: {}", msg),
            Self::Timeout => write!(f, "Operation timed out"),
            Self::NotFound(name) => write!(f, "Not found: {}", name),
            Self::NotSupported(msg) => write!(f, "Not supported: {}", msg),
        }
    }
}

impl std::error::Error for DebugServiceError {}

/// Result type for debug service operations.
pub type DebugServiceResult<T> = Result<T, DebugServiceError>;

// ---------------------------------------------------------------------------
// Execution State
// ---------------------------------------------------------------------------

/// The execution state of a debuggee thread.
///
/// Ported from Ghidra's `TraceExecutionState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExecutionState {
    /// The target is running.
    Running,
    /// The target is stopped.
    Stopped,
    /// The target has terminated.
    Terminated,
    /// The target state is unknown.
    Unknown,
}

impl Default for ExecutionState {
    fn default() -> Self {
        Self::Unknown
    }
}

// ---------------------------------------------------------------------------
// Breakpoint Kind
// ---------------------------------------------------------------------------

/// The kind of a breakpoint.
///
/// Ported from Ghidra's `TraceBreakpointKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BreakpointKind {
    /// Software execution breakpoint.
    SoftwareExecute,
    /// Hardware execution breakpoint.
    HardwareExecute,
    /// Read watchpoint.
    Read,
    /// Write watchpoint.
    Write,
    /// Access watchpoint (read/write).
    Access,
}

impl BreakpointKind {
    /// Convert to a bitmask value.
    pub fn to_bitmask(&self) -> u32 {
        match self {
            Self::SoftwareExecute => 0x01,
            Self::HardwareExecute => 0x02,
            Self::Read => 0x04,
            Self::Write => 0x08,
            Self::Access => 0x10,
        }
    }

    /// Convert from a bitmask value.
    pub fn from_bitmask(mask: u32) -> BTreeSet<BreakpointKind> {
        let mut kinds = BTreeSet::new();
        if mask & 0x01 != 0 {
            kinds.insert(Self::SoftwareExecute);
        }
        if mask & 0x02 != 0 {
            kinds.insert(Self::HardwareExecute);
        }
        if mask & 0x04 != 0 {
            kinds.insert(Self::Read);
        }
        if mask & 0x08 != 0 {
            kinds.insert(Self::Write);
        }
        if mask & 0x10 != 0 {
            kinds.insert(Self::Access);
        }
        kinds
    }
}

// ---------------------------------------------------------------------------
// Breakpoint Info
// ---------------------------------------------------------------------------

/// Information about a breakpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointInfo {
    /// The breakpoint address.
    pub address: u64,
    /// The breakpoint kinds.
    pub kinds: BTreeSet<BreakpointKind>,
    /// Whether the breakpoint is enabled.
    pub enabled: bool,
    /// Optional condition expression.
    pub condition: Option<String>,
    /// Optional hit count.
    pub hit_count: u64,
}

impl BreakpointInfo {
    /// Create a new breakpoint info.
    pub fn new(address: u64, kinds: BTreeSet<BreakpointKind>) -> Self {
        Self {
            address,
            kinds,
            enabled: true,
            condition: None,
            hit_count: 0,
        }
    }

    /// Check if this is a software breakpoint.
    pub fn is_software(&self) -> bool {
        self.kinds.contains(&BreakpointKind::SoftwareExecute)
    }

    /// Check if this is a hardware breakpoint.
    pub fn is_hardware(&self) -> bool {
        self.kinds.contains(&BreakpointKind::HardwareExecute)
    }

    /// Check if this is a watchpoint.
    pub fn is_watchpoint(&self) -> bool {
        self.kinds.contains(&BreakpointKind::Read)
            || self.kinds.contains(&BreakpointKind::Write)
            || self.kinds.contains(&BreakpointKind::Access)
    }
}

// ---------------------------------------------------------------------------
// Memory Region
// ---------------------------------------------------------------------------

/// A memory region in a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegionInfo {
    /// The region name.
    pub name: String,
    /// The start address.
    pub start: u64,
    /// The end address (inclusive).
    pub end: u64,
    /// Whether the region is readable.
    pub readable: bool,
    /// Whether the region is writable.
    pub writable: bool,
    /// Whether the region is executable.
    pub executable: bool,
}

impl MemoryRegionInfo {
    /// Create a new memory region.
    pub fn new(name: impl Into<String>, start: u64, end: u64) -> Self {
        Self {
            name: name.into(),
            start,
            end,
            readable: true,
            writable: false,
            executable: false,
        }
    }

    /// Get the size of the region.
    pub fn size(&self) -> u64 {
        self.end - self.start + 1
    }

    /// Check if an address is within this region.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start && address <= self.end
    }
}

// ---------------------------------------------------------------------------
// Register Info
// ---------------------------------------------------------------------------

/// Information about a register.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterInfo {
    /// The register name.
    pub name: String,
    /// The register address in the register space.
    pub address: u64,
    /// The register size in bytes.
    pub size: u32,
    /// The register group (e.g., "General", "Float").
    pub group: String,
}

impl RegisterInfo {
    /// Create a new register info.
    pub fn new(name: impl Into<String>, address: u64, size: u32, group: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            address,
            size,
            group: group.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Coordinates
// ---------------------------------------------------------------------------

/// Debugger coordinates describing a specific point in a trace.
///
/// Ported from Ghidra's `DebuggerCoordinates`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugCoordinates {
    /// The trace key.
    pub trace_key: String,
    /// The snapshot/snap value.
    pub snap: i64,
    /// The thread key (if applicable).
    pub thread_key: Option<i64>,
    /// The frame level (if applicable).
    pub frame: Option<u32>,
    /// The object path (if applicable).
    pub object_path: Option<String>,
}

impl DebugCoordinates {
    /// Create new coordinates for a trace and snap.
    pub fn new(trace_key: impl Into<String>, snap: i64) -> Self {
        Self {
            trace_key: trace_key.into(),
            snap,
            thread_key: None,
            frame: None,
            object_path: None,
        }
    }

    /// Set the thread.
    pub fn with_thread(mut self, thread_key: i64) -> Self {
        self.thread_key = Some(thread_key);
        self
    }

    /// Set the frame.
    pub fn with_frame(mut self, frame: u32) -> Self {
        self.frame = Some(frame);
        self
    }

    /// Set the object path.
    pub fn with_object_path(mut self, path: impl Into<String>) -> Self {
        self.object_path = Some(path.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Debug Target Service
// ---------------------------------------------------------------------------

/// Service for managing debug targets.
///
/// Ported from Ghidra's `DebuggerTargetService`.
pub trait DebugTargetService {
    /// Publish a target.
    fn publish_target(&mut self, target_key: &str);

    /// Withdraw a target.
    fn withdraw_target(&mut self, target_key: &str);

    /// Get all published targets.
    fn get_published_targets(&self) -> Vec<String>;

    /// Get the target for a given trace.
    fn get_target_for_trace(&self, trace_key: &str) -> Option<String>;
}

// ---------------------------------------------------------------------------
// Debug Control Service
// ---------------------------------------------------------------------------

/// Service for execution control.
///
/// Ported from Ghidra's `DebuggerControlService`.
pub trait DebugControlService {
    /// Resume execution.
    fn resume(&mut self, trace_key: &str) -> DebugServiceResult<()>;

    /// Interrupt execution.
    fn interrupt(&mut self, trace_key: &str) -> DebugServiceResult<()>;

    /// Step into.
    fn step_into(&mut self, trace_key: &str) -> DebugServiceResult<()>;

    /// Step over.
    fn step_over(&mut self, trace_key: &str) -> DebugServiceResult<()>;

    /// Step out.
    fn step_out(&mut self, trace_key: &str) -> DebugServiceResult<()>;

    /// Step back.
    fn step_back(&mut self, trace_key: &str) -> DebugServiceResult<()>;

    /// Kill the target.
    fn kill(&mut self, trace_key: &str) -> DebugServiceResult<()>;

    /// Detach from the target.
    fn detach(&mut self, trace_key: &str) -> DebugServiceResult<()>;

    /// Get the execution state.
    fn get_execution_state(&self, trace_key: &str, thread_key: i64) -> ExecutionState;
}

// ---------------------------------------------------------------------------
// Debug Breakpoint Service
// ---------------------------------------------------------------------------

/// Service for breakpoint management.
///
/// Ported from Ghidra's `DebuggerLogicalBreakpointService`.
pub trait DebugBreakpointService {
    /// Place a breakpoint.
    fn place_breakpoint(
        &mut self,
        trace_key: &str,
        address: u64,
        kinds: BTreeSet<BreakpointKind>,
    ) -> DebugServiceResult<BreakpointInfo>;

    /// Delete a breakpoint.
    fn delete_breakpoint(&mut self, trace_key: &str, address: u64) -> DebugServiceResult<()>;

    /// Enable a breakpoint.
    fn enable_breakpoint(&mut self, trace_key: &str, address: u64) -> DebugServiceResult<()>;

    /// Disable a breakpoint.
    fn disable_breakpoint(&mut self, trace_key: &str, address: u64) -> DebugServiceResult<()>;

    /// Toggle a breakpoint.
    fn toggle_breakpoint(&mut self, trace_key: &str, address: u64) -> DebugServiceResult<bool>;

    /// Get all breakpoints.
    fn get_breakpoints(&self, trace_key: &str) -> Vec<BreakpointInfo>;

    /// Get breakpoint at address.
    fn get_breakpoint_at(&self, trace_key: &str, address: u64) -> Option<BreakpointInfo>;

    /// Check if a breakpoint is valid.
    fn is_breakpoint_valid(&self, trace_key: &str, address: u64) -> bool;
}

// ---------------------------------------------------------------------------
// Debug Trace Manager Service
// ---------------------------------------------------------------------------

/// Service for trace lifecycle management.
///
/// Ported from Ghidra's `DebuggerTraceManagerService`.
pub trait DebugTraceManagerService {
    /// Get the active trace key.
    fn active_trace(&self) -> Option<String>;

    /// Get the current coordinates.
    fn current_coordinates(&self) -> Option<DebugCoordinates>;

    /// Activate a trace.
    fn activate_trace(&mut self, trace_key: &str);

    /// Open a trace.
    fn open_trace(&mut self, trace_key: &str) -> DebugServiceResult<()>;

    /// Close a trace.
    fn close_trace(&mut self, trace_key: &str) -> DebugServiceResult<()>;

    /// Close all traces.
    fn close_all_traces(&mut self);

    /// Get all open traces.
    fn open_traces(&self) -> Vec<String>;

    /// Navigate to coordinates.
    fn go_to(&mut self, coordinates: DebugCoordinates);
}

// ---------------------------------------------------------------------------
// Debug Memory Service
// ---------------------------------------------------------------------------

/// Service for memory read/write operations.
///
/// Ported from Ghidra's memory-related service methods.
pub trait DebugMemoryService {
    /// Read memory bytes.
    fn read_memory(
        &self,
        trace_key: &str,
        address: u64,
        length: usize,
    ) -> DebugServiceResult<Vec<u8>>;

    /// Write memory bytes.
    fn write_memory(
        &mut self,
        trace_key: &str,
        address: u64,
        data: &[u8],
    ) -> DebugServiceResult<()>;

    /// Get memory regions.
    fn get_memory_regions(&self, trace_key: &str) -> Vec<MemoryRegionInfo>;

    /// Invalidate memory caches.
    fn invalidate_caches(&mut self, trace_key: &str);
}

// ---------------------------------------------------------------------------
// Debug Register Service
// ---------------------------------------------------------------------------

/// Service for register read/write operations.
pub trait DebugRegisterService {
    /// Read a register value.
    fn read_register(
        &self,
        trace_key: &str,
        thread_key: i64,
        register_name: &str,
    ) -> DebugServiceResult<Vec<u8>>;

    /// Write a register value.
    fn write_register(
        &mut self,
        trace_key: &str,
        thread_key: i64,
        register_name: &str,
        value: &[u8],
    ) -> DebugServiceResult<()>;

    /// Get all registers.
    fn get_registers(&self, trace_key: &str) -> Vec<RegisterInfo>;

    /// Get registers for a group.
    fn get_registers_in_group(&self, trace_key: &str, group: &str) -> Vec<RegisterInfo>;
}

// ---------------------------------------------------------------------------
// Debug Listing Service
// ---------------------------------------------------------------------------

/// Service for listing integration.
///
/// Ported from Ghidra's `DebuggerListingService`.
pub trait DebugListingService {
    /// Go to an address in the listing.
    fn go_to_address(&mut self, address: u64);

    /// Get the current cursor address.
    fn current_address(&self) -> Option<u64>;
}

// ---------------------------------------------------------------------------
// Debug Mapping Service
// ---------------------------------------------------------------------------

/// A static mapping entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticMappingEntry {
    /// Unique ID.
    pub id: u64,
    /// Trace address range start.
    pub trace_start: u64,
    /// Trace address range end.
    pub trace_end: u64,
    /// Program URL.
    pub program_url: String,
    /// Program address range start.
    pub program_start: u64,
    /// Program address range end.
    pub program_end: u64,
    /// Start snap.
    pub snap_start: i64,
    /// End snap.
    pub snap_end: i64,
}

impl StaticMappingEntry {
    /// Check if a program address maps to a trace address.
    pub fn program_to_trace(&self, program_addr: u64) -> Option<u64> {
        if program_addr >= self.program_start && program_addr <= self.program_end {
            let offset = program_addr - self.program_start;
            Some(self.trace_start + offset)
        } else {
            None
        }
    }

    /// Check if a trace address maps to a program address.
    pub fn trace_to_program(&self, trace_addr: u64) -> Option<u64> {
        if trace_addr >= self.trace_start && trace_addr <= self.trace_end {
            let offset = trace_addr - self.trace_start;
            Some(self.program_start + offset)
        } else {
            None
        }
    }
}

/// Service for static mapping management.
///
/// Ported from Ghidra's `DebuggerStaticMappingService`.
pub trait DebugMappingService {
    /// Add a static mapping.
    fn add_mapping(
        &mut self,
        trace_key: &str,
        trace_start: u64,
        trace_end: u64,
        snap_start: i64,
        snap_end: i64,
        program_url: &str,
        program_start: u64,
        program_end: u64,
    ) -> DebugServiceResult<u64>;

    /// Remove a mapping.
    fn remove_mapping(&mut self, mapping_id: u64) -> DebugServiceResult<()>;

    /// Get all mappings for a trace.
    fn get_mappings_for_trace(&self, trace_key: &str) -> Vec<StaticMappingEntry>;

    /// Get all mappings for a program.
    fn get_mappings_for_program(&self, program_url: &str) -> Vec<StaticMappingEntry>;

    /// Find a trace address for a program address.
    fn program_to_trace(
        &self,
        program_url: &str,
        program_addr: u64,
        snap: i64,
    ) -> Option<u64>;

    /// Find a program address for a trace address.
    fn trace_to_program(
        &self,
        trace_key: &str,
        trace_addr: u64,
        snap: i64,
    ) -> Option<(String, u64)>;
}

// ---------------------------------------------------------------------------
// Debug Console Service
// ---------------------------------------------------------------------------

/// Console log level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConsoleLevel {
    /// Informational message.
    Info,
    /// Warning message.
    Warning,
    /// Error message.
    Error,
    /// Standard output.
    StdOut,
    /// Standard error.
    StdErr,
}

/// A console log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleEntry {
    /// The message text.
    pub message: String,
    /// The log level.
    pub level: ConsoleLevel,
    /// Timestamp (millis since epoch).
    pub timestamp: i64,
}

/// Service for the debug console.
///
/// Ported from Ghidra's `DebuggerConsoleService`.
pub trait DebugConsoleService {
    /// Print a message.
    fn print(&mut self, level: ConsoleLevel, message: &str);

    /// Print an info message.
    fn print_info(&mut self, message: &str) {
        self.print(ConsoleLevel::Info, message);
    }

    /// Print a warning message.
    fn print_warning(&mut self, message: &str) {
        self.print(ConsoleLevel::Warning, message);
    }

    /// Print an error message.
    fn print_error(&mut self, message: &str) {
        self.print(ConsoleLevel::Error, message);
    }

    /// Get recent entries.
    fn get_recent_entries(&self, count: usize) -> Vec<ConsoleEntry>;
}

// ---------------------------------------------------------------------------
// Debug Emulation Service
// ---------------------------------------------------------------------------

/// Result of an emulation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationResult {
    /// The snapshot where emulated state is stored.
    pub snapshot: i64,
    /// The schedule at which emulation stopped.
    pub stopped_at: String,
    /// Whether emulation was interrupted.
    pub interrupted: bool,
    /// Error message, if any.
    pub error: Option<String>,
}

/// Service for emulation management.
///
/// Ported from Ghidra's `DebuggerEmulationService`.
pub trait DebugEmulationService {
    /// Emulate for a definite number of steps.
    fn emulate(
        &mut self,
        trace_key: &str,
        schedule: &str,
        steps: u64,
    ) -> DebugServiceResult<EmulationResult>;

    /// Run emulation until interrupted.
    fn run(&mut self, trace_key: &str, from_schedule: &str) -> DebugServiceResult<EmulationResult>;

    /// Stop emulation.
    fn stop(&mut self, trace_key: &str) -> DebugServiceResult<()>;

    /// Check if emulation is active.
    fn is_emulating(&self, trace_key: &str) -> bool;
}

// ---------------------------------------------------------------------------
// Debug Service Container
// ---------------------------------------------------------------------------

/// Container aggregating all debug service trait objects.
///
/// This is the main entry point for accessing debug services.
pub struct DebugServiceContainer {
    /// The trace key this container is associated with.
    pub trace_key: String,
    /// Whether services are initialized.
    pub initialized: bool,
}

impl DebugServiceContainer {
    /// Create a new service container for a trace.
    pub fn new(trace_key: impl Into<String>) -> Self {
        Self {
            trace_key: trace_key.into(),
            initialized: false,
        }
    }

    /// Initialize the services.
    pub fn initialize(&mut self) {
        self.initialized = true;
    }

    /// Check if services are initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Dispose the services.
    pub fn dispose(&mut self) {
        self.initialized = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_state() {
        let state = ExecutionState::default();
        assert_eq!(state, ExecutionState::Unknown);
        assert_ne!(ExecutionState::Running, ExecutionState::Stopped);
    }

    #[test]
    fn test_breakpoint_kind_bitmask() {
        let kinds = BreakpointKind::from_bitmask(0x09);
        assert!(kinds.contains(&BreakpointKind::SoftwareExecute));
        assert!(kinds.contains(&BreakpointKind::Write));
        assert!(!kinds.contains(&BreakpointKind::Read));

        assert_eq!(BreakpointKind::SoftwareExecute.to_bitmask(), 0x01);
        assert_eq!(BreakpointKind::HardwareExecute.to_bitmask(), 0x02);
    }

    #[test]
    fn test_breakpoint_info() {
        let mut kinds = BTreeSet::new();
        kinds.insert(BreakpointKind::SoftwareExecute);
        let bp = BreakpointInfo::new(0x400000, kinds);
        assert!(bp.is_software());
        assert!(!bp.is_hardware());
        assert!(!bp.is_watchpoint());
        assert!(bp.enabled);
        assert_eq!(bp.hit_count, 0);
    }

    #[test]
    fn test_breakpoint_info_watchpoint() {
        let mut kinds = BTreeSet::new();
        kinds.insert(BreakpointKind::Write);
        let bp = BreakpointInfo::new(0x500000, kinds);
        assert!(!bp.is_software());
        assert!(bp.is_watchpoint());
    }

    #[test]
    fn test_memory_region_info() {
        let region = MemoryRegionInfo::new(".text", 0x400000, 0x401000);
        assert_eq!(region.size(), 0x1001);
        assert!(region.contains(0x400500));
        assert!(!region.contains(0x300000));
        assert!(region.readable);
        assert!(!region.writable);
    }

    #[test]
    fn test_register_info() {
        let reg = RegisterInfo::new("RAX", 0x00, 8, "General");
        assert_eq!(reg.name, "RAX");
        assert_eq!(reg.size, 8);
        assert_eq!(reg.group, "General");
    }

    #[test]
    fn test_debug_coordinates() {
        let coords = DebugCoordinates::new("trace1", 42)
            .with_thread(1)
            .with_frame(0);
        assert_eq!(coords.trace_key, "trace1");
        assert_eq!(coords.snap, 42);
        assert_eq!(coords.thread_key, Some(1));
        assert_eq!(coords.frame, Some(0));
        assert!(coords.object_path.is_none());
    }

    #[test]
    fn test_debug_service_error_display() {
        let err = DebugServiceError::NotConnected;
        assert_eq!(format!("{}", err), "Not connected to target");

        let err = DebugServiceError::BackendError("timeout".into());
        assert!(format!("{}", err).contains("timeout"));
    }

    #[test]
    fn test_static_mapping_entry() {
        let entry = StaticMappingEntry {
            id: 1,
            trace_start: 0x400000,
            trace_end: 0x401000,
            program_url: "file:///test.gzf".into(),
            program_start: 0x1000,
            program_end: 0x2000,
            snap_start: 0,
            snap_end: i64::MAX,
        };

        assert_eq!(entry.program_to_trace(0x1500), Some(0x400500));
        assert_eq!(entry.trace_to_program(0x400500), Some(0x1500));
        assert_eq!(entry.program_to_trace(0x3000), None);
    }

    #[test]
    fn test_emulation_result() {
        let result = EmulationResult {
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
    fn test_console_level() {
        assert_ne!(ConsoleLevel::Info, ConsoleLevel::Error);
        assert_eq!(ConsoleLevel::StdOut, ConsoleLevel::StdOut);
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
    fn test_debug_service_container() {
        let mut container = DebugServiceContainer::new("trace1");
        assert!(!container.is_initialized());
        assert_eq!(container.trace_key, "trace1");

        container.initialize();
        assert!(container.is_initialized());

        container.dispose();
        assert!(!container.is_initialized());
    }

    #[test]
    fn test_execution_state_serde() {
        let state = ExecutionState::Running;
        let json = serde_json::to_string(&state).unwrap();
        let back: ExecutionState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }

    #[test]
    fn test_breakpoint_info_serde() {
        let mut kinds = BTreeSet::new();
        kinds.insert(BreakpointKind::SoftwareExecute);
        let bp = BreakpointInfo::new(0x400000, kinds);
        let json = serde_json::to_string(&bp).unwrap();
        let back: BreakpointInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.address, 0x400000);
        assert!(back.is_software());
    }
}
