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
// Watch Expression Service
// ---------------------------------------------------------------------------

/// Display format for watch expression values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WatchFormat {
    /// Hexadecimal.
    Hex,
    /// Decimal.
    Decimal,
    /// Binary.
    Binary,
    /// Octal.
    Octal,
    /// ASCII character representation.
    Char,
    /// Floating point.
    Float,
    /// String.
    String,
    /// Auto-detect.
    Auto,
}

impl Default for WatchFormat {
    fn default() -> Self {
        Self::Hex
    }
}

/// A watch expression entry.
///
/// Ported from Ghidra's `DebuggerWatchesService`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchExpression {
    /// The expression string (e.g., register name, memory address).
    pub expression: String,
    /// The current value, if evaluated.
    pub current_value: Option<String>,
    /// The display format.
    pub format: WatchFormat,
    /// Whether this expression is enabled.
    pub enabled: bool,
    /// User-provided label.
    pub label: Option<String>,
}

impl WatchExpression {
    /// Create a new watch expression.
    pub fn new(expression: impl Into<String>) -> Self {
        Self {
            expression: expression.into(),
            current_value: None,
            format: WatchFormat::Hex,
            enabled: true,
            label: None,
        }
    }

    /// Create a watch expression with a specific format.
    pub fn with_format(expression: impl Into<String>, format: WatchFormat) -> Self {
        Self {
            format,
            ..Self::new(expression)
        }
    }

    /// Set the label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

/// Service for managing watch expressions.
///
/// Ported from Ghidra's `DebuggerWatchesService`.
pub trait DebugWatchesService {
    /// Add a watch expression.
    fn add_watch(&mut self, expression: WatchExpression);

    /// Remove a watch expression by index.
    fn remove_watch(&mut self, index: usize) -> DebugServiceResult<()>;

    /// Get all watch expressions.
    fn watches(&self) -> &[WatchExpression];

    /// Update the value of a watch expression.
    fn update_value(&mut self, index: usize, value: String);

    /// Clear all watch expressions.
    fn clear(&mut self);

    /// Set the format for a watch expression.
    fn set_format(&mut self, index: usize, format: WatchFormat);

    /// Toggle a watch expression on/off.
    fn toggle_watch(&mut self, index: usize);
}

// ---------------------------------------------------------------------------
// Platform Service
// ---------------------------------------------------------------------------

/// Information about an available debugger platform.
///
/// Ported from Ghidra's `DebuggerPlatformService`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformOffer {
    /// The platform name (e.g., "gdb", "lldb", "dbgeng").
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// The connector type identifier.
    pub connector_type: String,
    /// Supported architecture IDs.
    pub supported_languages: Vec<String>,
    /// Whether this platform can launch targets.
    pub can_launch: bool,
    /// Whether this platform can attach to running processes.
    pub can_attach: bool,
    /// Whether this platform supports connection to remote targets.
    pub can_connect_remote: bool,
}

impl PlatformOffer {
    /// Create a new platform offer.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        connector_type: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            connector_type: connector_type.into(),
            supported_languages: Vec::new(),
            can_launch: false,
            can_attach: false,
            can_connect_remote: false,
        }
    }
}

/// Platform opinion about what language/platform to use for a given target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformOpinion {
    /// The language ID.
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// The source of this opinion.
    pub source: String,
}

impl PlatformOpinion {
    /// Create a new platform opinion.
    pub fn new(
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
        confidence: f64,
        source: impl Into<String>,
    ) -> Self {
        Self {
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
            confidence,
            source: source.into(),
        }
    }
}

/// Service for managing debugger platform connections.
///
/// Ported from Ghidra's `DebuggerPlatformService`.
pub trait DebugPlatformService {
    /// Get available platform offers.
    fn available_platforms(&self) -> Vec<PlatformOffer>;

    /// Get opinions about what language to use for a target.
    fn get_opinions(
        &self,
        connector_type: &str,
        target_info: &str,
    ) -> Vec<PlatformOpinion>;

    /// Register a new platform offer.
    fn register_platform(&mut self, offer: PlatformOffer);

    /// Get the current platform for a connection.
    fn current_platform(&self, connection_key: i64) -> Option<&PlatformOffer>;
}

// ---------------------------------------------------------------------------
// Auto Mapping Service
// ---------------------------------------------------------------------------

/// Auto-mapping mode for program-to-trace mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AutoMapMode {
    /// No automatic mapping.
    None,
    /// Map by module name.
    ByModule,
    /// Map by section name.
    BySection,
    /// Map by region.
    ByRegion,
    /// One-to-one mapping.
    OneToOne,
}

impl Default for AutoMapMode {
    fn default() -> Self {
        Self::ByModule
    }
}

/// A single entry in an auto-mapping proposal.
///
/// Ported from Ghidra's `DebuggerAutoMappingService`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoMappingEntry {
    /// Program address range start.
    pub program_min: u64,
    /// Program address range end.
    pub program_max: u64,
    /// Trace address range start.
    pub trace_min: u64,
    /// Trace address range end.
    pub trace_max: u64,
    /// Start snap for this mapping.
    pub snap_start: i64,
    /// End snap for this mapping.
    pub snap_end: i64,
    /// The matched module/section name, if any.
    pub matched_name: Option<String>,
}

impl AutoMappingEntry {
    /// Create a new auto-mapping entry.
    pub fn new(
        program_min: u64,
        program_max: u64,
        trace_min: u64,
        trace_max: u64,
    ) -> Self {
        Self {
            program_min,
            program_max,
            trace_min,
            trace_max,
            snap_start: 0,
            snap_end: i64::MAX,
            matched_name: None,
        }
    }

    /// Set the matched name.
    pub fn with_matched_name(mut self, name: impl Into<String>) -> Self {
        self.matched_name = Some(name.into());
        self
    }
}

/// A proposal for automatically mapping a program to a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoMappingProposal {
    /// The program URL.
    pub program_url: String,
    /// The trace key.
    pub trace_key: String,
    /// Proposed address mappings.
    pub entries: Vec<AutoMappingEntry>,
    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,
}

impl AutoMappingProposal {
    /// Create a new auto-mapping proposal.
    pub fn new(
        program_url: impl Into<String>,
        trace_key: impl Into<String>,
        confidence: f64,
    ) -> Self {
        Self {
            program_url: program_url.into(),
            trace_key: trace_key.into(),
            entries: Vec::new(),
            confidence,
        }
    }

    /// Add an entry to the proposal.
    pub fn add_entry(&mut self, entry: AutoMappingEntry) {
        self.entries.push(entry);
    }
}

/// Service for automatic mapping between programs and traces.
///
/// Ported from Ghidra's `DebuggerAutoMappingService`.
pub trait DebugAutoMappingService {
    /// Propose automatic mappings for a program.
    fn propose_mappings(
        &self,
        program_url: &str,
        trace_key: &str,
    ) -> Vec<AutoMappingProposal>;

    /// Execute a mapping proposal.
    fn execute_mapping(&mut self, proposal: &AutoMappingProposal) -> DebugServiceResult<()>;

    /// Auto-map all open programs to a trace.
    fn auto_map_all(&mut self, trace_key: &str) -> DebugServiceResult<Vec<AutoMappingProposal>>;

    /// Get the current auto-map mode.
    fn auto_map_mode(&self) -> AutoMapMode;

    /// Set the auto-map mode.
    fn set_auto_map_mode(&mut self, mode: AutoMapMode);
}

// ---------------------------------------------------------------------------
// Debug Process Service
// ---------------------------------------------------------------------------

/// Information about a debug process.
///
/// Ported from Ghidra's process management in `ghidra.debug.api.process`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// The process ID.
    pub pid: i64,
    /// The process name.
    pub name: String,
    /// The user running the process.
    pub user: Option<String>,
    /// The command line.
    pub command_line: Option<String>,
    /// When the process was created (millis since epoch).
    pub created_at: i64,
}

impl ProcessInfo {
    /// Create a new process info.
    pub fn new(pid: i64, name: impl Into<String>) -> Self {
        Self {
            pid,
            name: name.into(),
            user: None,
            command_line: None,
            created_at: 0,
        }
    }

    /// Set the user.
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Set the command line.
    pub fn with_command_line(mut self, cmd: impl Into<String>) -> Self {
        self.command_line = Some(cmd.into());
        self
    }
}

/// Information about a thread within a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadInfo {
    /// The thread ID.
    pub tid: i64,
    /// The owning process ID.
    pub pid: i64,
    /// The thread name.
    pub name: String,
    /// Whether the thread is currently running.
    pub running: bool,
}

impl ThreadInfo {
    /// Create a new thread info.
    pub fn new(tid: i64, pid: i64, name: impl Into<String>) -> Self {
        Self {
            tid,
            pid,
            name: name.into(),
            running: false,
        }
    }
}

/// Service for process and thread management.
///
/// Ported from Ghidra's `DebuggerProcessService`.
pub trait DebugProcessService {
    /// List all processes on the target.
    fn list_processes(&self, trace_key: &str) -> DebugServiceResult<Vec<ProcessInfo>>;

    /// List all threads in a process.
    fn list_threads(&self, trace_key: &str, pid: i64) -> DebugServiceResult<Vec<ThreadInfo>>;

    /// Get the current process info.
    fn current_process(&self, trace_key: &str) -> DebugServiceResult<Option<ProcessInfo>>;

    /// Get the current thread info.
    fn current_thread(&self, trace_key: &str) -> DebugServiceResult<Option<ThreadInfo>>;

    /// Select a thread as the active context.
    fn select_thread(&mut self, trace_key: &str, tid: i64) -> DebugServiceResult<()>;

    /// Get the execution state of a specific thread.
    fn thread_state(&self, trace_key: &str, tid: i64) -> ExecutionState;
}

// ---------------------------------------------------------------------------
// Debug Source Service
// ---------------------------------------------------------------------------

/// Source file location information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLocation {
    /// The file path.
    pub file: String,
    /// The line number (1-based).
    pub line: u32,
    /// The column number (1-based, 0 = unknown).
    pub column: u32,
    /// The function name, if known.
    pub function: Option<String>,
}

impl SourceLocation {
    /// Create a new source location.
    pub fn new(file: impl Into<String>, line: u32) -> Self {
        Self {
            file: file.into(),
            line,
            column: 0,
            function: None,
        }
    }

    /// Set the column.
    pub fn with_column(mut self, column: u32) -> Self {
        self.column = column;
        self
    }

    /// Set the function name.
    pub fn with_function(mut self, function: impl Into<String>) -> Self {
        self.function = Some(function.into());
        self
    }
}

/// Service for source-level debugging.
///
/// Ported from Ghidra's `DebuggerSourceService`.
pub trait DebugSourceService {
    /// Get the source location for a trace address.
    fn source_location_for_address(
        &self,
        trace_key: &str,
        address: u64,
    ) -> DebugServiceResult<Option<SourceLocation>>;

    /// Get the trace address for a source location.
    fn address_for_source_location(
        &self,
        trace_key: &str,
        file: &str,
        line: u32,
    ) -> DebugServiceResult<Option<u64>>;

    /// Get available source files.
    fn source_files(&self, trace_key: &str) -> DebugServiceResult<Vec<String>>;

    /// Step to the next source line.
    fn step_to_source_line(
        &mut self,
        trace_key: &str,
        file: &str,
        line: u32,
    ) -> DebugServiceResult<()>;
}

// ---------------------------------------------------------------------------
// Debug Stack Service
// ---------------------------------------------------------------------------

/// A stack frame in a call stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrameInfo {
    /// The frame level (0 = top of stack).
    pub level: u32,
    /// The program counter address.
    pub pc: u64,
    /// The stack pointer address.
    pub sp: u64,
    /// The frame pointer address.
    pub fp: u64,
    /// The function name, if known.
    pub function: Option<String>,
    /// The source location, if available.
    pub source: Option<SourceLocation>,
    /// Whether this frame belongs to library (non-user) code.
    pub is_library: bool,
}

impl StackFrameInfo {
    /// Create a new stack frame info.
    pub fn new(level: u32, pc: u64, sp: u64) -> Self {
        Self {
            level,
            pc,
            sp,
            fp: 0,
            function: None,
            source: None,
            is_library: false,
        }
    }

    /// Set the function name.
    pub fn with_function(mut self, function: impl Into<String>) -> Self {
        self.function = Some(function.into());
        self
    }

    /// Set the source location.
    pub fn with_source(mut self, source: SourceLocation) -> Self {
        self.source = Some(source);
        self
    }

    /// Set the frame pointer.
    pub fn with_fp(mut self, fp: u64) -> Self {
        self.fp = fp;
        self
    }
}

/// Service for call stack management.
///
/// Ported from Ghidra's `DebuggerStackService`.
pub trait DebugStackService {
    /// Get the call stack for a thread.
    fn get_call_stack(
        &self,
        trace_key: &str,
        thread_key: i64,
    ) -> DebugServiceResult<Vec<StackFrameInfo>>;

    /// Get the current frame for a thread.
    fn current_frame(
        &self,
        trace_key: &str,
        thread_key: i64,
    ) -> DebugServiceResult<Option<StackFrameInfo>>;

    /// Select a stack frame.
    fn select_frame(
        &mut self,
        trace_key: &str,
        thread_key: i64,
        frame_level: u32,
    ) -> DebugServiceResult<()>;

    /// Get the number of frames in the stack.
    fn frame_count(&self, trace_key: &str, thread_key: i64) -> DebugServiceResult<u32>;
}

// ---------------------------------------------------------------------------
// Debug Variable Service
// ---------------------------------------------------------------------------

/// Information about a local variable or parameter.
///
/// Ported from Ghidra's `DebuggerVariableService`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableInfo {
    /// The variable name.
    pub name: String,
    /// The data type (e.g., "int", "char*", "struct foo").
    pub data_type: String,
    /// The size in bytes.
    pub size: u32,
    /// Whether this is a parameter or local.
    pub is_parameter: bool,
    /// The storage location: register name or stack offset.
    pub storage: VariableStorage,
    /// The current value, if available.
    pub current_value: Option<String>,
    /// The display format.
    pub format: WatchFormat,
}

/// The storage location of a variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VariableStorage {
    /// Stored in a register.
    Register(String),
    /// Stored on the stack at the given offset from the frame pointer.
    Stack(i64),
    /// Stored at a memory address.
    Memory(u64),
    /// No storage (optimized out or not yet available).
    None,
}

impl VariableInfo {
    /// Create a new variable info.
    pub fn new(
        name: impl Into<String>,
        data_type: impl Into<String>,
        size: u32,
        is_parameter: bool,
        storage: VariableStorage,
    ) -> Self {
        Self {
            name: name.into(),
            data_type: data_type.into(),
            size,
            is_parameter,
            storage,
            current_value: None,
            format: WatchFormat::default(),
        }
    }
}

/// Service for local variable inspection.
pub trait DebugVariableService {
    /// Get variables for a stack frame.
    fn get_variables(
        &self,
        trace_key: &str,
        thread_key: i64,
        frame_level: u32,
    ) -> DebugServiceResult<Vec<VariableInfo>>;

    /// Get the value of a variable.
    fn get_variable_value(
        &self,
        trace_key: &str,
        thread_key: i64,
        frame_level: u32,
        variable_name: &str,
    ) -> DebugServiceResult<Option<String>>;

    /// Set the value of a variable.
    fn set_variable_value(
        &mut self,
        trace_key: &str,
        thread_key: i64,
        frame_level: u32,
        variable_name: &str,
        value: &str,
    ) -> DebugServiceResult<()>;
}

// ---------------------------------------------------------------------------
// Debug Snap Service
// ---------------------------------------------------------------------------

/// Information about a snapshot in the trace.
///
/// Ported from Ghidra's snapshot management in `ghidra.trace.model.TraceSnapshot`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapInfo {
    /// The snap value.
    pub snap: i64,
    /// A description of the snap.
    pub description: String,
    /// The creation timestamp.
    pub timestamp: i64,
    /// The thread key associated with this snap (if any).
    pub thread_key: Option<i64>,
    /// The program counter at this snap.
    pub pc: Option<u64>,
    /// Whether this snap was created by a user action.
    pub user_created: bool,
}

impl SnapInfo {
    /// Create a new snap info.
    pub fn new(snap: i64, description: impl Into<String>) -> Self {
        Self {
            snap,
            description: description.into(),
            timestamp: 0,
            thread_key: None,
            pc: None,
            user_created: false,
        }
    }

    /// Mark this snap as user-created.
    pub fn with_user_created(mut self) -> Self {
        self.user_created = true;
        self
    }

    /// Set the thread key.
    pub fn with_thread_key(mut self, thread_key: i64) -> Self {
        self.thread_key = Some(thread_key);
        self
    }

    /// Set the program counter.
    pub fn with_pc(mut self, pc: u64) -> Self {
        self.pc = Some(pc);
        self
    }
}

/// Service for managing trace snapshots and time navigation.
///
/// Ported from Ghidra's `DebuggerSnapService`.
pub trait DebugSnapService {
    /// Get all snaps in a trace.
    fn get_snaps(&self, trace_key: &str) -> DebugServiceResult<Vec<SnapInfo>>;

    /// Get a specific snap.
    fn get_snap(&self, trace_key: &str, snap: i64) -> DebugServiceResult<Option<SnapInfo>>;

    /// Create a new snapshot.
    fn create_snap(
        &mut self,
        trace_key: &str,
        description: &str,
    ) -> DebugServiceResult<i64>;

    /// Get the minimum snap.
    fn min_snap(&self, trace_key: &str) -> DebugServiceResult<i64>;

    /// Get the maximum snap.
    fn max_snap(&self, trace_key: &str) -> DebugServiceResult<i64>;

    /// Get the number of snaps.
    fn snap_count(&self, trace_key: &str) -> DebugServiceResult<usize>;

    /// Delete a snapshot.
    fn delete_snap(&mut self, trace_key: &str, snap: i64) -> DebugServiceResult<()>;
}

// ---------------------------------------------------------------------------
// Debug Model Service
// ---------------------------------------------------------------------------

/// A schema definition for trace objects.
///
/// Ported from Ghidra's `TraceObjectSchema` in the object model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSchema {
    /// The schema name.
    pub name: String,
    /// The schema version.
    pub version: u32,
    /// The set of attribute names with their types.
    pub attributes: BTreeMap<String, String>,
    /// The set of link names with their target schema names.
    pub links: BTreeMap<String, String>,
    /// Whether this schema can be deleted.
    pub deletable: bool,
}

impl ModelSchema {
    /// Create a new model schema.
    pub fn new(name: impl Into<String>, version: u32) -> Self {
        Self {
            name: name.into(),
            version,
            attributes: BTreeMap::new(),
            links: BTreeMap::new(),
            deletable: true,
        }
    }

    /// Add an attribute definition.
    pub fn add_attribute(&mut self, name: impl Into<String>, type_name: impl Into<String>) {
        self.attributes.insert(name.into(), type_name.into());
    }

    /// Add a link definition.
    pub fn add_link(&mut self, name: impl Into<String>, target_schema: impl Into<String>) {
        self.links.insert(name.into(), target_schema.into());
    }
}

/// Service for the trace object model.
///
/// Ported from Ghidra's `DebuggerModelService`.
pub trait DebugModelService {
    /// Get all registered schema names.
    fn schema_names(&self, trace_key: &str) -> DebugServiceResult<Vec<String>>;

    /// Get a specific schema.
    fn get_schema(&self, trace_key: &str, name: &str) -> DebugServiceResult<Option<ModelSchema>>;

    /// Register a new schema.
    fn register_schema(&mut self, trace_key: &str, schema: ModelSchema) -> DebugServiceResult<()>;

    /// Get the root object path.
    fn root_path(&self, trace_key: &str) -> DebugServiceResult<String>;

    /// List children of an object path.
    fn list_children(
        &self,
        trace_key: &str,
        path: &str,
    ) -> DebugServiceResult<Vec<String>>;
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

    #[test]
    fn test_watch_format() {
        assert_eq!(WatchFormat::default(), WatchFormat::Hex);
        assert_ne!(WatchFormat::Hex, WatchFormat::Decimal);
        assert_ne!(WatchFormat::Binary, WatchFormat::Float);
    }

    #[test]
    fn test_watch_expression() {
        let expr = WatchExpression::new("RAX");
        assert_eq!(expr.expression, "RAX");
        assert!(expr.enabled);
        assert_eq!(expr.format, WatchFormat::Hex);
        assert!(expr.label.is_none());
        assert!(expr.current_value.is_none());
    }

    #[test]
    fn test_watch_expression_builder() {
        let expr = WatchExpression::with_format("RSP", WatchFormat::Decimal)
            .with_label("Stack Pointer");
        assert_eq!(expr.format, WatchFormat::Decimal);
        assert_eq!(expr.label.as_deref(), Some("Stack Pointer"));
    }

    #[test]
    fn test_watch_expression_serde() {
        let expr = WatchExpression::new("RAX");
        let json = serde_json::to_string(&expr).unwrap();
        let back: WatchExpression = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expression, "RAX");
    }

    #[test]
    fn test_platform_offer() {
        let offer = PlatformOffer::new("gdb", "GNU Debugger", "gdb-remote");
        assert_eq!(offer.name, "gdb");
        assert_eq!(offer.connector_type, "gdb-remote");
        assert!(!offer.can_launch);
    }

    #[test]
    fn test_platform_offer_serde() {
        let offer = PlatformOffer::new("lldb", "LLDB Debugger", "lldb-remote");
        let json = serde_json::to_string(&offer).unwrap();
        let back: PlatformOffer = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "lldb");
    }

    #[test]
    fn test_platform_opinion() {
        let opinion = PlatformOpinion::new(
            "x86:LE:64:default",
            "default",
            0.9,
            "ELF header",
        );
        assert_eq!(opinion.language_id, "x86:LE:64:default");
        assert!(opinion.confidence > 0.5);
    }

    #[test]
    fn test_auto_map_mode() {
        assert_eq!(AutoMapMode::default(), AutoMapMode::ByModule);
        assert_ne!(AutoMapMode::None, AutoMapMode::ByModule);
        assert_ne!(AutoMapMode::BySection, AutoMapMode::OneToOne);
    }

    #[test]
    fn test_auto_mapping_entry() {
        let entry = AutoMappingEntry::new(0, 0x1000, 0x400000, 0x401000)
            .with_matched_name(".text");
        assert_eq!(entry.program_min, 0);
        assert_eq!(entry.trace_max, 0x401000);
        assert_eq!(entry.matched_name.as_deref(), Some(".text"));
        assert_eq!(entry.snap_end, i64::MAX);
    }

    #[test]
    fn test_auto_mapping_entry_serde() {
        let entry = AutoMappingEntry::new(0, 0x1000, 0x400000, 0x401000);
        let json = serde_json::to_string(&entry).unwrap();
        let back: AutoMappingEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.program_min, 0);
    }

    #[test]
    fn test_auto_mapping_proposal() {
        let mut proposal = AutoMappingProposal::new("file:///test.gzf", "trace1", 0.95);
        assert_eq!(proposal.confidence, 0.95);
        assert!(proposal.entries.is_empty());

        proposal.add_entry(AutoMappingEntry::new(0, 0x1000, 0x400000, 0x401000));
        assert_eq!(proposal.entries.len(), 1);
    }

    #[test]
    fn test_auto_mapping_proposal_serde() {
        let proposal = AutoMappingProposal::new("file:///test.gzf", "trace1", 0.9);
        let json = serde_json::to_string(&proposal).unwrap();
        let back: AutoMappingProposal = serde_json::from_str(&json).unwrap();
        assert_eq!(back.program_url, "file:///test.gzf");
    }

    #[test]
    fn test_process_info() {
        let proc = ProcessInfo::new(1234, "target")
            .with_user("root")
            .with_command_line("/usr/bin/target --arg");
        assert_eq!(proc.pid, 1234);
        assert_eq!(proc.name, "target");
        assert_eq!(proc.user.as_deref(), Some("root"));
        assert_eq!(proc.command_line.as_deref(), Some("/usr/bin/target --arg"));
    }

    #[test]
    fn test_process_info_serde() {
        let proc = ProcessInfo::new(42, "test");
        let json = serde_json::to_string(&proc).unwrap();
        let back: ProcessInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pid, 42);
        assert_eq!(back.name, "test");
    }

    #[test]
    fn test_thread_info() {
        let thread = ThreadInfo::new(100, 1234, "main");
        assert_eq!(thread.tid, 100);
        assert_eq!(thread.pid, 1234);
        assert_eq!(thread.name, "main");
        assert!(!thread.running);
    }

    #[test]
    fn test_thread_info_serde() {
        let thread = ThreadInfo::new(1, 2, "worker");
        let json = serde_json::to_string(&thread).unwrap();
        let back: ThreadInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tid, 1);
    }

    #[test]
    fn test_source_location() {
        let loc = SourceLocation::new("main.c", 42)
            .with_column(10)
            .with_function("main");
        assert_eq!(loc.file, "main.c");
        assert_eq!(loc.line, 42);
        assert_eq!(loc.column, 10);
        assert_eq!(loc.function.as_deref(), Some("main"));
    }

    #[test]
    fn test_source_location_serde() {
        let loc = SourceLocation::new("test.rs", 1);
        let json = serde_json::to_string(&loc).unwrap();
        let back: SourceLocation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.file, "test.rs");
        assert_eq!(back.line, 1);
    }

    #[test]
    fn test_stack_frame_info() {
        let frame = StackFrameInfo::new(0, 0x400000, 0x7fff0000)
            .with_function("main")
            .with_fp(0x7fff1000)
            .with_source(SourceLocation::new("main.c", 10));
        assert_eq!(frame.level, 0);
        assert_eq!(frame.pc, 0x400000);
        assert_eq!(frame.sp, 0x7fff0000);
        assert_eq!(frame.fp, 0x7fff1000);
        assert_eq!(frame.function.as_deref(), Some("main"));
        assert!(frame.source.is_some());
        assert!(!frame.is_library);
    }

    #[test]
    fn test_stack_frame_info_serde() {
        let frame = StackFrameInfo::new(1, 0x1000, 0x2000);
        let json = serde_json::to_string(&frame).unwrap();
        let back: StackFrameInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.level, 1);
        assert_eq!(back.pc, 0x1000);
    }

    #[test]
    fn test_variable_info() {
        let var = VariableInfo::new(
            "count",
            "int",
            4,
            false,
            VariableStorage::Register("eax".into()),
        );
        assert_eq!(var.name, "count");
        assert_eq!(var.data_type, "int");
        assert_eq!(var.size, 4);
        assert!(!var.is_parameter);
        assert!(matches!(&var.storage, VariableStorage::Register(r) if r == "eax"));
    }

    #[test]
    fn test_variable_info_parameter() {
        let var = VariableInfo::new(
            "argc",
            "int",
            4,
            true,
            VariableStorage::Stack(-8),
        );
        assert!(var.is_parameter);
        assert!(matches!(&var.storage, VariableStorage::Stack(-8)));
    }

    #[test]
    fn test_variable_storage_serde() {
        let reg = VariableStorage::Register("rax".into());
        let json = serde_json::to_string(&reg).unwrap();
        let back: VariableStorage = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, VariableStorage::Register(r) if r == "rax"));

        let stack = VariableStorage::Stack(16);
        let json = serde_json::to_string(&stack).unwrap();
        let back: VariableStorage = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, VariableStorage::Stack(16)));

        let mem = VariableStorage::Memory(0x400000);
        let json = serde_json::to_string(&mem).unwrap();
        let back: VariableStorage = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, VariableStorage::Memory(0x400000)));
    }

    #[test]
    fn test_variable_info_serde() {
        let var = VariableInfo::new("x", "int", 4, false, VariableStorage::None);
        let json = serde_json::to_string(&var).unwrap();
        let back: VariableInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "x");
    }

    #[test]
    fn test_snap_info() {
        let snap = SnapInfo::new(42, "Initial state")
            .with_user_created();
        assert_eq!(snap.snap, 42);
        assert_eq!(snap.description, "Initial state");
    }

    #[test]
    fn test_snap_info_serde() {
        let snap = SnapInfo::new(0, "start");
        let json = serde_json::to_string(&snap).unwrap();
        let back: SnapInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.snap, 0);
        assert_eq!(back.description, "start");
    }

    #[test]
    fn test_model_schema() {
        let mut schema = ModelSchema::new("Process", 1);
        schema.add_attribute("pid", "int");
        schema.add_attribute("name", "string");
        schema.add_link("threads", "Thread");

        assert_eq!(schema.name, "Process");
        assert_eq!(schema.version, 1);
        assert_eq!(schema.attributes.len(), 2);
        assert_eq!(schema.links.len(), 1);
        assert!(schema.deletable);
    }

    #[test]
    fn test_model_schema_serde() {
        let schema = ModelSchema::new("Test", 2);
        let json = serde_json::to_string(&schema).unwrap();
        let back: ModelSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "Test");
        assert_eq!(back.version, 2);
    }
}
