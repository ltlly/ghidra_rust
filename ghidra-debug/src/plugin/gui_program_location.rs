//! Program location action context for the debugger.
//!
//! Ported from Ghidra's `DebuggerProgramLocationActionContext` and
//! `DebuggerGoToTrait`. Provides context for actions that operate on
//! specific program locations within the debugger listing.

use serde::{Deserialize, Serialize};

use crate::api::tracemgr::DebuggerCoordinates;

/// A program location within a debugger context.
///
/// Ported from Ghidra's `DebuggerProgramLocationActionContext`. Represents
/// a specific address in a program/trace that the user has navigated to
/// or that an action is targeting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramLocationContext {
    /// The trace ID.
    pub trace_id: String,
    /// The address offset.
    pub offset: u64,
    /// The address space name (e.g., "ram", "register").
    pub address_space: String,
    /// The snap (time).
    pub snap: i64,
    /// The thread key (if location is thread-specific).
    pub thread_key: Option<i64>,
    /// The frame level.
    pub frame_level: Option<i32>,
    /// Whether this location is in the current program.
    pub in_current_program: bool,
}

impl ProgramLocationContext {
    /// Create a new program location context.
    pub fn new(
        trace_id: impl Into<String>,
        offset: u64,
        address_space: impl Into<String>,
        snap: i64,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            offset,
            address_space: address_space.into(),
            snap,
            thread_key: None,
            frame_level: None,
            in_current_program: true,
        }
    }

    /// Set the thread context.
    pub fn with_thread(mut self, thread_key: i64) -> Self {
        self.thread_key = Some(thread_key);
        self
    }

    /// Set the frame level.
    pub fn with_frame(mut self, frame_level: i32) -> Self {
        self.frame_level = Some(frame_level);
        self
    }

    /// Whether this location is in RAM (vs. register space, etc.).
    pub fn is_ram_address(&self) -> bool {
        self.address_space == "ram" || self.address_space == "code"
    }

    /// Whether this location is a register.
    pub fn is_register(&self) -> bool {
        self.address_space == "register"
    }
}

impl ProgramLocationContext {
    /// Create from debugger coordinates (using trace_key as trace_id).
    pub fn from_coordinates(coords: &DebuggerCoordinates) -> Self {
        Self {
            trace_id: coords
                .trace_key
                .map(|k| k.to_string())
                .unwrap_or_default(),
            offset: 0,
            address_space: "ram".into(),
            snap: coords.snap.unwrap_or(0),
            thread_key: coords.thread_key,
            frame_level: coords.frame_level,
            in_current_program: true,
        }
    }
}

/// Go-to action trait for navigating to addresses in the debugger.
///
/// Ported from Ghidra's `DebuggerGoToTrait`.
pub trait GoToAction {
    /// Navigate to the given address offset.
    fn go_to_address(&mut self, offset: u64) -> Result<(), String>;

    /// Navigate to the given address in a specific space.
    fn go_to_address_in_space(&mut self, space: &str, offset: u64) -> Result<(), String>;

    /// Navigate to the current program counter.
    fn go_to_pc(&mut self) -> Result<(), String>;

    /// Navigate to a symbol by name.
    fn go_to_symbol(&mut self, name: &str) -> Result<(), String>;

    /// Get the current address.
    fn current_address(&self) -> Option<u64>;
}

/// A go-to action context combining address and program info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoToContext {
    /// The target offset.
    pub offset: u64,
    /// The address space.
    pub space: Option<String>,
    /// The program URL (if navigating to a static program).
    pub program_url: Option<String>,
    /// Whether to center the listing on this address.
    pub center: bool,
}

impl GoToContext {
    /// Create a go-to context for an offset.
    pub fn offset(offset: u64) -> Self {
        Self {
            offset,
            space: None,
            program_url: None,
            center: true,
        }
    }

    /// Create a go-to context for a space:offset.
    pub fn space_offset(space: impl Into<String>, offset: u64) -> Self {
        Self {
            offset,
            space: Some(space.into()),
            program_url: None,
            center: true,
        }
    }

    /// Set whether to center the listing.
    pub fn with_center(mut self, center: bool) -> Self {
        self.center = center;
        self
    }

    /// Set the target program.
    pub fn with_program(mut self, program_url: impl Into<String>) -> Self {
        self.program_url = Some(program_url.into());
        self
    }
}

/// The auto-read memory specification for the debugger listing.
///
/// Ported from Ghidra's `DebuggerAutoReadMemoryAction` and
/// `BasicAutoReadMemorySpec`. Controls whether the debugger automatically
/// reads memory when the listing scrolls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoReadMemorySpec {
    /// The spec name.
    pub name: String,
    /// Whether auto-read is enabled.
    pub enabled: bool,
    /// The maximum number of bytes to read at once.
    pub max_bytes: usize,
    /// The number of pages to read ahead.
    pub read_ahead_pages: usize,
}

impl AutoReadMemorySpec {
    /// Create a basic auto-read spec.
    pub fn basic() -> Self {
        Self {
            name: "Basic Auto-Read".into(),
            enabled: true,
            max_bytes: 65536,
            read_ahead_pages: 2,
        }
    }

    /// Create a disabled auto-read spec.
    pub fn none() -> Self {
        Self {
            name: "No Auto-Read".into(),
            enabled: false,
            max_bytes: 0,
            read_ahead_pages: 0,
        }
    }

    /// Whether this spec will perform reads.
    pub fn should_read(&self) -> bool {
        self.enabled && self.max_bytes > 0
    }
}

/// Tracks location changes in the debugger listing.
///
/// Ported from Ghidra's `DebuggerTrackLocationAction`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocationTracker {
    /// The current tracked address.
    pub current_address: Option<u64>,
    /// The tracking spec being used.
    pub spec_name: Option<String>,
    /// Whether tracking is active.
    pub active: bool,
    /// The last known snap.
    pub last_snap: Option<i64>,
}

impl LocationTracker {
    /// Create a new inactive tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Activate tracking with a spec.
    pub fn activate(&mut self, spec_name: impl Into<String>) {
        self.spec_name = Some(spec_name.into());
        self.active = true;
    }

    /// Deactivate tracking.
    pub fn deactivate(&mut self) {
        self.active = false;
        self.spec_name = None;
    }

    /// Update the tracked address.
    pub fn update(&mut self, address: u64, snap: i64) {
        self.current_address = Some(address);
        self.last_snap = Some(snap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_location_context() {
        let ctx = ProgramLocationContext::new("trace1", 0x400000, "ram", 0);
        assert_eq!(ctx.offset, 0x400000);
        assert!(ctx.is_ram_address());
        assert!(!ctx.is_register());
    }

    #[test]
    fn test_program_location_context_register() {
        let ctx = ProgramLocationContext::new("trace1", 0, "register", 0)
            .with_thread(42)
            .with_frame(1);
        assert!(ctx.is_register());
        assert_eq!(ctx.thread_key, Some(42));
        assert_eq!(ctx.frame_level, Some(1));
    }

    #[test]
    fn test_go_to_context() {
        let ctx = GoToContext::offset(0x400000);
        assert_eq!(ctx.offset, 0x400000);
        assert!(ctx.space.is_none());
        assert!(ctx.center);

        let ctx = GoToContext::space_offset("ram", 0x500000)
            .with_center(false)
            .with_program("/path/to/prog");
        assert_eq!(ctx.space, Some("ram".to_string()));
        assert!(!ctx.center);
        assert!(ctx.program_url.is_some());
    }

    #[test]
    fn test_auto_read_memory_spec() {
        let spec = AutoReadMemorySpec::basic();
        assert!(spec.should_read());
        assert_eq!(spec.max_bytes, 65536);

        let spec = AutoReadMemorySpec::none();
        assert!(!spec.should_read());
    }

    #[test]
    fn test_location_tracker() {
        let mut tracker = LocationTracker::new();
        assert!(!tracker.active);
        assert!(tracker.current_address.is_none());

        tracker.activate("PC Tracker");
        assert!(tracker.active);
        assert_eq!(tracker.spec_name, Some("PC Tracker".to_string()));

        tracker.update(0x400000, 5);
        assert_eq!(tracker.current_address, Some(0x400000));
        assert_eq!(tracker.last_snap, Some(5));

        tracker.deactivate();
        assert!(!tracker.active);
    }

    #[test]
    fn test_program_location_from_coordinates() {
        let coords = crate::api::tracemgr::DebuggerCoordinates {
            trace_key: Some(42),
            snap: Some(5),
            thread_key: Some(100),
            frame_level: Some(1),
            process_key: None,
        };
        let ctx = ProgramLocationContext::from_coordinates(&coords);
        assert_eq!(ctx.trace_id, "42");
        assert_eq!(ctx.snap, 5);
        assert_eq!(ctx.thread_key, Some(100));
        assert_eq!(ctx.frame_level, Some(1));
    }

    #[test]
    fn test_auto_read_memory_spec_serde() {
        let spec = AutoReadMemorySpec::basic();
        let json = serde_json::to_string(&spec).unwrap();
        let back: AutoReadMemorySpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "Basic Auto-Read");
        assert!(back.enabled);
    }

    #[test]
    fn test_location_tracker_serde() {
        let mut tracker = LocationTracker::new();
        tracker.activate("PC");
        tracker.update(0x400000, 0);
        let json = serde_json::to_string(&tracker).unwrap();
        let back: LocationTracker = serde_json::from_str(&json).unwrap();
        assert!(back.active);
        assert_eq!(back.current_address, Some(0x400000));
    }
}
