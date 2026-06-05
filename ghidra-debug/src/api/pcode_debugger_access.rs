//! PcodeDebuggerAccess - trace-and-debugger access shim for p-code emulation.
//!
//! Ported from Ghidra's `PcodeDebuggerAccess`, `PcodeDebuggerMemoryAccess`,
//! `PcodeDebuggerRegistersAccess`, and related types in
//! `ghidra.debug.api.emulation`.
//!
//! Provides the access interface for p-code executor states to read and
//! write trace data during emulation, combining trace coordinates with
//! debugger session context.

use serde::{Deserialize, Serialize};

/// The access scope for a p-code data access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessScope {
    /// Access shared state (memory, properties).
    Shared,
    /// Access local state (registers for a specific thread/frame).
    Local,
}

/// Describes the coordinates of a p-code access into a trace.
///
/// Ported from Ghidra's `PcodeTraceAccess` interface concept.
/// Encapsulates the snap, thread, and frame for trace data access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeTraceCoordinates {
    /// The snap (time point) being accessed.
    pub snap: i64,
    /// The thread ID being accessed (for register access).
    pub thread_id: Option<u64>,
    /// The frame level (0 = innermost).
    pub frame_level: u32,
}

impl PcodeTraceCoordinates {
    /// Create coordinates for shared state access (no thread context).
    pub fn shared(snap: i64) -> Self {
        Self {
            snap,
            thread_id: None,
            frame_level: 0,
        }
    }

    /// Create coordinates for local state access.
    pub fn local(snap: i64, thread_id: u64, frame_level: u32) -> Self {
        Self {
            snap,
            thread_id: Some(thread_id),
            frame_level,
        }
    }

    /// Whether these coordinates include thread context.
    pub fn has_thread(&self) -> bool {
        self.thread_id.is_some()
    }

    /// The access scope.
    pub fn scope(&self) -> AccessScope {
        if self.thread_id.is_some() {
            AccessScope::Local
        } else {
            AccessScope::Shared
        }
    }
}

/// Memory access data for p-code emulation.
///
/// Ported from Ghidra's `PcodeDebuggerMemoryAccess` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeMemoryAccess {
    /// The coordinates for this access.
    pub coordinates: PcodeTraceCoordinates,
    /// Address space name (e.g., "ram", "register").
    pub space_name: String,
}

impl PcodeMemoryAccess {
    /// Create a new memory access.
    pub fn new(coordinates: PcodeTraceCoordinates, space_name: impl Into<String>) -> Self {
        Self {
            coordinates,
            space_name: space_name.into(),
        }
    }

    /// Create a memory access for the default "ram" space.
    pub fn ram(snap: i64) -> Self {
        Self::new(PcodeTraceCoordinates::shared(snap), "ram")
    }

    /// Create a register space access for a specific thread.
    pub fn registers(snap: i64, thread_id: u64, frame_level: u32) -> Self {
        Self::new(
            PcodeTraceCoordinates::local(snap, thread_id, frame_level),
            "register",
        )
    }
}

/// Register access data for p-code emulation.
///
/// Ported from Ghidra's `PcodeDebuggerRegistersAccess` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeRegistersAccess {
    /// The coordinates for this access.
    pub coordinates: PcodeTraceCoordinates,
    /// The register space name.
    pub space_name: String,
    /// Cached register values (register name -> value bytes).
    pub cached_values: indexmap::IndexMap<String, Vec<u8>>,
}

impl PcodeRegistersAccess {
    /// Create a new register access.
    pub fn new(snap: i64, thread_id: u64, frame_level: u32) -> Self {
        Self {
            coordinates: PcodeTraceCoordinates::local(snap, thread_id, frame_level),
            space_name: "register".into(),
            cached_values: indexmap::IndexMap::new(),
        }
    }

    /// Cache a register value.
    pub fn set_cached(&mut self, name: impl Into<String>, value: Vec<u8>) {
        self.cached_values.insert(name.into(), value);
    }

    /// Get a cached register value.
    pub fn get_cached(&self, name: &str) -> Option<&[u8]> {
        self.cached_values.get(name).map(|v| v.as_slice())
    }

    /// Clear the register cache.
    pub fn clear_cache(&mut self) {
        self.cached_values.clear();
    }

    /// The number of cached registers.
    pub fn cached_count(&self) -> usize {
        self.cached_values.len()
    }
}

/// The top-level debugger access interface for p-code emulation.
///
/// Ported from Ghidra's `PcodeDebuggerAccess` interface. Combines
/// trace coordinates with debugger session context for data access
/// during p-code emulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeDebuggerAccess {
    /// The base coordinates.
    pub coordinates: PcodeTraceCoordinates,
    /// Whether the session is currently active.
    pub session_active: bool,
    /// The program URL of the currently mapped program, if any.
    pub program_url: Option<String>,
}

impl PcodeDebuggerAccess {
    /// Create a new debugger access.
    pub fn new(snap: i64) -> Self {
        Self {
            coordinates: PcodeTraceCoordinates::shared(snap),
            session_active: true,
            program_url: None,
        }
    }

    /// Create a debugger access for local (thread) state.
    pub fn for_thread(snap: i64, thread_id: u64, frame_level: u32) -> Self {
        Self {
            coordinates: PcodeTraceCoordinates::local(snap, thread_id, frame_level),
            session_active: true,
            program_url: None,
        }
    }

    /// Get memory access for shared state.
    pub fn get_data_for_shared_state(&self) -> PcodeMemoryAccess {
        PcodeMemoryAccess::new(
            PcodeTraceCoordinates::shared(self.coordinates.snap),
            "ram",
        )
    }

    /// Get register access for a specific thread and frame.
    pub fn get_data_for_local_state(
        &self,
        thread_id: u64,
        frame_level: u32,
    ) -> PcodeRegistersAccess {
        PcodeRegistersAccess::new(self.coordinates.snap, thread_id, frame_level)
    }

    /// Set the program URL for static image access.
    pub fn with_program_url(mut self, url: impl Into<String>) -> Self {
        self.program_url = Some(url.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coordinates_shared() {
        let coords = PcodeTraceCoordinates::shared(5);
        assert_eq!(coords.snap, 5);
        assert!(!coords.has_thread());
        assert_eq!(coords.scope(), AccessScope::Shared);
    }

    #[test]
    fn test_coordinates_local() {
        let coords = PcodeTraceCoordinates::local(10, 42, 0);
        assert_eq!(coords.snap, 10);
        assert!(coords.has_thread());
        assert_eq!(coords.thread_id, Some(42));
        assert_eq!(coords.scope(), AccessScope::Local);
    }

    #[test]
    fn test_memory_access_ram() {
        let access = PcodeMemoryAccess::ram(5);
        assert_eq!(access.space_name, "ram");
        assert_eq!(access.coordinates.snap, 5);
    }

    #[test]
    fn test_memory_access_registers() {
        let access = PcodeMemoryAccess::registers(10, 1, 0);
        assert_eq!(access.space_name, "register");
        assert!(access.coordinates.has_thread());
    }

    #[test]
    fn test_registers_access() {
        let mut access = PcodeRegistersAccess::new(5, 1, 0);
        access.set_cached("RAX", vec![0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0]);
        assert_eq!(access.cached_count(), 1);

        let val = access.get_cached("RAX").unwrap();
        assert_eq!(val.len(), 8);

        assert!(access.get_cached("RBX").is_none());

        access.clear_cache();
        assert_eq!(access.cached_count(), 0);
    }

    #[test]
    fn test_debugger_access_shared() {
        let access = PcodeDebuggerAccess::new(5);
        assert_eq!(access.coordinates.snap, 5);
        assert!(access.session_active);

        let shared = access.get_data_for_shared_state();
        assert_eq!(shared.space_name, "ram");
    }

    #[test]
    fn test_debugger_access_local() {
        let access = PcodeDebuggerAccess::for_thread(10, 1, 0);
        let regs = access.get_data_for_local_state(1, 0);
        assert_eq!(regs.space_name, "register");
    }

    #[test]
    fn test_debugger_access_program_url() {
        let access = PcodeDebuggerAccess::new(5)
            .with_program_url("file:///path/to/program");
        assert_eq!(access.program_url.as_deref(), Some("file:///path/to/program"));
    }

    #[test]
    fn test_access_scope_enum() {
        assert_ne!(AccessScope::Shared, AccessScope::Local);
    }

    #[test]
    fn test_debugger_access_serde() {
        let access = PcodeDebuggerAccess::new(5);
        let json = serde_json::to_string(&access).unwrap();
        let back: PcodeDebuggerAccess = serde_json::from_str(&json).unwrap();
        assert_eq!(back.coordinates.snap, 5);
    }
}
