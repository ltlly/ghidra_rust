//! Flat (scripting) RMI API for debugger operations.
//!
//! Ported from Ghidra's `FlatDebuggerRmiAPI`.
//!
//! Provides a simplified scripting interface that wraps the full
//! debugger API, intended for use by RMI clients and automated scripts.

use crate::api::breakpoint::LogicalBreakpoint;
use crate::api::flat_api::{FlatApiResult, ProgramLocation};
use crate::api::tracemgr::DebuggerCoordinates;

/// The flat RMI API provides a high-level scripting interface
/// specifically for RMI (Remote Method Invocation) clients.
///
/// Unlike the full `FlatDebuggerApi`, this is designed for remote
/// invocations where operations may cross process boundaries.
pub trait FlatDebuggerRmiApi {
    /// Get the current coordinates (trace, snap, thread, frame).
    fn current_coordinates(&self) -> &DebuggerCoordinates;

    /// Set the current coordinates.
    fn set_coordinates(&mut self, coords: DebuggerCoordinates);

    /// Get the current trace key.
    fn current_trace_key(&self) -> Option<i64>;

    /// Get the current snap.
    fn current_snap(&self) -> Option<i64>;

    /// Get the current thread ID.
    fn current_thread_id(&self) -> Option<u64>;

    /// Go to a specific address in the listing.
    fn go_to_address(&mut self, offset: u64) -> FlatApiResult<()>;

    /// Get the current program location.
    fn get_current_location(&self) -> Option<ProgramLocation>;

    /// Set a breakpoint at the given address.
    fn set_breakpoint(&mut self, offset: u64) -> FlatApiResult<LogicalBreakpoint>;

    /// Delete a breakpoint at the given address.
    fn delete_breakpoint(&mut self, offset: u64) -> FlatApiResult<()>;

    /// Get all breakpoints.
    fn get_breakpoints(&self) -> Vec<LogicalBreakpoint>;

    /// Step the debugger by one instruction.
    fn step_into(&mut self) -> FlatApiResult<()>;

    /// Step over the current instruction.
    fn step_over(&mut self) -> FlatApiResult<()>;

    /// Continue execution until the next breakpoint.
    fn resume(&mut self) -> FlatApiResult<()>;

    /// Pause execution.
    fn pause(&mut self) -> FlatApiResult<()>;

    /// Read memory from the current trace.
    fn read_memory(&self, offset: u64, len: u32) -> FlatApiResult<Vec<u8>>;

    /// Write memory to the current trace.
    fn write_memory(&mut self, offset: u64, data: &[u8]) -> FlatApiResult<()>;

    /// Read a register value by name.
    fn read_register(&self, name: &str) -> FlatApiResult<Vec<u8>>;

    /// Write a register value by name.
    fn write_register(&mut self, name: &str, data: &[u8]) -> FlatApiResult<()>;

    /// Activate a specific trace for viewing.
    fn activate_trace(&mut self, trace_key: i64) -> FlatApiResult<()>;

    /// Open a trace for viewing.
    fn open_trace(&mut self, trace_key: i64) -> FlatApiResult<()>;

    /// Close a trace.
    fn close_trace(&mut self, trace_key: i64) -> FlatApiResult<()>;

    /// Get all available targets.
    fn get_targets(&self) -> Vec<String>;

    /// Connect to a target by its identifier.
    fn connect_target(&mut self, target_id: &str) -> FlatApiResult<()>;

    /// Disconnect from the current target.
    fn disconnect_target(&mut self) -> FlatApiResult<()>;

    /// Execute a target-specific command.
    fn execute_command(&mut self, command: &str) -> FlatApiResult<String>;
}

/// A stub implementation for testing RMI clients.
pub struct StubRmiApi {
    coordinates: DebuggerCoordinates,
    breakpoints: Vec<LogicalBreakpoint>,
    memory: Vec<u8>,
    memory_base: u64,
    connected: bool,
    last_error: Option<String>,
}

impl StubRmiApi {
    /// Create a new stub RMI API.
    pub fn new() -> Self {
        Self {
            coordinates: DebuggerCoordinates::default(),
            breakpoints: Vec::new(),
            memory: vec![0; 0x10000],
            memory_base: 0,
            connected: false,
            last_error: None,
        }
    }

    /// Set the base address for memory operations.
    pub fn set_memory_base(&mut self, base: u64) {
        self.memory_base = base;
    }

    /// Check if connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Get the last error message, if any.
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// Clear the last error.
    pub fn clear_error(&mut self) {
        self.last_error = None;
    }
}

impl Default for StubRmiApi {
    fn default() -> Self {
        Self::new()
    }
}

impl FlatDebuggerRmiApi for StubRmiApi {
    fn current_coordinates(&self) -> &DebuggerCoordinates {
        &self.coordinates
    }

    fn set_coordinates(&mut self, coords: DebuggerCoordinates) {
        self.coordinates = coords;
    }

    fn current_trace_key(&self) -> Option<i64> {
        self.coordinates.trace_key()
    }

    fn current_snap(&self) -> Option<i64> {
        self.coordinates.snap()
    }

    fn current_thread_id(&self) -> Option<u64> {
        self.coordinates.thread_id()
    }

    fn go_to_address(&mut self, offset: u64) -> FlatApiResult<()> {
        self.coordinates = self.coordinates.with_snap(offset as i64);
        Ok(())
    }

    fn get_current_location(&self) -> Option<ProgramLocation> {
        Some(ProgramLocation {
            offset: 0,
            space_name: "ram".into(),
        })
    }

    fn set_breakpoint(&mut self, offset: u64) -> FlatApiResult<LogicalBreakpoint> {
        let bp = LogicalBreakpoint::new(offset, &format!("0x{:x}", offset));
        self.breakpoints.push(bp.clone());
        Ok(bp)
    }

    fn delete_breakpoint(&mut self, offset: u64) -> FlatApiResult<()> {
        let before = self.breakpoints.len();
        self.breakpoints.retain(|bp| bp.offset != offset);
        if self.breakpoints.len() < before {
            Ok(())
        } else {
            Err(crate::api::flat_api::FlatApiError::NotConnected)
        }
    }

    fn get_breakpoints(&self) -> Vec<LogicalBreakpoint> {
        self.breakpoints.clone()
    }

    fn step_into(&mut self) -> FlatApiResult<()> {
        Ok(())
    }

    fn step_over(&mut self) -> FlatApiResult<()> {
        Ok(())
    }

    fn resume(&mut self) -> FlatApiResult<()> {
        Ok(())
    }

    fn pause(&mut self) -> FlatApiResult<()> {
        Ok(())
    }

    fn read_memory(&self, offset: u64, len: u32) -> FlatApiResult<Vec<u8>> {
        let start = (offset - self.memory_base) as usize;
        let end = start + len as usize;
        if end <= self.memory.len() {
            Ok(self.memory[start..end].to_vec())
        } else {
            Err(crate::api::flat_api::FlatApiError::NotConnected)
        }
    }

    fn write_memory(&mut self, offset: u64, data: &[u8]) -> FlatApiResult<()> {
        let start = (offset - self.memory_base) as usize;
        let end = start + data.len();
        if end <= self.memory.len() {
            self.memory[start..end].copy_from_slice(data);
            Ok(())
        } else {
            Err(crate::api::flat_api::FlatApiError::NotConnected)
        }
    }

    fn read_register(&self, _name: &str) -> FlatApiResult<Vec<u8>> {
        Ok(vec![0; 8])
    }

    fn write_register(&mut self, _name: &str, _data: &[u8]) -> FlatApiResult<()> {
        Ok(())
    }

    fn activate_trace(&mut self, trace_key: i64) -> FlatApiResult<()> {
        self.coordinates = DebuggerCoordinates::with_key(trace_key);
        Ok(())
    }

    fn open_trace(&mut self, trace_key: i64) -> FlatApiResult<()> {
        self.activate_trace(trace_key)
    }

    fn close_trace(&mut self, _trace_key: i64) -> FlatApiResult<()> {
        self.coordinates = DebuggerCoordinates::default();
        Ok(())
    }

    fn get_targets(&self) -> Vec<String> {
        vec!["gdb".into(), "lldb".into()]
    }

    fn connect_target(&mut self, _target_id: &str) -> FlatApiResult<()> {
        self.connected = true;
        Ok(())
    }

    fn disconnect_target(&mut self) -> FlatApiResult<()> {
        self.connected = false;
        Ok(())
    }

    fn execute_command(&mut self, command: &str) -> FlatApiResult<String> {
        Ok(format!("Executed: {}", command))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stub_rmi_api_lifecycle() {
        let mut api = StubRmiApi::new();
        assert!(!api.is_connected());
        assert!(api.current_trace_key().is_none());

        api.activate_trace(42).unwrap();
        assert_eq!(api.current_trace_key(), Some(42));

        api.connect_target("gdb").unwrap();
        assert!(api.is_connected());

        api.disconnect_target().unwrap();
        assert!(!api.is_connected());
    }

    #[test]
    fn test_stub_breakpoints() {
        let mut api = StubRmiApi::new();
        let bp = api.set_breakpoint(0x400000).unwrap();
        assert_eq!(bp.offset, 0x400000);
        assert_eq!(api.get_breakpoints().len(), 1);

        api.delete_breakpoint(0x400000).unwrap();
        assert!(api.get_breakpoints().is_empty());
    }

    #[test]
    fn test_stub_memory() {
        let mut api = StubRmiApi::new();
        api.set_memory_base(0x400000);
        api.write_memory(0x400000, &[0x90, 0xCC, 0xFF]).unwrap();
        let data = api.read_memory(0x400000, 3).unwrap();
        assert_eq!(data, vec![0x90, 0xCC, 0xFF]);
    }

    #[test]
    fn test_stub_commands() {
        let mut api = StubRmiApi::new();
        let result = api.execute_command("info registers").unwrap();
        assert!(result.contains("info registers"));

        let targets = api.get_targets();
        assert!(targets.contains(&"gdb".to_string()));
    }
}
