//! DebuggerLogicalBreakpointService - service for managing logical breakpoints.
//!
//! Ported from Ghidra's `ghidra.app.services.DebuggerLogicalBreakpointService`.

use crate::api::breakpoint::LogicalBreakpoint;

/// Listener for breakpoint changes.
pub trait LogicalBreakpointsChangeListener {
    /// Called when breakpoints are added.
    fn breakpoints_added(&self, bps: &[&LogicalBreakpoint]);

    /// Called when breakpoints are removed.
    fn breakpoints_removed(&self, bps: &[&LogicalBreakpoint]);

    /// Called when breakpoints are changed.
    fn breakpoints_changed(&self, bps: &[&LogicalBreakpoint]);
}

/// Service interface for managing logical breakpoints.
pub trait DebuggerLogicalBreakpointServiceExt {
    /// Get all logical breakpoints.
    fn breakpoints(&self) -> Vec<&LogicalBreakpoint>;

    /// Get a breakpoint at the given address.
    fn breakpoint_at(&self, offset: u64) -> Option<&LogicalBreakpoint>;

    /// Add a breakpoint.
    fn add_breakpoint(&mut self, bp: LogicalBreakpoint) -> Result<(), String>;

    /// Delete a breakpoint.
    fn delete_breakpoint(&mut self, offset: u64) -> Result<(), String>;

    /// Toggle a breakpoint enabled/disabled.
    fn toggle_breakpoint(&mut self, offset: u64, enabled: bool) -> Result<(), String>;

    /// Place breakpoints on a target.
    fn place_on_target(&mut self, bp_key: i64, target_key: i64) -> Result<(), String>;

    /// Remove breakpoints from a target.
    fn remove_from_target(&mut self, bp_key: i64, target_key: i64) -> Result<(), String>;

    /// Enable breakpoints on a target.
    fn enable_on_target(&mut self, bp_key: i64, target_key: i64) -> Result<(), String>;

    /// Disable breakpoints on a target.
    fn disable_on_target(&mut self, bp_key: i64, target_key: i64) -> Result<(), String>;

    /// Make all pending breakpoint changes effective on targets.
    fn make_effective(&mut self) -> Result<(), String>;

    /// Get the count of logical breakpoints.
    fn count(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_breakpoint_service_trait() {
        // Verify trait can be defined (compile-time test)
        struct MockService;
        impl DebuggerLogicalBreakpointServiceExt for MockService {
            fn breakpoints(&self) -> Vec<&LogicalBreakpoint> { vec![] }
            fn breakpoint_at(&self, _: u64) -> Option<&LogicalBreakpoint> { None }
            fn add_breakpoint(&mut self, _: LogicalBreakpoint) -> Result<(), String> { Ok(()) }
            fn delete_breakpoint(&mut self, _: u64) -> Result<(), String> { Ok(()) }
            fn toggle_breakpoint(&mut self, _: u64, _: bool) -> Result<(), String> { Ok(()) }
            fn place_on_target(&mut self, _: i64, _: i64) -> Result<(), String> { Ok(()) }
            fn remove_from_target(&mut self, _: i64, _: i64) -> Result<(), String> { Ok(()) }
            fn enable_on_target(&mut self, _: i64, _: i64) -> Result<(), String> { Ok(()) }
            fn disable_on_target(&mut self, _: i64, _: i64) -> Result<(), String> { Ok(()) }
            fn make_effective(&mut self) -> Result<(), String> { Ok(()) }
            fn count(&self) -> usize { 0 }
        }

        let svc = MockService;
        assert_eq!(svc.count(), 0);
    }
}
