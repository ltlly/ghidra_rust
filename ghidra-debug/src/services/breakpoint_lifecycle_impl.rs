//! Breakpoint lifecycle management ported from Java.
//!
//! Ported from `DebuggerLogicalBreakpointServicePlugin` and related
//! breakpoint service implementation classes. Manages the lifecycle
//! of logical breakpoints including creation, deletion, enabling,
//! disabling, and synchronization with target breakpoints.

use std::collections::HashMap;

use crate::api::breakpoint::{BreakpointMode, LogicalBreakpoint};

/// A tracked logical breakpoint with lifecycle state.
#[derive(Debug, Clone)]
pub struct LogicalBreakpointInternal {
    /// The logical breakpoint.
    pub breakpoint: LogicalBreakpoint,
    /// Whether this breakpoint is placed on the target.
    pub target_placed: bool,
    /// Whether this breakpoint is placed on the emulator.
    pub emu_placed: bool,
    /// Source of the breakpoint (user, script, etc.).
    pub source: BreakpointSource,
    /// Error message from the last placement attempt.
    pub last_error: Option<String>,
}

/// Source of a breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointSource {
    /// User-placed breakpoint.
    User,
    /// Script-placed breakpoint.
    Script,
    /// Programmatically placed breakpoint.
    Programmatic,
    /// Imported from another tool.
    Imported,
}

/// Action to take when a breakpoint is encountered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointAction {
    /// Stop execution.
    Stop,
    /// Continue execution.
    Continue,
    /// Log the hit.
    Log,
    /// Execute a custom action.
    Custom,
}

/// Breakpoint lifecycle manager.
///
/// Manages the creation, tracking, and synchronization of logical
/// breakpoints with target and emulator breakpoints.
#[derive(Debug, Default)]
pub struct BreakpointLifecycleManager {
    /// All managed logical breakpoints, keyed by offset.
    breakpoints: HashMap<u64, LogicalBreakpointInternal>,
    /// Next breakpoint ID.
    next_id: u64,
}

impl BreakpointLifecycleManager {
    /// Create a new lifecycle manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new logical breakpoint.
    pub fn add(&mut self, breakpoint: LogicalBreakpoint, source: BreakpointSource) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let offset = breakpoint.offset;
        let internal = LogicalBreakpointInternal {
            breakpoint,
            target_placed: false,
            emu_placed: false,
            source,
            last_error: None,
        };
        self.breakpoints.insert(offset, internal);
        id
    }

    /// Remove a breakpoint by offset.
    pub fn remove(&mut self, offset: u64) -> Option<LogicalBreakpointInternal> {
        self.breakpoints.remove(&offset)
    }

    /// Get a breakpoint by offset.
    pub fn get(&self, offset: u64) -> Option<&LogicalBreakpointInternal> {
        self.breakpoints.get(&offset)
    }

    /// Get a mutable reference to a breakpoint.
    pub fn get_mut(&mut self, offset: u64) -> Option<&mut LogicalBreakpointInternal> {
        self.breakpoints.get_mut(&offset)
    }

    /// Enable a breakpoint.
    pub fn enable(&mut self, offset: u64) -> Result<(), String> {
        let bp = self.breakpoints.get_mut(&offset)
            .ok_or("Breakpoint not found")?;
        bp.breakpoint.state.mode = Some(BreakpointMode::Enabled);
        Ok(())
    }

    /// Disable a breakpoint.
    pub fn disable(&mut self, offset: u64) -> Result<(), String> {
        let bp = self.breakpoints.get_mut(&offset)
            .ok_or("Breakpoint not found")?;
        bp.breakpoint.state.mode = Some(BreakpointMode::Disabled);
        Ok(())
    }

    /// Mark a breakpoint as placed on the target.
    pub fn mark_target_placed(&mut self, offset: u64, placed: bool) {
        if let Some(bp) = self.breakpoints.get_mut(&offset) {
            bp.target_placed = placed;
        }
    }

    /// Mark a breakpoint as placed on the emulator.
    pub fn mark_emu_placed(&mut self, offset: u64, placed: bool) {
        if let Some(bp) = self.breakpoints.get_mut(&offset) {
            bp.emu_placed = placed;
        }
    }

    /// Get all breakpoints.
    pub fn all(&self) -> Vec<&LogicalBreakpointInternal> {
        self.breakpoints.values().collect()
    }

    /// Get all enabled breakpoints.
    pub fn enabled(&self) -> Vec<&LogicalBreakpointInternal> {
        self.breakpoints
            .values()
            .filter(|bp| bp.breakpoint.is_enabled())
            .collect()
    }

    /// Get all breakpoints that need target placement.
    pub fn needs_target_placement(&self) -> Vec<&LogicalBreakpointInternal> {
        self.breakpoints
            .values()
            .filter(|bp| bp.breakpoint.is_enabled() && !bp.target_placed)
            .collect()
    }

    /// Get the total number of breakpoints.
    pub fn count(&self) -> usize {
        self.breakpoints.len()
    }

    /// Clear all breakpoints.
    pub fn clear(&mut self) {
        self.breakpoints.clear();
    }

    /// Get breakpoints by source.
    pub fn by_source(&self, source: BreakpointSource) -> Vec<&LogicalBreakpointInternal> {
        self.breakpoints
            .values()
            .filter(|bp| bp.source == source)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_manager() {
        let mut mgr = BreakpointLifecycleManager::new();
        let bp = LogicalBreakpoint::new(0x400000, "0x400000");
        mgr.add(bp, BreakpointSource::User);

        assert_eq!(mgr.count(), 1);
        assert!(mgr.get(0x400000).is_some());

        mgr.enable(0x400000).unwrap();
        assert!(mgr.get(0x400000).unwrap().breakpoint.is_enabled());

        mgr.mark_target_placed(0x400000, true);
        assert!(mgr.get(0x400000).unwrap().target_placed);
    }

    #[test]
    fn test_needs_placement() {
        let mut mgr = BreakpointLifecycleManager::new();
        let bp1 = LogicalBreakpoint::new(0x400000, "0x400000");
        let bp2 = LogicalBreakpoint::new(0x400100, "0x400100");
        mgr.add(bp1, BreakpointSource::User);
        mgr.add(bp2, BreakpointSource::Script);

        // Both need placement initially
        assert_eq!(mgr.needs_target_placement().len(), 2);

        mgr.mark_target_placed(0x400000, true);
        assert_eq!(mgr.needs_target_placement().len(), 1);
    }

    #[test]
    fn test_remove() {
        let mut mgr = BreakpointLifecycleManager::new();
        let bp = LogicalBreakpoint::new(0x400000, "0x400000");
        mgr.add(bp, BreakpointSource::User);

        let removed = mgr.remove(0x400000);
        assert!(removed.is_some());
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_by_source() {
        let mut mgr = BreakpointLifecycleManager::new();
        mgr.add(LogicalBreakpoint::new(0x400000, "0x400000"), BreakpointSource::User);
        mgr.add(LogicalBreakpoint::new(0x400100, "0x400100"), BreakpointSource::Script);
        mgr.add(LogicalBreakpoint::new(0x400200, "0x400200"), BreakpointSource::User);

        assert_eq!(mgr.by_source(BreakpointSource::User).len(), 2);
        assert_eq!(mgr.by_source(BreakpointSource::Script).len(), 1);
    }

    #[test]
    fn test_enable_disable() {
        let mut mgr = BreakpointLifecycleManager::new();
        mgr.add(LogicalBreakpoint::new(0x400000, "0x400000"), BreakpointSource::User);

        mgr.enable(0x400000).unwrap();
        assert!(mgr.enabled().len() == 1);

        mgr.disable(0x400000).unwrap();
        assert!(mgr.enabled().len() == 0);

        assert!(mgr.enable(0x999999).is_err());
    }
}
