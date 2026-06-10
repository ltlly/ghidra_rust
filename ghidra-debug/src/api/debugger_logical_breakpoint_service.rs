//! DebuggerLogicalBreakpointService - service for managing logical breakpoints.
//!
//! Ported from Ghidra's `ghidra.debug.api.breakpoint.DebuggerLogicalBreakpointService`.
//!
//! This service manages the set of logical breakpoints that the user has set
//! during a debug session. It provides operations for creating, deleting,
//! enabling/disabling, and querying breakpoints.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use super::breakpoint::{BreakpointConsistency, BreakpointMode, BreakpointState, LogicalBreakpoint};

/// A unique identifier for a logical breakpoint.
pub type BreakpointId = u64;

/// A tracked logical breakpoint with its id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedBreakpoint {
    /// The unique id.
    pub id: BreakpointId,
    /// The logical breakpoint data.
    pub breakpoint: LogicalBreakpoint,
}

impl TrackedBreakpoint {
    /// Create a new tracked breakpoint.
    pub fn new(id: BreakpointId, breakpoint: LogicalBreakpoint) -> Self {
        Self { id, breakpoint }
    }

    /// Whether this breakpoint is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.breakpoint.is_enabled()
    }
}

/// Listener for breakpoint change events.
pub trait BreakpointServiceListener: Send + Sync {
    /// Called when a breakpoint is added.
    fn breakpoint_added(&self, bp: &TrackedBreakpoint);

    /// Called when a breakpoint is removed.
    fn breakpoint_removed(&self, id: BreakpointId);

    /// Called when a breakpoint's state changes.
    fn breakpoint_state_changed(&self, bp: &TrackedBreakpoint);

    /// Called when all breakpoints are cleared.
    fn breakpoints_cleared(&self);
}

/// Service for managing logical breakpoints.
///
/// This service provides:
/// - Adding and removing logical breakpoints
/// - Enabling and disabling breakpoints
/// - Querying breakpoints by address, expression, or state
/// - Batch operations (enable all, disable all)
/// - Listener notifications for UI updates
pub struct DebuggerLogicalBreakpointService {
    /// Tracked breakpoints keyed by id.
    breakpoints: RwLock<HashMap<BreakpointId, TrackedBreakpoint>>,
    /// Next id counter.
    next_id: Mutex<BreakpointId>,
    /// Registered listeners.
    listeners: Mutex<Vec<Arc<dyn BreakpointServiceListener>>>,
}

impl DebuggerLogicalBreakpointService {
    /// Create a new logical breakpoint service.
    pub fn new() -> Self {
        Self {
            breakpoints: RwLock::new(HashMap::new()),
            next_id: Mutex::new(1),
            listeners: Mutex::new(Vec::new()),
        }
    }

    /// Register a listener.
    pub fn add_listener(&self, listener: Arc<dyn BreakpointServiceListener>) {
        if let Ok(mut listeners) = self.listeners.lock() {
            listeners.push(listener);
        }
    }

    /// Allocate the next breakpoint id.
    fn alloc_id(&self) -> BreakpointId {
        self.next_id
            .lock()
            .map(|mut id| {
                let current = *id;
                *id = current + 1;
                current
            })
            .unwrap_or(0)
    }

    /// Add a new logical breakpoint.
    ///
    /// Returns the id of the newly created breakpoint.
    pub fn add_breakpoint(&self, offset: u64, expression: impl Into<String>) -> BreakpointId {
        let id = self.alloc_id();
        let bp = LogicalBreakpoint::new(offset, expression);
        let tracked = TrackedBreakpoint::new(id, bp);

        if let Ok(mut bps) = self.breakpoints.write() {
            bps.insert(id, tracked.clone());
        }

        if let Ok(listeners) = self.listeners.lock() {
            for listener in listeners.iter() {
                listener.breakpoint_added(&tracked);
            }
        }

        id
    }

    /// Add a breakpoint with specific kinds.
    pub fn add_breakpoint_with_kinds(
        &self,
        offset: u64,
        expression: impl Into<String>,
        kinds: Vec<String>,
    ) -> BreakpointId {
        let id = self.alloc_id();
        let bp = LogicalBreakpoint::new(offset, expression).with_kinds(kinds);
        let tracked = TrackedBreakpoint::new(id, bp);

        if let Ok(mut bps) = self.breakpoints.write() {
            bps.insert(id, tracked.clone());
        }

        if let Ok(listeners) = self.listeners.lock() {
            for listener in listeners.iter() {
                listener.breakpoint_added(&tracked);
            }
        }

        id
    }

    /// Remove a breakpoint by id.
    ///
    /// Returns true if the breakpoint was found and removed.
    pub fn remove_breakpoint(&self, id: BreakpointId) -> bool {
        let removed = if let Ok(mut bps) = self.breakpoints.write() {
            bps.remove(&id).is_some()
        } else {
            false
        };

        if removed {
            if let Ok(listeners) = self.listeners.lock() {
                for listener in listeners.iter() {
                    listener.breakpoint_removed(id);
                }
            }
        }

        removed
    }

    /// Get a tracked breakpoint by id.
    pub fn get_breakpoint(&self, id: BreakpointId) -> Option<TrackedBreakpoint> {
        self.breakpoints
            .read()
            .ok()
            .and_then(|bps| bps.get(&id).cloned())
    }

    /// Get all tracked breakpoints.
    pub fn breakpoints(&self) -> Vec<TrackedBreakpoint> {
        self.breakpoints
            .read()
            .map(|bps| bps.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Get the number of breakpoints.
    pub fn breakpoint_count(&self) -> usize {
        self.breakpoints.read().map(|bps| bps.len()).unwrap_or(0)
    }

    /// Enable a breakpoint by id.
    pub fn enable_breakpoint(&self, id: BreakpointId) -> bool {
        self.set_mode(id, BreakpointMode::Enabled)
    }

    /// Disable a breakpoint by id.
    pub fn disable_breakpoint(&self, id: BreakpointId) -> bool {
        self.set_mode(id, BreakpointMode::Disabled)
    }

    /// Set the mode of a breakpoint.
    fn set_mode(&self, id: BreakpointId, mode: BreakpointMode) -> bool {
        let updated = if let Ok(mut bps) = self.breakpoints.write() {
            bps.get_mut(&id).map(|tracked| {
                tracked.breakpoint.state = BreakpointState::from_fields(
                    Some(mode),
                    tracked.breakpoint.state.consistency,
                );
                tracked.clone()
            })
        } else {
            None
        };

        if let Some(ref bp) = updated {
            if let Ok(listeners) = self.listeners.lock() {
                for listener in listeners.iter() {
                    listener.breakpoint_state_changed(bp);
                }
            }
            true
        } else {
            false
        }
    }

    /// Enable all breakpoints.
    pub fn enable_all(&self) -> usize {
        let ids: Vec<BreakpointId> = self
            .breakpoints
            .read()
            .map(|bps| {
                bps.values()
                    .filter(|bp| !bp.is_enabled())
                    .map(|bp| bp.id)
                    .collect()
            })
            .unwrap_or_default();

        let count = ids.len();
        for id in ids {
            self.enable_breakpoint(id);
        }
        count
    }

    /// Disable all breakpoints.
    pub fn disable_all(&self) -> usize {
        let ids: Vec<BreakpointId> = self
            .breakpoints
            .read()
            .map(|bps| {
                bps.values()
                    .filter(|bp| bp.is_enabled())
                    .map(|bp| bp.id)
                    .collect()
            })
            .unwrap_or_default();

        let count = ids.len();
        for id in ids {
            self.disable_breakpoint(id);
        }
        count
    }

    /// Find breakpoints at a given address offset.
    pub fn find_by_address(&self, offset: u64) -> Vec<TrackedBreakpoint> {
        self.breakpoints
            .read()
            .map(|bps| {
                bps.values()
                    .filter(|bp| bp.breakpoint.offset == offset)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Find breakpoints by expression.
    pub fn find_by_expression(&self, expression: &str) -> Vec<TrackedBreakpoint> {
        self.breakpoints
            .read()
            .map(|bps| {
                bps.values()
                    .filter(|bp| bp.breakpoint.expression == expression)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get only enabled breakpoints.
    pub fn enabled_breakpoints(&self) -> Vec<TrackedBreakpoint> {
        self.breakpoints
            .read()
            .map(|bps| {
                bps.values()
                    .filter(|bp| bp.is_enabled())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get only disabled breakpoints.
    pub fn disabled_breakpoints(&self) -> Vec<TrackedBreakpoint> {
        self.breakpoints
            .read()
            .map(|bps| {
                bps.values()
                    .filter(|bp| !bp.is_enabled())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Update the consistency of a breakpoint.
    pub fn update_consistency(
        &self,
        id: BreakpointId,
        consistency: BreakpointConsistency,
    ) -> bool {
        let updated = if let Ok(mut bps) = self.breakpoints.write() {
            bps.get_mut(&id).map(|tracked| {
                tracked.breakpoint.state = BreakpointState::from_fields(
                    tracked.breakpoint.state.mode,
                    Some(consistency),
                );
                tracked.clone()
            })
        } else {
            None
        };

        if let Some(ref bp) = updated {
            if let Ok(listeners) = self.listeners.lock() {
                for listener in listeners.iter() {
                    listener.breakpoint_state_changed(bp);
                }
            }
            true
        } else {
            false
        }
    }

    /// Set the comment on a breakpoint.
    pub fn set_comment(&self, id: BreakpointId, comment: impl Into<String>) -> bool {
        if let Ok(mut bps) = self.breakpoints.write() {
            if let Some(tracked) = bps.get_mut(&id) {
                tracked.breakpoint.comment = Some(comment.into());
                return true;
            }
        }
        false
    }

    /// Remove the comment from a breakpoint.
    pub fn clear_comment(&self, id: BreakpointId) -> bool {
        if let Ok(mut bps) = self.breakpoints.write() {
            if let Some(tracked) = bps.get_mut(&id) {
                tracked.breakpoint.comment = None;
                return true;
            }
        }
        false
    }

    /// Clear all breakpoints.
    pub fn clear(&self) {
        if let Ok(mut bps) = self.breakpoints.write() {
            bps.clear();
        }
        if let Ok(listeners) = self.listeners.lock() {
            for listener in listeners.iter() {
                listener.breakpoints_cleared();
            }
        }
    }

    /// Check if a breakpoint exists at the given address.
    pub fn has_breakpoint_at(&self, offset: u64) -> bool {
        self.breakpoints
            .read()
            .map(|bps| bps.values().any(|bp| bp.breakpoint.offset == offset))
            .unwrap_or(false)
    }

    /// Toggle a breakpoint at the given address: disable if enabled, enable if disabled.
    ///
    /// If multiple breakpoints exist at the address, the first one found is toggled.
    pub fn toggle_at(&self, offset: u64) -> bool {
        if let Ok(bps) = self.breakpoints.read() {
            if let Some(tracked) = bps.values().find(|bp| bp.breakpoint.offset == offset) {
                let id = tracked.id;
                let is_enabled = tracked.is_enabled();
                drop(bps);
                if is_enabled {
                    self.disable_breakpoint(id)
                } else {
                    self.enable_breakpoint(id)
                }
            } else {
                false
            }
        } else {
            false
        }
    }
}

impl Default for DebuggerLogicalBreakpointService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestListener {
        added: AtomicUsize,
        removed: AtomicUsize,
        state_changed: AtomicUsize,
        cleared: AtomicUsize,
    }

    impl TestListener {
        fn new() -> Self {
            Self {
                added: AtomicUsize::new(0),
                removed: AtomicUsize::new(0),
                state_changed: AtomicUsize::new(0),
                cleared: AtomicUsize::new(0),
            }
        }
    }

    impl BreakpointServiceListener for TestListener {
        fn breakpoint_added(&self, _: &TrackedBreakpoint) {
            self.added.fetch_add(1, Ordering::SeqCst);
        }
        fn breakpoint_removed(&self, _: BreakpointId) {
            self.removed.fetch_add(1, Ordering::SeqCst);
        }
        fn breakpoint_state_changed(&self, _: &TrackedBreakpoint) {
            self.state_changed.fetch_add(1, Ordering::SeqCst);
        }
        fn breakpoints_cleared(&self) {
            self.cleared.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_add_and_get() {
        let svc = DebuggerLogicalBreakpointService::new();
        let id = svc.add_breakpoint(0x400000, "0x400000");
        assert_eq!(svc.breakpoint_count(), 1);
        let tracked = svc.get_breakpoint(id).unwrap();
        assert_eq!(tracked.breakpoint.offset, 0x400000);
        assert!(tracked.is_enabled());
    }

    #[test]
    fn test_add_with_kinds() {
        let svc = DebuggerLogicalBreakpointService::new();
        let id = svc.add_breakpoint_with_kinds(
            0x400000,
            "0x400000",
            vec!["SW_EXECUTE".to_string()],
        );
        let tracked = svc.get_breakpoint(id).unwrap();
        assert_eq!(tracked.breakpoint.kinds, vec!["SW_EXECUTE".to_string()]);
    }

    #[test]
    fn test_remove() {
        let svc = DebuggerLogicalBreakpointService::new();
        let id = svc.add_breakpoint(0x400000, "0x400000");
        assert!(svc.remove_breakpoint(id));
        assert_eq!(svc.breakpoint_count(), 0);
        assert!(svc.get_breakpoint(id).is_none());
    }

    #[test]
    fn test_enable_disable() {
        let svc = DebuggerLogicalBreakpointService::new();
        let id = svc.add_breakpoint(0x400000, "0x400000");

        assert!(svc.disable_breakpoint(id));
        let tracked = svc.get_breakpoint(id).unwrap();
        assert!(!tracked.is_enabled());
        assert_eq!(
            tracked.breakpoint.state.mode,
            Some(BreakpointMode::Disabled)
        );

        assert!(svc.enable_breakpoint(id));
        let tracked = svc.get_breakpoint(id).unwrap();
        assert!(tracked.is_enabled());
    }

    #[test]
    fn test_enable_all_disable_all() {
        let svc = DebuggerLogicalBreakpointService::new();
        svc.add_breakpoint(0x400000, "0x400000");
        svc.add_breakpoint(0x401000, "0x401000");
        svc.add_breakpoint(0x402000, "0x402000");

        let disabled = svc.disable_all();
        assert_eq!(disabled, 3);
        assert_eq!(svc.enabled_breakpoints().len(), 0);
        assert_eq!(svc.disabled_breakpoints().len(), 3);

        let enabled = svc.enable_all();
        assert_eq!(enabled, 3);
        assert_eq!(svc.enabled_breakpoints().len(), 3);
        assert_eq!(svc.disabled_breakpoints().len(), 0);
    }

    #[test]
    fn test_find_by_address() {
        let svc = DebuggerLogicalBreakpointService::new();
        svc.add_breakpoint(0x400000, "0x400000");
        svc.add_breakpoint(0x401000, "0x401000");
        svc.add_breakpoint(0x400000, "0x400000_dup");

        let found = svc.find_by_address(0x400000);
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn test_find_by_expression() {
        let svc = DebuggerLogicalBreakpointService::new();
        svc.add_breakpoint(0x400000, "main");
        svc.add_breakpoint(0x401000, "printf");

        let found = svc.find_by_expression("main");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].breakpoint.expression, "main");
    }

    #[test]
    fn test_has_breakpoint_at() {
        let svc = DebuggerLogicalBreakpointService::new();
        svc.add_breakpoint(0x400000, "0x400000");

        assert!(svc.has_breakpoint_at(0x400000));
        assert!(!svc.has_breakpoint_at(0x401000));
    }

    #[test]
    fn test_toggle_at() {
        let svc = DebuggerLogicalBreakpointService::new();
        svc.add_breakpoint(0x400000, "0x400000");

        // Initially enabled -> toggle to disabled
        assert!(svc.toggle_at(0x400000));
        assert_eq!(svc.enabled_breakpoints().len(), 0);
        assert_eq!(svc.disabled_breakpoints().len(), 1);

        // Now disabled -> toggle back to enabled
        assert!(svc.toggle_at(0x400000));
        assert_eq!(svc.enabled_breakpoints().len(), 1);
    }

    #[test]
    fn test_toggle_at_no_breakpoint() {
        let svc = DebuggerLogicalBreakpointService::new();
        assert!(!svc.toggle_at(0x400000));
    }

    #[test]
    fn test_consistency_update() {
        let svc = DebuggerLogicalBreakpointService::new();
        let id = svc.add_breakpoint(0x400000, "0x400000");

        assert!(svc.update_consistency(id, BreakpointConsistency::Inconsistent));
        let tracked = svc.get_breakpoint(id).unwrap();
        assert_eq!(
            tracked.breakpoint.state.consistency,
            Some(BreakpointConsistency::Inconsistent)
        );
    }

    #[test]
    fn test_comment() {
        let svc = DebuggerLogicalBreakpointService::new();
        let id = svc.add_breakpoint(0x400000, "0x400000");

        svc.set_comment(id, "entry point");
        let tracked = svc.get_breakpoint(id).unwrap();
        assert_eq!(tracked.breakpoint.comment, Some("entry point".to_string()));

        svc.clear_comment(id);
        let tracked = svc.get_breakpoint(id).unwrap();
        assert!(tracked.breakpoint.comment.is_none());
    }

    #[test]
    fn test_clear() {
        let svc = DebuggerLogicalBreakpointService::new();
        svc.add_breakpoint(0x400000, "0x400000");
        svc.add_breakpoint(0x401000, "0x401000");
        svc.clear();
        assert_eq!(svc.breakpoint_count(), 0);
    }

    #[test]
    fn test_all_breakpoints() {
        let svc = DebuggerLogicalBreakpointService::new();
        svc.add_breakpoint(0x400000, "0x400000");
        svc.add_breakpoint(0x401000, "0x401000");

        let all = svc.breakpoints();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_listener_notifications() {
        let listener = Arc::new(TestListener::new());
        let svc = DebuggerLogicalBreakpointService::new();
        svc.add_listener(listener.clone());

        let id = svc.add_breakpoint(0x400000, "0x400000");
        svc.disable_breakpoint(id);
        svc.remove_breakpoint(id);
        svc.clear();

        assert_eq!(listener.added.load(Ordering::SeqCst), 1);
        assert_eq!(listener.state_changed.load(Ordering::SeqCst), 1);
        assert_eq!(listener.removed.load(Ordering::SeqCst), 1);
        assert_eq!(listener.cleared.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_tracked_breakpoint_is_enabled() {
        let bp = LogicalBreakpoint::new(0x400000, "0x400000");
        let tracked = TrackedBreakpoint::new(1, bp);
        assert!(tracked.is_enabled());

        let mut bp2 = LogicalBreakpoint::new(0x401000, "0x401000");
        bp2.state = BreakpointState::from_fields(Some(BreakpointMode::Disabled), None);
        let tracked2 = TrackedBreakpoint::new(2, bp2);
        assert!(!tracked2.is_enabled());
    }
}
