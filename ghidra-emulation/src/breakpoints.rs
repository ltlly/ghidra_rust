//! Breakpoint management for the emulator.
//!
//! [`BreakpointManager`] tracks execution, read, write, and access
//! breakpoints. Each breakpoint has a kind, address, enabled state, hit
//! count, and an optional condition expression.

use ghidra_core::addr::Address;
use std::collections::HashMap;

/// The kind of breakpoint trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BreakpointKind {
    /// Break when execution reaches the address.
    Execution,
    /// Break when the address is read from.
    Read,
    /// Break when the address is written to.
    Write,
    /// Break on any access (read or write) to the address.
    Access,
}

impl BreakpointKind {
    /// Human-readable name of this breakpoint kind.
    pub fn name(self) -> &'static str {
        match self {
            BreakpointKind::Execution => "execution",
            BreakpointKind::Read => "read",
            BreakpointKind::Write => "write",
            BreakpointKind::Access => "access",
        }
    }
}

/// Metadata for a single breakpoint.
#[derive(Debug, Clone)]
pub struct BreakpointInfo {
    /// The type of breakpoint.
    pub kind: BreakpointKind,
    /// Whether this breakpoint is currently active.
    pub enabled: bool,
    /// Number of times this breakpoint has been hit.
    pub hit_count: u64,
    /// Optional condition expression (e.g., `"RAX == 0"`).
    ///
    /// The breakpoint only triggers when this expression evaluates to true.
    /// When `None`, the breakpoint always triggers.
    pub condition: Option<String>,
}

impl BreakpointInfo {
    /// Create a new enabled breakpoint of the given kind.
    pub fn new(kind: BreakpointKind) -> Self {
        Self {
            kind,
            enabled: true,
            hit_count: 0,
            condition: None,
        }
    }

    /// Create a new enabled breakpoint with a condition expression.
    pub fn conditional(kind: BreakpointKind, condition: impl Into<String>) -> Self {
        Self {
            kind,
            enabled: true,
            hit_count: 0,
            condition: Some(condition.into()),
        }
    }

    /// Enable this breakpoint.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable this breakpoint.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Record a hit on this breakpoint (increment the hit counter).
    pub fn record_hit(&mut self) {
        self.hit_count = self.hit_count.saturating_add(1);
    }

    /// Returns true if this breakpoint should trigger.
    ///
    /// The breakpoint triggers when it is enabled. Condition expressions are
    /// not evaluated here; the caller is responsible for evaluating them
    /// against the current emulator state.
    pub fn should_trigger(&self) -> bool {
        self.enabled
    }
}

/// Manages a collection of breakpoints indexed by address.
#[derive(Debug, Clone, Default)]
pub struct BreakpointManager {
    /// Breakpoints keyed by address.
    pub breakpoints: HashMap<Address, BreakpointInfo>,
}

impl BreakpointManager {
    /// Create an empty breakpoint manager.
    pub fn new() -> Self {
        Self {
            breakpoints: HashMap::new(),
        }
    }

    /// Set a breakpoint at the given address.
    ///
    /// If a breakpoint already exists at this address, it is replaced.
    pub fn set(&mut self, addr: Address, kind: BreakpointKind) {
        self.breakpoints.insert(addr, BreakpointInfo::new(kind));
    }

    /// Set a conditional breakpoint at the given address.
    pub fn set_conditional(
        &mut self,
        addr: Address,
        kind: BreakpointKind,
        condition: impl Into<String>,
    ) {
        self.breakpoints
            .insert(addr, BreakpointInfo::conditional(kind, condition));
    }

    /// Clear (remove) the breakpoint at the given address.
    ///
    /// Returns the removed breakpoint info, or `None` if none existed.
    pub fn clear(&mut self, addr: Address) -> Option<BreakpointInfo> {
        self.breakpoints.remove(&addr)
    }

    /// Get the breakpoint info at the given address, if any.
    pub fn get(&self, addr: &Address) -> Option<&BreakpointInfo> {
        self.breakpoints.get(addr)
    }

    /// Get a mutable reference to the breakpoint at the given address.
    pub fn get_mut(&mut self, addr: &Address) -> Option<&mut BreakpointInfo> {
        self.breakpoints.get_mut(addr)
    }

    /// Check whether any enabled breakpoint exists at the given address.
    pub fn is_set(&self, addr: &Address) -> bool {
        self.breakpoints
            .get(addr)
            .map(|bp| bp.should_trigger())
            .unwrap_or(false)
    }

    /// Check for and record a hit on any execution breakpoint at the given
    /// address. Returns `true` if a breakpoint was triggered.
    pub fn check_execution(&mut self, addr: &Address) -> bool {
        if let Some(bp) = self.breakpoints.get_mut(addr) {
            if bp.kind == BreakpointKind::Execution && bp.should_trigger() {
                bp.record_hit();
                return true;
            }
        }
        false
    }

    /// Check for and record a hit on any read breakpoint at the given
    /// address. Returns `true` if a breakpoint was triggered.
    pub fn check_read(&mut self, addr: &Address) -> bool {
        if let Some(bp) = self.breakpoints.get_mut(addr) {
            if matches!(bp.kind, BreakpointKind::Read | BreakpointKind::Access)
                && bp.should_trigger()
            {
                bp.record_hit();
                return true;
            }
        }
        false
    }

    /// Check for and record a hit on any write breakpoint at the given
    /// address. Returns `true` if a breakpoint was triggered.
    pub fn check_write(&mut self, addr: &Address) -> bool {
        if let Some(bp) = self.breakpoints.get_mut(addr) {
            if matches!(bp.kind, BreakpointKind::Write | BreakpointKind::Access)
                && bp.should_trigger()
            {
                bp.record_hit();
                return true;
            }
        }
        false
    }

    /// Return the number of breakpoints.
    pub fn len(&self) -> usize {
        self.breakpoints.len()
    }

    /// Returns true if there are no breakpoints.
    pub fn is_empty(&self) -> bool {
        self.breakpoints.is_empty()
    }

    /// Remove all breakpoints.
    pub fn clear_all(&mut self) {
        self.breakpoints.clear();
    }

    /// Enable a disabled breakpoint at the given address.
    pub fn enable(&mut self, addr: &Address) -> bool {
        if let Some(bp) = self.breakpoints.get_mut(addr) {
            bp.enable();
            true
        } else {
            false
        }
    }

    /// Disable a breakpoint at the given address without removing it.
    pub fn disable(&mut self, addr: &Address) -> bool {
        if let Some(bp) = self.breakpoints.get_mut(addr) {
            bp.disable();
            true
        } else {
            false
        }
    }

    /// Return an iterator over all breakpoint entries.
    pub fn iter(&self) -> impl Iterator<Item = (&Address, &BreakpointInfo)> {
        self.breakpoints.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_set_and_clear_breakpoint() {
        let mut mgr = BreakpointManager::new();
        assert!(mgr.is_empty());

        mgr.set(addr(0x401000), BreakpointKind::Execution);
        assert_eq!(mgr.len(), 1);
        assert!(mgr.is_set(&addr(0x401000)));
        assert!(!mgr.is_set(&addr(0x402000)));

        mgr.clear(addr(0x401000));
        assert!(mgr.is_empty());
        assert!(!mgr.is_set(&addr(0x401000)));
    }

    #[test]
    fn test_breakpoint_hit_count() {
        let mut mgr = BreakpointManager::new();
        mgr.set(addr(0x401000), BreakpointKind::Execution);

        assert!(mgr.check_execution(&addr(0x401000)));
        assert!(mgr.check_execution(&addr(0x401000)));
        assert!(!mgr.check_execution(&addr(0x402000)));

        let bp = mgr.get(&addr(0x401000)).unwrap();
        assert_eq!(bp.hit_count, 2);
    }

    #[test]
    fn test_disabled_breakpoint_does_not_trigger() {
        let mut mgr = BreakpointManager::new();
        mgr.set(addr(0x401000), BreakpointKind::Execution);
        mgr.disable(&addr(0x401000));

        assert!(!mgr.check_execution(&addr(0x401000)));
    }

    #[test]
    fn test_read_write_access_breakpoints() {
        let mut mgr = BreakpointManager::new();

        // Read breakpoint only triggers on reads
        mgr.set(addr(0x1000), BreakpointKind::Read);
        assert!(mgr.check_read(&addr(0x1000)));
        assert!(!mgr.check_write(&addr(0x1000)));

        // Write breakpoint only triggers on writes
        mgr.set(addr(0x2000), BreakpointKind::Write);
        assert!(!mgr.check_read(&addr(0x2000)));
        assert!(mgr.check_write(&addr(0x2000)));

        // Access breakpoint triggers on both
        mgr.set(addr(0x3000), BreakpointKind::Access);
        assert!(mgr.check_read(&addr(0x3000)));
        assert!(mgr.check_write(&addr(0x3000)));
    }

    #[test]
    fn test_conditional_breakpoint() {
        let mut mgr = BreakpointManager::new();
        mgr.set_conditional(addr(0x401000), BreakpointKind::Execution, "RAX == 0");

        let bp = mgr.get(&addr(0x401000)).unwrap();
        assert_eq!(bp.condition.as_deref(), Some("RAX == 0"));
        assert!(bp.enabled);
    }

    #[test]
    fn test_iter() {
        let mut mgr = BreakpointManager::new();
        mgr.set(addr(0x1000), BreakpointKind::Execution);
        mgr.set(addr(0x2000), BreakpointKind::Read);

        let entries: Vec<_> = mgr.iter().map(|(a, _)| a.offset).collect();
        assert_eq!(entries.len(), 2);
        assert!(entries.contains(&0x1000));
        assert!(entries.contains(&0x2000));
    }
}
