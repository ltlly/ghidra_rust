//! Stack depth management for functions.
//!
//! Ported from `StackDepthChangeEvent.java`,
//! `StackDepthChangeListener.java`, `SetStackDepthChangeAction.java`,
//! `RemoveStackDepthChangeAction.java`, and `StackDepthFieldFactory.java`
//! in Ghidra's `ghidra.app.plugin.core.function`.
//!
//! This module provides:
//! - [`StackDepthChangeEvent`] -- an event emitted when a stack depth
//!   change point is added, modified, or removed
//! - [`StackDepthChangeListener`] -- trait for observing stack depth changes
//! - [`StackDepthChange`] -- a single stack depth change point
//! - [`StackDepthManager`] -- manages stack depth change points for a function
//! - [`SetStackDepthChangeAction`] -- action model for setting a stack
//!   depth change at an address
//! - [`RemoveStackDepthChangeAction`] -- action model for removing a
//!   stack depth change

use ghidra_core::Address;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// The type of stack depth change event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StackDepthChangeKind {
    /// A new stack depth change point was added.
    Added,
    /// An existing stack depth change point was modified.
    Modified,
    /// A stack depth change point was removed.
    Removed,
}

impl fmt::Display for StackDepthChangeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StackDepthChangeKind::Added => write!(f, "Added"),
            StackDepthChangeKind::Modified => write!(f, "Modified"),
            StackDepthChangeKind::Removed => write!(f, "Removed"),
        }
    }
}

/// An event representing a change to a stack depth change point.
///
/// Ported from `StackDepthChangeEvent.java`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackDepthChangeEvent {
    /// The address where the stack depth change occurs.
    pub address: Address,
    /// The kind of change.
    pub kind: StackDepthChangeKind,
    /// The new stack depth delta (0 for removal).
    pub delta: i32,
    /// The previous stack delta (if modifying).
    pub previous_delta: Option<i32>,
}

impl StackDepthChangeEvent {
    /// Creates an "added" event.
    pub fn added(address: Address, delta: i32) -> Self {
        Self {
            address,
            kind: StackDepthChangeKind::Added,
            delta,
            previous_delta: None,
        }
    }

    /// Creates a "modified" event.
    pub fn modified(address: Address, delta: i32, previous_delta: i32) -> Self {
        Self {
            address,
            kind: StackDepthChangeKind::Modified,
            delta,
            previous_delta: Some(previous_delta),
        }
    }

    /// Creates a "removed" event.
    pub fn removed(address: Address) -> Self {
        Self {
            address,
            kind: StackDepthChangeKind::Removed,
            delta: 0,
            previous_delta: None,
        }
    }
}

impl fmt::Display for StackDepthChangeEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            StackDepthChangeKind::Added => {
                write!(f, "Stack depth change added at {}: delta={}", self.address, self.delta)
            }
            StackDepthChangeKind::Modified => {
                write!(
                    f,
                    "Stack depth change modified at {}: delta={}",
                    self.address, self.delta
                )
            }
            StackDepthChangeKind::Removed => {
                write!(f, "Stack depth change removed at {}", self.address)
            }
        }
    }
}

/// Trait for observing stack depth change events.
///
/// Ported from `StackDepthChangeListener.java`.
pub trait StackDepthChangeListener {
    /// Called when a stack depth change event occurs.
    fn stack_depth_changed(&mut self, event: &StackDepthChangeEvent);
}

/// A single stack depth change point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackDepthChange {
    /// The address of the change point.
    pub address: Address,
    /// The stack depth delta at this point.
    pub delta: i32,
}

impl StackDepthChange {
    /// Creates a new stack depth change.
    pub fn new(address: Address, delta: i32) -> Self {
        Self { address, delta }
    }
}

impl fmt::Display for StackDepthChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.address, self.delta)
    }
}

/// Manages stack depth change points for a function.
///
/// This is the Rust equivalent of Ghidra's stack depth management
/// within `FunctionDB`.  Stack depth change points allow the user to
/// override the computed stack depth at specific addresses.
#[derive(Debug, Clone, Default)]
pub struct StackDepthManager {
    /// Stack depth changes keyed by address.
    changes: BTreeMap<u64, i32>,
}

impl StackDepthManager {
    /// Creates a new empty stack depth manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of stack depth change points.
    pub fn len(&self) -> usize {
        self.changes.len()
    }

    /// Returns `true` if there are no stack depth change points.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Sets a stack depth change at the given address.
    ///
    /// Returns the previous delta if one existed, or `None` if this is
    /// a new change point.
    pub fn set_change(&mut self, address: &Address, delta: i32) -> Option<i32> {
        self.changes.insert(address.offset, delta)
    }

    /// Removes the stack depth change at the given address.
    ///
    /// Returns the removed delta if one existed.
    pub fn remove_change(&mut self, address: &Address) -> Option<i32> {
        self.changes.remove(&address.offset)
    }

    /// Returns the stack depth delta at the given address.
    pub fn get_change(&self, address: &Address) -> Option<i32> {
        self.changes.get(&address.offset).copied()
    }

    /// Returns `true` if there is a stack depth change at the given address.
    pub fn has_change(&self, address: &Address) -> bool {
        self.changes.contains_key(&address.offset)
    }

    /// Returns all stack depth changes in address order.
    pub fn all_changes(&self) -> Vec<StackDepthChange> {
        self.changes
            .iter()
            .map(|(&addr, &delta)| StackDepthChange::new(Address::new(addr), delta))
            .collect()
    }

    /// Computes the stack depth at a given address based on the change points.
    ///
    /// Starting from the initial depth (typically 0 at function entry),
    /// walks through change points up to and including `address`.
    pub fn compute_depth_at(&self, address: &Address, initial_depth: i32) -> i32 {
        let mut depth = initial_depth;
        for (&addr, &delta) in self.changes.range(..=address.offset) {
            depth += delta;
        }
        depth
    }
}

/// Action model for setting a stack depth change.
///
/// Ported from `SetStackDepthChangeAction.java`.
#[derive(Debug, Clone)]
pub struct SetStackDepthChangeAction {
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The menu path.
    pub menu_path: Vec<String>,
}

impl SetStackDepthChangeAction {
    /// Creates a new action.
    pub fn new() -> Self {
        Self {
            enabled: true,
            menu_path: vec![
                "Function".to_string(),
                "Set Stack Depth Change...".to_string(),
            ],
        }
    }
}

impl Default for SetStackDepthChangeAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Action model for removing a stack depth change.
///
/// Ported from `RemoveStackDepthChangeAction.java`.
#[derive(Debug, Clone)]
pub struct RemoveStackDepthChangeAction {
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The menu path.
    pub menu_path: Vec<String>,
}

impl RemoveStackDepthChangeAction {
    /// Creates a new action.
    pub fn new() -> Self {
        Self {
            enabled: true,
            menu_path: vec![
                "Function".to_string(),
                "Remove Stack Depth Change".to_string(),
            ],
        }
    }
}

impl Default for RemoveStackDepthChangeAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Action model for editing the function's purge amount.
///
/// Ported from `EditFunctionPurgeAction.java`.
#[derive(Debug, Clone)]
pub struct EditFunctionPurgeAction {
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The menu path.
    pub menu_path: Vec<String>,
}

impl EditFunctionPurgeAction {
    /// Creates a new action.
    pub fn new() -> Self {
        Self {
            enabled: true,
            menu_path: vec![
                "Function".to_string(),
                "Set Function Purge...".to_string(),
            ],
        }
    }
}

impl Default for EditFunctionPurgeAction {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_stack_depth_change_event_added() {
        let event = StackDepthChangeEvent::added(addr(0x1000), 8);
        assert_eq!(event.kind, StackDepthChangeKind::Added);
        assert_eq!(event.delta, 8);
        assert!(event.previous_delta.is_none());
    }

    #[test]
    fn test_stack_depth_change_event_modified() {
        let event = StackDepthChangeEvent::modified(addr(0x1000), 16, 8);
        assert_eq!(event.kind, StackDepthChangeKind::Modified);
        assert_eq!(event.delta, 16);
        assert_eq!(event.previous_delta, Some(8));
    }

    #[test]
    fn test_stack_depth_change_event_removed() {
        let event = StackDepthChangeEvent::removed(addr(0x1000));
        assert_eq!(event.kind, StackDepthChangeKind::Removed);
        assert_eq!(event.delta, 0);
    }

    #[test]
    fn test_stack_depth_change_event_display() {
        let event = StackDepthChangeEvent::added(addr(0x1000), 8);
        let display = format!("{}", event);
        assert!(display.contains("added"));
        assert!(display.contains("1000"));
        assert!(display.contains("8"));
    }

    #[test]
    fn test_stack_depth_change_kind_display() {
        assert_eq!(format!("{}", StackDepthChangeKind::Added), "Added");
        assert_eq!(format!("{}", StackDepthChangeKind::Modified), "Modified");
        assert_eq!(format!("{}", StackDepthChangeKind::Removed), "Removed");
    }

    #[test]
    fn test_stack_depth_manager_new() {
        let mgr = StackDepthManager::new();
        assert!(mgr.is_empty());
        assert_eq!(mgr.len(), 0);
    }

    #[test]
    fn test_stack_depth_manager_set_and_get() {
        let mut mgr = StackDepthManager::new();
        assert!(mgr.set_change(&addr(0x1000), 8).is_none());
        assert_eq!(mgr.get_change(&addr(0x1000)), Some(8));
        assert!(!mgr.is_empty());

        // Modify existing
        let prev = mgr.set_change(&addr(0x1000), 16);
        assert_eq!(prev, Some(8));
        assert_eq!(mgr.get_change(&addr(0x1000)), Some(16));
    }

    #[test]
    fn test_stack_depth_manager_remove() {
        let mut mgr = StackDepthManager::new();
        mgr.set_change(&addr(0x1000), 8);
        assert!(mgr.has_change(&addr(0x1000)));

        let removed = mgr.remove_change(&addr(0x1000));
        assert_eq!(removed, Some(8));
        assert!(!mgr.has_change(&addr(0x1000)));
    }

    #[test]
    fn test_stack_depth_manager_all_changes() {
        let mut mgr = StackDepthManager::new();
        mgr.set_change(&addr(0x2000), 16);
        mgr.set_change(&addr(0x1000), 8);
        mgr.set_change(&addr(0x3000), -8);

        let changes = mgr.all_changes();
        assert_eq!(changes.len(), 3);
        // Should be in address order
        assert_eq!(changes[0].address, addr(0x1000));
        assert_eq!(changes[1].address, addr(0x2000));
        assert_eq!(changes[2].address, addr(0x3000));
    }

    #[test]
    fn test_stack_depth_manager_compute_depth_at() {
        let mut mgr = StackDepthManager::new();
        mgr.set_change(&addr(0x1000), 8);
        mgr.set_change(&addr(0x2000), -16);

        // Before any change
        assert_eq!(mgr.compute_depth_at(&addr(0x0500), 0), 0);

        // At first change
        assert_eq!(mgr.compute_depth_at(&addr(0x1000), 0), 8);

        // Between changes
        assert_eq!(mgr.compute_depth_at(&addr(0x1500), 0), 8);

        // At second change
        assert_eq!(mgr.compute_depth_at(&addr(0x2000), 0), -8);

        // With non-zero initial depth
        assert_eq!(mgr.compute_depth_at(&addr(0x2000), 100), 92);
    }

    #[test]
    fn test_stack_depth_change_display() {
        let change = StackDepthChange::new(addr(0x1000), 8);
        let display = format!("{}", change);
        assert!(display.contains("1000"));
        assert!(display.contains("8"));
    }

    #[test]
    fn test_set_stack_depth_change_action() {
        let action = SetStackDepthChangeAction::new();
        assert!(action.enabled);
        assert!(action.menu_path.last().unwrap().contains("Set Stack Depth"));
    }

    #[test]
    fn test_remove_stack_depth_change_action() {
        let action = RemoveStackDepthChangeAction::new();
        assert!(action.enabled);
        assert!(action.menu_path.last().unwrap().contains("Remove Stack Depth"));
    }

    #[test]
    fn test_edit_function_purge_action() {
        let action = EditFunctionPurgeAction::new();
        assert!(action.enabled);
        assert!(action.menu_path.last().unwrap().contains("Purge"));
    }

    #[test]
    fn test_integration_stack_depth_workflow() {
        let mut mgr = StackDepthManager::new();

        // Simulate function with stack frame adjustments
        mgr.set_change(&addr(0x1000), 16);  // push rbp; sub rsp, 8
        mgr.set_change(&addr(0x1020), -8);  // add rsp, 8
        mgr.set_change(&addr(0x1030), -16); // leave/ret

        // Walk through the function
        assert_eq!(mgr.compute_depth_at(&addr(0x0FFF), 0), 0);
        assert_eq!(mgr.compute_depth_at(&addr(0x1000), 0), 16);
        assert_eq!(mgr.compute_depth_at(&addr(0x1010), 0), 16);
        assert_eq!(mgr.compute_depth_at(&addr(0x1020), 0), 8);
        assert_eq!(mgr.compute_depth_at(&addr(0x1030), 0), -8);
    }

    #[test]
    fn test_integration_listener_pattern() {
        struct TestListener {
            events: Vec<StackDepthChangeEvent>,
        }

        impl StackDepthChangeListener for TestListener {
            fn stack_depth_changed(&mut self, event: &StackDepthChangeEvent) {
                self.events.push(event.clone());
            }
        }

        let mut listener = TestListener { events: Vec::new() };

        let event = StackDepthChangeEvent::added(addr(0x1000), 8);
        listener.stack_depth_changed(&event);

        assert_eq!(listener.events.len(), 1);
        assert_eq!(listener.events[0].kind, StackDepthChangeKind::Added);
    }

    #[test]
    fn test_stack_depth_change_kind_inequality() {
        assert_ne!(StackDepthChangeKind::Added, StackDepthChangeKind::Modified);
        assert_ne!(StackDepthChangeKind::Modified, StackDepthChangeKind::Removed);
        assert_ne!(StackDepthChangeKind::Added, StackDepthChangeKind::Removed);
    }
}
