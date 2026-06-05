//! Breakpoint action items for the breakpoint service.
//!
//! Ported from Ghidra's breakpoint action items in
//! `ghidra.app.plugin.core.debug.service.breakpoint`. These define
//! the individual actions that can be taken on breakpoints
//! (enable, disable, delete) for both target and emulated breakpoints.

use serde::{Deserialize, Serialize};

/// Types of breakpoint actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreakpointActionKind {
    /// Place a new breakpoint.
    Place,
    /// Enable an existing breakpoint.
    Enable,
    /// Disable a breakpoint.
    Disable,
    /// Delete a breakpoint.
    Delete,
}

/// The target of a breakpoint action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreakpointActionTarget {
    /// Apply to the live debug target.
    Target,
    /// Apply to the emulator.
    Emulator,
}

/// A breakpoint action item.
///
/// Represents a single action to take on a breakpoint, such as
/// enabling, disabling, or deleting it on either the target or emulator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointActionItem {
    /// The kind of action.
    pub kind: BreakpointActionKind,
    /// The target (target or emulator).
    pub target: BreakpointActionTarget,
    /// The breakpoint specification key.
    pub spec_key: i64,
    /// The breakpoint location key (for location-specific actions).
    pub location_key: Option<i64>,
    /// Description of this action.
    pub description: String,
}

impl BreakpointActionItem {
    /// Create a new action item.
    pub fn new(
        kind: BreakpointActionKind,
        target: BreakpointActionTarget,
        spec_key: i64,
    ) -> Self {
        Self {
            kind,
            target,
            spec_key,
            location_key: None,
            description: String::new(),
        }
    }

    /// Create a place-target-breakpoint action.
    pub fn place_target(spec_key: i64) -> Self {
        Self::new(
            BreakpointActionKind::Place,
            BreakpointActionTarget::Target,
            spec_key,
        )
    }

    /// Create a place-emulator-breakpoint action.
    pub fn place_emu(spec_key: i64) -> Self {
        Self::new(
            BreakpointActionKind::Place,
            BreakpointActionTarget::Emulator,
            spec_key,
        )
    }

    /// Create an enable-target-breakpoint action.
    pub fn enable_target(spec_key: i64) -> Self {
        Self::new(
            BreakpointActionKind::Enable,
            BreakpointActionTarget::Target,
            spec_key,
        )
    }

    /// Create a disable-target-breakpoint action.
    pub fn disable_target(spec_key: i64) -> Self {
        Self::new(
            BreakpointActionKind::Disable,
            BreakpointActionTarget::Target,
            spec_key,
        )
    }

    /// Create a delete-target-breakpoint action.
    pub fn delete_target(spec_key: i64) -> Self {
        Self::new(
            BreakpointActionKind::Delete,
            BreakpointActionTarget::Target,
            spec_key,
        )
    }

    /// Create a delete-emulator-breakpoint action.
    pub fn delete_emu(spec_key: i64) -> Self {
        Self::new(
            BreakpointActionKind::Delete,
            BreakpointActionTarget::Emulator,
            spec_key,
        )
    }

    /// Set the location key for location-specific actions.
    pub fn with_location(mut self, location_key: i64) -> Self {
        self.location_key = Some(location_key);
        self
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }
}

/// A set of breakpoint actions to execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointActionSet {
    /// The actions in this set.
    actions: Vec<BreakpointActionItem>,
}

impl BreakpointActionSet {
    /// Create an empty action set.
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),
        }
    }

    /// Add an action.
    pub fn add(&mut self, action: BreakpointActionItem) {
        self.actions.push(action);
    }

    /// Get all actions.
    pub fn actions(&self) -> &[BreakpointActionItem] {
        &self.actions
    }

    /// Get the number of actions.
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Filter actions by target.
    pub fn for_target(&self, target: BreakpointActionTarget) -> Vec<&BreakpointActionItem> {
        self.actions.iter().filter(|a| a.target == target).collect()
    }

    /// Filter actions by kind.
    pub fn by_kind(&self, kind: BreakpointActionKind) -> Vec<&BreakpointActionItem> {
        self.actions.iter().filter(|a| a.kind == kind).collect()
    }
}

impl Default for BreakpointActionSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Exception for tracked-too-soon breakpoint state.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Breakpoint tracked too soon: {message}")]
pub struct TrackedTooSoonException {
    /// The error message.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_item_place_target() {
        let item = BreakpointActionItem::place_target(42);
        assert_eq!(item.kind, BreakpointActionKind::Place);
        assert_eq!(item.target, BreakpointActionTarget::Target);
        assert_eq!(item.spec_key, 42);
    }

    #[test]
    fn test_action_item_place_emu() {
        let item = BreakpointActionItem::place_emu(10);
        assert_eq!(item.target, BreakpointActionTarget::Emulator);
    }

    #[test]
    fn test_action_item_builder() {
        let item = BreakpointActionItem::enable_target(5)
            .with_location(100)
            .with_description("enable bp");
        assert_eq!(item.location_key, Some(100));
        assert_eq!(item.description, "enable bp");
    }

    #[test]
    fn test_action_item_delete() {
        let item = BreakpointActionItem::delete_target(1);
        assert_eq!(item.kind, BreakpointActionKind::Delete);
    }

    #[test]
    fn test_action_set_add_and_count() {
        let mut set = BreakpointActionSet::new();
        set.add(BreakpointActionItem::place_target(1));
        set.add(BreakpointActionItem::delete_emu(2));
        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());
    }

    #[test]
    fn test_action_set_filter_by_target() {
        let mut set = BreakpointActionSet::new();
        set.add(BreakpointActionItem::place_target(1));
        set.add(BreakpointActionItem::place_emu(2));
        set.add(BreakpointActionItem::enable_target(3));
        let target_actions = set.for_target(BreakpointActionTarget::Target);
        assert_eq!(target_actions.len(), 2);
    }

    #[test]
    fn test_action_set_filter_by_kind() {
        let mut set = BreakpointActionSet::new();
        set.add(BreakpointActionItem::enable_target(1));
        set.add(BreakpointActionItem::disable_target(2));
        set.add(BreakpointActionItem::enable_target(3));
        let enables = set.by_kind(BreakpointActionKind::Enable);
        assert_eq!(enables.len(), 2);
    }

    #[test]
    fn test_tracked_too_soon_exception() {
        let err = TrackedTooSoonException {
            message: "too soon".to_string(),
        };
        assert!(err.to_string().contains("too soon"));
    }
}
