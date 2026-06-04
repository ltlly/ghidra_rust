//! Breakpoint action items for the debugger plugin.
//!
//! Ported from Ghidra's `BreakpointActionItem`, `BreakpointActionSet`,
//! and related types. These define the actions that can be taken on
//! breakpoints: place, delete, enable, disable for both target and
//! emulated breakpoints.

use std::collections::BTreeMap;

/// The type of action to perform on a breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BreakpointActionType {
    /// Place (create) a breakpoint.
    Place,
    /// Delete a breakpoint.
    Delete,
    /// Enable a breakpoint.
    Enable,
    /// Disable a breakpoint.
    Disable,
}

/// Whether this action applies to a target breakpoint, emulated, or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BreakpointActionTarget {
    /// A breakpoint on the live target.
    Target,
    /// An emulated breakpoint.
    Emulated,
    /// Both target and emulated.
    Both,
}

/// An action item for a breakpoint.
#[derive(Debug, Clone)]
pub struct BreakpointActionItem {
    /// The type of action.
    pub action_type: BreakpointActionType,
    /// Which kind of breakpoint this applies to.
    pub action_target: BreakpointActionTarget,
    /// The address (offset) of the breakpoint.
    pub offset: u64,
    /// An optional length for a range breakpoint.
    pub length: Option<u64>,
}

impl BreakpointActionItem {
    /// Create a new action item.
    pub fn new(
        action_type: BreakpointActionType,
        action_target: BreakpointActionTarget,
        offset: u64,
    ) -> Self {
        Self {
            action_type,
            action_target,
            offset,
            length: None,
        }
    }

    /// Create a place-target-breakpoint action.
    pub fn place_target(offset: u64) -> Self {
        Self::new(
            BreakpointActionType::Place,
            BreakpointActionTarget::Target,
            offset,
        )
    }

    /// Create a delete-target-breakpoint action.
    pub fn delete_target(offset: u64) -> Self {
        Self::new(
            BreakpointActionType::Delete,
            BreakpointActionTarget::Target,
            offset,
        )
    }

    /// Create an enable-target-breakpoint action.
    pub fn enable_target(offset: u64) -> Self {
        Self::new(
            BreakpointActionType::Enable,
            BreakpointActionTarget::Target,
            offset,
        )
    }

    /// Create a disable-target-breakpoint action.
    pub fn disable_target(offset: u64) -> Self {
        Self::new(
            BreakpointActionType::Disable,
            BreakpointActionTarget::Target,
            offset,
        )
    }

    /// Create a place-emulated-breakpoint action.
    pub fn place_emu(offset: u64) -> Self {
        Self::new(
            BreakpointActionType::Place,
            BreakpointActionTarget::Emulated,
            offset,
        )
    }

    /// Create a delete-emulated-breakpoint action.
    pub fn delete_emu(offset: u64) -> Self {
        Self::new(
            BreakpointActionType::Delete,
            BreakpointActionTarget::Emulated,
            offset,
        )
    }

    /// Create an enable-emulated-breakpoint action.
    pub fn enable_emu(offset: u64) -> Self {
        Self::new(
            BreakpointActionType::Enable,
            BreakpointActionTarget::Emulated,
            offset,
        )
    }

    /// Create a disable-emulated-breakpoint action.
    pub fn disable_emu(offset: u64) -> Self {
        Self::new(
            BreakpointActionType::Disable,
            BreakpointActionTarget::Emulated,
            offset,
        )
    }

    /// Set the length for range breakpoints.
    pub fn with_length(mut self, length: u64) -> Self {
        self.length = Some(length);
        self
    }
}

/// A set of breakpoint action items that should be applied atomically.
#[derive(Debug, Clone, Default)]
pub struct BreakpointActionSet {
    items: Vec<BreakpointActionItem>,
}

impl BreakpointActionSet {
    /// Create a new empty action set.
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Add an action item to this set.
    pub fn add(&mut self, item: BreakpointActionItem) {
        self.items.push(item);
    }

    /// Get all action items.
    pub fn items(&self) -> &[BreakpointActionItem] {
        &self.items
    }

    /// Whether this set is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Number of action items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Clear all action items.
    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// Merge another action set into this one.
    pub fn merge(&mut self, other: BreakpointActionSet) {
        self.items.extend(other.items);
    }

    /// Get only the target actions.
    pub fn target_actions(&self) -> Vec<&BreakpointActionItem> {
        self.items
            .iter()
            .filter(|i| i.action_target == BreakpointActionTarget::Target)
            .collect()
    }

    /// Get only the emulated actions.
    pub fn emu_actions(&self) -> Vec<&BreakpointActionItem> {
        self.items
            .iter()
            .filter(|i| i.action_target == BreakpointActionTarget::Emulated)
            .collect()
    }
}

/// Internal tracked breakpoint state for the breakpoint service.
#[derive(Debug, Clone)]
pub struct LogicalBreakpointInternal {
    /// The address (offset).
    pub offset: u64,
    /// Optional length for range breakpoints.
    pub length: Option<u64>,
    /// Whether the target breakpoint is enabled.
    pub target_enabled: bool,
    /// Whether the emulated breakpoint is enabled.
    pub emu_enabled: bool,
    /// The expression (e.g., hex address string).
    pub expression: String,
    /// Program URL this breakpoint belongs to.
    pub program_url: Option<String>,
    /// Trace-specific overrides.
    pub trace_overrides: BTreeMap<u64, TraceBreakpointOverride>,
}

/// An override for a breakpoint in a specific trace.
#[derive(Debug, Clone)]
pub struct TraceBreakpointOverride {
    /// Whether the breakpoint is enabled in this trace.
    pub enabled: bool,
    /// The trace-specific offset.
    pub offset: Option<u64>,
}

impl LogicalBreakpointInternal {
    /// Create a new internal breakpoint state.
    pub fn new(offset: u64, expression: impl Into<String>) -> Self {
        Self {
            offset,
            length: None,
            target_enabled: true,
            emu_enabled: false,
            expression: expression.into(),
            program_url: None,
            trace_overrides: BTreeMap::new(),
        }
    }

    /// Whether the breakpoint is active (either target or emulated is enabled).
    pub fn is_active(&self) -> bool {
        self.target_enabled || self.emu_enabled
    }

    /// Toggle the target breakpoint.
    pub fn toggle_target(&mut self) {
        self.target_enabled = !self.target_enabled;
    }

    /// Toggle the emulated breakpoint.
    pub fn toggle_emu(&mut self) {
        self.emu_enabled = !self.emu_enabled;
    }

    /// Add a trace-specific override.
    pub fn add_trace_override(&mut self, trace_key: u64, overr: TraceBreakpointOverride) {
        self.trace_overrides.insert(trace_key, overr);
    }

    /// Get the override for a specific trace.
    pub fn get_trace_override(&self, trace_key: u64) -> Option<&TraceBreakpointOverride> {
        self.trace_overrides.get(&trace_key)
    }
}

/// A lone logical breakpoint that doesn't have a mapping to a program address.
#[derive(Debug, Clone)]
pub struct LoneLogicalBreakpoint {
    /// The internal state.
    pub inner: LogicalBreakpointInternal,
}

impl LoneLogicalBreakpoint {
    /// Create a new lone breakpoint.
    pub fn new(offset: u64, expression: impl Into<String>) -> Self {
        Self {
            inner: LogicalBreakpointInternal::new(offset, expression),
        }
    }
}

/// A mapped logical breakpoint that corresponds to a program address.
#[derive(Debug, Clone)]
pub struct MappedLogicalBreakpoint {
    /// The internal state.
    pub inner: LogicalBreakpointInternal,
    /// The program this breakpoint is mapped to.
    pub program_url: String,
    /// The program address this maps to.
    pub program_address: u64,
}

impl MappedLogicalBreakpoint {
    /// Create a new mapped breakpoint.
    pub fn new(
        offset: u64,
        expression: impl Into<String>,
        program_url: impl Into<String> + Clone,
        program_address: u64,
    ) -> Self {
        let url = program_url.clone().into();
        let mut inner = LogicalBreakpointInternal::new(offset, expression);
        inner.program_url = Some(url.clone());
        Self {
            inner,
            program_url: url,
            program_address,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_breakpoint_action_item() {
        let item = BreakpointActionItem::place_target(0x400000);
        assert_eq!(item.action_type, BreakpointActionType::Place);
        assert_eq!(item.action_target, BreakpointActionTarget::Target);
        assert_eq!(item.offset, 0x400000);
    }

    #[test]
    fn test_action_set() {
        let mut set = BreakpointActionSet::new();
        set.add(BreakpointActionItem::place_target(0x400000));
        set.add(BreakpointActionItem::delete_emu(0x500000));
        assert_eq!(set.len(), 2);
        assert_eq!(set.target_actions().len(), 1);
        assert_eq!(set.emu_actions().len(), 1);
    }

    #[test]
    fn test_action_set_merge() {
        let mut set1 = BreakpointActionSet::new();
        set1.add(BreakpointActionItem::place_target(0x400000));

        let mut set2 = BreakpointActionSet::new();
        set2.add(BreakpointActionItem::delete_target(0x500000));

        set1.merge(set2);
        assert_eq!(set1.len(), 2);
    }

    #[test]
    fn test_internal_breakpoint() {
        let mut bp = LogicalBreakpointInternal::new(0x400000, "0x400000");
        assert!(bp.is_active());
        bp.toggle_target();
        assert!(!bp.is_active());
        bp.toggle_emu();
        assert!(bp.is_active());
    }

    #[test]
    fn test_mapped_breakpoint() {
        let bp = MappedLogicalBreakpoint::new(0x400000, "0x400000", "/path/to/prog", 0x400000);
        assert_eq!(bp.program_url, "/path/to/prog");
        assert_eq!(bp.program_address, 0x400000);
    }

    #[test]
    fn test_trace_override() {
        let mut bp = LogicalBreakpointInternal::new(0x400000, "0x400000");
        bp.add_trace_override(
            1,
            TraceBreakpointOverride {
                enabled: true,
                offset: Some(0x500000),
            },
        );
        let ov = bp.get_trace_override(1).unwrap();
        assert!(ov.enabled);
        assert_eq!(ov.offset, Some(0x500000));
    }

    #[test]
    fn test_action_item_with_length() {
        let item = BreakpointActionItem::place_target(0x400000).with_length(10);
        assert_eq!(item.length, Some(10));
    }
}
