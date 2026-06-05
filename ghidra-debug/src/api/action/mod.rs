//! Action source, GoTo input, location tracking, and auto-map spec.
//!
//! Ported from Ghidra's `ghidra.debug.api.action` package.

pub mod factories;

use serde::{Deserialize, Serialize};

/// Possible sources that drive actions or method invocations.
///
/// This is primarily used to determine where and how errors should be reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionSource {
    /// The action was requested by the user, usually via a UI action.
    /// It is acceptable to display an error message.
    Manual,
    /// The action was requested automatically, usually by some background thread.
    /// Error messages should be delivered to the log or Debug Console.
    Automatic,
}

impl ActionSource {
    /// Whether this source is user-driven.
    pub fn is_manual(&self) -> bool {
        *self == Self::Manual
    }

    /// Whether this source is automatic/background.
    pub fn is_automatic(&self) -> bool {
        *self == Self::Automatic
    }
}

/// Input for a "Go To" action, combining an optional address space and an offset.
///
/// Ported from Ghidra's `GoToInput` record.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GoToInput {
    /// The address space name, or `None` for a raw offset.
    pub space: Option<String>,
    /// The offset expression (hex string, Sleigh expression, etc.).
    pub offset: String,
}

impl GoToInput {
    /// Create from an offset only (no space).
    pub fn offset_only(offset: impl Into<String>) -> Self {
        Self {
            space: None,
            offset: offset.into(),
        }
    }

    /// Create with a specific address space.
    pub fn with_space(space: impl Into<String>, offset: impl Into<String>) -> Self {
        Self {
            space: Some(space.into()),
            offset: offset.into(),
        }
    }

    /// Parse from a string like `"ram:0x400000"` or `"0x400000"`.
    pub fn from_string(s: &str) -> Self {
        if let Some(idx) = s.find(':') {
            Self {
                space: Some(s[..idx].to_string()),
                offset: s[idx + 1..].to_string(),
            }
        } else {
            Self {
                space: None,
                offset: s.to_string(),
            }
        }
    }

    /// Format as a display string.
    pub fn to_display_string(&self) -> String {
        match &self.space {
            Some(s) => format!("{}:{}", s, self.offset),
            None => self.offset.clone(),
        }
    }
}

impl std::fmt::Display for GoToInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_display_string())
    }
}

/// The kind of tracking event that may trigger a location update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrackingEvent {
    /// A value changed in the trace.
    ValueChanged,
    /// The stack changed (e.g., frame pointer changed).
    StackChanged,
    /// The snap/time changed.
    SnapChanged,
    /// The thread/process focus changed.
    ThreadChanged,
}

/// A location tracking specification.
///
/// Ported from Ghidra's `LocationTrackingSpec` / `LocationTracker` interfaces.
/// Each implementation specifies how to track a particular kind of location
/// (e.g., the program counter, the stack pointer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationTrackingSpec {
    /// Display name for this tracking spec.
    pub name: String,
    /// The address space being tracked (e.g., "register", "ram").
    pub space: String,
    /// Whether to disassemble at this location.
    pub should_disassemble: bool,
    /// Which events trigger re-computation.
    pub triggers: Vec<TrackingEvent>,
}

impl LocationTrackingSpec {
    /// Create a new tracking spec.
    pub fn new(
        name: impl Into<String>,
        space: impl Into<String>,
        should_disassemble: bool,
    ) -> Self {
        Self {
            name: name.into(),
            space: space.into(),
            should_disassemble,
            triggers: Vec::new(),
        }
    }

    /// Add a trigger event.
    pub fn with_trigger(mut self, event: TrackingEvent) -> Self {
        self.triggers.push(event);
        self
    }
}

/// An auto-map specification for mapping dynamic (trace) memory to static (program) memory.
///
/// Ported from Ghidra's `AutoMapSpec` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoMapSpec {
    /// Configuration name for serialization.
    pub config_name: String,
    /// Menu display name.
    pub menu_name: String,
    /// Description of this mapping specification.
    pub description: String,
    /// Whether this spec has an associated background task.
    pub has_task: bool,
}

impl AutoMapSpec {
    /// Create a new auto-map spec.
    pub fn new(
        config_name: impl Into<String>,
        menu_name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            config_name: config_name.into(),
            menu_name: menu_name.into(),
            description: description.into(),
            has_task: true,
        }
    }
}

/// Registry of auto-map specifications.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AutoMapSpecRegistry {
    specs: std::collections::BTreeMap<String, AutoMapSpec>,
}

impl AutoMapSpecRegistry {
    /// Create a new registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an auto-map spec.
    pub fn register(&mut self, spec: AutoMapSpec) {
        self.specs.insert(spec.config_name.clone(), spec);
    }

    /// Get a spec by config name.
    pub fn get(&self, name: &str) -> Option<&AutoMapSpec> {
        self.specs.get(name)
    }

    /// Get all registered specs.
    pub fn all_specs(&self) -> &std::collections::BTreeMap<String, AutoMapSpec> {
        &self.specs
    }

    /// Number of registered specs.
    pub fn len(&self) -> usize {
        self.specs.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.specs.is_empty()
    }
}

/// A location tracker that computes the current trace address for navigation.
///
/// Ported from Ghidra's `LocationTracker` interface. Implementations
/// compute addresses for "Go To" actions and determine whether changes
/// should trigger re-navigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationTracker {
    /// The name of the tracking specification.
    pub spec_name: String,
    /// The default Sleigh expression for "Go To".
    pub goto_expression: String,
    /// Whether this tracker is currently active.
    pub active: bool,
    /// Last computed address (offset), if any.
    pub last_computed_offset: Option<u64>,
    /// Last computed address space, if any.
    pub last_computed_space: Option<String>,
}

impl LocationTracker {
    /// Create a new location tracker.
    pub fn new(spec_name: impl Into<String>) -> Self {
        Self {
            spec_name: spec_name.into(),
            goto_expression: String::new(),
            active: true,
            last_computed_offset: None,
            last_computed_space: None,
        }
    }

    /// Set the Go To expression.
    pub fn with_goto_expression(mut self, expr: impl Into<String>) -> Self {
        self.goto_expression = expr.into();
        self
    }

    /// Check if the tracker is affected by a bytes change.
    pub fn affected_by_bytes_change(&self, _space: &str, _snap: i64) -> bool {
        self.active
    }

    /// Check if the tracker is affected by a register change.
    pub fn affected_by_register_change(&self, _register_name: &str, _snap: i64) -> bool {
        self.active
    }

    /// Check if the tracker is affected by a stack change.
    pub fn affected_by_stack_change(&self, _snap: i64) -> bool {
        self.active
    }

    /// Update the last computed address.
    pub fn set_computed_address(&mut self, space: impl Into<String>, offset: u64) {
        self.last_computed_space = Some(space.into());
        self.last_computed_offset = Some(offset);
    }

    /// Clear the last computed address.
    pub fn clear_computed_address(&mut self) {
        self.last_computed_space = None;
        self.last_computed_offset = None;
    }
}

/// An auto-read memory specification.
///
/// Ported from Ghidra's `AutoReadMemorySpec`. Specifies how to
/// automatically read target memory into the trace when the target
/// state changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoReadMemorySpec {
    /// Configuration name for serialization.
    pub config_name: String,
    /// Menu display name.
    pub menu_name: String,
    /// Description of this specification.
    pub description: String,
    /// Whether this spec is enabled.
    pub enabled: bool,
}

impl AutoReadMemorySpec {
    /// Create a new auto-read memory spec.
    pub fn new(
        config_name: impl Into<String>,
        menu_name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            config_name: config_name.into(),
            menu_name: menu_name.into(),
            description: description.into(),
            enabled: true,
        }
    }
}

/// Registry of auto-read memory specifications.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AutoReadMemorySpecRegistry {
    specs: std::collections::BTreeMap<String, AutoReadMemorySpec>,
}

impl AutoReadMemorySpecRegistry {
    /// Create a new registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an auto-read memory spec.
    pub fn register(&mut self, spec: AutoReadMemorySpec) {
        self.specs.insert(spec.config_name.clone(), spec);
    }

    /// Get a spec by config name.
    pub fn get(&self, name: &str) -> Option<&AutoReadMemorySpec> {
        self.specs.get(name)
    }

    /// Get all registered specs.
    pub fn all_specs(&self) -> &std::collections::BTreeMap<String, AutoReadMemorySpec> {
        &self.specs
    }

    /// Number of registered specs.
    pub fn len(&self) -> usize {
        self.specs.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.specs.is_empty()
    }
}

/// Utility for collecting unique instances by name.
///
/// Ported from Ghidra's `InstanceUtils`.
pub struct InstanceUtils;

impl InstanceUtils {
    /// Collect unique instances by their name into a map.
    pub fn collect_by_name<T, F>(items: impl IntoIterator<Item = T>, name_fn: F) -> std::collections::BTreeMap<String, T>
    where
        F: Fn(&T) -> String,
    {
        items
            .into_iter()
            .map(|item| {
                let name = name_fn(&item);
                (name, item)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_source() {
        assert!(ActionSource::Manual.is_manual());
        assert!(!ActionSource::Manual.is_automatic());
        assert!(ActionSource::Automatic.is_automatic());
        assert!(!ActionSource::Automatic.is_manual());
    }

    #[test]
    fn test_goto_input_parse() {
        let input = GoToInput::from_string("ram:0x400000");
        assert_eq!(input.space.as_deref(), Some("ram"));
        assert_eq!(input.offset, "0x400000");

        let input = GoToInput::from_string("0x400000");
        assert!(input.space.is_none());
        assert_eq!(input.offset, "0x400000");
    }

    #[test]
    fn test_goto_input_display() {
        let input = GoToInput::with_space("ram", "0x400000");
        assert_eq!(input.to_string(), "ram:0x400000");

        let input = GoToInput::offset_only("0x400000");
        assert_eq!(input.to_string(), "0x400000");
    }

    #[test]
    fn test_location_tracking_spec() {
        let spec = LocationTrackingSpec::new("PC", "register", true)
            .with_trigger(TrackingEvent::ValueChanged)
            .with_trigger(TrackingEvent::SnapChanged);
        assert_eq!(spec.name, "PC");
        assert!(spec.should_disassemble);
        assert_eq!(spec.triggers.len(), 2);
    }

    #[test]
    fn test_auto_map_spec() {
        let spec = AutoMapSpec::new("module", "Map Modules", "Maps loaded modules");
        assert_eq!(spec.config_name, "module");
        assert!(spec.has_task);
    }

    #[test]
    fn test_auto_map_registry() {
        let mut reg = AutoMapSpecRegistry::new();
        assert!(reg.is_empty());

        reg.register(AutoMapSpec::new("m1", "Map 1", "First"));
        reg.register(AutoMapSpec::new("m2", "Map 2", "Second"));

        assert_eq!(reg.len(), 2);
        assert!(reg.get("m1").is_some());
        assert!(reg.get("missing").is_none());
    }

    #[test]
    fn test_action_source_serde() {
        let src = ActionSource::Manual;
        let json = serde_json::to_string(&src).unwrap();
        let back: ActionSource = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ActionSource::Manual);
    }

    #[test]
    fn test_goto_input_serde() {
        let input = GoToInput::with_space("register", "RIP");
        let json = serde_json::to_string(&input).unwrap();
        let back: GoToInput = serde_json::from_str(&json).unwrap();
        assert_eq!(back, input);
    }

    #[test]
    fn test_location_tracker() {
        let mut tracker = LocationTracker::new("PC")
            .with_goto_expression("RIP");
        assert_eq!(tracker.spec_name, "PC");
        assert_eq!(tracker.goto_expression, "RIP");
        assert!(tracker.active);
        assert!(tracker.last_computed_offset.is_none());

        tracker.set_computed_address("register", 0x400000);
        assert_eq!(tracker.last_computed_offset, Some(0x400000));
        assert_eq!(tracker.last_computed_space.as_deref(), Some("register"));

        tracker.clear_computed_address();
        assert!(tracker.last_computed_offset.is_none());
    }

    #[test]
    fn test_location_tracker_affected() {
        let tracker = LocationTracker::new("PC");
        assert!(tracker.affected_by_bytes_change("ram", 0));
        assert!(tracker.affected_by_register_change("RIP", 0));
        assert!(tracker.affected_by_stack_change(0));
    }

    #[test]
    fn test_auto_read_memory_spec() {
        let spec = AutoReadMemorySpec::new(
            "regions",
            "Read Regions",
            "Read memory regions automatically",
        );
        assert_eq!(spec.config_name, "regions");
        assert!(spec.enabled);
    }

    #[test]
    fn test_auto_read_memory_spec_registry() {
        let mut reg = AutoReadMemorySpecRegistry::new();
        assert!(reg.is_empty());

        reg.register(AutoReadMemorySpec::new("r1", "Read 1", "First"));
        reg.register(AutoReadMemorySpec::new("r2", "Read 2", "Second"));

        assert_eq!(reg.len(), 2);
        assert!(reg.get("r1").is_some());
        assert!(reg.get("missing").is_none());
    }

    #[test]
    fn test_instance_utils() {
        let items = vec![
            AutoMapSpec::new("a", "A", "first"),
            AutoMapSpec::new("b", "B", "second"),
        ];
        let map = InstanceUtils::collect_by_name(items, |s| s.config_name.clone());
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("a"));
    }

    #[test]
    fn test_location_tracker_serde() {
        let tracker = LocationTracker::new("PC");
        let json = serde_json::to_string(&tracker).unwrap();
        let back: LocationTracker = serde_json::from_str(&json).unwrap();
        assert_eq!(back.spec_name, "PC");
    }

    #[test]
    fn test_auto_read_memory_spec_serde() {
        let spec = AutoReadMemorySpec::new("test", "Test", "Desc");
        let json = serde_json::to_string(&spec).unwrap();
        let back: AutoReadMemorySpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back.config_name, "test");
    }
}
