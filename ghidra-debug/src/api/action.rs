//! Action source, GoTo input, location tracking, and auto-map spec.
//!
//! Ported from Ghidra's `ghidra.debug.api.action` package.

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
}
