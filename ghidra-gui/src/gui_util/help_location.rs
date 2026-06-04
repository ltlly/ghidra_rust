//! Help location types for context-sensitive help.
//!
//! Ports `ghidra.util.HelpLocation` and `ghidra.util.DynamicHelpLocation`.

use std::fmt;

/// Identifies a specific location in the help system.
///
/// Ported from Ghidra's `ghidra.util.HelpLocation`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct HelpLocation {
    /// The help topic (module or area name).
    topic: String,
    /// The anchor within the topic page.
    anchor: String,
}

impl HelpLocation {
    /// Create a new help location.
    pub fn new(topic: impl Into<String>, anchor: impl Into<String>) -> Self {
        Self { topic: topic.into(), anchor: anchor.into() }
    }

    /// Get the topic.
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// Get the anchor.
    pub fn anchor(&self) -> &str {
        &self.anchor
    }
}

impl fmt::Display for HelpLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.topic, self.anchor)
    }
}

/// A help location whose anchor is determined dynamically at runtime.
///
/// Ported from Ghidra's `ghidra.util.DynamicHelpLocation`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct DynamicHelpLocation {
    topic: String,
    /// The dynamic anchor is resolved at query time based on program state.
    dynamic_anchor: String,
}

impl DynamicHelpLocation {
    /// Create a new dynamic help location.
    pub fn new(topic: impl Into<String>, dynamic_anchor: impl Into<String>) -> Self {
        Self { topic: topic.into(), dynamic_anchor: dynamic_anchor.into() }
    }

    /// Get the topic.
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// Get the dynamic anchor.
    pub fn dynamic_anchor(&self) -> &str {
        &self.dynamic_anchor
    }

    /// Resolve to a concrete `HelpLocation`.
    pub fn resolve(&self) -> HelpLocation {
        HelpLocation::new(&self.topic, &self.dynamic_anchor)
    }
}

impl fmt::Display for DynamicHelpLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.topic, self.dynamic_anchor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_help_location_creation() {
        let hl = HelpLocation::new("MyPlugin", "main_window");
        assert_eq!(hl.topic(), "MyPlugin");
        assert_eq!(hl.anchor(), "main_window");
    }

    #[test]
    fn test_help_location_display() {
        let hl = HelpLocation::new("CodeBrowser", "listing_view");
        assert_eq!(hl.to_string(), "CodeBrowser#listing_view");
    }

    #[test]
    fn test_help_location_serialization() {
        let hl = HelpLocation::new("Test", "anchor");
        let json = serde_json::to_string(&hl).unwrap();
        let deserialized: HelpLocation = serde_json::from_str(&json).unwrap();
        assert_eq!(hl, deserialized);
    }

    #[test]
    fn test_dynamic_help_location() {
        let dhl = DynamicHelpLocation::new("Functions", "func_0x1000");
        let resolved = dhl.resolve();
        assert_eq!(resolved.topic(), "Functions");
        assert_eq!(resolved.anchor(), "func_0x1000");
    }

    #[test]
    fn test_dynamic_help_location_display() {
        let dhl = DynamicHelpLocation::new("Help", "dynamic");
        assert_eq!(dhl.to_string(), "Help#dynamic");
    }
}
