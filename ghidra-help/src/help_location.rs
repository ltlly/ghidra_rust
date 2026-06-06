//! Help location types: `HelpLocation` and `DynamicHelpLocation`.
//!
//! Ported from `ghidra.util.HelpLocation` and `ghidra.util.DynamicHelpLocation`.

/// Identifies a specific help topic by module name and topic path.
///
/// Equivalent to Ghidra's `HelpLocation`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HelpLocation {
    /// The help module (book) name, e.g., `"FunctionID"`.
    pub module_name: String,
    /// The topic path within the module, e.g., `"FunctionIDPlugin.html"`.
    pub topic_path: String,
    /// Optional anchor within the topic, e.g., `"Options"`.
    pub anchor: Option<String>,
}

impl HelpLocation {
    /// Create a new help location.
    pub fn new(
        module_name: impl Into<String>,
        topic_path: impl Into<String>,
    ) -> Self {
        Self {
            module_name: module_name.into(),
            topic_path: topic_path.into(),
            anchor: None,
        }
    }

    /// Create a new help location with an anchor.
    pub fn with_anchor(
        module_name: impl Into<String>,
        topic_path: impl Into<String>,
        anchor: impl Into<String>,
    ) -> Self {
        Self {
            module_name: module_name.into(),
            topic_path: topic_path.into(),
            anchor: Some(anchor.into()),
        }
    }

    /// Returns the full URL path (module/topic#anchor).
    pub fn url_path(&self) -> String {
        let base = format!("{}/{}", self.module_name, self.topic_path);
        match &self.anchor {
            Some(a) => format!("{}#{}", base, a),
            None => base,
        }
    }
}

impl std::fmt::Display for HelpLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.url_path())
    }
}

/// A help location that computes its target dynamically at display time.
///
/// Ported from `ghidra.util.DynamicHelpLocation`. The caller provides a
/// closure that, when invoked, returns the current [`HelpLocation`].
#[derive(Clone)]
pub struct DynamicHelpLocation {
    /// A descriptive label for this dynamic help.
    pub description: String,
    /// The lazily-evaluated location (stored as a description in this
    /// non-GUI port; the actual closure would be registered at the GUI layer).
    pub provider_hint: String,
}

impl DynamicHelpLocation {
    /// Create a new dynamic help location.
    pub fn new(description: impl Into<String>, provider_hint: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            provider_hint: provider_hint.into(),
        }
    }
}

impl std::fmt::Debug for DynamicHelpLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicHelpLocation")
            .field("description", &self.description)
            .field("provider_hint", &self.provider_hint)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_help_location_new() {
        let loc = HelpLocation::new("Module", "topic.html");
        assert_eq!(loc.module_name, "Module");
        assert_eq!(loc.topic_path, "topic.html");
        assert!(loc.anchor.is_none());
    }

    #[test]
    fn test_help_location_with_anchor() {
        let loc = HelpLocation::with_anchor("Module", "topic.html", "section1");
        assert_eq!(loc.anchor.as_deref(), Some("section1"));
        assert_eq!(loc.url_path(), "Module/topic.html#section1");
    }

    #[test]
    fn test_help_location_display() {
        let loc = HelpLocation::new("Core", "index.html");
        assert_eq!(format!("{}", loc), "Core/index.html");
    }

    #[test]
    fn test_help_location_url_path_no_anchor() {
        let loc = HelpLocation::new("A", "b.html");
        assert_eq!(loc.url_path(), "A/b.html");
    }

    #[test]
    fn test_dynamic_help_location() {
        let dhl = DynamicHelpLocation::new("context-sensitive", "resolve_fn");
        assert_eq!(dhl.description, "context-sensitive");
        assert_eq!(dhl.provider_hint, "resolve_fn");
    }

    #[test]
    fn test_help_location_equality() {
        let a = HelpLocation::new("M", "t.html");
        let b = HelpLocation::new("M", "t.html");
        assert_eq!(a, b);
    }

    #[test]
    fn test_help_location_inequality() {
        let a = HelpLocation::new("M", "t1.html");
        let b = HelpLocation::new("M", "t2.html");
        assert_ne!(a, b);
    }
}
