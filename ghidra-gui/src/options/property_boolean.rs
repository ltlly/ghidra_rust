//! Port of `ghidra.framework.options.PropertyBoolean`.
//!
//! A checkbox-based boolean property editor that allows toggling a boolean
//! option value. In the Java version this extends `JCheckBox`; in Rust/egui
//! it stores the current boolean state and provides toggle/select operations.

/// A checkbox-based editor for boolean option values.
///
/// Ported from Ghidra's `ghidra.framework.options.PropertyBoolean`.
/// In the Java version, this extends `JCheckBox` and listens for item events.
/// In Rust, this stores the current boolean value and syncs it back to
/// the parent editor.
#[derive(Debug, Clone)]
pub struct PropertyBoolean {
    /// Current selected state.
    selected: bool,
    /// Whether to notify the parent editor of changes.
    notify_editor: bool,
    /// Error message, if any.
    error: Option<String>,
}

impl PropertyBoolean {
    /// Create a new boolean property editor with an initial value.
    pub fn new(initial_value: bool) -> Self {
        Self {
            selected: initial_value,
            notify_editor: true,
            error: None,
        }
    }

    /// Get the current selected state.
    pub fn is_selected(&self) -> bool {
        self.selected
    }

    /// Toggle the selected state.
    pub fn toggle(&mut self) {
        self.selected = !self.selected;
    }

    /// Set the selected state directly.
    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }

    /// Update the value from an external source without triggering editor notifications.
    pub fn set_value_silent(&mut self, value: bool) {
        self.notify_editor = false;
        self.selected = value;
        self.notify_editor = true;
    }

    /// Check whether editor notifications are enabled.
    pub fn notify_editor(&self) -> bool {
        self.notify_editor
    }

    /// Get the error message, if any.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Set an error message.
    pub fn set_error(&mut self, msg: impl Into<String>) {
        self.error = Some(msg.into());
    }

    /// Clear the error message.
    pub fn clear_error(&mut self) {
        self.error = None;
    }

    /// Get the current value as a boolean.
    pub fn value(&self) -> bool {
        self.selected
    }
}

impl Default for PropertyBoolean {
    fn default() -> Self {
        Self::new(false)
    }
}

impl std::fmt::Display for PropertyBoolean {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PropertyBoolean: {}", self.selected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_boolean_new() {
        let pb = PropertyBoolean::new(true);
        assert!(pb.is_selected());
        assert!(pb.value());
    }

    #[test]
    fn test_property_boolean_default() {
        let pb = PropertyBoolean::default();
        assert!(!pb.is_selected());
        assert!(!pb.value());
    }

    #[test]
    fn test_property_boolean_toggle() {
        let mut pb = PropertyBoolean::new(false);
        assert!(!pb.is_selected());
        pb.toggle();
        assert!(pb.is_selected());
        pb.toggle();
        assert!(!pb.is_selected());
    }

    #[test]
    fn test_property_boolean_set_selected() {
        let mut pb = PropertyBoolean::new(false);
        pb.set_selected(true);
        assert!(pb.is_selected());
    }

    #[test]
    fn test_property_boolean_set_value_silent() {
        let mut pb = PropertyBoolean::new(false);
        assert!(pb.notify_editor());
        pb.set_value_silent(true);
        assert!(pb.is_selected());
        assert!(pb.notify_editor());
    }

    #[test]
    fn test_property_boolean_error() {
        let mut pb = PropertyBoolean::new(false);
        assert!(pb.error().is_none());
        pb.set_error("something went wrong");
        assert!(pb.error().is_some());
        assert_eq!(pb.error().unwrap(), "something went wrong");
        pb.clear_error();
        assert!(pb.error().is_none());
    }

    #[test]
    fn test_property_boolean_display() {
        let pb = PropertyBoolean::new(true);
        let s = format!("{}", pb);
        assert!(s.contains("true"));
    }
}
