//! Action trigger (key stroke + mouse binding).
//!
//! Ports `ghidra.framework.options.ActionTrigger`.

use std::fmt;

use crate::gui_event::MouseBinding;
use super::option_value::KeyStroke;

/// Represents a way to trigger an action: a key stroke, a mouse binding,
/// or both.
///
/// Ported from Ghidra's `ghidra.framework.options.ActionTrigger`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ActionTrigger {
    key_stroke: Option<KeyStroke>,
    mouse_binding: Option<MouseBinding>,
}

impl ActionTrigger {
    /// Create a trigger from a key stroke only.
    pub fn from_key_stroke(ks: KeyStroke) -> Self {
        Self { key_stroke: Some(ks), mouse_binding: None }
    }

    /// Create a trigger from a mouse binding only.
    pub fn from_mouse_binding(mb: MouseBinding) -> Self {
        Self { key_stroke: None, mouse_binding: Some(mb) }
    }

    /// Create a trigger from both a key stroke and a mouse binding.
    ///
    /// At least one must be `Some`.
    pub fn new(key_stroke: Option<KeyStroke>, mouse_binding: Option<MouseBinding>) -> Option<Self> {
        if key_stroke.is_none() && mouse_binding.is_none() {
            return None;
        }
        Some(Self { key_stroke, mouse_binding })
    }

    /// Get the key stroke, if any.
    pub fn key_stroke(&self) -> Option<&KeyStroke> {
        self.key_stroke.as_ref()
    }

    /// Get the mouse binding, if any.
    pub fn mouse_binding(&self) -> Option<&MouseBinding> {
        self.mouse_binding.as_ref()
    }

    /// Parse from the string representation.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        // Simple parsing: if it contains "Button" it's a mouse binding,
        // otherwise treat as key stroke.
        if s.contains("Button") || s.contains("button") {
            let mb = MouseBinding::parse(s)?;
            Some(Self::from_mouse_binding(mb))
        } else {
            Some(Self::from_key_stroke(KeyStroke::new(s)))
        }
    }
}

impl fmt::Display for ActionTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ActionTrigger: Key Stroke[")?;
        if let Some(ks) = &self.key_stroke {
            write!(f, "{}", ks)?;
        }
        write!(f, "], Mouse Binding[")?;
        if let Some(mb) = &self.mouse_binding {
            write!(f, "{}", mb)?;
        }
        write!(f, "]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_trigger_from_key_stroke() {
        let at = ActionTrigger::from_key_stroke(KeyStroke::new("Ctrl+S"));
        assert!(at.key_stroke().is_some());
        assert!(at.mouse_binding().is_none());
    }

    #[test]
    fn test_action_trigger_new_requires_at_least_one() {
        assert!(ActionTrigger::new(None, None).is_none());
        assert!(ActionTrigger::new(Some(KeyStroke::new("F1")), None).is_some());
    }

    #[test]
    fn test_action_trigger_display() {
        let at = ActionTrigger::from_key_stroke(KeyStroke::new("Ctrl+Z"));
        let s = at.to_string();
        assert!(s.contains("Ctrl+Z"));
    }

    #[test]
    fn test_action_trigger_parse_key() {
        let at = ActionTrigger::parse("Ctrl+Z").unwrap();
        assert!(at.key_stroke().is_some());
    }

    #[test]
    fn test_action_trigger_parse_empty() {
        assert!(ActionTrigger::parse("").is_none());
    }
}
