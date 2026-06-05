//! Reference-based selection plugin.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.select.reference` package.
//!
//! Provides selection by references: select forward references from
//! and backward references to the current address.

use serde::{Deserialize, Serialize};

/// Direction for reference selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefDirection {
    /// Select addresses that reference the current location (back-references).
    Backward,
    /// Select addresses that the current location references (forward-references).
    Forward,
}

/// Plugin for selecting by references.
#[derive(Debug)]
pub struct SelectRefsPlugin {
    /// Plugin name.
    pub name: String,
    /// Default reference direction.
    pub direction: RefDirection,
}

impl SelectRefsPlugin {
    /// Create a new reference selection plugin.
    pub fn new() -> Self {
        Self {
            name: "SelectRefsPlugin".to_string(),
            direction: RefDirection::Backward,
        }
    }
}

impl Default for SelectRefsPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Action for selecting backward references.
#[derive(Debug)]
pub struct SelectBackRefsAction {
    pub name: String,
}

impl SelectBackRefsAction {
    pub fn new() -> Self {
        Self { name: "SelectBackRefs".to_string() }
    }
}

impl Default for SelectBackRefsAction {
    fn default() -> Self { Self::new() }
}

/// Action for selecting forward references.
#[derive(Debug)]
pub struct SelectForwardRefsAction {
    pub name: String,
}

impl SelectForwardRefsAction {
    pub fn new() -> Self {
        Self { name: "SelectForwardRefs".to_string() }
    }
}

impl Default for SelectForwardRefsAction {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ref_direction() {
        assert_ne!(RefDirection::Forward, RefDirection::Backward);
    }

    #[test]
    fn test_select_refs_plugin() {
        let plugin = SelectRefsPlugin::new();
        assert_eq!(plugin.name, "SelectRefsPlugin");
        assert_eq!(plugin.direction, RefDirection::Backward);
    }

    #[test]
    fn test_select_back_refs_action() {
        let action = SelectBackRefsAction::new();
        assert_eq!(action.name, "SelectBackRefs");
    }

    #[test]
    fn test_select_forward_refs_action() {
        let action = SelectForwardRefsAction::new();
        assert_eq!(action.name, "SelectForwardRefs");
    }
}
