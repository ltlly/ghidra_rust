//! Label editing actions.
//!
//! Ported from Ghidra's label plugin action classes.

use serde::{Deserialize, Serialize};

/// Label actions available in the listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LabelAction {
    /// Add a new label at the current address.
    AddLabel,
    /// Edit the existing label at the current address.
    EditLabel,
    /// Remove the label at the current address.
    RemoveLabel,
    /// Rename a label.
    Rename,
    /// Apply the primary label.
    SetPrimary,
}

impl LabelAction {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::AddLabel => "Add Label",
            Self::EditLabel => "Edit Label",
            Self::RemoveLabel => "Remove Label",
            Self::Rename => "Rename Label",
            Self::SetPrimary => "Set Primary Label",
        }
    }
}

/// A label at an address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelEntry {
    /// Address of the label.
    pub address: String,
    /// Label name.
    pub name: String,
    /// Whether this is the primary label at the address.
    pub is_primary: bool,
    /// Namespace path.
    pub namespace: String,
}

impl LabelEntry {
    pub fn new(address: &str, name: &str) -> Self {
        Self { address: address.to_string(), name: name.to_string(), is_primary: true, namespace: "Global".to_string() }
    }
    pub fn with_namespace(mut self, ns: &str) -> Self {
        self.namespace = ns.to_string(); self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_action_display() {
        assert_eq!(LabelAction::AddLabel.display_name(), "Add Label");
        assert_eq!(LabelAction::Rename.display_name(), "Rename Label");
    }

    #[test]
    fn test_label_entry() {
        let entry = LabelEntry::new("0x401000", "main").with_namespace("Global");
        assert_eq!(entry.name, "main");
        assert!(entry.is_primary);
        assert_eq!(entry.namespace, "Global");
    }
}
