//! Cycle group support for data-type cycling in the function signature.
//!
//! Ported from `ghidra.app.plugin.core.function.CycleGroup` and
//! `CycleGroupAction`.  Cycle groups allow users to quickly toggle
//! between equivalent data-type representations (e.g., hex/decimal/
//! octal/binary for an integer, or pointer/integer for an address).

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CycleGroup -- a group of related data types the user can cycle through
// ---------------------------------------------------------------------------

/// A group of related data-type representations that the user can cycle
/// through when editing a variable or operand.
///
/// Ported from `ghidra.app.plugin.core.function.CycleGroup`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleGroup {
    /// Display name for this cycle group.
    pub name: String,
    /// Ordered list of type names in this group.
    pub types: Vec<String>,
}

impl CycleGroup {
    /// Create a new cycle group.
    pub fn new(name: impl Into<String>, types: Vec<String>) -> Self {
        Self {
            name: name.into(),
            types,
        }
    }

    /// Get the next type in the cycle after the given type.
    pub fn next(&self, current: &str) -> Option<&str> {
        let idx = self.types.iter().position(|t| t == current)?;
        let next_idx = (idx + 1) % self.types.len();
        self.types.get(next_idx).map(|s| s.as_str())
    }

    /// Get the previous type in the cycle before the given type.
    pub fn previous(&self, current: &str) -> Option<&str> {
        let idx = self.types.iter().position(|t| t == current)?;
        let prev_idx = if idx == 0 { self.types.len() - 1 } else { idx - 1 };
        self.types.get(prev_idx).map(|s| s.as_str())
    }

    /// Whether the given type name is in this cycle group.
    pub fn contains(&self, type_name: &str) -> bool {
        self.types.iter().any(|t| t == type_name)
    }

    /// Number of types in this group.
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// Whether this group is empty.
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Built-in cycle groups
// ---------------------------------------------------------------------------

/// All built-in cycle groups defined by Ghidra.
///
/// Ported from `CycleGroup.ALL_CYCLE_GROUPS`.
pub fn all_cycle_groups() -> Vec<CycleGroup> {
    vec![
        CycleGroup::new(
            "Signedness",
            vec![
                "byte".into(),
                "char".into(),
                "word".into(),
                "short".into(),
                "dword".into(),
                "int".into(),
                "qword".into(),
                "long long".into(),
            ],
        ),
        CycleGroup::new(
            "Pointer / Integer",
            vec![
                "pointer".into(),
                "dword".into(),
                "qword".into(),
            ],
        ),
        CycleGroup::new(
            "Float",
            vec![
                "float".into(),
                "double".into(),
            ],
        ),
        CycleGroup::new(
            "String",
            vec![
                "string".into(),
                "unicode".into(),
                "pstring".into(),
            ],
        ),
    ]
}

/// A cycle group action -- pairs a [`CycleGroup`] with a default type.
///
/// Ported from `CycleGroupAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleGroupAction {
    /// The cycle group.
    pub group: CycleGroup,
    /// The current type selected in this cycle group.
    pub current_type: String,
    /// Whether this action is enabled.
    pub enabled: bool,
}

impl CycleGroupAction {
    /// Create a new cycle group action.
    pub fn new(group: CycleGroup) -> Self {
        let first = group.types.first().cloned().unwrap_or_default();
        Self {
            current_type: first,
            group,
            enabled: true,
        }
    }

    /// Cycle to the next type.
    pub fn cycle_next(&mut self) {
        if let Some(next) = self.group.next(&self.current_type) {
            self.current_type = next.to_string();
        }
    }

    /// Cycle to the previous type.
    pub fn cycle_previous(&mut self) {
        if let Some(prev) = self.group.previous(&self.current_type) {
            self.current_type = prev.to_string();
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cycle_group_next() {
        let g = CycleGroup::new("Integers", vec![
            "byte".into(), "word".into(), "dword".into(), "qword".into(),
        ]);
        assert_eq!(g.next("byte"), Some("word"));
        assert_eq!(g.next("dword"), Some("qword"));
        assert_eq!(g.next("qword"), Some("byte")); // wraps
    }

    #[test]
    fn test_cycle_group_previous() {
        let g = CycleGroup::new("Integers", vec![
            "byte".into(), "word".into(), "dword".into(),
        ]);
        assert_eq!(g.previous("byte"), Some("dword")); // wraps
        assert_eq!(g.previous("word"), Some("byte"));
    }

    #[test]
    fn test_cycle_group_contains() {
        let g = CycleGroup::new("Float", vec!["float".into(), "double".into()]);
        assert!(g.contains("float"));
        assert!(!g.contains("int"));
    }

    #[test]
    fn test_cycle_group_len() {
        let g = CycleGroup::new("Test", vec!["a".into(), "b".into()]);
        assert_eq!(g.len(), 2);
        assert!(!g.is_empty());

        let empty = CycleGroup::new("Empty", vec![]);
        assert!(empty.is_empty());
    }

    #[test]
    fn test_all_cycle_groups() {
        let groups = all_cycle_groups();
        assert!(!groups.is_empty());
        // Signedness group should exist
        assert!(groups.iter().any(|g| g.name == "Signedness"));
    }

    #[test]
    fn test_cycle_group_action() {
        let g = CycleGroup::new("Test", vec!["a".into(), "b".into(), "c".into()]);
        let mut action = CycleGroupAction::new(g);
        assert_eq!(action.current_type, "a");

        action.cycle_next();
        assert_eq!(action.current_type, "b");

        action.cycle_next();
        assert_eq!(action.current_type, "c");

        action.cycle_next();
        assert_eq!(action.current_type, "a"); // wraps

        action.cycle_previous();
        assert_eq!(action.current_type, "c");
    }

    #[test]
    fn test_cycle_group_action_disabled() {
        let g = CycleGroup::new("X", vec!["x".into()]);
        let mut action = CycleGroupAction::new(g);
        action.enabled = false;
        assert!(!action.enabled);
    }
}
