//! Extended data actions -- additional actions for data management.
//!
//! Ported from `VoidDataAction.java`, `CycleGroupAction.java`,
//! and recently-used data type tracking in Ghidra's
//! `ghidra.app.plugin.core.data`.
//!
//! This module provides:
//! - [`PointerSize`] -- pointer size enum for data type conversions
//! - [`VoidDataAction`] -- clears/undefined data
//! - [`CycleGroup`] -- a named sequence of data types to cycle through
//! - [`RecentlyUsedTypes`] -- MRU list of recently used data types
//! - [`default_cycle_groups`] -- Ghidra's built-in cycle groups

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;

/// Maximum number of recently used data types to remember.
const MAX_RECENT: usize = 10;

/// The pointer size for a given address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PointerSize {
    /// 16-bit pointer.
    Pointer16,
    /// 32-bit pointer.
    Pointer32,
    /// 64-bit pointer.
    Pointer64,
}

impl PointerSize {
    /// Returns the byte size of this pointer.
    pub fn byte_size(&self) -> usize {
        match self {
            PointerSize::Pointer16 => 2,
            PointerSize::Pointer32 => 4,
            PointerSize::Pointer64 => 8,
        }
    }
}

impl fmt::Display for PointerSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PointerSize::Pointer16 => write!(f, "pointer16"),
            PointerSize::Pointer32 => write!(f, "pointer32"),
            PointerSize::Pointer64 => write!(f, "pointer64"),
        }
    }
}

/// An action that converts data to undefined (clears the data type).
///
/// Ported from `VoidDataAction.java`.
#[derive(Debug, Clone)]
pub struct VoidDataAction {
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The menu label.
    pub menu_label: String,
}

impl VoidDataAction {
    /// Creates a new void/undefined data action.
    pub fn new() -> Self {
        Self {
            enabled: true,
            menu_label: "Undefined".to_string(),
        }
    }
}

impl Default for VoidDataAction {
    fn default() -> Self {
        Self::new()
    }
}

/// A cycle group entry: a sequence of data types to cycle through.
///
/// Ported from `CycleGroupAction.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleGroup {
    /// The name of this cycle group.
    pub name: String,
    /// The data type names in this cycle group, in order.
    pub types: Vec<String>,
}

impl CycleGroup {
    /// Creates a new cycle group.
    pub fn new(name: impl Into<String>, types: Vec<String>) -> Self {
        Self {
            name: name.into(),
            types,
        }
    }

    /// Returns the next type in the cycle after the given current type.
    ///
    /// Returns `None` if the current type is not in this group.
    pub fn next_type(&self, current: &str) -> Option<&str> {
        let idx = self.types.iter().position(|t| t == current)?;
        let next_idx = (idx + 1) % self.types.len();
        Some(&self.types[next_idx])
    }

    /// Returns the previous type in the cycle.
    pub fn previous_type(&self, current: &str) -> Option<&str> {
        let idx = self.types.iter().position(|t| t == current)?;
        let prev_idx = if idx == 0 {
            self.types.len() - 1
        } else {
            idx - 1
        };
        Some(&self.types[prev_idx])
    }
}

/// Default cycle groups as defined in Ghidra.
pub fn default_cycle_groups() -> Vec<CycleGroup> {
    vec![
        CycleGroup::new(
            "Byte",
            vec![
                "byte".to_string(),
                "char".to_string(),
                "boolean".to_string(),
                "hex".to_string(),
                "decimal".to_string(),
                "octal".to_string(),
                "binary".to_string(),
            ],
        ),
        CycleGroup::new(
            "Word",
            vec![
                "word".to_string(),
                "short".to_string(),
                "char2".to_string(),
                "hex2".to_string(),
                "decimal2".to_string(),
                "octal2".to_string(),
                "binary2".to_string(),
            ],
        ),
        CycleGroup::new(
            "Dword",
            vec![
                "dword".to_string(),
                "int".to_string(),
                "float".to_string(),
                "hex4".to_string(),
                "decimal4".to_string(),
                "octal4".to_string(),
                "binary4".to_string(),
                "addr32".to_string(),
            ],
        ),
        CycleGroup::new(
            "Qword",
            vec![
                "qword".to_string(),
                "long".to_string(),
                "double".to_string(),
                "hex8".to_string(),
                "decimal8".to_string(),
                "octal8".to_string(),
                "binary8".to_string(),
                "addr64".to_string(),
            ],
        ),
    ]
}

/// Manages the recently used data types list.
///
/// Ported from `RecentlyUsedAction.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentlyUsedTypes {
    /// The list of recently used type names, most recent first.
    types: VecDeque<String>,
}

impl RecentlyUsedTypes {
    /// Creates a new empty recently-used list.
    pub fn new() -> Self {
        Self {
            types: VecDeque::new(),
        }
    }

    /// Adds a type name to the recently-used list.
    ///
    /// Moves it to the front if it already exists.
    pub fn add(&mut self, type_name: impl Into<String>) {
        let name = type_name.into();
        self.types.retain(|t| t != &name);
        self.types.push_front(name);
        while self.types.len() > MAX_RECENT {
            self.types.pop_back();
        }
    }

    /// Returns the list of recently used type names.
    pub fn types(&self) -> &VecDeque<String> {
        &self.types
    }

    /// Returns the most recently used type name.
    pub fn most_recent(&self) -> Option<&str> {
        self.types.front().map(|s| s.as_str())
    }

    /// Returns the number of recently used types.
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// Returns `true` if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Clears the list.
    pub fn clear(&mut self) {
        self.types.clear();
    }
}

impl Default for RecentlyUsedTypes {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pointer_size_display() {
        assert_eq!(format!("{}", PointerSize::Pointer16), "pointer16");
        assert_eq!(format!("{}", PointerSize::Pointer32), "pointer32");
        assert_eq!(format!("{}", PointerSize::Pointer64), "pointer64");
    }

    #[test]
    fn test_pointer_size_byte_size() {
        assert_eq!(PointerSize::Pointer16.byte_size(), 2);
        assert_eq!(PointerSize::Pointer32.byte_size(), 4);
        assert_eq!(PointerSize::Pointer64.byte_size(), 8);
    }

    #[test]
    fn test_void_data_action() {
        let action = VoidDataAction::new();
        assert!(action.enabled);
        assert_eq!(action.menu_label, "Undefined");
    }

    #[test]
    fn test_cycle_group_next_type() {
        let group = CycleGroup::new(
            "Byte",
            vec![
                "byte".to_string(),
                "char".to_string(),
                "boolean".to_string(),
            ],
        );
        assert_eq!(group.next_type("byte"), Some("char"));
        assert_eq!(group.next_type("char"), Some("boolean"));
        assert_eq!(group.next_type("boolean"), Some("byte")); // wraps
        assert_eq!(group.next_type("unknown"), None);
    }

    #[test]
    fn test_cycle_group_previous_type() {
        let group = CycleGroup::new(
            "Word",
            vec![
                "word".to_string(),
                "short".to_string(),
                "char2".to_string(),
            ],
        );
        assert_eq!(group.previous_type("word"), Some("char2")); // wraps
        assert_eq!(group.previous_type("short"), Some("word"));
        assert_eq!(group.previous_type("char2"), Some("short"));
    }

    #[test]
    fn test_default_cycle_groups() {
        let groups = default_cycle_groups();
        assert_eq!(groups.len(), 4);
        assert_eq!(groups[0].name, "Byte");
        assert_eq!(groups[1].name, "Word");
        assert_eq!(groups[2].name, "Dword");
        assert_eq!(groups[3].name, "Qword");
    }

    #[test]
    fn test_recently_used_types_new() {
        let recent = RecentlyUsedTypes::new();
        assert!(recent.is_empty());
        assert!(recent.most_recent().is_none());
    }

    #[test]
    fn test_recently_used_types_add() {
        let mut recent = RecentlyUsedTypes::new();
        recent.add("byte");
        recent.add("word");
        recent.add("dword");

        assert_eq!(recent.len(), 3);
        assert_eq!(recent.most_recent(), Some("dword"));
        assert_eq!(recent.types()[0], "dword");
        assert_eq!(recent.types()[1], "word");
        assert_eq!(recent.types()[2], "byte");
    }

    #[test]
    fn test_recently_used_types_move_to_front() {
        let mut recent = RecentlyUsedTypes::new();
        recent.add("byte");
        recent.add("word");
        recent.add("byte"); // move byte to front

        assert_eq!(recent.len(), 2);
        assert_eq!(recent.most_recent(), Some("byte"));
        assert_eq!(recent.types()[1], "word");
    }

    #[test]
    fn test_recently_used_types_max_limit() {
        let mut recent = RecentlyUsedTypes::new();
        for i in 0..15 {
            recent.add(format!("type_{}", i));
        }
        assert_eq!(recent.len(), MAX_RECENT);
    }

    #[test]
    fn test_recently_used_types_clear() {
        let mut recent = RecentlyUsedTypes::new();
        recent.add("byte");
        recent.add("word");
        recent.clear();
        assert!(recent.is_empty());
    }

    #[test]
    fn test_integration_cycle_group_with_recently_used() {
        let group = CycleGroup::new(
            "Dword",
            vec![
                "dword".to_string(),
                "int".to_string(),
                "float".to_string(),
            ],
        );

        let mut recent = RecentlyUsedTypes::new();

        // Cycle through the group
        let mut current = "dword";
        recent.add(current);

        current = group.next_type(current).unwrap();
        assert_eq!(current, "int");
        recent.add(current);

        current = group.next_type(current).unwrap();
        assert_eq!(current, "float");
        recent.add(current);

        // Recently used should have float first
        assert_eq!(recent.most_recent(), Some("float"));
        assert_eq!(recent.len(), 3);
    }

    #[test]
    fn test_cycle_group_single_type() {
        let group = CycleGroup::new("Boolean", vec!["boolean".to_string()]);
        assert_eq!(group.next_type("boolean"), Some("boolean"));
        assert_eq!(group.previous_type("boolean"), Some("boolean"));
    }

}
