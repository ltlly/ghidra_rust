//! Recently used data type tracking -- ported from `RecentlyUsedAction.java`.
//!
//! Maintains a most-recently-used (MRU) list of data type names so
//! that users can quickly re-apply a recently chosen data type without
//! navigating the full data type tree.
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::data::recently_used::RecentlyUsedDataTypes;
//!
//! let mut mru = RecentlyUsedDataTypes::new(5);
//! mru.record("int");
//! mru.record("char");
//! mru.record("int"); // moves "int" to front
//!
//! let entries = mru.entries();
//! assert_eq!(entries[0], "int");
//! assert_eq!(entries[1], "char");
//! assert_eq!(entries.len(), 2);
//! ```

use std::collections::VecDeque;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// RecentlyUsedDataTypes
// ---------------------------------------------------------------------------

/// An MRU (most recently used) list of data type names.
///
/// Ported from the recently-used tracking logic in
/// `ghidra.app.plugin.core.data` (the `RecentlyUsedAction` class).
///
/// When the user applies a data type through the data plugin, the type
/// name is added to this list.  The list is capped at `max_size`
/// entries and duplicate entries are moved to the front rather than
/// added again.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentlyUsedDataTypes {
    /// The ordered list of recently used type names (most recent first).
    entries: VecDeque<String>,
    /// Maximum number of entries to keep.
    max_size: usize,
}

impl RecentlyUsedDataTypes {
    /// Creates a new recently-used list with the given maximum size.
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            max_size,
        }
    }

    /// Records a data type name as recently used.
    ///
    /// If the name already exists, it is moved to the front.
    /// If the list is at capacity, the oldest entry is removed.
    pub fn record(&mut self, name: &str) {
        // Remove existing entry if present.
        if let Some(pos) = self.entries.iter().position(|e| e == name) {
            self.entries.remove(pos);
        }
        // Push to front.
        self.entries.push_front(name.to_string());
        // Trim if over capacity.
        while self.entries.len() > self.max_size {
            self.entries.pop_back();
        }
    }

    /// Returns the list of entries, most recent first.
    pub fn entries(&self) -> Vec<&str> {
        self.entries.iter().map(|s| s.as_str()).collect()
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the maximum size.
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Removes all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Returns the most recently used entry, if any.
    pub fn most_recent(&self) -> Option<&str> {
        self.entries.front().map(|s| s.as_str())
    }

    /// Removes a specific entry by name.
    pub fn remove(&mut self, name: &str) -> bool {
        if let Some(pos) = self.entries.iter().position(|e| e == name) {
            self.entries.remove(pos);
            true
        } else {
            false
        }
    }

    /// Returns `true` if the list contains the given name.
    pub fn contains(&self, name: &str) -> bool {
        self.entries.iter().any(|e| e == name)
    }
}

impl Default for RecentlyUsedDataTypes {
    fn default() -> Self {
        Self::new(10)
    }
}

impl fmt::Display for RecentlyUsedDataTypes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecentlyUsed[")?;
        for (i, entry) in self.entries.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", entry)?;
        }
        write!(f, "]")
    }
}

// ---------------------------------------------------------------------------
// RecentlyUsedAction
// ---------------------------------------------------------------------------

/// Action metadata for applying a recently used data type.
///
/// Ported from `RecentlyUsedAction.java`.  Each action represents a
/// single recently-used data type that can be applied at the cursor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentlyUsedAction {
    /// The data type name.
    pub data_type_name: String,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl RecentlyUsedAction {
    /// Creates a new action for the given data type name.
    pub fn new(data_type_name: impl Into<String>) -> Self {
        Self {
            data_type_name: data_type_name.into(),
            enabled: true,
        }
    }

    /// Returns the action display name.
    pub fn display_name(&self) -> &str {
        &self.data_type_name
    }
}

impl fmt::Display for RecentlyUsedAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.data_type_name)
    }
}

// ---------------------------------------------------------------------------
// RecentlyUsedActionList
// ---------------------------------------------------------------------------

/// Manages the list of recently-used data type actions.
///
/// Combines [`RecentlyUsedDataTypes`] with [`RecentlyUsedAction`] to
/// provide a complete action management interface.
#[derive(Debug, Clone)]
pub struct RecentlyUsedActionList {
    /// The underlying MRU list.
    data_types: RecentlyUsedDataTypes,
}

impl RecentlyUsedActionList {
    /// Creates a new action list with the given maximum size.
    pub fn new(max_size: usize) -> Self {
        Self {
            data_types: RecentlyUsedDataTypes::new(max_size),
        }
    }

    /// Records a data type as recently used and returns the updated
    /// action list.
    pub fn record(&mut self, name: &str) {
        self.data_types.record(name);
    }

    /// Returns the list of recently used data type names.
    pub fn entries(&self) -> Vec<&str> {
        self.data_types.entries()
    }

    /// Returns action objects for all recently used types.
    pub fn actions(&self) -> Vec<RecentlyUsedAction> {
        self.data_types
            .entries()
            .iter()
            .map(|name| RecentlyUsedAction::new(*name))
            .collect()
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.data_types.len()
    }

    /// Returns whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.data_types.is_empty()
    }

    /// Returns the underlying data types list.
    pub fn data_types(&self) -> &RecentlyUsedDataTypes {
        &self.data_types
    }

    /// Returns a mutable reference to the underlying data types list.
    pub fn data_types_mut(&mut self) -> &mut RecentlyUsedDataTypes {
        &mut self.data_types
    }
}

impl Default for RecentlyUsedActionList {
    fn default() -> Self {
        Self::new(10)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- RecentlyUsedDataTypes --

    #[test]
    fn test_mru_basic() {
        let mut mru = RecentlyUsedDataTypes::new(5);
        mru.record("int");
        mru.record("char");
        mru.record("float");

        assert_eq!(mru.len(), 3);
        assert_eq!(mru.entries(), vec!["float", "char", "int"]);
    }

    #[test]
    fn test_mru_duplicate_moves_to_front() {
        let mut mru = RecentlyUsedDataTypes::new(5);
        mru.record("int");
        mru.record("char");
        mru.record("int"); // move to front

        assert_eq!(mru.entries(), vec!["int", "char"]);
        assert_eq!(mru.len(), 2); // no duplicate
    }

    #[test]
    fn test_mru_max_size() {
        let mut mru = RecentlyUsedDataTypes::new(3);
        mru.record("a");
        mru.record("b");
        mru.record("c");
        mru.record("d"); // evicts "a"

        assert_eq!(mru.len(), 3);
        assert_eq!(mru.entries(), vec!["d", "c", "b"]);
        assert!(!mru.contains("a"));
    }

    #[test]
    fn test_mru_most_recent() {
        let mut mru = RecentlyUsedDataTypes::new(5);
        assert!(mru.most_recent().is_none());

        mru.record("first");
        assert_eq!(mru.most_recent(), Some("first"));

        mru.record("second");
        assert_eq!(mru.most_recent(), Some("second"));
    }

    #[test]
    fn test_mru_contains() {
        let mut mru = RecentlyUsedDataTypes::new(5);
        mru.record("int");
        assert!(mru.contains("int"));
        assert!(!mru.contains("char"));
    }

    #[test]
    fn test_mru_remove() {
        let mut mru = RecentlyUsedDataTypes::new(5);
        mru.record("int");
        mru.record("char");

        assert!(mru.remove("int"));
        assert_eq!(mru.len(), 1);
        assert!(!mru.contains("int"));
        assert!(!mru.remove("nonexistent"));
    }

    #[test]
    fn test_mru_clear() {
        let mut mru = RecentlyUsedDataTypes::new(5);
        mru.record("int");
        mru.record("char");
        mru.clear();

        assert!(mru.is_empty());
        assert_eq!(mru.len(), 0);
    }

    #[test]
    fn test_mru_default() {
        let mru = RecentlyUsedDataTypes::default();
        assert_eq!(mru.max_size(), 10);
        assert!(mru.is_empty());
    }

    #[test]
    fn test_mru_display() {
        let mut mru = RecentlyUsedDataTypes::new(5);
        mru.record("int");
        mru.record("char");
        let display = format!("{}", mru);
        assert!(display.contains("char"));
        assert!(display.contains("int"));
        assert!(display.starts_with("RecentlyUsed["));
    }

    // -- RecentlyUsedAction --

    #[test]
    fn test_action_new() {
        let action = RecentlyUsedAction::new("int");
        assert_eq!(action.data_type_name, "int");
        assert!(action.enabled);
        assert_eq!(action.display_name(), "int");
    }

    #[test]
    fn test_action_display() {
        let action = RecentlyUsedAction::new("void *");
        assert_eq!(format!("{}", action), "void *");
    }

    // -- RecentlyUsedActionList --

    #[test]
    fn test_action_list_basic() {
        let mut list = RecentlyUsedActionList::new(5);
        list.record("int");
        list.record("char");

        assert_eq!(list.len(), 2);
        assert!(!list.is_empty());
    }

    #[test]
    fn test_action_list_actions() {
        let mut list = RecentlyUsedActionList::new(5);
        list.record("int");
        list.record("char");

        let actions = list.actions();
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].data_type_name, "char");
        assert_eq!(actions[1].data_type_name, "int");
    }

    #[test]
    fn test_action_list_default() {
        let list = RecentlyUsedActionList::default();
        assert!(list.is_empty());
        assert_eq!(list.actions().len(), 0);
    }

    #[test]
    fn test_action_list_data_types_access() {
        let mut list = RecentlyUsedActionList::new(5);
        list.record("int");

        assert_eq!(list.data_types().most_recent(), Some("int"));

        list.data_types_mut().record("char");
        assert_eq!(list.data_types().most_recent(), Some("char"));
    }

    // -- Integration: MRU with actions --

    #[test]
    fn test_mru_serialization_roundtrip() {
        let mut mru = RecentlyUsedDataTypes::new(5);
        mru.record("int");
        mru.record("char");

        let json = serde_json::to_string(&mru).unwrap();
        let deserialized: RecentlyUsedDataTypes = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.entries(), vec!["char", "int"]);
    }

    #[test]
    fn test_action_list_entries() {
        let mut list = RecentlyUsedActionList::new(3);
        list.record("int");
        list.record("char");
        list.record("short");
        list.record("int"); // moves int to front

        let entries = list.entries();
        assert_eq!(entries, vec!["int", "short", "char"]);
    }
}
