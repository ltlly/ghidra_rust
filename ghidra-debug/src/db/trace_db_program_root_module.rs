//! Root module for trace program views.
//!
//! Ported from Ghidra's `DBTraceProgramViewRootModule` in
//! `ghidra.trace.database.program`. The root module represents the
//! top-level module in the program view's module tree, equivalent
//! to Ghidra's Program's root Namespace.

use serde::{Deserialize, Serialize};

/// The root module in a trace program view.
///
/// This corresponds to the global namespace of the program view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewRootModule {
    /// The trace identifier.
    pub trace_id: String,
    /// The snap at which this module is observed.
    pub snap: i64,
    /// The name (always "Global" for root).
    pub name: String,
    /// Child namespace keys.
    pub children: Vec<i64>,
}

impl ProgramViewRootModule {
    /// Create a new root module.
    pub fn new(trace_id: impl Into<String>, snap: i64) -> Self {
        Self {
            trace_id: trace_id.into(),
            snap,
            name: "Global".to_string(),
            children: Vec::new(),
        }
    }

    /// Add a child namespace key.
    pub fn add_child(&mut self, key: i64) {
        if !self.children.contains(&key) {
            self.children.push(key);
        }
    }

    /// Remove a child namespace key.
    pub fn remove_child(&mut self, key: i64) -> bool {
        let before = self.children.len();
        self.children.retain(|&k| k != key);
        self.children.len() < before
    }

    /// Get the child count.
    pub fn child_count(&self) -> usize {
        self.children.len()
    }

    /// Check if a key is a child.
    pub fn has_child(&self, key: i64) -> bool {
        self.children.contains(&key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_module_new() {
        let root = ProgramViewRootModule::new("trace1", 0);
        assert_eq!(root.name, "Global");
        assert_eq!(root.snap, 0);
        assert_eq!(root.child_count(), 0);
    }

    #[test]
    fn test_root_module_children() {
        let mut root = ProgramViewRootModule::new("t", 0);
        root.add_child(10);
        root.add_child(20);
        assert_eq!(root.child_count(), 2);
        assert!(root.has_child(10));
        assert!(!root.has_child(30));
    }

    #[test]
    fn test_root_module_remove_child() {
        let mut root = ProgramViewRootModule::new("t", 0);
        root.add_child(10);
        assert!(root.remove_child(10));
        assert_eq!(root.child_count(), 0);
    }

    #[test]
    fn test_root_module_no_duplicate_children() {
        let mut root = ProgramViewRootModule::new("t", 0);
        root.add_child(10);
        root.add_child(10);
        assert_eq!(root.child_count(), 1);
    }
}
