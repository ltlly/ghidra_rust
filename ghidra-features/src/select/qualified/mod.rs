//! Qualified selection plugin.
//!
//! Ported from Ghidra's `QualifiedSelectionPlugin`.
//!
//! Provides selection qualified by both address range and program
//! tree view (fragment), enabling operations scoped to a specific
//! module/fragment in the program tree.

use serde::{Deserialize, Serialize};

/// A qualified selection combining an address range with a program tree view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualifiedSelection {
    /// The tree view name (e.g., "Program Tree").
    pub view_name: String,
    /// The selected address ranges.
    pub addresses: Vec<(String, String)>,
}

impl QualifiedSelection {
    /// Create a new qualified selection.
    pub fn new(view_name: &str) -> Self {
        Self {
            view_name: view_name.to_string(),
            addresses: Vec::new(),
        }
    }
    /// Add an address range.
    pub fn add_range(&mut self, start: &str, end: &str) {
        self.addresses.push((start.to_string(), end.to_string()));
    }
    /// Return the number of ranges.
    pub fn range_count(&self) -> usize {
        self.addresses.len()
    }
    /// Check if this selection is empty.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }
}

/// Plugin for qualified selection management.
#[derive(Debug)]
pub struct QualifiedSelectionPlugin {
    pub name: String,
}

impl QualifiedSelectionPlugin {
    pub fn new() -> Self {
        Self { name: "QualifiedSelectionPlugin".to_string() }
    }
}

impl Default for QualifiedSelectionPlugin {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qualified_selection() {
        let mut sel = QualifiedSelection::new("Program Tree");
        sel.add_range("0x401000", "0x401100");
        sel.add_range("0x402000", "0x402100");
        assert_eq!(sel.range_count(), 2);
        assert!(!sel.is_empty());
    }

    #[test]
    fn test_qualified_selection_empty() {
        let sel = QualifiedSelection::new("Program Tree");
        assert!(sel.is_empty());
    }
}
