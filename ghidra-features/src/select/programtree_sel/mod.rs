//! Program tree selection plugin.
//!
//! Ported from Ghidra's `ProgramTreeSelectionPlugin`.
//!
//! Provides selection of address ranges based on the currently
//! selected nodes in the program tree view.

use serde::{Deserialize, Serialize};

/// Plugin for selecting addresses from the program tree.
#[derive(Debug)]
pub struct ProgramTreeSelectionPlugin {
    pub name: String,
    /// The selected tree node paths.
    pub selected_nodes: Vec<String>,
}

impl ProgramTreeSelectionPlugin {
    pub fn new() -> Self {
        Self {
            name: "ProgramTreeSelectionPlugin".to_string(),
            selected_nodes: Vec::new(),
        }
    }
    /// Select a tree node.
    pub fn select_node(&mut self, path: &str) {
        self.selected_nodes.push(path.to_string());
    }
    /// Clear all selected nodes.
    pub fn clear_selection(&mut self) {
        self.selected_nodes.clear();
    }
}

impl Default for ProgramTreeSelectionPlugin {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_programtree_selection_plugin() {
        let mut plugin = ProgramTreeSelectionPlugin::new();
        plugin.select_node("/Program Tree/.text");
        plugin.select_node("/Program Tree/.data");
        assert_eq!(plugin.selected_nodes.len(), 2);
        plugin.clear_selection();
        assert!(plugin.selected_nodes.is_empty());
    }
}
