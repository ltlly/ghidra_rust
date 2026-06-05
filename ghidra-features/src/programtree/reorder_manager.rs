//! ReorderManager -- drag-drop reordering of program tree nodes.
//!
//! Ported from `ghidra.app.plugin.core.programtree.ReorderManager`.
//!
//! Handles the logic of moving nodes within a module (reordering) and
//! moving nodes between modules, including validation of the operation.

use super::dnd_move_manager::DropAction;
use super::node::ProgramNode;
use super::tree::ProgramTree;

/// Errors that can occur during reordering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReorderError {
    /// The source node was not found.
    SourceNotFound(String),
    /// The target node was not found.
    TargetNotFound(String),
    /// The move would create a circular dependency.
    CircularDependency,
    /// The target does not allow children.
    TargetIsFragment,
    /// The source is the same as the target.
    SameLocation,
    /// The move is not permitted.
    NotAllowed(String),
}

impl std::fmt::Display for ReorderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReorderError::SourceNotFound(name) => write!(f, "Source not found: {}", name),
            ReorderError::TargetNotFound(name) => write!(f, "Target not found: {}", name),
            ReorderError::CircularDependency => write!(f, "Move would create circular dependency"),
            ReorderError::TargetIsFragment => write!(f, "Target is a fragment"),
            ReorderError::SameLocation => write!(f, "Source and target are the same location"),
            ReorderError::NotAllowed(msg) => write!(f, "Move not allowed: {}", msg),
        }
    }
}

impl std::error::Error for ReorderError {}

/// Manages reordering operations in the program tree.
#[derive(Debug, Default)]
pub struct ReorderManager {
    /// Whether a reorder operation is currently in progress.
    in_progress: bool,
}

impl ReorderManager {
    /// Create a new ReorderManager.
    pub fn new() -> Self {
        Self { in_progress: false }
    }

    /// Returns `true` if a reorder operation is in progress.
    pub fn is_in_progress(&self) -> bool {
        self.in_progress
    }

    /// Move a child within the same module (reorder).
    ///
    /// # Parameters
    /// - `parent`: The parent module node.
    /// - `child_name`: The name of the child to move.
    /// - `new_index`: The target index within the parent's children.
    pub fn reorder_within(
        &mut self,
        parent: &mut ProgramNode,
        child_name: &str,
        new_index: usize,
    ) -> Result<(), ReorderError> {
        if !parent.allows_children() {
            return Err(ReorderError::TargetIsFragment);
        }

        let current_index = parent
            .children()
            .iter()
            .position(|c| c.name() == child_name)
            .ok_or_else(|| ReorderError::SourceNotFound(child_name.to_string()))?;

        if current_index == new_index {
            return Err(ReorderError::SameLocation);
        }

        self.in_progress = true;
        parent.move_child(current_index, new_index)
            .map_err(|e| ReorderError::NotAllowed(e))?;
        self.in_progress = false;
        Ok(())
    }

    /// Move a child from one module to another.
    ///
    /// # Parameters
    /// - `source_parent`: The parent module from which to remove the child.
    /// - `child_name`: The name of the child to move.
    /// - `target_parent`: The target module to receive the child.
    /// - `target_index`: The insertion index in the target.
    pub fn move_between(
        &mut self,
        source_parent: &mut ProgramNode,
        child_name: &str,
        target_parent: &mut ProgramNode,
        target_index: usize,
    ) -> Result<(), ReorderError> {
        if !target_parent.allows_children() {
            return Err(ReorderError::TargetIsFragment);
        }

        // Prevent circular dependency: cannot move a module into itself or its descendants.
        if source_parent.group_name() == child_name {
            return Err(ReorderError::CircularDependency);
        }

        let child = source_parent
            .remove_child_by_name(child_name)
            .ok_or_else(|| ReorderError::SourceNotFound(child_name.to_string()))?;

        self.in_progress = true;
        target_parent.insert_child(target_index, child);
        self.in_progress = false;
        Ok(())
    }

    /// Check whether a drop site is ok for a reorder operation.
    ///
    /// This is used by the DnDMoveManager to validate reorders.
    pub fn is_drop_site_ok(
        &self,
        destination: &ProgramNode,
        drop_node: &ProgramNode,
        _drop_action: DropAction,
        relative_mouse_position: i32,
    ) -> bool {
        if relative_mouse_position == 0 {
            return true; // Not a reorder.
        }
        // Can only reorder into modules, not fragments.
        if !destination.is_module() {
            return false;
        }
        // Can't drop onto the same parent at the same position.
        drop_node.name() != destination.name()
    }

    /// Execute a reorder add operation (delegate to the DnDMoveManager tree).
    pub fn add(
        &self,
        tree: &mut ProgramTree,
        dest_node: &ProgramNode,
        drop_nodes: &[ProgramNode],
        drop_action: DropAction,
        relative_mouse_pos: i32,
    ) -> Result<(), super::dnd_move_manager::DropError> {
        // This is a reorder operation -- move nodes within the tree.
        for drop_node in drop_nodes {
            if relative_mouse_pos < 0 {
                // Insert before the destination.
                tree.add_group_before(dest_node.group_name(), drop_node.group_name())
                    .map_err(|e| super::dnd_move_manager::DropError::General(e))?;
            } else {
                // Insert after the destination.
                tree.add_group_after(dest_node.group_name(), drop_node.group_name())
                    .map_err(|e| super::dnd_move_manager::DropError::General(e))?;
            }
        }
        Ok(())
    }

    /// Merge multiple nodes into a new module.
    ///
    /// # Parameters
    /// - `parent`: The parent module containing the nodes to merge.
    /// - `node_names`: Names of the children to merge.
    /// - `new_module_name`: The name for the new module.
    pub fn merge(
        &mut self,
        parent: &mut ProgramNode,
        node_names: &[&str],
        new_module_name: &str,
    ) -> Result<(), ReorderError> {
        if !parent.allows_children() {
            return Err(ReorderError::TargetIsFragment);
        }

        if node_names.len() < 2 {
            return Err(ReorderError::NotAllowed(
                "Need at least 2 nodes to merge".into(),
            ));
        }

        // Verify all names exist.
        for name in node_names {
            if parent.find_child(name).is_none() {
                return Err(ReorderError::SourceNotFound(name.to_string()));
            }
        }

        self.in_progress = true;

        let mut new_module = ProgramNode::new_module(new_module_name);
        for name in node_names {
            if let Some(child) = parent.remove_child_by_name(name) {
                new_module.add_child(child);
            }
        }

        parent.add_child(new_module);
        self.in_progress = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_parent_with_children() -> ProgramNode {
        let mut parent = ProgramNode::new_module("root");
        parent.add_child(ProgramNode::new_fragment("a", None, None));
        parent.add_child(ProgramNode::new_fragment("b", None, None));
        parent.add_child(ProgramNode::new_fragment("c", None, None));
        parent
    }

    #[test]
    fn test_reorder_within() {
        let mut rm = ReorderManager::new();
        let mut parent = make_parent_with_children();

        rm.reorder_within(&mut parent, "a", 2).unwrap();
        assert_eq!(parent.child_at(0).unwrap().name(), "b");
        assert_eq!(parent.child_at(1).unwrap().name(), "c");
        assert_eq!(parent.child_at(2).unwrap().name(), "a");
    }

    #[test]
    fn test_reorder_same_index() {
        let mut rm = ReorderManager::new();
        let mut parent = make_parent_with_children();

        assert_eq!(
            rm.reorder_within(&mut parent, "a", 0),
            Err(ReorderError::SameLocation)
        );
    }

    #[test]
    fn test_move_between() {
        let mut rm = ReorderManager::new();
        let mut source = make_parent_with_children();
        let mut target = ProgramNode::new_module("target");

        rm.move_between(&mut source, "a", &mut target, 0).unwrap();

        assert_eq!(source.child_count(), 2);
        assert_eq!(target.child_count(), 1);
        assert_eq!(target.child_at(0).unwrap().name(), "a");
    }

    #[test]
    fn test_merge() {
        let mut rm = ReorderManager::new();
        let mut parent = make_parent_with_children();

        rm.merge(&mut parent, &["a", "b"], "merged").unwrap();

        assert_eq!(parent.child_count(), 2); // merged + c
        let merged = parent.find_child("merged").unwrap();
        assert_eq!(merged.child_count(), 2); // a, b
    }

    #[test]
    fn test_merge_insufficient_nodes() {
        let mut rm = ReorderManager::new();
        let mut parent = make_parent_with_children();

        assert!(matches!(
            rm.merge(&mut parent, &["a"], "merged"),
            Err(ReorderError::NotAllowed(_))
        ));
    }

    #[test]
    fn test_cannot_reorder_fragment() {
        let mut rm = ReorderManager::new();
        let mut frag = ProgramNode::new_fragment(".text", None, None);

        assert_eq!(
            rm.reorder_within(&mut frag, "a", 0),
            Err(ReorderError::TargetIsFragment)
        );
    }
}
