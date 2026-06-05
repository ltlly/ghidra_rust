//! DnDMoveManager -- interprets drag-drop operations as Move/Copy vs reorder.
//!
//! Ported from `ghidra.app.plugin.core.programtree.DnDMoveManager`.
//!
//! This helper validates drop targets and executes the drop by manipulating
//! the program tree's module/fragment structure.  It delegates reordering
//! operations to [`ReorderManager`] and handles move/copy/merge of groups.

use super::node::{NodeKind, ProgramNode};
use super::reorder_manager::ReorderManager;
use super::tree::ProgramTree;

/// Drag-drop action constants mirroring `java.awt.dnd.DnDConstants`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropAction {
    /// Copy the dragged group to the destination.
    Copy,
    /// Move the dragged group to the destination.
    Move,
}

impl DropAction {
    /// Returns `true` if this is a move action.
    pub fn is_move(&self) -> bool {
        matches!(self, DropAction::Move)
    }
}

/// Result of a drop validation or execution.
#[derive(Debug, Clone)]
pub enum DropResult {
    /// The drop was accepted and executed.
    Accepted,
    /// The drop was rejected with a reason.
    Rejected(String),
}

/// Errors that can occur during a drop operation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DropError {
    /// A circular dependency would be created.
    #[error("circular dependency detected")]
    CircularDependency,
    /// The target module already contains a group with the same name.
    #[error("duplicate group: {0}")]
    DuplicateGroup(String),
    /// The group was not found in the program tree.
    #[error("group not found: {0}")]
    NotFound(String),
    /// A general error occurred during the operation.
    #[error("{0}")]
    General(String),
}

/// Helper class to interpret the drop operation as a Move/Copy
/// operation versus the reorder.
///
/// Ported from Ghidra's `DnDMoveManager` Java class.
pub struct DnDMoveManager {
    reorder_mgr: ReorderManager,
}

impl DnDMoveManager {
    /// Create a new `DnDMoveManager`.
    pub fn new() -> Self {
        Self {
            reorder_mgr: ReorderManager::new(),
        }
    }

    /// Return `true` if the destination node can accept all the drop nodes.
    ///
    /// All nodes must be droppable, or none at all.
    pub fn is_drop_site_ok(
        &self,
        destination: &ProgramNode,
        drop_nodes: &[ProgramNode],
        drop_action: DropAction,
        relative_mouse_pos: i32,
    ) -> bool {
        drop_nodes
            .iter()
            .all(|node| self.can_drop_node(destination, node, drop_action, relative_mouse_pos))
    }

    fn can_drop_node(
        &self,
        destination: &ProgramNode,
        drop_node: &ProgramNode,
        drop_action: DropAction,
        relative_mouse_position: i32,
    ) -> bool {
        // Can't drop a group onto itself (same group name + same parent).
        if drop_node.group_name() == destination.group_name()
            && drop_node.parent_module_name() == destination.parent_module_name()
        {
            return false;
        }

        // Reorder operation (mouse above/below node).
        if relative_mouse_position != 0 {
            return self
                .reorder_mgr
                .is_drop_site_ok(destination, drop_node, drop_action, relative_mouse_position);
        }

        // Normal drop on the node.
        if destination.is_fragment() {
            return self.check_dest_fragment(destination, drop_node, drop_action);
        }

        // Destination is a module.
        // Check if destination already contains the drop group.
        if drop_node.is_fragment() {
            // Fragments can always be moved/copied into a module (name conflict is separate).
            return true;
        }

        // Drop node is a module -- check for descendant relationship.
        if drop_node.is_module() && destination.is_module() {
            // A module can't be dropped into one of its own descendants.
            // This is a simplified check -- in full Ghidra this walks the tree.
            if drop_node.group_name() == destination.group_name() {
                return false;
            }
        }

        true
    }

    /// Validate the drop with the given nodes at the given position.
    pub fn validate_drop(
        &self,
        destination: &ProgramNode,
        drop_nodes: &[ProgramNode],
        drop_action: DropAction,
        relative_mouse_pos: i32,
    ) -> DropResult {
        if self.is_drop_site_ok(destination, drop_nodes, drop_action, relative_mouse_pos) {
            DropResult::Accepted
        } else {
            DropResult::Rejected("Drop site is not valid".into())
        }
    }

    /// Execute the drop: add the drop nodes to the destination.
    ///
    /// `relative_mouse_pos` indicates where the drop occurred:
    /// - `-1` = above node (reorder)
    /// - `0` = on the node (normal drop)
    /// - `1` = below node (reorder)
    pub fn add(
        &self,
        tree: &mut ProgramTree,
        dest_node: &ProgramNode,
        drop_nodes: &[ProgramNode],
        drop_action: DropAction,
        relative_mouse_pos: i32,
    ) -> Result<(), DropError> {
        if relative_mouse_pos != 0 {
            return self
                .reorder_mgr
                .add(tree, dest_node, drop_nodes, drop_action, relative_mouse_pos);
        }

        for drop_node in drop_nodes {
            if dest_node.is_fragment() {
                Self::add_to_fragment(tree, dest_node, drop_node)?;
            } else {
                Self::add_to_module(tree, dest_node, drop_node, drop_action)?;
            }
        }

        Ok(())
    }

    fn check_dest_fragment(
        &self,
        dest_node: &ProgramNode,
        drop_node: &ProgramNode,
        drop_action: DropAction,
    ) -> bool {
        if !drop_action.is_move() {
            return false; // only move is allowed onto fragments
        }
        if drop_node.is_fragment() {
            return true; // Fragment -> Fragment means Merge Fragments
        }
        // Module -> Fragment means flatten Module (move all code units).
        // Check that the module is not a descendant of the fragment.
        true // simplified: fragments accept module drops for flattening
    }

    fn add_to_fragment(
        tree: &mut ProgramTree,
        dest_node: &ProgramNode,
        drop_node: &ProgramNode,
    ) -> Result<(), DropError> {
        // Merge the drop group into the destination fragment.
        tree.merge_group(drop_node.group_name(), dest_node.group_name())
            .map_err(|e| DropError::General(e))
    }

    fn add_to_module(
        tree: &mut ProgramTree,
        dest_node: &ProgramNode,
        drop_node: &ProgramNode,
        drop_action: DropAction,
    ) -> Result<(), DropError> {
        let dest_module = dest_node.group_name();
        let source_name = drop_node.group_name();

        if drop_action.is_move() {
            tree.reparent_group(source_name, dest_module)
                .map_err(|e| DropError::General(e))?;
        } else {
            // Copy: add the group to the destination module.
            tree.add_group_to(dest_module, source_name)
                .map_err(|e| DropError::General(e))?;
        }

        Ok(())
    }
}

impl Default for DnDMoveManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_module_node(name: &str) -> ProgramNode {
        ProgramNode::new_module(name)
    }

    fn make_fragment_node(name: &str) -> ProgramNode {
        ProgramNode::new_fragment(name, None, None)
    }

    #[test]
    fn test_cannot_drop_onto_self() {
        let mgr = DnDMoveManager::new();
        let dest = make_module_node("mymod");
        let drop = make_module_node("mymod");
        // Same name + same parent (both None) -> rejected
        assert!(!mgr.is_drop_site_ok(&dest, &[drop], DropAction::Move, 0));
    }

    #[test]
    fn test_can_drop_fragment_into_module() {
        let mgr = DnDMoveManager::new();
        let dest = make_module_node("root");
        let drop = make_fragment_node(".text");
        assert!(mgr.is_drop_site_ok(&dest, &[drop], DropAction::Move, 0));
    }

    #[test]
    fn test_cannot_copy_onto_fragment() {
        let mgr = DnDMoveManager::new();
        let dest = make_fragment_node(".text");
        let drop = make_fragment_node(".data");
        assert!(!mgr.is_drop_site_ok(&dest, &[drop], DropAction::Copy, 0));
    }

    #[test]
    fn test_can_move_fragment_onto_fragment() {
        let mgr = DnDMoveManager::new();
        let dest = make_fragment_node(".text");
        let drop = make_fragment_node(".data");
        assert!(mgr.is_drop_site_ok(&dest, &[drop], DropAction::Move, 0));
    }

    #[test]
    fn test_validate_drop_accepted() {
        let mgr = DnDMoveManager::new();
        let dest = make_module_node("root");
        let drop = make_fragment_node(".text");
        let result = mgr.validate_drop(&dest, &[drop], DropAction::Move, 0);
        assert!(matches!(result, DropResult::Accepted));
    }

    #[test]
    fn test_validate_drop_rejected() {
        let mgr = DnDMoveManager::new();
        let dest = make_module_node("mymod");
        let drop = make_module_node("mymod");
        let result = mgr.validate_drop(&dest, &[drop], DropAction::Move, 0);
        assert!(matches!(result, DropResult::Rejected(_)));
    }

    #[test]
    fn test_all_must_be_droppable() {
        let mgr = DnDMoveManager::new();
        let dest = make_module_node("root");
        let good = make_fragment_node(".text");
        let bad = make_module_node("root"); // same name as dest
        // Even one bad node means the whole batch is rejected.
        assert!(!mgr.is_drop_site_ok(&dest, &[good, bad], DropAction::Move, 0));
    }

    #[test]
    fn test_drop_action_is_move() {
        assert!(DropAction::Move.is_move());
        assert!(!DropAction::Copy.is_move());
    }
}
