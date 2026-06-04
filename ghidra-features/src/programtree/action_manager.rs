//! ProgramTreeActionManager -- action dispatch for the program tree.
//!
//! Ported from `ghidra.app.plugin.core.programtree.ProgramTreeActionManager`.
//!
//! Manages the available actions (cut, copy, paste, create folder/fragment,
//! merge, delete, expand, rename, view operations) and dispatches them.

use super::node::ProgramNode;
use super::paste_manager::{ClipboardItem, ClipboardOp, PasteManager};
use super::reorder_manager::{ReorderError, ReorderManager};
use super::GroupPath;

/// An action that can be performed on the program tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeAction {
    /// Cut the selected nodes.
    Cut,
    /// Copy the selected nodes.
    Copy,
    /// Paste from clipboard.
    Paste,
    /// Create a new folder (module) under the target.
    CreateFolder(String),
    /// Create a new fragment under the target.
    CreateFragment(String),
    /// Merge selected nodes into a new module.
    Merge(String),
    /// Delete the selected nodes.
    Delete,
    /// Expand the selected nodes.
    Expand,
    /// Collapse the selected nodes.
    Collapse,
    /// Rename the selected node.
    Rename(String),
    /// Set the view to the selected node.
    SetView,
    /// Add the selected node to the view.
    AddToView,
    /// Remove the selected node from the view.
    RemoveFromView,
    /// Go to the selected node's address range.
    GoToView,
}

/// The result of executing a tree action.
#[derive(Debug, Clone)]
pub enum ActionResult {
    /// The action completed successfully with a message.
    Success(String),
    /// The action was cancelled or had no effect.
    NoOp(String),
    /// The action failed.
    Error(String),
}

impl ActionResult {
    /// Returns `true` if the action succeeded.
    pub fn is_success(&self) -> bool {
        matches!(self, ActionResult::Success(_))
    }

    /// Returns `true` if the action had no effect.
    pub fn is_noop(&self) -> bool {
        matches!(self, ActionResult::NoOp(_))
    }

    /// Returns `true` if the action failed.
    pub fn is_error(&self) -> bool {
        matches!(self, ActionResult::Error(_))
    }

    /// Returns the message string.
    pub fn message(&self) -> &str {
        match self {
            ActionResult::Success(msg) => msg,
            ActionResult::NoOp(msg) => msg,
            ActionResult::Error(msg) => msg,
        }
    }
}

/// Manages actions and dispatches them for the program tree.
#[derive(Debug)]
pub struct ProgramTreeActionManager {
    /// The paste manager for clipboard operations.
    paste_manager: PasteManager,
    /// The reorder manager for move/merge operations.
    reorder_manager: ReorderManager,
    /// Whether the system clipboard has content from this tree.
    has_system_clipboard: bool,
}

impl ProgramTreeActionManager {
    /// Create a new action manager.
    pub fn new() -> Self {
        Self {
            paste_manager: PasteManager::new(),
            reorder_manager: ReorderManager::new(),
            has_system_clipboard: false,
        }
    }

    /// Returns a reference to the paste manager.
    pub fn paste_manager(&self) -> &PasteManager {
        &self.paste_manager
    }

    /// Returns a mutable reference to the paste manager.
    pub fn paste_manager_mut(&mut self) -> &mut PasteManager {
        &mut self.paste_manager
    }

    /// Returns a reference to the reorder manager.
    pub fn reorder_manager(&self) -> &ReorderManager {
        &self.reorder_manager
    }

    /// Returns a mutable reference to the reorder manager.
    pub fn reorder_manager_mut(&mut self) -> &mut ReorderManager {
        &mut self.reorder_manager
    }

    /// Clear the system clipboard tracking.
    pub fn clear_system_clipboard(&mut self) {
        self.has_system_clipboard = false;
    }

    /// Execute a cut action on the given nodes.
    ///
    /// Copies the selected paths to the clipboard with a Cut operation.
    pub fn execute_cut(
        &mut self,
        paths: Vec<GroupPath>,
        tree_name: &str,
    ) -> ActionResult {
        if paths.is_empty() {
            return ActionResult::NoOp("No nodes selected".into());
        }
        self.paste_manager.set_clipboard(ClipboardItem::new(
            ClipboardOp::Cut,
            paths,
            tree_name,
        ));
        self.has_system_clipboard = true;
        ActionResult::Success("Nodes cut to clipboard".into())
    }

    /// Execute a copy action on the given nodes.
    pub fn execute_copy(
        &mut self,
        paths: Vec<GroupPath>,
        tree_name: &str,
    ) -> ActionResult {
        if paths.is_empty() {
            return ActionResult::NoOp("No nodes selected".into());
        }
        self.paste_manager.set_clipboard(ClipboardItem::new(
            ClipboardOp::Copy,
            paths,
            tree_name,
        ));
        self.has_system_clipboard = true;
        ActionResult::Success("Nodes copied to clipboard".into())
    }

    /// Execute a paste action.
    ///
    /// Pastes clipboard content into the target module node.
    pub fn execute_paste(
        &mut self,
        target: &mut ProgramNode,
        source_nodes: &[ProgramNode],
    ) -> ActionResult {
        match self.paste_manager.paste(target, source_nodes) {
            Ok(names) => {
                let msg = format!("Pasted {} node(s): {}", names.len(), names.join(", "));
                ActionResult::Success(msg)
            }
            Err(e) => ActionResult::Error(e.to_string()),
        }
    }

    /// Execute a create-folder action.
    pub fn execute_create_folder(
        &self,
        parent: &mut ProgramNode,
        name: &str,
    ) -> ActionResult {
        if !parent.allows_children() {
            return ActionResult::Error("Cannot create folder in a fragment".into());
        }
        if parent.find_child(name).is_some() {
            return ActionResult::Error(format!("'{}' already exists", name));
        }
        parent.add_child(ProgramNode::new_module(name));
        ActionResult::Success(format!("Created folder '{}'", name))
    }

    /// Execute a create-fragment action.
    pub fn execute_create_fragment(
        &self,
        parent: &mut ProgramNode,
        name: &str,
    ) -> ActionResult {
        if !parent.allows_children() {
            return ActionResult::Error("Cannot create fragment in a fragment".into());
        }
        if parent.find_child(name).is_some() {
            return ActionResult::Error(format!("'{}' already exists", name));
        }
        parent.add_child(ProgramNode::new_fragment(name, None, None));
        ActionResult::Success(format!("Created fragment '{}'", name))
    }

    /// Execute a delete action.
    pub fn execute_delete(
        &self,
        parent: &mut ProgramNode,
        names: &[&str],
    ) -> ActionResult {
        let mut deleted = Vec::new();
        for name in names {
            if parent.remove_child_by_name(name).is_some() {
                deleted.push(name.to_string());
            }
        }
        if deleted.is_empty() {
            ActionResult::NoOp("No nodes deleted".into())
        } else {
            ActionResult::Success(format!("Deleted: {}", deleted.join(", ")))
        }
    }

    /// Execute a rename action.
    pub fn execute_rename(
        &self,
        parent: &mut ProgramNode,
        old_name: &str,
        new_name: &str,
    ) -> ActionResult {
        // Check for duplicate name first (before mutable borrow)
        if parent.find_child(new_name).is_some() {
            return ActionResult::Error(format!("'{}' already exists", new_name));
        }
        if let Some(child) = parent.find_child_mut(old_name) {
            child.set_name(new_name);
            ActionResult::Success(format!("Renamed '{}' to '{}'", old_name, new_name))
        } else {
            ActionResult::Error(format!("'{}' not found", old_name))
        }
    }

    /// Execute a merge action.
    pub fn execute_merge(
        &mut self,
        parent: &mut ProgramNode,
        node_names: &[&str],
        new_module_name: &str,
    ) -> ActionResult {
        match self.reorder_manager.merge(parent, node_names, new_module_name) {
            Ok(()) => ActionResult::Success(format!(
                "Merged {} nodes into '{}'",
                node_names.len(),
                new_module_name
            )),
            Err(e) => ActionResult::Error(e.to_string()),
        }
    }

    /// Execute a move (reorder) within the same parent.
    pub fn execute_move_within(
        &mut self,
        parent: &mut ProgramNode,
        child_name: &str,
        new_index: usize,
    ) -> ActionResult {
        match self
            .reorder_manager
            .reorder_within(parent, child_name, new_index)
        {
            Ok(()) => ActionResult::Success(format!("Moved '{}'", child_name)),
            Err(ReorderError::SameLocation) => {
                ActionResult::NoOp("Node is already at this position".into())
            }
            Err(e) => ActionResult::Error(e.to_string()),
        }
    }
}

impl Default for ProgramTreeActionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cut_copy() {
        let mut am = ProgramTreeActionManager::new();

        let paths = vec![GroupPath::new(vec!["tree".into(), "a".into()])];
        let result = am.execute_cut(paths.clone(), "tree");
        assert!(result.is_success());
        assert!(am.paste_manager().has_clipboard_content());
        assert!(am.paste_manager().clipboard().unwrap().is_cut());

        am.execute_copy(paths, "tree");
        assert!(am.paste_manager().clipboard().unwrap().is_copy());
    }

    #[test]
    fn test_create_folder_and_fragment() {
        let am = ProgramTreeActionManager::new();
        let mut parent = ProgramNode::new_module("root");

        let result = am.execute_create_folder(&mut parent, "my_folder");
        assert!(result.is_success());
        assert_eq!(parent.child_count(), 1);

        let result = am.execute_create_fragment(&mut parent, ".text");
        assert!(result.is_success());
        assert_eq!(parent.child_count(), 2);
    }

    #[test]
    fn test_cannot_create_in_fragment() {
        let am = ProgramTreeActionManager::new();
        let mut frag = ProgramNode::new_fragment(".text", None, None);

        let result = am.execute_create_folder(&mut frag, "bad");
        assert!(result.is_error());
    }

    #[test]
    fn test_delete() {
        let am = ProgramTreeActionManager::new();
        let mut parent = ProgramNode::new_module("root");
        parent.add_child(ProgramNode::new_fragment("a", None, None));
        parent.add_child(ProgramNode::new_fragment("b", None, None));

        let result = am.execute_delete(&mut parent, &["a"]);
        assert!(result.is_success());
        assert_eq!(parent.child_count(), 1);
    }

    #[test]
    fn test_rename() {
        let am = ProgramTreeActionManager::new();
        let mut parent = ProgramNode::new_module("root");
        parent.add_child(ProgramNode::new_fragment("old", None, None));

        let result = am.execute_rename(&mut parent, "old", "new");
        assert!(result.is_success());
        assert_eq!(parent.child_at(0).unwrap().name(), "new");
    }

    #[test]
    fn test_rename_duplicate() {
        let am = ProgramTreeActionManager::new();
        let mut parent = ProgramNode::new_module("root");
        parent.add_child(ProgramNode::new_fragment("a", None, None));
        parent.add_child(ProgramNode::new_fragment("b", None, None));

        let result = am.execute_rename(&mut parent, "a", "b");
        assert!(result.is_error());
    }

    #[test]
    fn test_merge() {
        let mut am = ProgramTreeActionManager::new();
        let mut parent = ProgramNode::new_module("root");
        parent.add_child(ProgramNode::new_fragment("a", None, None));
        parent.add_child(ProgramNode::new_fragment("b", None, None));
        parent.add_child(ProgramNode::new_fragment("c", None, None));

        let result = am.execute_merge(&mut parent, &["a", "b"], "merged");
        assert!(result.is_success());
        assert_eq!(parent.child_count(), 2); // merged + c
    }

    #[test]
    fn test_move_within() {
        let mut am = ProgramTreeActionManager::new();
        let mut parent = ProgramNode::new_module("root");
        parent.add_child(ProgramNode::new_fragment("a", None, None));
        parent.add_child(ProgramNode::new_fragment("b", None, None));

        let result = am.execute_move_within(&mut parent, "a", 1);
        assert!(result.is_success());
        assert_eq!(parent.child_at(0).unwrap().name(), "b");
        assert_eq!(parent.child_at(1).unwrap().name(), "a");
    }

    #[test]
    fn test_action_result_variants() {
        let s = ActionResult::Success("ok".into());
        assert!(s.is_success());
        assert_eq!(s.message(), "ok");

        let n = ActionResult::NoOp("skip".into());
        assert!(n.is_noop());

        let e = ActionResult::Error("fail".into());
        assert!(e.is_error());
    }
}
