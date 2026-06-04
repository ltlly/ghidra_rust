//! PasteManager -- clipboard paste support for the program tree.
//!
//! Ported from `ghidra.app.plugin.core.programtree.PasteManager`.
//!
//! Handles pasting fragments and modules into the program tree after a
//! cut or copy operation, including validation (preventing circular
//! dependencies) and the actual tree mutation.

use super::GroupPath;
use super::node::ProgramNode;

/// Clipboard operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardOp {
    /// Cut (remove from source, paste into destination).
    Cut,
    /// Copy (copy from source, paste into destination).
    Copy,
}

/// An item on the program tree clipboard.
#[derive(Debug, Clone)]
pub struct ClipboardItem {
    /// The operation that created this item.
    pub op: ClipboardOp,
    /// The group paths of the nodes that were cut/copied.
    pub paths: Vec<GroupPath>,
    /// The name of the tree from which the nodes were taken.
    pub source_tree_name: String,
}

impl ClipboardItem {
    /// Create a new clipboard item.
    pub fn new(op: ClipboardOp, paths: Vec<GroupPath>, source_tree_name: impl Into<String>) -> Self {
        Self {
            op,
            paths,
            source_tree_name: source_tree_name.into(),
        }
    }

    /// Returns `true` if this is a cut operation.
    pub fn is_cut(&self) -> bool {
        self.op == ClipboardOp::Cut
    }

    /// Returns `true` if this is a copy operation.
    pub fn is_copy(&self) -> bool {
        self.op == ClipboardOp::Copy
    }
}

/// Manages paste operations for the program tree.
///
/// Validates paste targets, prevents circular dependencies, and
/// executes the paste by modifying the tree.
#[derive(Debug, Default)]
pub struct PasteManager {
    /// The current clipboard content.
    clipboard: Option<ClipboardItem>,
}

impl PasteManager {
    /// Create a new empty PasteManager.
    pub fn new() -> Self {
        Self { clipboard: None }
    }

    /// Set the clipboard content.
    pub fn set_clipboard(&mut self, item: ClipboardItem) {
        self.clipboard = Some(item);
    }

    /// Clear the clipboard.
    pub fn clear_clipboard(&mut self) {
        self.clipboard = None;
    }

    /// Returns `true` if there is content on the clipboard.
    pub fn has_clipboard_content(&self) -> bool {
        self.clipboard.is_some()
    }

    /// Returns a reference to the current clipboard item.
    pub fn clipboard(&self) -> Option<&ClipboardItem> {
        self.clipboard.as_ref()
    }

    /// Validate whether a paste can be performed.
    ///
    /// Checks:
    /// - Clipboard is not empty.
    /// - Target node allows children (is a module).
    /// - Pasting would not create a circular dependency.
    pub fn can_paste(&self, target: &ProgramNode) -> Result<(), PasteError> {
        let item = self.clipboard.as_ref().ok_or(PasteError::EmptyClipboard)?;

        if !target.allows_children() {
            return Err(PasteError::TargetIsFragment);
        }

        // Check for circular dependencies: the target cannot be a descendant
        // of any of the paths being pasted (for cut operations).
        if item.is_cut() {
            let target_name = target.group_name();
            for path in &item.paths {
                if path.names().contains(&target_name.to_string()) {
                    return Err(PasteError::CircularDependency);
                }
            }
        }

        Ok(())
    }

    /// Execute a paste operation.
    ///
    /// Returns the names of the nodes that were pasted.
    pub fn paste(
        &mut self,
        target: &mut ProgramNode,
        source_nodes: &[ProgramNode],
    ) -> Result<Vec<String>, PasteError> {
        self.can_paste(target)?;

        let mut pasted_names = Vec::new();
        for node in source_nodes {
            let name = node.name().to_string();
            // Avoid duplicates
            if target.find_child(&name).is_some() {
                // Generate a unique name
                let unique_name = Self::make_unique_name(target, &name);
                let mut clone = node.clone();
                clone.set_name(&unique_name);
                target.add_child(clone);
                pasted_names.push(unique_name);
            } else {
                target.add_child(node.clone());
                pasted_names.push(name);
            }
        }

        // For cut operations, we should also mark the source as cleared,
        // but that is handled by the caller (action manager).

        Ok(pasted_names)
    }

    fn make_unique_name(parent: &ProgramNode, base_name: &str) -> String {
        let mut idx = 1;
        loop {
            let candidate = format!("{}({})", base_name, idx);
            if parent.find_child(&candidate).is_none() {
                return candidate;
            }
            idx += 1;
        }
    }
}

/// Errors that can occur during paste operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasteError {
    /// The clipboard is empty.
    EmptyClipboard,
    /// The target is a fragment (cannot have children).
    TargetIsFragment,
    /// The paste would create a circular dependency.
    CircularDependency,
}

impl std::fmt::Display for PasteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasteError::EmptyClipboard => write!(f, "Clipboard is empty"),
            PasteError::TargetIsFragment => write!(f, "Cannot paste into a fragment"),
            PasteError::CircularDependency => {
                write!(f, "Paste would create a circular dependency")
            }
        }
    }
}

impl std::error::Error for PasteError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_clipboard() {
        let pm = PasteManager::new();
        let target = ProgramNode::new_module("target");
        assert!(!pm.has_clipboard_content());
        assert_eq!(pm.can_paste(&target), Err(PasteError::EmptyClipboard));
    }

    #[test]
    fn test_cannot_paste_into_fragment() {
        let mut pm = PasteManager::new();
        pm.set_clipboard(ClipboardItem::new(
            ClipboardOp::Copy,
            vec![GroupPath::root("tree")],
            "tree",
        ));
        let target = ProgramNode::new_fragment(".text", None, None);
        assert_eq!(pm.can_paste(&target), Err(PasteError::TargetIsFragment));
    }

    #[test]
    fn test_paste_copy() {
        let mut pm = PasteManager::new();
        pm.set_clipboard(ClipboardItem::new(
            ClipboardOp::Copy,
            vec![GroupPath::new(vec!["tree".into(), "src".into()])],
            "tree",
        ));

        let mut target = ProgramNode::new_module("tree");
        let source = vec![ProgramNode::new_fragment(".text", None, None)];

        let result = pm.paste(&mut target, &source).unwrap();
        assert_eq!(result, vec![".text".to_string()]);
        assert_eq!(target.child_count(), 1);
    }

    #[test]
    fn test_paste_duplicate_name() {
        let mut pm = PasteManager::new();
        pm.set_clipboard(ClipboardItem::new(
            ClipboardOp::Copy,
            vec![GroupPath::root("tree")],
            "tree",
        ));

        let mut target = ProgramNode::new_module("tree");
        target.add_child(ProgramNode::new_fragment(".text", None, None));

        let source = vec![ProgramNode::new_fragment(".text", None, None)];
        let result = pm.paste(&mut target, &source).unwrap();
        assert_eq!(result, vec![".text(1)".to_string()]);
        assert_eq!(target.child_count(), 2);
    }

    #[test]
    fn test_circular_dependency_check() {
        let mut pm = PasteManager::new();
        pm.set_clipboard(ClipboardItem::new(
            ClipboardOp::Cut,
            vec![GroupPath::new(vec!["tree".into(), "src".into()])],
            "tree",
        ));

        let target = ProgramNode::new_module("src");
        assert_eq!(pm.can_paste(&target), Err(PasteError::CircularDependency));
    }

    #[test]
    fn test_clipboard_item() {
        let item = ClipboardItem::new(
            ClipboardOp::Cut,
            vec![GroupPath::root("tree")],
            "tree",
        );
        assert!(item.is_cut());
        assert!(!item.is_copy());
    }
}
