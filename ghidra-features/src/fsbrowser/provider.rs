//! File System Browser component provider.
//!
//! Ported from `ghidra.plugins.fsbrowser.FSBComponentProvider`.
//!
//! Each instance represents a single filesystem browser window with a
//! tree view, action handling, and file handler integration.


use super::{Fsrl, GFile, GFileSystem, FileSystemRef};
use super::node::{FsBrowserNode, FsBrowserNodeKind, FsBrowserNodeTree, NodeId};

// ---------------------------------------------------------------------------
// ProviderState -- visibility state of the component provider
// ---------------------------------------------------------------------------

/// Visibility state of the browser component provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderState {
    /// Not yet visible.
    Hidden,
    /// Visible and active.
    Visible,
    /// Closed/disposed.
    Disposed,
}

// ---------------------------------------------------------------------------
// FocusInfo -- information about the currently focused node
// ---------------------------------------------------------------------------

/// Information about the currently focused file in the browser tree.
#[derive(Debug, Clone)]
pub struct FocusInfo {
    /// The focused node ID.
    pub node_id: NodeId,
    /// The FSRL of the focused file.
    pub fsrl: Fsrl,
    /// The file name.
    pub name: String,
    /// Whether the focused file is a directory.
    pub is_directory: bool,
}

// ---------------------------------------------------------------------------
// FsBrowserComponentProvider -- a single browser window
// ---------------------------------------------------------------------------

/// Component provider for the filesystem browser.
///
/// Each instance manages one filesystem browser window with its own
/// tree of nodes representing the mounted filesystem.
///
/// Ported from `ghidra.plugins.fsbrowser.FSBComponentProvider`.
#[derive(Debug)]
pub struct FsBrowserComponentProvider {
    /// Unique provider identifier.
    pub provider_id: u64,
    /// Window title.
    pub title: String,
    /// Current visibility state.
    pub state: ProviderState,
    /// The filesystem reference being browsed.
    pub fs_ref: FileSystemRef,
    /// The tree of nodes.
    pub tree: FsBrowserNodeTree,
    /// Root node ID.
    pub root_node_id: Option<NodeId>,
    /// Currently focused node.
    pub focus: Option<FocusInfo>,
    /// Pending program selection (from delayed activation timer).
    pub pending_program: Option<String>,
    /// Whether file handlers have been initialized.
    pub handlers_initialized: bool,
}

impl FsBrowserComponentProvider {
    /// Create a new component provider.
    pub fn new(provider_id: u64, title: impl Into<String>, fs_ref: FileSystemRef) -> Self {
        Self {
            provider_id,
            title: title.into(),
            state: ProviderState::Hidden,
            fs_ref,
            tree: FsBrowserNodeTree::new(),
            root_node_id: None,
            focus: None,
            pending_program: None,
            handlers_initialized: false,
        }
    }

    /// Initialize the tree from the filesystem.
    pub fn init_tree(&mut self) {
        let fs = match self.fs_ref.filesystem.read() {
            Ok(fs) => fs,
            Err(_) => return,
        };

        let root_id = self.tree.alloc_id();
        let mut root_node = FsBrowserNode::root(root_id, fs.fsrl_root.clone());
        // Pre-populate root children from the filesystem's root directory.
        let children = fs
            .root
            .children
            .iter()
            .enumerate()
            .map(|(i, child)| {
                let child_id = NodeId(root_id.0 + i as u64 + 1);
                if child.is_directory {
                    FsBrowserNode::directory(child_id, child, root_id)
                } else {
                    FsBrowserNode::file(child_id, child, root_id)
                }
            })
            .collect::<Vec<_>>();
        root_node.set_children(children);
        self.tree.add_root(root_node);
        self.root_node_id = Some(root_id);
    }

    /// Show the browser component.
    pub fn show(&mut self) {
        self.state = ProviderState::Visible;
    }

    /// Hide the browser component.
    pub fn hide(&mut self) {
        self.state = ProviderState::Hidden;
    }

    /// Dispose the browser component.
    pub fn dispose(&mut self) {
        self.state = ProviderState::Disposed;
        self.tree = FsBrowserNodeTree::new();
        self.root_node_id = None;
        self.focus = None;
    }

    /// Check if the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.state == ProviderState::Visible
    }

    /// Set the focus to a node.
    pub fn set_focus(&mut self, node_id: NodeId) {
        if let Some(node) = self.tree.get(node_id) {
            self.focus = Some(FocusInfo {
                node_id,
                fsrl: node.fsrl.clone(),
                name: node.name.clone(),
                is_directory: node.kind == FsBrowserNodeKind::Directory,
            });
        }
    }

    /// Clear the focus.
    pub fn clear_focus(&mut self) {
        self.focus = None;
    }

    /// Load children for a directory node by populating from the filesystem.
    pub fn load_children(&mut self, node_id: NodeId) -> Result<(), String> {
        let fs = self
            .fs_ref
            .filesystem
            .read()
            .map_err(|e| format!("Lock error: {e}"))?;

        // Find the matching GFile in the filesystem
        let node_fsrl = self
            .tree
            .get(node_id)
            .map(|n| n.fsrl.clone())
            .ok_or_else(|| "Node not found".to_string())?;

        let children = self.collect_children_from_fs(&fs, &node_fsrl);

        if let Some(node) = self.tree.get_mut(node_id) {
            node.set_children(children);
        }

        Ok(())
    }

    fn collect_children_from_fs(
        &self,
        fs: &GFileSystem,
        parent_fsrl: &Fsrl,
    ) -> Vec<FsBrowserNode> {
        // Walk the filesystem tree to find children matching parent_fsrl
        self.find_children_recursive(&fs.root, parent_fsrl)
    }

    fn find_children_recursive(
        &self,
        gfile: &GFile,
        target_fsrl: &Fsrl,
    ) -> Vec<FsBrowserNode> {
        if &gfile.fsrl == target_fsrl {
            return gfile
                .children
                .iter()
                .enumerate()
                .map(|(i, child)| {
                    let id = NodeId(self.tree.node_count() as u64 + i as u64 + 100);
                    if child.is_directory {
                        FsBrowserNode::directory(id, child, NodeId(0))
                    } else {
                        FsBrowserNode::file(id, child, NodeId(0))
                    }
                })
                .collect();
        }

        for child in &gfile.children {
            let found = self.find_children_recursive(child, target_fsrl);
            if !found.is_empty() {
                return found;
            }
        }

        Vec::new()
    }

    /// Set the pending program (from delayed activation timer).
    pub fn set_pending_program(&mut self, program: Option<String>) {
        self.pending_program = program;
    }

    /// Activate the pending program.
    pub fn activate_pending_program(&mut self) -> Option<String> {
        self.pending_program.take()
    }

    /// Get a descriptive name for the filesystem.
    pub fn descriptive_fs_name(fs: &GFileSystem) -> String {
        format!("{} [{}]", fs.fsrl_root.name, fs.fs_type)
    }

    /// Get all file names at a given level (for debugging/testing).
    pub fn list_children(&self, node_id: NodeId) -> Vec<String> {
        self.tree
            .get(node_id)
            .map(|n| n.children.iter().map(|c| c.name.clone()).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsbrowser::{GFile, Fsrl as FsrlType};

    fn make_fs_with_children() -> GFileSystem {
        let mut root = GFile::directory("/", FsrlType::new("zipfs:/", "/"));

        let dir1 = {
            let mut d = GFile::directory("subdir", FsrlType::new("zipfs:/subdir", "subdir"));
            d.children.push(GFile::file(
                "inner.txt",
                FsrlType::new("zipfs:/subdir/inner.txt", "inner.txt"),
                100,
            ));
            d
        };

        let file1 = GFile::file(
            "readme.txt",
            FsrlType::new("zipfs:/readme.txt", "readme.txt"),
            256,
        );
        let file2 = GFile::file(
            "data.bin",
            FsrlType::new("zipfs:/data.bin", "data.bin"),
            1024,
        );

        root.children.push(file1);
        root.children.push(dir1);
        root.children.push(file2);

        GFileSystem::new(FsrlType::new("zipfs:", "archive.zip"), "ZIP", root)
    }

    fn make_provider() -> FsBrowserComponentProvider {
        let fs = make_fs_with_children();
        let fs_ref = FileSystemRef::new(fs);
        let mut provider = FsBrowserComponentProvider::new(1, "archive.zip [ZIP]", fs_ref);
        provider.init_tree();
        provider
    }

    #[test]
    fn test_provider_creation_and_init() {
        let provider = make_provider();
        assert_eq!(provider.title, "archive.zip [ZIP]");
        assert_eq!(provider.state, ProviderState::Hidden);
        assert!(provider.root_node_id.is_some());
        // Only the root is registered in the tree; children are nested inside the root node.
        assert_eq!(provider.tree.node_count(), 1);
        // Verify children were populated via list_children
        let root_id = provider.root_node_id.unwrap();
        let children = provider.list_children(root_id);
        assert_eq!(children.len(), 3);
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = make_provider();
        assert!(!provider.is_visible());

        provider.show();
        assert!(provider.is_visible());

        provider.hide();
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_provider_dispose() {
        let mut provider = make_provider();
        provider.show();
        provider.set_focus(NodeId(1));

        provider.dispose();
        assert_eq!(provider.state, ProviderState::Disposed);
        assert!(provider.focus.is_none());
        assert_eq!(provider.tree.node_count(), 0);
    }

    #[test]
    fn test_provider_focus() {
        let mut provider = make_provider();
        let root_id = provider.root_node_id.unwrap();

        provider.set_focus(root_id);
        let focus = provider.focus.as_ref().unwrap();
        assert_eq!(focus.name, "archive.zip");

        provider.clear_focus();
        assert!(provider.focus.is_none());
    }

    #[test]
    fn test_provider_pending_program() {
        let mut provider = make_provider();
        assert!(provider.pending_program.is_none());

        provider.set_pending_program(Some("test.exe".to_string()));
        assert_eq!(provider.pending_program, Some("test.exe".to_string()));

        let activated = provider.activate_pending_program();
        assert_eq!(activated, Some("test.exe".to_string()));
        assert!(provider.pending_program.is_none());
    }

    #[test]
    fn test_descriptive_fs_name() {
        let fs = make_fs_with_children();
        let name = FsBrowserComponentProvider::descriptive_fs_name(&fs);
        assert_eq!(name, "archive.zip [ZIP]");
    }

    #[test]
    fn test_provider_init_tree_populates_root_children() {
        let provider = make_provider();
        let root_id = provider.root_node_id.unwrap();

        // init_tree already populates root children from the filesystem
        let children = provider.list_children(root_id);
        assert_eq!(children.len(), 3);
        assert!(children.contains(&"readme.txt".to_string()));
        assert!(children.contains(&"subdir".to_string()));
        assert!(children.contains(&"data.bin".to_string()));
    }
}
