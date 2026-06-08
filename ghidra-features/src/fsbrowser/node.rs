//! Tree nodes for the filesystem browser.
//!
//! Ported from `ghidra.plugins.fsbrowser.FSBNode`, `FSBFileNode`,
//! `FSBDirNode`, `FSBRootNode`.

use std::collections::HashMap;

use super::{Fsrl, GFile};

// ---------------------------------------------------------------------------
// NodeId -- unique identifier for a node in the tree
// ---------------------------------------------------------------------------

/// Unique identifier for a node in the filesystem browser tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub u64);

impl NodeId {
    /// Create a new node ID from a counter value.
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

// ---------------------------------------------------------------------------
// FsBrowserNode -- abstract base for all browser tree nodes
// ---------------------------------------------------------------------------

/// The kind of filesystem browser node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsBrowserNodeKind {
    /// Root node representing a mounted filesystem.
    Root,
    /// Directory node.
    Directory,
    /// File node.
    File,
}

/// Base class for all filesystem browser tree nodes.
///
/// Ported from `ghidra.plugins.fsbrowser.FSBNode`.
#[derive(Debug, Clone)]
pub struct FsBrowserNode {
    /// Unique node identifier.
    pub id: NodeId,
    /// The kind of node (root, directory, file).
    pub kind: FsBrowserNodeKind,
    /// Display name.
    pub name: String,
    /// The FSRL of the filesystem object this node represents.
    pub fsrl: Fsrl,
    /// Whether this node's children have been loaded.
    pub loaded: bool,
    /// Whether this node is a leaf (no children possible).
    pub is_leaf: bool,
    /// Child nodes.
    pub children: Vec<FsBrowserNode>,
    /// Parent node ID (None for root).
    pub parent_id: Option<NodeId>,
    /// File size (0 for directories).
    pub size: u64,
    /// File extension.
    pub extension: String,
    /// Tool tip text.
    pub tooltip: String,
}

impl FsBrowserNode {
    /// Create a new node.
    pub fn new(
        id: NodeId,
        kind: FsBrowserNodeKind,
        name: impl Into<String>,
        fsrl: Fsrl,
        parent_id: Option<NodeId>,
    ) -> Self {
        let name = name.into();
        let extension = name
            .rfind('.')
            .map(|i| name[i + 1..].to_string())
            .unwrap_or_default();
        let tooltip = name.clone();
        Self {
            id,
            kind,
            name,
            fsrl,
            loaded: false,
            is_leaf: kind == FsBrowserNodeKind::File,
            children: Vec::new(),
            parent_id,
            size: 0,
            extension,
            tooltip,
        }
    }

    /// Create a root node for a filesystem.
    pub fn root(id: NodeId, fsrl: Fsrl) -> Self {
        Self::new(id, FsBrowserNodeKind::Root, fsrl.name.clone(), fsrl, None)
    }

    /// Create a file node.
    pub fn file(id: NodeId, gfile: &GFile, parent_id: NodeId) -> Self {
        let mut node = Self::new(
            id,
            FsBrowserNodeKind::File,
            &gfile.name,
            gfile.fsrl.clone(),
            Some(parent_id),
        );
        node.size = gfile.size;
        node.is_leaf = true;
        node.loaded = true; // files have no children
        node
    }

    /// Create a directory node.
    pub fn directory(id: NodeId, gfile: &GFile, parent_id: NodeId) -> Self {
        let mut node = Self::new(
            id,
            FsBrowserNodeKind::Directory,
            &gfile.name,
            gfile.fsrl.clone(),
            Some(parent_id),
        );
        node.is_leaf = false;
        node
    }

    /// Check if this node is a leaf (no children).
    pub fn is_leaf(&self) -> bool {
        self.is_leaf
    }

    /// Check if children have been loaded.
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Set children and mark as loaded.
    pub fn set_children(&mut self, children: Vec<FsBrowserNode>) {
        self.children = children;
        self.loaded = true;
    }

    /// Get the formatted tree path (root/file1/file2/...).
    pub fn formatted_tree_path(&self, all_nodes: &HashMap<NodeId, FsBrowserNode>) -> String {
        let mut path_parts = Vec::new();
        self.collect_path_parts(&mut path_parts, all_nodes);
        path_parts.join("/")
    }

    fn collect_path_parts(
        &self,
        parts: &mut Vec<String>,
        all_nodes: &HashMap<NodeId, FsBrowserNode>,
    ) {
        if let Some(parent_id) = self.parent_id {
            if let Some(parent) = all_nodes.get(&parent_id) {
                parent.collect_path_parts(parts, all_nodes);
            }
        }
        if self.kind == FsBrowserNodeKind::Root {
            if let Some(name) = self.fsrl.uri.split(':').next() {
                parts.push(name.to_string());
            }
        } else {
            parts.push(self.name.clone());
        }
    }

    /// Find a child node by FSRL.
    pub fn find_child_by_fsrl(&self, fsrl: &Fsrl) -> Option<&FsBrowserNode> {
        self.children.iter().find(|c| &c.fsrl == fsrl)
    }

    /// Sort children: directories first, then alphabetically.
    pub fn sort_children(&mut self) {
        self.children.sort_by(|a, b| {
            let a_dir = a.kind == FsBrowserNodeKind::Directory;
            let b_dir = b.kind == FsBrowserNodeKind::Directory;
            b_dir
                .cmp(&a_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
    }

    /// Refresh this node's children against the current filesystem state.
    ///
    /// Returns true if any changes were detected.
    pub fn refresh_children(&mut self, current_files: &[GFile]) -> bool {
        if self.is_leaf || !self.loaded {
            return false;
        }

        let mut change_count = 0;
        let existing_fsrls: Vec<Fsrl> = self.children.iter().map(|c| c.fsrl.clone()).collect();
        let new_fsrls: Vec<Fsrl> = current_files.iter().map(|f| f.fsrl.clone()).collect();

        // Remove children no longer present
        self.children
            .retain(|c| new_fsrls.contains(&c.fsrl));
        let removed = existing_fsrls.len() - self.children.len();
        change_count += removed;

        // Add new children
        let next_id = self.children.len() as u64;
        for (i, file) in current_files.iter().enumerate() {
            if !existing_fsrls.contains(&file.fsrl) {
                let node = if file.is_directory {
                    FsBrowserNode::directory(NodeId(next_id + i as u64), file, self.id)
                } else {
                    FsBrowserNode::file(NodeId(next_id + i as u64), file, self.id)
                };
                self.children.push(node);
                change_count += 1;
            }
        }

        if change_count > 0 {
            self.sort_children();
        }

        change_count > 0
    }
}

// ---------------------------------------------------------------------------
// FsBrowserNodeTree -- tree container with node management
// ---------------------------------------------------------------------------

/// A container managing a flat collection of nodes with parent-child
/// relationships, used by the filesystem browser.
#[derive(Debug, Clone)]
pub struct FsBrowserNodeTree {
    /// All nodes by ID.
    pub nodes: HashMap<NodeId, FsBrowserNode>,
    /// Root node IDs (in display order).
    pub roots: Vec<NodeId>,
    /// Next available node ID.
    next_id: u64,
}

impl FsBrowserNodeTree {
    /// Create an empty tree.
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            roots: Vec::new(),
            next_id: 1,
        }
    }

    /// Allocate a new unique node ID.
    pub fn alloc_id(&mut self) -> NodeId {
        let id = NodeId::new(self.next_id);
        self.next_id += 1;
        id
    }

    /// Add a root node.
    pub fn add_root(&mut self, node: FsBrowserNode) -> NodeId {
        let id = node.id;
        self.roots.push(id);
        self.nodes.insert(id, node);
        id
    }

    /// Get a node by ID.
    pub fn get(&self, id: NodeId) -> Option<&FsBrowserNode> {
        self.nodes.get(&id)
    }

    /// Get a mutable node by ID.
    pub fn get_mut(&mut self, id: NodeId) -> Option<&mut FsBrowserNode> {
        self.nodes.get_mut(&id)
    }

    /// Remove a node and all its descendants.
    pub fn remove(&mut self, id: NodeId) {
        // Collect all descendant IDs
        let mut to_remove = Vec::new();
        self.collect_descendants(id, &mut to_remove);
        to_remove.push(id);

        for rid in &to_remove {
            self.nodes.remove(rid);
        }
        self.roots.retain(|r| !to_remove.contains(r));
    }

    fn collect_descendants(&self, id: NodeId, result: &mut Vec<NodeId>) {
        if let Some(node) = self.nodes.get(&id) {
            for child in &node.children {
                result.push(child.id);
                self.collect_descendants(child.id, result);
            }
        }
    }

    /// Get the total number of nodes in the tree.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

impl Default for FsBrowserNodeTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fsrl(name: &str) -> Fsrl {
        Fsrl::new(format!("zipfs:/{name}"), name)
    }

    fn make_root_node(tree: &mut FsBrowserNodeTree) -> NodeId {
        let id = tree.alloc_id();
        let node = FsBrowserNode::root(id, make_fsrl("archive.zip"));
        tree.add_root(node)
    }

    #[test]
    fn test_node_creation() {
        let node = FsBrowserNode::new(
            NodeId(1),
            FsBrowserNodeKind::File,
            "test.txt",
            make_fsrl("test.txt"),
            None,
        );
        assert_eq!(node.name, "test.txt");
        assert_eq!(node.kind, FsBrowserNodeKind::File);
        assert!(node.is_leaf());
        assert_eq!(node.extension, "txt");
    }

    #[test]
    fn test_file_node_from_gfile() {
        let gfile = GFile::file("data.bin", make_fsrl("data.bin"), 2048);
        let node = FsBrowserNode::file(NodeId(2), &gfile, NodeId(1));
        assert_eq!(node.name, "data.bin");
        assert_eq!(node.size, 2048);
        assert!(node.is_leaf());
        assert!(node.is_loaded()); // files are immediately loaded
    }

    #[test]
    fn test_directory_node_from_gfile() {
        let gfile = GFile::directory("subdir", make_fsrl("subdir"));
        let node = FsBrowserNode::directory(NodeId(3), &gfile, NodeId(1));
        assert_eq!(node.name, "subdir");
        assert_eq!(node.kind, FsBrowserNodeKind::Directory);
        assert!(!node.is_leaf());
        assert!(!node.is_loaded()); // directories need lazy loading
    }

    #[test]
    fn test_node_sort_children() {
        let mut node = FsBrowserNode::root(NodeId(1), make_fsrl("root"));

        let f1 = GFile::file("zebra.txt", make_fsrl("zebra.txt"), 10);
        let f2 = GFile::directory("alpha", make_fsrl("alpha"));
        let f3 = GFile::file("middle.bin", make_fsrl("middle.bin"), 20);
        let f4 = GFile::directory("beta", make_fsrl("beta"));

        node.children = vec![
            FsBrowserNode::file(NodeId(2), &f1, NodeId(1)),
            FsBrowserNode::directory(NodeId(3), &f2, NodeId(1)),
            FsBrowserNode::file(NodeId(4), &f3, NodeId(1)),
            FsBrowserNode::directory(NodeId(5), &f4, NodeId(1)),
        ];

        node.sort_children();

        // Directories first, then files, both alphabetically
        assert_eq!(node.children[0].name, "alpha");
        assert_eq!(node.children[1].name, "beta");
        assert_eq!(node.children[2].name, "middle.bin");
        assert_eq!(node.children[3].name, "zebra.txt");
    }

    #[test]
    fn test_node_find_child() {
        let mut node = FsBrowserNode::root(NodeId(1), make_fsrl("root"));
        let f1 = GFile::file("target.txt", make_fsrl("target.txt"), 100);
        let f2 = GFile::file("other.txt", make_fsrl("other.txt"), 50);
        node.children = vec![
            FsBrowserNode::file(NodeId(2), &f1, NodeId(1)),
            FsBrowserNode::file(NodeId(3), &f2, NodeId(1)),
        ];

        let found = node.find_child_by_fsrl(&make_fsrl("target.txt"));
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "target.txt");

        let not_found = node.find_child_by_fsrl(&make_fsrl("missing.txt"));
        assert!(not_found.is_none());
    }

    #[test]
    fn test_node_refresh_children() {
        let mut node = FsBrowserNode::root(NodeId(1), make_fsrl("root"));
        let f1 = GFile::file("keep.txt", make_fsrl("keep.txt"), 10);
        let f2 = GFile::file("remove.txt", make_fsrl("remove.txt"), 20);
        node.children = vec![
            FsBrowserNode::file(NodeId(2), &f1, NodeId(1)),
            FsBrowserNode::file(NodeId(3), &f2, NodeId(1)),
        ];
        node.loaded = true;

        // New state: keep.txt stays, remove.txt is gone, new.txt appears
        let new_files = vec![
            GFile::file("keep.txt", make_fsrl("keep.txt"), 10),
            GFile::file("new.txt", make_fsrl("new.txt"), 30),
        ];

        let changed = node.refresh_children(&new_files);
        assert!(changed);
        assert_eq!(node.children.len(), 2);
        let names: Vec<&str> = node.children.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"keep.txt"));
        assert!(names.contains(&"new.txt"));
        assert!(!names.contains(&"remove.txt"));
    }

    #[test]
    fn test_node_tree_basic() {
        let mut tree = FsBrowserNodeTree::new();
        let root_id = make_root_node(&mut tree);

        assert_eq!(tree.node_count(), 1);
        assert!(tree.get(root_id).is_some());
        assert_eq!(tree.roots.len(), 1);
    }

    #[test]
    fn test_node_tree_remove() {
        let mut tree = FsBrowserNodeTree::new();
        let root_id = make_root_node(&mut tree);

        tree.remove(root_id);
        assert_eq!(tree.node_count(), 0);
        assert!(tree.roots.is_empty());
    }

    #[test]
    fn test_formatted_tree_path() {
        let mut all_nodes = HashMap::new();

        let root = FsBrowserNode::root(NodeId(1), Fsrl::new("zipfs:", "archive.zip"));
        all_nodes.insert(NodeId(1), root);

        let dir = FsBrowserNode::new(
            NodeId(2),
            FsBrowserNodeKind::Directory,
            "subdir",
            make_fsrl("subdir"),
            Some(NodeId(1)),
        );
        all_nodes.insert(NodeId(2), dir);

        let file = FsBrowserNode::new(
            NodeId(3),
            FsBrowserNodeKind::File,
            "data.bin",
            make_fsrl("data.bin"),
            Some(NodeId(2)),
        );
        all_nodes.insert(NodeId(3), file);

        let path = all_nodes.get(&NodeId(3)).unwrap().formatted_tree_path(&all_nodes);
        assert_eq!(path, "zipfs/subdir/data.bin");
    }

    #[test]
    fn test_node_extension() {
        let node = FsBrowserNode::new(
            NodeId(1),
            FsBrowserNodeKind::File,
            "archive.tar.gz",
            make_fsrl("archive.tar.gz"),
            None,
        );
        assert_eq!(node.extension, "gz");
    }
}
