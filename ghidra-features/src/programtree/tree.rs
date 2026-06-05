//! ProgramTree -- the tree data structure with expansion/selection state.
//!
//! Ported from Ghidra's `ProgramDnDTree` / `DragNDropTree` concepts.
//!
//! This struct owns the root [`ProgramNode`] and tracks which nodes are
//! expanded, selected, and in the view.  It also maintains a name indexer
//! for fast lookups by group name.

use std::collections::{HashMap, HashSet};

use ghidra_core::Address;

use super::{GroupPath, ProgramNode};

/// The program tree data structure.
///
/// Owns the root node and maintains expansion, selection, and view state.
#[derive(Debug, Clone)]
pub struct ProgramTree {
    /// The name of this tree (e.g. "Program Tree").
    tree_name: String,
    /// The root node of the tree.
    root: ProgramNode,
    /// Set of group paths that are currently expanded.
    expanded_paths: HashSet<GroupPath>,
    /// Ordered list of group paths that are currently selected.
    selected_paths: Vec<GroupPath>,
    /// Ordered list of group paths that define the current view.
    view_paths: Vec<GroupPath>,
    /// Map from group name to GroupPath for fast name-based lookups.
    name_index: HashMap<String, Vec<GroupPath>>,
    /// Version tag for the tree, used for cache invalidation.
    version_tag: Option<u64>,
}

impl ProgramTree {
    /// Create a new ProgramTree with the given name and root node.
    pub fn new(tree_name: impl Into<String>, root: ProgramNode) -> Self {
        let name = tree_name.into();
        let root_path = GroupPath::root(&name);
        let mut root_node = root;
        root_node.set_group_path(root_path.clone());

        let mut tree = Self {
            tree_name: name,
            root: root_node,
            expanded_paths: HashSet::new(),
            selected_paths: Vec::new(),
            view_paths: vec![root_path],
            name_index: HashMap::new(),
            version_tag: None,
        };
        // Build the name index from the full tree structure
        tree.rebuild_name_index();
        tree
    }

    /// Returns the tree name.
    pub fn tree_name(&self) -> &str {
        &self.tree_name
    }

    /// Returns a reference to the root node.
    pub fn root(&self) -> &ProgramNode {
        &self.root
    }

    /// Returns a mutable reference to the root node.
    pub fn root_mut(&mut self) -> &mut ProgramNode {
        &mut self.root
    }

    /// Returns the version tag.
    pub fn version_tag(&self) -> Option<u64> {
        self.version_tag
    }

    /// Set the version tag.
    pub fn set_version_tag(&mut self, tag: Option<u64>) {
        self.version_tag = tag;
    }

    // ------------------------------------------------------------------
    // Expansion
    // ------------------------------------------------------------------

    /// Expand the given group path.
    pub fn expand(&mut self, path: &GroupPath) {
        self.expanded_paths.insert(path.clone());
    }

    /// Collapse the given group path.
    pub fn collapse(&mut self, path: &GroupPath) {
        self.expanded_paths.remove(path);
    }

    /// Toggle expansion of the given group path.
    pub fn toggle_expand(&mut self, path: &GroupPath) {
        if self.is_expanded(path) {
            self.collapse(path);
        } else {
            self.expand(path);
        }
    }

    /// Returns `true` if the given path is expanded.
    pub fn is_expanded(&self, path: &GroupPath) -> bool {
        self.expanded_paths.contains(path)
    }

    /// Returns a reference to the set of expanded paths.
    pub fn expanded_paths(&self) -> &HashSet<GroupPath> {
        &self.expanded_paths
    }

    // ------------------------------------------------------------------
    // Selection
    // ------------------------------------------------------------------

    /// Select the given group path (adds to selection).
    pub fn select(&mut self, path: GroupPath) {
        if !self.selected_paths.contains(&path) {
            self.selected_paths.push(path);
        }
    }

    /// Deselect the given group path.
    pub fn deselect(&mut self, path: &GroupPath) {
        self.selected_paths.retain(|p| p != path);
    }

    /// Clear the entire selection.
    pub fn clear_selection(&mut self) {
        self.selected_paths.clear();
    }

    /// Set the selection to exactly the given paths.
    pub fn set_selection(&mut self, paths: Vec<GroupPath>) {
        self.selected_paths = paths;
    }

    /// Returns the selected group paths.
    pub fn selected_paths(&self) -> &[GroupPath] {
        &self.selected_paths
    }

    /// Returns `true` if nothing is selected.
    pub fn is_selection_empty(&self) -> bool {
        self.selected_paths.is_empty()
    }

    // ------------------------------------------------------------------
    // View
    // ------------------------------------------------------------------

    /// Add a group path to the view.
    pub fn add_to_view(&mut self, path: GroupPath) {
        if !self.view_paths.contains(&path) {
            self.view_paths.push(path);
        }
    }

    /// Remove a group path from the view.
    pub fn remove_from_view(&mut self, path: &GroupPath) {
        self.view_paths.retain(|p| p != path);
    }

    /// Clear the view.
    pub fn clear_view(&mut self) {
        self.view_paths.clear();
    }

    /// Returns the view group paths.
    pub fn view_paths(&self) -> &[GroupPath] {
        &self.view_paths
    }

    /// Compute the effective address set for the current view.
    ///
    /// Walks the subtree under each view path and collects the min/max
    /// addresses of all fragment nodes.
    pub fn compute_view_address_ranges(&self) -> Vec<(Address, Address)> {
        let mut ranges = Vec::new();
        for view_path in &self.view_paths {
            if let Some(node) = self.root.find_by_path(view_path) {
                Self::collect_fragment_ranges(node, &mut ranges);
            }
        }
        ranges
    }

    fn collect_fragment_ranges(node: &ProgramNode, ranges: &mut Vec<(Address, Address)>) {
        if node.is_fragment() {
            if let (Some(min), Some(max)) = (node.min_address(), node.max_address()) {
                ranges.push((min, max));
            }
        }
        for child in node.children() {
            Self::collect_fragment_ranges(child, ranges);
        }
    }

    // ------------------------------------------------------------------
    // Name index
    // ------------------------------------------------------------------

    /// Register a group path in the name index.
    pub fn index_name(&mut self, name: &str, path: GroupPath) {
        self.name_index
            .entry(name.to_string())
            .or_default()
            .push(path);
    }

    /// Remove a name from the index.
    pub fn remove_name(&mut self, name: &str) {
        self.name_index.remove(name);
    }

    /// Look up group paths by name.
    pub fn find_paths_by_name(&self, name: &str) -> Option<&Vec<GroupPath>> {
        self.name_index.get(name)
    }

    /// Returns all indexed names.
    pub fn indexed_names(&self) -> Vec<&String> {
        self.name_index.keys().collect()
    }

    /// Returns a reference to the full name index.
    pub fn name_index(&self) -> &HashMap<String, Vec<GroupPath>> {
        &self.name_index
    }

    // ------------------------------------------------------------------
    // Reload / rebuild
    // ------------------------------------------------------------------

    /// Rebuild the name index from the current tree structure.
    pub fn rebuild_name_index(&mut self) {
        self.name_index.clear();
        let root_path = GroupPath::root(&self.tree_name);
        // Collect all (name, path) pairs first, then insert into the index
        // to avoid borrow checker conflicts between self.root and self.name_index.
        let entries = Self::collect_index_entries(&self.root, &root_path);
        for (name, path) in entries {
            self.name_index.entry(name).or_default().push(path);
        }
    }

    fn collect_index_entries(node: &ProgramNode, path: &GroupPath) -> Vec<(String, GroupPath)> {
        let mut entries = vec![(node.name().to_string(), path.clone())];
        for child in node.children() {
            let child_path = path.child(child.name());
            entries.extend(Self::collect_index_entries(child, &child_path));
        }
        entries
    }

    /// Reload the tree from the root. Resets expansion/selection state.
    pub fn reload(&mut self, new_root: ProgramNode) {
        let root_path = GroupPath::root(&self.tree_name);
        let mut r = new_root;
        r.set_group_path(root_path);
        self.root = r;
        self.expanded_paths.clear();
        self.selected_paths.clear();
        self.rebuild_name_index();
    }

    /// Returns all node names (depth-first).
    pub fn all_node_names(&self) -> Vec<String> {
        self.root.collect_all_names()
    }

    /// Returns the total number of nodes.
    pub fn node_count(&self) -> usize {
        self.root.total_count()
    }

    // ------------------------------------------------------------------
    // Group manipulation (for DnDMoveManager / ReorderManager)
    // ------------------------------------------------------------------

    /// Merge the source group into the destination fragment.
    ///
    /// Moves all children of the source into the destination.
    pub fn merge_group(
        &mut self,
        source_name: &str,
        dest_name: &str,
    ) -> Result<(), String> {
        // Find source and destination nodes.
        let source_path = self
            .name_index
            .get(source_name)
            .and_then(|paths| paths.first().cloned())
            .ok_or_else(|| format!("Source group '{}' not found", source_name))?;

        // Remove source from its parent and merge into dest.
        if let Some(source_node) = self.root.find_by_path(&source_path) {
            let children: Vec<_> = source_node.children().to_vec();
            let dest_path = self
                .name_index
                .get(dest_name)
                .and_then(|paths| paths.first().cloned())
                .ok_or_else(|| format!("Destination group '{}' not found", dest_name))?;

            if let Some(dest_node) = self.root.find_by_path_mut(&dest_path) {
                for child in children {
                    dest_node.add_child(child);
                }
            }
            // Remove source from parent.
            self.remove_group_by_path(&source_path);
            self.rebuild_name_index();
            Ok(())
        } else {
            Err(format!("Source group '{}' not found", source_name))
        }
    }

    /// Reparent a group: move it from its current parent to a new parent.
    pub fn reparent_group(
        &mut self,
        group_name: &str,
        new_parent_name: &str,
    ) -> Result<(), String> {
        let group_path = self
            .name_index
            .get(group_name)
            .and_then(|paths| paths.first().cloned())
            .ok_or_else(|| format!("Group '{}' not found", group_name))?;

        // Extract the node.
        let node = self.remove_group_by_path(&group_path)
            .ok_or_else(|| format!("Could not remove group '{}'", group_name))?;

        // Find the new parent.
        let parent_path = self
            .name_index
            .get(new_parent_name)
            .and_then(|paths| paths.first().cloned())
            .ok_or_else(|| format!("New parent '{}' not found", new_parent_name))?;

        if let Some(parent) = self.root.find_by_path_mut(&parent_path) {
            parent.add_child(node);
            self.rebuild_name_index();
            Ok(())
        } else {
            Err(format!("Could not find parent '{}'", new_parent_name))
        }
    }

    /// Add a group to a destination module (copy operation).
    pub fn add_group_to(
        &mut self,
        dest_name: &str,
        source_name: &str,
    ) -> Result<(), String> {
        let source_path = self
            .name_index
            .get(source_name)
            .and_then(|paths| paths.first().cloned())
            .ok_or_else(|| format!("Source '{}' not found", source_name))?;

        let source_node = self.root.find_by_path(&source_path)
            .ok_or_else(|| format!("Source '{}' not found at path", source_name))?
            .clone();

        let dest_path = self
            .name_index
            .get(dest_name)
            .and_then(|paths| paths.first().cloned())
            .ok_or_else(|| format!("Destination '{}' not found", dest_name))?;

        if let Some(dest) = self.root.find_by_path_mut(&dest_path) {
            dest.add_child(source_node);
            self.rebuild_name_index();
            Ok(())
        } else {
            Err(format!("Destination '{}' not found at path", dest_name))
        }
    }

    /// Add a group before the reference group (reorder).
    pub fn add_group_before(
        &mut self,
        ref_name: &str,
        group_name: &str,
    ) -> Result<(), String> {
        let group_path = self
            .name_index
            .get(group_name)
            .and_then(|paths| paths.first().cloned())
            .ok_or_else(|| format!("Group '{}' not found", group_name))?;

        let node = self.remove_group_by_path(&group_path)
            .ok_or_else(|| format!("Could not remove group '{}'", group_name))?;

        // Find the parent of the reference group.
        let ref_path = self
            .name_index
            .get(ref_name)
            .and_then(|paths| paths.first().cloned())
            .ok_or_else(|| format!("Reference '{}' not found", ref_name))?;

        if let Some(parent_path) = ref_path.parent() {
            if let Some(parent) = self.root.find_by_path_mut(&parent_path) {
                if let Some(idx) = parent.children().iter().position(|c| c.name() == ref_name) {
                    parent.insert_child(idx, node);
                } else {
                    parent.add_child(node);
                }
                self.rebuild_name_index();
                return Ok(());
            }
        }
        Err(format!("Could not find parent for '{}'", ref_name))
    }

    /// Add a group after the reference group (reorder).
    pub fn add_group_after(
        &mut self,
        ref_name: &str,
        group_name: &str,
    ) -> Result<(), String> {
        let group_path = self
            .name_index
            .get(group_name)
            .and_then(|paths| paths.first().cloned())
            .ok_or_else(|| format!("Group '{}' not found", group_name))?;

        let node = self.remove_group_by_path(&group_path)
            .ok_or_else(|| format!("Could not remove group '{}'", group_name))?;

        let ref_path = self
            .name_index
            .get(ref_name)
            .and_then(|paths| paths.first().cloned())
            .ok_or_else(|| format!("Reference '{}' not found", ref_name))?;

        if let Some(parent_path) = ref_path.parent() {
            if let Some(parent) = self.root.find_by_path_mut(&parent_path) {
                if let Some(idx) = parent.children().iter().position(|c| c.name() == ref_name) {
                    parent.insert_child(idx + 1, node);
                } else {
                    parent.add_child(node);
                }
                self.rebuild_name_index();
                return Ok(());
            }
        }
        Err(format!("Could not find parent for '{}'", ref_name))
    }

    /// Remove a group by its path, returning the removed node.
    fn remove_group_by_path(&mut self, path: &GroupPath) -> Option<ProgramNode> {
        let names = path.names();
        if names.len() < 2 {
            return None;
        }
        let child_name = names.last()?;
        let parent_path = GroupPath::new(names[..names.len() - 1].to_vec());

        if let Some(parent) = self.root.find_by_path_mut(&parent_path) {
            parent.remove_child_by_name(child_name)
        } else {
            None
        }
    }
}

impl std::fmt::Display for ProgramTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ProgramTree({}, {} nodes, {} expanded, {} selected, {} view)",
            self.tree_name,
            self.node_count(),
            self.expanded_paths.len(),
            self.selected_paths.len(),
            self.view_paths.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sample_tree() -> ProgramTree {
        let mut root = ProgramNode::new_module("Program Tree");
        let mut folder = ProgramNode::new_module("src");
        folder.add_child(ProgramNode::new_fragment(".text", Some(Address::new(0x1000)), Some(Address::new(0x2000))));
        folder.add_child(ProgramNode::new_fragment(".data", Some(Address::new(0x3000)), Some(Address::new(0x3500))));
        root.add_child(folder);
        root.add_child(ProgramNode::new_fragment(".bss", Some(Address::new(0x4000)), Some(Address::new(0x5000))));

        ProgramTree::new("Program Tree", root)
    }

    #[test]
    fn test_tree_creation() {
        let tree = make_sample_tree();
        assert_eq!(tree.tree_name(), "Program Tree");
        assert_eq!(tree.root().name(), "Program Tree");
        assert!(tree.root().is_module());
    }

    #[test]
    fn test_expand_collapse() {
        let mut tree = make_sample_tree();
        let path = GroupPath::new(vec!["Program Tree".into(), "src".into()]);

        assert!(!tree.is_expanded(&path));
        tree.expand(&path);
        assert!(tree.is_expanded(&path));

        tree.collapse(&path);
        assert!(!tree.is_expanded(&path));

        tree.toggle_expand(&path);
        assert!(tree.is_expanded(&path));
        tree.toggle_expand(&path);
        assert!(!tree.is_expanded(&path));
    }

    #[test]
    fn test_selection() {
        let mut tree = make_sample_tree();
        let p1 = GroupPath::new(vec!["Program Tree".into(), "src".into(), ".text".into()]);
        let p2 = GroupPath::new(vec!["Program Tree".into(), ".bss".into()]);

        assert!(tree.is_selection_empty());

        tree.select(p1.clone());
        tree.select(p2.clone());
        assert_eq!(tree.selected_paths().len(), 2);

        tree.deselect(&p1);
        assert_eq!(tree.selected_paths().len(), 1);
        assert_eq!(tree.selected_paths()[0], p2);

        tree.clear_selection();
        assert!(tree.is_selection_empty());
    }

    #[test]
    fn test_view() {
        let mut tree = make_sample_tree();
        let view_path = GroupPath::new(vec!["Program Tree".into(), "src".into()]);

        // Default view includes root
        assert_eq!(tree.view_paths().len(), 1);

        tree.add_to_view(view_path.clone());
        assert_eq!(tree.view_paths().len(), 2);
        assert!(tree.view_paths().contains(&view_path));

        tree.remove_from_view(&view_path);
        assert_eq!(tree.view_paths().len(), 1);
    }

    #[test]
    fn test_view_address_ranges() {
        let tree = make_sample_tree();
        // Default view includes root, so all fragments should be counted
        let ranges = tree.compute_view_address_ranges();
        // 3 fragments: .text, .data, .bss
        assert_eq!(ranges.len(), 3);
    }

    #[test]
    fn test_name_index() {
        let tree = make_sample_tree();
        assert!(tree.find_paths_by_name(".text").is_some());
        assert!(tree.find_paths_by_name(".data").is_some());
        assert!(tree.find_paths_by_name(".bss").is_some());
        assert!(tree.find_paths_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_node_count() {
        let tree = make_sample_tree();
        // root + src + .text + .data + .bss = 5
        assert_eq!(tree.node_count(), 5);
    }

    #[test]
    fn test_all_node_names() {
        let tree = make_sample_tree();
        let names = tree.all_node_names();
        assert!(names.contains(&"Program Tree".to_string()));
        assert!(names.contains(&"src".to_string()));
        assert!(names.contains(&".text".to_string()));
        assert!(names.contains(&".data".to_string()));
        assert!(names.contains(&".bss".to_string()));
    }

    #[test]
    fn test_display() {
        let tree = make_sample_tree();
        let s = tree.to_string();
        assert!(s.contains("Program Tree"));
        assert!(s.contains("5 nodes"));
    }

    #[test]
    fn test_reload() {
        let mut tree = make_sample_tree();
        tree.expand(&GroupPath::root("Program Tree"));

        let new_root = ProgramNode::new_module("New Root");
        tree.reload(new_root);

        assert_eq!(tree.root().name(), "New Root");
        assert!(tree.expanded_paths().is_empty());
        assert!(tree.is_selection_empty());
    }
}
