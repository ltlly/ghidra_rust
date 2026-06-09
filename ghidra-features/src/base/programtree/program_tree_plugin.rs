//! Program Tree Plugin -- displays program tree views.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.programtree.ProgramTreePlugin`.
//!
//! This module provides the main plugin for displaying program trees.
//! It manages multiple tree view providers, handles program lifecycle
//! events, and coordinates tree navigation and selection.
//!
//! # Architecture
//!
//! ```text
//! ProgramTreePlugin
//!   ├── TreeViewProvider (per-tree view management)
//!   ├── ProgramTreeActionManager (action coordination)
//!   ├── ViewManagerComponentProvider (UI container)
//!   └── ProgramListener (program change handling)
//! ```
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::programtree::program_tree_plugin::ProgramTreePlugin;
//!
//! let mut plugin = ProgramTreePlugin::new("ProgramTree");
//! plugin.init();
//! assert_eq!(plugin.name(), "ProgramTree");
//! ```

use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// ProgramNodeType -- types of nodes in the program tree
// ---------------------------------------------------------------------------

/// Types of nodes in the program tree.
///
/// Ported from Ghidra's program tree node types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramNodeType {
    /// Root node of the tree.
    Root,
    /// A module (folder/group) node.
    Module,
    /// A fragment (address range) node.
    Fragment,
}

impl ProgramNodeType {
    /// Returns the display name for this node type.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Root => "Root",
            Self::Module => "Module",
            Self::Fragment => "Fragment",
        }
    }
}

impl fmt::Display for ProgramNodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// ProgramNode -- a node in the program tree
// ---------------------------------------------------------------------------

/// A node in the program tree.
///
/// Represents either a module (folder) or fragment (address range)
/// in the program's hierarchical structure.
///
/// Ported from Ghidra's `ProgramNode` Java class.
#[derive(Debug, Clone)]
pub struct ProgramNode {
    /// The node name.
    pub name: String,
    /// The node type.
    pub node_type: ProgramNodeType,
    /// Child nodes.
    pub children: Vec<ProgramNode>,
    /// Whether the node is expanded.
    pub expanded: bool,
    /// Whether the node is a leaf (no children).
    pub is_leaf: bool,
    /// The address range (for fragment nodes).
    pub address_range: Option<AddressRange>,
    /// The version tag for validity checking.
    pub version_tag: u64,
}

/// An address range in the program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRange {
    /// Start address (as hex string).
    pub start: String,
    /// End address (as hex string).
    pub end: String,
}

impl AddressRange {
    /// Creates a new address range.
    pub fn new(start: impl Into<String>, end: impl Into<String>) -> Self {
        Self {
            start: start.into(),
            end: end.into(),
        }
    }

    /// Returns the size of the range (if parseable).
    pub fn size(&self) -> Option<u64> {
        let start = u64::from_str_radix(self.start.trim_start_matches("0x"), 16).ok()?;
        let end = u64::from_str_radix(self.end.trim_start_matches("0x"), 16).ok()?;
        Some(end - start + 1)
    }
}

impl ProgramNode {
    /// Creates a new program node.
    pub fn new(name: impl Into<String>, node_type: ProgramNodeType) -> Self {
        Self {
            name: name.into(),
            node_type,
            children: Vec::new(),
            expanded: false,
            is_leaf: true,
            address_range: None,
            version_tag: 0,
        }
    }

    /// Creates a new root node.
    pub fn root(name: impl Into<String>) -> Self {
        Self::new(name, ProgramNodeType::Root)
    }

    /// Creates a new module node.
    pub fn module(name: impl Into<String>) -> Self {
        Self::new(name, ProgramNodeType::Module)
    }

    /// Creates a new fragment node.
    pub fn fragment(name: impl Into<String>, range: AddressRange) -> Self {
        let mut node = Self::new(name, ProgramNodeType::Fragment);
        node.address_range = Some(range);
        node
    }

    /// Adds a child node.
    pub fn add_child(&mut self, child: ProgramNode) {
        self.children.push(child);
        self.is_leaf = false;
    }

    /// Returns the number of children.
    pub fn child_count(&self) -> usize {
        self.children.len()
    }

    /// Returns a reference to a child by index.
    pub fn child(&self, index: usize) -> Option<&ProgramNode> {
        self.children.get(index)
    }

    /// Returns a mutable reference to a child by index.
    pub fn child_mut(&mut self, index: usize) -> Option<&mut ProgramNode> {
        self.children.get_mut(index)
    }

    /// Sets the expanded state.
    pub fn set_expanded(&mut self, expanded: bool) {
        self.expanded = expanded;
    }

    /// Returns whether the node is expanded.
    pub fn is_expanded(&self) -> bool {
        self.expanded
    }

    /// Returns whether this is a root node.
    pub fn is_root(&self) -> bool {
        self.node_type == ProgramNodeType::Root
    }

    /// Returns whether this is a module node.
    pub fn is_module(&self) -> bool {
        self.node_type == ProgramNodeType::Module
    }

    /// Returns whether this is a fragment node.
    pub fn is_fragment(&self) -> bool {
        self.node_type == ProgramNodeType::Fragment
    }

    /// Returns the address range (for fragment nodes).
    pub fn get_address_range(&self) -> Option<&AddressRange> {
        self.address_range.as_ref()
    }

    /// Returns the minimum address (for fragment nodes).
    pub fn get_min_address(&self) -> Option<&str> {
        self.address_range.as_ref().map(|r| r.start.as_str())
    }

    /// Returns the total number of descendants.
    pub fn total_descendants(&self) -> usize {
        let mut count = self.children.len();
        for child in &self.children {
            count += child.total_descendants();
        }
        count
    }

    /// Finds a child by name.
    pub fn find_child(&self, name: &str) -> Option<&ProgramNode> {
        self.children.iter().find(|c| c.name == name)
    }

    /// Finds a child by name (mutable).
    pub fn find_child_mut(&mut self, name: &str) -> Option<&mut ProgramNode> {
        self.children.iter_mut().find(|c| c.name == name)
    }

    /// Returns whether the node is valid for the given version tag.
    pub fn is_valid(&self, version_tag: u64) -> bool {
        self.version_tag == version_tag
    }

    /// Updates the version tag.
    pub fn set_version_tag(&mut self, tag: u64) {
        self.version_tag = tag;
    }
}

// ---------------------------------------------------------------------------
// TreeViewState -- state for tree view persistence
// ---------------------------------------------------------------------------

/// State for tree view persistence.
///
/// Stores the expanded and selected state of tree nodes for
/// serialization and restoration.
///
/// Ported from Ghidra's tree view state management.
#[derive(Debug, Clone, Default)]
pub struct TreeViewState {
    /// Expanded node paths.
    pub expanded_paths: Vec<Vec<String>>,
    /// Selected node paths.
    pub selected_paths: Vec<Vec<String>>,
    /// Viewed group paths.
    pub viewed_paths: Vec<Vec<String>>,
}

impl TreeViewState {
    /// Creates a new empty tree view state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an expanded path.
    pub fn add_expanded_path(&mut self, path: Vec<String>) {
        self.expanded_paths.push(path);
    }

    /// Adds a selected path.
    pub fn add_selected_path(&mut self, path: Vec<String>) {
        self.selected_paths.push(path);
    }

    /// Adds a viewed path.
    pub fn add_viewed_path(&mut self, path: Vec<String>) {
        self.viewed_paths.push(path);
    }

    /// Clears all state.
    pub fn clear(&mut self) {
        self.expanded_paths.clear();
        self.selected_paths.clear();
        self.viewed_paths.clear();
    }
}

// ---------------------------------------------------------------------------
// ProgramTreePlugin -- the main plugin
// ---------------------------------------------------------------------------

/// The program tree plugin.
///
/// Displays program structure as a tree of modules and fragments.
/// Manages multiple tree view providers and coordinates navigation.
///
/// Ported from Ghidra's `ProgramTreePlugin` Java class.
#[derive(Debug)]
pub struct ProgramTreePlugin {
    /// The plugin name.
    name: String,
    /// Map of tree name to tree view state.
    tree_states: BTreeMap<String, TreeViewState>,
    /// The current tree name.
    current_tree: Option<String>,
    /// Whether the plugin is initialized.
    initialized: bool,
    /// Whether the plugin is disposed.
    disposed: bool,
    /// Whether replace view mode is enabled.
    replace_view_mode: bool,
    /// Plugin options.
    options: BTreeMap<String, String>,
    /// Current program name.
    current_program: Option<String>,
    /// Number of views.
    view_count: usize,
}

impl ProgramTreePlugin {
    /// The default tree name.
    pub const DEFAULT_TREE_NAME: &'static str = "Program Tree";

    /// Creates a new program tree plugin.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            tree_states: BTreeMap::new(),
            current_tree: None,
            initialized: false,
            disposed: false,
            replace_view_mode: false,
            options: BTreeMap::new(),
            current_program: None,
            view_count: 0,
        }
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Initializes the plugin.
    pub fn init(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;
        // Add default tree view
        self.add_tree_view(Self::DEFAULT_TREE_NAME);
    }

    /// Disposes the plugin.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.tree_states.clear();
        self.current_tree = None;
        self.current_program = None;
    }

    /// Returns whether the plugin is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Sets the current program.
    pub fn set_program(&mut self, program: Option<String>) {
        self.current_program = program;
        if self.current_program.is_none() {
            self.tree_states.clear();
            self.add_tree_view(Self::DEFAULT_TREE_NAME);
        }
    }

    /// Returns the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Adds a tree view for the given tree name.
    pub fn add_tree_view(&mut self, tree_name: &str) -> &mut TreeViewState {
        self.tree_states
            .entry(tree_name.to_string())
            .or_insert_with(TreeViewState::new);
        self.view_count = self.tree_states.len();
        if self.current_tree.is_none() {
            self.current_tree = Some(tree_name.to_string());
        }
        self.tree_states.get_mut(tree_name).unwrap()
    }

    /// Removes a tree view.
    pub fn remove_tree_view(&mut self, tree_name: &str) -> bool {
        if self.tree_states.len() <= 1 {
            return false; // Cannot remove last view
        }
        let removed = self.tree_states.remove(tree_name).is_some();
        if removed {
            self.view_count = self.tree_states.len();
            if self.current_tree.as_deref() == Some(tree_name) {
                self.current_tree = self.tree_states.keys().next().cloned();
            }
        }
        removed
    }

    /// Returns whether a tree view exists.
    pub fn has_tree_view(&self, tree_name: &str) -> bool {
        self.tree_states.contains_key(tree_name)
    }

    /// Sets the current tree view.
    pub fn set_current_tree(&mut self, tree_name: &str) -> bool {
        if self.tree_states.contains_key(tree_name) {
            self.current_tree = Some(tree_name.to_string());
            true
        } else {
            false
        }
    }

    /// Returns the current tree name.
    pub fn current_tree(&self) -> Option<&str> {
        self.current_tree.as_deref()
    }

    /// Returns the tree view state for the given tree name.
    pub fn tree_state(&self, tree_name: &str) -> Option<&TreeViewState> {
        self.tree_states.get(tree_name)
    }

    /// Returns a mutable reference to the tree view state.
    pub fn tree_state_mut(&mut self, tree_name: &str) -> Option<&mut TreeViewState> {
        self.tree_states.get_mut(tree_name)
    }

    /// Returns the number of views.
    pub fn view_count(&self) -> usize {
        self.view_count
    }

    /// Returns all tree names.
    pub fn tree_names(&self) -> Vec<&str> {
        self.tree_states.keys().map(|s| s.as_str()).collect()
    }

    /// Sets replace view mode.
    pub fn set_replace_view_mode(&mut self, enabled: bool) {
        self.replace_view_mode = enabled;
    }

    /// Returns whether replace view mode is enabled.
    pub fn is_replace_view_mode(&self) -> bool {
        self.replace_view_mode
    }

    /// Sets a plugin option.
    pub fn set_option(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.options.insert(key.into(), value.into());
    }

    /// Gets a plugin option.
    pub fn get_option(&self, key: &str) -> Option<&str> {
        self.options.get(key).map(|s| s.as_str())
    }

    /// Renames a tree view.
    pub fn rename_tree_view(&mut self, old_name: &str, new_name: &str) -> bool {
        if let Some(state) = self.tree_states.remove(old_name) {
            self.tree_states.insert(new_name.to_string(), state);
            if self.current_tree.as_deref() == Some(old_name) {
                self.current_tree = Some(new_name.to_string());
            }
            true
        } else {
            false
        }
    }

    /// Clears the system clipboard state.
    pub fn clear_system_clipboard(&self) {
        // Placeholder for clipboard integration
    }

    /// Handles a tree selection event.
    pub fn on_tree_selection(&mut self, tree_name: &str, paths: Vec<Vec<String>>) {
        if let Some(state) = self.tree_states.get_mut(tree_name) {
            state.selected_paths = paths;
        }
    }

    /// Handles a program location change.
    pub fn on_location_changed(&self, _address: &str) {
        // Placeholder for location change handling
    }

    /// Handles a double-click on a node.
    pub fn on_double_click(&self, _node: &ProgramNode) {
        // Placeholder for double-click handling
    }
}

impl Default for ProgramTreePlugin {
    fn default() -> Self {
        Self::new("ProgramTreePlugin")
    }
}

impl fmt::Display for ProgramTreePlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProgramTreePlugin({}, views={})",
            self.name,
            self.view_count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = ProgramTreePlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(!plugin.is_initialized());
        assert_eq!(plugin.view_count(), 0);
    }

    #[test]
    fn test_plugin_init() {
        let mut plugin = ProgramTreePlugin::new("TestPlugin");
        plugin.init();
        assert!(plugin.is_initialized());
        assert_eq!(plugin.view_count(), 1);
        assert_eq!(plugin.current_tree(), Some("Program Tree"));
    }

    #[test]
    fn test_add_tree_view() {
        let mut plugin = ProgramTreePlugin::new("TestPlugin");
        plugin.init();
        plugin.add_tree_view("Custom Tree");
        assert_eq!(plugin.view_count(), 2);
        assert!(plugin.has_tree_view("Custom Tree"));
    }

    #[test]
    fn test_remove_tree_view() {
        let mut plugin = ProgramTreePlugin::new("TestPlugin");
        plugin.init();
        plugin.add_tree_view("Custom Tree");
        assert_eq!(plugin.view_count(), 2);

        assert!(plugin.remove_tree_view("Custom Tree"));
        assert_eq!(plugin.view_count(), 1);
        assert!(!plugin.has_tree_view("Custom Tree"));
    }

    #[test]
    fn test_cannot_remove_last_view() {
        let mut plugin = ProgramTreePlugin::new("TestPlugin");
        plugin.init();
        assert!(!plugin.remove_tree_view("Program Tree"));
        assert_eq!(plugin.view_count(), 1);
    }

    #[test]
    fn test_set_current_tree() {
        let mut plugin = ProgramTreePlugin::new("TestPlugin");
        plugin.init();
        plugin.add_tree_view("Custom Tree");

        assert!(plugin.set_current_tree("Custom Tree"));
        assert_eq!(plugin.current_tree(), Some("Custom Tree"));

        assert!(!plugin.set_current_tree("Nonexistent"));
    }

    #[test]
    fn test_rename_tree_view() {
        let mut plugin = ProgramTreePlugin::new("TestPlugin");
        plugin.init();
        assert!(plugin.rename_tree_view("Program Tree", "My Tree"));
        assert_eq!(plugin.current_tree(), Some("My Tree"));
        assert!(plugin.has_tree_view("My Tree"));
        assert!(!plugin.has_tree_view("Program Tree"));
    }

    #[test]
    fn test_replace_view_mode() {
        let mut plugin = ProgramTreePlugin::new("TestPlugin");
        assert!(!plugin.is_replace_view_mode());

        plugin.set_replace_view_mode(true);
        assert!(plugin.is_replace_view_mode());
    }

    #[test]
    fn test_program_node_types() {
        assert_eq!(ProgramNodeType::Root.display_name(), "Root");
        assert_eq!(ProgramNodeType::Module.display_name(), "Module");
        assert_eq!(ProgramNodeType::Fragment.display_name(), "Fragment");
    }

    #[test]
    fn test_program_node_creation() {
        let root = ProgramNode::root("MyProgram");
        assert!(root.is_root());
        assert_eq!(root.name, "MyProgram");

        let module = ProgramNode::module("MyModule");
        assert!(module.is_module());

        let range = AddressRange::new("0x401000", "0x401fff");
        let fragment = ProgramNode::fragment("MyFragment", range);
        assert!(fragment.is_fragment());
        assert_eq!(fragment.get_min_address(), Some("0x401000"));
    }

    #[test]
    fn test_program_node_children() {
        let mut root = ProgramNode::root("root");
        assert!(root.is_leaf);
        assert_eq!(root.child_count(), 0);

        let child = ProgramNode::module("child");
        root.add_child(child);
        assert!(!root.is_leaf);
        assert_eq!(root.child_count(), 1);
        assert_eq!(root.total_descendants(), 1);
    }

    #[test]
    fn test_address_range() {
        let range = AddressRange::new("0x401000", "0x401fff");
        assert_eq!(range.size(), Some(0x1000));

        let range = AddressRange::new("0x1000", "0x1000");
        assert_eq!(range.size(), Some(1));
    }

    #[test]
    fn test_tree_view_state() {
        let mut state = TreeViewState::new();
        state.add_expanded_path(vec!["root".to_string(), "child".to_string()]);
        state.add_selected_path(vec!["root".to_string(), "child".to_string()]);

        assert_eq!(state.expanded_paths.len(), 1);
        assert_eq!(state.selected_paths.len(), 1);

        state.clear();
        assert_eq!(state.expanded_paths.len(), 0);
        assert_eq!(state.selected_paths.len(), 0);
    }

    #[test]
    fn test_init_dispose() {
        let mut plugin = ProgramTreePlugin::new("TestPlugin");
        plugin.init();
        assert!(plugin.is_initialized());
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_plugin_display() {
        let plugin = ProgramTreePlugin::new("TestPlugin");
        let display = format!("{}", plugin);
        assert!(display.contains("TestPlugin"));
        assert!(display.contains("views=0"));
    }
}
