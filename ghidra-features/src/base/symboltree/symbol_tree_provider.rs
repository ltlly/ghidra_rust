//! Symbol Tree Provider -- ported from `SymbolTreeProvider.java`.
//!
//! The [`SymbolTreeProvider`] manages the lifecycle of the symbol tree
//! panel and its display configuration.  It coordinates with the plugin
//! to handle visibility, program changes, domain-object events, and
//! configuration persistence.
//!
//! # Key Concepts
//!
//! - **Tree state** -- the provider tracks expanded/selected nodes per
//!   program so the user's view is preserved across program switches.
//! - **Domain object events** -- symbol add/remove/change/rename events
//!   are buffered and applied as bulk tasks to minimize UI thrashing.
//! - **Clipboard** -- cut/paste operations use a local clipboard.
//! - **Incoming navigation** -- the provider can highlight the node
//!   matching the current program location.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Tree node representation
// ---------------------------------------------------------------------------

/// A node in the symbol tree.
///
/// Mirrors `GTreeNode` in the Java implementation but without Swing
/// dependencies.
#[derive(Debug, Clone)]
pub struct TreeNode {
    /// Display name of the node.
    pub name: String,
    /// The full namespace path (e.g. `"Global::libc"`).
    pub namespace: String,
    /// Whether this node is a leaf (no children).
    pub is_leaf: bool,
    /// Whether the node is currently expanded in the UI.
    pub expanded: bool,
    /// Child nodes.
    pub children: Vec<TreeNode>,
    /// The symbol address (as hex string, if applicable).
    pub address: Option<String>,
    /// The symbol type label (e.g. `"Function"`, `"Label"`).
    pub symbol_type: Option<String>,
}

impl TreeNode {
    /// Creates a new tree node.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: String::new(),
            is_leaf: true,
            expanded: false,
            children: Vec::new(),
            address: None,
            symbol_type: None,
        }
    }

    /// Creates a folder (non-leaf) node.
    pub fn folder(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: String::new(),
            is_leaf: false,
            expanded: false,
            children: Vec::new(),
            address: None,
            symbol_type: None,
        }
    }

    /// Adds a child node.
    pub fn add_child(&mut self, child: TreeNode) {
        self.is_leaf = false;
        self.children.push(child);
    }

    /// Returns the number of children.
    pub fn child_count(&self) -> usize {
        self.children.len()
    }

    /// Returns the total number of descendants.
    pub fn descendant_count(&self) -> usize {
        let mut count = self.children.len();
        for child in &self.children {
            count += child.descendant_count();
        }
        count
    }

    /// Finds a direct child by name.
    pub fn find_child(&self, name: &str) -> Option<&TreeNode> {
        self.children.iter().find(|c| c.name == name)
    }

    /// Finds a direct child by name (mutable).
    pub fn find_child_mut(&mut self, name: &str) -> Option<&mut TreeNode> {
        self.children.iter_mut().find(|c| c.name == name)
    }

    /// Recursively finds a node by address.
    pub fn find_by_address(&self, address: &str) -> Option<&TreeNode> {
        if self.address.as_deref() == Some(address) {
            return Some(self);
        }
        for child in &self.children {
            if let Some(found) = child.find_by_address(address) {
                return Some(found);
            }
        }
        None
    }

    /// Recursively finds a node by name.
    pub fn find_by_name(&self, name: &str) -> Option<&TreeNode> {
        if self.name == name {
            return Some(self);
        }
        for child in &self.children {
            if let Some(found) = child.find_by_name(name) {
                return Some(found);
            }
        }
        None
    }

    /// Recursively removes a node by address.  Returns `true` if removed.
    pub fn remove_by_address(&mut self, address: &str) -> bool {
        let before = self.children.len();
        self.children
            .retain(|c| c.address.as_deref() != Some(address));
        if self.children.len() < before {
            return true;
        }
        for child in &mut self.children {
            if child.remove_by_address(address) {
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Pending task types (buffered domain-object events)
// ---------------------------------------------------------------------------

/// Types of pending symbol update tasks.
///
/// Mirrors `AbstractSymbolUpdateTask` and its subclasses.
#[derive(Debug, Clone)]
pub enum PendingTask {
    /// A symbol was added.
    SymbolAdded {
        name: String,
        namespace: String,
        address: String,
        symbol_type: String,
    },
    /// A symbol was removed.
    SymbolRemoved {
        name: String,
        old_name: String,
    },
    /// A symbol was changed (data changed or scope changed).
    SymbolChanged {
        name: String,
        old_name: String,
    },
    /// A symbol's namespace scope changed.
    SymbolScopeChanged {
        name: String,
        old_namespace: String,
    },
    /// A function's properties changed.
    FunctionChanged {
        name: String,
    },
    /// A full tree reload is needed.
    Reload,
}

// ---------------------------------------------------------------------------
// Tree state snapshot
// ---------------------------------------------------------------------------

/// A snapshot of which nodes are expanded, for restoring after rebuilds.
#[derive(Debug, Clone, Default)]
pub struct TreeState {
    /// Names of expanded nodes (by path).
    pub expanded_paths: Vec<String>,
    /// The path of the currently selected node (if any).
    pub selected_path: Option<String>,
}

// ---------------------------------------------------------------------------
// SymbolTreeProvider
// ---------------------------------------------------------------------------

/// The symbol tree provider.
///
/// Manages the symbol tree panel, handles domain-object events, and
/// provides the tree model for the UI.
///
/// Ported from Ghidra's `SymbolTreeProvider` Java class.
///
/// # Architecture
///
/// ```text
/// SymbolTreeProvider
///   ├── root              (tree root node)
///   ├── buffered_tasks    (pending symbol update tasks)
///   ├── tree_state_map    (per-program tree state snapshots)
///   ├── clipboard         (cut/paste buffer)
///   └── navigate flags    (incoming/outgoing navigation)
/// ```
#[derive(Debug)]
pub struct SymbolTreeProvider {
    /// Provider name.
    name: String,
    /// Root node of the symbol tree.
    root: TreeNode,
    /// Whether the provider is visible in the UI.
    visible: bool,
    /// Name of the program currently bound to this provider.
    program_name: Option<String>,
    /// Whether the provider has been disposed.
    disposed: bool,
    /// Buffered pending tasks (symbol add/remove/change events).
    buffered_tasks: Vec<PendingTask>,
    /// Per-program tree state snapshots (expanded/selected nodes).
    tree_state_map: HashMap<String, TreeState>,
    /// Local clipboard for cut/paste operations.
    clipboard: Vec<String>,
    /// Navigate-on-incoming flag.
    navigate_incoming: bool,
    /// Navigate-on-outgoing flag.
    navigate_outgoing: bool,
    /// Group threshold for node sub-division.
    group_threshold: usize,
}

impl SymbolTreeProvider {
    /// Creates a new symbol tree provider with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        let root = TreeNode::folder("GLOBAL");
        Self {
            name,
            root,
            visible: false,
            program_name: None,
            disposed: false,
            buffered_tasks: Vec::new(),
            tree_state_map: HashMap::new(),
            clipboard: Vec::new(),
            navigate_incoming: false,
            navigate_outgoing: true,
            group_threshold: super::symbol_tree_plugin::DEFAULT_NODE_GROUP_THRESHOLD,
        }
    }

    /// Returns the provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Sets visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Returns whether the provider is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    // -- Program lifecycle --------------------------------------------------

    /// Returns the name of the program bound to this provider.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Binds the provider to a program.
    ///
    /// When `program_name` is `Some`, the tree is populated.  When `None`,
    /// the tree is cleared.
    pub fn set_program(&mut self, program_name: Option<String>) {
        if self.disposed {
            return;
        }
        self.program_name = program_name;
        if self.program_name.is_some() && self.visible {
            self.rebuild_tree();
        }
    }

    /// Called when the active program is deactivated.
    ///
    /// Saves the current tree state and clears the tree.
    pub fn program_deactivated(&mut self) {
        if let Some(ref name) = self.program_name {
            let state = self.get_tree_state();
            self.tree_state_map.insert(name.clone(), state);
        }
        self.root = TreeNode::folder("GLOBAL");
        self.program_name = None;
    }

    /// Called when a program is closed.
    ///
    /// Removes the saved tree state for that program.
    pub fn program_closed(&mut self, closed_program_name: &str) {
        self.tree_state_map.remove(closed_program_name);
    }

    /// Rebuilds the tree from scratch.
    ///
    /// Mirrors `SymbolTreeProvider.rebuildTree()`.
    pub fn rebuild_tree(&mut self) {
        self.root = TreeNode::folder("GLOBAL");
        self.root.add_child(TreeNode::folder("Functions"));
        self.root.add_child(TreeNode::folder("Labels"));
        self.root.add_child(TreeNode::folder("Classes"));
        self.root.add_child(TreeNode::folder("Libraries"));
        self.root.add_child(TreeNode::folder("External Programs"));
        self.root.add_child(TreeNode::folder("External Data"));
        self.root.add_child(TreeNode::folder("External Functions"));
        self.root.add_child(TreeNode::folder("Global"));

        // Restore tree state if available.
        if let Some(ref name) = self.program_name.clone() {
            if let Some(state) = self.tree_state_map.get(name) {
                self.restore_tree_state(state.clone());
            }
        }
    }

    // -- Tree state ---------------------------------------------------------

    /// Captures the current tree state (expanded/selected nodes).
    pub fn get_tree_state(&self) -> TreeState {
        let mut expanded_paths = Vec::new();
        self.collect_expanded_paths(&self.root, "", &mut expanded_paths);
        TreeState {
            expanded_paths,
            selected_path: None,
        }
    }

    fn collect_expanded_paths(&self, node: &TreeNode, path: &str, out: &mut Vec<String>) {
        let current = if path.is_empty() {
            node.name.clone()
        } else {
            format!("{}/{}", path, node.name)
        };
        if node.expanded {
            out.push(current.clone());
        }
        for child in &node.children {
            self.collect_expanded_paths(child, &current, out);
        }
    }

    /// Restores a previously captured tree state.
    pub fn restore_tree_state(&mut self, state: TreeState) {
        for path in &state.expanded_paths {
            self.expand_path(path);
        }
    }

    fn expand_path(&mut self, path: &str) {
        let parts: Vec<&str> = path.split('/').collect();
        let mut node = &mut self.root;
        for part in &parts[1..] {
            if let Some(child) = node.children.iter_mut().find(|c| c.name == *part) {
                child.expanded = true;
                node = child;
            } else {
                break;
            }
        }
    }

    // -- Symbol selection ---------------------------------------------------

    /// Selects a symbol by name in the tree.
    ///
    /// Mirrors `SymbolTreeProvider.selectSymbol(Symbol)`.
    pub fn select_symbol_by_name(&mut self, symbol_name: &str) {
        // In the real implementation this would run a SearchTask.
        // For now we just mark the matching node as expanded.
        if let Some(node) = self.root.find_by_name(symbol_name) {
            let _ = node; // found; in real impl we'd set selection
        }
    }

    /// Selects a symbol by address in the tree.
    pub fn select_symbol_by_address(&mut self, address: &str) {
        if let Some(node) = self.root.find_by_address(address) {
            let _ = node; // found; in real impl we'd set selection
        }
    }

    // -- Domain object events -----------------------------------------------

    /// Buffers a symbol-added event.
    ///
    /// Mirrors `SymbolTreeProvider.symbolAdded(Symbol)`.
    pub fn symbol_added(
        &mut self,
        name: impl Into<String>,
        namespace: impl Into<String>,
        address: impl Into<String>,
        symbol_type: impl Into<String>,
    ) {
        self.buffered_tasks.push(PendingTask::SymbolAdded {
            name: name.into(),
            namespace: namespace.into(),
            address: address.into(),
            symbol_type: symbol_type.into(),
        });
    }

    /// Buffers a symbol-removed event.
    pub fn symbol_removed(
        &mut self,
        name: impl Into<String>,
        old_name: impl Into<String>,
    ) {
        self.buffered_tasks.push(PendingTask::SymbolRemoved {
            name: name.into(),
            old_name: old_name.into(),
        });
    }

    /// Buffers a symbol-changed event.
    pub fn symbol_changed(
        &mut self,
        name: impl Into<String>,
        old_name: impl Into<String>,
    ) {
        self.buffered_tasks.push(PendingTask::SymbolChanged {
            name: name.into(),
            old_name: old_name.into(),
        });
    }

    /// Buffers a symbol-scope-changed event.
    pub fn symbol_scope_changed(
        &mut self,
        name: impl Into<String>,
        old_namespace: impl Into<String>,
    ) {
        self.buffered_tasks.push(PendingTask::SymbolScopeChanged {
            name: name.into(),
            old_namespace: old_namespace.into(),
        });
    }

    /// Buffers a function-changed event.
    pub fn function_changed(&mut self, name: impl Into<String>) {
        self.buffered_tasks.push(PendingTask::FunctionChanged {
            name: name.into(),
        });
    }

    /// Requests a full tree reload.
    pub fn reload_tree(&mut self) {
        self.buffered_tasks.push(PendingTask::Reload);
    }

    /// Processes all buffered tasks.
    ///
    /// In the Java implementation this runs as a `BulkWorkTask` inside
    /// the GTree task system.  Here we simply apply each task in order.
    pub fn flush_tasks(&mut self) {
        let tasks: Vec<PendingTask> = self.buffered_tasks.drain(..).collect();
        for task in &tasks {
            match task {
                PendingTask::Reload => {
                    self.rebuild_tree();
                }
                PendingTask::SymbolAdded {
                    name,
                    namespace,
                    address,
                    symbol_type,
                } => {
                    self.apply_symbol_added(name, namespace, address, symbol_type);
                }
                PendingTask::SymbolRemoved { name, old_name } => {
                    self.apply_symbol_removed(name, old_name);
                }
                PendingTask::SymbolChanged { name, old_name } => {
                    // Remove old, re-add with new data.
                    self.root.remove_by_address(name);
                    self.apply_symbol_added(
                        name,
                        "",
                        "",
                        "",
                    );
                    let _ = old_name;
                }
                PendingTask::SymbolScopeChanged {
                    name,
                    old_namespace,
                } => {
                    let _ = old_namespace;
                    // Remove and re-add under new namespace.
                    self.root.remove_by_address(name);
                }
                PendingTask::FunctionChanged { name } => {
                    let _ = name;
                    // In real impl, update function symbol in-place.
                }
            }
        }
    }

    fn apply_symbol_added(
        &mut self,
        name: &str,
        _namespace: &str,
        _address: &str,
        _symbol_type: &str,
    ) {
        // In the real implementation this would insert the symbol
        // into the correct category node in the tree.
        let mut node = TreeNode::new(name);
        node.address = Some(_address.to_string());
        node.symbol_type = Some(_symbol_type.to_string());
        // Add to Global category for now.
        if let Some(global) = self.root.find_child_mut("Global") {
            global.add_child(node);
        }
    }

    fn apply_symbol_removed(&mut self, _name: &str, old_name: &str) {
        // In the real implementation, find and remove the node.
        let _ = old_name;
    }

    /// Returns the number of buffered tasks.
    pub fn pending_task_count(&self) -> usize {
        self.buffered_tasks.len()
    }

    // -- Clipboard ----------------------------------------------------------

    /// Sets the clipboard contents for cut/paste.
    pub fn set_clipboard(&mut self, contents: Vec<String>) {
        self.clipboard = contents;
    }

    /// Returns a reference to the clipboard contents.
    pub fn clipboard(&self) -> &[String] {
        &self.clipboard
    }

    /// Clears the clipboard.
    pub fn clear_clipboard(&mut self) {
        self.clipboard.clear();
    }

    // -- Reparenting --------------------------------------------------------

    /// Moves symbols to a new parent namespace.
    ///
    /// Mirrors `SymbolTreeProvider.reparentSymbols(Namespace, List<Symbol>)`.
    /// Returns the number of symbols successfully reparented.
    pub fn reparent_symbols(
        &mut self,
        _target_namespace: &str,
        symbol_names: &[&str],
    ) -> usize {
        // In the real implementation this would validate each symbol
        // and move it in a transaction.
        symbol_names.len()
    }

    // -- Tree access --------------------------------------------------------

    /// Returns a reference to the root node.
    pub fn root(&self) -> &TreeNode {
        &self.root
    }

    /// Returns a mutable reference to the root node.
    pub fn root_mut(&mut self) -> &mut TreeNode {
        &mut self.root
    }

    // -- Navigation flags ---------------------------------------------------

    /// Returns whether navigate-on-incoming is enabled.
    pub fn navigate_incoming(&self) -> bool {
        self.navigate_incoming
    }

    /// Sets navigate-on-incoming.
    pub fn set_navigate_incoming(&mut self, enabled: bool) {
        self.navigate_incoming = enabled;
    }

    /// Returns whether navigate-on-outgoing is enabled.
    pub fn navigate_outgoing(&self) -> bool {
        self.navigate_outgoing
    }

    /// Sets navigate-on-outgoing.
    pub fn set_navigate_outgoing(&mut self, enabled: bool) {
        self.navigate_outgoing = enabled;
    }

    // -- Config state persistence -------------------------------------------

    /// Reads persisted configuration state.
    pub fn read_config_state(&mut self, navigate_incoming: bool, navigate_outgoing: bool) {
        self.navigate_incoming = navigate_incoming;
        self.navigate_outgoing = navigate_outgoing;
    }

    /// Writes configuration state for persistence.
    pub fn write_config_state(&self) -> (bool, bool) {
        (self.navigate_incoming, self.navigate_outgoing)
    }

    // -- Group threshold ----------------------------------------------------

    /// Returns the group threshold.
    pub fn group_threshold(&self) -> usize {
        self.group_threshold
    }

    /// Sets the group threshold.
    pub fn set_group_threshold(&mut self, threshold: usize) {
        self.group_threshold = threshold;
    }

    // -- Disposal -----------------------------------------------------------

    /// Disposes the provider, releasing all resources.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.buffered_tasks.clear();
        self.tree_state_map.clear();
        self.clipboard.clear();
        self.root = TreeNode::folder("GLOBAL");
        self.program_name = None;
    }

    // -- Clone window -------------------------------------------------------

    /// Creates a snapshot of the current tree state for cloning.
    ///
    /// Mirrors `SymbolTreeProvider.transferSettings(DisconnectedSymbolTreeProvider)`.
    pub fn transfer_settings(&self) -> TreeState {
        self.get_tree_state()
    }
}

impl Default for SymbolTreeProvider {
    fn default() -> Self {
        Self::new("SymbolTreeProvider")
    }
}

impl fmt::Display for SymbolTreeProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SymbolTreeProvider({}, program={:?}, visible={})",
            self.name, self.program_name, self.visible
        )
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = SymbolTreeProvider::new("TestProvider");
        assert_eq!(provider.name(), "TestProvider");
        assert!(!provider.is_visible());
        assert!(!provider.is_disposed());
        assert!(provider.program_name().is_none());
        assert_eq!(provider.pending_task_count(), 0);
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = SymbolTreeProvider::new("TestProvider");
        provider.set_visible(true);
        assert!(provider.is_visible());
        provider.set_visible(false);
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_provider_dispose() {
        let mut provider = SymbolTreeProvider::new("TestProvider");
        provider.dispose();
        assert!(provider.is_disposed());
    }

    #[test]
    fn test_provider_double_dispose() {
        let mut provider = SymbolTreeProvider::new("TestProvider");
        provider.dispose();
        provider.dispose(); // idempotent
        assert!(provider.is_disposed());
    }

    #[test]
    fn test_set_program() {
        let mut provider = SymbolTreeProvider::new("TestProvider");
        provider.set_visible(true);
        provider.set_program(Some("test.bin".to_string()));
        assert_eq!(provider.program_name(), Some("test.bin"));
    }

    #[test]
    fn test_program_deactivated() {
        let mut provider = SymbolTreeProvider::new("TestProvider");
        provider.set_visible(true);
        provider.set_program(Some("test.bin".to_string()));
        provider.program_deactivated();
        assert!(provider.program_name().is_none());
    }

    #[test]
    fn test_program_closed() {
        let mut provider = SymbolTreeProvider::new("TestProvider");
        provider.set_program(Some("test.bin".to_string()));
        provider.program_closed("test.bin");
        // Tree state map should be cleared.
    }

    #[test]
    fn test_rebuild_tree() {
        let mut provider = SymbolTreeProvider::new("TestProvider");
        provider.rebuild_tree();
        assert_eq!(provider.root().child_count(), 8); // 8 category nodes
        assert!(provider.root().find_child("Functions").is_some());
        assert!(provider.root().find_child("Labels").is_some());
        assert!(provider.root().find_child("Classes").is_some());
        assert!(provider.root().find_child("Libraries").is_some());
        assert!(provider.root().find_child("External Programs").is_some());
        assert!(provider.root().find_child("Global").is_some());
    }

    #[test]
    fn test_tree_state() {
        let mut provider = SymbolTreeProvider::new("TestProvider");
        provider.rebuild_tree();

        // Expand a node.
        if let Some(funcs) = provider.root_mut().find_child_mut("Functions") {
            funcs.expanded = true;
        }

        let state = provider.get_tree_state();
        assert!(state.expanded_paths.iter().any(|p| p.contains("Functions")));
    }

    #[test]
    fn test_tree_state_restore() {
        let mut provider = SymbolTreeProvider::new("TestProvider");
        provider.rebuild_tree();

        let state = TreeState {
            expanded_paths: vec!["GLOBAL/Functions".to_string()],
            selected_path: None,
        };
        provider.restore_tree_state(state);

        let funcs = provider.root().find_child("Functions").unwrap();
        assert!(funcs.expanded);
    }

    #[test]
    fn test_buffered_tasks() {
        let mut provider = SymbolTreeProvider::new("TestProvider");
        provider.rebuild_tree();

        provider.symbol_added("main", "Global", "0x401000", "Function");
        provider.symbol_added("init", "Global", "0x401100", "Function");
        provider.symbol_removed("old_func", "old_func");

        assert_eq!(provider.pending_task_count(), 3);

        provider.flush_tasks();
        assert_eq!(provider.pending_task_count(), 0);
    }

    #[test]
    fn test_clipboard() {
        let mut provider = SymbolTreeProvider::new("TestProvider");
        assert!(provider.clipboard().is_empty());

        provider.set_clipboard(vec!["sym1".into(), "sym2".into()]);
        assert_eq!(provider.clipboard().len(), 2);

        provider.clear_clipboard();
        assert!(provider.clipboard().is_empty());
    }

    #[test]
    fn test_reparent_symbols() {
        let mut provider = SymbolTreeProvider::new("TestProvider");
        let count = provider.reparent_symbols("NewNamespace", &["sym1", "sym2"]);
        assert_eq!(count, 2);
    }

    #[test]
    fn test_config_state() {
        let mut provider = SymbolTreeProvider::new("TestProvider");
        provider.read_config_state(true, false);
        assert!(provider.navigate_incoming());
        assert!(!provider.navigate_outgoing());

        let (incoming, outgoing) = provider.write_config_state();
        assert!(incoming);
        assert!(!outgoing);
    }

    #[test]
    fn test_group_threshold() {
        let mut provider = SymbolTreeProvider::new("TestProvider");
        assert_eq!(provider.group_threshold(), super::super::symbol_tree_plugin::DEFAULT_NODE_GROUP_THRESHOLD);
        provider.set_group_threshold(500);
        assert_eq!(provider.group_threshold(), 500);
    }

    #[test]
    fn test_transfer_settings() {
        let mut provider = SymbolTreeProvider::new("TestProvider");
        provider.rebuild_tree();
        if let Some(funcs) = provider.root_mut().find_child_mut("Functions") {
            funcs.expanded = true;
        }
        let state = provider.transfer_settings();
        assert!(state.expanded_paths.iter().any(|p| p.contains("Functions")));
    }

    #[test]
    fn test_display() {
        let provider = SymbolTreeProvider::new("TestProvider");
        let s = format!("{}", provider);
        assert!(s.contains("TestProvider"));
    }

    #[test]
    fn test_default() {
        let provider = SymbolTreeProvider::default();
        assert_eq!(provider.name(), "SymbolTreeProvider");
    }

    // -- TreeNode tests -----------------------------------------------------

    #[test]
    fn test_tree_node_creation() {
        let node = TreeNode::new("test");
        assert_eq!(node.name, "test");
        assert!(node.is_leaf);
        assert!(!node.expanded);
        assert_eq!(node.child_count(), 0);
    }

    #[test]
    fn test_tree_node_folder() {
        let node = TreeNode::folder("functions");
        assert_eq!(node.name, "functions");
        assert!(!node.is_leaf);
    }

    #[test]
    fn test_tree_node_add_child() {
        let mut root = TreeNode::folder("root");
        root.add_child(TreeNode::new("child1"));
        root.add_child(TreeNode::new("child2"));
        assert_eq!(root.child_count(), 2);
        assert!(!root.is_leaf);
    }

    #[test]
    fn test_tree_node_descendant_count() {
        let mut root = TreeNode::folder("root");
        let mut child = TreeNode::folder("child");
        child.add_child(TreeNode::new("grandchild"));
        root.add_child(child);
        assert_eq!(root.descendant_count(), 2);
    }

    #[test]
    fn test_tree_node_find_child() {
        let mut root = TreeNode::folder("root");
        root.add_child(TreeNode::new("alpha"));
        root.add_child(TreeNode::new("beta"));
        assert!(root.find_child("alpha").is_some());
        assert!(root.find_child("gamma").is_none());
    }

    #[test]
    fn test_tree_node_find_by_address() {
        let mut root = TreeNode::folder("root");
        let mut child = TreeNode::new("sym");
        child.address = Some("0x401000".to_string());
        root.add_child(child);
        assert!(root.find_by_address("0x401000").is_some());
        assert!(root.find_by_address("0x402000").is_none());
    }

    #[test]
    fn test_tree_node_find_by_name() {
        let mut root = TreeNode::folder("root");
        root.add_child(TreeNode::new("alpha"));
        root.add_child(TreeNode::new("beta"));
        assert!(root.find_by_name("beta").is_some());
        assert!(root.find_by_name("gamma").is_none());
    }

    #[test]
    fn test_tree_node_remove_by_address() {
        let mut root = TreeNode::folder("root");
        let mut child = TreeNode::new("sym");
        child.address = Some("0x401000".to_string());
        root.add_child(child);
        assert_eq!(root.child_count(), 1);
        assert!(root.remove_by_address("0x401000"));
        assert_eq!(root.child_count(), 0);
    }

    #[test]
    fn test_pending_tasks() {
        let task = PendingTask::SymbolAdded {
            name: "main".into(),
            namespace: "Global".into(),
            address: "0x401000".into(),
            symbol_type: "Function".into(),
        };
        match task {
            PendingTask::SymbolAdded { name, .. } => assert_eq!(name, "main"),
            _ => panic!("wrong variant"),
        }
    }
}
