//! Symbol tree plugin for browsing program symbols in a tree hierarchy.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.symboltree` package.
//!
//! Displays symbols from the program in a tree organized by namespace.
//! Supports symbol operations like rename, delete, move, create
//! namespaces/classes, and external library management.
//!
//! # Key Types
//!
//! - [`SymbolTreePlugin`] -- Plugin providing the symbol tree view
//! - [`SymbolCategory`] -- Category nodes in the symbol tree
//! - [`SymbolNode`] -- A node representing a single symbol
//! - [`SymbolTreeService`] -- Service trait for symbol tree operations

/// Symbol tree node types (function, code, class, library, etc.).
///
/// Ported from Ghidra's `ghidra.app.plugin.core.symboltree.nodes` package.
pub mod nodes;

/// Symbol tree user actions (delete, rename, create, cut/paste, etc.).
///
/// Ported from Ghidra's `ghidra.app.plugin.core.symboltree.actions` package.
pub mod actions;

/// Symbol tree operations with undo/redo and clipboard support.
///
/// Ported from action classes in `ghidra.app.plugin.core.symboltree.actions`.
pub mod operations;

use std::collections::BTreeMap;

/// Options category name.
pub const OPTIONS_CATEGORY: &str = "Symbol Tree";

/// Default group threshold for creating sub-nodes.
pub const DEFAULT_GROUP_THRESHOLD: usize = 200;

// ---------------------------------------------------------------------------
// Symbol category
// ---------------------------------------------------------------------------

/// Top-level categories in the symbol tree.
///
/// Ported from `ghidra.app.plugin.core.symboltree.SymbolCategory`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SymbolCategory {
    /// Function symbols.
    Functions,
    /// Label symbols.
    Labels,
    /// Class/namespace symbols.
    Classes,
    /// Library symbols.
    Libraries,
    /// External program symbols.
    ExternalPrograms,
    /// Global namespace.
    Global,
}

impl SymbolCategory {
    /// Display name for this category.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Functions => "Functions",
            Self::Labels => "Labels",
            Self::Classes => "Classes",
            Self::Libraries => "Libraries",
            Self::ExternalPrograms => "External Programs",
            Self::Global => "Global",
        }
    }

    /// All categories in display order.
    pub fn all() -> &'static [SymbolCategory] {
        &[
            Self::Functions,
            Self::Labels,
            Self::Classes,
            Self::Libraries,
            Self::ExternalPrograms,
            Self::Global,
        ]
    }
}

// ---------------------------------------------------------------------------
// Symbol type
// ---------------------------------------------------------------------------

/// Types of symbols in the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolType {
    /// Function symbol.
    Function,
    /// Label (code address).
    Label,
    /// Class/namespace.
    Class,
    /// Library.
    Library,
    /// External program.
    ExternalProgram,
    /// External location.
    ExternalLocation,
    /// Global namespace.
    Global,
}

impl SymbolType {
    /// Whether this symbol type represents a namespace.
    pub fn is_namespace(&self) -> bool {
        matches!(self, Self::Class | Self::Library | Self::ExternalProgram | Self::Global)
    }
}

// ---------------------------------------------------------------------------
// Symbol node
// ---------------------------------------------------------------------------

/// A node in the symbol tree, representing a single symbol.
///
/// Ported from `ghidra.app.plugin.core.symboltree.SymbolNode`.
#[derive(Debug, Clone)]
pub struct SymbolNode {
    /// The symbol name.
    pub name: String,
    /// The symbol type.
    pub symbol_type: SymbolType,
    /// The address of the symbol (0 for namespace types).
    pub address: u64,
    /// The namespace path.
    pub namespace: String,
    /// Child nodes (for namespace types).
    pub children: Vec<SymbolNode>,
    /// Whether this node has been expanded.
    pub expanded: bool,
}

impl SymbolNode {
    /// Create a new symbol node.
    pub fn new(
        name: impl Into<String>,
        symbol_type: SymbolType,
        address: u64,
    ) -> Self {
        Self {
            name: name.into(),
            symbol_type,
            address,
            namespace: String::new(),
            children: Vec::new(),
            expanded: false,
        }
    }

    /// Fully qualified name (namespace + name).
    pub fn qualified_name(&self) -> String {
        if self.namespace.is_empty() {
            self.name.clone()
        } else {
            format!("{}::{}", self.namespace, self.name)
        }
    }

    /// Whether this node has children.
    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }

    /// Add a child node.
    pub fn add_child(&mut self, child: SymbolNode) {
        self.children.push(child);
    }

    /// Number of descendant nodes.
    pub fn descendant_count(&self) -> usize {
        let mut count = self.children.len();
        for child in &self.children {
            count += child.descendant_count();
        }
        count
    }
}

// ---------------------------------------------------------------------------
// Symbol tree service
// ---------------------------------------------------------------------------

/// Service trait for symbol tree operations.
///
/// Ported from `ghidra.app.plugin.core.symboltree.SymbolTreeService`.
pub trait SymbolTreeService: Send + Sync {
    /// Navigate to a symbol in the listing.
    fn go_to_symbol(&self, address: u64);

    /// Get the root symbol nodes.
    fn get_root_nodes(&self) -> Vec<SymbolNode>;
}

// ---------------------------------------------------------------------------
// Symbol tree plugin
// ---------------------------------------------------------------------------

/// Plugin providing the symbol tree view.
///
/// Ported from `ghidra.app.plugin.core.symboltree.SymbolTreePlugin`.
#[derive(Debug)]
pub struct SymbolTreePlugin {
    /// Root nodes organized by category.
    roots: BTreeMap<SymbolCategory, SymbolNode>,
    /// Group threshold before splitting into subgroups.
    group_threshold: usize,
    /// Whether the tree is visible.
    visible: bool,
}

impl SymbolTreePlugin {
    /// Create a new symbol tree plugin.
    pub fn new() -> Self {
        let mut roots = BTreeMap::new();
        for cat in SymbolCategory::all() {
            roots.insert(
                *cat,
                SymbolNode::new(cat.display_name(), SymbolType::Global, 0),
            );
        }
        Self {
            roots,
            group_threshold: DEFAULT_GROUP_THRESHOLD,
            visible: false,
        }
    }

    /// Get the root node for a category.
    pub fn root(&self, category: SymbolCategory) -> Option<&SymbolNode> {
        self.roots.get(&category)
    }

    /// Get a mutable reference to a root node.
    pub fn root_mut(&mut self, category: SymbolCategory) -> Option<&mut SymbolNode> {
        self.roots.get_mut(&category)
    }

    /// Add a symbol to the tree.
    pub fn add_symbol(&mut self, category: SymbolCategory, node: SymbolNode) {
        if let Some(root) = self.roots.get_mut(&category) {
            root.add_child(node);
        }
    }

    /// Get the group threshold.
    pub fn group_threshold(&self) -> usize {
        self.group_threshold
    }

    /// Set the group threshold.
    pub fn set_group_threshold(&mut self, threshold: usize) {
        self.group_threshold = threshold;
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Whether visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Get total symbol count across all categories.
    pub fn total_symbol_count(&self) -> usize {
        self.roots.values().map(|r| r.descendant_count()).sum()
    }
}

impl Default for SymbolTreePlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Symbol tree drag-drop support
// ---------------------------------------------------------------------------

/// Drag-and-drop operation for symbols in the tree.
///
/// Ported from `ghidra.app.plugin.core.symboltree.SymbolGTreeDragNDropHandler`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolDragDropAction {
    /// Move the symbol to a new location.
    Move,
    /// Copy the symbol to a new location.
    Copy,
    /// Link the symbol (create a reference).
    Link,
}

/// Represents a drag-drop operation in progress.
#[derive(Debug, Clone)]
pub struct SymbolDragDropOperation {
    /// The source symbol node names being dragged.
    pub sources: Vec<String>,
    /// The target namespace path.
    pub target_namespace: String,
    /// The action being performed.
    pub action: SymbolDragDropAction,
}

impl SymbolDragDropOperation {
    /// Create a new drag-drop operation.
    pub fn new(
        sources: Vec<String>,
        target_namespace: impl Into<String>,
        action: SymbolDragDropAction,
    ) -> Self {
        Self {
            sources,
            target_namespace: target_namespace.into(),
            action,
        }
    }

    /// Number of symbols being moved/copied.
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }
}

// ---------------------------------------------------------------------------
// Symbol tree search
// ---------------------------------------------------------------------------

/// Search criteria for filtering symbols in the tree.
///
/// Ported from search functionality in `SymbolTreeProvider`.
#[derive(Debug, Clone)]
pub struct SymbolSearchCriteria {
    /// Text to match against symbol names (substring match).
    pub name_pattern: Option<String>,
    /// Filter by symbol type.
    pub symbol_type: Option<SymbolType>,
    /// Filter by category.
    pub category: Option<SymbolCategory>,
    /// Filter by namespace path prefix.
    pub namespace_prefix: Option<String>,
    /// Whether the search is case-sensitive.
    pub case_sensitive: bool,
    /// Maximum number of results to return.
    pub max_results: Option<usize>,
}

impl Default for SymbolSearchCriteria {
    fn default() -> Self {
        Self {
            name_pattern: None,
            symbol_type: None,
            category: None,
            namespace_prefix: None,
            case_sensitive: false,
            max_results: None,
        }
    }
}

impl SymbolSearchCriteria {
    /// Check whether a symbol node matches this search criteria.
    pub fn matches(&self, node: &SymbolNode) -> bool {
        if let Some(ref pattern) = self.name_pattern {
            let name = if self.case_sensitive {
                node.name.clone()
            } else {
                node.name.to_lowercase()
            };
            let pat = if self.case_sensitive {
                pattern.clone()
            } else {
                pattern.to_lowercase()
            };
            if !name.contains(&pat) {
                return false;
            }
        }

        if let Some(ref st) = self.symbol_type {
            if node.symbol_type != *st {
                return false;
            }
        }

        if let Some(ref prefix) = self.namespace_prefix {
            if !node.namespace.starts_with(prefix.as_str()) {
                return false;
            }
        }

        true
    }
}

/// Search results from a symbol tree search.
#[derive(Debug, Clone)]
pub struct SymbolSearchResults {
    /// Matching symbol nodes.
    pub results: Vec<SymbolSearchResult>,
    /// Whether the search was truncated (too many matches).
    pub truncated: bool,
}

/// A single search result.
#[derive(Debug, Clone)]
pub struct SymbolSearchResult {
    /// The matched symbol node.
    pub node: SymbolNode,
    /// The full path from root to this node.
    pub path: String,
}

// ---------------------------------------------------------------------------
// Symbol tree with search
// ---------------------------------------------------------------------------

impl SymbolTreePlugin {
    /// Search for symbols matching the given criteria.
    pub fn search(&self, criteria: &SymbolSearchCriteria) -> SymbolSearchResults {
        let mut results = Vec::new();
        let max = criteria.max_results.unwrap_or(usize::MAX);

        for (_, root) in &self.roots {
            self.search_node(root, criteria, &root.name, &mut results, max);
            if results.len() >= max {
                break;
            }
        }

        let truncated = results.len() >= max;
        SymbolSearchResults { results, truncated }
    }

    fn search_node(
        &self,
        node: &SymbolNode,
        criteria: &SymbolSearchCriteria,
        path: &str,
        results: &mut Vec<SymbolSearchResult>,
        max: usize,
    ) {
        if results.len() >= max {
            return;
        }

        if criteria.matches(node) {
            results.push(SymbolSearchResult {
                node: node.clone(),
                path: path.to_string(),
            });
        }

        for child in &node.children {
            let child_path = format!("{}::{}", path, child.name);
            self.search_node(child, criteria, &child_path, results, max);
        }
    }

    /// Remove a symbol from the tree by address.
    pub fn remove_symbol(&mut self, address: u64) -> bool {
        for root in self.roots.values_mut() {
            if Self::remove_from_node(root, address) {
                return true;
            }
        }
        false
    }

    fn remove_from_node(node: &mut SymbolNode, address: u64) -> bool {
        let before = node.children.len();
        node.children.retain(|c| c.address != address);
        if node.children.len() < before {
            return true;
        }
        for child in &mut node.children {
            if Self::remove_from_node(child, address) {
                return true;
            }
        }
        false
    }

    /// Get a flat list of all symbols across all categories.
    pub fn all_symbols(&self) -> Vec<&SymbolNode> {
        let mut result = Vec::new();
        for root in self.roots.values() {
            Self::collect_symbols(root, &mut result);
        }
        result
    }

    fn collect_symbols<'a>(node: &'a SymbolNode, result: &mut Vec<&'a SymbolNode>) {
        for child in &node.children {
            result.push(child);
            Self::collect_symbols(child, result);
        }
    }

    /// Execute a drag-drop operation.
    pub fn execute_drag_drop(&mut self, op: &SymbolDragDropOperation) -> Result<(), String> {
        // In the real implementation, this would move symbols between namespaces.
        // Here we validate the operation.
        if op.sources.is_empty() {
            return Err("No source symbols specified".into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// External location management
// ---------------------------------------------------------------------------

/// An external location representing a symbol defined in an external library.
///
/// Ported from `ghidra.app.plugin.core.symboltree.EditExternalLocationDialog`.
#[derive(Debug, Clone)]
pub struct ExternalLocation {
    /// The label/name of the external symbol.
    pub label: String,
    /// The namespace path.
    pub namespace: String,
    /// The external library name.
    pub library: String,
    /// The original data type name (if known).
    pub original_data_type: Option<String>,
    /// The external address (if known).
    pub external_address: Option<String>,
}

impl ExternalLocation {
    /// Create a new external location.
    pub fn new(
        label: impl Into<String>,
        namespace: impl Into<String>,
        library: impl Into<String>,
    ) -> Self {
        Self {
            label: label.into(),
            namespace: namespace.into(),
            library: library.into(),
            original_data_type: None,
            external_address: None,
        }
    }

    /// The fully qualified name.
    pub fn qualified_name(&self) -> String {
        if self.namespace.is_empty() {
            format!("{}::{}", self.library, self.label)
        } else {
            format!("{}::{}::{}", self.library, self.namespace, self.label)
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_category_display() {
        assert_eq!(SymbolCategory::Functions.display_name(), "Functions");
        assert_eq!(SymbolCategory::all().len(), 6);
    }

    #[test]
    fn test_symbol_type_is_namespace() {
        assert!(SymbolType::Class.is_namespace());
        assert!(SymbolType::Library.is_namespace());
        assert!(!SymbolType::Function.is_namespace());
        assert!(!SymbolType::Label.is_namespace());
    }

    #[test]
    fn test_symbol_node_creation() {
        let node = SymbolNode::new("myFunc", SymbolType::Function, 0x400000);
        assert_eq!(node.name, "myFunc");
        assert_eq!(node.address, 0x400000);
        assert!(!node.has_children());
    }

    #[test]
    fn test_symbol_node_qualified_name() {
        let mut node = SymbolNode::new("foo", SymbolType::Function, 0x100);
        assert_eq!(node.qualified_name(), "foo");

        node.namespace = "MyClass".to_string();
        assert_eq!(node.qualified_name(), "MyClass::foo");
    }

    #[test]
    fn test_symbol_node_children() {
        let mut root = SymbolNode::new("root", SymbolType::Class, 0);
        root.add_child(SymbolNode::new("child1", SymbolType::Function, 0x100));
        root.add_child(SymbolNode::new("child2", SymbolType::Function, 0x200));
        assert!(root.has_children());
        assert_eq!(root.descendant_count(), 2);
    }

    #[test]
    fn test_symbol_node_nested_count() {
        let mut root = SymbolNode::new("root", SymbolType::Class, 0);
        let mut child = SymbolNode::new("child", SymbolType::Class, 0);
        child.add_child(SymbolNode::new("grandchild", SymbolType::Function, 0x300));
        root.add_child(child);
        // child (1) + grandchild (1) = 2
        assert_eq!(root.descendant_count(), 2);
    }

    #[test]
    fn test_symbol_tree_plugin() {
        let mut plugin = SymbolTreePlugin::new();
        assert!(!plugin.is_visible());
        assert_eq!(plugin.group_threshold(), DEFAULT_GROUP_THRESHOLD);

        plugin.set_visible(true);
        assert!(plugin.is_visible());

        // Root nodes should exist for all categories
        assert!(plugin.root(SymbolCategory::Functions).is_some());
        assert!(plugin.root(SymbolCategory::Labels).is_some());
    }

    #[test]
    fn test_symbol_tree_plugin_add_symbol() {
        let mut plugin = SymbolTreePlugin::new();
        let node = SymbolNode::new("main", SymbolType::Function, 0x400000);
        plugin.add_symbol(SymbolCategory::Functions, node);
        assert_eq!(plugin.total_symbol_count(), 1);
    }

    #[test]
    fn test_symbol_tree_plugin_group_threshold() {
        let mut plugin = SymbolTreePlugin::new();
        plugin.set_group_threshold(500);
        assert_eq!(plugin.group_threshold(), 500);
    }

    #[test]
    fn test_symbol_drag_drop_operation() {
        let op = SymbolDragDropOperation::new(
            vec!["main".into(), "init".into()],
            "MyNamespace",
            SymbolDragDropAction::Move,
        );
        assert_eq!(op.source_count(), 2);
        assert_eq!(op.target_namespace, "MyNamespace");
        assert_eq!(op.action, SymbolDragDropAction::Move);
    }

    #[test]
    fn test_symbol_search_criteria() {
        let criteria = SymbolSearchCriteria {
            name_pattern: Some("main".into()),
            case_sensitive: true,
            ..Default::default()
        };

        let node = SymbolNode::new("main", SymbolType::Function, 0x400000);
        assert!(criteria.matches(&node));

        let other = SymbolNode::new("init", SymbolType::Function, 0x401000);
        assert!(!criteria.matches(&other));
    }

    #[test]
    fn test_symbol_search_case_insensitive() {
        let criteria = SymbolSearchCriteria {
            name_pattern: Some("MAIN".into()),
            case_sensitive: false,
            ..Default::default()
        };
        let node = SymbolNode::new("main", SymbolType::Function, 0x400000);
        assert!(criteria.matches(&node));
    }

    #[test]
    fn test_symbol_search_by_type() {
        let criteria = SymbolSearchCriteria {
            symbol_type: Some(SymbolType::Function),
            ..Default::default()
        };
        let func = SymbolNode::new("foo", SymbolType::Function, 0x100);
        let label = SymbolNode::new("bar", SymbolType::Label, 0x200);
        assert!(criteria.matches(&func));
        assert!(!criteria.matches(&label));
    }

    #[test]
    fn test_symbol_search_by_namespace() {
        let criteria = SymbolSearchCriteria {
            namespace_prefix: Some("MyClass".into()),
            ..Default::default()
        };
        let mut node = SymbolNode::new("method", SymbolType::Function, 0x100);
        node.namespace = "MyClass::Inner".into();
        assert!(criteria.matches(&node));

        node.namespace = "OtherClass".into();
        assert!(!criteria.matches(&node));
    }

    #[test]
    fn test_symbol_tree_search() {
        let mut plugin = SymbolTreePlugin::new();
        let n1 = SymbolNode::new("main", SymbolType::Function, 0x400000);
        let n2 = SymbolNode::new("init", SymbolType::Function, 0x401000);
        let n3 = SymbolNode::new("main_loop", SymbolType::Function, 0x402000);
        plugin.add_symbol(SymbolCategory::Functions, n1);
        plugin.add_symbol(SymbolCategory::Functions, n2);
        plugin.add_symbol(SymbolCategory::Functions, n3);

        let criteria = SymbolSearchCriteria {
            name_pattern: Some("main".into()),
            ..Default::default()
        };
        let results = plugin.search(&criteria);
        assert_eq!(results.results.len(), 2);
        assert!(!results.truncated);
    }

    #[test]
    fn test_symbol_tree_search_truncated() {
        let mut plugin = SymbolTreePlugin::new();
        for i in 0..10 {
            let node = SymbolNode::new(format!("func_{}", i), SymbolType::Function, i * 0x100);
            plugin.add_symbol(SymbolCategory::Functions, node);
        }

        let criteria = SymbolSearchCriteria {
            name_pattern: Some("func".into()),
            max_results: Some(3),
            ..Default::default()
        };
        let results = plugin.search(&criteria);
        assert!(results.truncated);
        assert_eq!(results.results.len(), 3);
    }

    #[test]
    fn test_symbol_tree_remove_symbol() {
        let mut plugin = SymbolTreePlugin::new();
        let node = SymbolNode::new("main", SymbolType::Function, 0x400000);
        plugin.add_symbol(SymbolCategory::Functions, node);
        assert_eq!(plugin.total_symbol_count(), 1);

        assert!(plugin.remove_symbol(0x400000));
        assert_eq!(plugin.total_symbol_count(), 0);
    }

    #[test]
    fn test_symbol_tree_all_symbols() {
        let mut plugin = SymbolTreePlugin::new();
        plugin.add_symbol(SymbolCategory::Functions, SymbolNode::new("a", SymbolType::Function, 0x100));
        plugin.add_symbol(SymbolCategory::Labels, SymbolNode::new("b", SymbolType::Label, 0x200));
        assert_eq!(plugin.all_symbols().len(), 2);
    }

    #[test]
    fn test_external_location() {
        let loc = ExternalLocation::new("printf", "", "libc.so");
        assert_eq!(loc.qualified_name(), "libc.so::printf");

        let loc2 = ExternalLocation::new("method", "MyClass", "libgui.so");
        assert_eq!(loc2.qualified_name(), "libgui.so::MyClass::method");
    }

    #[test]
    fn test_drag_drop_actions() {
        assert_ne!(SymbolDragDropAction::Move, SymbolDragDropAction::Copy);
        assert_ne!(SymbolDragDropAction::Copy, SymbolDragDropAction::Link);
    }
}
