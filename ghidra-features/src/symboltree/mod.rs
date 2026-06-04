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
}
