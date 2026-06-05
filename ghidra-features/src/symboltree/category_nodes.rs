//! Category nodes and tree root for the symbol tree.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.symboltree.nodes` package.
//!
//! Provides the top-level category grouping nodes:
//! - [`FunctionCategoryNode`] -- groups function symbols
//! - [`LabelCategoryNode`] -- groups label symbols
//! - [`ClassCategoryNode`] -- groups class/namespace symbols
//! - [`ImportsCategoryNode`] -- groups imported symbols
//! - [`ExportsCategoryNode`] -- groups exported symbols
//! - [`NamespaceCategoryNode`] -- groups namespace symbols
//! - [`SymbolTreeRootNode`] -- the root of the symbol tree
//! - [`ConfigurableSymbolTreeRootNode`] -- configurable root with custom categories

use std::collections::BTreeMap;

use super::SymbolCategory;
use super::nodes::{SymbolTreeNodeData, SymbolNodeKind};

// ---------------------------------------------------------------------------
// Category node types
// ---------------------------------------------------------------------------

/// A category node that groups symbols of a specific kind.
///
/// Ported from `ghidra.app.plugin.core.symboltree.nodes.SymbolCategoryNode`.
#[derive(Debug, Clone)]
pub struct CategoryNode {
    /// The category this node represents.
    pub category: SymbolCategory,
    /// The display name.
    pub name: String,
    /// The child symbol nodes in this category.
    children: Vec<SymbolTreeNodeData>,
    /// Maximum children before auto-grouping.
    pub group_threshold: usize,
}

impl CategoryNode {
    /// Create a new category node.
    pub fn new(category: SymbolCategory) -> Self {
        let name = category.display_name().to_string();
        Self {
            category,
            name,
            children: Vec::new(),
            group_threshold: super::DEFAULT_GROUP_THRESHOLD,
        }
    }

    /// Add a child symbol node.
    pub fn add_child(&mut self, child: SymbolTreeNodeData) {
        self.children.push(child);
    }

    /// Get the children.
    pub fn children(&self) -> &[SymbolTreeNodeData] {
        &self.children
    }

    /// Number of direct children.
    pub fn child_count(&self) -> usize {
        self.children.len()
    }

    /// Whether the category needs organization (too many children).
    pub fn needs_organization(&self) -> bool {
        self.children.len() > self.group_threshold
    }

    /// Remove a child by symbol ID.
    pub fn remove_child(&mut self, symbol_id: u64) -> Option<SymbolTreeNodeData> {
        if let Some(pos) = self.children.iter().position(|c| c.symbol_id == symbol_id) {
            Some(self.children.remove(pos))
        } else {
            None
        }
    }

    /// Search children by name prefix.
    pub fn search_by_prefix(&self, prefix: &str) -> Vec<&SymbolTreeNodeData> {
        let lower_prefix = prefix.to_lowercase();
        self.children
            .iter()
            .filter(|c| c.name.to_lowercase().starts_with(&lower_prefix))
            .collect()
    }

    /// Clear all children.
    pub fn clear(&mut self) {
        self.children.clear();
    }
}

// ---------------------------------------------------------------------------
// Specific category nodes
// ---------------------------------------------------------------------------

/// Category node for function symbols.
///
/// Ported from `ghidra.app.plugin.core.symboltree.nodes.FunctionCategoryNode`.
pub type FunctionCategoryNode = CategoryNode;

/// Category node for label symbols.
///
/// Ported from `ghidra.app.plugin.core.symboltree.nodes.LabelCategoryNode`.
pub type LabelCategoryNode = CategoryNode;

/// Category node for class/namespace symbols.
///
/// Ported from `ghidra.app.plugin.core.symboltree.nodes.ClassCategoryNode`.
pub type ClassCategoryNode = CategoryNode;

/// Category node for imported symbols.
///
/// Ported from `ghidra.app.plugin.core.symboltree.nodes.ImportsCategoryNode`.
pub type ImportsCategoryNode = CategoryNode;

/// Category node for exported symbols.
///
/// Ported from `ghidra.app.plugin.core.symboltree.nodes.ExportsCategoryNode`.
pub type ExportsCategoryNode = CategoryNode;

/// Category node for namespace symbols.
///
/// Ported from `ghidra.app.plugin.core.symboltree.nodes.NamespaceCategoryNode`.
pub type NamespaceCategoryNode = CategoryNode;

// ---------------------------------------------------------------------------
// SymbolTreeRootNode
// ---------------------------------------------------------------------------

/// The root node of the symbol tree.
///
/// Ported from `ghidra.app.plugin.core.symboltree.nodes.SymbolTreeRootNode`.
#[derive(Debug, Clone)]
pub struct SymbolTreeRootNode {
    /// Category nodes organized by category.
    categories: BTreeMap<SymbolCategory, CategoryNode>,
    /// The program name.
    pub program_name: String,
}

impl SymbolTreeRootNode {
    /// Create a new root node with all default categories.
    pub fn new(program_name: impl Into<String>) -> Self {
        let mut categories = BTreeMap::new();
        for cat in SymbolCategory::all() {
            categories.insert(*cat, CategoryNode::new(*cat));
        }
        Self {
            categories,
            program_name: program_name.into(),
        }
    }

    /// Get a category node.
    pub fn category(&self, cat: SymbolCategory) -> Option<&CategoryNode> {
        self.categories.get(&cat)
    }

    /// Get a mutable category node.
    pub fn category_mut(&mut self, cat: SymbolCategory) -> Option<&mut CategoryNode> {
        self.categories.get_mut(&cat)
    }

    /// Add a symbol to the appropriate category.
    pub fn add_symbol(&mut self, category: SymbolCategory, node: SymbolTreeNodeData) {
        if let Some(cat_node) = self.categories.get_mut(&category) {
            cat_node.add_child(node);
        }
    }

    /// Get all category nodes.
    pub fn categories(&self) -> &BTreeMap<SymbolCategory, CategoryNode> {
        &self.categories
    }

    /// Total symbol count across all categories.
    pub fn total_symbols(&self) -> usize {
        self.categories.values().map(|c| c.child_count()).sum()
    }

    /// Remove a symbol by ID from any category.
    pub fn remove_symbol(&mut self, symbol_id: u64) -> Option<SymbolTreeNodeData> {
        for cat_node in self.categories.values_mut() {
            if let Some(removed) = cat_node.remove_child(symbol_id) {
                return Some(removed);
            }
        }
        None
    }

    /// Search across all categories.
    pub fn search_all(&self, prefix: &str) -> Vec<(SymbolCategory, &SymbolTreeNodeData)> {
        let mut results = Vec::new();
        for (cat, cat_node) in &self.categories {
            for node in cat_node.search_by_prefix(prefix) {
                results.push((*cat, node));
            }
        }
        results
    }

    /// Clear all categories.
    pub fn clear(&mut self) {
        for cat_node in self.categories.values_mut() {
            cat_node.clear();
        }
    }
}

// ---------------------------------------------------------------------------
// ConfigurableSymbolTreeRootNode
// ---------------------------------------------------------------------------

/// A configurable root node that allows custom category configuration.
///
/// Ported from `ghidra.app.plugin.core.symboltree.nodes.ConfigurableSymbolTreeRootNode`.
#[derive(Debug, Clone)]
pub struct ConfigurableSymbolTreeRootNode {
    /// The base root node.
    pub base: SymbolTreeRootNode,
    /// Whether to show the imports category.
    pub show_imports: bool,
    /// Whether to show the exports category.
    pub show_exports: bool,
    /// Whether to show the classes category.
    pub show_classes: bool,
    /// Whether to show the libraries category.
    pub show_libraries: bool,
    /// Custom category names (overrides defaults).
    custom_names: BTreeMap<SymbolCategory, String>,
}

impl ConfigurableSymbolTreeRootNode {
    /// Create a new configurable root node.
    pub fn new(program_name: impl Into<String>) -> Self {
        Self {
            base: SymbolTreeRootNode::new(program_name),
            show_imports: true,
            show_exports: true,
            show_classes: true,
            show_libraries: true,
            custom_names: BTreeMap::new(),
        }
    }

    /// Get the display name for a category.
    pub fn display_name(&self, cat: SymbolCategory) -> &str {
        self.custom_names
            .get(&cat)
            .map(|s| s.as_str())
            .unwrap_or_else(|| cat.display_name())
    }

    /// Set a custom name for a category.
    pub fn set_custom_name(&mut self, cat: SymbolCategory, name: impl Into<String>) {
        self.custom_names.insert(cat, name.into());
    }

    /// Whether a category is visible.
    pub fn is_category_visible(&self, cat: SymbolCategory) -> bool {
        match cat {
            SymbolCategory::Functions => true, // Always visible
            SymbolCategory::Labels => true,
            SymbolCategory::Classes => self.show_classes,
            SymbolCategory::Libraries => self.show_libraries,
            SymbolCategory::ExternalPrograms => true,
            SymbolCategory::Global => true,
        }
    }

    /// Get the visible categories in order.
    pub fn visible_categories(&self) -> Vec<SymbolCategory> {
        SymbolCategory::all()
            .iter()
            .filter(|c| self.is_category_visible(**c))
            .copied()
            .collect()
    }

    /// Total symbol count in visible categories.
    pub fn visible_symbol_count(&self) -> usize {
        self.visible_categories()
            .iter()
            .filter_map(|c| self.base.category(*c))
            .map(|c| c.child_count())
            .sum()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(name: &str, id: u64) -> SymbolTreeNodeData {
        SymbolTreeNodeData::function(name, id * 0x100, id)
    }

    #[test]
    fn test_category_node_creation() {
        let node = CategoryNode::new(SymbolCategory::Functions);
        assert_eq!(node.name, "Functions");
        assert_eq!(node.child_count(), 0);
        assert!(!node.needs_organization());
    }

    #[test]
    fn test_category_node_add_child() {
        let mut cat = CategoryNode::new(SymbolCategory::Functions);
        cat.add_child(make_node("main", 1));
        cat.add_child(make_node("init", 2));
        assert_eq!(cat.child_count(), 2);
    }

    #[test]
    fn test_category_node_remove_child() {
        let mut cat = CategoryNode::new(SymbolCategory::Functions);
        cat.add_child(make_node("main", 1));
        cat.add_child(make_node("init", 2));
        let removed = cat.remove_child(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name, "main");
        assert_eq!(cat.child_count(), 1);
    }

    #[test]
    fn test_category_node_search_by_prefix() {
        let mut cat = CategoryNode::new(SymbolCategory::Functions);
        cat.add_child(make_node("main", 1));
        cat.add_child(make_node("mainLoop", 2));
        cat.add_child(make_node("init", 3));

        let results = cat.search_by_prefix("main");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_category_node_needs_organization() {
        let mut cat = CategoryNode::new(SymbolCategory::Functions);
        cat.group_threshold = 3;
        for i in 0..5 {
            cat.add_child(make_node(&format!("func_{}", i), i));
        }
        assert!(cat.needs_organization());
    }

    #[test]
    fn test_category_node_clear() {
        let mut cat = CategoryNode::new(SymbolCategory::Functions);
        cat.add_child(make_node("a", 1));
        cat.clear();
        assert_eq!(cat.child_count(), 0);
    }

    #[test]
    fn test_symbol_tree_root_node() {
        let root = SymbolTreeRootNode::new("test.exe");
        assert_eq!(root.program_name, "test.exe");
        assert_eq!(root.total_symbols(), 0);
        assert!(root.category(SymbolCategory::Functions).is_some());
    }

    #[test]
    fn test_symbol_tree_root_add_symbol() {
        let mut root = SymbolTreeRootNode::new("test.exe");
        root.add_symbol(SymbolCategory::Functions, make_node("main", 1));
        root.add_symbol(SymbolCategory::Labels, make_node("LAB_00400", 2));
        assert_eq!(root.total_symbols(), 2);
    }

    #[test]
    fn test_symbol_tree_root_remove_symbol() {
        let mut root = SymbolTreeRootNode::new("test.exe");
        root.add_symbol(SymbolCategory::Functions, make_node("main", 1));
        let removed = root.remove_symbol(1);
        assert!(removed.is_some());
        assert_eq!(root.total_symbols(), 0);
    }

    #[test]
    fn test_symbol_tree_root_search() {
        let mut root = SymbolTreeRootNode::new("test.exe");
        root.add_symbol(SymbolCategory::Functions, make_node("main", 1));
        root.add_symbol(SymbolCategory::Labels, make_node("main_entry", 2));
        root.add_symbol(SymbolCategory::Functions, make_node("init", 3));

        let results = root.search_all("main");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_symbol_tree_root_clear() {
        let mut root = SymbolTreeRootNode::new("test.exe");
        root.add_symbol(SymbolCategory::Functions, make_node("a", 1));
        root.add_symbol(SymbolCategory::Labels, make_node("b", 2));
        root.clear();
        assert_eq!(root.total_symbols(), 0);
    }

    #[test]
    fn test_configurable_root_node() {
        let root = ConfigurableSymbolTreeRootNode::new("test.exe");
        assert!(root.is_category_visible(SymbolCategory::Functions));
        assert!(root.is_category_visible(SymbolCategory::Labels));
        assert!(root.is_category_visible(SymbolCategory::Classes));
    }

    #[test]
    fn test_configurable_root_visible_categories() {
        let mut root = ConfigurableSymbolTreeRootNode::new("test.exe");
        root.show_imports = false;
        root.show_libraries = false;
        let visible = root.visible_categories();
        assert!(visible.contains(&SymbolCategory::Functions));
        assert!(!visible.contains(&SymbolCategory::Libraries));
    }

    #[test]
    fn test_configurable_root_custom_name() {
        let mut root = ConfigurableSymbolTreeRootNode::new("test.exe");
        root.set_custom_name(SymbolCategory::Functions, "My Functions");
        assert_eq!(root.display_name(SymbolCategory::Functions), "My Functions");
        assert_eq!(root.display_name(SymbolCategory::Labels), "Labels");
    }

    #[test]
    fn test_configurable_root_visible_symbol_count() {
        let mut root = ConfigurableSymbolTreeRootNode::new("test.exe");
        root.base.add_symbol(SymbolCategory::Functions, make_node("a", 1));
        root.base.add_symbol(SymbolCategory::Libraries, make_node("lib", 2));
        root.show_libraries = false;
        assert_eq!(root.visible_symbol_count(), 1);
    }

    #[test]
    fn test_type_aliases() {
        let _: FunctionCategoryNode = CategoryNode::new(SymbolCategory::Functions);
        let _: LabelCategoryNode = CategoryNode::new(SymbolCategory::Labels);
        let _: ClassCategoryNode = CategoryNode::new(SymbolCategory::Classes);
        let _: ImportsCategoryNode = CategoryNode::new(SymbolCategory::Libraries);
        let _: ExportsCategoryNode = CategoryNode::new(SymbolCategory::Global);
    }
}
