//! Symbol tree node types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.symboltree.nodes` package.
//!
//! Each node type corresponds to a specific kind of symbol in the program:
//! - [`CodeSymbolNode`] for labels / code addresses
//! - [`FunctionSymbolNode`] for function symbols
//! - [`ClassSymbolNode`] for class/namespace symbols
//! - [`LibrarySymbolNode`] for external library symbols
//! - [`LocalVariableSymbolNode`] for function-local variables
//! - [`ParameterSymbolNode`] for function parameters
//! - [`NamespaceSymbolNode`] for namespace symbols
//! - [`SymbolCategoryNode`] for top-level category groupings
//! - [`OrganizationNode`] for grouping many children by name prefix
//! - [`MoreNode`] for pagination ("show more...") in large groups

use std::cmp::Ordering;

/// The type of symbol tree data flavor for drag-and-drop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolTreeDataFlavor(pub &'static str);

/// How to organize child nodes when there are too many.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrganizationStrategy {
    /// No organization -- all children are direct.
    None,
    /// Group children alphabetically by first letter.
    AlphaGroup,
    /// Group children by address range.
    AddressGroup,
    /// Group children by namespace path prefix.
    NamespaceGroup,
}

/// Types of symbol nodes in the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolNodeKind {
    /// Function symbol.
    Function,
    /// Label / code symbol.
    Code,
    /// Class / namespace symbol.
    Class,
    /// Library symbol.
    Library,
    /// Local variable symbol.
    LocalVariable,
    /// Parameter symbol.
    Parameter,
    /// Namespace symbol.
    Namespace,
    /// External location.
    ExternalLocation,
    /// External program.
    ExternalProgram,
}

impl SymbolNodeKind {
    /// Whether this kind represents a namespace container.
    pub fn is_namespace(&self) -> bool {
        matches!(
            self,
            Self::Class | Self::Library | Self::ExternalProgram | Self::Namespace
        )
    }

    /// The data flavor for drag-and-drop.
    pub fn data_flavor(&self) -> SymbolTreeDataFlavor {
        match self {
            Self::Function => SymbolTreeDataFlavor("Symbol Tree Data Flavor - Functions"),
            Self::Code => SymbolTreeDataFlavor("Symbol Tree Data Flavor - Labels"),
            Self::Class => SymbolTreeDataFlavor("Symbol Tree Data Flavor - Classes"),
            Self::Library => SymbolTreeDataFlavor("Symbol Tree Data Flavor - Libraries"),
            Self::LocalVariable => SymbolTreeDataFlavor("Symbol Tree Data Flavor - Local Variables"),
            Self::Parameter => SymbolTreeDataFlavor("Symbol Tree Data Flavor - Parameters"),
            Self::Namespace => SymbolTreeDataFlavor("Symbol Tree Data Flavor - Namespaces"),
            Self::ExternalLocation => SymbolTreeDataFlavor("Symbol Tree Data Flavor - External Locations"),
            Self::ExternalProgram => SymbolTreeDataFlavor("Symbol Tree Data Flavor - External Programs"),
        }
    }
}

/// A node in the symbol tree.
///
/// Ported from `ghidra.app.plugin.core.symboltree.nodes.SymbolTreeNode`
/// and `ghidra.app.plugin.core.symboltree.nodes.SymbolNode`.
#[derive(Debug, Clone)]
pub struct SymbolTreeNodeData {
    /// The name of this node (symbol name or category name).
    pub name: String,
    /// The kind of symbol node.
    pub kind: SymbolNodeKind,
    /// The symbol ID (0 if this is a category/non-symbol node).
    pub symbol_id: u64,
    /// The address this symbol references (0 if none).
    pub address: u64,
    /// The namespace path (e.g., "Global::MyClass").
    pub namespace_path: String,
    /// Whether this node has been loaded (children populated).
    pub loaded: bool,
    /// Whether this node has been cut (for cut-paste operations).
    pub cut: bool,
    /// Child nodes.
    pub children: Vec<SymbolTreeNodeData>,
}

impl SymbolTreeNodeData {
    /// Create a new symbol tree node.
    pub fn new(name: impl Into<String>, kind: SymbolNodeKind) -> Self {
        Self {
            name: name.into(),
            kind,
            symbol_id: 0,
            address: 0,
            namespace_path: String::new(),
            loaded: false,
            cut: false,
            children: Vec::new(),
        }
    }

    /// Create a function symbol node.
    pub fn function(name: impl Into<String>, address: u64, symbol_id: u64) -> Self {
        Self {
            name: name.into(),
            kind: SymbolNodeKind::Function,
            symbol_id,
            address,
            namespace_path: String::new(),
            loaded: false,
            cut: false,
            children: Vec::new(),
        }
    }

    /// Create a code/label symbol node.
    pub fn code_label(name: impl Into<String>, address: u64, symbol_id: u64) -> Self {
        Self {
            name: name.into(),
            kind: SymbolNodeKind::Code,
            symbol_id,
            address,
            namespace_path: String::new(),
            loaded: false,
            cut: false,
            children: Vec::new(),
        }
    }

    /// Create a class/namespace node.
    pub fn class(name: impl Into<String>, symbol_id: u64) -> Self {
        Self {
            name: name.into(),
            kind: SymbolNodeKind::Class,
            symbol_id,
            address: 0,
            namespace_path: String::new(),
            loaded: false,
            cut: false,
            children: Vec::new(),
        }
    }

    /// Create a library node.
    pub fn library(name: impl Into<String>, symbol_id: u64) -> Self {
        Self {
            name: name.into(),
            kind: SymbolNodeKind::Library,
            symbol_id,
            address: 0,
            namespace_path: String::new(),
            loaded: false,
            cut: false,
            children: Vec::new(),
        }
    }

    /// Whether this node is a namespace that can contain children.
    pub fn is_namespace(&self) -> bool {
        self.kind.is_namespace()
    }

    /// Whether this node has children.
    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }

    /// The total number of descendants.
    pub fn descendant_count(&self) -> usize {
        let mut count = self.children.len();
        for child in &self.children {
            count += child.descendant_count();
        }
        count
    }

    /// Add a child node, maintaining sorted order.
    pub fn add_child(&mut self, child: SymbolTreeNodeData) {
        let pos = self
            .children
            .binary_search_by(|c| node_name_cmp(&c.name, &child.name))
            .unwrap_or_else(|e| e);
        self.children.insert(pos, child);
    }

    /// Remove a child by symbol ID.
    pub fn remove_child(&mut self, symbol_id: u64) -> Option<SymbolTreeNodeData> {
        if let Some(pos) = self.children.iter().position(|c| c.symbol_id == symbol_id) {
            Some(self.children.remove(pos))
        } else {
            None
        }
    }

    /// Find a child by name using binary search.
    pub fn find_child_by_name(&self, name: &str) -> Option<&SymbolTreeNodeData> {
        self.children
            .binary_search_by(|c| node_name_cmp(&c.name, name))
            .ok()
            .map(|i| &self.children[i])
    }

    /// Find a descendant node by symbol ID (recursive).
    pub fn find_by_symbol_id(&self, symbol_id: u64) -> Option<&SymbolTreeNodeData> {
        if self.symbol_id == symbol_id {
            return Some(self);
        }
        for child in &self.children {
            if let Some(found) = child.find_by_symbol_id(symbol_id) {
                return Some(found);
            }
        }
        None
    }

    /// Get the icon name for this node kind.
    pub fn icon_name(&self) -> &'static str {
        match self.kind {
            SymbolNodeKind::Function => "FunctionIcon",
            SymbolNodeKind::Code => "CodeIcon",
            SymbolNodeKind::Class => "ClassIcon",
            SymbolNodeKind::Library => "LibraryIcon",
            SymbolNodeKind::LocalVariable => "LocalVariableIcon",
            SymbolNodeKind::Parameter => "ParameterIcon",
            SymbolNodeKind::Namespace => "NamespaceIcon",
            SymbolNodeKind::ExternalLocation => "ExternalLocationIcon",
            SymbolNodeKind::ExternalProgram => "ExternalProgramIcon",
        }
    }
}

/// Compare node names (case-insensitive, then case-sensitive tie-break).
fn node_name_cmp(a: &str, b: &str) -> Ordering {
    let a_lower = a.to_lowercase();
    let b_lower = b.to_lowercase();
    a_lower
        .cmp(&b_lower)
        .then_with(|| a.cmp(b))
}

/// An organization node that groups many children under a name prefix.
///
/// Ported from `ghidra.app.plugin.core.symboltree.nodes.OrganizationNode`.
#[derive(Debug, Clone)]
pub struct OrganizationNode {
    /// The display name (e.g., "A-D", "E-H").
    pub name: String,
    /// The children in this group.
    pub children: Vec<SymbolTreeNodeData>,
}

impl OrganizationNode {
    /// Create a new organization node.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            children: Vec::new(),
        }
    }

    /// Add a child to this group.
    pub fn add_child(&mut self, child: SymbolTreeNodeData) {
        self.children.push(child);
    }
}

/// A "show more" pagination node.
///
/// When a category has too many children, they are split into groups
/// with `MoreNode` markers indicating more results are available.
///
/// Ported from `ghidra.app.plugin.core.symboltree.nodes.MoreNode`.
#[derive(Debug, Clone)]
pub struct MoreNode {
    /// The number of additional symbols available.
    pub remaining_count: usize,
    /// The name prefix this "more" node represents.
    pub prefix: String,
}

impl MoreNode {
    /// Create a new "more" node.
    pub fn new(remaining_count: usize, prefix: impl Into<String>) -> Self {
        Self {
            remaining_count,
            prefix: prefix.into(),
        }
    }

    /// Display text for this node.
    pub fn display_text(&self) -> String {
        format!("({} more...)", self.remaining_count)
    }
}

/// A special symbol node used as a key when searching for other symbol nodes.
///
/// Allows searching for another symbol node using whatever name is desired,
/// overriding the symbol's actual name.
///
/// Ported from `ghidra.app.plugin.core.symboltree.nodes.SearchKeySymbolNode`.
#[derive(Debug, Clone)]
pub struct SearchKeySymbolNode {
    /// The base symbol node data.
    pub base: SymbolTreeNodeData,
    /// The search name used for lookups instead of the symbol's real name.
    pub search_name: String,
}

impl SearchKeySymbolNode {
    /// Create a new search key node with a custom search name.
    pub fn new(
        _name: impl Into<String>,
        kind: SymbolNodeKind,
        symbol_id: u64,
        search_name: impl Into<String>,
    ) -> Self {
        let search = search_name.into();
        assert!(!search.is_empty(), "search_name must not be null/empty");
        let base = SymbolTreeNodeData {
            name: search.clone(),
            kind,
            symbol_id,
            address: 0,
            namespace_path: String::new(),
            loaded: false,
            cut: false,
            children: Vec::new(),
        };
        Self {
            base,
            search_name: search,
        }
    }

    /// Get the effective name used for searching.
    pub fn name(&self) -> &str {
        &self.search_name
    }

    /// Get the symbol ID.
    pub fn symbol_id(&self) -> u64 {
        self.base.symbol_id
    }

    /// Get the kind.
    pub fn kind(&self) -> SymbolNodeKind {
        self.base.kind
    }
}

// ---------------------------------------------------------------------------
// ExportCategoryNode
// ---------------------------------------------------------------------------

/// A category node for the "Exports" section of the symbol tree.
///
/// Ported from `ghidra.app.plugin.core.symboltree.nodes.ExportsCategoryNode`.
#[derive(Debug, Clone)]
pub struct ExportsCategoryNode {
    /// The display name.
    pub name: String,
    /// Child export symbol nodes.
    pub children: Vec<SymbolTreeNodeData>,
}

impl ExportsCategoryNode {
    /// Create a new exports category node.
    pub fn new() -> Self {
        Self {
            name: "Exports".to_string(),
            children: Vec::new(),
        }
    }

    /// Add an export symbol.
    pub fn add_export(&mut self, node: SymbolTreeNodeData) {
        self.children.push(node);
    }

    /// Number of exports.
    pub fn count(&self) -> usize {
        self.children.len()
    }
}

impl Default for ExportsCategoryNode {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ConfigurableSymbolTreeRootNode
// ---------------------------------------------------------------------------

/// A configurable root node for the symbol tree.
///
/// Ported from `ghidra.app.plugin.core.symboltree.nodes.ConfigurableSymbolTreeRootNode`.
#[derive(Debug, Clone)]
pub struct ConfigurableSymbolTreeRootNode {
    /// The display name.
    pub name: String,
    /// Top-level category children.
    pub categories: Vec<SymbolTreeNodeData>,
    /// Whether the root is expanded.
    pub expanded: bool,
}

impl ConfigurableSymbolTreeRootNode {
    /// Create a new configurable root node.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            categories: Vec::new(),
            expanded: true,
        }
    }

    /// Add a category node.
    pub fn add_category(&mut self, category: SymbolTreeNodeData) {
        self.categories.push(category);
    }

    /// Total number of symbols across all categories.
    pub fn total_symbols(&self) -> usize {
        self.categories
            .iter()
            .map(|c| c.descendant_count() + 1)
            .sum()
    }

    /// Find a category by name.
    pub fn find_category(&self, name: &str) -> Option<&SymbolTreeNodeData> {
        self.categories.iter().find(|c| c.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_node_kind_is_namespace() {
        assert!(SymbolNodeKind::Class.is_namespace());
        assert!(SymbolNodeKind::Library.is_namespace());
        assert!(!SymbolNodeKind::Function.is_namespace());
        assert!(!SymbolNodeKind::Code.is_namespace());
    }

    #[test]
    fn test_symbol_tree_node_data_new() {
        let node = SymbolTreeNodeData::function("main", 0x4000, 1);
        assert_eq!(node.name, "main");
        assert_eq!(node.kind, SymbolNodeKind::Function);
        assert_eq!(node.address, 0x4000);
        assert_eq!(node.symbol_id, 1);
        assert!(!node.has_children());
    }

    #[test]
    fn test_add_child_sorted() {
        let mut root = SymbolTreeNodeData::new("Root", SymbolNodeKind::Namespace);
        root.add_child(SymbolTreeNodeData::function("zebra", 0x1000, 1));
        root.add_child(SymbolTreeNodeData::function("alpha", 0x2000, 2));
        root.add_child(SymbolTreeNodeData::function("middle", 0x3000, 3));
        assert_eq!(root.children[0].name, "alpha");
        assert_eq!(root.children[1].name, "middle");
        assert_eq!(root.children[2].name, "zebra");
    }

    #[test]
    fn test_find_child_by_name() {
        let mut root = SymbolTreeNodeData::new("Root", SymbolNodeKind::Namespace);
        root.add_child(SymbolTreeNodeData::function("foo", 0x1000, 1));
        root.add_child(SymbolTreeNodeData::function("bar", 0x2000, 2));
        assert!(root.find_child_by_name("foo").is_some());
        assert!(root.find_child_by_name("baz").is_none());
    }

    #[test]
    fn test_find_by_symbol_id() {
        let mut root = SymbolTreeNodeData::new("Root", SymbolNodeKind::Namespace);
        let mut child = SymbolTreeNodeData::function("parent", 0x1000, 1);
        child.add_child(SymbolTreeNodeData::function("child", 0x1100, 2));
        root.add_child(child);
        assert!(root.find_by_symbol_id(2).is_some());
        assert!(root.find_by_symbol_id(99).is_none());
    }

    #[test]
    fn test_remove_child() {
        let mut root = SymbolTreeNodeData::new("Root", SymbolNodeKind::Namespace);
        root.add_child(SymbolTreeNodeData::function("foo", 0x1000, 1));
        root.add_child(SymbolTreeNodeData::function("bar", 0x2000, 2));
        let removed = root.remove_child(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name, "foo");
        assert_eq!(root.children.len(), 1);
    }

    #[test]
    fn test_descendant_count() {
        let mut root = SymbolTreeNodeData::new("Root", SymbolNodeKind::Namespace);
        let mut child = SymbolTreeNodeData::function("parent", 0x1000, 1);
        child.add_child(SymbolTreeNodeData::function("c1", 0x1100, 2));
        child.add_child(SymbolTreeNodeData::function("c2", 0x1200, 3));
        root.add_child(child);
        // root has 1 direct child + 2 descendants of that child = 3
        assert_eq!(root.descendant_count(), 3);
    }

    #[test]
    fn test_code_label_node() {
        let node = SymbolTreeNodeData::code_label("LAB_00400", 0x400, 5);
        assert_eq!(node.kind, SymbolNodeKind::Code);
        assert_eq!(node.address, 0x400);
    }

    #[test]
    fn test_class_node() {
        let node = SymbolTreeNodeData::class("MyClass", 10);
        assert!(node.is_namespace());
        assert_eq!(node.icon_name(), "ClassIcon");
    }

    #[test]
    fn test_library_node() {
        let node = SymbolTreeNodeData::library("libc.so", 20);
        assert!(node.is_namespace());
        assert_eq!(node.icon_name(), "LibraryIcon");
    }

    #[test]
    fn test_organization_node() {
        let mut org = OrganizationNode::new("A-F");
        org.add_child(SymbolTreeNodeData::function("alpha", 0x1000, 1));
        assert_eq!(org.children.len(), 1);
    }

    #[test]
    fn test_more_node() {
        let more = MoreNode::new(500, "M");
        assert_eq!(more.display_text(), "(500 more...)");
    }

    #[test]
    fn test_node_name_cmp() {
        // Case-insensitive equal, then case-sensitive tie-break (lowercase > uppercase in ASCII).
        assert_eq!(node_name_cmp("abc", "ABC"), Ordering::Greater);
        assert_eq!(node_name_cmp("ABC", "abc"), Ordering::Less);
        assert_eq!(node_name_cmp("abc", "abc"), Ordering::Equal);
        assert_eq!(node_name_cmp("abc", "abd"), Ordering::Less);
    }

    #[test]
    fn test_data_flavor() {
        let flavor = SymbolNodeKind::Function.data_flavor();
        assert_eq!(flavor.0, "Symbol Tree Data Flavor - Functions");
    }

    #[test]
    fn test_icon_names() {
        assert_eq!(SymbolTreeNodeData::function("f", 0, 0).icon_name(), "FunctionIcon");
        assert_eq!(SymbolTreeNodeData::code_label("l", 0, 0).icon_name(), "CodeIcon");
        assert_eq!(SymbolTreeNodeData::class("c", 0).icon_name(), "ClassIcon");
        assert_eq!(SymbolTreeNodeData::library("lib", 0).icon_name(), "LibraryIcon");
    }

    #[test]
    fn test_search_key_symbol_node() {
        let node = SearchKeySymbolNode::new("real_name", SymbolNodeKind::Function, 42, "lookup_key");
        assert_eq!(node.name(), "lookup_key");
        assert_eq!(node.symbol_id(), 42);
        assert_eq!(node.kind(), SymbolNodeKind::Function);
    }

    #[test]
    fn test_exports_category_node() {
        let mut exports = ExportsCategoryNode::new();
        assert_eq!(exports.count(), 0);
        exports.add_export(SymbolTreeNodeData::code_label("printf", 0x1000, 1));
        exports.add_export(SymbolTreeNodeData::function("main", 0x2000, 2));
        assert_eq!(exports.count(), 2);
    }

    #[test]
    fn test_configurable_root_node() {
        let mut root = ConfigurableSymbolTreeRootNode::new("Program");
        root.add_category(SymbolTreeNodeData::new("Functions", SymbolNodeKind::Namespace));
        root.add_category(SymbolTreeNodeData::new("Labels", SymbolNodeKind::Namespace));
        assert_eq!(root.categories.len(), 2);
        assert!(root.find_category("Functions").is_some());
        assert!(root.find_category("Missing").is_none());
        assert!(root.expanded);
    }

    #[test]
    fn test_configurable_root_total_symbols() {
        let mut root = ConfigurableSymbolTreeRootNode::new("Program");
        let mut funcs = SymbolTreeNodeData::new("Functions", SymbolNodeKind::Namespace);
        funcs.add_child(SymbolTreeNodeData::function("a", 0x100, 1));
        funcs.add_child(SymbolTreeNodeData::function("b", 0x200, 2));
        root.add_category(funcs);
        // Functions category + 2 children = 3
        assert_eq!(root.total_symbols(), 3);
    }

    #[test]
    fn test_more_node_display() {
        let more = MoreNode::new(100, "A");
        assert_eq!(more.display_text(), "(100 more...)");
        assert_eq!(more.prefix, "A");
    }
}
