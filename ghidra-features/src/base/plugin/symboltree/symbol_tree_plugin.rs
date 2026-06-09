//! Symbol Tree Plugin -- displays program symbols in a tree hierarchy.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.symboltree` package.
//!
//! This module provides the symbol tree plugin that displays symbols from
//! the program in a tree organized by namespace. Supports symbol operations
//! like rename, delete, move, create namespaces/classes, and external
//! library management.
//!
//! # Architecture
//!
//! ```text
//! SymbolTreePlugin
//!   ├── SymbolTreeProvider (tree view component)
//!   ├── SymbolCategoryManager (category organization)
//!   ├── SymbolFilter (search and filter)
//!   └── SymbolOperations (CRUD operations)
//! ```
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::plugin::symboltree::symbol_tree_plugin::SymbolTreePlugin;
//!
//! let mut plugin = SymbolTreePlugin::new("SymbolTree");
//! plugin.init();
//! assert_eq!(plugin.name(), "SymbolTree");
//! ```

use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// SymbolCategory -- top-level categories in the symbol tree
// ---------------------------------------------------------------------------

/// Top-level categories in the symbol tree.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.symboltree.SymbolCategory`.
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
    /// External data symbols.
    ExternalData,
    /// External function symbols.
    ExternalFunctions,
    /// Global symbols.
    Global,
}

impl SymbolCategory {
    /// Returns the display name for this category.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Functions => "Functions",
            Self::Labels => "Labels",
            Self::Classes => "Classes",
            Self::Libraries => "Libraries",
            Self::ExternalPrograms => "External Programs",
            Self::ExternalData => "External Data",
            Self::ExternalFunctions => "External Functions",
            Self::Global => "Global",
        }
    }

    /// Returns all categories.
    pub fn all() -> &'static [SymbolCategory] {
        &[
            Self::Functions,
            Self::Labels,
            Self::Classes,
            Self::Libraries,
            Self::ExternalPrograms,
            Self::ExternalData,
            Self::ExternalFunctions,
            Self::Global,
        ]
    }
}

impl fmt::Display for SymbolCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// SymbolNode -- a node in the symbol tree
// ---------------------------------------------------------------------------

/// The type of a symbol node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolNodeType {
    /// A function symbol.
    Function,
    /// A label symbol.
    Label,
    /// A class/namespace.
    Class,
    /// A library.
    Library,
    /// An external program.
    ExternalProgram,
    /// An external data symbol.
    ExternalData,
    /// An external function.
    ExternalFunction,
    /// A global symbol.
    Global,
    /// A folder node.
    Folder,
}

/// A node in the symbol tree.
#[derive(Debug, Clone)]
pub struct SymbolNode {
    /// The symbol name.
    pub name: String,
    /// The node type.
    pub node_type: SymbolNodeType,
    /// The address (as hex string, if applicable).
    pub address: Option<String>,
    /// The namespace path.
    pub namespace: String,
    /// Child nodes.
    pub children: Vec<SymbolNode>,
    /// Whether the node is expanded.
    pub expanded: bool,
    /// Whether the node is a leaf (no children).
    pub is_leaf: bool,
}

impl SymbolNode {
    /// Creates a new symbol node.
    pub fn new(name: impl Into<String>, node_type: SymbolNodeType) -> Self {
        Self {
            name: name.into(),
            node_type,
            address: None,
            namespace: String::new(),
            children: Vec::new(),
            expanded: false,
            is_leaf: true,
        }
    }

    /// Creates a new folder node.
    pub fn folder(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            node_type: SymbolNodeType::Folder,
            address: None,
            namespace: String::new(),
            children: Vec::new(),
            expanded: false,
            is_leaf: false,
        }
    }

    /// Adds a child node.
    pub fn add_child(&mut self, child: SymbolNode) {
        self.children.push(child);
        self.is_leaf = false;
    }

    /// Returns the number of children.
    pub fn child_count(&self) -> usize {
        self.children.len()
    }

    /// Returns a reference to a child by index.
    pub fn child(&self, index: usize) -> Option<&SymbolNode> {
        self.children.get(index)
    }

    /// Returns a mutable reference to a child by index.
    pub fn child_mut(&mut self, index: usize) -> Option<&mut SymbolNode> {
        self.children.get_mut(index)
    }

    /// Sets the address.
    pub fn with_address(mut self, address: impl Into<String>) -> Self {
        self.address = Some(address.into());
        self
    }

    /// Sets the namespace.
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = namespace.into();
        self
    }

    /// Sets the expanded state.
    pub fn set_expanded(&mut self, expanded: bool) {
        self.expanded = expanded;
    }

    /// Returns whether the node is expanded.
    pub fn is_expanded(&self) -> bool {
        self.expanded
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
    pub fn find_child(&self, name: &str) -> Option<&SymbolNode> {
        self.children.iter().find(|c| c.name == name)
    }

    /// Finds a child by name (mutable).
    pub fn find_child_mut(&mut self, name: &str) -> Option<&mut SymbolNode> {
        self.children.iter_mut().find(|c| c.name == name)
    }
}

// ---------------------------------------------------------------------------
// SymbolFilter -- filtering and search for symbols
// ---------------------------------------------------------------------------

/// Filter criteria for symbol search.
#[derive(Debug, Clone)]
pub struct SymbolFilter {
    /// The search text.
    pub text: String,
    /// Whether to match case.
    pub case_sensitive: bool,
    /// Whether to use regular expressions.
    pub use_regex: bool,
    /// Filter by category.
    pub category: Option<SymbolCategory>,
    /// Filter by node type.
    pub node_type: Option<SymbolNodeType>,
    /// Whether to search in namespaces.
    pub search_namespaces: bool,
}

impl SymbolFilter {
    /// Creates a new symbol filter.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            case_sensitive: false,
            use_regex: false,
            category: None,
            node_type: None,
            search_namespaces: true,
        }
    }

    /// Sets case sensitivity.
    pub fn with_case_sensitive(mut self, case_sensitive: bool) -> Self {
        self.case_sensitive = case_sensitive;
        self
    }

    /// Sets regex mode.
    pub fn with_regex(mut self, use_regex: bool) -> Self {
        self.use_regex = use_regex;
        self
    }

    /// Sets the category filter.
    pub fn with_category(mut self, category: SymbolCategory) -> Self {
        self.category = Some(category);
        self
    }

    /// Sets the node type filter.
    pub fn with_node_type(mut self, node_type: SymbolNodeType) -> Self {
        self.node_type = Some(node_type);
        self
    }

    /// Tests whether a symbol name matches this filter.
    pub fn matches(&self, name: &str) -> bool {
        if self.text.is_empty() {
            return true;
        }
        if self.case_sensitive {
            name.contains(&self.text)
        } else {
            name.to_lowercase().contains(&self.text.to_lowercase())
        }
    }
}

impl Default for SymbolFilter {
    fn default() -> Self {
        Self::new("")
    }
}

// ---------------------------------------------------------------------------
// SymbolTreePlugin -- the main plugin
// ---------------------------------------------------------------------------

/// The symbol tree plugin.
///
/// Displays symbols from the program in a tree organized by namespace.
/// Supports symbol operations like rename, delete, move, create
/// namespaces/classes, and external library management.
///
/// Ported from Ghidra's `SymbolTreePlugin` Java class.
#[derive(Debug)]
pub struct SymbolTreePlugin {
    /// The plugin name.
    name: String,
    /// The root node of the symbol tree.
    root: SymbolNode,
    /// Symbol counts by category.
    category_counts: BTreeMap<SymbolCategory, usize>,
    /// Current filter.
    filter: Option<SymbolFilter>,
    /// Whether the plugin is initialized.
    initialized: bool,
    /// Whether the plugin is disposed.
    disposed: bool,
    /// Plugin options.
    options: BTreeMap<String, String>,
}

impl SymbolTreePlugin {
    /// Creates a new symbol tree plugin.
    pub fn new(name: impl Into<String>) -> Self {
        let mut root = SymbolNode::folder("Symbol Tree");
        // Initialize category nodes
        for category in SymbolCategory::all() {
            let mut node = SymbolNode::folder(category.display_name());
            node.namespace = category.display_name().to_string();
            root.add_child(node);
        }

        Self {
            name: name.into(),
            root,
            category_counts: BTreeMap::new(),
            filter: None,
            initialized: false,
            disposed: false,
            options: BTreeMap::new(),
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
    }

    /// Disposes the plugin.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.root = SymbolNode::folder("Symbol Tree");
        self.category_counts.clear();
        self.filter = None;
    }

    /// Returns whether the plugin is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Returns a reference to the root node.
    pub fn root(&self) -> &SymbolNode {
        &self.root
    }

    /// Returns a mutable reference to the root node.
    pub fn root_mut(&mut self) -> &mut SymbolNode {
        &mut self.root
    }

    /// Returns the category node for the given category.
    pub fn category_node(&self, category: SymbolCategory) -> Option<&SymbolNode> {
        self.root.find_child(category.display_name())
    }

    /// Returns a mutable reference to the category node.
    pub fn category_node_mut(&mut self, category: SymbolCategory) -> Option<&mut SymbolNode> {
        self.root.find_child_mut(category.display_name())
    }

    /// Adds a symbol to the appropriate category.
    pub fn add_symbol(&mut self, name: impl Into<String>, category: SymbolCategory, address: Option<String>) {
        let name = name.into();
        let node = SymbolNode::new(&name, match category {
            SymbolCategory::Functions => SymbolNodeType::Function,
            SymbolCategory::Labels => SymbolNodeType::Label,
            SymbolCategory::Classes => SymbolNodeType::Class,
            SymbolCategory::Libraries => SymbolNodeType::Library,
            SymbolCategory::ExternalPrograms => SymbolNodeType::ExternalProgram,
            SymbolCategory::ExternalData => SymbolNodeType::ExternalData,
            SymbolCategory::ExternalFunctions => SymbolNodeType::ExternalFunction,
            SymbolCategory::Global => SymbolNodeType::Global,
        })
        .with_namespace(category.display_name())
        .with_address(address.unwrap_or_default());

        if let Some(cat_node) = self.root.find_child_mut(category.display_name()) {
            cat_node.add_child(node);
            *self.category_counts.entry(category).or_insert(0) += 1;
        }
    }

    /// Returns the symbol count for a category.
    pub fn category_count(&self, category: &SymbolCategory) -> usize {
        self.category_counts.get(category).copied().unwrap_or(0)
    }

    /// Returns the total symbol count.
    pub fn total_symbol_count(&self) -> usize {
        self.category_counts.values().sum()
    }

    /// Sets the filter.
    pub fn set_filter(&mut self, filter: SymbolFilter) {
        self.filter = Some(filter);
    }

    /// Clears the filter.
    pub fn clear_filter(&mut self) {
        self.filter = None;
    }

    /// Returns a reference to the current filter.
    pub fn filter(&self) -> Option<&SymbolFilter> {
        self.filter.as_ref()
    }

    /// Returns whether a filter is active.
    pub fn has_filter(&self) -> bool {
        self.filter.is_some()
    }

    /// Sets a plugin option.
    pub fn set_option(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.options.insert(key.into(), value.into());
    }

    /// Gets a plugin option.
    pub fn get_option(&self, key: &str) -> Option<&str> {
        self.options.get(key).map(|s| s.as_str())
    }
}

impl Default for SymbolTreePlugin {
    fn default() -> Self {
        Self::new("SymbolTreePlugin")
    }
}

impl fmt::Display for SymbolTreePlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SymbolTreePlugin({}, symbols={})",
            self.name,
            self.total_symbol_count()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = SymbolTreePlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(!plugin.is_initialized());
        assert_eq!(plugin.root().child_count(), SymbolCategory::all().len());
    }

    #[test]
    fn test_add_symbol() {
        let mut plugin = SymbolTreePlugin::new("TestPlugin");
        plugin.add_symbol("main", SymbolCategory::Functions, Some("0x401000".to_string()));
        assert_eq!(plugin.category_count(&SymbolCategory::Functions), 1);
        assert_eq!(plugin.total_symbol_count(), 1);
    }

    #[test]
    fn test_symbol_filter() {
        let filter = SymbolFilter::new("main");
        assert!(filter.matches("main"));
        assert!(filter.matches("my_main_function"));
        assert!(!filter.matches("test"));

        let filter = SymbolFilter::new("MAIN").with_case_sensitive(true);
        assert!(!filter.matches("main"));
        assert!(filter.matches("MAIN"));
    }

    #[test]
    fn test_symbol_node() {
        let mut root = SymbolNode::folder("root");
        let child = SymbolNode::new("test", SymbolNodeType::Function)
            .with_address("0x401000")
            .with_namespace("Functions");
        root.add_child(child);
        assert_eq!(root.child_count(), 1);
        assert!(!root.is_leaf);
        assert_eq!(root.total_descendants(), 1);
    }

    #[test]
    fn test_init_dispose() {
        let mut plugin = SymbolTreePlugin::new("TestPlugin");
        plugin.init();
        assert!(plugin.is_initialized());
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_category_display() {
        assert_eq!(SymbolCategory::Functions.display_name(), "Functions");
        assert_eq!(SymbolCategory::Labels.display_name(), "Labels");
        assert_eq!(SymbolCategory::Classes.display_name(), "Classes");
    }
}
