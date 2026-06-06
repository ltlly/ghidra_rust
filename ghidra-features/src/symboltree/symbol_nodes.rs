//! Extended symbol tree node types and search functionality.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.symboltree` Java package.
//!
//! Provides higher-level node operations:
//! - `SymbolNodeData` -- data payload for symbol tree nodes
//! - `SymbolSearchResult` -- result of searching the symbol tree
//! - `SymbolTreeState` -- serializable tree expansion and selection state
//! - Node creation helpers for common symbol patterns

use serde::{Deserialize, Serialize};

/// The kind of symbol represented in the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolNodeKind {
    /// A function symbol.
    Function,
    /// A label (code address) symbol.
    Label,
    /// A class or namespace.
    Class,
    /// An external library.
    Library,
    /// A generic namespace.
    Namespace,
    /// A function parameter.
    Parameter,
    /// A local variable.
    LocalVariable,
    /// An external location.
    External,
    /// A "load more" placeholder.
    More,
}

impl SymbolNodeKind {
    /// Display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Function => "Function",
            Self::Label => "Label",
            Self::Class => "Class",
            Self::Library => "Library",
            Self::Namespace => "Namespace",
            Self::Parameter => "Parameter",
            Self::LocalVariable => "Local Variable",
            Self::External => "External",
            Self::More => "More...",
        }
    }

    /// Whether this kind can have child nodes.
    pub fn can_have_children(&self) -> bool {
        matches!(self, Self::Class | Self::Namespace | Self::Library | Self::Function)
    }
}

/// Data payload for a symbol tree node.
///
/// Ported from `ghidra.app.plugin.core.symboltree.SymbolNode`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolNodeData {
    /// The symbol name.
    pub name: String,
    /// The kind of symbol.
    pub kind: SymbolNodeKind,
    /// The address (as string).
    pub address: Option<String>,
    /// The full namespace path.
    pub namespace_path: String,
    /// Whether this is the primary symbol at its address.
    pub is_primary: bool,
    /// Whether this symbol is pinned.
    pub is_pinned: bool,
    /// Source type (USER_DEFINED, ANALYSIS, IMPORTED, etc.).
    pub source_type: String,
}

impl SymbolNodeData {
    /// Create new symbol node data.
    pub fn new(
        name: impl Into<String>,
        kind: SymbolNodeKind,
        address: Option<String>,
    ) -> Self {
        let name = name.into();
        Self {
            namespace_path: name.clone(),
            name,
            kind,
            address,
            is_primary: true,
            is_pinned: false,
            source_type: "USER_DEFINED".into(),
        }
    }

    /// Create a function symbol node.
    pub fn function(name: impl Into<String>, address: impl Into<String>) -> Self {
        Self::new(name, SymbolNodeKind::Function, Some(address.into()))
    }

    /// Create a label symbol node.
    pub fn label(name: impl Into<String>, address: impl Into<String>) -> Self {
        Self::new(name, SymbolNodeKind::Label, Some(address.into()))
    }

    /// Create a class/namespace node.
    pub fn class(name: impl Into<String>) -> Self {
        Self::new(name, SymbolNodeKind::Class, None)
    }

    /// Create a library node.
    pub fn library(name: impl Into<String>) -> Self {
        Self::new(name, SymbolNodeKind::Library, None)
    }

    /// Create a namespace node.
    pub fn namespace(name: impl Into<String>) -> Self {
        Self::new(name, SymbolNodeKind::Namespace, None)
    }

    /// Create a parameter node.
    pub fn parameter(name: impl Into<String>) -> Self {
        Self::new(name, SymbolNodeKind::Parameter, None)
    }

    /// Create a local variable node.
    pub fn local_variable(name: impl Into<String>) -> Self {
        Self::new(name, SymbolNodeKind::LocalVariable, None)
    }

    /// Create an external symbol node.
    pub fn external(name: impl Into<String>, library: impl Into<String>) -> Self {
        let mut node = Self::new(name, SymbolNodeKind::External, None);
        node.source_type = "IMPORTED".into();
        node.namespace_path = format!("External::{}", library.into());
        node
    }
}

/// Result of searching the symbol tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolSearchResult {
    /// Matching symbol names.
    pub matches: Vec<SymbolNodeData>,
    /// Total number of matches.
    pub total_count: usize,
    /// Whether results were truncated.
    pub truncated: bool,
    /// The search pattern used.
    pub pattern: String,
}

impl SymbolSearchResult {
    /// Create a new search result.
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            matches: Vec::new(),
            total_count: 0,
            truncated: false,
            pattern: pattern.into(),
        }
    }

    /// Add a match.
    pub fn add_match(&mut self, node: SymbolNodeData) {
        self.matches.push(node);
        self.total_count += 1;
    }

    /// Whether the search found any results.
    pub fn has_results(&self) -> bool {
        !self.matches.is_empty()
    }
}

/// Serializable state of the symbol tree (expansion, selection, scroll position).
///
/// Used to save and restore the tree view state between sessions.
///
/// Ported from `ghidra.app.plugin.core.symboltree.SymbolTreeProvider`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolTreeState {
    /// Paths of expanded nodes.
    pub expanded_paths: Vec<String>,
    /// The currently selected path.
    pub selected_path: Option<String>,
    /// The scroll position.
    pub scroll_position: usize,
    /// Whether to show only pinned nodes.
    pub show_pinned_only: bool,
    /// The filter text.
    pub filter_text: String,
}

impl SymbolTreeState {
    /// Create a new empty state.
    pub fn new() -> Self {
        Self {
            expanded_paths: Vec::new(),
            selected_path: None,
            scroll_position: 0,
            show_pinned_only: false,
            filter_text: String::new(),
        }
    }

    /// Add an expanded path.
    pub fn expand(&mut self, path: impl Into<String>) {
        let path = path.into();
        if !self.expanded_paths.contains(&path) {
            self.expanded_paths.push(path);
        }
    }

    /// Collapse a path.
    pub fn collapse(&mut self, path: &str) {
        self.expanded_paths.retain(|p| p != path);
    }

    /// Whether a path is expanded.
    pub fn is_expanded(&self, path: &str) -> bool {
        self.expanded_paths.contains(&path.to_string())
    }

    /// Clear all state.
    pub fn clear(&mut self) {
        self.expanded_paths.clear();
        self.selected_path = None;
        self.scroll_position = 0;
        self.filter_text.clear();
    }
}

impl Default for SymbolTreeState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_node_kind_display() {
        assert_eq!(SymbolNodeKind::Function.display_name(), "Function");
        assert_eq!(SymbolNodeKind::Class.display_name(), "Class");
        assert_eq!(SymbolNodeKind::Library.display_name(), "Library");
        assert_eq!(SymbolNodeKind::More.display_name(), "More...");
    }

    #[test]
    fn test_symbol_node_kind_children() {
        assert!(SymbolNodeKind::Class.can_have_children());
        assert!(SymbolNodeKind::Namespace.can_have_children());
        assert!(SymbolNodeKind::Library.can_have_children());
        assert!(SymbolNodeKind::Function.can_have_children());
        assert!(!SymbolNodeKind::Label.can_have_children());
        assert!(!SymbolNodeKind::Parameter.can_have_children());
    }

    #[test]
    fn test_symbol_node_data_creation() {
        let func = SymbolNodeData::function("main", "0x401000");
        assert_eq!(func.name, "main");
        assert_eq!(func.kind, SymbolNodeKind::Function);
        assert_eq!(func.address, Some("0x401000".into()));
        assert!(func.is_primary);

        let label = SymbolNodeData::label("start", "0x400000");
        assert_eq!(label.kind, SymbolNodeKind::Label);

        let class = SymbolNodeData::class("MyClass");
        assert_eq!(class.kind, SymbolNodeKind::Class);
        assert!(class.address.is_none());

        let lib = SymbolNodeData::library("libc.so");
        assert_eq!(lib.kind, SymbolNodeKind::Library);

        let ns = SymbolNodeData::namespace("MyNamespace");
        assert_eq!(ns.kind, SymbolNodeKind::Namespace);

        let param = SymbolNodeData::parameter("argc");
        assert_eq!(param.kind, SymbolNodeKind::Parameter);

        let local = SymbolNodeData::local_variable("temp");
        assert_eq!(local.kind, SymbolNodeKind::LocalVariable);
    }

    #[test]
    fn test_symbol_node_data_external() {
        let ext = SymbolNodeData::external("printf", "libc.so");
        assert_eq!(ext.kind, SymbolNodeKind::External);
        assert_eq!(ext.source_type, "IMPORTED");
        assert!(ext.namespace_path.contains("libc.so"));
    }

    #[test]
    fn test_symbol_search_result() {
        let mut result = SymbolSearchResult::new("main");
        assert!(!result.has_results());

        result.add_match(SymbolNodeData::function("main", "0x401000"));
        result.add_match(SymbolNodeData::function("main_loop", "0x401200"));

        assert!(result.has_results());
        assert_eq!(result.total_count, 2);
        assert!(!result.truncated);
        assert_eq!(result.pattern, "main");
    }

    #[test]
    fn test_symbol_tree_state() {
        let mut state = SymbolTreeState::new();
        assert!(state.expanded_paths.is_empty());
        assert!(state.selected_path.is_none());

        state.expand("Global::MyClass");
        state.expand("Global::MyNamespace");
        assert!(state.is_expanded("Global::MyClass"));
        assert!(state.is_expanded("Global::MyNamespace"));
        assert!(!state.is_expanded("Global::Other"));

        state.collapse("Global::MyClass");
        assert!(!state.is_expanded("Global::MyClass"));
        assert!(state.is_expanded("Global::MyNamespace"));
    }

    #[test]
    fn test_symbol_tree_state_no_duplicate_expand() {
        let mut state = SymbolTreeState::new();
        state.expand("test");
        state.expand("test");
        assert_eq!(state.expanded_paths.len(), 1);
    }

    #[test]
    fn test_symbol_tree_state_clear() {
        let mut state = SymbolTreeState::new();
        state.expand("a");
        state.expand("b");
        state.selected_path = Some("a".into());
        state.scroll_position = 100;
        state.filter_text = "test".into();

        state.clear();
        assert!(state.expanded_paths.is_empty());
        assert!(state.selected_path.is_none());
        assert_eq!(state.scroll_position, 0);
        assert!(state.filter_text.is_empty());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let node = SymbolNodeData::function("main", "0x401000");
        let json = serde_json::to_string(&node).unwrap();
        let deserialized: SymbolNodeData = serde_json::from_str(&json).unwrap();
        assert_eq!(node.name, deserialized.name);
        assert_eq!(node.kind, deserialized.kind);

        let mut state = SymbolTreeState::new();
        state.expand("Global");
        state.selected_path = Some("Global::main".into());
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: SymbolTreeState = serde_json::from_str(&json).unwrap();
        assert_eq!(state.expanded_paths, deserialized.expanded_paths);
    }
}
