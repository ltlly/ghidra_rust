//! Symbol tree provider -- ported from `SymbolTreeProvider.java`.
//!
//! The [`SymbolTreeProvider`] manages the tree model that backs the
//! symbol tree UI panel.  It watches the program's symbol table for
//! changes and rebuilds the tree accordingly.
//!
//! In Ghidra Java the provider extends `ComponentProviderDocking` and
//! renders a Swing `GTree`.  Here we keep the data model and the tree-
//! rebuild logic; rendering is delegated to `ghidra-gui`.

use ghidra_core::symbol::{SymbolType, Symbol, SymbolPath};
use serde::{Deserialize, Serialize};

use super::category::{SymbolCategory, all_categories};

/// Configuration for the symbol tree display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolTreeConfig {
    /// The maximum number of child nodes before the tree introduces
    /// intermediate grouping nodes by first character.
    pub group_threshold: usize,
    /// Whether to show namespace symbols in the tree.
    pub show_namespaces: bool,
    /// Whether to show library symbols in the tree.
    pub show_libraries: bool,
    /// Whether to show class symbols in the tree.
    pub show_classes: bool,
    /// Whether to sort alphabetically within each category.
    pub sort_alphabetically: bool,
}

impl Default for SymbolTreeConfig {
    fn default() -> Self {
        Self {
            group_threshold: 200,
            show_namespaces: true,
            show_libraries: true,
            show_classes: true,
            sort_alphabetically: true,
        }
    }
}

// ---------------------------------------------------------------------------
// SymbolTreeProvider
// ---------------------------------------------------------------------------

/// Manages the tree model for a connected or disconnected symbol tree panel.
///
/// A connected provider is tied to the currently active program and receives
/// symbol-table change notifications.  A disconnected provider holds a
/// snapshot that does not update.
///
/// # Example
///
/// ```
/// use ghidra_features::base::symbol::{SymbolTreeProvider, SymbolTreeConfig};
///
/// let provider = SymbolTreeProvider::new_connected("Main Symbol Tree");
/// let config = provider.config();
/// assert_eq!(config.group_threshold, 200);
/// ```
#[derive(Debug)]
pub struct SymbolTreeProvider {
    /// Display name for this provider.
    name: String,
    /// Whether this provider is connected to the active program.
    connected: bool,
    /// Current configuration.
    config: SymbolTreeConfig,
    /// The flat list of symbols that populate the tree.
    symbols: Vec<Symbol>,
    /// The current program name (if a program is loaded).
    program_name: Option<String>,
    /// Grouped tree data built from `symbols` and `config`.
    tree_root: Option<GroupedTreeRoot>,
}

/// The root of the grouped symbol tree.
#[derive(Debug, Clone)]
pub struct GroupedTreeRoot {
    /// Display name of the root node.
    pub name: String,
    /// Category children of the root.
    pub categories: Vec<CategoryNode>,
}

/// A category node in the grouped tree.
#[derive(Debug, Clone)]
pub struct CategoryNode {
    /// The category metadata.
    pub category: SymbolCategory,
    /// Child symbol entries.
    pub entries: Vec<SymbolEntry>,
    /// Sub-groups (when the number of entries exceeds the threshold).
    pub sub_groups: Vec<GroupNode>,
}

/// A leaf symbol entry in the tree.
#[derive(Debug, Clone)]
pub struct SymbolEntry {
    /// The symbol path in the hierarchy.
    pub path: SymbolPath,
    /// The symbol type.
    pub symbol_type: SymbolType,
    /// Whether the symbol is external.
    pub is_external: bool,
    /// The symbol name (display).
    pub name: String,
}

/// An intermediate grouping node (e.g., symbols starting with "a" through "f").
#[derive(Debug, Clone)]
pub struct GroupNode {
    /// Label for this group (e.g., "A-F", "G-M").
    pub label: String,
    /// Symbols in this group.
    pub entries: Vec<SymbolEntry>,
}

impl SymbolTreeProvider {
    /// Creates a new connected provider.
    pub fn new_connected(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            connected: true,
            config: SymbolTreeConfig::default(),
            symbols: Vec::new(),
            program_name: None,
            tree_root: None,
        }
    }

    /// Creates a new disconnected provider (snapshot mode).
    pub fn new_disconnected(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            connected: false,
            config: SymbolTreeConfig::default(),
            symbols: Vec::new(),
            program_name: None,
            tree_root: None,
        }
    }

    /// Returns the display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns `true` if this provider is connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Returns the current configuration.
    pub fn config(&self) -> &SymbolTreeConfig {
        &self.config
    }

    /// Updates the configuration and triggers a tree rebuild.
    pub fn set_config(&mut self, config: SymbolTreeConfig) {
        self.config = config;
        self.rebuild_tree();
    }

    /// Sets the program name for this provider.
    pub fn set_program_name(&mut self, name: Option<String>) {
        self.program_name = name;
    }

    /// Returns the program name, if set.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Returns the current symbol list.
    pub fn symbols(&self) -> &[Symbol] {
        &self.symbols
    }

    /// Replaces the symbol list (typically from the program's symbol table)
    /// and rebuilds the tree.
    pub fn set_symbols(&mut self, symbols: Vec<Symbol>) {
        self.symbols = symbols;
        self.rebuild_tree();
    }

    /// Adds a single symbol and inserts it into the tree.
    pub fn add_symbol(&mut self, symbol: Symbol) {
        self.symbols.push(symbol);
        // Incremental update: for simplicity we rebuild the whole tree.
        // A production implementation would insert into the correct
        // category node directly.
        self.rebuild_tree();
    }

    /// Removes all occurrences of the given symbol (by name + address).
    pub fn remove_symbol(&mut self, name: &str, addr_offset: u64) -> bool {
        let before = self.symbols.len();
        self.symbols.retain(|s| {
            !(s.name() == name && s.address().offset == addr_offset)
        });
        if self.symbols.len() < before {
            self.rebuild_tree();
            true
        } else {
            false
        }
    }

    /// Returns a reference to the built tree root, if available.
    pub fn tree_root(&self) -> Option<&GroupedTreeRoot> {
        self.tree_root.as_ref()
    }

    /// Triggers a full tree rebuild from the current symbol list and config.
    pub fn rebuild_tree(&mut self) {
        let mut categories = Vec::new();

        for cat_def in all_categories() {
            if cat_def.is_root() {
                // Root collects everything; skip for now (handled
                // differently in the full Ghidra UI).
                continue;
            }

            let mut entries: Vec<SymbolEntry> = self
                .symbols
                .iter()
                .filter(|s| cat_def.accepts(s.kind()))
                .map(|s| SymbolEntry {
                    path: s.path(),
                    symbol_type: s.kind(),
                    is_external: s.is_external_symbol(),
                    name: s.name(),
                })
                .collect();

            if self.config.sort_alphabetically {
                entries.sort_by(|a, b| a.name.cmp(&b.name));
            }

            // If the number of entries exceeds the threshold, create
            // sub-groups.
            let sub_groups = if entries.len() > self.config.group_threshold {
                Self::make_sub_groups(std::mem::take(&mut self.config.group_threshold), &mut entries)
            } else {
                Vec::new()
            };

            categories.push(CategoryNode {
                category: cat_def,
                entries,
                sub_groups,
            });
        }

        self.tree_root = Some(GroupedTreeRoot {
            name: "Global".to_string(),
            categories,
        });
    }

    fn make_sub_groups(threshold: usize, entries: &mut Vec<SymbolEntry>) -> Vec<GroupNode> {
        // Simple alphabetical sub-grouping: split into chunks of
        // `threshold` entries.
        let chunks: Vec<Vec<SymbolEntry>> = entries
            .chunks(threshold)
            .map(|c| c.to_vec())
            .collect();
        chunks
            .into_iter()
            .enumerate()
            .map(|(i, chunk)| {
                let first = chunk.first().map(|e| e.name.clone()).unwrap_or_default();
                let last = chunk.last().map(|e| e.name.clone()).unwrap_or_default();
                GroupNode {
                    label: format!("{}-{}", first.chars().next().unwrap_or('?'), last.chars().next().unwrap_or('?')),
                    entries: chunk,
                }
            })
            .collect()
    }

    /// Returns the total number of symbols in the tree.
    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }

    /// Finds symbols matching the given name (case-sensitive).
    pub fn find_by_name(&self, name: &str) -> Vec<&Symbol> {
        self.symbols.iter().filter(|s| s.name() == name).collect()
    }

    /// Finds symbols at the given address offset.
    pub fn find_by_address(&self, offset: u64) -> Vec<&Symbol> {
        self.symbols
            .iter()
            .filter(|s| s.address().offset == offset)
            .collect()
    }

    /// Navigates to a symbol in the tree by path.
    pub fn navigate_to_path(&self, path: &SymbolPath) -> Option<&SymbolEntry> {
        if let Some(root) = &self.tree_root {
            for cat in &root.categories {
                for entry in &cat.entries {
                    if entry.path == *path {
                        return Some(entry);
                    }
                }
            }
        }
        None
    }

    /// Returns the number of categories in the tree.
    pub fn category_count(&self) -> usize {
        self.tree_root
            .as_ref()
            .map(|r| r.categories.len())
            .unwrap_or(0)
    }

    /// Clears all symbols and the tree.
    pub fn clear(&mut self) {
        self.symbols.clear();
        self.tree_root = None;
    }
}

// ---------------------------------------------------------------------------
// Serialization helpers for config state persistence
// ---------------------------------------------------------------------------

impl SymbolTreeConfig {
    /// Serialize configuration to JSON for `SaveState` equivalent.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Deserialize configuration from JSON.
    pub fn from_json(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;

    fn make_symbols() -> Vec<Symbol> {
        vec![
            Symbol::function("main", Address::new(0x401000)),
            Symbol::function("init", Address::new(0x401100)),
            Symbol::label("loop_start", Address::new(0x401010)),
            Symbol::library("libc.so.6"),
            Symbol::import("printf", Address::new(0)),
            Symbol::export("_start", Address::new(0x401000)),
        ]
    }

    #[test]
    fn test_provider_creation() {
        let p = SymbolTreeProvider::new_connected("Test");
        assert!(p.is_connected());
        assert_eq!(p.name(), "Test");
        assert_eq!(p.symbol_count(), 0);
    }

    #[test]
    fn test_disconnected_provider() {
        let p = SymbolTreeProvider::new_disconnected("Snapshot");
        assert!(!p.is_connected());
    }

    #[test]
    fn test_set_symbols_and_rebuild() {
        let mut p = SymbolTreeProvider::new_connected("Test");
        p.set_symbols(make_symbols());
        assert_eq!(p.symbol_count(), 6);
        assert!(p.tree_root().is_some());
        assert!(p.category_count() > 0);
    }

    #[test]
    fn test_add_and_remove_symbol() {
        let mut p = SymbolTreeProvider::new_connected("Test");
        p.add_symbol(Symbol::function("foo", Address::new(0x500000)));
        assert_eq!(p.symbol_count(), 1);
        assert!(p.remove_symbol("foo", 0x500000));
        assert_eq!(p.symbol_count(), 0);
    }

    #[test]
    fn test_find_by_name() {
        let mut p = SymbolTreeProvider::new_connected("Test");
        p.set_symbols(make_symbols());
        let found = p.find_by_name("main");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name(), "main");
    }

    #[test]
    fn test_find_by_address() {
        let mut p = SymbolTreeProvider::new_connected("Test");
        p.set_symbols(make_symbols());
        let found = p.find_by_address(0x401000);
        assert_eq!(found.len(), 2); // main + _start
    }

    #[test]
    fn test_clear() {
        let mut p = SymbolTreeProvider::new_connected("Test");
        p.set_symbols(make_symbols());
        p.clear();
        assert_eq!(p.symbol_count(), 0);
        assert!(p.tree_root().is_none());
    }

    #[test]
    fn test_config_json_roundtrip() {
        let config = SymbolTreeConfig {
            group_threshold: 500,
            show_namespaces: false,
            ..Default::default()
        };
        let json = config.to_json();
        let restored = SymbolTreeConfig::from_json(&json).unwrap();
        assert_eq!(restored.group_threshold, 500);
        assert!(!restored.show_namespaces);
    }

    #[test]
    fn test_program_name() {
        let mut p = SymbolTreeProvider::new_connected("Test");
        assert!(p.program_name().is_none());
        p.set_program_name(Some("test_binary".to_string()));
        assert_eq!(p.program_name(), Some("test_binary"));
    }

    #[test]
    fn test_tree_structure() {
        let mut p = SymbolTreeProvider::new_connected("Test");
        p.set_symbols(make_symbols());
        let root = p.tree_root().unwrap();
        assert_eq!(root.name, "Global");
        // Should have categories for functions, exports, imports, labels,
        // namespaces, classes
        assert!(root.categories.len() >= 4);

        // Check that functions are in the functions category
        let func_cat = root
            .categories
            .iter()
            .find(|c| c.category.name() == "Functions")
            .unwrap();
        assert_eq!(func_cat.entries.len(), 2); // main, init
    }

    #[test]
    fn test_navigate_to_path() {
        let mut p = SymbolTreeProvider::new_connected("Test");
        p.set_symbols(make_symbols());
        // Symbol::path() uses SymbolApi::get_path() which returns
        // vec![name] for concrete symbols, so the path is just ["main"].
        let path = SymbolPath::from_segments(vec!["main".to_string()]);
        let entry = p.navigate_to_path(&path);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().name, "main");
    }
}
