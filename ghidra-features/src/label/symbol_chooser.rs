//! SymbolChooser -- search and select symbols (labels/functions).
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.label.SymbolChooserDialog`.
//!
//! Provides a model for filtering, searching, and selecting from the
//! program's symbol table.  Used by the label plugin and other plugins
//! that need to present a filtered list of symbols.

use super::LabelManager;
use ghidra_core::Address;

// ============================================================================
// SymbolType -- kind of symbol
// ============================================================================

/// The kind of symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolType {
    /// A label (code or data symbol).
    Label,
    /// A function symbol.
    Function,
    /// A class/namespace symbol.
    Class,
    /// A library symbol.
    Library,
    /// An external symbol (imported).
    External,
    /// A local variable symbol.
    LocalVariable,
    /// A parameter symbol.
    Parameter,
}

impl SymbolType {
    /// Human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Label => "Label",
            Self::Function => "Function",
            Self::Class => "Class",
            Self::Library => "Library",
            Self::External => "External",
            Self::LocalVariable => "Local Variable",
            Self::Parameter => "Parameter",
        }
    }
}

// ============================================================================
// SymbolEntry -- a single symbol in the chooser
// ============================================================================

/// A single symbol entry in the symbol chooser.
#[derive(Debug, Clone)]
pub struct SymbolEntry {
    /// The symbol name.
    pub name: String,
    /// The address of the symbol.
    pub address: Address,
    /// The kind of symbol.
    pub symbol_type: SymbolType,
    /// Whether this is the primary symbol at its address.
    pub primary: bool,
    /// The namespace or parent symbol (if any).
    pub namespace: Option<String>,
    /// The source of the symbol (user, analysis, import, etc.).
    pub source: String,
}

impl SymbolEntry {
    /// Create a new symbol entry.
    pub fn new(
        name: impl Into<String>,
        address: Address,
        symbol_type: SymbolType,
    ) -> Self {
        Self {
            name: name.into(),
            address,
            symbol_type,
            primary: true,
            namespace: None,
            source: "user".into(),
        }
    }

    /// Set the namespace.
    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }

    /// Set the source.
    pub fn with_source(mut self, src: impl Into<String>) -> Self {
        self.source = src.into();
        self
    }

    /// The fully qualified name (namespace::name).
    pub fn qualified_name(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{}::{}", ns, self.name),
            None => self.name.clone(),
        }
    }
}

// ============================================================================
// SymbolFilter -- filter criteria for the chooser
// ============================================================================

/// Filter criteria for the symbol chooser.
#[derive(Debug, Clone, Default)]
pub struct SymbolFilter {
    /// Only show symbols whose name contains this substring (case-insensitive).
    pub name_filter: Option<String>,
    /// Only show symbols of these types (empty = all types).
    pub type_filter: Vec<SymbolType>,
    /// Only show symbols in this address range.
    pub address_range: Option<(Address, Address)>,
    /// Only show primary symbols.
    pub primary_only: bool,
    /// Only show symbols in this namespace.
    pub namespace_filter: Option<String>,
}

impl SymbolFilter {
    /// Create a new empty filter (matches everything).
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by name substring.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name_filter = Some(name.into());
        self
    }

    /// Filter by symbol type.
    pub fn with_type(mut self, symbol_type: SymbolType) -> Self {
        self.type_filter.push(symbol_type);
        self
    }

    /// Filter by address range.
    pub fn with_address_range(mut self, start: Address, end: Address) -> Self {
        self.address_range = Some((start, end));
        self
    }

    /// Only primary symbols.
    pub fn primary_only(mut self) -> Self {
        self.primary_only = true;
        self
    }

    /// Filter by namespace.
    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace_filter = Some(ns.into());
        self
    }

    /// Check if a symbol entry matches this filter.
    pub fn matches(&self, entry: &SymbolEntry) -> bool {
        // Name filter
        if let Some(ref name) = self.name_filter {
            let name_lower = name.to_lowercase();
            if !entry.name.to_lowercase().contains(&name_lower)
                && !entry.qualified_name().to_lowercase().contains(&name_lower)
            {
                return false;
            }
        }

        // Type filter
        if !self.type_filter.is_empty() && !self.type_filter.contains(&entry.symbol_type) {
            return false;
        }

        // Address range
        if let Some((start, end)) = self.address_range {
            if entry.address.offset < start.offset || entry.address.offset > end.offset {
                return false;
            }
        }

        // Primary only
        if self.primary_only && !entry.primary {
            return false;
        }

        // Namespace filter
        if let Some(ref ns) = self.namespace_filter {
            match &entry.namespace {
                Some(entry_ns) => {
                    if !entry_ns.to_lowercase().contains(&ns.to_lowercase()) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }
}

// ============================================================================
// SymbolChooserModel -- the symbol chooser model
// ============================================================================

/// Model for the symbol chooser dialog.
///
/// Manages the symbol list, applies filters, and tracks the current selection.
#[derive(Debug)]
pub struct SymbolChooserModel {
    /// All known symbols.
    symbols: Vec<SymbolEntry>,
    /// The current filter.
    filter: SymbolFilter,
    /// Indices of symbols matching the current filter.
    filtered_indices: Vec<usize>,
    /// The currently selected index (into filtered_indices).
    selected_index: Option<usize>,
}

impl SymbolChooserModel {
    /// Create a new symbol chooser model.
    pub fn new() -> Self {
        Self {
            symbols: Vec::new(),
            filter: SymbolFilter::new(),
            filtered_indices: Vec::new(),
            selected_index: None,
        }
    }

    /// Add a symbol entry.
    pub fn add_symbol(&mut self, entry: SymbolEntry) {
        self.symbols.push(entry);
        self.refilter();
    }

    /// Add multiple symbols.
    pub fn add_symbols(&mut self, entries: impl IntoIterator<Item = SymbolEntry>) {
        for entry in entries {
            self.symbols.push(entry);
        }
        self.refilter();
    }

    /// Load symbols from a label manager.
    pub fn load_from_label_manager(&mut self, manager: &LabelManager) {
        // We'd iterate the label manager's labels, but we only have the
        // in-memory model.  In a real integration, this would query the
        // program's symbol table.
        let _ = manager;
    }

    /// Set the filter and recompute the filtered list.
    pub fn set_filter(&mut self, filter: SymbolFilter) {
        self.filter = filter;
        self.refilter();
    }

    /// Get the current filter.
    pub fn filter(&self) -> &SymbolFilter {
        &self.filter
    }

    /// Get the filtered symbol entries.
    pub fn filtered_symbols(&self) -> Vec<&SymbolEntry> {
        self.filtered_indices
            .iter()
            .filter_map(|&i| self.symbols.get(i))
            .collect()
    }

    /// The number of symbols matching the current filter.
    pub fn filtered_count(&self) -> usize {
        self.filtered_indices.len()
    }

    /// The total number of symbols.
    pub fn total_count(&self) -> usize {
        self.symbols.len()
    }

    /// Select a symbol by index (into the filtered list).
    pub fn select(&mut self, index: usize) -> bool {
        if index < self.filtered_indices.len() {
            self.selected_index = Some(index);
            true
        } else {
            false
        }
    }

    /// Get the currently selected symbol.
    pub fn selected_symbol(&self) -> Option<&SymbolEntry> {
        self.selected_index
            .and_then(|i| self.filtered_indices.get(i))
            .and_then(|&idx| self.symbols.get(idx))
    }

    /// Clear the selection.
    pub fn clear_selection(&mut self) {
        self.selected_index = None;
    }

    /// Find a symbol by name (case-insensitive exact match).
    pub fn find_by_name(&self, name: &str) -> Option<&SymbolEntry> {
        let lower = name.to_lowercase();
        self.symbols.iter().find(|e| e.name.to_lowercase() == lower)
    }

    /// Find symbols at a given address.
    pub fn find_at_address(&self, address: Address) -> Vec<&SymbolEntry> {
        self.symbols
            .iter()
            .filter(|e| e.address == address)
            .collect()
    }

    /// Get all unique namespaces.
    pub fn namespaces(&self) -> Vec<&str> {
        let mut ns: Vec<&str> = self
            .symbols
            .iter()
            .filter_map(|e| e.namespace.as_deref())
            .collect();
        ns.sort();
        ns.dedup();
        ns
    }

    /// Recompute the filtered list based on the current filter.
    fn refilter(&mut self) {
        self.filtered_indices = self
            .symbols
            .iter()
            .enumerate()
            .filter(|(_, e)| self.filter.matches(e))
            .map(|(i, _)| i)
            .collect();
        // Reset selection if it's out of bounds
        if let Some(idx) = self.selected_index {
            if idx >= self.filtered_indices.len() {
                self.selected_index = None;
            }
        }
    }
}

impl Default for SymbolChooserModel {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_symbols() -> Vec<SymbolEntry> {
        vec![
            SymbolEntry::new("main", Address::new(0x1000), SymbolType::Function)
                .with_namespace("app"),
            SymbolEntry::new("init", Address::new(0x1100), SymbolType::Function)
                .with_namespace("app"),
            SymbolEntry::new("DATA_TABLE", Address::new(0x2000), SymbolType::Label),
            SymbolEntry::new("local_var", Address::new(0x3000), SymbolType::LocalVariable)
                .with_namespace("app::main"),
            SymbolEntry::new("printf", Address::new(0x4000), SymbolType::External)
                .with_namespace("libc"),
            SymbolEntry::new("_start", Address::new(0x500), SymbolType::Label),
        ]
    }

    #[test]
    fn test_symbol_chooser_unfiltered() {
        let mut model = SymbolChooserModel::new();
        model.add_symbols(make_test_symbols());
        assert_eq!(model.total_count(), 6);
        assert_eq!(model.filtered_count(), 6);
    }

    #[test]
    fn test_symbol_chooser_name_filter() {
        let mut model = SymbolChooserModel::new();
        model.add_symbols(make_test_symbols());

        model.set_filter(SymbolFilter::new().with_name("main"));
        // Should match "main" and "local_var" (namespace contains "main")
        assert_eq!(model.filtered_count(), 2);
    }

    #[test]
    fn test_symbol_chooser_type_filter() {
        let mut model = SymbolChooserModel::new();
        model.add_symbols(make_test_symbols());

        model.set_filter(SymbolFilter::new().with_type(SymbolType::Function));
        assert_eq!(model.filtered_count(), 2); // main, init
    }

    #[test]
    fn test_symbol_chooser_namespace_filter() {
        let mut model = SymbolChooserModel::new();
        model.add_symbols(make_test_symbols());

        model.set_filter(SymbolFilter::new().with_namespace("libc"));
        assert_eq!(model.filtered_count(), 1);
    }

    #[test]
    fn test_symbol_chooser_address_range_filter() {
        let mut model = SymbolChooserModel::new();
        model.add_symbols(make_test_symbols());

        model.set_filter(
            SymbolFilter::new().with_address_range(Address::new(0x1000), Address::new(0x1FFF)),
        );
        assert_eq!(model.filtered_count(), 2); // main@0x1000, init@0x1100
    }

    #[test]
    fn test_symbol_chooser_combined_filter() {
        let mut model = SymbolChooserModel::new();
        model.add_symbols(make_test_symbols());

        model.set_filter(
            SymbolFilter::new()
                .with_type(SymbolType::Function)
                .with_namespace("app"),
        );
        assert_eq!(model.filtered_count(), 2); // main, init
    }

    #[test]
    fn test_symbol_chooser_select() {
        let mut model = SymbolChooserModel::new();
        model.add_symbols(make_test_symbols());

        assert!(model.select(0));
        let selected = model.selected_symbol().unwrap();
        assert_eq!(selected.name, "main");

        assert!(!model.select(999));
        assert!(model.selected_symbol().is_some()); // unchanged
    }

    #[test]
    fn test_symbol_chooser_clear_selection() {
        let mut model = SymbolChooserModel::new();
        model.add_symbols(make_test_symbols());
        model.select(0);
        model.clear_selection();
        assert!(model.selected_symbol().is_none());
    }

    #[test]
    fn test_symbol_chooser_find_by_name() {
        let mut model = SymbolChooserModel::new();
        model.add_symbols(make_test_symbols());

        let entry = model.find_by_name("printf").unwrap();
        assert_eq!(entry.address.offset, 0x4000);
        assert!(model.find_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_symbol_chooser_find_at_address() {
        let mut model = SymbolChooserModel::new();
        model.add_symbols(make_test_symbols());

        let entries = model.find_at_address(Address::new(0x1000));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "main");
    }

    #[test]
    fn test_symbol_chooser_namespaces() {
        let mut model = SymbolChooserModel::new();
        model.add_symbols(make_test_symbols());

        let ns = model.namespaces();
        assert!(ns.contains(&"app"));
        assert!(ns.contains(&"libc"));
        assert!(ns.contains(&"app::main"));
    }

    #[test]
    fn test_symbol_entry_qualified_name() {
        let entry = SymbolEntry::new("main", Address::new(0x1000), SymbolType::Function)
            .with_namespace("app");
        assert_eq!(entry.qualified_name(), "app::main");

        let no_ns = SymbolEntry::new("foo", Address::new(0x2000), SymbolType::Label);
        assert_eq!(no_ns.qualified_name(), "foo");
    }

    #[test]
    fn test_filter_matches_primary_only() {
        let mut entry = SymbolEntry::new("test", Address::new(0x1000), SymbolType::Label);
        entry.primary = false;

        let filter = SymbolFilter::new().primary_only();
        assert!(!filter.matches(&entry));

        entry.primary = true;
        assert!(filter.matches(&entry));
    }

    #[test]
    fn test_symbol_type_display_name() {
        assert_eq!(SymbolType::Function.display_name(), "Function");
        assert_eq!(SymbolType::Label.display_name(), "Label");
        assert_eq!(SymbolType::External.display_name(), "External");
    }

    #[test]
    fn test_filter_reset_on_add() {
        let mut model = SymbolChooserModel::new();
        model.set_filter(SymbolFilter::new().with_name("nonexistent"));
        assert_eq!(model.filtered_count(), 0);

        model.add_symbol(SymbolEntry::new(
            "nonexistent",
            Address::new(0x1000),
            SymbolType::Label,
        ));
        assert_eq!(model.filtered_count(), 1);
    }

    #[test]
    fn test_selection_reset_on_refilter() {
        let mut model = SymbolChooserModel::new();
        model.add_symbols(make_test_symbols());
        model.select(5); // _start

        // Filter to only functions - selection should reset if out of bounds
        model.set_filter(SymbolFilter::new().with_type(SymbolType::Function));
        assert_eq!(model.filtered_count(), 2);
        // Selection index 5 >= 2, so should be None
        assert!(model.selected_symbol().is_none());
    }
}
