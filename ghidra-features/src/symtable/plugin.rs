//! Symbol Table Plugin -- ported from `SymbolTablePlugin.java`.
//!
//! The [`SymbolTablePlugin`] manages the symbol table provider and
//! coordinates symbol selection, filtering, and navigation.

use super::filter::SymbolFilter;
use super::model::{SymbolRowObject, SymbolTableModel, SymbolTableKind};
use super::provider::SymbolTableConfig;

/// The symbol table plugin.
///
/// Ported from Ghidra's `SymbolTablePlugin` which extends `ProgramPlugin`.
///
/// # Example
///
/// ```
/// use ghidra_features::symtable::*;
///
/// let mut plugin = SymbolTablePlugin::new("SymTable");
/// plugin.add_symbol(SymbolRowObject::new("main", 0x401000, SymbolTableKind::Function, "Global"));
/// assert_eq!(plugin.row_count(), 1);
/// ```
#[derive(Debug)]
pub struct SymbolTablePlugin {
    /// The plugin name.
    name: String,
    /// The table model.
    model: SymbolTableModel,
    /// The current filter.
    filter: SymbolFilter,
    /// The configuration.
    config: SymbolTableConfig,
    /// The active program name, if any.
    active_program: Option<String>,
    /// Whether the plugin has been disposed.
    disposed: bool,
}

impl SymbolTablePlugin {
    /// Creates a new symbol table plugin.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            model: SymbolTableModel::default(),
            filter: SymbolFilter::default(),
            config: SymbolTableConfig::default(),
            active_program: None,
            disposed: false,
        }
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    // -- Symbol management --

    /// Adds a symbol to the table.
    pub fn add_symbol(&mut self, row: SymbolRowObject) {
        self.model.add_row(row);
    }

    /// Removes a symbol by index.
    pub fn remove_symbol(&mut self, index: usize) -> Option<SymbolRowObject> {
        self.model.remove_row(index)
    }

    /// Returns the row count.
    pub fn row_count(&self) -> usize {
        self.model.row_count()
    }

    /// Returns all rows.
    pub fn rows(&self) -> &[SymbolRowObject] {
        self.model.rows()
    }

    /// Returns the model.
    pub fn model(&self) -> &SymbolTableModel {
        &self.model
    }

    /// Returns a mutable reference to the model.
    pub fn model_mut(&mut self) -> &mut SymbolTableModel {
        &mut self.model
    }

    // -- Filter --

    /// Sets the symbol filter.
    pub fn set_filter(&mut self, filter: SymbolFilter) {
        self.filter = filter;
    }

    /// Returns the current filter.
    pub fn filter(&self) -> &SymbolFilter {
        &self.filter
    }

    /// Returns a mutable reference to the filter.
    pub fn filter_mut(&mut self) -> &mut SymbolFilter {
        &mut self.filter
    }

    /// Applies the current filter and returns the matching row indices.
    pub fn apply_filter(&self) -> Vec<usize> {
        self.model
            .rows()
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                self.filter.matches_name(row.name())
                    && self.filter.matches_address(row.address())
            })
            .map(|(i, _)| i)
            .collect()
    }

    // -- Config --

    /// Returns the configuration.
    pub fn config(&self) -> &SymbolTableConfig {
        &self.config
    }

    /// Returns a mutable reference to the configuration.
    pub fn config_mut(&mut self) -> &mut SymbolTableConfig {
        &mut self.config
    }

    // -- Program lifecycle --

    /// Sets the active program.
    pub fn program_activated(&mut self, program_name: String) {
        self.active_program = Some(program_name);
        self.model.clear();
    }

    /// Called when the active program is closed.
    pub fn program_closed(&mut self) {
        self.active_program = None;
        self.model.clear();
    }

    /// Returns the active program name.
    pub fn active_program(&self) -> Option<&str> {
        self.active_program.as_deref()
    }

    // -- Sorting --

    /// Sorts the table by address.
    pub fn sort_by_address(&mut self) {
        self.model.sort_by_address();
    }

    /// Sorts the table by name.
    pub fn sort_by_name(&mut self) {
        self.model.sort_by_name();
    }

    // -- Lookup --

    /// Finds a symbol by address.
    pub fn find_by_address(&self, addr: u64) -> Option<&SymbolRowObject> {
        self.model
            .find_by_address(addr)
            .and_then(|i| self.model.rows().get(i))
    }

    // -- Disposal --

    /// Disposes the plugin.
    pub fn dispose(&mut self) {
        self.model.clear();
        self.active_program = None;
        self.disposed = true;
    }
}

impl Default for SymbolTablePlugin {
    fn default() -> Self {
        Self::new("SymbolTable")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_row(name: &str, addr: u64) -> SymbolRowObject {
        SymbolRowObject::new(name, addr, SymbolTableKind::Function, "Global")
    }

    #[test]
    fn test_plugin_creation() {
        let plugin = SymbolTablePlugin::new("TestSymTable");
        assert_eq!(plugin.name(), "TestSymTable");
        assert!(!plugin.is_disposed());
        assert_eq!(plugin.row_count(), 0);
    }

    #[test]
    fn test_plugin_add_remove() {
        let mut plugin = SymbolTablePlugin::new("Test");
        plugin.add_symbol(make_row("main", 0x401000));
        plugin.add_symbol(make_row("init", 0x401100));
        assert_eq!(plugin.row_count(), 2);

        let removed = plugin.remove_symbol(0);
        assert!(removed.is_some());
        assert_eq!(plugin.row_count(), 1);
    }

    #[test]
    fn test_plugin_filter() {
        let mut plugin = SymbolTablePlugin::new("Test");
        plugin.add_symbol(make_row("main", 0x401000));
        plugin.add_symbol(make_row("init", 0x401100));
        plugin.add_symbol(make_row("data", 0x402000));

        let mut filter = SymbolFilter::default();
        filter.set_name_pattern(Some("main".into()));
        plugin.set_filter(filter);

        let matching = plugin.apply_filter();
        assert_eq!(matching.len(), 1);
        assert_eq!(plugin.rows()[matching[0]].name(), "main");
    }

    #[test]
    fn test_plugin_find_by_address() {
        let mut plugin = SymbolTablePlugin::new("Test");
        plugin.add_symbol(make_row("main", 0x401000));

        let found = plugin.find_by_address(0x401000);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name(), "main");

        assert!(plugin.find_by_address(0x9999).is_none());
    }

    #[test]
    fn test_plugin_sort() {
        let mut plugin = SymbolTablePlugin::new("Test");
        plugin.add_symbol(make_row("zebra", 0x2000));
        plugin.add_symbol(make_row("alpha", 0x1000));

        plugin.sort_by_address();
        assert_eq!(plugin.rows()[0].name(), "alpha");

        plugin.sort_by_name();
        assert_eq!(plugin.rows()[0].name(), "alpha");
    }

    #[test]
    fn test_plugin_program_lifecycle() {
        let mut plugin = SymbolTablePlugin::new("Test");
        assert!(plugin.active_program().is_none());

        plugin.program_activated("test.exe".to_string());
        assert_eq!(plugin.active_program(), Some("test.exe"));

        plugin.add_symbol(make_row("main", 0x401000));
        plugin.program_closed();
        assert!(plugin.active_program().is_none());
        assert_eq!(plugin.row_count(), 0);
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = SymbolTablePlugin::new("Test");
        plugin.add_symbol(make_row("a", 0x1000));
        plugin.dispose();
        assert!(plugin.is_disposed());
        assert_eq!(plugin.row_count(), 0);
    }

    #[test]
    fn test_plugin_config() {
        let mut plugin = SymbolTablePlugin::new("Test");
        assert!(plugin.config().show_address_hex);
        plugin.config_mut().show_address_hex = true;
        assert!(plugin.config().show_address_hex);
    }
}
