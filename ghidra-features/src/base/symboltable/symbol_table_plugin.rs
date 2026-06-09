//! Symbol Table Plugin -- ported from `SymbolTablePlugin.java`.
//!
//! The [`SymbolTablePlugin`] is the central controller for the flat symbol
//! table view.  It owns a [`super::symbol_table_provider::SymbolTableProvider`]
//! and a [`SymbolTableModel`] and coordinates filtering, sorting, and
//! program lifecycle events.
//!
//! # Key Concepts
//!
//! - **Flat table** -- unlike the hierarchical symbol tree, the symbol
//!   table shows every symbol as a single row.
//! - **Filtering** -- the user can narrow visible symbols by name
//!   pattern, kind, namespace, and address range.
//! - **Sorting** -- columns are independently sortable (name, address,
//!   kind, namespace, source).
//! - **Program lifecycle** -- the plugin clears and repopulates the
//!   model when the active program changes.

use std::fmt;

// ---------------------------------------------------------------------------
// EntryKind -- symbol kind for table display
// ---------------------------------------------------------------------------

/// The kind of symbol as displayed in the symbol table.
///
/// This is a display-oriented classification; the canonical type is
/// [`ghidra_core::SymbolType`], but for the flat table we use a
/// simpler enum that covers the columns the user sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    /// A function symbol.
    Function,
    /// A label (code or data).
    Label,
    /// A class or namespace.
    Class,
    /// A library.
    Library,
    /// An external location.
    External,
    /// A parameter.
    Parameter,
    /// A local variable.
    Local,
    /// An unknown or custom type.
    Unknown,
}

impl fmt::Display for EntryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Function => write!(f, "Function"),
            Self::Label => write!(f, "Label"),
            Self::Class => write!(f, "Class"),
            Self::Library => write!(f, "Library"),
            Self::External => write!(f, "External"),
            Self::Parameter => write!(f, "Parameter"),
            Self::Local => write!(f, "Local"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// SymbolTableEntry -- a single row in the symbol table
// ---------------------------------------------------------------------------

/// One row in the flat symbol table.
///
/// Ported from `SymbolRowObject.java`.
#[derive(Debug, Clone)]
pub struct SymbolTableEntry {
    /// Symbol name.
    name: String,
    /// Symbol address (raw offset).
    address: u64,
    /// Symbol kind.
    kind: EntryKind,
    /// Namespace path (e.g., `"Global"`, `"libc"`).
    namespace: String,
    /// Source of the symbol (`"User"`, `"Analysis"`, `"Imported"`).
    source: String,
    /// Whether this is the primary symbol at its address.
    is_primary: bool,
    /// Whether this is an external symbol.
    is_external: bool,
    /// Whether the symbol is pinned.
    is_pinned: bool,
    /// Unique symbol ID.
    id: u64,
}

impl SymbolTableEntry {
    /// Creates a new symbol table entry.
    pub fn new(
        name: impl Into<String>,
        address: u64,
        kind: EntryKind,
        namespace: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            address,
            kind,
            namespace: namespace.into(),
            source: "User".to_string(),
            is_primary: false,
            is_external: false,
            is_pinned: false,
            id: 0,
        }
    }

    /// Returns the symbol name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the address.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Returns the kind.
    pub fn kind(&self) -> EntryKind {
        self.kind
    }

    /// Returns the namespace.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Returns the source.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns whether this is the primary symbol.
    pub fn is_primary(&self) -> bool {
        self.is_primary
    }

    /// Returns whether this is external.
    pub fn is_external(&self) -> bool {
        self.is_external
    }

    /// Returns whether the symbol is pinned.
    pub fn is_pinned(&self) -> bool {
        self.is_pinned
    }

    /// Returns the symbol ID.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Sets the primary flag.
    pub fn set_primary(&mut self, primary: bool) {
        self.is_primary = primary;
    }

    /// Sets the external flag.
    pub fn set_external(&mut self, external: bool) {
        self.is_external = external;
    }

    /// Sets the symbol ID.
    pub fn set_id(&mut self, id: u64) {
        self.id = id;
    }

    /// Sets the source.
    pub fn set_source(&mut self, source: impl Into<String>) {
        self.source = source.into();
    }

    /// Returns the fully qualified display name.
    pub fn qualified_name(&self) -> String {
        if self.namespace.is_empty() || self.namespace == "Global" {
            self.name.clone()
        } else {
            format!("{}::{}", self.namespace, self.name)
        }
    }

    /// Returns the display text for a given column index.
    ///
    /// Column order: 0=name, 1=address, 2=kind, 3=namespace,
    /// 4=source, 5=primary.
    pub fn column_text(&self, col: usize) -> String {
        match col {
            0 => self.name.clone(),
            1 => format!("0x{:x}", self.address),
            2 => self.kind.to_string(),
            3 => self.namespace.clone(),
            4 => self.source.clone(),
            5 => {
                if self.is_primary {
                    "Y".into()
                } else {
                    "N".into()
                }
            }
            _ => String::new(),
        }
    }
}

impl fmt::Display for SymbolTableEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} @ 0x{:x} ({})", self.name, self.address, self.kind)
    }
}

// ---------------------------------------------------------------------------
// SymbolTableModel -- the backing data model
// ---------------------------------------------------------------------------

/// Column identifiers for the symbol table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TableColumn {
    Name,
    Address,
    Kind,
    Namespace,
    Source,
    Primary,
}

impl fmt::Display for TableColumn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name => write!(f, "Name"),
            Self::Address => write!(f, "Address"),
            Self::Kind => write!(f, "Kind"),
            Self::Namespace => write!(f, "Namespace"),
            Self::Source => write!(f, "Source"),
            Self::Primary => write!(f, "Primary"),
        }
    }
}

/// The abstract symbol table model.
///
/// Stores the rows, supports add/remove/sort/undo and cell value
/// queries.  Ported from `AbstractSymbolTableModel`.
#[derive(Debug, Clone)]
pub struct SymbolTableModel {
    columns: Vec<TableColumn>,
    rows: Vec<SymbolTableEntry>,
    /// Deleted rows kept for undo support.
    deleted: Vec<SymbolTableEntry>,
    editable: bool,
}

impl SymbolTableModel {
    /// Creates a new model with default columns.
    pub fn new(editable: bool) -> Self {
        Self {
            columns: vec![
                TableColumn::Name,
                TableColumn::Address,
                TableColumn::Kind,
                TableColumn::Namespace,
                TableColumn::Source,
                TableColumn::Primary,
            ],
            rows: Vec::new(),
            deleted: Vec::new(),
            editable,
        }
    }

    /// Returns the column definitions.
    pub fn columns(&self) -> &[TableColumn] {
        &self.columns
    }

    /// Returns the number of columns.
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Returns the rows.
    pub fn rows(&self) -> &[SymbolTableEntry] {
        &self.rows
    }

    /// Returns the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Returns `true` if there are no rows.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Adds a row.
    pub fn add_row(&mut self, entry: SymbolTableEntry) {
        self.rows.push(entry);
    }

    /// Removes a row by index, tracking it for undo.
    pub fn remove_row(&mut self, index: usize) -> Option<SymbolTableEntry> {
        if index < self.rows.len() {
            let entry = self.rows.remove(index);
            self.deleted.push(entry.clone());
            Some(entry)
        } else {
            None
        }
    }

    /// Gets a cell value by row and column index.
    pub fn get_value_at(&self, row: usize, col: usize) -> Option<String> {
        let r = self.rows.get(row)?;
        Some(r.column_text(col))
    }

    /// Returns whether the model is editable.
    pub fn is_editable(&self) -> bool {
        self.editable
    }

    /// Sets whether the model is editable.
    pub fn set_editable(&mut self, editable: bool) {
        self.editable = editable;
    }

    /// Returns the deleted rows (for undo).
    pub fn deleted_rows(&self) -> &[SymbolTableEntry] {
        &self.deleted
    }

    /// Restores the last deleted row.
    pub fn undo_last_delete(&mut self) -> Option<SymbolTableEntry> {
        let entry = self.deleted.pop()?;
        self.rows.push(entry.clone());
        Some(entry)
    }

    /// Clears all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
    }

    /// Sorts rows by address.
    pub fn sort_by_address(&mut self) {
        self.rows.sort_by_key(|r| r.address());
    }

    /// Sorts rows by name (case-insensitive).
    pub fn sort_by_name(&mut self) {
        self.rows
            .sort_by(|a, b| a.name().to_lowercase().cmp(&b.name().to_lowercase()));
    }

    /// Sorts rows by kind.
    pub fn sort_by_kind(&mut self) {
        self.rows.sort_by_key(|r| r.kind().to_string());
    }

    /// Returns the index of the row at the given address, if any.
    pub fn find_by_address(&self, addr: u64) -> Option<usize> {
        self.rows.iter().position(|r| r.address() == addr)
    }
}

impl Default for SymbolTableModel {
    fn default() -> Self {
        Self::new(true)
    }
}

// ---------------------------------------------------------------------------
// SymbolFilter -- filter criteria for the table
// ---------------------------------------------------------------------------

/// Filter criteria applied to the symbol table.
///
/// Ported from `SymbolFilter.java` / `NewSymbolFilter.java`.
#[derive(Debug, Clone, Default)]
pub struct SymbolFilter {
    /// Name substring pattern (case-insensitive).
    name_pattern: Option<String>,
    /// Restrict to a specific kind.
    kind: Option<EntryKind>,
    /// Restrict to a namespace.
    namespace: Option<String>,
    /// Minimum address (inclusive).
    addr_min: Option<u64>,
    /// Maximum address (inclusive).
    addr_max: Option<u64>,
}

impl SymbolFilter {
    /// Creates a new empty filter (matches everything).
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the name pattern.
    pub fn set_name_pattern(&mut self, pattern: Option<String>) {
        self.name_pattern = pattern;
    }

    /// Returns the name pattern.
    pub fn name_pattern(&self) -> Option<&str> {
        self.name_pattern.as_deref()
    }

    /// Sets the kind filter.
    pub fn set_kind(&mut self, kind: Option<EntryKind>) {
        self.kind = kind;
    }

    /// Returns the kind filter.
    pub fn kind_filter(&self) -> Option<EntryKind> {
        self.kind
    }

    /// Sets the namespace filter.
    pub fn set_namespace(&mut self, ns: Option<String>) {
        self.namespace = ns;
    }

    /// Returns the namespace filter.
    pub fn namespace_filter(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// Sets the address range.
    pub fn set_address_range(&mut self, min: Option<u64>, max: Option<u64>) {
        self.addr_min = min;
        self.addr_max = max;
    }

    /// Tests whether a name matches the name pattern.
    pub fn matches_name(&self, name: &str) -> bool {
        match &self.name_pattern {
            Some(pat) => name.to_lowercase().contains(&pat.to_lowercase()),
            None => true,
        }
    }

    /// Tests whether an address matches the address range.
    pub fn matches_address(&self, addr: u64) -> bool {
        if let Some(min) = self.addr_min {
            if addr < min {
                return false;
            }
        }
        if let Some(max) = self.addr_max {
            if addr > max {
                return false;
            }
        }
        true
    }

    /// Tests whether a full entry matches all filter criteria.
    pub fn matches(&self, entry: &SymbolTableEntry) -> bool {
        self.matches_name(entry.name())
            && self.matches_address(entry.address())
            && self.kind.map_or(true, |k| k == entry.kind())
            && self
                .namespace
                .as_ref()
                .map_or(true, |ns| ns == entry.namespace())
    }
}

// ---------------------------------------------------------------------------
// SymbolTablePlugin -- the main plugin
// ---------------------------------------------------------------------------

/// The symbol table plugin.
///
/// Manages the flat symbol table view.  Coordinates the
/// [`SymbolTableModel`], [`SymbolFilter`], and display configuration.
///
/// Ported from Ghidra's `SymbolTablePlugin` which extends
/// `ProgramPlugin`.
///
/// # Example
///
/// ```
/// use ghidra_features::base::symboltable::*;
///
/// let mut plugin = SymbolTablePlugin::new("SymbolTable");
/// plugin.add_symbol(SymbolTableEntry::new("main", 0x401000, EntryKind::Function, "Global"));
/// plugin.add_symbol(SymbolTableEntry::new("init", 0x401100, EntryKind::Function, "Global"));
/// assert_eq!(plugin.row_count(), 2);
///
/// plugin.sort_by_address();
/// assert_eq!(plugin.rows()[0].name(), "main");
/// ```
#[derive(Debug)]
pub struct SymbolTablePlugin {
    /// Display name.
    name: String,
    /// The table model.
    model: SymbolTableModel,
    /// Current filter.
    filter: SymbolFilter,
    /// Active program name.
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

    /// Adds a symbol entry to the table.
    pub fn add_symbol(&mut self, entry: SymbolTableEntry) {
        self.model.add_row(entry);
    }

    /// Removes a symbol by index.
    pub fn remove_symbol(&mut self, index: usize) -> Option<SymbolTableEntry> {
        self.model.remove_row(index)
    }

    /// Returns the row count.
    pub fn row_count(&self) -> usize {
        self.model.row_count()
    }

    /// Returns all rows.
    pub fn rows(&self) -> &[SymbolTableEntry] {
        self.model.rows()
    }

    /// Returns a reference to the model.
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

    /// Applies the current filter and returns matching row indices.
    pub fn apply_filter(&self) -> Vec<usize> {
        self.model
            .rows()
            .iter()
            .enumerate()
            .filter(|(_, entry)| self.filter.matches(entry))
            .map(|(i, _)| i)
            .collect()
    }

    // -- Program lifecycle --

    /// Sets the active program and clears the model.
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

    /// Sorts the table by kind.
    pub fn sort_by_kind(&mut self) {
        self.model.sort_by_kind();
    }

    // -- Lookup --

    /// Finds a symbol by address.
    pub fn find_by_address(&self, addr: u64) -> Option<&SymbolTableEntry> {
        self.model
            .find_by_address(addr)
            .and_then(|i| self.model.rows().get(i))
    }

    /// Returns visible (filtered) row count.
    pub fn visible_count(&self) -> usize {
        self.apply_filter().len()
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

impl fmt::Display for SymbolTablePlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SymbolTablePlugin({}, rows={})",
            self.name,
            self.row_count()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(name: &str, addr: u64) -> SymbolTableEntry {
        SymbolTableEntry::new(name, addr, EntryKind::Function, "Global")
    }

    #[test]
    fn test_entry_kind_display() {
        assert_eq!(EntryKind::Function.to_string(), "Function");
        assert_eq!(EntryKind::Label.to_string(), "Label");
        assert_eq!(EntryKind::Library.to_string(), "Library");
        assert_eq!(EntryKind::External.to_string(), "External");
        assert_eq!(EntryKind::Parameter.to_string(), "Parameter");
        assert_eq!(EntryKind::Local.to_string(), "Local");
        assert_eq!(EntryKind::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_symbol_table_entry() {
        let entry = make_entry("main", 0x401000);
        assert_eq!(entry.name(), "main");
        assert_eq!(entry.address(), 0x401000);
        assert_eq!(entry.kind(), EntryKind::Function);
        assert_eq!(entry.namespace(), "Global");
        assert_eq!(entry.source(), "User");
        assert!(!entry.is_primary());
    }

    #[test]
    fn test_entry_column_text() {
        let entry = make_entry("main", 0x401000);
        assert_eq!(entry.column_text(0), "main");
        assert_eq!(entry.column_text(1), "0x401000");
        assert_eq!(entry.column_text(2), "Function");
        assert_eq!(entry.column_text(3), "Global");
        assert_eq!(entry.column_text(5), "N");
    }

    #[test]
    fn test_entry_qualified_name() {
        let entry = make_entry("main", 0x401000);
        assert_eq!(entry.qualified_name(), "main");

        let entry = SymbolTableEntry::new("malloc", 0, EntryKind::External, "libc");
        assert_eq!(entry.qualified_name(), "libc::malloc");
    }

    #[test]
    fn test_entry_display() {
        let entry = make_entry("main", 0x401000);
        let s = format!("{}", entry);
        assert!(s.contains("main"));
        assert!(s.contains("401000"));
    }

    #[test]
    fn test_model_creation() {
        let model = SymbolTableModel::new(true);
        assert!(model.is_empty());
        assert_eq!(model.column_count(), 6);
        assert!(model.is_editable());
    }

    #[test]
    fn test_model_add_remove() {
        let mut model = SymbolTableModel::new(true);
        model.add_row(make_entry("main", 0x401000));
        model.add_row(make_entry("init", 0x401100));
        assert_eq!(model.row_count(), 2);

        let removed = model.remove_row(0);
        assert!(removed.is_some());
        assert_eq!(model.row_count(), 1);
        assert_eq!(model.deleted_rows().len(), 1);
    }

    #[test]
    fn test_model_undo() {
        let mut model = SymbolTableModel::new(true);
        model.add_row(make_entry("a", 0x1000));
        model.remove_row(0);
        assert!(model.is_empty());

        let restored = model.undo_last_delete();
        assert!(restored.is_some());
        assert_eq!(model.row_count(), 1);
    }

    #[test]
    fn test_model_sort() {
        let mut model = SymbolTableModel::new(true);
        model.add_row(make_entry("zebra", 0x2000));
        model.add_row(make_entry("alpha", 0x1000));

        model.sort_by_address();
        assert_eq!(model.rows()[0].name(), "alpha");

        model.sort_by_name();
        assert_eq!(model.rows()[0].name(), "alpha");
    }

    #[test]
    fn test_model_get_value() {
        let mut model = SymbolTableModel::new(true);
        model.add_row(make_entry("main", 0x401000));
        assert_eq!(model.get_value_at(0, 0), Some("main".into()));
        assert_eq!(model.get_value_at(0, 1), Some("0x401000".into()));
        assert_eq!(model.get_value_at(99, 0), None);
    }

    #[test]
    fn test_filter_matches() {
        let mut filter = SymbolFilter::new();
        filter.set_name_pattern(Some("main".into()));
        assert!(filter.matches(&make_entry("main", 0x401000)));
        assert!(filter.matches(&make_entry("my_main", 0x401000)));
        assert!(!filter.matches(&make_entry("init", 0x401000)));
    }

    #[test]
    fn test_filter_address_range() {
        let mut filter = SymbolFilter::new();
        filter.set_address_range(Some(0x400000), Some(0x4FFFFF));
        assert!(filter.matches_address(0x401000));
        assert!(!filter.matches_address(0x500000));
        assert!(!filter.matches_address(0x300000));
    }

    #[test]
    fn test_filter_kind() {
        let mut filter = SymbolFilter::new();
        filter.set_kind(Some(EntryKind::Function));
        assert!(filter.matches(&make_entry("main", 0x401000)));
        assert!(!filter.matches(&SymbolTableEntry::new(
            "data",
            0x402000,
            EntryKind::Label,
            "Global",
        )));
    }

    #[test]
    fn test_plugin_creation() {
        let plugin = SymbolTablePlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(!plugin.is_disposed());
        assert_eq!(plugin.row_count(), 0);
        assert!(plugin.active_program().is_none());
    }

    #[test]
    fn test_plugin_add_remove() {
        let mut plugin = SymbolTablePlugin::new("Test");
        plugin.add_symbol(make_entry("main", 0x401000));
        plugin.add_symbol(make_entry("init", 0x401100));
        assert_eq!(plugin.row_count(), 2);

        let removed = plugin.remove_symbol(0);
        assert!(removed.is_some());
        assert_eq!(plugin.row_count(), 1);
    }

    #[test]
    fn test_plugin_filter() {
        let mut plugin = SymbolTablePlugin::new("Test");
        plugin.add_symbol(make_entry("main", 0x401000));
        plugin.add_symbol(make_entry("init", 0x401100));

        let mut filter = SymbolFilter::new();
        filter.set_name_pattern(Some("main".into()));
        plugin.set_filter(filter);

        let matching = plugin.apply_filter();
        assert_eq!(matching.len(), 1);
        assert_eq!(plugin.rows()[matching[0]].name(), "main");
    }

    #[test]
    fn test_plugin_find_by_address() {
        let mut plugin = SymbolTablePlugin::new("Test");
        plugin.add_symbol(make_entry("main", 0x401000));

        let found = plugin.find_by_address(0x401000);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name(), "main");
        assert!(plugin.find_by_address(0x9999).is_none());
    }

    #[test]
    fn test_plugin_sort() {
        let mut plugin = SymbolTablePlugin::new("Test");
        plugin.add_symbol(make_entry("zebra", 0x2000));
        plugin.add_symbol(make_entry("alpha", 0x1000));

        plugin.sort_by_address();
        assert_eq!(plugin.rows()[0].name(), "alpha");
    }

    #[test]
    fn test_plugin_program_lifecycle() {
        let mut plugin = SymbolTablePlugin::new("Test");
        assert!(plugin.active_program().is_none());

        plugin.program_activated("test.exe".to_string());
        assert_eq!(plugin.active_program(), Some("test.exe"));

        plugin.add_symbol(make_entry("main", 0x401000));
        plugin.program_closed();
        assert!(plugin.active_program().is_none());
        assert_eq!(plugin.row_count(), 0);
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = SymbolTablePlugin::new("Test");
        plugin.add_symbol(make_entry("a", 0x1000));
        plugin.dispose();
        assert!(plugin.is_disposed());
        assert_eq!(plugin.row_count(), 0);
    }

    #[test]
    fn test_plugin_visible_count() {
        let mut plugin = SymbolTablePlugin::new("Test");
        plugin.add_symbol(make_entry("main", 0x401000));
        plugin.add_symbol(make_entry("init", 0x401100));
        assert_eq!(plugin.visible_count(), 2);

        let mut filter = SymbolFilter::new();
        filter.set_name_pattern(Some("main".into()));
        plugin.set_filter(filter);
        assert_eq!(plugin.visible_count(), 1);
    }

    #[test]
    fn test_table_column_display() {
        assert_eq!(TableColumn::Name.to_string(), "Name");
        assert_eq!(TableColumn::Address.to_string(), "Address");
        assert_eq!(TableColumn::Kind.to_string(), "Kind");
    }

    #[test]
    fn test_plugin_display() {
        let mut plugin = SymbolTablePlugin::new("Test");
        plugin.add_symbol(make_entry("main", 0x401000));
        let s = format!("{}", plugin);
        assert!(s.contains("Test"));
        assert!(s.contains("rows=1"));
    }
}
