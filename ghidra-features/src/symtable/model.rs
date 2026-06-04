//! Symbol table model -- ported from `AbstractSymbolTableModel`,
//! `SymbolRowObject`, and `DeletedSymbolRowObject`.
//!
//! Provides the data model backing the flat symbol table view.

use std::fmt;

// ---------------------------------------------------------------------------
// SymbolKind (for the table)
// ---------------------------------------------------------------------------

/// The kind of symbol as shown in the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolTableKind {
    /// A function symbol.
    Function,
    /// A label (code or data label).
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
    /// An unknown/custom type.
    Unknown,
}

impl fmt::Display for SymbolTableKind {
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
// SymbolRowObject
// ---------------------------------------------------------------------------

/// A single row in the symbol table.
///
/// Ported from `SymbolRowObject.java`.
///
/// # Example
///
/// ```
/// use ghidra_features::symtable::model::*;
///
/// let row = SymbolRowObject::new(
///     "main",
///     0x401000,
///     SymbolTableKind::Function,
///     "Global",
/// );
/// assert_eq!(row.name(), "main");
/// assert_eq!(row.address(), 0x401000);
/// ```
#[derive(Debug, Clone)]
pub struct SymbolRowObject {
    /// The symbol name.
    name: String,
    /// The symbol address.
    address: u64,
    /// The kind of symbol.
    kind: SymbolTableKind,
    /// The namespace.
    namespace: String,
    /// The source (user, analysis, imported).
    source: String,
    /// Whether this is the primary symbol at its address.
    is_primary: bool,
    /// Whether this is an external symbol.
    is_external: bool,
    /// Whether the symbol is pinned.
    is_pinned: bool,
    /// The symbol ID.
    id: u64,
}

impl SymbolRowObject {
    /// Creates a new symbol row object.
    pub fn new(
        name: impl Into<String>,
        address: u64,
        kind: SymbolTableKind,
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

    /// Returns the symbol address.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Returns the symbol kind.
    pub fn kind(&self) -> SymbolTableKind {
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

    /// Returns whether this is an external symbol.
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

    /// Sets whether this is the primary symbol.
    pub fn set_primary(&mut self, primary: bool) {
        self.is_primary = primary;
    }

    /// Sets whether this is an external symbol.
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

    /// Returns the display text for a given column index.
    pub fn get_column_text(&self, col: usize) -> String {
        match col {
            0 => self.name.clone(),
            1 => format!("0x{:x}", self.address),
            2 => self.kind.to_string(),
            3 => self.namespace.clone(),
            4 => self.source.clone(),
            5 => {
                if self.is_primary {
                    "Y".to_string()
                } else {
                    "N".to_string()
                }
            }
            _ => String::new(),
        }
    }
}

impl fmt::Display for SymbolRowObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} @ 0x{:x} ({})", self.name, self.address, self.kind)
    }
}

// ---------------------------------------------------------------------------
// DeletedSymbolRowObject
// ---------------------------------------------------------------------------

/// A row representing a deleted symbol (used for undo tracking).
///
/// Ported from `DeletedSymbolRowObject.java`.
#[derive(Debug, Clone)]
pub struct DeletedSymbolRowObject {
    /// The original row object.
    original: SymbolRowObject,
    /// The timestamp when the symbol was deleted.
    deleted_at: u64,
}

impl DeletedSymbolRowObject {
    /// Creates a new deleted symbol row.
    pub fn new(original: SymbolRowObject, deleted_at: u64) -> Self {
        Self { original, deleted_at }
    }

    /// Returns the original symbol row.
    pub fn original(&self) -> &SymbolRowObject {
        &self.original
    }

    /// Returns the deletion timestamp.
    pub fn deleted_at(&self) -> u64 {
        self.deleted_at
    }
}

// ---------------------------------------------------------------------------
// SymbolTableModel
// ---------------------------------------------------------------------------

/// Column identifiers for the symbol table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolTableColumn {
    /// Symbol name.
    Name,
    /// Symbol address.
    Address,
    /// Symbol kind.
    Kind,
    /// Namespace.
    Namespace,
    /// Source.
    Source,
    /// Primary flag.
    Primary,
}

impl fmt::Display for SymbolTableColumn {
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
/// Ported from `AbstractSymbolTableModel`.  This is the backend data model
/// that stores and manages the rows shown in the symbol table.
#[derive(Debug, Clone)]
pub struct SymbolTableModel {
    /// Column definitions.
    columns: Vec<SymbolTableColumn>,
    /// The rows.
    rows: Vec<SymbolRowObject>,
    /// Deleted rows (for undo).
    deleted_rows: Vec<DeletedSymbolRowObject>,
    /// Whether the model is editable.
    editable: bool,
}

impl SymbolTableModel {
    /// Creates a new symbol table model with default columns.
    pub fn new(editable: bool) -> Self {
        Self {
            columns: vec![
                SymbolTableColumn::Name,
                SymbolTableColumn::Address,
                SymbolTableColumn::Kind,
                SymbolTableColumn::Namespace,
                SymbolTableColumn::Source,
                SymbolTableColumn::Primary,
            ],
            rows: Vec::new(),
            deleted_rows: Vec::new(),
            editable,
        }
    }

    /// Returns the column definitions.
    pub fn columns(&self) -> &[SymbolTableColumn] {
        &self.columns
    }

    /// Returns the number of columns.
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Returns the rows.
    pub fn rows(&self) -> &[SymbolRowObject] {
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
    pub fn add_row(&mut self, row: SymbolRowObject) {
        self.rows.push(row);
    }

    /// Removes a row by index, tracking it for undo.
    pub fn remove_row(&mut self, index: usize) -> Option<SymbolRowObject> {
        if index < self.rows.len() {
            let row = self.rows.remove(index);
            self.deleted_rows
                .push(DeletedSymbolRowObject::new(row.clone(), 0));
            Some(row)
        } else {
            None
        }
    }

    /// Gets a cell value by row and column index.
    pub fn get_value_at(&self, row: usize, col: usize) -> Option<String> {
        let r = self.rows.get(row)?;
        Some(r.get_column_text(col))
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
    pub fn deleted_rows(&self) -> &[DeletedSymbolRowObject] {
        &self.deleted_rows
    }

    /// Restores the last deleted row.
    pub fn undo_last_delete(&mut self) -> Option<SymbolRowObject> {
        let deleted = self.deleted_rows.pop()?;
        self.rows.push(deleted.original.clone());
        Some(deleted.original)
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
        self.rows.sort_by(|a, b| {
            a.name()
                .to_lowercase()
                .cmp(&b.name().to_lowercase())
        });
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_row(name: &str, addr: u64) -> SymbolRowObject {
        SymbolRowObject::new(name, addr, SymbolTableKind::Function, "Global")
    }

    #[test]
    fn test_symbol_table_kind_display() {
        assert_eq!(SymbolTableKind::Function.to_string(), "Function");
        assert_eq!(SymbolTableKind::Label.to_string(), "Label");
        assert_eq!(SymbolTableKind::Library.to_string(), "Library");
    }

    #[test]
    fn test_symbol_row_object() {
        let row = make_row("main", 0x401000);
        assert_eq!(row.name(), "main");
        assert_eq!(row.address(), 0x401000);
        assert_eq!(row.namespace(), "Global");
        assert!(!row.is_primary());
    }

    #[test]
    fn test_symbol_row_get_column_text() {
        let row = make_row("main", 0x401000);
        assert_eq!(row.get_column_text(0), "main");
        assert_eq!(row.get_column_text(1), "0x401000");
        assert_eq!(row.get_column_text(2), "Function");
        assert_eq!(row.get_column_text(3), "Global");
    }

    #[test]
    fn test_symbol_row_display() {
        let row = make_row("main", 0x401000);
        let s = format!("{}", row);
        assert!(s.contains("main"));
        assert!(s.contains("401000"));
    }

    #[test]
    fn test_deleted_symbol_row_object() {
        let row = make_row("old", 0x1000);
        let deleted = DeletedSymbolRowObject::new(row, 12345);
        assert_eq!(deleted.original().name(), "old");
        assert_eq!(deleted.deleted_at(), 12345);
    }

    #[test]
    fn test_symbol_table_model() {
        let mut model = SymbolTableModel::new(true);
        assert!(model.is_empty());
        assert_eq!(model.column_count(), 6);
        assert!(model.is_editable());

        model.add_row(make_row("main", 0x401000));
        model.add_row(make_row("init", 0x401100));
        assert_eq!(model.row_count(), 2);
    }

    #[test]
    fn test_symbol_table_model_get_value() {
        let mut model = SymbolTableModel::new(true);
        model.add_row(make_row("main", 0x401000));
        assert_eq!(model.get_value_at(0, 0), Some("main".into()));
        assert_eq!(model.get_value_at(0, 1), Some("0x401000".into()));
        assert_eq!(model.get_value_at(1, 0), None);
    }

    #[test]
    fn test_symbol_table_model_remove_and_undo() {
        let mut model = SymbolTableModel::new(true);
        model.add_row(make_row("a", 0x1000));
        model.add_row(make_row("b", 0x2000));

        let removed = model.remove_row(0);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name(), "a");
        assert_eq!(model.row_count(), 1);
        assert_eq!(model.deleted_rows().len(), 1);

        let restored = model.undo_last_delete();
        assert!(restored.is_some());
        assert_eq!(model.row_count(), 2);
    }

    #[test]
    fn test_symbol_table_model_sort_by_address() {
        let mut model = SymbolTableModel::new(true);
        model.add_row(make_row("b", 0x2000));
        model.add_row(make_row("a", 0x1000));
        model.sort_by_address();
        assert_eq!(model.rows()[0].name(), "a");
        assert_eq!(model.rows()[1].name(), "b");
    }

    #[test]
    fn test_symbol_table_model_sort_by_name() {
        let mut model = SymbolTableModel::new(true);
        model.add_row(make_row("zebra", 0x1000));
        model.add_row(make_row("alpha", 0x2000));
        model.sort_by_name();
        assert_eq!(model.rows()[0].name(), "alpha");
        assert_eq!(model.rows()[1].name(), "zebra");
    }

    #[test]
    fn test_symbol_table_model_find_by_address() {
        let mut model = SymbolTableModel::new(true);
        model.add_row(make_row("a", 0x1000));
        assert_eq!(model.find_by_address(0x1000), Some(0));
        assert_eq!(model.find_by_address(0x9999), None);
    }

    #[test]
    fn test_symbol_table_column_display() {
        assert_eq!(SymbolTableColumn::Name.to_string(), "Name");
        assert_eq!(SymbolTableColumn::Address.to_string(), "Address");
    }

    #[test]
    fn test_symbol_table_model_clear() {
        let mut model = SymbolTableModel::new(true);
        model.add_row(make_row("a", 0x1000));
        model.clear();
        assert!(model.is_empty());
    }
}
