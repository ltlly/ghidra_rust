//! Additional symbol database types.
//!
//! Ported from Ghidra's `ghidra.trace.database.symbol` package.
//! Provides concrete implementations for:
//! - `DBTraceEquate`: Database-backed equate entity.
//! - `DBTraceClassSymbolView`: View for class symbols.
//! - `DBTraceLabelSymbolView`: View for label symbols.
//! - Various multi-type symbol views.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::model::Lifespan;

/// A database-backed equate (named constant).
///
/// Ported from `DBTraceEquate`. Represents a named constant value
/// that can be associated with addresses in a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceEquate {
    /// The equate ID.
    pub id: i64,
    /// The equate name.
    pub name: String,
    /// The numeric value.
    pub value: i64,
    /// The address where this equate is used.
    pub address: u64,
    /// The address space name.
    pub space_name: String,
    /// The snap range.
    pub lifespan: Lifespan,
}

impl DBTraceEquate {
    /// Create a new equate.
    pub fn new(
        id: i64,
        name: impl Into<String>,
        value: i64,
        address: u64,
        space_name: impl Into<String>,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            value,
            address,
            space_name: space_name.into(),
            lifespan: Lifespan::ALL,
        }
    }

    /// Get a display string for this equate.
    pub fn display(&self) -> String {
        format!("{} = 0x{:x}", self.name, self.value)
    }
}

/// Source type for symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SourceType {
    /// User-defined.
    UserDefined,
    /// Analysis-generated.
    Analysis,
    /// Imported (from library/symbol file).
    Imported,
    /// Default (inherent to the program).
    Default,
}

impl Default for SourceType {
    fn default() -> Self {
        Self::Analysis
    }
}

/// The type of a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SymbolType {
    /// A label (simple address name).
    Label,
    /// A function.
    Function,
    /// A class/struct.
    Class,
    /// A namespace.
    Namespace,
    /// An equate.
    Equate,
    /// A library.
    Library,
    /// An external reference.
    External,
    /// A local variable.
    LocalVar,
    /// A parameter.
    Parameter,
    /// A generic symbol.
    Generic,
}

/// A symbol entry in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSymbolEntry {
    /// The symbol ID.
    pub id: i64,
    /// The symbol name.
    pub name: String,
    /// The symbol type.
    pub symbol_type: SymbolType,
    /// The address (if any).
    pub address: Option<u64>,
    /// The address space name.
    pub space_name: Option<String>,
    /// The source type.
    pub source: SourceType,
    /// The parent namespace/class ID.
    pub parent_id: Option<i64>,
    /// Whether this is a primary symbol at its address.
    pub primary: bool,
    /// The snap range.
    pub lifespan: Lifespan,
}

impl TraceSymbolEntry {
    /// Create a new label symbol.
    pub fn label(id: i64, name: impl Into<String>, address: u64, space: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            symbol_type: SymbolType::Label,
            address: Some(address),
            space_name: Some(space.into()),
            source: SourceType::Analysis,
            parent_id: None,
            primary: true,
            lifespan: Lifespan::ALL,
        }
    }

    /// Create a new namespace symbol.
    pub fn namespace(id: i64, name: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            symbol_type: SymbolType::Namespace,
            address: None,
            space_name: None,
            source: SourceType::UserDefined,
            parent_id: None,
            primary: false,
            lifespan: Lifespan::ALL,
        }
    }

    /// Create a new class symbol.
    pub fn class(id: i64, name: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            symbol_type: SymbolType::Class,
            address: None,
            space_name: None,
            source: SourceType::UserDefined,
            parent_id: None,
            primary: false,
            lifespan: Lifespan::ALL,
        }
    }

    /// Whether this symbol has an address.
    pub fn has_address(&self) -> bool {
        self.address.is_some()
    }

    /// Get the fully qualified name (simplified: just the name).
    pub fn qualified_name(&self) -> &str {
        &self.name
    }
}

/// The database symbol manager.
///
/// Ported from `TraceDbSymbolManager`. Manages all symbols in the trace database.
#[derive(Debug)]
pub struct TraceDbSymbolManager {
    symbols: BTreeMap<i64, TraceSymbolEntry>,
    name_index: BTreeMap<String, Vec<i64>>,
    address_index: BTreeMap<(String, u64), Vec<i64>>,
    next_id: i64,
}

impl Default for TraceDbSymbolManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceDbSymbolManager {
    /// Create a new symbol manager.
    pub fn new() -> Self {
        Self {
            symbols: BTreeMap::new(),
            name_index: BTreeMap::new(),
            address_index: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Create a symbol.
    pub fn create_symbol(&mut self, mut entry: TraceSymbolEntry) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        entry.id = id;

        self.name_index
            .entry(entry.name.clone())
            .or_default()
            .push(id);

        if let (Some(space), Some(addr)) = (&entry.space_name, entry.address) {
            self.address_index
                .entry((space.clone(), addr))
                .or_default()
                .push(id);
        }

        self.symbols.insert(id, entry);
        id
    }

    /// Get a symbol by ID.
    pub fn get_symbol(&self, id: i64) -> Option<&TraceSymbolEntry> {
        self.symbols.get(&id)
    }

    /// Get a mutable reference to a symbol by ID.
    pub fn get_symbol_mut(&mut self, id: i64) -> Option<&mut TraceSymbolEntry> {
        self.symbols.get_mut(&id)
    }

    /// Delete a symbol by ID.
    pub fn delete_symbol(&mut self, id: i64) -> Option<TraceSymbolEntry> {
        let entry = self.symbols.remove(&id)?;
        // Update indexes
        if let Some(ids) = self.name_index.get_mut(&entry.name) {
            ids.retain(|&i| i != id);
            if ids.is_empty() {
                self.name_index.remove(&entry.name);
            }
        }
        if let (Some(space), Some(addr)) = (&entry.space_name, entry.address) {
            let key = (space.clone(), addr);
            if let Some(ids) = self.address_index.get_mut(&key) {
                ids.retain(|&i| i != id);
                if ids.is_empty() {
                    self.address_index.remove(&key);
                }
            }
        }
        Some(entry)
    }

    /// Get symbols by name.
    pub fn get_symbols_by_name(&self, name: &str) -> Vec<&TraceSymbolEntry> {
        self.name_index
            .get(name)
            .map(|ids| ids.iter().filter_map(|&id| self.symbols.get(&id)).collect())
            .unwrap_or_default()
    }

    /// Get symbols at an address.
    pub fn get_symbols_at(
        &self,
        space: &str,
        address: u64,
    ) -> Vec<&TraceSymbolEntry> {
        let key = (space.to_string(), address);
        self.address_index
            .get(&key)
            .map(|ids| ids.iter().filter_map(|&id| self.symbols.get(&id)).collect())
            .unwrap_or_default()
    }

    /// Get the primary symbol at an address.
    pub fn get_primary_symbol_at(
        &self,
        space: &str,
        address: u64,
    ) -> Option<&TraceSymbolEntry> {
        self.get_symbols_at(space, address)
            .into_iter()
            .find(|s| s.primary)
    }

    /// Get all symbols of a given type.
    pub fn get_symbols_of_type(&self, symbol_type: SymbolType) -> Vec<&TraceSymbolEntry> {
        self.symbols
            .values()
            .filter(|s| s.symbol_type == symbol_type)
            .collect()
    }

    /// Get the total number of symbols.
    pub fn count(&self) -> usize {
        self.symbols.len()
    }

    /// Get all equates.
    pub fn get_equates(&self) -> Vec<&TraceSymbolEntry> {
        self.get_symbols_of_type(SymbolType::Equate)
    }

    /// Get all labels.
    pub fn get_labels(&self) -> Vec<&TraceSymbolEntry> {
        self.get_symbols_of_type(SymbolType::Label)
    }

    /// Get all namespaces.
    pub fn get_namespaces(&self) -> Vec<&TraceSymbolEntry> {
        self.get_symbols_of_type(SymbolType::Namespace)
    }
}

/// A view for class symbols.
///
/// Ported from `DBTraceClassSymbolView`.
#[derive(Debug, Default)]
pub struct DBTraceClassSymbolView {
    /// Class symbols indexed by ID.
    classes: BTreeMap<i64, TraceSymbolEntry>,
}

impl DBTraceClassSymbolView {
    /// Create a new class symbol view.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a class symbol.
    pub fn add_class(&mut self, entry: TraceSymbolEntry) {
        self.classes.insert(entry.id, entry);
    }

    /// Get a class by ID.
    pub fn get_class(&self, id: i64) -> Option<&TraceSymbolEntry> {
        self.classes.get(&id)
    }

    /// Get all classes.
    pub fn all_classes(&self) -> Vec<&TraceSymbolEntry> {
        self.classes.values().collect()
    }

    /// Get the number of classes.
    pub fn count(&self) -> usize {
        self.classes.len()
    }
}

/// A view for label symbols.
///
/// Ported from `DBTraceLabelSymbolView`.
#[derive(Debug, Default)]
pub struct DBTraceLabelSymbolView {
    /// Label symbols indexed by (space, address).
    labels: BTreeMap<(String, u64), TraceSymbolEntry>,
}

impl DBTraceLabelSymbolView {
    /// Create a new label symbol view.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a label symbol.
    pub fn add_label(&mut self, entry: TraceSymbolEntry) {
        if let (Some(space), Some(addr)) = (&entry.space_name, entry.address) {
            self.labels.insert((space.clone(), addr), entry);
        }
    }

    /// Get a label at an address.
    pub fn get_label(&self, space: &str, address: u64) -> Option<&TraceSymbolEntry> {
        self.labels.get(&(space.to_string(), address))
    }

    /// Get all labels in a space.
    pub fn labels_in_space(&self, space: &str) -> Vec<&TraceSymbolEntry> {
        self.labels
            .iter()
            .filter(|((s, _), _)| s == space)
            .map(|(_, e)| e)
            .collect()
    }

    /// Get the number of labels.
    pub fn count(&self) -> usize {
        self.labels.len()
    }
}

/// A composite view for symbols of multiple types.
///
/// Ported from `DBTraceSymbolMultipleTypesView`.
#[derive(Debug, Default)]
pub struct MultiTypeSymbolView {
    /// Symbols organized by type.
    by_type: BTreeMap<SymbolType, Vec<TraceSymbolEntry>>,
}

impl MultiTypeSymbolView {
    /// Create a new multi-type symbol view.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a symbol.
    pub fn add(&mut self, entry: TraceSymbolEntry) {
        self.by_type.entry(entry.symbol_type).or_default().push(entry);
    }

    /// Get all symbols of a given type.
    pub fn get_by_type(&self, symbol_type: SymbolType) -> &[TraceSymbolEntry] {
        self.by_type
            .get(&symbol_type)
            .map_or(&[], |v| v.as_slice())
    }

    /// Get all symbols.
    pub fn all(&self) -> Vec<&TraceSymbolEntry> {
        self.by_type.values().flat_map(|v| v.iter()).collect()
    }

    /// Get the total count.
    pub fn count(&self) -> usize {
        self.by_type.values().map(|v| v.len()).sum()
    }

    /// Get the number of types represented.
    pub fn type_count(&self) -> usize {
        self.by_type.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_trace_equate() {
        let equate = DBTraceEquate::new(1, "MAX_SIZE", 0x1000, 0x400000, "ram");
        assert_eq!(equate.name, "MAX_SIZE");
        assert_eq!(equate.value, 0x1000);
        assert_eq!(equate.display(), "MAX_SIZE = 0x1000");
    }

    #[test]
    fn test_source_type() {
        assert_eq!(SourceType::default(), SourceType::Analysis);
        assert_ne!(SourceType::UserDefined, SourceType::Imported);
    }

    #[test]
    fn test_symbol_type() {
        assert_ne!(SymbolType::Label, SymbolType::Function);
        assert_eq!(SymbolType::Namespace, SymbolType::Namespace);
    }

    #[test]
    fn test_trace_symbol_entry() {
        let label = TraceSymbolEntry::label(1, "main", 0x401000, "ram");
        assert_eq!(label.symbol_type, SymbolType::Label);
        assert!(label.has_address());
        assert_eq!(label.address, Some(0x401000));

        let ns = TraceSymbolEntry::namespace(2, "std");
        assert_eq!(ns.symbol_type, SymbolType::Namespace);
        assert!(!ns.has_address());

        let class = TraceSymbolEntry::class(3, "MyClass");
        assert_eq!(class.symbol_type, SymbolType::Class);
    }

    #[test]
    fn test_symbol_manager_create() {
        let mut mgr = TraceDbSymbolManager::new();
        assert_eq!(mgr.count(), 0);

        let id = mgr.create_symbol(TraceSymbolEntry::label(0, "main", 0x401000, "ram"));
        assert_eq!(mgr.count(), 1);

        let sym = mgr.get_symbol(id).unwrap();
        assert_eq!(sym.name, "main");
    }

    #[test]
    fn test_symbol_manager_by_name() {
        let mut mgr = TraceDbSymbolManager::new();
        mgr.create_symbol(TraceSymbolEntry::label(0, "main", 0x401000, "ram"));
        mgr.create_symbol(TraceSymbolEntry::label(0, "main", 0x501000, "ram2"));

        let syms = mgr.get_symbols_by_name("main");
        assert_eq!(syms.len(), 2);

        let no_such = mgr.get_symbols_by_name("missing");
        assert!(no_such.is_empty());
    }

    #[test]
    fn test_symbol_manager_at_address() {
        let mut mgr = TraceDbSymbolManager::new();
        mgr.create_symbol(TraceSymbolEntry::label(0, "main", 0x401000, "ram"));
        mgr.create_symbol(TraceSymbolEntry::label(0, "func", 0x401000, "ram"));

        let syms = mgr.get_symbols_at("ram", 0x401000);
        assert_eq!(syms.len(), 2);

        let no_such = mgr.get_symbols_at("ram", 0x500000);
        assert!(no_such.is_empty());
    }

    #[test]
    fn test_symbol_manager_delete() {
        let mut mgr = TraceDbSymbolManager::new();
        let id = mgr.create_symbol(TraceSymbolEntry::label(0, "main", 0x401000, "ram"));

        let deleted = mgr.delete_symbol(id);
        assert!(deleted.is_some());
        assert_eq!(mgr.count(), 0);
        assert!(mgr.get_symbols_by_name("main").is_empty());
    }

    #[test]
    fn test_class_symbol_view() {
        let mut view = DBTraceClassSymbolView::new();
        view.add_class(TraceSymbolEntry::class(1, "MyClass"));
        view.add_class(TraceSymbolEntry::class(2, "AnotherClass"));

        assert_eq!(view.count(), 2);
        assert!(view.get_class(1).is_some());
        assert_eq!(view.get_class(1).unwrap().name, "MyClass");
    }

    #[test]
    fn test_label_symbol_view() {
        let mut view = DBTraceLabelSymbolView::new();
        view.add_label(TraceSymbolEntry::label(1, "main", 0x401000, "ram"));
        view.add_label(TraceSymbolEntry::label(2, "start", 0x500000, "ram"));

        assert_eq!(view.count(), 2);
        assert!(view.get_label("ram", 0x401000).is_some());
        assert_eq!(view.labels_in_space("ram").len(), 2);
        assert_eq!(view.labels_in_space("other").len(), 0);
    }

    #[test]
    fn test_multi_type_symbol_view() {
        let mut view = MultiTypeSymbolView::new();
        view.add(TraceSymbolEntry::label(1, "main", 0x401000, "ram"));
        view.add(TraceSymbolEntry::label(2, "start", 0x500000, "ram"));
        view.add(TraceSymbolEntry::namespace(3, "std"));

        assert_eq!(view.count(), 3);
        assert_eq!(view.type_count(), 2);
        assert_eq!(view.get_by_type(SymbolType::Label).len(), 2);
        assert_eq!(view.get_by_type(SymbolType::Namespace).len(), 1);
        assert_eq!(view.get_by_type(SymbolType::Function).len(), 0);
    }
}
