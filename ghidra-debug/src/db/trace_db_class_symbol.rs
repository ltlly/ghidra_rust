//! Database-backed class/namespace symbol types for traces.
//!
//! Ported from Ghidra's `DBTraceClassSymbol`, `DBTraceClassSymbolView`,
//! `DBTraceLabelSymbol`, `DBTraceLabelSymbolView`, `DBTraceNamespaceSymbol`,
//! `DBTraceNamespaceSymbolView`.
//!
//! Provides the database-backed implementations for class symbols (namespaces),
//! label symbols, and their views over the trace symbol table.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A unique identifier for a symbol.
pub type SymbolId = u64;

/// The kind of namespace/class symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NamespaceKind {
    /// A global namespace (the root).
    Global,
    /// A library namespace.
    Library,
    /// A class namespace.
    Class,
    /// A function namespace (local scope).
    Function,
    /// A struct/union namespace.
    Struct,
    /// An enum namespace.
    Enum,
}

/// A namespace/class symbol in the trace.
///
/// Ported from Ghidra's `DBTraceClassSymbol` / `DBTraceNamespaceSymbol`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceClassSymbol {
    /// The unique symbol ID.
    pub id: SymbolId,
    /// The name of the namespace.
    pub name: String,
    /// The kind of namespace.
    pub kind: NamespaceKind,
    /// The parent namespace ID (None for global).
    pub parent_id: Option<SymbolId>,
    /// The lifespan of this symbol in the trace.
    pub lifespan: Lifespan,
}

impl TraceClassSymbol {
    /// Create a new class/namespace symbol.
    pub fn new(
        id: SymbolId,
        name: impl Into<String>,
        kind: NamespaceKind,
        parent_id: Option<SymbolId>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            kind,
            parent_id,
            lifespan,
        }
    }

    /// Check if this is the global namespace.
    pub fn is_global(&self) -> bool {
        self.kind == NamespaceKind::Global && self.parent_id.is_none()
    }

    /// Check if this symbol is active at a given snap.
    pub fn is_active_at(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }
}

/// A label symbol in the trace.
///
/// Ported from Ghidra's `DBTraceLabelSymbol`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceLabelSymbol {
    /// The unique symbol ID.
    pub id: SymbolId,
    /// The label name.
    pub name: String,
    /// The address offset.
    pub address: u64,
    /// The address space name.
    pub space_name: String,
    /// The namespace this label belongs to.
    pub namespace_id: Option<SymbolId>,
    /// The lifespan of this label in the trace.
    pub lifespan: Lifespan,
    /// Whether this is an external label.
    pub is_external: bool,
    /// The source of this label (user, analysis, etc.).
    pub source: SymbolSource,
}

impl TraceLabelSymbol {
    /// Create a new label symbol.
    pub fn new(
        id: SymbolId,
        name: impl Into<String>,
        address: u64,
        space_name: impl Into<String>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            address,
            space_name: space_name.into(),
            namespace_id: None,
            lifespan,
            is_external: false,
            source: SymbolSource::Default,
        }
    }

    /// Set the namespace.
    pub fn with_namespace(mut self, namespace_id: SymbolId) -> Self {
        self.namespace_id = Some(namespace_id);
        self
    }

    /// Set the source.
    pub fn with_source(mut self, source: SymbolSource) -> Self {
        self.source = source;
        self
    }

    /// Check if this label is active at a given snap.
    pub fn is_active_at(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }
}

/// The source of a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolSource {
    /// Default (unknown) source.
    Default,
    /// User-defined.
    User,
    /// Created by analysis.
    Analysis,
    /// Imported from an external source.
    Import,
    /// Created by the debugger backend.
    Debugger,
}

/// A view over class/namespace symbols.
///
/// Ported from Ghidra's `DBTraceClassSymbolView`.
#[derive(Debug)]
pub struct TraceClassSymbolView {
    symbols: HashMap<SymbolId, TraceClassSymbol>,
}

impl TraceClassSymbolView {
    /// Create a new class symbol view.
    pub fn new() -> Self {
        Self {
            symbols: HashMap::new(),
        }
    }

    /// Add a symbol to the view.
    pub fn add(&mut self, symbol: TraceClassSymbol) {
        self.symbols.insert(symbol.id, symbol);
    }

    /// Get a symbol by ID.
    pub fn get(&self, id: SymbolId) -> Option<&TraceClassSymbol> {
        self.symbols.get(&id)
    }

    /// Get all symbols in the view.
    pub fn all(&self) -> Vec<&TraceClassSymbol> {
        self.symbols.values().collect()
    }

    /// Get symbols active at a given snap.
    pub fn active_at(&self, snap: i64) -> Vec<&TraceClassSymbol> {
        self.symbols
            .values()
            .filter(|s| s.is_active_at(snap))
            .collect()
    }

    /// Get child namespaces of a given parent.
    pub fn children_of(&self, parent_id: SymbolId) -> Vec<&TraceClassSymbol> {
        self.symbols
            .values()
            .filter(|s| s.parent_id == Some(parent_id))
            .collect()
    }

    /// Get the number of symbols.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Check if the view is empty.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
}

impl Default for TraceClassSymbolView {
    fn default() -> Self {
        Self::new()
    }
}

/// A view over label symbols.
///
/// Ported from Ghidra's `DBTraceLabelSymbolView`.
#[derive(Debug)]
pub struct TraceLabelSymbolView {
    symbols: Vec<TraceLabelSymbol>,
}

impl TraceLabelSymbolView {
    /// Create a new label symbol view.
    pub fn new() -> Self {
        Self {
            symbols: Vec::new(),
        }
    }

    /// Add a label to the view.
    pub fn add(&mut self, label: TraceLabelSymbol) {
        self.symbols.push(label);
    }

    /// Get labels at a given address in a space.
    pub fn at_address(&self, space_name: &str, address: u64, snap: i64) -> Vec<&TraceLabelSymbol> {
        self.symbols
            .iter()
            .filter(|l| {
                l.space_name == space_name && l.address == address && l.is_active_at(snap)
            })
            .collect()
    }

    /// Get labels matching a name pattern.
    pub fn by_name(&self, name: &str, snap: i64) -> Vec<&TraceLabelSymbol> {
        self.symbols
            .iter()
            .filter(|l| l.name == name && l.is_active_at(snap))
            .collect()
    }

    /// Get all labels.
    pub fn all(&self) -> &[TraceLabelSymbol] {
        &self.symbols
    }

    /// Get the number of labels.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Check if the view is empty.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
}

impl Default for TraceLabelSymbolView {
    fn default() -> Self {
        Self::new()
    }
}

/// A view over namespace symbols.
///
/// Ported from Ghidra's `DBTraceNamespaceSymbolView`.
pub type TraceNamespaceSymbolView = TraceClassSymbolView;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_class_symbol_creation() {
        let sym = TraceClassSymbol::new(1, "MyClass", NamespaceKind::Class, Some(0), Lifespan::ALL);
        assert_eq!(sym.name, "MyClass");
        assert_eq!(sym.kind, NamespaceKind::Class);
        assert!(!sym.is_global());
        assert!(sym.is_active_at(5));
    }

    #[test]
    fn test_global_namespace() {
        let sym = TraceClassSymbol::new(0, "Global", NamespaceKind::Global, None, Lifespan::ALL);
        assert!(sym.is_global());
    }

    #[test]
    fn test_label_symbol_creation() {
        let label = TraceLabelSymbol::new(1, "main", 0x400000, "ram", Lifespan::now_on(0))
            .with_namespace(0)
            .with_source(SymbolSource::User);
        assert_eq!(label.name, "main");
        assert_eq!(label.address, 0x400000);
        assert_eq!(label.namespace_id, Some(0));
        assert_eq!(label.source, SymbolSource::User);
    }

    #[test]
    fn test_class_symbol_view() {
        let mut view = TraceClassSymbolView::new();
        assert!(view.is_empty());

        view.add(TraceClassSymbol::new(1, "ClassA", NamespaceKind::Class, None, Lifespan::ALL));
        view.add(TraceClassSymbol::new(
            2,
            "ClassB",
            NamespaceKind::Class,
            Some(1),
            Lifespan::now_on(0),
        ));

        assert_eq!(view.len(), 2);
        assert!(view.get(1).is_some());
        assert_eq!(view.get(1).unwrap().name, "ClassA");

        let children = view.children_of(1);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].name, "ClassB");
    }

    #[test]
    fn test_class_symbol_view_active_at() {
        let mut view = TraceClassSymbolView::new();
        view.add(TraceClassSymbol::new(1, "A", NamespaceKind::Class, None, Lifespan::now_on(0)));
        view.add(TraceClassSymbol::new(
            2,
            "B",
            NamespaceKind::Class,
            None,
            Lifespan::span(5, 10),
        ));

        assert_eq!(view.active_at(0).len(), 1); // Only A
        assert_eq!(view.active_at(5).len(), 2); // A and B
        assert_eq!(view.active_at(11).len(), 1); // Only A (ALL)
    }

    #[test]
    fn test_label_symbol_view() {
        let mut view = TraceLabelSymbolView::new();
        view.add(TraceLabelSymbol::new(1, "main", 0x400000, "ram", Lifespan::ALL));
        view.add(TraceLabelSymbol::new(2, "printf", 0x500000, "ram", Lifespan::ALL));

        assert_eq!(view.len(), 2);
        let main_labels = view.at_address("ram", 0x400000, 0);
        assert_eq!(main_labels.len(), 1);
        assert_eq!(main_labels[0].name, "main");

        let by_name = view.by_name("printf", 0);
        assert_eq!(by_name.len(), 1);
        assert_eq!(by_name[0].address, 0x500000);
    }

    #[test]
    fn test_namespace_kinds() {
        assert_ne!(NamespaceKind::Global, NamespaceKind::Class);
        assert_ne!(NamespaceKind::Library, NamespaceKind::Function);
    }

    #[test]
    fn test_symbol_source_variants() {
        assert_ne!(SymbolSource::User, SymbolSource::Analysis);
        assert_eq!(SymbolSource::Default, SymbolSource::Default);
    }

    #[test]
    fn test_label_not_active_outside_lifespan() {
        let label = TraceLabelSymbol::new(1, "temp", 0x1000, "ram", Lifespan::span(5, 10));
        assert!(!label.is_active_at(4));
        assert!(label.is_active_at(5));
        assert!(label.is_active_at(7));
        assert!(label.is_active_at(10));
        assert!(!label.is_active_at(11));
    }
}
