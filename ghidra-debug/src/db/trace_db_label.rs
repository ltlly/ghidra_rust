//! Database-backed label, namespace, and class symbol types.
//!
//! Ported from Ghidra's `ghidra.trace.database.symbol` package.
//! Extends the basic symbol model with specialized types for labels,
//! namespaces, class symbols, and symbol views.

use serde::{Deserialize, Serialize};

use crate::model::{Lifespan, symbol::{TraceSymbol, TraceSymbolKind}};

/// A database-backed label symbol.
///
/// Ported from `DBTraceLabelSymbol`. Labels are point symbols at specific
/// addresses (function entries, data labels, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceLabelSymbol {
    /// The base symbol.
    pub symbol: TraceSymbol,
    /// The source (e.g., "imported", "analysis", "user").
    pub source: Option<String>,
    /// Whether this is an external label.
    pub is_external: bool,
}

impl DbTraceLabelSymbol {
    /// Create a new label symbol.
    pub fn new(
        key: i64,
        name: impl Into<String>,
        address: u64,
        space: impl Into<String>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            symbol: TraceSymbol::label(key, name, address, space, lifespan),
            source: None,
            is_external: false,
        }
    }

    /// Set the source.
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Mark as external.
    pub fn as_external(mut self) -> Self {
        self.is_external = true;
        self
    }
}

/// A database-backed namespace symbol.
///
/// Ported from `DBTraceNamespaceSymbol`. Namespaces are containers for
/// other symbols (e.g., library names, class scopes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceNamespaceSymbol {
    /// The base symbol.
    pub symbol: TraceSymbol,
    /// The depth in the namespace hierarchy.
    pub depth: u32,
}

impl DbTraceNamespaceSymbol {
    /// Create a new namespace symbol.
    pub fn new(
        key: i64,
        name: impl Into<String>,
        parent_key: Option<i64>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            symbol: TraceSymbol::namespace(key, name, parent_key, lifespan),
            depth: 0,
        }
    }

    /// Set the depth.
    pub fn with_depth(mut self, depth: u32) -> Self {
        self.depth = depth;
        self
    }
}

/// A database-backed class symbol.
///
/// Ported from `DBTraceClassSymbol`. Class symbols are namespaces that
/// represent class scopes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceClassSymbol {
    /// The base namespace.
    pub namespace: DbTraceNamespaceSymbol,
    /// Whether this is a struct type.
    pub is_struct: bool,
    /// Whether this is a union type.
    pub is_union: bool,
}

impl DbTraceClassSymbol {
    /// Create a new class symbol.
    pub fn new(
        key: i64,
        name: impl Into<String>,
        parent_key: Option<i64>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            namespace: DbTraceNamespaceSymbol::new(key, name, parent_key, lifespan),
            is_struct: false,
            is_union: false,
        }
    }
}

/// A view (filter) over symbols in the database.
///
/// Ported from Ghidra's various `*View` classes that provide filtered
/// read access to the symbol table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolView {
    /// The filter kind.
    pub kind: SymbolViewKind,
    /// The space filter (None = all spaces).
    pub space: Option<String>,
    /// The snap filter.
    pub snap: Option<i64>,
    /// The parent namespace filter.
    pub parent_key: Option<i64>,
}

/// The kind of symbol view filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolViewKind {
    /// All symbols.
    All,
    /// Labels only.
    LabelsOnly,
    /// Namespaces only.
    NamespacesOnly,
    /// Classes only.
    ClassesOnly,
    /// Functions only.
    FunctionsOnly,
    /// Symbols with addresses.
    WithAddress,
    /// Symbols with no duplicates at an address.
    NoDuplicates,
}

impl SymbolView {
    /// Create a view of all symbols.
    pub fn all() -> Self {
        Self {
            kind: SymbolViewKind::All,
            space: None,
            snap: None,
            parent_key: None,
        }
    }

    /// Create a labels-only view.
    pub fn labels() -> Self {
        Self {
            kind: SymbolViewKind::LabelsOnly,
            space: None,
            snap: None,
            parent_key: None,
        }
    }

    /// Create a functions-only view.
    pub fn functions() -> Self {
        Self {
            kind: SymbolViewKind::FunctionsOnly,
            space: None,
            snap: None,
            parent_key: None,
        }
    }

    /// Filter by space.
    pub fn in_space(mut self, space: impl Into<String>) -> Self {
        self.space = Some(space.into());
        self
    }

    /// Filter by snap.
    pub fn at_snap(mut self, snap: i64) -> Self {
        self.snap = Some(snap);
        self
    }

    /// Filter by parent namespace.
    pub fn in_namespace(mut self, parent_key: i64) -> Self {
        self.parent_key = Some(parent_key);
        self
    }

    /// Check if a symbol matches this view.
    pub fn matches(&self, symbol: &TraceSymbol) -> bool {
        // Check kind filter
        match self.kind {
            SymbolViewKind::All => {}
            SymbolViewKind::LabelsOnly => {
                if symbol.kind != TraceSymbolKind::Label {
                    return false;
                }
            }
            SymbolViewKind::NamespacesOnly => {
                if symbol.kind != TraceSymbolKind::Namespace {
                    return false;
                }
            }
            SymbolViewKind::ClassesOnly => {
                if symbol.kind != TraceSymbolKind::Class {
                    return false;
                }
            }
            SymbolViewKind::FunctionsOnly => {
                if symbol.kind != TraceSymbolKind::Function {
                    return false;
                }
            }
            SymbolViewKind::WithAddress => {
                if symbol.address.is_none() {
                    return false;
                }
            }
            SymbolViewKind::NoDuplicates => {
                // No-duplicates view: just check address exists
                if symbol.address.is_none() {
                    return false;
                }
            }
        }

        // Check space filter
        if let Some(ref space) = self.space {
            if symbol.space.as_deref() != Some(space.as_str()) {
                return false;
            }
        }

        // Check snap filter
        if let Some(snap) = self.snap {
            if !symbol.lifespan.contains(snap) {
                return false;
            }
        }

        // Check parent namespace filter
        if let Some(parent_key) = self.parent_key {
            if symbol.parent_key != Some(parent_key) {
                return false;
            }
        }

        true
    }
}

/// Extended symbol operations that complement the basic `TraceSymbolManager`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SymbolOperations {
    /// The label symbols.
    pub labels: Vec<DbTraceLabelSymbol>,
    /// The namespace symbols.
    pub namespaces: Vec<DbTraceNamespaceSymbol>,
    /// The class symbols.
    pub classes: Vec<DbTraceClassSymbol>,
}

impl SymbolOperations {
    /// Create a new operations container.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a label.
    pub fn add_label(&mut self, label: DbTraceLabelSymbol) {
        self.labels.push(label);
    }

    /// Add a namespace.
    pub fn add_namespace(&mut self, ns: DbTraceNamespaceSymbol) {
        self.namespaces.push(ns);
    }

    /// Add a class.
    pub fn add_class(&mut self, class: DbTraceClassSymbol) {
        self.classes.push(class);
    }

    /// Find labels by name at a snap.
    pub fn find_labels_by_name(&self, name: &str, snap: i64) -> Vec<&DbTraceLabelSymbol> {
        self.labels
            .iter()
            .filter(|l| {
                l.symbol.name == name && l.symbol.lifespan.contains(snap)
            })
            .collect()
    }

    /// Find labels at an address.
    pub fn find_labels_at(
        &self,
        address: u64,
        space: &str,
        snap: i64,
    ) -> Vec<&DbTraceLabelSymbol> {
        self.labels
            .iter()
            .filter(|l| {
                l.symbol.address == Some(address)
                    && l.symbol.space.as_deref() == Some(space)
                    && l.symbol.lifespan.contains(snap)
            })
            .collect()
    }

    /// Find namespaces by name.
    pub fn find_namespaces_by_name(&self, name: &str, snap: i64) -> Vec<&DbTraceNamespaceSymbol> {
        self.namespaces
            .iter()
            .filter(|ns| {
                ns.symbol.name == name && ns.symbol.lifespan.contains(snap)
            })
            .collect()
    }

    /// The total number of symbols.
    pub fn total_count(&self) -> usize {
        self.labels.len() + self.namespaces.len() + self.classes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_symbol() {
        let label = DbTraceLabelSymbol::new(1, "main", 0x400000, "ram", Lifespan::now_on(0))
            .with_source("user")
            .as_external();
        assert_eq!(label.symbol.name, "main");
        assert_eq!(label.source, Some("user".into()));
        assert!(label.is_external);
    }

    #[test]
    fn test_namespace_symbol() {
        let ns = DbTraceNamespaceSymbol::new(1, "libc", None, Lifespan::ALL).with_depth(1);
        assert_eq!(ns.symbol.name, "libc");
        assert_eq!(ns.depth, 1);
    }

    #[test]
    fn test_class_symbol() {
        let class = DbTraceClassSymbol::new(1, "MyStruct", None, Lifespan::ALL);
        assert_eq!(class.namespace.symbol.name, "MyStruct");
    }

    #[test]
    fn test_symbol_view() {
        let view = SymbolView::labels().in_space("ram").at_snap(5);
        assert_eq!(view.kind, SymbolViewKind::LabelsOnly);
        assert_eq!(view.space.as_deref(), Some("ram"));
        assert_eq!(view.snap, Some(5));

        let label = TraceSymbol::label(1, "main", 0x400000, "ram", Lifespan::now_on(0));
        assert!(view.matches(&label));

        let ns = TraceSymbol::namespace(2, "libc", None, Lifespan::ALL);
        assert!(!view.matches(&ns)); // wrong kind

        let label_other_space = TraceSymbol::label(3, "foo", 0x100, "register", Lifespan::ALL);
        assert!(!view.matches(&label_other_space)); // wrong space
    }

    #[test]
    fn test_symbol_view_all() {
        let view = SymbolView::all();
        let label = TraceSymbol::label(1, "main", 0x400000, "ram", Lifespan::ALL);
        let ns = TraceSymbol::namespace(2, "libc", None, Lifespan::ALL);
        assert!(view.matches(&label));
        assert!(view.matches(&ns));
    }

    #[test]
    fn test_symbol_operations() {
        let mut ops = SymbolOperations::new();
        ops.add_label(DbTraceLabelSymbol::new(1, "main", 0x400000, "ram", Lifespan::now_on(0)));
        ops.add_label(DbTraceLabelSymbol::new(2, "printf", 0x400100, "ram", Lifespan::now_on(0)));
        ops.add_namespace(DbTraceNamespaceSymbol::new(3, "libc", None, Lifespan::ALL));

        assert_eq!(ops.total_count(), 3);

        let labels = ops.find_labels_by_name("main", 5);
        assert_eq!(labels.len(), 1);

        let at_addr = ops.find_labels_at(0x400000, "ram", 5);
        assert_eq!(at_addr.len(), 1);

        let nss = ops.find_namespaces_by_name("libc", 5);
        assert_eq!(nss.len(), 1);
    }

    #[test]
    fn test_symbol_operations_filter() {
        let mut ops = SymbolOperations::new();
        ops.add_label(DbTraceLabelSymbol::new(1, "a", 0x100, "ram", Lifespan::span(0, 5)));
        ops.add_label(DbTraceLabelSymbol::new(2, "b", 0x200, "ram", Lifespan::span(10, 20)));

        let at_snap_3 = ops.find_labels_at(0x100, "ram", 3);
        assert_eq!(at_snap_3.len(), 1);

        let at_snap_15 = ops.find_labels_at(0x100, "ram", 15);
        assert_eq!(at_snap_15.len(), 0);
    }

    #[test]
    fn test_serde() {
        let label = DbTraceLabelSymbol::new(1, "test", 0x100, "ram", Lifespan::ALL);
        let json = serde_json::to_string(&label).unwrap();
        let back: DbTraceLabelSymbol = serde_json::from_str(&json).unwrap();
        assert_eq!(back.symbol.name, "test");
    }
}
