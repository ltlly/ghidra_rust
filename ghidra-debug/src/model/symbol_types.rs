//! Extended symbol types for trace symbols.
//!
//! Ported from Ghidra's `ghidra.trace.model.symbol` package:
//! - TraceSymbolWithLifespan
//! - TraceLabelSymbol
//! - TraceNamespaceSymbol
//! - TraceClassSymbol
//!
//! These extend the base TraceSymbol with additional semantics specific
//! to different kinds of symbols.

use serde::{Deserialize, Serialize};

use super::listing::TraceCodeUnit;
use super::symbol::{TraceSymbol, TraceSymbolKind};
use super::Lifespan;

/// A trace symbol having a lifespan.
///
/// Ported from Ghidra's `TraceSymbolWithLifespan` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSymbolWithLifespan {
    /// The base symbol.
    pub symbol: TraceSymbol,
}

impl TraceSymbolWithLifespan {
    /// Create a new symbol with lifespan.
    pub fn new(symbol: TraceSymbol) -> Self {
        Self { symbol }
    }

    /// Get the lifespan of the symbol.
    pub fn lifespan(&self) -> &Lifespan {
        &self.symbol.lifespan
    }

    /// Get the minimum snapshot key in the lifespan.
    pub fn start_snap(&self) -> i64 {
        self.symbol.lifespan.lmin()
    }

    /// Set the maximum snapshot key in the lifespan.
    pub fn set_end_snap(&mut self, snap: i64) {
        self.symbol.lifespan = Lifespan::span(self.symbol.lifespan.lmin(), snap);
    }

    /// Get the maximum snapshot key in the lifespan.
    pub fn end_snap(&self) -> i64 {
        self.symbol.lifespan.lmax()
    }

    /// Get the symbol name.
    pub fn name(&self) -> &str {
        &self.symbol.name
    }

    /// Get the symbol key.
    pub fn key(&self) -> i64 {
        self.symbol.key
    }

    /// Get the symbol address.
    pub fn address(&self) -> Option<u64> {
        self.symbol.address
    }
}

/// A trace label symbol.
///
/// Ported from Ghidra's `TraceLabelSymbol` interface.
/// Labels mark specific addresses in a trace as significant
/// (function entries, data labels, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceLabelSymbol {
    /// The base symbol with lifespan.
    pub base: TraceSymbolWithLifespan,
}

impl TraceLabelSymbol {
    /// Create a new label symbol.
    pub fn new(
        key: i64,
        name: impl Into<String>,
        address: u64,
        space: impl Into<String>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            base: TraceSymbolWithLifespan::new(TraceSymbol::label(
                key, name, address, space, lifespan,
            )),
        }
    }

    /// Create from an existing symbol (must be of kind Label).
    pub fn from_symbol(symbol: TraceSymbol) -> Option<Self> {
        if symbol.kind == TraceSymbolKind::Label {
            Some(Self {
                base: TraceSymbolWithLifespan::new(symbol),
            })
        } else {
            None
        }
    }

    /// Get the address of this label.
    pub fn address(&self) -> Option<u64> {
        self.base.symbol.address
    }

    /// Get the address space.
    pub fn space(&self) -> Option<&str> {
        self.base.symbol.space.as_deref()
    }

    /// Get the name of this label.
    pub fn name(&self) -> &str {
        &self.base.symbol.name
    }

    /// Get the lifespan of this label.
    pub fn lifespan(&self) -> &Lifespan {
        self.base.lifespan()
    }
}

/// A trace namespace symbol.
///
/// Ported from Ghidra's `TraceNamespaceSymbol` interface.
/// Namespaces are containers for other symbols, providing hierarchical
/// organization (e.g., classes, libraries).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceNamespaceSymbol {
    /// The base symbol.
    pub symbol: TraceSymbol,
    /// Keys of child symbols.
    pub children_keys: Vec<i64>,
    /// Whether this is the global namespace.
    pub is_global: bool,
}

impl TraceNamespaceSymbol {
    /// Create a new namespace symbol.
    pub fn new(
        key: i64,
        name: impl Into<String>,
        parent_key: Option<i64>,
        lifespan: Lifespan,
    ) -> Self {
        let is_global = parent_key.is_none();
        Self {
            symbol: TraceSymbol::namespace(key, name, parent_key, lifespan),
            children_keys: Vec::new(),
            is_global,
        }
    }

    /// Create from an existing symbol.
    pub fn from_symbol(symbol: TraceSymbol) -> Option<Self> {
        if symbol.kind == TraceSymbolKind::Namespace || symbol.kind == TraceSymbolKind::Class {
            let is_global = symbol.parent_key.is_none();
            Some(Self {
                symbol,
                children_keys: Vec::new(),
                is_global,
            })
        } else {
            None
        }
    }

    /// Whether this is the global namespace.
    pub fn is_global(&self) -> bool {
        self.is_global
    }

    /// Get the parent namespace key.
    pub fn parent_key(&self) -> Option<i64> {
        self.symbol.parent_key
    }

    /// Add a child symbol key.
    pub fn add_child(&mut self, child_key: i64) {
        if !self.children_keys.contains(&child_key) {
            self.children_keys.push(child_key);
        }
    }

    /// Remove a child symbol key.
    pub fn remove_child(&mut self, child_key: i64) {
        self.children_keys.retain(|&k| k != child_key);
    }

    /// Get the number of children.
    pub fn child_count(&self) -> usize {
        self.children_keys.len()
    }

    /// Get the name.
    pub fn name(&self) -> &str {
        &self.symbol.name
    }

    /// Get the path segments.
    pub fn path(&self) -> Vec<&str> {
        let mut path = vec![self.symbol.name.as_str()];
        if let Some(ref parent_path) = self.symbol.space {
            path.insert(0, parent_path);
        }
        path
    }
}

/// A trace class symbol.
///
/// Ported from Ghidra's `TraceClassSymbol` interface.
/// A class is a namespace that represents an object-oriented class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceClassSymbol {
    /// The base namespace.
    pub namespace: TraceNamespaceSymbol,
}

impl TraceClassSymbol {
    /// Create a new class symbol.
    pub fn new(
        key: i64,
        name: impl Into<String>,
        parent_key: Option<i64>,
        lifespan: Lifespan,
    ) -> Self {
        let mut ns = TraceNamespaceSymbol::new(key, name, parent_key, lifespan);
        ns.symbol.kind = TraceSymbolKind::Class;
        Self { namespace: ns }
    }

    /// Create from an existing symbol.
    pub fn from_symbol(symbol: TraceSymbol) -> Option<Self> {
        if symbol.kind == TraceSymbolKind::Class {
            Some(Self {
                namespace: TraceNamespaceSymbol::from_symbol(symbol).unwrap(),
            })
        } else {
            None
        }
    }

    /// Get the class name.
    pub fn name(&self) -> &str {
        &self.namespace.symbol.name
    }

    /// Get the parent namespace key.
    pub fn parent_key(&self) -> Option<i64> {
        self.namespace.symbol.parent_key
    }

    /// Whether this is a global class.
    pub fn is_global(&self) -> bool {
        self.namespace.is_global()
    }

    /// Add a child member.
    pub fn add_child(&mut self, child_key: i64) {
        self.namespace.add_child(child_key);
    }
}

/// A view over namespace symbols with their children (extended).
///
/// This provides additional query capabilities beyond the base TraceNamespaceSymbolView.
#[derive(Debug, Clone)]
pub struct TraceNamespaceSymbolExtView<'a> {
    /// The namespaces in this view.
    pub namespaces: Vec<&'a TraceNamespaceSymbol>,
}

impl<'a> TraceNamespaceSymbolExtView<'a> {
    /// Create a new view.
    pub fn new(namespaces: Vec<&'a TraceNamespaceSymbol>) -> Self {
        Self { namespaces }
    }

    /// Get the number of namespaces.
    pub fn len(&self) -> usize {
        self.namespaces.len()
    }

    /// Whether this view is empty.
    pub fn is_empty(&self) -> bool {
        self.namespaces.is_empty()
    }

    /// Get the global namespace.
    pub fn global(&self) -> Option<&'a TraceNamespaceSymbol> {
        self.namespaces.iter().find(|ns| ns.is_global()).copied()
    }

    /// Get a namespace by name.
    pub fn get_by_name(&self, name: &str) -> Option<&'a TraceNamespaceSymbol> {
        self.namespaces
            .iter()
            .find(|ns| ns.name() == name)
            .copied()
    }
}

/// A view over class symbols (extended).
///
/// This provides additional query capabilities beyond the base TraceClassSymbolView.
#[derive(Debug, Clone)]
pub struct TraceClassSymbolExtView<'a> {
    /// The classes in this view.
    pub classes: Vec<&'a TraceClassSymbol>,
}

impl<'a> TraceClassSymbolExtView<'a> {
    /// Create a new view.
    pub fn new(classes: Vec<&'a TraceClassSymbol>) -> Self {
        Self { classes }
    }

    /// Get the number of classes.
    pub fn len(&self) -> usize {
        self.classes.len()
    }

    /// Whether this view is empty.
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }

    /// Get a class by name.
    pub fn get_by_name(&self, name: &str) -> Option<&'a TraceClassSymbol> {
        self.classes
            .iter()
            .find(|c| c.name() == name)
            .copied()
    }
}

/// A view over label symbols (extended).
///
/// This provides additional query capabilities beyond the base TraceLabelSymbolView.
#[derive(Debug, Clone)]
pub struct TraceLabelSymbolExtView<'a> {
    /// The labels in this view.
    pub labels: Vec<&'a TraceLabelSymbol>,
}

impl<'a> TraceLabelSymbolExtView<'a> {
    /// Create a new view.
    pub fn new(labels: Vec<&'a TraceLabelSymbol>) -> Self {
        Self { labels }
    }

    /// Get the number of labels.
    pub fn len(&self) -> usize {
        self.labels.len()
    }

    /// Whether this view is empty.
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    /// Get labels at a specific address.
    pub fn get_at(&self, address: u64) -> Vec<&'a TraceLabelSymbol> {
        self.labels
            .iter()
            .filter(|l| l.address() == Some(address))
            .copied()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_with_lifespan() {
        let symbol = TraceSymbol::label(1, "main", 0x1000, "ram", Lifespan::span(0, 100));
        let swl = TraceSymbolWithLifespan::new(symbol);
        assert_eq!(swl.start_snap(), 0);
        assert_eq!(swl.end_snap(), 100);
        assert_eq!(swl.name(), "main");
    }

    #[test]
    fn test_symbol_with_lifespan_set_end() {
        let symbol = TraceSymbol::label(1, "main", 0x1000, "ram", Lifespan::span(0, 100));
        let mut swl = TraceSymbolWithLifespan::new(symbol);
        swl.set_end_snap(200);
        assert_eq!(swl.end_snap(), 200);
    }

    #[test]
    fn test_label_symbol() {
        let label = TraceLabelSymbol::new(1, "main", 0x1000, "ram", Lifespan::span(0, 100));
        assert_eq!(label.name(), "main");
        assert_eq!(label.address(), Some(0x1000));
        assert_eq!(label.space(), Some("ram"));
    }

    #[test]
    fn test_label_from_symbol() {
        let symbol = TraceSymbol::label(1, "main", 0x1000, "ram", Lifespan::span(0, 100));
        assert!(TraceLabelSymbol::from_symbol(symbol).is_some());

        let ns = TraceSymbol::namespace(2, "std", None, Lifespan::span(0, 100));
        assert!(TraceLabelSymbol::from_symbol(ns).is_none());
    }

    #[test]
    fn test_namespace_symbol() {
        let mut ns = TraceNamespaceSymbol::new(1, "std", None, Lifespan::span(0, 100));
        assert!(ns.is_global());
        assert_eq!(ns.name(), "std");
        assert_eq!(ns.child_count(), 0);

        ns.add_child(2);
        ns.add_child(3);
        assert_eq!(ns.child_count(), 2);

        ns.remove_child(2);
        assert_eq!(ns.child_count(), 1);
    }

    #[test]
    fn test_namespace_from_symbol() {
        let symbol = TraceSymbol::namespace(1, "std", None, Lifespan::span(0, 100));
        let ns = TraceNamespaceSymbol::from_symbol(symbol);
        assert!(ns.is_some());
        assert!(ns.unwrap().is_global());
    }

    #[test]
    fn test_class_symbol() {
        let class = TraceClassSymbol::new(1, "MyClass", None, Lifespan::span(0, 100));
        assert_eq!(class.name(), "MyClass");
        assert!(class.is_global());
        assert_eq!(class.parent_key(), None);
    }

    #[test]
    fn test_class_from_symbol() {
        let mut symbol = TraceSymbol::namespace(1, "MyClass", None, Lifespan::span(0, 100));
        symbol.kind = TraceSymbolKind::Class;
        assert!(TraceClassSymbol::from_symbol(symbol).is_some());
    }

    #[test]
    fn test_namespace_view() {
        let ns1 = TraceNamespaceSymbol::new(1, "global", None, Lifespan::span(0, 100));
        let ns2 = TraceNamespaceSymbol::new(2, "std", Some(1), Lifespan::span(0, 100));
        let view = TraceNamespaceSymbolExtView::new(vec![&ns1, &ns2]);

        assert_eq!(view.len(), 2);
        assert!(view.global().is_some());
        assert_eq!(view.global().unwrap().name(), "global");
        assert!(view.get_by_name("std").is_some());
        assert!(view.get_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_class_view() {
        let c1 = TraceClassSymbol::new(1, "ClassA", None, Lifespan::span(0, 100));
        let c2 = TraceClassSymbol::new(2, "ClassB", None, Lifespan::span(0, 100));
        let view = TraceClassSymbolExtView::new(vec![&c1, &c2]);

        assert_eq!(view.len(), 2);
        assert!(view.get_by_name("ClassA").is_some());
        assert!(view.get_by_name("ClassC").is_none());
    }

    #[test]
    fn test_label_view() {
        let l1 = TraceLabelSymbol::new(1, "main", 0x1000, "ram", Lifespan::span(0, 100));
        let l2 = TraceLabelSymbol::new(2, "start", 0x2000, "ram", Lifespan::span(0, 100));
        let view = TraceLabelSymbolExtView::new(vec![&l1, &l2]);

        assert_eq!(view.len(), 2);
        assert_eq!(view.get_at(0x1000).len(), 1);
        assert!(view.get_at(0x3000).is_empty());
    }
}
