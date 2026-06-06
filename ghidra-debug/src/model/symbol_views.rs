//! Symbol view types for querying symbols by type and scope.
//!
//! Ported from Ghidra's `ghidra.trace.model.symbol` view interfaces.
//! Provides filtered views into the symbol table (labels, namespaces,
//! classes, equates, references) with address, name, and lifespan queries.

use super::symbol::{TraceEquate, TraceEquateReference, TraceReference, TraceSymbol, TraceSymbolKind};

/// A view over symbols of a specific kind.
#[derive(Debug, Clone)]
pub struct TraceSymbolView<'a> {
    /// The symbols in this view.
    pub symbols: Vec<&'a TraceSymbol>,
}

impl<'a> TraceSymbolView<'a> {
    /// Create a new view from a slice of symbols.
    pub fn new(symbols: Vec<&'a TraceSymbol>) -> Self {
        Self { symbols }
    }

    /// Get the number of symbols in this view.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Whether this view is empty.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Get a symbol by key.
    pub fn get_by_key(&self, key: i64) -> Option<&'a TraceSymbol> {
        self.symbols.iter().find(|s| s.key == key).copied()
    }

    /// Get symbols at a given address and snap.
    pub fn get_at(&self, address: u64, space: &str, snap: i64) -> Vec<&'a TraceSymbol> {
        self.symbols
            .iter()
            .filter(|s| {
                s.address == Some(address)
                    && s.space.as_deref() == Some(space)
                    && s.lifespan.contains(snap)
            })
            .copied()
            .collect()
    }

    /// Get the symbol at a given address that is primary.
    pub fn get_primary_at(&self, address: u64, space: &str, snap: i64) -> Option<&'a TraceSymbol> {
        self.get_at(address, space, snap)
            .into_iter()
            .min_by_key(|s| {
                // Primary symbols sort first; order by key as tiebreaker
                if s.kind == TraceSymbolKind::Label {
                    (0, s.key)
                } else {
                    (1, s.key)
                }
            })
    }

    /// Get symbols with a given name at a given snap.
    pub fn get_by_name(&self, name: &str, snap: i64) -> Vec<&'a TraceSymbol> {
        self.symbols
            .iter()
            .filter(|s| s.name == name && s.lifespan.contains(snap))
            .copied()
            .collect()
    }

    /// Get all symbols that are valid at a given snap.
    pub fn all_at(&self, snap: i64) -> Vec<&'a TraceSymbol> {
        self.symbols
            .iter()
            .filter(|s| s.lifespan.contains(snap))
            .copied()
            .collect()
    }

    /// Get symbols in a given namespace at a snap.
    pub fn in_namespace(&self, parent_key: Option<i64>, snap: i64) -> Vec<&'a TraceSymbol> {
        self.symbols
            .iter()
            .filter(|s| s.parent_key == parent_key && s.lifespan.contains(snap))
            .copied()
            .collect()
    }

    /// Get all symbols in an address range at a given snap.
    pub fn in_range(
        &self,
        min_addr: u64,
        max_addr: u64,
        space: &str,
        snap: i64,
    ) -> Vec<&'a TraceSymbol> {
        self.symbols
            .iter()
            .filter(|s| {
                if let Some(addr) = s.address {
                    addr >= min_addr
                        && addr <= max_addr
                        && s.space.as_deref() == Some(space)
                        && s.lifespan.contains(snap)
                } else {
                    false
                }
            })
            .copied()
            .collect()
    }
}

/// A view over symbols without duplicates (one per canonical location).
#[derive(Debug, Clone)]
pub struct TraceSymbolNoDuplicatesView<'a> {
    /// The symbols in this view.
    symbols: Vec<&'a TraceSymbol>,
}

impl<'a> TraceSymbolNoDuplicatesView<'a> {
    /// Create a new no-duplicates view.
    pub fn new(symbols: Vec<&'a TraceSymbol>) -> Self {
        Self { symbols }
    }

    /// Get the number of symbols.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Whether this view is empty.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Iterate over symbols.
    pub fn iter(&self) -> impl Iterator<Item = &&'a TraceSymbol> {
        self.symbols.iter()
    }
}

/// A view over label symbols.
#[derive(Debug, Clone)]
pub struct TraceLabelSymbolView<'a> {
    inner: TraceSymbolView<'a>,
}

impl<'a> TraceLabelSymbolView<'a> {
    /// Create a label view from the full symbol list.
    pub fn from_all(symbols: &'a [TraceSymbol]) -> Self {
        let filtered: Vec<&'a TraceSymbol> = symbols
            .iter()
            .filter(|s| s.kind == TraceSymbolKind::Label)
            .collect();
        Self {
            inner: TraceSymbolView::new(filtered),
        }
    }

    /// Get the label at a specific address.
    pub fn get_at(&self, address: u64, space: &str, snap: i64) -> Vec<&'a TraceSymbol> {
        self.inner.get_at(address, space, snap)
    }

    /// Get the primary label at an address.
    pub fn get_primary_at(&self, address: u64, space: &str, snap: i64) -> Option<&'a TraceSymbol> {
        self.inner.get_primary_at(address, space, snap)
    }

    /// Get labels with a given name.
    pub fn get_by_name(&self, name: &str, snap: i64) -> Vec<&'a TraceSymbol> {
        self.inner.get_by_name(name, snap)
    }

    /// Get all labels valid at a snap.
    pub fn all_at(&self, snap: i64) -> Vec<&'a TraceSymbol> {
        self.inner.all_at(snap)
    }

    /// Get the number of labels.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether this view is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// A view over namespace symbols.
#[derive(Debug, Clone)]
pub struct TraceNamespaceSymbolView<'a> {
    inner: TraceSymbolView<'a>,
}

impl<'a> TraceNamespaceSymbolView<'a> {
    /// Create a namespace view from the full symbol list.
    pub fn from_all(symbols: &'a [TraceSymbol]) -> Self {
        let filtered: Vec<&'a TraceSymbol> = symbols
            .iter()
            .filter(|s| s.kind == TraceSymbolKind::Namespace)
            .collect();
        Self {
            inner: TraceSymbolView::new(filtered),
        }
    }

    /// Get all namespaces valid at a snap.
    pub fn all_at(&self, snap: i64) -> Vec<&'a TraceSymbol> {
        self.inner.all_at(snap)
    }

    /// Get namespaces in a given parent namespace.
    pub fn in_namespace(&self, parent_key: Option<i64>, snap: i64) -> Vec<&'a TraceSymbol> {
        self.inner.in_namespace(parent_key, snap)
    }

    /// Get the number of namespaces.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether this view is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// A view over class symbols.
#[derive(Debug, Clone)]
pub struct TraceClassSymbolView<'a> {
    inner: TraceSymbolView<'a>,
}

impl<'a> TraceClassSymbolView<'a> {
    /// Create a class view from the full symbol list.
    pub fn from_all(symbols: &'a [TraceSymbol]) -> Self {
        let filtered: Vec<&'a TraceSymbol> = symbols
            .iter()
            .filter(|s| s.kind == TraceSymbolKind::Class)
            .collect();
        Self {
            inner: TraceSymbolView::new(filtered),
        }
    }

    /// Get all classes valid at a snap.
    pub fn all_at(&self, snap: i64) -> Vec<&'a TraceSymbol> {
        self.inner.all_at(snap)
    }

    /// Get the number of classes.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether this view is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// A view over equates (named constants).
#[derive(Debug, Clone)]
pub struct TraceEquateView<'a> {
    /// The equates in this view.
    pub equates: Vec<&'a TraceEquate>,
    /// The equate references.
    pub references: Vec<&'a TraceEquateReference>,
}

impl<'a> TraceEquateView<'a> {
    /// Create a new equate view.
    pub fn new(
        equates: Vec<&'a TraceEquate>,
        references: Vec<&'a TraceEquateReference>,
    ) -> Self {
        Self {
            equates,
            references,
        }
    }

    /// Get equates at a given address.
    pub fn at_address(&self, address: u64, snap: i64) -> Vec<&'a TraceEquate> {
        self.references
            .iter()
            .filter(|r| r.address == address && r.lifespan.contains(snap))
            .filter_map(|r| self.equates.iter().find(|e| e.key == r.equate_key).copied())
            .collect()
    }

    /// Get an equate by name.
    pub fn get_by_name(&self, name: &str) -> Option<&'a TraceEquate> {
        self.equates.iter().find(|e| e.name == name).copied()
    }

    /// Get an equate by value.
    pub fn get_by_value(&self, value: i64) -> Vec<&'a TraceEquate> {
        self.equates
            .iter()
            .filter(|e| e.value == value)
            .copied()
            .collect()
    }
}

/// A view over references.
#[derive(Debug, Clone)]
pub struct TraceReferenceView<'a> {
    /// The references in this view.
    pub references: Vec<&'a TraceReference>,
}

impl<'a> TraceReferenceView<'a> {
    /// Create a new reference view.
    pub fn new(references: Vec<&'a TraceReference>) -> Self {
        Self { references }
    }

    /// Get references from a given address.
    pub fn from_address(&self, address: u64, snap: i64) -> Vec<&'a TraceReference> {
        self.references
            .iter()
            .filter(|r| r.from_address == address && r.lifespan.contains(snap))
            .copied()
            .collect()
    }

    /// Get references to a given address.
    pub fn to_address(&self, address: u64, snap: i64) -> Vec<&'a TraceReference> {
        self.references
            .iter()
            .filter(|r| r.to_address == address && r.lifespan.contains(snap))
            .copied()
            .collect()
    }

    /// Get primary references from a given address.
    pub fn primary_from(&self, address: u64, snap: i64) -> Vec<&'a TraceReference> {
        self.from_address(address, snap)
            .into_iter()
            .filter(|r| r.is_primary)
            .collect()
    }

    /// Get references of a specific kind.
    pub fn of_kind(
        &self,
        kind: super::symbol::TraceReferenceKind,
        snap: i64,
    ) -> Vec<&'a TraceReference> {
        self.references
            .iter()
            .filter(|r| r.kind == kind && r.lifespan.contains(snap))
            .copied()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Lifespan;

    fn make_label(key: i64, name: &str, addr: u64) -> TraceSymbol {
        TraceSymbol::label(key, name, addr, "ram", Lifespan::now_on(0))
    }

    fn make_ns(key: i64, name: &str, parent: Option<i64>) -> TraceSymbol {
        TraceSymbol::namespace(key, name, parent, Lifespan::ALL)
    }

    #[test]
    fn test_symbol_view_basic() {
        let labels = vec![make_label(1, "main", 0x400000), make_label(2, "foo", 0x400100)];
        let view = TraceSymbolView::new(labels.iter().collect());
        assert_eq!(view.len(), 2);
        assert!(!view.is_empty());
    }

    #[test]
    fn test_symbol_view_get_at() {
        let labels = vec![make_label(1, "main", 0x400000), make_label(2, "foo", 0x400100)];
        let view = TraceSymbolView::new(labels.iter().collect());
        let at = view.get_at(0x400000, "ram", 5);
        assert_eq!(at.len(), 1);
        assert_eq!(at[0].name, "main");
    }

    #[test]
    fn test_symbol_view_by_name() {
        let syms = vec![
            make_label(1, "shared", 0x100),
            make_label(2, "shared", 0x200),
            make_label(3, "unique", 0x300),
        ];
        let view = TraceSymbolView::new(syms.iter().collect());
        let shared = view.get_by_name("shared", 5);
        assert_eq!(shared.len(), 2);
    }

    #[test]
    fn test_label_view() {
        let syms = vec![
            make_label(1, "main", 0x400000),
            make_ns(2, "libc", None),
            make_label(3, "printf", 0x400100),
        ];
        let view = TraceLabelSymbolView::from_all(&syms);
        assert_eq!(view.len(), 2); // only labels
        assert_eq!(view.all_at(5).len(), 2);
    }

    #[test]
    fn test_namespace_view() {
        let syms = vec![
            make_label(1, "main", 0x400000),
            make_ns(2, "libc", None),
            make_ns(3, "stdio", Some(2)),
        ];
        let view = TraceNamespaceSymbolView::from_all(&syms);
        assert_eq!(view.len(), 2);
        assert_eq!(view.in_namespace(None, 0).len(), 1); // libc
        assert_eq!(view.in_namespace(Some(2), 0).len(), 1); // stdio
    }

    #[test]
    fn test_class_view() {
        let syms = vec![
            make_label(1, "main", 0x400000),
            TraceSymbol {
                key: 2,
                name: "MyClass".into(),
                address: None,
                space: None,
                kind: TraceSymbolKind::Class,
                parent_key: None,
                lifespan: Lifespan::ALL,
            },
        ];
        let view = TraceClassSymbolView::from_all(&syms);
        assert_eq!(view.len(), 1);
    }

    #[test]
    fn test_symbol_view_in_range() {
        let syms = vec![
            make_label(1, "a", 0x100),
            make_label(2, "b", 0x200),
            make_label(3, "c", 0x300),
            make_label(4, "d", 0x400),
        ];
        let view = TraceSymbolView::new(syms.iter().collect());
        let in_range = view.in_range(0x150, 0x350, "ram", 5);
        assert_eq!(in_range.len(), 2); // b, c
    }

    #[test]
    fn test_equate_view() {
        let equates = vec![
            TraceEquate::new(1, "MY_CONST", 42, Lifespan::ALL),
            TraceEquate::new(2, "OTHER", 99, Lifespan::ALL),
        ];
        let refs = vec![TraceEquateReference {
            equate_key: 1,
            address: 0x400000,
            operand_index: 0,
            lifespan: Lifespan::ALL,
        }];
        let view = TraceEquateView::new(equates.iter().collect(), refs.iter().collect());
        let at = view.at_address(0x400000, 0);
        assert_eq!(at.len(), 1);
        assert_eq!(at[0].name, "MY_CONST");

        let by_name = view.get_by_name("OTHER");
        assert!(by_name.is_some());
    }

    #[test]
    fn test_reference_view() {
        let refs = vec![
            TraceReference::memory(1, 0x100, 0x200, Lifespan::ALL),
            TraceReference::memory(2, 0x100, 0x300, Lifespan::ALL).with_primary(true),
            TraceReference::stack(3, 0x200, 0x400, Lifespan::ALL),
        ];
        let view = TraceReferenceView::new(refs.iter().collect());
        let from = view.from_address(0x100, 0);
        assert_eq!(from.len(), 2);

        let primary = view.primary_from(0x100, 0);
        assert_eq!(primary.len(), 1);

        let to = view.to_address(0x300, 0);
        assert_eq!(to.len(), 1);
    }

    #[test]
    fn test_no_duplicates_view() {
        let syms = vec![make_label(1, "a", 0x100), make_label(2, "b", 0x200)];
        let view = TraceSymbolNoDuplicatesView::new(syms.iter().collect());
        assert_eq!(view.len(), 2);
        let collected: Vec<_> = view.iter().collect();
        assert_eq!(collected.len(), 2);
    }
}
