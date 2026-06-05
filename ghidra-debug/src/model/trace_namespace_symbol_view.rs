//! TraceNamespaceSymbolView - view for querying namespace symbols in a trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.symbol.TraceNamespaceSymbolView`.

use super::Lifespan;
use super::symbol::{TraceSymbol, TraceSymbolKind};

/// A view for querying namespace symbols, filtered by snap and parent.
#[derive(Debug, Clone)]
pub struct TraceNamespaceSymbolView;

impl TraceNamespaceSymbolView {
    /// Get all namespaces at the given snap.
    pub fn get_all_at(snap: i64, symbols: &[TraceSymbol]) -> Vec<&TraceSymbol> {
        symbols
            .iter()
            .filter(|s| {
                (s.kind == TraceSymbolKind::Namespace || s.kind == TraceSymbolKind::Class)
                    && s.lifespan.contains(snap)
            })
            .collect()
    }

    /// Get a namespace by name at the given snap.
    pub fn get_by_name<'a>(
        snap: i64,
        name: &str,
        symbols: &'a [TraceSymbol],
    ) -> Option<&'a TraceSymbol> {
        symbols.iter().find(|s| {
            (s.kind == TraceSymbolKind::Namespace || s.kind == TraceSymbolKind::Class)
                && s.lifespan.contains(snap)
                && s.name == name
        })
    }

    /// Get a namespace by its key.
    pub fn get_by_key(key: i64, symbols: &[TraceSymbol]) -> Option<&TraceSymbol> {
        symbols.iter().find(|s| {
            (s.kind == TraceSymbolKind::Namespace || s.kind == TraceSymbolKind::Class)
                && s.key == key
        })
    }

    /// Get child namespaces of a given parent at the given snap.
    pub fn get_children(
        snap: i64,
        parent_key: Option<i64>,
        symbols: &[TraceSymbol],
    ) -> Vec<&TraceSymbol> {
        symbols
            .iter()
            .filter(|s| {
                (s.kind == TraceSymbolKind::Namespace || s.kind == TraceSymbolKind::Class)
                    && s.lifespan.contains(snap)
                    && s.parent_key == parent_key
            })
            .collect()
    }

    /// Create a namespace symbol.
    pub fn create(
        key: i64,
        name: impl Into<String>,
        parent_key: Option<i64>,
        lifespan: Lifespan,
    ) -> TraceSymbol {
        TraceSymbol::namespace(key, name, parent_key, lifespan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_view_filter() {
        let symbols = vec![
            TraceSymbol::namespace(1, "global", None, Lifespan::span(0, 100)),
            TraceSymbol::namespace(2, "libc", Some(1), Lifespan::span(0, 100)),
            TraceSymbol::label(3, "main", 0x400000, "ram", Lifespan::span(0, 100)),
        ];

        let namespaces = TraceNamespaceSymbolView::get_all_at(0, &symbols);
        assert_eq!(namespaces.len(), 2);
    }

    #[test]
    fn test_namespace_by_name() {
        let symbols = vec![
            TraceSymbol::namespace(1, "global", None, Lifespan::span(0, 100)),
            TraceSymbol::namespace(2, "libc", Some(1), Lifespan::span(0, 100)),
        ];

        let ns = TraceNamespaceSymbolView::get_by_name(0, "libc", &symbols);
        assert!(ns.is_some());
        assert_eq!(ns.unwrap().key, 2);
    }

    #[test]
    fn test_namespace_children() {
        let symbols = vec![
            TraceSymbol::namespace(1, "global", None, Lifespan::span(0, 100)),
            TraceSymbol::namespace(2, "libc", Some(1), Lifespan::span(0, 100)),
            TraceSymbol::namespace(3, "kernel", Some(1), Lifespan::span(0, 100)),
            TraceSymbol::namespace(4, "net", Some(2), Lifespan::span(0, 100)),
        ];

        let children = TraceNamespaceSymbolView::get_children(0, Some(1), &symbols);
        assert_eq!(children.len(), 2);

        let root = TraceNamespaceSymbolView::get_children(0, None, &symbols);
        assert_eq!(root.len(), 1);
    }
}
