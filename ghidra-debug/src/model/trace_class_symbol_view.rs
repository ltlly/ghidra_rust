//! TraceClassSymbolView - view for querying class symbols in a trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.symbol.TraceClassSymbolView`.

use super::Lifespan;
use super::symbol::{TraceSymbol, TraceSymbolKind};

/// A view for querying class symbols, filtered by snap.
#[derive(Debug, Clone)]
pub struct TraceClassSymbolView;

impl TraceClassSymbolView {
    /// Get all class symbols at the given snap.
    pub fn get_all_at(snap: i64, symbols: &[TraceSymbol]) -> Vec<&TraceSymbol> {
        symbols
            .iter()
            .filter(|s| s.kind == TraceSymbolKind::Class && s.lifespan.contains(snap))
            .collect()
    }

    /// Get a class symbol by name at the given snap.
    pub fn get_by_name<'a>(
        snap: i64,
        name: &str,
        symbols: &'a [TraceSymbol],
    ) -> Option<&'a TraceSymbol> {
        symbols.iter().find(|s| {
            s.kind == TraceSymbolKind::Class && s.lifespan.contains(snap) && s.name == name
        })
    }

    /// Get a class symbol by key.
    pub fn get_by_key(key: i64, symbols: &[TraceSymbol]) -> Option<&TraceSymbol> {
        symbols
            .iter()
            .find(|s| s.kind == TraceSymbolKind::Class && s.key == key)
    }

    /// Create a class symbol.
    pub fn create(
        key: i64,
        name: impl Into<String>,
        parent_key: Option<i64>,
        lifespan: Lifespan,
    ) -> TraceSymbol {
        TraceSymbol {
            key,
            name: name.into(),
            address: None,
            space: None,
            kind: TraceSymbolKind::Class,
            parent_key,
            lifespan,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_class_view() {
        let symbols = vec![
            TraceSymbol::namespace(1, "global", None, Lifespan::new(0, 100)),
            TraceClassSymbolView::create(2, "MyClass", Some(1), Lifespan::new(0, 100)),
            TraceSymbol::label(3, "main", 0x400000, "ram", Lifespan::new(0, 100)),
        ];

        let classes = TraceClassSymbolView::get_all_at(0, &symbols);
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].name, "MyClass");
    }

    #[test]
    fn test_class_by_name() {
        let symbols = vec![
            TraceClassSymbolView::create(1, "MyClass", None, Lifespan::new(0, 100)),
            TraceClassSymbolView::create(2, "OtherClass", None, Lifespan::new(0, 100)),
        ];

        let found = TraceClassSymbolView::get_by_name(0, "MyClass", &symbols);
        assert!(found.is_some());
        assert_eq!(found.unwrap().key, 1);
    }
}
