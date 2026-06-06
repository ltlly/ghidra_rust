//! TraceSymbolView - generic view for querying all symbol types in a trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.symbol.TraceSymbolView`.

use super::symbol::{TraceSymbol, TraceSymbolKind};

/// Sort order for symbol queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolSortOrder {
    /// Sort by address ascending.
    AddressAscending,
    /// Sort by address descending.
    AddressDescending,
    /// Sort by name ascending.
    NameAscending,
    /// Sort by key ascending.
    KeyAscending,
    /// Primary symbols first.
    PrimaryFirst,
}

/// A view for querying all symbol types, optionally filtered by kind.
#[derive(Debug, Clone)]
pub struct TraceSymbolView {
    /// Filter to a specific symbol kind.
    pub kind_filter: Option<TraceSymbolKind>,
    /// Sort order for results.
    pub sort_order: SymbolSortOrder,
}

impl TraceSymbolView {
    /// Create a new view showing all symbol types.
    pub fn all() -> Self {
        Self {
            kind_filter: None,
            sort_order: SymbolSortOrder::AddressAscending,
        }
    }

    /// Create a view filtered to a specific kind.
    pub fn of_kind(kind: TraceSymbolKind) -> Self {
        Self {
            kind_filter: Some(kind),
            sort_order: SymbolSortOrder::AddressAscending,
        }
    }

    /// Get all symbols at the given snap.
    pub fn get_all_at<'a>(&self, snap: i64, symbols: &'a [TraceSymbol]) -> Vec<&'a TraceSymbol> {
        let mut result: Vec<&'a TraceSymbol> = symbols
            .iter()
            .filter(|s| {
                s.lifespan.contains(snap)
                    && self
                        .kind_filter
                        .map_or(true, |k| s.kind == k)
            })
            .collect();

        match self.sort_order {
            SymbolSortOrder::AddressAscending => {
                result.sort_by_key(|s| s.address.unwrap_or(0));
            }
            SymbolSortOrder::AddressDescending => {
                result.sort_by(|a, b| {
                    b.address.unwrap_or(0).cmp(&a.address.unwrap_or(0))
                });
            }
            SymbolSortOrder::NameAscending => {
                result.sort_by(|a, b| a.name.cmp(&b.name));
            }
            SymbolSortOrder::KeyAscending => {
                result.sort_by_key(|s| s.key);
            }
            SymbolSortOrder::PrimaryFirst => {
                result.sort_by_key(|s| (s.parent_key.is_some(), s.address.unwrap_or(0)));
            }
        }
        result
    }

    /// Get a symbol by its key.
    pub fn get_by_key<'a>(&self, key: i64, symbols: &'a [TraceSymbol]) -> Option<&'a TraceSymbol> {
        symbols.iter().find(|s| {
            s.key == key && self.kind_filter.map_or(true, |k| s.kind == k)
        })
    }

    /// Get symbols contained in the given address range at a snap.
    pub fn get_in_range<'a>(
        &self,
        snap: i64,
        min_addr: u64,
        max_addr: u64,
        symbols: &'a [TraceSymbol],
    ) -> Vec<&'a TraceSymbol> {
        symbols
            .iter()
            .filter(|s| {
                s.lifespan.contains(snap)
                    && self.kind_filter.map_or(true, |k| s.kind == k)
                    && s.address.is_some()
                    && s.address.unwrap() >= min_addr
                    && s.address.unwrap() <= max_addr
            })
            .collect()
    }

    /// Count symbols at the given snap.
    pub fn count_at(&self, snap: i64, symbols: &[TraceSymbol]) -> usize {
        symbols
            .iter()
            .filter(|s| {
                s.lifespan.contains(snap)
                    && self.kind_filter.map_or(true, |k| s.kind == k)
            })
            .count()
    }

    /// Get symbols matching a name pattern at the given snap.
    pub fn get_by_name_contains<'a>(
        &self,
        snap: i64,
        pattern: &str,
        symbols: &'a [TraceSymbol],
    ) -> Vec<&'a TraceSymbol> {
        symbols
            .iter()
            .filter(|s| {
                s.lifespan.contains(snap)
                    && self.kind_filter.map_or(true, |k| s.kind == k)
                    && s.name.contains(pattern)
            })
            .collect()
    }
}

impl Default for TraceSymbolView {
    fn default() -> Self {
        Self::all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Lifespan;

    #[test]
    fn test_all_symbols_view() {
        let symbols = vec![
            TraceSymbol::label(1, "main", 0x400000, "ram", Lifespan::span(0, 100)),
            TraceSymbol::namespace(2, "global", None, Lifespan::span(0, 100)),
            TraceSymbol {
                key: 3,
                name: "MyClass".into(),
                address: None,
                space: None,
                kind: TraceSymbolKind::Class,
                parent_key: None,
                lifespan: Lifespan::span(0, 100),
            },
        ];

        let view = TraceSymbolView::all();
        assert_eq!(view.count_at(0, &symbols), 3);
    }

    #[test]
    fn test_filtered_view() {
        let symbols = vec![
            TraceSymbol::label(1, "main", 0x400000, "ram", Lifespan::span(0, 100)),
            TraceSymbol::namespace(2, "global", None, Lifespan::span(0, 100)),
        ];

        let label_view = TraceSymbolView::of_kind(TraceSymbolKind::Label);
        assert_eq!(label_view.count_at(0, &symbols), 1);

        let ns_view = TraceSymbolView::of_kind(TraceSymbolKind::Namespace);
        assert_eq!(ns_view.count_at(0, &symbols), 1);
    }

    #[test]
    fn test_sort_orders() {
        let symbols = vec![
            TraceSymbol::label(1, "c_sym", 0x3000, "ram", Lifespan::span(0, 100)),
            TraceSymbol::label(2, "a_sym", 0x1000, "ram", Lifespan::span(0, 100)),
            TraceSymbol::label(3, "b_sym", 0x2000, "ram", Lifespan::span(0, 100)),
        ];

        let mut view = TraceSymbolView::of_kind(TraceSymbolKind::Label);
        view.sort_order = SymbolSortOrder::NameAscending;
        let result = view.get_all_at(0, &symbols);
        assert_eq!(result[0].name, "a_sym");
        assert_eq!(result[1].name, "b_sym");
        assert_eq!(result[2].name, "c_sym");
    }

    #[test]
    fn test_name_search() {
        let symbols = vec![
            TraceSymbol::label(1, "malloc", 0x1000, "ram", Lifespan::span(0, 100)),
            TraceSymbol::label(2, "calloc", 0x2000, "ram", Lifespan::span(0, 100)),
            TraceSymbol::label(3, "free", 0x3000, "ram", Lifespan::span(0, 100)),
        ];

        let view = TraceSymbolView::all();
        let found = view.get_by_name_contains(0, "alloc", &symbols);
        assert_eq!(found.len(), 2);
    }
}
