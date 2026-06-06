//! TraceSymbolNoDuplicatesView - view that ensures no duplicate symbols.
//!
//! Ported from Ghidra's `ghidra.trace.model.symbol.TraceSymbolNoDuplicatesView`.

use super::symbol::{TraceSymbol, TraceSymbolKind};
use std::collections::HashMap;

/// A view that returns only unique symbols (one per address at a given snap).
///
/// When multiple symbols exist at the same address, the primary symbol is preferred.
#[derive(Debug, Clone)]
pub struct TraceSymbolNoDuplicatesView {
    /// Filter to a specific symbol kind.
    pub kind_filter: Option<TraceSymbolKind>,
}

impl TraceSymbolNoDuplicatesView {
    /// Create a new no-duplicates view.
    pub fn new() -> Self {
        Self { kind_filter: None }
    }

    /// Create a view filtered to a specific kind.
    pub fn of_kind(kind: TraceSymbolKind) -> Self {
        Self {
            kind_filter: Some(kind),
        }
    }

    /// Get unique symbols at the given snap, preferring primary symbols.
    pub fn get_all_at<'a>(&self, snap: i64, symbols: &'a [TraceSymbol]) -> Vec<&'a TraceSymbol> {
        let filtered: Vec<&TraceSymbol> = symbols
            .iter()
            .filter(|s| {
                s.lifespan.contains(snap)
                    && self.kind_filter.map_or(true, |k| s.kind == k)
            })
            .collect();

        // Group by (space, address) and pick the primary symbol (or first)
        let mut by_addr: HashMap<(Option<String>, Option<u64>), &TraceSymbol> = HashMap::new();
        for sym in filtered {
            let key = (sym.space.clone(), sym.address);
            by_addr
                .entry(key)
                .and_modify(|existing| {
                    // Prefer the one without a parent (more top-level / primary)
                    if sym.parent_key.is_none() && existing.parent_key.is_some() {
                        *existing = sym;
                    }
                })
                .or_insert(sym);
        }
        by_addr.into_values().collect()
    }

    /// Get the unique symbol at a specific address.
    pub fn get_at<'a>(
        &self,
        snap: i64,
        address: u64,
        symbols: &'a [TraceSymbol],
    ) -> Option<&'a TraceSymbol> {
        let candidates: Vec<&TraceSymbol> = symbols
            .iter()
            .filter(|s| {
                s.lifespan.contains(snap)
                    && s.address == Some(address)
                    && self.kind_filter.map_or(true, |k| s.kind == k)
            })
            .collect();

        // Prefer primary (no parent)
        candidates
            .iter()
            .find(|s| s.parent_key.is_none())
            .or_else(|| candidates.first())
            .copied()
    }
}

impl Default for TraceSymbolNoDuplicatesView {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_duplicates_prefers_primary() {
        let symbols = vec![
            TraceSymbol::label(1, "primary", 0x1000, "ram", Lifespan::span(0, 100)),
            TraceSymbol {
                key: 2,
                name: "secondary".into(),
                address: Some(0x1000),
                space: Some("ram".into()),
                kind: TraceSymbolKind::Label,
                parent_key: Some(5),
                lifespan: Lifespan::span(0, 100),
            },
        ];

        let view = TraceSymbolNoDuplicatesView::new();
        let result = view.get_all_at(0, &symbols);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "primary");
    }

    #[test]
    fn test_get_at() {
        let symbols = vec![
            TraceSymbol::label(1, "foo", 0x1000, "ram", Lifespan::span(0, 100)),
            TraceSymbol::label(2, "bar", 0x2000, "ram", Lifespan::span(0, 100)),
        ];

        let view = TraceSymbolNoDuplicatesView::new();
        let found = view.get_at(0, 0x1000, &symbols);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "foo");
    }

    #[test]
    fn test_different_addresses_not_deduplicated() {
        let symbols = vec![
            TraceSymbol::label(1, "a", 0x1000, "ram", Lifespan::span(0, 100)),
            TraceSymbol::label(2, "b", 0x2000, "ram", Lifespan::span(0, 100)),
        ];

        let view = TraceSymbolNoDuplicatesView::new();
        assert_eq!(view.get_all_at(0, &symbols).len(), 2);
    }
}
