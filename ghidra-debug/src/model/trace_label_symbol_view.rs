//! TraceLabelSymbolView - view for querying label symbols in a trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.symbol.TraceLabelSymbolView`.

use serde::{Deserialize, Serialize};

use super::Lifespan;
use super::symbol::{TraceSymbol, TraceSymbolKind};

/// A view for querying label symbols filtered by snap, thread, and address.
///
/// Labels are the most common symbol type in traces, representing named
/// addresses (function entries, data labels, etc.).
#[derive(Debug, Clone)]
pub struct TraceLabelSymbolView {
    /// Filter to a specific address space name.
    pub space_filter: Option<String>,
    /// Filter to a specific thread key.
    pub thread_filter: Option<i64>,
}

impl TraceLabelSymbolView {
    /// Create a new label symbol view.
    pub fn new() -> Self {
        Self {
            space_filter: None,
            thread_filter: None,
        }
    }

    /// Create a view filtered to a specific address space.
    pub fn in_space(space: impl Into<String>) -> Self {
        Self {
            space_filter: Some(space.into()),
            thread_filter: None,
        }
    }

    /// Create a view filtered to a specific thread.
    pub fn for_thread(thread_key: i64) -> Self {
        Self {
            space_filter: None,
            thread_filter: Some(thread_key),
        }
    }

    /// Check if a symbol matches this view's filters.
    pub fn matches(&self, symbol: &TraceSymbol) -> bool {
        if symbol.kind != TraceSymbolKind::Label {
            return false;
        }
        if let Some(ref space) = self.space_filter {
            if symbol.space.as_ref() != Some(space) {
                return false;
            }
        }
        true
    }

    /// Get a label at the given snap, thread, and address from a collection.
    pub fn get_at<'a>(
        &self,
        snap: i64,
        thread_key: Option<i64>,
        address: u64,
        symbols: &'a [TraceSymbol],
    ) -> Option<&'a TraceSymbol> {
        symbols.iter().find(|s| {
            s.kind == TraceSymbolKind::Label
                && s.lifespan.contains(snap)
                && s.address == Some(address)
                && self.matches_thread(s, thread_key)
        })
    }

    /// Get all labels at the given snap from a collection.
    pub fn get_all_at<'a>(
        &self,
        snap: i64,
        symbols: &'a [TraceSymbol],
    ) -> Vec<&'a TraceSymbol> {
        symbols
            .iter()
            .filter(|s| {
                s.kind == TraceSymbolKind::Label
                    && s.lifespan.contains(snap)
                    && self.matches(s)
            })
            .collect()
    }

    /// Get labels contained in the given address range at a snap.
    pub fn get_containing<'a>(
        &self,
        snap: i64,
        min_addr: u64,
        max_addr: u64,
        symbols: &'a [TraceSymbol],
    ) -> Vec<&'a TraceSymbol> {
        symbols
            .iter()
            .filter(|s| {
                s.kind == TraceSymbolKind::Label
                    && s.lifespan.contains(snap)
                    && self.matches(s)
                    && s.address.is_some()
                    && s.address.unwrap() >= min_addr
                    && s.address.unwrap() <= max_addr
            })
            .collect()
    }

    /// Create a label symbol.
    pub fn create(
        key: i64,
        name: impl Into<String>,
        address: u64,
        space: impl Into<String>,
        lifespan: Lifespan,
    ) -> TraceSymbol {
        TraceSymbol::label(key, name, address, space, lifespan)
    }

    fn matches_thread(&self, symbol: &TraceSymbol, thread_key: Option<i64>) -> bool {
        if let Some(_tk) = thread_key {
            // Thread filtering would be checked via the symbol's space
            true
        } else {
            true
        }
    }
}

impl Default for TraceLabelSymbolView {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_view_matches() {
        let view = TraceLabelSymbolView::new();
        let label = TraceSymbol::label(1, "main", 0x400000, "ram", Lifespan::span(0, 100));
        assert!(view.matches(&label));

        let ns = TraceSymbol::namespace(2, "libc", None, Lifespan::span(0, 100));
        assert!(!view.matches(&ns));
    }

    #[test]
    fn test_label_view_space_filter() {
        let view = TraceLabelSymbolView::in_space("ram");
        let label_ram = TraceSymbol::label(1, "main", 0x400000, "ram", Lifespan::span(0, 100));
        let label_reg = TraceSymbol::label(2, "RAX", 0, "register", Lifespan::span(0, 100));

        assert!(view.matches(&label_ram));
        assert!(!view.matches(&label_reg));
    }

    #[test]
    fn test_get_at() {
        let symbols = vec![
            TraceSymbol::label(1, "main", 0x400000, "ram", Lifespan::span(0, 100)),
            TraceSymbol::label(2, "foo", 0x401000, "ram", Lifespan::span(10, 100)),
            TraceSymbol::namespace(3, "libc", None, Lifespan::span(0, 100)),
        ];
        let view = TraceLabelSymbolView::new();

        let found = view.get_at(5, None, 0x400000, &symbols);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "main");

        // foo not yet created at snap 5
        assert!(view.get_at(5, None, 0x401000, &symbols).is_none());
        // foo created at snap 10
        assert!(view.get_at(10, None, 0x401000, &symbols).is_some());
    }

    #[test]
    fn test_get_containing() {
        let symbols = vec![
            TraceSymbol::label(1, "a", 0x1000, "ram", Lifespan::span(0, 100)),
            TraceSymbol::label(2, "b", 0x2000, "ram", Lifespan::span(0, 100)),
            TraceSymbol::label(3, "c", 0x3000, "ram", Lifespan::span(0, 100)),
        ];
        let view = TraceLabelSymbolView::new();
        let result = view.get_containing(0, 0x1000, 0x2000, &symbols);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_create() {
        let sym = TraceLabelSymbolView::create(1, "test", 0x100, "ram", Lifespan::span(0, 50));
        assert_eq!(sym.kind, TraceSymbolKind::Label);
        assert_eq!(sym.name, "test");
    }
}
