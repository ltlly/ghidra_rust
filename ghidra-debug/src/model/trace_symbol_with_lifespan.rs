//! TraceSymbolWithLifespan - symbols with explicit lifespan tracking.
//!
//! Ported from Ghidra's `ghidra.trace.model.symbol.TraceSymbolWithLifespan`.

use serde::{Deserialize, Serialize};

use super::Lifespan;
use super::symbol::{TraceSymbol, TraceSymbolKind};

/// Extension trait for symbols that carry an explicit lifespan.
///
/// In Ghidra, symbols can be created and destroyed over time in a trace.
/// This trait provides the lifespan-aware query API.
pub trait SymbolWithLifespan {
    /// Get the lifespan of this symbol.
    fn lifespan(&self) -> Lifespan;

    /// Check if this symbol is live at the given snap.
    fn is_live_at(&self, snap: i64) -> bool {
        self.lifespan().contains(snap)
    }

    /// Check if this symbol is in the scratch (current) snap.
    fn is_scratch(&self) -> bool {
        self.lifespan().lmax() == i64::MAX
    }
}

/// A symbol entry that includes lifespan information, used for DB storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSymbolEntry {
    /// The symbol data.
    pub symbol: TraceSymbol,
    /// The source type (user-defined, analysis, import, etc.).
    pub source_type: SourceType,
    /// Whether this is the primary symbol at its address.
    pub primary: bool,
    /// Whether the symbol is pinned (cannot be moved by memory shifts).
    pub pinned: bool,
}

/// Source of a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceType {
    /// User-defined.
    UserDefined,
    /// Analysis-derived.
    Analysis,
    /// Imported from external source.
    Import,
    /// Default / implicit.
    Default,
}

impl TraceSymbolEntry {
    /// Create a new symbol entry.
    pub fn new(symbol: TraceSymbol, source_type: SourceType) -> Self {
        Self {
            symbol,
            source_type,
            primary: true,
            pinned: false,
        }
    }

    /// Create a primary user-defined entry.
    pub fn user_primary(symbol: TraceSymbol) -> Self {
        Self {
            symbol,
            source_type: SourceType::UserDefined,
            primary: true,
            pinned: false,
        }
    }

    /// Get the lifespan.
    pub fn lifespan(&self) -> Lifespan {
        self.symbol.lifespan
    }

    /// Check if live at a snap.
    pub fn is_live_at(&self, snap: i64) -> bool {
        self.symbol.lifespan.contains(snap)
    }
}

impl SymbolWithLifespan for TraceSymbolEntry {
    fn lifespan(&self) -> Lifespan {
        self.symbol.lifespan
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_entry() {
        let sym = TraceSymbol::label(1, "test", 0x1000, "ram", Lifespan::span(0, 100));
        let entry = TraceSymbolEntry::user_primary(sym);

        assert_eq!(entry.source_type, SourceType::UserDefined);
        assert!(entry.primary);
        assert!(!entry.pinned);
        assert!(entry.is_live_at(50));
        assert!(!entry.is_live_at(200));
    }

    #[test]
    fn test_source_type() {
        assert_ne!(SourceType::UserDefined, SourceType::Analysis);
        assert_ne!(SourceType::Import, SourceType::Default);
    }

    #[test]
    fn test_scratch_detection() {
        let sym = TraceSymbol::label(1, "test", 0x1000, "ram", Lifespan::span(0, i64::MAX));
        let entry = TraceSymbolEntry::new(sym, SourceType::UserDefined);
        assert!(entry.is_scratch());
    }
}
