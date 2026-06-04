//! Symbol tree service -- ported from `SymbolTreeService.java`.
//!
//! The [`SymbolTreeService`] trait defines the interface that other
//! plugins use to interact with the symbol tree (selecting symbols,
//! navigating to them, etc.).

use ghidra_core::symbol::Symbol;

/// Service interface for the symbol tree plugin.
///
/// Provides methods for selecting and navigating to symbols from
/// external consumers (e.g., the listing, the decompiler, search
/// results).
pub trait SymbolTreeService: Send + Sync {
    /// Selects (highlights) the given symbol in the tree.
    fn select_symbol(&self, symbol: &Symbol);

    /// Navigates to the given symbol (selects and scrolls to it).
    fn go_to_symbol(&self, symbol: &Symbol) -> bool;

    /// Returns the number of symbols currently displayed in the tree.
    fn symbol_count(&self) -> usize;

    /// Expands the tree to show the given symbol's location.
    fn expand_to_symbol(&self, symbol: &Symbol) -> bool;

    /// Refreshes the tree from the current program state.
    fn refresh(&mut self);

    /// Returns `true` if a program is currently loaded.
    fn has_program(&self) -> bool;
}

/// A no-op implementation of [`SymbolTreeService`] for testing.
#[derive(Debug, Default)]
pub struct NullSymbolTreeService;

impl SymbolTreeService for NullSymbolTreeService {
    fn select_symbol(&self, _symbol: &Symbol) {}
    fn go_to_symbol(&self, _symbol: &Symbol) -> bool { false }
    fn symbol_count(&self) -> usize { 0 }
    fn expand_to_symbol(&self, _symbol: &Symbol) -> bool { false }
    fn refresh(&mut self) {}
    fn has_program(&self) -> bool { false }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;

    #[test]
    fn test_null_service() {
        let svc = NullSymbolTreeService;
        assert!(!svc.has_program());
        assert_eq!(svc.symbol_count(), 0);
        let sym = Symbol::function("main", Address::new(0x401000));
        assert!(!svc.go_to_symbol(&sym));
        assert!(!svc.expand_to_symbol(&sym));
        svc.select_symbol(&sym); // no-op
    }
}
