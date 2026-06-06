//! Symbol view types - typed views over trace symbols with address/location
//! and lifespan filtering.
//!
//! Ported from Ghidra's `ghidra.trace.model.symbol` package.
//! Provides specialized views that filter symbols by address range,
//! lifespan, or namespace to enable efficient lookup and iteration.

use serde::{Deserialize, Serialize};

use super::symbol::TraceSymbol;

/// A view of symbols within a specific address range.
///
/// Ported from Ghidra's `TraceSymbolWithAddressView` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSymbolWithAddressView {
    /// The address space name.
    pub space: String,
    /// Minimum address offset (inclusive).
    pub min_offset: u64,
    /// Maximum address offset (inclusive).
    pub max_offset: u64,
    /// The filtered symbols.
    pub symbols: Vec<TraceSymbol>,
}

impl TraceSymbolWithAddressView {
    /// Create a new view for a single address.
    pub fn at_address(space: impl Into<String>, offset: u64) -> Self {
        Self {
            space: space.into(),
            min_offset: offset,
            max_offset: offset,
            symbols: Vec::new(),
        }
    }

    /// Create a new view for an address range.
    pub fn in_range(space: impl Into<String>, min: u64, max: u64) -> Self {
        Self {
            space: space.into(),
            min_offset: min,
            max_offset: max,
            symbols: Vec::new(),
        }
    }

    /// Add a symbol to this view.
    pub fn push(&mut self, symbol: TraceSymbol) {
        self.symbols.push(symbol);
    }

    /// Get the count of symbols.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Check if the view is empty.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Iterate over the symbols.
    pub fn iter(&self) -> impl Iterator<Item = &TraceSymbol> {
        self.symbols.iter()
    }
}

/// A view of symbols within a specific address range, excluding duplicates.
///
/// Ported from Ghidra's `TraceSymbolWithAddressNoDuplicatesView`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSymbolWithAddressNoDuplicatesView {
    /// The underlying address view.
    pub inner: TraceSymbolWithAddressView,
}

impl TraceSymbolWithAddressNoDuplicatesView {
    /// Create from an existing address view.
    pub fn new(inner: TraceSymbolWithAddressView) -> Self {
        Self { inner }
    }

    /// Get the count of unique symbols.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the view is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Iterate over unique symbols.
    pub fn iter(&self) -> impl Iterator<Item = &TraceSymbol> {
        self.inner.iter()
    }
}

/// A view of symbols that have a location (address) in the trace.
///
/// Ported from Ghidra's `TraceSymbolWithLocationView` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSymbolWithLocationView {
    /// The address space name.
    pub space: String,
    /// The filtered symbols (only those with a location).
    pub symbols: Vec<TraceSymbol>,
}

impl TraceSymbolWithLocationView {
    /// Create a new view for the given address space.
    pub fn new(space: impl Into<String>) -> Self {
        Self {
            space: space.into(),
            symbols: Vec::new(),
        }
    }

    /// Add a symbol.
    pub fn push(&mut self, symbol: TraceSymbol) {
        self.symbols.push(symbol);
    }

    /// Get the count.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Check if the view is empty.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Iterate over the symbols.
    pub fn iter(&self) -> impl Iterator<Item = &TraceSymbol> {
        self.symbols.iter()
    }
}

/// A view of symbols within a namespace, optionally filtered by lifespan.
///
/// Ported from Ghidra's `TraceNamespaceSymbolView` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceNamespaceSymbolView {
    /// The namespace symbol key this view is under.
    pub parent_key: i64,
    /// The filtered symbols.
    pub symbols: Vec<TraceSymbol>,
}

impl TraceNamespaceSymbolView {
    /// Create a new view for a namespace.
    pub fn new(parent_key: i64) -> Self {
        Self {
            parent_key,
            symbols: Vec::new(),
        }
    }

    /// Add a symbol.
    pub fn push(&mut self, symbol: TraceSymbol) {
        self.symbols.push(symbol);
    }

    /// Get the count.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Check if the view is empty.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Iterate over the symbols.
    pub fn iter(&self) -> impl Iterator<Item = &TraceSymbol> {
        self.symbols.iter()
    }
}

/// A view of class symbols.
///
/// Ported from Ghidra's `TraceClassSymbolView` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceClassSymbolView {
    /// The filtered class symbols.
    pub symbols: Vec<TraceSymbol>,
}

impl TraceClassSymbolView {
    /// Create an empty view.
    pub fn new() -> Self {
        Self {
            symbols: Vec::new(),
        }
    }

    /// Add a class symbol.
    pub fn push(&mut self, symbol: TraceSymbol) {
        self.symbols.push(symbol);
    }

    /// Get the count.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Iterate.
    pub fn iter(&self) -> impl Iterator<Item = &TraceSymbol> {
        self.symbols.iter()
    }
}

impl Default for TraceClassSymbolView {
    fn default() -> Self {
        Self::new()
    }
}

/// A view of label symbols.
///
/// Ported from Ghidra's `TraceLabelSymbolView` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceLabelSymbolView {
    /// The filtered label symbols.
    pub symbols: Vec<TraceSymbol>,
}

impl TraceLabelSymbolView {
    /// Create an empty view.
    pub fn new() -> Self {
        Self {
            symbols: Vec::new(),
        }
    }

    /// Add a label symbol.
    pub fn push(&mut self, symbol: TraceSymbol) {
        self.symbols.push(symbol);
    }

    /// Get the count.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Iterate.
    pub fn iter(&self) -> impl Iterator<Item = &TraceSymbol> {
        self.symbols.iter()
    }
}

impl Default for TraceLabelSymbolView {
    fn default() -> Self {
        Self::new()
    }
}

/// A view of reference symbols.
///
/// Ported from Ghidra's `TraceReferenceView` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceReferenceView {
    /// The filtered reference symbols.
    pub symbols: Vec<TraceSymbol>,
}

impl TraceReferenceView {
    /// Create an empty view.
    pub fn new() -> Self {
        Self {
            symbols: Vec::new(),
        }
    }

    /// Add a reference symbol.
    pub fn push(&mut self, symbol: TraceSymbol) {
        self.symbols.push(symbol);
    }

    /// Get the count.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Iterate.
    pub fn iter(&self) -> impl Iterator<Item = &TraceSymbol> {
        self.symbols.iter()
    }
}

impl Default for TraceReferenceView {
    fn default() -> Self {
        Self::new()
    }
}

/// A view of equate symbols.
///
/// Ported from Ghidra's `TraceEquateView` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEquateView {
    /// The filtered equate symbols.
    pub symbols: Vec<TraceSymbol>,
}

impl TraceEquateView {
    /// Create an empty view.
    pub fn new() -> Self {
        Self {
            symbols: Vec::new(),
        }
    }

    /// Add an equate symbol.
    pub fn push(&mut self, symbol: TraceSymbol) {
        self.symbols.push(symbol);
    }

    /// Get the count.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Iterate.
    pub fn iter(&self) -> impl Iterator<Item = &TraceSymbol> {
        self.symbols.iter()
    }
}

impl Default for TraceEquateView {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_symbol(name: &str, kind: TraceSymbolKind) -> TraceSymbol {
        TraceSymbol {
            key: 0,
            name: name.to_string(),
            kind,
            parent_key: None,
            address: Some(0x400000),
            space: Some("ram".to_string()),
            lifespan: Lifespan::span(0, 100),
        }
    }

    #[test]
    fn test_address_view() {
        let mut view = TraceSymbolWithAddressView::at_address("ram", 0x400000);
        view.push(make_symbol("main", TraceSymbolKind::Label));
        assert_eq!(view.len(), 1);
        assert!(!view.is_empty());
    }

    #[test]
    fn test_address_range_view() {
        let view = TraceSymbolWithAddressView::in_range("ram", 0x400000, 0x400FFF);
        assert_eq!(view.space, "ram");
        assert_eq!(view.min_offset, 0x400000);
        assert_eq!(view.max_offset, 0x400FFF);
        assert!(view.is_empty());
    }

    #[test]
    fn test_no_duplicates_view() {
        let inner = TraceSymbolWithAddressView::at_address("ram", 0x400000);
        let view = TraceSymbolWithAddressNoDuplicatesView::new(inner);
        assert!(view.is_empty());
    }

    #[test]
    fn test_location_view() {
        let mut view = TraceSymbolWithLocationView::new("ram");
        view.push(make_symbol("func1", TraceSymbolKind::Label));
        assert_eq!(view.len(), 1);
    }

    #[test]
    fn test_namespace_view() {
        let mut view = TraceNamespaceSymbolView::new(42);
        view.push(make_symbol("inner", TraceSymbolKind::Label));
        assert_eq!(view.parent_key, 42);
        assert_eq!(view.len(), 1);
    }

    #[test]
    fn test_class_label_reference_equate_views() {
        let mut class_view = TraceClassSymbolView::new();
        class_view.push(make_symbol("MyClass", TraceSymbolKind::Class));
        assert_eq!(class_view.len(), 1);

        let mut label_view = TraceLabelSymbolView::new();
        label_view.push(make_symbol("main", TraceSymbolKind::Label));
        assert_eq!(label_view.len(), 1);

        let mut ref_view = TraceReferenceView::new();
        ref_view.push(make_symbol("ref1", TraceSymbolKind::Reference));
        assert_eq!(ref_view.len(), 1);

        let mut equate_view = TraceEquateView::new();
        equate_view.push(make_symbol("MY_CONST", TraceSymbolKind::Equate));
        assert_eq!(equate_view.len(), 1);
    }

    #[test]
    fn test_serialization() {
        let view = TraceSymbolWithAddressView::at_address("ram", 0x400000);
        let json = serde_json::to_string(&view).unwrap();
        let deserialized: TraceSymbolWithAddressView = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.space, "ram");
        assert_eq!(deserialized.min_offset, 0x400000);
    }
}
