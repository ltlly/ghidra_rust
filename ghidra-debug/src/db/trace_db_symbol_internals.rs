//! Internal symbol view abstractions.
//!
//! Ported from Ghidra's `ghidra.trace.database.symbol` package internal interfaces:
//! - `AbstractDBTraceSymbolSingleTypeView`: Single symbol type view base.
//! - `AbstractDBTraceSymbolSingleTypeWithAddressView`: Single type with address filtering.
//! - `AbstractDBTraceSymbolSingleTypeWithLocationView`: Single type with location filtering.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// Filter criteria for symbol queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolQueryFilter {
    /// Filter by symbol name (substring match).
    pub name_filter: Option<String>,
    /// Filter by address range start.
    pub address_start: Option<u64>,
    /// Filter by address range end.
    pub address_end: Option<u64>,
    /// Filter by namespace.
    pub namespace: Option<String>,
    /// Filter by snap.
    pub snap: Option<i64>,
}

impl Default for SymbolQueryFilter {
    fn default() -> Self {
        Self {
            name_filter: None,
            address_start: None,
            address_end: None,
            namespace: None,
            snap: None,
        }
    }
}

impl SymbolQueryFilter {
    /// Create a new empty filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set name filter.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name_filter = Some(name.into());
        self
    }

    /// Set address range filter.
    pub fn with_address_range(mut self, start: u64, end: u64) -> Self {
        self.address_start = Some(start);
        self.address_end = Some(end);
        self
    }

    /// Set namespace filter.
    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }

    /// Set snap filter.
    pub fn with_snap(mut self, snap: i64) -> Self {
        self.snap = Some(snap);
        self
    }
}

/// Abstract base for single-type symbol views.
///
/// Ported from Ghidra's `AbstractDBTraceSymbolSingleTypeView`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbstractDBTraceSymbolSingleTypeView {
    /// The symbol type this view represents.
    pub symbol_type: String,
    /// The snap to view at.
    pub snap: i64,
    /// The lifespan for the view.
    pub lifespan: Lifespan,
}

impl AbstractDBTraceSymbolSingleTypeView {
    /// Create a new single-type symbol view.
    pub fn new(symbol_type: impl Into<String>, snap: i64) -> Self {
        Self {
            symbol_type: symbol_type.into(),
            snap,
            lifespan: Lifespan::now_on(snap),
        }
    }
}

/// Abstract base for single-type symbol views with address filtering.
///
/// Ported from Ghidra's `AbstractDBTraceSymbolSingleTypeWithAddressView`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbstractDBTraceSymbolSingleTypeWithAddressView {
    /// The base view.
    pub base: AbstractDBTraceSymbolSingleTypeView,
    /// The address range start (inclusive).
    pub address_start: u64,
    /// The address range end (inclusive).
    pub address_end: u64,
}

impl AbstractDBTraceSymbolSingleTypeWithAddressView {
    /// Create a new address-filtered symbol view.
    pub fn new(
        symbol_type: impl Into<String>,
        snap: i64,
        address_start: u64,
        address_end: u64,
    ) -> Self {
        Self {
            base: AbstractDBTraceSymbolSingleTypeView::new(symbol_type, snap),
            address_start,
            address_end,
        }
    }

    /// Check if an address falls within the view's range.
    pub fn contains_address(&self, addr: u64) -> bool {
        addr >= self.address_start && addr <= self.address_end
    }
}

/// Abstract base for single-type symbol views with location filtering.
///
/// Ported from Ghidra's `AbstractDBTraceSymbolSingleTypeWithLocationView`.
/// A "location" includes both address and space information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbstractDBTraceSymbolSingleTypeWithLocationView {
    /// The base view.
    pub base: AbstractDBTraceSymbolSingleTypeView,
    /// The address space name (e.g., "ram", "register").
    pub space: String,
    /// The address within the space.
    pub address: u64,
    /// Whether to include symbols at addresses in sub-spaces.
    pub include_subspaces: bool,
}

impl AbstractDBTraceSymbolSingleTypeWithLocationView {
    /// Create a new location-filtered symbol view.
    pub fn new(
        symbol_type: impl Into<String>,
        snap: i64,
        space: impl Into<String>,
        address: u64,
    ) -> Self {
        Self {
            base: AbstractDBTraceSymbolSingleTypeView::new(symbol_type, snap),
            space: space.into(),
            address,
            include_subspaces: false,
        }
    }

    /// Enable sub-space inclusion.
    pub fn with_subspaces(mut self) -> Self {
        self.include_subspaces = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_query_filter_default() {
        let filter = SymbolQueryFilter::new();
        assert!(filter.name_filter.is_none());
        assert!(filter.address_start.is_none());
    }

    #[test]
    fn test_symbol_query_filter_builder() {
        let filter = SymbolQueryFilter::new()
            .with_name("main")
            .with_address_range(0x1000, 0x2000)
            .with_namespace("Global")
            .with_snap(5);
        assert_eq!(filter.name_filter.as_deref(), Some("main"));
        assert_eq!(filter.address_start, Some(0x1000));
        assert_eq!(filter.address_end, Some(0x2000));
        assert_eq!(filter.namespace.as_deref(), Some("Global"));
        assert_eq!(filter.snap, Some(5));
    }

    #[test]
    fn test_single_type_view() {
        let view = AbstractDBTraceSymbolSingleTypeView::new("Label", 10);
        assert_eq!(view.symbol_type, "Label");
        assert_eq!(view.snap, 10);
    }

    #[test]
    fn test_single_type_with_address_view() {
        let view = AbstractDBTraceSymbolSingleTypeWithAddressView::new("Function", 5, 0x1000, 0x2000);
        assert!(view.contains_address(0x1500));
        assert!(!view.contains_address(0x3000));
        assert!(view.contains_address(0x1000)); // inclusive start
        assert!(view.contains_address(0x2000)); // inclusive end
    }

    #[test]
    fn test_single_type_with_location_view() {
        let view = AbstractDBTraceSymbolSingleTypeWithLocationView::new("Label", 5, "ram", 0x1000)
            .with_subspaces();
        assert_eq!(view.space, "ram");
        assert_eq!(view.address, 0x1000);
        assert!(view.include_subspaces);
    }

    #[test]
    fn test_symbol_query_filter_serde() {
        let filter = SymbolQueryFilter::new().with_name("test");
        let json = serde_json::to_string(&filter).unwrap();
        let back: SymbolQueryFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name_filter.as_deref(), Some("test"));
    }
}
