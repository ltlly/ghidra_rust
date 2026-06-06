//! Extended symbol view types for database-backed traces.
//!
//! Ported from Ghidra's `ghidra.trace.database.symbol` package.
//! Provides multi-type views, no-duplicates views, and location-scoped views
//! that aggregate results across multiple single-type symbol views.




/// Aggregated view of symbols across multiple symbol types.
///
/// Corresponds to Java's `DBTraceSymbolMultipleTypesView`.
#[derive(Debug)]
pub struct SymbolMultipleTypesView<T: Clone + std::fmt::Debug> {
    /// Name of this view for debugging purposes.
    pub view_name: String,
    /// Underlying per-type view identifiers.
    pub type_view_ids: Vec<u32>,
    /// Cached count across all type views.
    pub total_count_hint: usize,
    /// Phantom for generic type.
    _marker: std::marker::PhantomData<T>,
}

impl<T: Clone + std::fmt::Debug> SymbolMultipleTypesView<T> {
    /// Create a new multi-type symbol view.
    pub fn new(view_name: impl Into<String>, type_view_ids: Vec<u32>) -> Self {
        let total_count_hint = type_view_ids.len();
        Self {
            view_name: view_name.into(),
            type_view_ids,
            total_count_hint,
            _marker: std::marker::PhantomData,
        }
    }

    /// Get the number of type views aggregated.
    pub fn type_view_count(&self) -> usize {
        self.type_view_ids.len()
    }

    /// Check if the view is empty (no type views).
    pub fn is_empty(&self) -> bool {
        self.type_view_ids.is_empty()
    }
}

/// Multi-type view that excludes duplicates.
///
/// Corresponds to Java's `DBTraceSymbolMultipleTypesNoDuplicatesView`.
#[derive(Debug)]
pub struct SymbolMultipleTypesNoDuplicatesView<T: Clone + std::fmt::Debug> {
    /// The underlying multi-type view.
    pub base: SymbolMultipleTypesView<T>,
}

impl<T: Clone + std::fmt::Debug> SymbolMultipleTypesNoDuplicatesView<T> {
    /// Create from an existing multi-type view.
    pub fn new(base: SymbolMultipleTypesView<T>) -> Self {
        Self { base }
    }

    /// Get the view name.
    pub fn view_name(&self) -> &str {
        &self.base.view_name
    }

    /// Get the number of type views.
    pub fn type_view_count(&self) -> usize {
        self.base.type_view_count()
    }
}

/// Multi-type view with address filtering that excludes duplicates.
///
/// Corresponds to Java's `DBTraceSymbolMultipleTypesWithAddressNoDuplicatesView`.
#[derive(Debug)]
pub struct SymbolMultipleTypesWithAddressNoDuplicatesView<T: Clone + std::fmt::Debug> {
    /// The underlying multi-type view.
    pub base: SymbolMultipleTypesView<T>,
    /// Address range filter (min offset, max offset).
    pub address_filter: Option<(u64, u64)>,
}

impl<T: Clone + std::fmt::Debug> SymbolMultipleTypesWithAddressNoDuplicatesView<T> {
    /// Create from a multi-type view with optional address filter.
    pub fn new(base: SymbolMultipleTypesView<T>, address_filter: Option<(u64, u64)>) -> Self {
        Self {
            base,
            address_filter,
        }
    }

    /// Check if an address falls within the filter range.
    pub fn matches_address(&self, offset: u64) -> bool {
        match self.address_filter {
            Some((min, max)) => offset >= min && offset <= max,
            None => true,
        }
    }
}

/// Multi-type view with location (address + namespace) filtering.
///
/// Corresponds to Java's `DBTraceSymbolMultipleTypesWithLocationView`.
#[derive(Debug)]
pub struct SymbolMultipleTypesWithLocationView<T: Clone + std::fmt::Debug> {
    /// The underlying multi-type view.
    pub base: SymbolMultipleTypesView<T>,
    /// Namespace path filter.
    pub namespace_filter: Option<String>,
    /// Address range filter (min, max).
    pub address_filter: Option<(u64, u64)>,
    /// Snap range filter (snap_min, snap_max).
    pub snap_filter: Option<(i64, i64)>,
}

impl<T: Clone + std::fmt::Debug> SymbolMultipleTypesWithLocationView<T> {
    /// Create from a multi-type view with optional filters.
    pub fn new(
        base: SymbolMultipleTypesView<T>,
        namespace_filter: Option<String>,
        address_filter: Option<(u64, u64)>,
        snap_filter: Option<(i64, i64)>,
    ) -> Self {
        Self {
            base,
            namespace_filter,
            address_filter,
            snap_filter,
        }
    }

    /// Check if an address matches the filter.
    pub fn matches_address(&self, offset: u64) -> bool {
        match self.address_filter {
            Some((min, max)) => offset >= min && offset <= max,
            None => true,
        }
    }

    /// Check if a snap value matches the filter.
    pub fn matches_snap(&self, snap: i64) -> bool {
        match self.snap_filter {
            Some((min, max)) => snap >= min && snap <= max,
            None => true,
        }
    }

    /// Check if a namespace path matches the filter.
    pub fn matches_namespace(&self, ns_path: &str) -> bool {
        match &self.namespace_filter {
            Some(filter) => ns_path.starts_with(filter),
            None => true,
        }
    }
}

/// Snap-selected reference space that filters references by a specific snapshot.
///
/// Corresponds to Java's `DBTraceSnapSelectedReferenceSpace`.
#[derive(Debug, Clone)]
pub struct SnapSelectedReferenceSpace {
    /// The snap (time point) to select references from.
    pub selected_snap: i64,
    /// The underlying reference space identifier.
    pub space_id: u32,
}

impl SnapSelectedReferenceSpace {
    /// Create a new snap-selected reference space.
    pub fn new(selected_snap: i64, space_id: u32) -> Self {
        Self {
            selected_snap,
            space_id,
        }
    }

    /// Check if a reference's lifespan includes the selected snap.
    pub fn includes_snap(&self, snap_min: i64, snap_max: i64) -> bool {
        self.selected_snap >= snap_min && self.selected_snap <= snap_max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_multiple_types_view() {
        let view = SymbolMultipleTypesView::<String>::new("all_symbols", vec![1, 2, 3]);
        assert_eq!(view.view_name, "all_symbols");
        assert_eq!(view.type_view_count(), 3);
        assert!(!view.is_empty());
    }

    #[test]
    fn test_symbol_multiple_types_empty() {
        let view = SymbolMultipleTypesView::<String>::new("empty", vec![]);
        assert!(view.is_empty());
        assert_eq!(view.type_view_count(), 0);
    }

    #[test]
    fn test_no_duplicates_view() {
        let base = SymbolMultipleTypesView::<String>::new("test", vec![1, 2]);
        let view = SymbolMultipleTypesNoDuplicatesView::new(base);
        assert_eq!(view.view_name(), "test");
        assert_eq!(view.type_view_count(), 2);
    }

    #[test]
    fn test_with_address_no_duplicates() {
        let base = SymbolMultipleTypesView::<String>::new("test", vec![1]);
        let view = SymbolMultipleTypesWithAddressNoDuplicatesView::new(
            base,
            Some((0x1000, 0x2000)),
        );
        assert!(view.matches_address(0x1500));
        assert!(!view.matches_address(0x3000));
    }

    #[test]
    fn test_with_address_no_filter() {
        let base = SymbolMultipleTypesView::<String>::new("test", vec![1]);
        let view = SymbolMultipleTypesWithAddressNoDuplicatesView::new(base, None);
        assert!(view.matches_address(0x0));
        assert!(view.matches_address(u64::MAX));
    }

    #[test]
    fn test_with_location_view_address_filter() {
        let base = SymbolMultipleTypesView::<String>::new("test", vec![1]);
        let view = SymbolMultipleTypesWithLocationView::new(
            base,
            Some("Global::main".to_string()),
            Some((0x400000, 0x500000)),
            Some((0, 100)),
        );
        assert!(view.matches_address(0x450000));
        assert!(!view.matches_address(0x600000));
        assert!(view.matches_snap(50));
        assert!(!view.matches_snap(200));
        assert!(view.matches_namespace("Global::main::inner"));
        assert!(!view.matches_namespace("Other::func"));
    }

    #[test]
    fn test_snap_selected_reference_space() {
        let space = SnapSelectedReferenceSpace::new(10, 1);
        assert!(space.includes_snap(5, 15));
        assert!(space.includes_snap(10, 10));
        assert!(!space.includes_snap(11, 20));
        assert!(!space.includes_snap(0, 9));
    }

    #[test]
    fn test_snap_selected_reference_space_boundary() {
        let space = SnapSelectedReferenceSpace::new(i64::MAX, 1);
        assert!(space.includes_snap(0, i64::MAX));
        assert!(!space.includes_snap(0, i64::MAX - 1));
    }
}
