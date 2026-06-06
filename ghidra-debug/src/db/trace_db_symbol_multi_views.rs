//! Multi-type symbol view implementations for the trace database.
//!
//! Ported from Ghidra's `DBTraceSymbolMultipleTypesView`,
//! `DBTraceSymbolMultipleTypesWithAddressView`,
//! `DBTraceSymbolMultipleTypesWithLocationView`, and their
//! no-duplicates variants.
//!
//! These views combine multiple single-type symbol views into a
//! unified view that iterates over all symbol types at once.

use std::collections::HashSet;

use crate::model::Lifespan;
use crate::model::symbol::{
    TraceSymbolKind,
};

/// Options for filtering a combined multi-type symbol view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiTypeFilter {
    /// The set of symbol kinds to include.
    pub kinds: HashSet<TraceSymbolKind>,
    /// Whether to filter by address (memory space).
    pub filter_by_address: bool,
    /// Whether to filter by address and operand index (location).
    pub filter_by_location: bool,
    /// Whether to exclude duplicates (same name + same address).
    pub no_duplicates: bool,
    /// Optional address filter - minimum address.
    pub min_address: Option<u64>,
    /// Optional address filter - maximum address.
    pub max_address: Option<u64>,
    /// Optional snap filter.
    pub snap: Option<i64>,
}

impl MultiTypeFilter {
    /// Create a new filter accepting all symbol kinds.
    pub fn all() -> Self {
        Self {
            kinds: TraceSymbolKind::all_kinds().iter().copied().collect(),
            filter_by_address: false,
            filter_by_location: false,
            no_duplicates: false,
            min_address: None,
            max_address: None,
            snap: None,
        }
    }

    /// Create a filter for only labels.
    pub fn labels_only() -> Self {
        let mut kinds = HashSet::new();
        kinds.insert(TraceSymbolKind::Label);
        Self {
            kinds,
            filter_by_address: false,
            filter_by_location: false,
            no_duplicates: false,
            min_address: None,
            max_address: None,
            snap: None,
        }
    }

    /// Create a filter for only classes/namespaces.
    pub fn namespaces_only() -> Self {
        let mut kinds = HashSet::new();
        kinds.insert(TraceSymbolKind::Class);
        kinds.insert(TraceSymbolKind::Namespace);
        Self {
            kinds,
            filter_by_address: false,
            filter_by_location: false,
            no_duplicates: false,
            min_address: None,
            max_address: None,
            snap: None,
        }
    }

    /// Enable address filtering.
    pub fn with_address_range(mut self, min: u64, max: u64) -> Self {
        self.filter_by_address = true;
        self.min_address = Some(min);
        self.max_address = Some(max);
        self
    }

    /// Enable location filtering (address + operand index).
    pub fn with_location_filter(mut self) -> Self {
        self.filter_by_location = true;
        self
    }

    /// Enable no-duplicates mode.
    pub fn no_duplicates(mut self) -> Self {
        self.no_duplicates = true;
        self
    }

    /// Set a snap filter.
    pub fn at_snap(mut self, snap: i64) -> Self {
        self.snap = Some(snap);
        self
    }

    /// Check if a symbol kind passes this filter.
    pub fn accepts_kind(&self, kind: TraceSymbolKind) -> bool {
        self.kinds.contains(&kind)
    }

    /// Check if an address passes this filter.
    pub fn accepts_address(&self, addr: u64) -> bool {
        if !self.filter_by_address {
            return true;
        }
        match (self.min_address, self.max_address) {
            (Some(min), Some(max)) => addr >= min && addr <= max,
            (Some(min), None) => addr >= min,
            (None, Some(max)) => addr <= max,
            (None, None) => true,
        }
    }

    /// Check if a snap passes this filter.
    pub fn accepts_snap(&self, snap: i64) -> bool {
        match self.snap {
            Some(s) => snap == s,
            None => true,
        }
    }

    /// Check if a lifespan intersects the snap filter.
    pub fn lifespan_intersects(&self, lifespan: &Lifespan) -> bool {
        match self.snap {
            Some(s) => lifespan.contains(s),
            None => true,
        }
    }
}

/// A combined entry from a multi-type symbol view.
#[derive(Debug, Clone, PartialEq)]
pub struct MultiTypeSymbolEntry {
    /// The symbol kind.
    pub kind: TraceSymbolKind,
    /// The symbol ID.
    pub symbol_id: i64,
    /// The symbol name.
    pub name: String,
    /// The namespace ID this symbol belongs to.
    pub namespace_id: i64,
    /// The address (for address-based symbols).
    pub address: Option<u64>,
    /// The operand index (for location-based symbols).
    pub operand_index: Option<i32>,
    /// The lifespan of this symbol.
    pub lifespan: Lifespan,
    /// Whether this symbol is primary (for references).
    pub is_primary: bool,
    /// The thread ID (for register-space symbols).
    pub thread_id: Option<i64>,
}

impl MultiTypeSymbolEntry {
    /// Create a label entry.
    pub fn label(
        symbol_id: i64,
        name: impl Into<String>,
        namespace_id: i64,
        address: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            kind: TraceSymbolKind::Label,
            symbol_id,
            name: name.into(),
            namespace_id,
            address: Some(address),
            operand_index: None,
            lifespan,
            is_primary: false,
            thread_id: None,
        }
    }

    /// Create a namespace entry.
    pub fn namespace(
        symbol_id: i64,
        name: impl Into<String>,
        namespace_id: i64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            kind: TraceSymbolKind::Namespace,
            symbol_id,
            name: name.into(),
            namespace_id,
            address: None,
            operand_index: None,
            lifespan,
            is_primary: false,
            thread_id: None,
        }
    }

    /// Create a class entry.
    pub fn class(
        symbol_id: i64,
        name: impl Into<String>,
        namespace_id: i64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            kind: TraceSymbolKind::Class,
            symbol_id,
            name: name.into(),
            namespace_id,
            address: None,
            operand_index: None,
            lifespan,
            is_primary: false,
            thread_id: None,
        }
    }

    /// Create a function entry.
    pub fn function(
        symbol_id: i64,
        name: impl Into<String>,
        namespace_id: i64,
        address: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            kind: TraceSymbolKind::Function,
            symbol_id,
            name: name.into(),
            namespace_id,
            address: Some(address),
            operand_index: None,
            lifespan,
            is_primary: false,
            thread_id: None,
        }
    }

    /// Whether this entry passes the given filter.
    pub fn matches_filter(&self, filter: &MultiTypeFilter) -> bool {
        if !filter.accepts_kind(self.kind) {
            return false;
        }
        if let Some(addr) = self.address {
            if !filter.accepts_address(addr) {
                return false;
            }
        }
        if !filter.lifespan_intersects(&self.lifespan) {
            return false;
        }
        true
    }
}

/// Builder for constructing a filtered multi-type symbol view.
#[derive(Debug, Clone)]
pub struct MultiTypeSymbolViewBuilder {
    filter: MultiTypeFilter,
    entries: Vec<MultiTypeSymbolEntry>,
}

impl MultiTypeSymbolViewBuilder {
    /// Create a new view builder with the given filter.
    pub fn new(filter: MultiTypeFilter) -> Self {
        Self {
            filter,
            entries: Vec::new(),
        }
    }

    /// Add an entry to the view. Returns false if filtered out.
    pub fn push(&mut self, entry: MultiTypeSymbolEntry) -> bool {
        if entry.matches_filter(&self.filter) {
            self.entries.push(entry);
            true
        } else {
            false
        }
    }

    /// Add multiple entries, filtering as needed.
    pub fn extend(&mut self, entries: impl IntoIterator<Item = MultiTypeSymbolEntry>) {
        for entry in entries {
            self.push(entry);
        }
    }

    /// Build the final view, applying deduplication if requested.
    pub fn build(mut self) -> Vec<MultiTypeSymbolEntry> {
        if self.filter.no_duplicates {
            self.deduplicate();
        }
        self.entries
    }

    fn deduplicate(&mut self) {
        let mut seen = HashSet::new();
        self.entries.retain(|e| {
            let key = (e.name.clone(), e.address, e.namespace_id);
            seen.insert(key)
        });
    }

    /// The current number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the view is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_lifespan(min: i64, max: i64) -> Lifespan {
        Lifespan::span(min, max)
    }

    #[test]
    fn test_multi_type_filter_all() {
        let filter = MultiTypeFilter::all();
        assert!(filter.accepts_kind(TraceSymbolKind::Label));
        assert!(filter.accepts_kind(TraceSymbolKind::Function));
        assert!(filter.accepts_kind(TraceSymbolKind::Namespace));
        assert!(filter.accepts_kind(TraceSymbolKind::Class));
        assert!(filter.accepts_address(0x1000));
        assert!(filter.accepts_snap(0));
    }

    #[test]
    fn test_multi_type_filter_labels_only() {
        let filter = MultiTypeFilter::labels_only();
        assert!(filter.accepts_kind(TraceSymbolKind::Label));
        assert!(!filter.accepts_kind(TraceSymbolKind::Function));
        assert!(!filter.accepts_kind(TraceSymbolKind::Namespace));
    }

    #[test]
    fn test_multi_type_filter_address_range() {
        let filter = MultiTypeFilter::all().with_address_range(0x1000, 0x2000);
        assert!(!filter.accepts_address(0x0500));
        assert!(filter.accepts_address(0x1000));
        assert!(filter.accepts_address(0x1500));
        assert!(filter.accepts_address(0x2000));
        assert!(!filter.accepts_address(0x3000));
    }

    #[test]
    fn test_multi_type_filter_snap() {
        let filter = MultiTypeFilter::all().at_snap(5);
        assert!(filter.accepts_snap(5));
        assert!(!filter.accepts_snap(0));
        assert!(!filter.accepts_snap(10));

        let lifespan = test_lifespan(0, 10);
        assert!(filter.lifespan_intersects(&lifespan));

        let lifespan = test_lifespan(10, 20);
        assert!(!filter.lifespan_intersects(&lifespan));
    }

    #[test]
    fn test_multi_type_filter_no_duplicates() {
        let filter = MultiTypeFilter::all().no_duplicates();
        assert!(filter.no_duplicates);
    }

    #[test]
    fn test_multi_type_entry_label() {
        let entry = MultiTypeSymbolEntry::label(1, "main", 0, 0x400000, test_lifespan(0, 100));
        assert_eq!(entry.kind, TraceSymbolKind::Label);
        assert_eq!(entry.name, "main");
        assert_eq!(entry.address, Some(0x400000));
    }

    #[test]
    fn test_multi_type_entry_namespace() {
        let entry = MultiTypeSymbolEntry::namespace(2, "libc", 0, test_lifespan(0, 100));
        assert_eq!(entry.kind, TraceSymbolKind::Namespace);
        assert!(entry.address.is_none());
    }

    #[test]
    fn test_multi_type_entry_function() {
        let entry = MultiTypeSymbolEntry::function(3, "printf", 0, 0x401000, test_lifespan(0, 100));
        assert_eq!(entry.kind, TraceSymbolKind::Function);
        assert_eq!(entry.address, Some(0x401000));
    }

    #[test]
    fn test_entry_matches_filter() {
        let entry = MultiTypeSymbolEntry::label(1, "main", 0, 0x400000, test_lifespan(0, 100));

        let filter = MultiTypeFilter::all();
        assert!(entry.matches_filter(&filter));

        let filter = MultiTypeFilter::labels_only();
        assert!(entry.matches_filter(&filter));

        let filter = MultiTypeFilter::all().with_address_range(0x400000, 0x500000);
        assert!(entry.matches_filter(&filter));

        let filter = MultiTypeFilter::all().with_address_range(0x500000, 0x600000);
        assert!(!entry.matches_filter(&filter));

        let filter = MultiTypeFilter::namespaces_only();
        assert!(!entry.matches_filter(&filter));
    }

    #[test]
    fn test_view_builder_basic() {
        let filter = MultiTypeFilter::all();
        let mut builder = MultiTypeSymbolViewBuilder::new(filter);

        builder.push(MultiTypeSymbolEntry::label(1, "main", 0, 0x400000, test_lifespan(0, 100)));
        builder.push(MultiTypeSymbolEntry::namespace(2, "libc", 0, test_lifespan(0, 100)));
        builder.push(MultiTypeSymbolEntry::function(3, "printf", 0, 0x401000, test_lifespan(0, 100)));

        let view = builder.build();
        assert_eq!(view.len(), 3);
    }

    #[test]
    fn test_view_builder_with_filter() {
        let filter = MultiTypeFilter::labels_only();
        let mut builder = MultiTypeSymbolViewBuilder::new(filter);

        assert!(builder.push(MultiTypeSymbolEntry::label(1, "main", 0, 0x400000, test_lifespan(0, 100))));
        assert!(!builder.push(MultiTypeSymbolEntry::function(2, "printf", 0, 0x401000, test_lifespan(0, 100))));

        let view = builder.build();
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].kind, TraceSymbolKind::Label);
    }

    #[test]
    fn test_view_builder_dedup() {
        let filter = MultiTypeFilter::all().no_duplicates();
        let mut builder = MultiTypeSymbolViewBuilder::new(filter);

        builder.push(MultiTypeSymbolEntry::label(1, "main", 0, 0x400000, test_lifespan(0, 100)));
        builder.push(MultiTypeSymbolEntry::label(2, "main", 0, 0x400000, test_lifespan(0, 100)));
        builder.push(MultiTypeSymbolEntry::label(3, "other", 0, 0x400000, test_lifespan(0, 100)));

        let view = builder.build();
        assert_eq!(view.len(), 2); // "main" deduped, "other" kept
    }

    #[test]
    fn test_view_builder_extend() {
        let filter = MultiTypeFilter::all();
        let mut builder = MultiTypeSymbolViewBuilder::new(filter);

        let entries = vec![
            MultiTypeSymbolEntry::label(1, "a", 0, 0x1000, test_lifespan(0, 100)),
            MultiTypeSymbolEntry::label(2, "b", 0, 0x2000, test_lifespan(0, 100)),
            MultiTypeSymbolEntry::label(3, "c", 0, 0x3000, test_lifespan(0, 100)),
        ];
        builder.extend(entries);

        assert_eq!(builder.len(), 3);
        let view = builder.build();
        assert_eq!(view.len(), 3);
    }

    #[test]
    fn test_view_builder_with_address_range() {
        let filter = MultiTypeFilter::all().with_address_range(0x2000, 0x4000);
        let mut builder = MultiTypeSymbolViewBuilder::new(filter);

        builder.push(MultiTypeSymbolEntry::label(1, "low", 0, 0x1000, test_lifespan(0, 100)));
        builder.push(MultiTypeSymbolEntry::label(2, "mid", 0, 0x3000, test_lifespan(0, 100)));
        builder.push(MultiTypeSymbolEntry::label(3, "high", 0, 0x5000, test_lifespan(0, 100)));

        let view = builder.build();
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].name, "mid");
    }

    #[test]
    fn test_view_builder_empty() {
        let filter = MultiTypeFilter::all();
        let builder = MultiTypeSymbolViewBuilder::new(filter);
        assert!(builder.is_empty());
        assert_eq!(builder.len(), 0);
        let view = builder.build();
        assert!(view.is_empty());
    }

    #[test]
    fn test_multi_type_filter_location() {
        let filter = MultiTypeFilter::all().with_location_filter();
        assert!(filter.filter_by_location);
    }

    #[test]
    fn test_multi_type_entry_class() {
        let entry = MultiTypeSymbolEntry::class(5, "MyClass", 0, test_lifespan(0, 100));
        assert_eq!(entry.kind, TraceSymbolKind::Class);
        assert_eq!(entry.name, "MyClass");
    }

    #[test]
    fn test_filter_namespaces_includes_class() {
        let filter = MultiTypeFilter::namespaces_only();
        assert!(filter.accepts_kind(TraceSymbolKind::Class));
        assert!(filter.accepts_kind(TraceSymbolKind::Namespace));
        assert!(!filter.accepts_kind(TraceSymbolKind::Label));
        assert!(!filter.accepts_kind(TraceSymbolKind::Function));
    }

    #[test]
    fn test_multi_type_serde() {
        let entry = MultiTypeSymbolEntry::label(1, "main", 0, 0x400000, test_lifespan(0, 100));
        // MultiTypeSymbolEntry doesn't derive Serialize but we can test Debug
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("Label"));
        assert!(debug_str.contains("main"));
    }
}
