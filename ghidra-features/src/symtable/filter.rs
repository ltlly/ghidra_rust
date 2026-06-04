//! Symbol filtering -- ported from `SymbolFilter`, `NewSymbolFilter`,
//! and `FilterDialog`.
//!
//! Provides predicate-based filtering for the symbol table view,
//! supporting filter by symbol type, namespace, source, and name pattern.

use std::fmt;

// ---------------------------------------------------------------------------
// SymbolTypeFilter
// ---------------------------------------------------------------------------

/// Filter criteria for symbol types.
///
/// Ported from Ghidra's `NewSymbolFilter`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolTypeFilter {
    /// Show function symbols.
    pub functions: bool,
    /// Show label symbols.
    pub labels: bool,
    /// Show class/namespace symbols.
    pub classes: bool,
    /// Show library symbols.
    pub libraries: bool,
    /// Show external symbols.
    pub external: bool,
    /// Show parameter symbols.
    pub parameters: bool,
    /// Show local variable symbols.
    pub locals: bool,
}

impl SymbolTypeFilter {
    /// Creates a filter that matches all symbol types.
    pub fn all() -> Self {
        Self {
            functions: true,
            labels: true,
            classes: true,
            libraries: true,
            external: true,
            parameters: true,
            locals: true,
        }
    }

    /// Creates a filter that matches no symbol types.
    pub fn none() -> Self {
        Self {
            functions: false,
            labels: false,
            classes: false,
            libraries: false,
            external: false,
            parameters: false,
            locals: false,
        }
    }

    /// Creates a filter matching only function symbols.
    pub fn functions_only() -> Self {
        let mut f = Self::none();
        f.functions = true;
        f
    }

    /// Returns the count of enabled filter criteria.
    pub fn enabled_count(&self) -> usize {
        [
            self.functions,
            self.labels,
            self.classes,
            self.libraries,
            self.external,
            self.parameters,
            self.locals,
        ]
        .iter()
        .filter(|&&b| b)
        .count()
    }

    /// Returns `true` if all criteria are enabled.
    pub fn is_all_enabled(&self) -> bool {
        self.enabled_count() == 7
    }
}

impl Default for SymbolTypeFilter {
    fn default() -> Self {
        Self::all()
    }
}

// ---------------------------------------------------------------------------
// SymbolSourceFilter
// ---------------------------------------------------------------------------

/// Filter criteria for symbol source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolSourceFilter {
    /// Show all symbols regardless of source.
    All,
    /// Only show user-defined symbols.
    UserDefined,
    /// Only show analysis-derived symbols.
    Analysis,
    /// Only show imported symbols.
    Imported,
}

impl fmt::Display for SymbolSourceFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => write!(f, "All"),
            Self::UserDefined => write!(f, "User Defined"),
            Self::Analysis => write!(f, "Analysis"),
            Self::Imported => write!(f, "Imported"),
        }
    }
}

impl Default for SymbolSourceFilter {
    fn default() -> Self {
        Self::All
    }
}

// ---------------------------------------------------------------------------
// SymbolFilter
// ---------------------------------------------------------------------------

/// A combined filter for the symbol table.
///
/// Ported from Ghidra's `SymbolFilter` interface / `NewSymbolFilter`.
///
/// # Example
///
/// ```
/// use ghidra_features::symtable::filter::*;
///
/// let mut filter = SymbolFilter::default();
/// filter.set_name_pattern(Some("main".into()));
/// filter.set_type_filter(SymbolTypeFilter::functions_only());
/// assert!(filter.matches_name("main"));
/// assert!(!filter.matches_name("data"));
/// ```
#[derive(Debug, Clone)]
pub struct SymbolFilter {
    /// The name pattern (substring match; case-insensitive).
    name_pattern: Option<String>,
    /// The type filter.
    type_filter: SymbolTypeFilter,
    /// The source filter.
    source_filter: SymbolSourceFilter,
    /// The namespace filter (None = all namespaces).
    namespace_filter: Option<String>,
    /// Whether to show only primary symbols.
    primary_only: bool,
    /// Whether to show only external symbols.
    external_only: bool,
    /// Whether to show only pinned symbols.
    pinned_only: bool,
    /// Address range filter: low bound (inclusive).
    address_low: Option<u64>,
    /// Address range filter: high bound (inclusive).
    address_high: Option<u64>,
}

impl SymbolFilter {
    /// Creates a new empty symbol filter (all off).
    pub fn new() -> Self {
        Self {
            name_pattern: None,
            type_filter: SymbolTypeFilter::none(),
            source_filter: SymbolSourceFilter::All,
            namespace_filter: None,
            primary_only: false,
            external_only: false,
            pinned_only: false,
            address_low: None,
            address_high: None,
        }
    }

    // -- Name --

    /// Sets the name pattern (substring, case-insensitive).
    pub fn set_name_pattern(&mut self, pattern: Option<String>) {
        self.name_pattern = pattern;
    }

    /// Returns the name pattern.
    pub fn name_pattern(&self) -> Option<&str> {
        self.name_pattern.as_deref()
    }

    /// Returns `true` if the given name matches the filter's name pattern.
    pub fn matches_name(&self, name: &str) -> bool {
        match &self.name_pattern {
            Some(pat) => name.to_lowercase().contains(&pat.to_lowercase()),
            None => true,
        }
    }

    // -- Type --

    /// Sets the type filter.
    pub fn set_type_filter(&mut self, filter: SymbolTypeFilter) {
        self.type_filter = filter;
    }

    /// Returns the type filter.
    pub fn type_filter(&self) -> &SymbolTypeFilter {
        &self.type_filter
    }

    /// Returns a mutable reference to the type filter.
    pub fn type_filter_mut(&mut self) -> &mut SymbolTypeFilter {
        &mut self.type_filter
    }

    // -- Source --

    /// Sets the source filter.
    pub fn set_source_filter(&mut self, filter: SymbolSourceFilter) {
        self.source_filter = filter;
    }

    /// Returns the source filter.
    pub fn source_filter(&self) -> SymbolSourceFilter {
        self.source_filter
    }

    // -- Namespace --

    /// Sets the namespace filter.
    pub fn set_namespace_filter(&mut self, ns: Option<String>) {
        self.namespace_filter = ns;
    }

    /// Returns the namespace filter.
    pub fn namespace_filter(&self) -> Option<&str> {
        self.namespace_filter.as_deref()
    }

    // -- Flags --

    /// Sets whether to show only primary symbols.
    pub fn set_primary_only(&mut self, primary_only: bool) {
        self.primary_only = primary_only;
    }

    /// Returns whether to show only primary symbols.
    pub fn is_primary_only(&self) -> bool {
        self.primary_only
    }

    /// Sets whether to show only external symbols.
    pub fn set_external_only(&mut self, external_only: bool) {
        self.external_only = external_only;
    }

    /// Returns whether to show only external symbols.
    pub fn is_external_only(&self) -> bool {
        self.external_only
    }

    /// Sets whether to show only pinned symbols.
    pub fn set_pinned_only(&mut self, pinned_only: bool) {
        self.pinned_only = pinned_only;
    }

    /// Returns whether to show only pinned symbols.
    pub fn is_pinned_only(&self) -> bool {
        self.pinned_only
    }

    // -- Address range --

    /// Sets the address range filter.
    pub fn set_address_range(&mut self, low: Option<u64>, high: Option<u64>) {
        self.address_low = low;
        self.address_high = high;
    }

    /// Returns the address range low bound.
    pub fn address_low(&self) -> Option<u64> {
        self.address_low
    }

    /// Returns the address range high bound.
    pub fn address_high(&self) -> Option<u64> {
        self.address_high
    }

    /// Returns `true` if the given address is within the filter range.
    pub fn matches_address(&self, addr: u64) -> bool {
        let low_ok = self.address_low.map_or(true, |low| addr >= low);
        let high_ok = self.address_high.map_or(true, |high| addr <= high);
        low_ok && high_ok
    }

    // -- Composite --

    /// Returns `true` if the filter has any criteria set.
    pub fn has_criteria(&self) -> bool {
        self.name_pattern.is_some()
            || !self.type_filter.is_all_enabled()
            || self.source_filter != SymbolSourceFilter::All
            || self.namespace_filter.is_some()
            || self.primary_only
            || self.external_only
            || self.pinned_only
            || self.address_low.is_some()
            || self.address_high.is_some()
    }

    /// Resets the filter to show all symbols.
    pub fn clear(&mut self) {
        self.name_pattern = None;
        self.type_filter = SymbolTypeFilter::all();
        self.source_filter = SymbolSourceFilter::All;
        self.namespace_filter = None;
        self.primary_only = false;
        self.external_only = false;
        self.pinned_only = false;
        self.address_low = None;
        self.address_high = None;
    }
}

impl Default for SymbolFilter {
    fn default() -> Self {
        Self {
            name_pattern: None,
            type_filter: SymbolTypeFilter::all(),
            source_filter: SymbolSourceFilter::All,
            namespace_filter: None,
            primary_only: false,
            external_only: false,
            pinned_only: false,
            address_low: None,
            address_high: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_filter_all() {
        let f = SymbolTypeFilter::all();
        assert!(f.is_all_enabled());
        assert_eq!(f.enabled_count(), 7);
    }

    #[test]
    fn test_type_filter_none() {
        let f = SymbolTypeFilter::none();
        assert_eq!(f.enabled_count(), 0);
    }

    #[test]
    fn test_type_filter_functions_only() {
        let f = SymbolTypeFilter::functions_only();
        assert_eq!(f.enabled_count(), 1);
        assert!(f.functions);
        assert!(!f.labels);
    }

    #[test]
    fn test_source_filter_display() {
        assert_eq!(SymbolSourceFilter::All.to_string(), "All");
        assert_eq!(SymbolSourceFilter::UserDefined.to_string(), "User Defined");
    }

    #[test]
    fn test_symbol_filter_name_matching() {
        let mut f = SymbolFilter::default();
        f.set_name_pattern(Some("main".into()));
        assert!(f.matches_name("main"));
        assert!(f.matches_name("MAIN"));
        assert!(f.matches_name("my_main_func"));
        assert!(!f.matches_name("init"));
    }

    #[test]
    fn test_symbol_filter_no_name() {
        let f = SymbolFilter::default();
        assert!(f.matches_name("anything"));
    }

    #[test]
    fn test_symbol_filter_address_range() {
        let mut f = SymbolFilter::default();
        f.set_address_range(Some(0x400000), Some(0x500000));
        assert!(f.matches_address(0x400000));
        assert!(f.matches_address(0x450000));
        assert!(f.matches_address(0x500000));
        assert!(!f.matches_address(0x300000));
        assert!(!f.matches_address(0x600000));
    }

    #[test]
    fn test_symbol_filter_has_criteria() {
        let mut f = SymbolFilter::default();
        assert!(!f.has_criteria());
        f.set_name_pattern(Some("test".into()));
        assert!(f.has_criteria());
    }

    #[test]
    fn test_symbol_filter_clear() {
        let mut f = SymbolFilter::default();
        f.set_name_pattern(Some("test".into()));
        f.set_primary_only(true);
        f.set_address_range(Some(0), Some(0xFF));
        assert!(f.has_criteria());

        f.clear();
        assert!(!f.has_criteria());
        assert!(f.matches_name("anything"));
        assert!(f.matches_address(0x100000));
    }

    #[test]
    fn test_symbol_filter_external_only() {
        let mut f = SymbolFilter::default();
        assert!(!f.is_external_only());
        f.set_external_only(true);
        assert!(f.is_external_only());
    }

    #[test]
    fn test_symbol_filter_pinned_only() {
        let mut f = SymbolFilter::default();
        f.set_pinned_only(true);
        assert!(f.is_pinned_only());
    }

    #[test]
    fn test_symbol_filter_namespace() {
        let mut f = SymbolFilter::default();
        f.set_namespace_filter(Some("Global".into()));
        assert_eq!(f.namespace_filter(), Some("Global"));
    }
}
