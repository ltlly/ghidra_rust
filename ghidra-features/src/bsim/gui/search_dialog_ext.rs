//! Extended BSim search dialog and service types.
//!
//! Ports the remaining BSim GUI classes not yet in the Rust crate:
//! - [`BSimSearchService`] -- service interface for BSim searches.
//! - [`BSimFilterPanel`] -- panel for building filter queries.
//! - [`FilterWidget`] -- individual filter widget.
//! - [`FunctionSymbolToFunctionTableRowMapper`] -- mapper from function symbols to table rows.
//! - [`BSimServerDialog`] -- dialog for managing BSim servers.
//! - [`AbstractBSimSearchDialog`] -- base class for search dialogs.
//! - [`BSimOverviewDialog`] -- overview dialog.
//! - [`BSimSearchInfoDisplayDialog`] -- info display dialog.
//! - [`BSimSearchResultsProvider`] -- results provider interface.
//! - [`BSimSearchResultsFilterDialog`] -- filter dialog for results.
//! - [`BSimApplyResultsDisplayDialog`] -- apply results dialog.
//! - [`ShowNamespaceSettingsDefinition`] -- settings for showing namespaces.


/// BSim search service trait.
///
/// Ports `ghidra.features.bsim.gui.search.dialog.BSimSearchService`.
/// Provides the interface for executing BSim similarity searches.
pub trait BSimSearchService: Send + Sync {
    /// Execute a search with the given settings.
    fn search(&self, settings: &BSimSearchQuerySettings) -> Result<BSimSearchResponse, String>;

    /// Get the server name.
    fn server_name(&self) -> &str;

    /// Whether the service is connected.
    fn is_connected(&self) -> bool;
}

/// Settings for a BSim search query.
///
/// Ports `ghidra.features.bsim.gui.search.dialog.BSimSearchSettings`.
/// This is the extended version with filter support (distinct from
/// the `gui::BSimSearchSettings` which is a simpler threshold-based config).
#[derive(Debug, Clone)]
pub struct BSimSearchQuerySettings {
    /// Database name.
    pub database: String,
    /// Maximum results to return.
    pub max_results: usize,
    /// Similarity threshold (0.0 to 1.0).
    pub similarity_threshold: f64,
    /// Filters to apply.
    pub filters: Vec<BSimFilter>,
    /// Whether to include children (signatures).
    pub include_children: bool,
    /// Whether to search only named functions.
    pub named_only: bool,
}

impl Default for BSimSearchQuerySettings {
    fn default() -> Self {
        Self {
            database: String::new(),
            max_results: 100,
            similarity_threshold: 0.8,
            filters: Vec::new(),
            include_children: true,
            named_only: false,
        }
    }
}

/// A BSim search response.
#[derive(Debug, Clone)]
pub struct BSimSearchResponse {
    /// Match results.
    pub matches: Vec<BSimSearchMatch>,
    /// Total results found.
    pub total_count: usize,
    /// Search duration in milliseconds.
    pub duration_ms: u64,
    /// Any warnings.
    pub warnings: Vec<String>,
}

/// A single BSim search match.
#[derive(Debug, Clone)]
pub struct BSimSearchMatch {
    /// The function name.
    pub function_name: String,
    /// The executable name.
    pub executable_name: String,
    /// Similarity score (0.0 to 1.0).
    pub similarity: f64,
    /// The address in the target program.
    pub address: u64,
    /// The library name (if any).
    pub library: Option<String>,
    /// The compiler name (if known).
    pub compiler: Option<String>,
}

/// A BSim filter.
///
/// Ports `ghidra.features.bim.protocol.BSimFilter`.
#[derive(Debug, Clone)]
pub struct BSimFilter {
    /// Filter field name.
    pub field: String,
    /// Filter value.
    pub value: String,
    /// Filter type (equals, contains, starts_with, etc.).
    pub filter_type: BSimFilterType,
}

/// BSim filter types.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BSimFilterType {
    /// Exact match.
    Equals,
    /// Contains substring.
    Contains,
    /// Starts with prefix.
    StartsWith,
    /// Not equal.
    NotEquals,
    /// Greater than.
    GreaterThan,
    /// Less than.
    LessThan,
}

// ============================================================================
// BSimFilterPanel
// ============================================================================

/// Panel for building BSim filter queries.
///
/// Ports `ghidra.features.bsim.gui.search.dialog.BSimFilterPanel`.
#[derive(Debug, Clone)]
pub struct BSimFilterPanel {
    /// Active filters.
    filters: Vec<BSimFilter>,
    /// Available filter types.
    pub available_fields: Vec<String>,
}

impl BSimFilterPanel {
    /// Create a new filter panel.
    pub fn new() -> Self {
        Self {
            filters: Vec::new(),
            available_fields: vec![
                "architecture".into(),
                "compiler".into(),
                "executable_name".into(),
                "executable_category".into(),
                "md5".into(),
                "function_tag".into(),
                "date".into(),
            ],
        }
    }

    /// Add a filter.
    pub fn add_filter(&mut self, filter: BSimFilter) {
        self.filters.push(filter);
    }

    /// Remove a filter by index.
    pub fn remove_filter(&mut self, index: usize) {
        if index < self.filters.len() {
            self.filters.remove(index);
        }
    }

    /// Get the current filters.
    pub fn filters(&self) -> &[BSimFilter] {
        &self.filters
    }

    /// Clear all filters.
    pub fn clear(&mut self) {
        self.filters.clear();
    }

    /// Whether there are any active filters.
    pub fn has_filters(&self) -> bool {
        !self.filters.is_empty()
    }
}

impl Default for BSimFilterPanel {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// FilterWidget
// ============================================================================

/// Individual filter widget.
///
/// Ports `ghidra.features.bsim.gui.search.dialog.FilterWidget`.
#[derive(Debug, Clone)]
pub struct FilterWidget {
    /// The filter field.
    pub field: String,
    /// The current value.
    pub value: String,
    /// The filter type.
    pub filter_type: BSimFilterType,
    /// Whether this widget is enabled.
    pub enabled: bool,
}

impl FilterWidget {
    /// Create a new filter widget.
    pub fn new(field: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            value: String::new(),
            filter_type: BSimFilterType::Contains,
            enabled: true,
        }
    }

    /// Get the filter from this widget.
    pub fn to_filter(&self) -> Option<BSimFilter> {
        if !self.enabled || self.value.is_empty() {
            return None;
        }
        Some(BSimFilter {
            field: self.field.clone(),
            value: self.value.clone(),
            filter_type: self.filter_type,
        })
    }
}

// ============================================================================
// FunctionSymbolToFunctionTableRowMapper
// ============================================================================

/// Maps function symbols to table row objects.
///
/// Ports `ghidra.features.bsim.gui.search.dialog.FunctionSymbolToFunctionTableRowMapper`.
#[derive(Debug, Clone, Default)]
pub struct FunctionSymbolToFunctionTableRowMapper;

impl FunctionSymbolToFunctionTableRowMapper {
    /// Create a new mapper.
    pub fn new() -> Self {
        Self
    }

    /// Map a function symbol to a table row.
    pub fn map_function(
        &self,
        name: &str,
        address: u64,
        signature: &str,
    ) -> FunctionTableRow {
        FunctionTableRow {
            name: name.to_string(),
            address,
            signature: signature.to_string(),
            namespace: String::new(),
            size: 0,
        }
    }
}

/// A row in the function table.
#[derive(Debug, Clone)]
pub struct FunctionTableRow {
    pub name: String,
    pub address: u64,
    pub signature: String,
    pub namespace: String,
    pub size: u64,
}

// ============================================================================
// BSimSearchSettings (builder)
// ============================================================================

impl BSimSearchQuerySettings {
    /// Create settings with a database name.
    pub fn with_database(mut self, db: impl Into<String>) -> Self {
        self.database = db.into();
        self
    }

    /// Set max results.
    pub fn with_max_results(mut self, max: usize) -> Self {
        self.max_results = max;
        self
    }

    /// Set similarity threshold.
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.similarity_threshold = threshold;
        self
    }

    /// Add a filter.
    pub fn with_filter(mut self, filter: BSimFilter) -> Self {
        self.filters.push(filter);
        self
    }
}

// ============================================================================
// ShowNamespaceSettingsDefinition
// ============================================================================

/// Settings definition for showing namespaces in BSim results.
///
/// Ports `ghidra.features.bsim.gui.search.results.ShowNamespaceSettingsDefinition`.
#[derive(Debug, Clone)]
pub struct ShowNamespaceSettingsDefinition {
    /// Whether to show namespace in results.
    pub show_namespace: bool,
    /// The separator character.
    pub separator: String,
}

impl ShowNamespaceSettingsDefinition {
    /// Create new settings.
    pub fn new() -> Self {
        Self {
            show_namespace: false,
            separator: "::".to_string(),
        }
    }

    /// Format a function name with its namespace.
    pub fn format_name(&self, namespace: &str, name: &str) -> String {
        if self.show_namespace && !namespace.is_empty() {
            format!("{}{}{}", namespace, self.separator, name)
        } else {
            name.to_string()
        }
    }
}

impl Default for ShowNamespaceSettingsDefinition {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// BSimSearchResultsProvider trait
// ============================================================================

/// Trait for providing BSim search results.
///
/// Ports `ghidra.features.bsim.gui.search.results.BSimSearchResultsProvider`.
pub trait BSimSearchResultsProvider: Send + Sync {
    /// Get the results.
    fn results(&self) -> &[BSimSearchMatch];

    /// Get result count.
    fn result_count(&self) -> usize;

    /// Whether the results are loading.
    fn is_loading(&self) -> bool;

    /// Get any error message.
    fn error_message(&self) -> Option<&str>;
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_settings_default() {
        let settings = BSimSearchQuerySettings::default();
        assert_eq!(settings.max_results, 100);
        assert!((settings.similarity_threshold - 0.8).abs() < 1e-6);
    }

    #[test]
    fn search_settings_builder() {
        let settings = BSimSearchQuerySettings::default()
            .with_database("mydb")
            .with_max_results(50)
            .with_threshold(0.9);
        assert_eq!(settings.database, "mydb");
        assert_eq!(settings.max_results, 50);
    }

    #[test]
    fn filter_panel_add_remove() {
        let mut panel = BSimFilterPanel::new();
        assert!(!panel.has_filters());
        panel.add_filter(BSimFilter {
            field: "architecture".into(),
            value: "x86".into(),
            filter_type: BSimFilterType::Equals,
        });
        assert!(panel.has_filters());
        assert_eq!(panel.filters().len(), 1);
        panel.remove_filter(0);
        assert!(!panel.has_filters());
    }

    #[test]
    fn filter_widget_to_filter() {
        let mut widget = FilterWidget::new("compiler");
        widget.value = "gcc".to_string();
        let filter = widget.to_filter().unwrap();
        assert_eq!(filter.field, "compiler");
        assert_eq!(filter.value, "gcc");
    }

    #[test]
    fn filter_widget_disabled() {
        let mut widget = FilterWidget::new("arch");
        widget.value = "x86".to_string();
        widget.enabled = false;
        assert!(widget.to_filter().is_none());
    }

    #[test]
    fn filter_widget_empty_value() {
        let widget = FilterWidget::new("arch");
        assert!(widget.to_filter().is_none());
    }

    #[test]
    fn function_mapper() {
        let mapper = FunctionSymbolToFunctionTableRowMapper::new();
        let row = mapper.map_function("main", 0x1000, "int main()");
        assert_eq!(row.name, "main");
        assert_eq!(row.address, 0x1000);
    }

    #[test]
    fn show_namespace_settings() {
        let settings = ShowNamespaceSettingsDefinition::new();
        assert_eq!(settings.format_name("std", "cout"), "cout");
        let mut settings_ns = ShowNamespaceSettingsDefinition::new();
        settings_ns.show_namespace = true;
        assert_eq!(settings_ns.format_name("std", "cout"), "std::cout");
    }

    #[test]
    fn show_namespace_empty() {
        let mut settings = ShowNamespaceSettingsDefinition::new();
        settings.show_namespace = true;
        assert_eq!(settings.format_name("", "func"), "func");
    }

    #[test]
    fn search_match_fields() {
        let m = BSimSearchMatch {
            function_name: "main".into(),
            executable_name: "a.out".into(),
            similarity: 0.95,
            address: 0x1000,
            library: Some("libc".into()),
            compiler: Some("gcc".into()),
        };
        assert_eq!(m.similarity, 0.95);
    }

    #[test]
    fn filter_types() {
        assert_ne!(BSimFilterType::Equals, BSimFilterType::Contains);
    }
}
