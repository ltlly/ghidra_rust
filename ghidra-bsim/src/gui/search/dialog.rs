//! BSim search dialog types.
//!
//! Ports `ghidra.features.bsim.gui.search.dialog` from Ghidra's Java source.

/// Configuration for creating a new BSim server info from the dialog.
#[derive(Debug, Clone)]
pub struct CreateBSimServerInfoDialog {
    /// Server name entered by the user.
    pub server_name: String,
    /// Backend type selected.
    pub backend_type: String,
    /// Hostname entered.
    pub hostname: String,
    /// Port entered.
    pub port: u16,
    /// Database name entered.
    pub database: String,
    /// Username entered.
    pub username: String,
}

impl Default for CreateBSimServerInfoDialog {
    fn default() -> Self {
        Self {
            server_name: String::new(),
            backend_type: "postgresql".into(),
            hostname: "localhost".into(),
            port: 5432,
            database: "bsim".into(),
            username: "bsim".into(),
        }
    }
}

impl CreateBSimServerInfoDialog {
    /// Validate the dialog inputs.
    pub fn validate(&self) -> Result<(), String> {
        if self.server_name.is_empty() {
            return Err("Server name is required".into());
        }
        if self.hostname.is_empty() {
            return Err("Hostname is required".into());
        }
        if self.database.is_empty() {
            return Err("Database name is required".into());
        }
        if self.port == 0 {
            return Err("Port must be non-zero".into());
        }
        Ok(())
    }
}

/// Settings for a BSim search query.
///
/// Ports `ghidra.features.bsim.gui.search.dialog.BSimSearchSettings`.
#[derive(Debug, Clone)]
pub struct BSimSearchSettings {
    /// Minimum similarity threshold.
    pub min_similarity: f64,
    /// Maximum number of results to return.
    pub max_results: usize,
    /// Whether to include callgraph information.
    pub include_callgraph: bool,
    /// Whether to apply filters to the search.
    pub apply_filters: bool,
    /// Active filter entries.
    pub filters: Vec<super::super::filter_types::BSimFilterEntry>,
    /// Selected functions to search (empty = all).
    pub selected_functions: Vec<u64>,
}

impl BSimSearchSettings {
    /// Create default settings.
    pub fn new() -> Self {
        Self {
            min_similarity: 0.5,
            max_results: 100,
            include_callgraph: true,
            apply_filters: false,
            filters: Vec::new(),
            selected_functions: Vec::new(),
        }
    }

    /// Set the minimum similarity.
    pub fn with_min_similarity(mut self, threshold: f64) -> Self {
        self.min_similarity = threshold;
        self
    }

    /// Set the max results.
    pub fn with_max_results(mut self, max: usize) -> Self {
        self.max_results = max;
        self
    }
}

impl Default for BSimSearchSettings {
    fn default() -> Self {
        Self::new()
    }
}

/// Panel for configuring BSim search filters.
///
/// Ports `ghidra.features.bsim.gui.search.dialog.BSimFilterPanel`.
#[derive(Debug, Clone)]
pub struct BSimFilterPanel {
    /// Available filter types.
    pub available_types: Vec<String>,
    /// Currently configured filters.
    pub active_filters: Vec<super::super::filter_types::BSimFilterEntry>,
    /// Currently selected filter type index.
    pub selected_type_index: Option<usize>,
}

impl BSimFilterPanel {
    /// Create a new filter panel.
    pub fn new() -> Self {
        Self {
            available_types: super::super::filter_types::BSimFilterBasis::all_filters()
                .into_iter()
                .map(String::from)
                .collect(),
            active_filters: Vec::new(),
            selected_type_index: None,
        }
    }

    /// Add a filter to the active set.
    pub fn add_filter(&mut self, entry: super::super::filter_types::BSimFilterEntry) {
        self.active_filters.push(entry);
    }

    /// Remove a filter by name.
    pub fn remove_filter(&mut self, name: &str) {
        self.active_filters.retain(|f| f.filter_name != name);
    }

    /// Get the number of active filters.
    pub fn active_count(&self) -> usize {
        self.active_filters.len()
    }

    /// Clear all active filters.
    pub fn clear(&mut self) {
        self.active_filters.clear();
        self.selected_type_index = None;
    }

    /// Select a filter type by index.
    pub fn select_type(&mut self, index: usize) {
        if index < self.available_types.len() {
            self.selected_type_index = Some(index);
        }
    }
}

impl Default for BSimFilterPanel {
    fn default() -> Self {
        Self::new()
    }
}

/// Table model for BSim server list.
///
/// Ports `ghidra.features.bsim.gui.search.dialog.BSimServerTableModel`.
#[derive(Debug, Clone)]
pub struct BSimServerTableModel {
    /// Server entries.
    pub entries: Vec<BSimServerTableEntry>,
    /// Currently selected index.
    pub selected_index: Option<usize>,
}

/// A single server entry in the table.
#[derive(Debug, Clone)]
pub struct BSimServerTableEntry {
    /// Display name.
    pub name: String,
    /// Backend type.
    pub backend_type: String,
    /// Hostname.
    pub hostname: String,
    /// Port.
    pub port: u16,
    /// Database name.
    pub database: String,
    /// Whether the server is connected.
    pub connected: bool,
    /// Last error message (if any).
    pub last_error: Option<String>,
}

impl BSimServerTableModel {
    /// Create a new empty table model.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            selected_index: None,
        }
    }

    /// Add a server entry.
    pub fn add(&mut self, entry: BSimServerTableEntry) {
        self.entries.push(entry);
    }

    /// Remove a server by name.
    pub fn remove(&mut self, name: &str) {
        self.entries.retain(|e| e.name != name);
        self.selected_index = None;
    }

    /// Get the selected entry.
    pub fn selected(&self) -> Option<&BSimServerTableEntry> {
        self.selected_index.and_then(|i| self.entries.get(i))
    }

    /// Select by index.
    pub fn select(&mut self, index: usize) {
        if index < self.entries.len() {
            self.selected_index = Some(index);
        }
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for BSimServerTableModel {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache for BSim server connection pools.
///
/// Ports `ghidra.features.bsim.gui.search.dialog.BSimServerCache`.
#[derive(Debug, Clone)]
pub struct BSimServerCache {
    /// Cached server info entries.
    entries: std::collections::HashMap<String, BSimCacheEntry>,
}

/// A cached server entry.
#[derive(Debug, Clone)]
pub struct BSimCacheEntry {
    /// Server name.
    pub server_name: String,
    /// When this entry was cached (Unix timestamp).
    pub cached_at: i64,
    /// Time-to-live in seconds.
    pub ttl_seconds: i64,
    /// Whether this entry has expired.
    pub expired: bool,
}

impl BSimServerCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self {
            entries: std::collections::HashMap::new(),
        }
    }

    /// Insert an entry into the cache.
    pub fn insert(&mut self, name: impl Into<String>, ttl_seconds: i64) {
        let name = name.into();
        self.entries.insert(
            name.clone(),
            BSimCacheEntry {
                server_name: name,
                cached_at: 0,
                ttl_seconds,
                expired: false,
            },
        );
    }

    /// Get an entry from the cache.
    pub fn get(&self, name: &str) -> Option<&BSimCacheEntry> {
        self.entries.get(name)
    }

    /// Remove an entry.
    pub fn remove(&mut self, name: &str) {
        self.entries.remove(name);
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Get the number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove expired entries.
    pub fn evict_expired(&mut self) {
        self.entries.retain(|_, e| !e.expired);
    }
}

impl Default for BSimServerCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Connection pool status information.
///
/// Ports `ghidra.features.bsim.gui.search.dialog.ConnectionPoolStatus`.
#[derive(Debug, Clone)]
pub struct ConnectionPoolStatus {
    /// Total number of connections in the pool.
    pub total_connections: usize,
    /// Number of active (in-use) connections.
    pub active_connections: usize,
    /// Number of idle connections.
    pub idle_connections: usize,
    /// Number of pending connection requests.
    pub pending_requests: usize,
    /// Maximum pool size.
    pub max_pool_size: usize,
    /// Pool name/identifier.
    pub pool_name: String,
}

impl ConnectionPoolStatus {
    /// Create a new connection pool status.
    pub fn new(pool_name: impl Into<String>, max_pool_size: usize) -> Self {
        Self {
            total_connections: 0,
            active_connections: 0,
            idle_connections: 0,
            pending_requests: 0,
            max_pool_size,
            pool_name: pool_name.into(),
        }
    }

    /// Whether the pool has available connections.
    pub fn has_available(&self) -> bool {
        self.idle_connections > 0 || self.total_connections < self.max_pool_size
    }

    /// Pool utilization as a fraction (0.0 to 1.0).
    pub fn utilization(&self) -> f64 {
        if self.max_pool_size == 0 {
            return 0.0;
        }
        self.active_connections as f64 / self.max_pool_size as f64
    }
}

/// Service for managing BSim search operations.
///
/// Ports `ghidra.features.bsim.gui.search.dialog.BSimSearchService`.
#[derive(Debug)]
pub struct BSimSearchService {
    /// Current search state.
    pub state: super::BSimSearchState,
    /// Server model for the search.
    pub server_model: BSimServerTableModel,
    /// Search settings.
    pub settings: BSimSearchSettings,
}

impl BSimSearchService {
    /// Create a new search service.
    pub fn new() -> Self {
        Self {
            state: super::BSimSearchState::Idle,
            server_model: BSimServerTableModel::new(),
            settings: BSimSearchSettings::new(),
        }
    }

    /// Start a search.
    pub fn start_search(&mut self) {
        self.state = super::BSimSearchState::Searching;
    }

    /// Complete the search.
    pub fn complete_search(&mut self) {
        self.state = super::BSimSearchState::Complete;
    }

    /// Fail the search.
    pub fn fail_search(&mut self, message: impl Into<String>) {
        self.state = super::BSimSearchState::Failed(message.into());
    }

    /// Reset to idle.
    pub fn reset(&mut self) {
        self.state = super::BSimSearchState::Idle;
    }

    /// Whether a search is in progress.
    pub fn is_searching(&self) -> bool {
        self.state.is_searching()
    }
}

impl Default for BSimSearchService {
    fn default() -> Self {
        Self::new()
    }
}

/// Maps function symbols to function table row data.
///
/// Ports `ghidra.features.bsim.gui.search.dialog.FunctionSymbolToFunctionTableRowMapper`.
#[derive(Debug, Clone)]
pub struct FunctionSymbolMapper {
    /// Source symbol name.
    pub symbol_name: String,
    /// Source address.
    pub address: u64,
    /// Mapped function entry point.
    pub function_entry_point: u64,
    /// The function's namespace.
    pub namespace: String,
    /// Whether the mapping is valid.
    pub valid: bool,
}

impl FunctionSymbolMapper {
    /// Create a new mapper.
    pub fn new(
        symbol_name: impl Into<String>,
        address: u64,
        function_entry_point: u64,
    ) -> Self {
        Self {
            symbol_name: symbol_name.into(),
            address,
            function_entry_point,
            namespace: String::new(),
            valid: true,
        }
    }

    /// Set the namespace.
    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = ns.into();
        self
    }

    /// Get the fully qualified name.
    pub fn qualified_name(&self) -> String {
        if self.namespace.is_empty() {
            self.symbol_name.clone()
        } else {
            format!("{}::{}", self.namespace, self.symbol_name)
        }
    }
}

/// Dialog for managing BSim database server definitions.
///
/// Ports `ghidra.features.bsim.gui.search.dialog.BSimServerDialog`.
#[derive(Debug, Clone)]
pub struct BSimServerDialog {
    /// Title of the dialog.
    pub title: String,
    /// The server table model.
    pub server_model: BSimServerTableModel,
    /// Whether the dialog is currently visible.
    pub visible: bool,
    /// Preferred width.
    pub preferred_width: u32,
    /// Preferred height.
    pub preferred_height: u32,
    /// Last added server info (for auto-selecting).
    pub last_added: Option<String>,
    /// Whether the database connection is active.
    pub db_connection_active: bool,
}

impl BSimServerDialog {
    /// Create a new server dialog.
    pub fn new() -> Self {
        Self {
            title: "BSim Server Manager".into(),
            server_model: BSimServerTableModel::new(),
            visible: false,
            preferred_width: 600,
            preferred_height: 400,
            last_added: None,
            db_connection_active: false,
        }
    }

    /// Show the dialog.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Dismiss the dialog.
    pub fn dismiss(&mut self) {
        self.visible = false;
    }

    /// Add a new server.
    pub fn add_server(&mut self, entry: BSimServerTableEntry) {
        self.last_added = Some(entry.name.clone());
        self.server_model.add(entry);
    }

    /// Toggle the database connection state.
    pub fn toggle_connection(&mut self) {
        self.db_connection_active = !self.db_connection_active;
    }
}

impl Default for BSimServerDialog {
    fn default() -> Self {
        Self::new()
    }
}

/// Dialog for the BSim overview (showing all known databases/executables).
///
/// Ports `ghidra.features.bsim.gui.search.dialog.BSimOverviewDialog`.
#[derive(Debug, Clone)]
pub struct BSimOverviewDialog {
    /// Title of the dialog.
    pub title: String,
    /// Overview entries.
    pub entries: Vec<BSimOverviewEntry>,
    /// Currently selected entry index.
    pub selected_index: Option<usize>,
    /// Whether the dialog is visible.
    pub visible: bool,
}

/// A single entry in the BSim overview.
#[derive(Debug, Clone)]
pub struct BSimOverviewEntry {
    /// Database/server name.
    pub server_name: String,
    /// Executable name.
    pub executable_name: String,
    /// Architecture.
    pub architecture: String,
    /// Number of functions.
    pub function_count: usize,
    /// Database type.
    pub db_type: String,
}

impl BSimOverviewDialog {
    /// Create a new overview dialog.
    pub fn new() -> Self {
        Self {
            title: "BSim Database Overview".into(),
            entries: Vec::new(),
            selected_index: None,
            visible: false,
        }
    }

    /// Add an entry.
    pub fn add_entry(&mut self, entry: BSimOverviewEntry) {
        self.entries.push(entry);
    }

    /// Get the selected entry.
    pub fn selected(&self) -> Option<&BSimOverviewEntry> {
        self.selected_index.and_then(|i| self.entries.get(i))
    }

    /// Select an entry by index.
    pub fn select(&mut self, index: usize) {
        if index < self.entries.len() {
            self.selected_index = Some(index);
        }
    }

    /// Show the dialog.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Dismiss the dialog.
    pub fn dismiss(&mut self) {
        self.visible = false;
    }

    /// Get the number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

impl Default for BSimOverviewDialog {
    fn default() -> Self {
        Self::new()
    }
}

/// A widget for configuring a single BSim filter.
///
/// Ports `ghidra.features.bsim.gui.filters.FilterWidget`.
#[derive(Debug, Clone)]
pub struct FilterWidget {
    /// The filter type name.
    pub filter_type: String,
    /// The filter value.
    pub value: String,
    /// Whether the filter is enabled.
    pub enabled: bool,
    /// Whether this is a negated filter.
    pub negated: bool,
}

impl FilterWidget {
    /// Create a new filter widget.
    pub fn new(filter_type: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            filter_type: filter_type.into(),
            value: value.into(),
            enabled: true,
            negated: false,
        }
    }

    /// Create a negated filter widget.
    pub fn negated(filter_type: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            filter_type: filter_type.into(),
            value: value.into(),
            enabled: true,
            negated: true,
        }
    }

    /// Toggle the enabled state.
    pub fn toggle(&mut self) {
        self.enabled = !self.enabled;
    }

    /// Set the value.
    pub fn set_value(&mut self, value: impl Into<String>) {
        self.value = value.into();
    }

    /// Get the display label for this filter.
    pub fn display_label(&self) -> String {
        let prefix = if self.negated { "NOT " } else { "" };
        format!("{}{}: {}", prefix, self.filter_type, self.value)
    }
}

/// The main BSim search plugin entry point.
///
/// Ports `ghidra.features.bsim.gui.BSimSearchPlugin`.
#[derive(Debug)]
pub struct BSimSearchPlugin {
    /// Plugin name.
    pub name: String,
    /// Whether the plugin is enabled.
    pub enabled: bool,
    /// Search service.
    pub search_service: BSimSearchService,
    /// Server dialog reference.
    pub server_dialog: BSimServerDialog,
    /// Overview dialog reference.
    pub overview_dialog: BSimOverviewDialog,
    /// Active filter widgets.
    pub filter_widgets: Vec<FilterWidget>,
}

impl BSimSearchPlugin {
    /// Create a new BSim search plugin.
    pub fn new() -> Self {
        Self {
            name: "BSimSearchPlugin".into(),
            enabled: true,
            search_service: BSimSearchService::new(),
            server_dialog: BSimServerDialog::new(),
            overview_dialog: BSimOverviewDialog::new(),
            filter_widgets: Vec::new(),
        }
    }

    /// Add a filter widget.
    pub fn add_filter(&mut self, widget: FilterWidget) {
        self.filter_widgets.push(widget);
    }

    /// Remove a filter by type name.
    pub fn remove_filter(&mut self, filter_type: &str) {
        self.filter_widgets.retain(|w| w.filter_type != filter_type);
    }

    /// Get the number of active filters.
    pub fn active_filter_count(&self) -> usize {
        self.filter_widgets.iter().filter(|w| w.enabled).count()
    }

    /// Open the server manager dialog.
    pub fn open_server_dialog(&mut self) {
        self.server_dialog.show();
    }

    /// Open the overview dialog.
    pub fn open_overview_dialog(&mut self) {
        self.overview_dialog.show();
    }

    /// Start a search with current settings.
    pub fn start_search(&mut self) {
        self.search_service.start_search();
    }

    /// Get the search state.
    pub fn search_state(&self) -> &super::BSimSearchState {
        &self.search_service.state
    }
}

impl Default for BSimSearchPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// A dialog for selecting functions to search.
#[derive(Debug, Clone, Default)]
pub struct SelectedFunctionsTableDialog {
    /// Selected function entry points.
    pub selected_functions: Vec<u64>,
    /// Total functions available.
    pub total_functions: usize,
}

impl SelectedFunctionsTableDialog {
    /// Create a new dialog.
    pub fn new(total_functions: usize) -> Self {
        Self {
            selected_functions: Vec::new(),
            total_functions,
        }
    }

    /// Add a function to the selection.
    pub fn select(&mut self, entry_point: u64) {
        if !self.selected_functions.contains(&entry_point) {
            self.selected_functions.push(entry_point);
        }
    }

    /// Remove a function from the selection.
    pub fn deselect(&mut self, entry_point: u64) {
        self.selected_functions.retain(|&f| f != entry_point);
    }

    /// Toggle selection.
    pub fn toggle(&mut self, entry_point: u64) {
        if self.selected_functions.contains(&entry_point) {
            self.deselect(entry_point);
        } else {
            self.select(entry_point);
        }
    }

    /// Get the number of selected functions.
    pub fn selection_count(&self) -> usize {
        self.selected_functions.len()
    }

    /// Whether all functions are selected.
    pub fn is_all_selected(&self) -> bool {
        self.selected_functions.len() == self.total_functions
    }

    /// Select all functions.
    pub fn select_all(&mut self) {
        self.selected_functions = (0..self.total_functions as u64).collect();
    }

    /// Clear the selection.
    pub fn clear(&mut self) {
        self.selected_functions.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_dialog_validate() {
        let mut dialog = CreateBSimServerInfoDialog::default();
        assert!(dialog.validate().is_err()); // name is empty

        dialog.server_name = "test".into();
        assert!(dialog.validate().is_ok());
    }

    #[test]
    fn test_create_dialog_validate_empty_hostname() {
        let dialog = CreateBSimServerInfoDialog {
            server_name: "test".into(),
            hostname: String::new(),
            ..Default::default()
        };
        assert!(dialog.validate().is_err());
        assert!(dialog.validate().unwrap_err().contains("Hostname"));
    }

    #[test]
    fn test_selected_functions_dialog() {
        let mut dialog = SelectedFunctionsTableDialog::new(100);
        assert_eq!(dialog.selection_count(), 0);

        dialog.select(0x1000);
        dialog.select(0x2000);
        assert_eq!(dialog.selection_count(), 2);

        dialog.toggle(0x1000);
        assert_eq!(dialog.selection_count(), 1);

        dialog.toggle(0x3000);
        assert_eq!(dialog.selection_count(), 2);
    }

    #[test]
    fn test_selected_functions_select_all() {
        let mut dialog = SelectedFunctionsTableDialog::new(10);
        assert!(!dialog.is_all_selected());

        dialog.select_all();
        assert!(dialog.is_all_selected());
        assert_eq!(dialog.selection_count(), 10);

        dialog.clear();
        assert_eq!(dialog.selection_count(), 0);
        assert!(!dialog.is_all_selected());
    }

    #[test]
    fn test_search_settings() {
        let settings = BSimSearchSettings::new();
        assert!((settings.min_similarity - 0.5).abs() < f64::EPSILON);
        assert_eq!(settings.max_results, 100);
        assert!(settings.include_callgraph);
        assert!(!settings.apply_filters);
        assert!(settings.filters.is_empty());
    }

    #[test]
    fn test_search_settings_builder() {
        let settings = BSimSearchSettings::new()
            .with_min_similarity(0.8)
            .with_max_results(50);
        assert!((settings.min_similarity - 0.8).abs() < f64::EPSILON);
        assert_eq!(settings.max_results, 50);
    }

    #[test]
    fn test_filter_panel() {
        let mut panel = BSimFilterPanel::new();
        assert!(!panel.available_types.is_empty());
        assert_eq!(panel.active_count(), 0);

        panel.add_filter(crate::gui::filter_types::BSimFilterEntry::new("architecture", "x86"));
        assert_eq!(panel.active_count(), 1);

        panel.remove_filter("architecture");
        assert_eq!(panel.active_count(), 0);
    }

    #[test]
    fn test_filter_panel_select_type() {
        let mut panel = BSimFilterPanel::new();
        assert!(panel.selected_type_index.is_none());

        panel.select_type(0);
        assert_eq!(panel.selected_type_index, Some(0));

        panel.select_type(9999);
        assert_eq!(panel.selected_type_index, Some(0)); // unchanged
    }

    #[test]
    fn test_filter_panel_clear() {
        let mut panel = BSimFilterPanel::new();
        panel.add_filter(crate::gui::filter_types::BSimFilterEntry::new("test", "value"));
        panel.select_type(0);
        panel.clear();
        assert_eq!(panel.active_count(), 0);
        assert!(panel.selected_type_index.is_none());
    }

    #[test]
    fn test_server_table_model() {
        let mut model = BSimServerTableModel::new();
        assert!(model.is_empty());

        model.add(BSimServerTableEntry {
            name: "server1".into(),
            backend_type: "postgresql".into(),
            hostname: "localhost".into(),
            port: 5432,
            database: "bsim".into(),
            connected: false,
            last_error: None,
        });
        assert_eq!(model.len(), 1);
        assert!(!model.is_empty());

        model.select(0);
        let selected = model.selected();
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().name, "server1");

        model.remove("server1");
        assert!(model.is_empty());
    }

    #[test]
    fn test_server_table_model_select() {
        let mut model = BSimServerTableModel::new();
        model.select(0); // no entries, should be no-op
        assert!(model.selected().is_none());

        model.add(BSimServerTableEntry {
            name: "s1".into(),
            backend_type: "elastic".into(),
            hostname: "localhost".into(),
            port: 9200,
            database: "bsim".into(),
            connected: true,
            last_error: None,
        });
        model.select(9999); // out of bounds
        assert!(model.selected().is_none());

        model.select(0);
        assert!(model.selected().is_some());
    }

    #[test]
    fn test_server_cache() {
        let mut cache = BSimServerCache::new();
        assert!(cache.is_empty());

        cache.insert("server1", 3600);
        assert_eq!(cache.len(), 1);
        assert!(!cache.is_empty());

        let entry = cache.get("server1");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().ttl_seconds, 3600);

        cache.remove("server1");
        assert!(cache.is_empty());
    }

    #[test]
    fn test_server_cache_evict() {
        let mut cache = BSimServerCache::new();
        cache.insert("s1", 60);
        cache.insert("s2", 60);

        // Manually mark as expired
        if let Some(entry) = cache.entries.get_mut("s1") {
            entry.expired = true;
        }

        cache.evict_expired();
        assert_eq!(cache.len(), 1);
        assert!(cache.get("s1").is_none());
        assert!(cache.get("s2").is_some());
    }

    #[test]
    fn test_connection_pool_status() {
        let mut status = ConnectionPoolStatus::new("main-pool", 10);
        assert_eq!(status.pool_name, "main-pool");
        assert_eq!(status.max_pool_size, 10);
        assert!(status.has_available());

        status.active_connections = 8;
        status.idle_connections = 2;
        status.total_connections = 10;
        assert!((status.utilization() - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_connection_pool_status_no_available() {
        let mut status = ConnectionPoolStatus::new("full-pool", 5);
        status.active_connections = 5;
        status.total_connections = 5;
        status.idle_connections = 0;
        assert!(!status.has_available());
    }

    #[test]
    fn test_connection_pool_status_utilization_zero() {
        let status = ConnectionPoolStatus::new("empty", 0);
        assert!((status.utilization() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_search_service() {
        let mut service = BSimSearchService::new();
        assert!(!service.is_searching());

        service.start_search();
        assert!(service.is_searching());
        assert!(service.state.is_searching());

        service.complete_search();
        assert!(service.state.is_complete());

        service.fail_search("timeout");
        assert!(service.state.is_failed());
        assert_eq!(service.state.error_message(), Some("timeout"));

        service.reset();
        assert!(!service.is_searching());
    }

    #[test]
    fn test_function_symbol_mapper() {
        let mapper = FunctionSymbolMapper::new("main", 0x1000, 0x1000)
            .with_namespace("MyApp");
        assert_eq!(mapper.symbol_name, "main");
        assert_eq!(mapper.qualified_name(), "MyApp::main");
        assert!(mapper.valid);

        let mapper = FunctionSymbolMapper::new("printf", 0x4000, 0x4000);
        assert_eq!(mapper.qualified_name(), "printf");
    }

    #[test]
    fn test_bsim_server_dialog() {
        let mut dialog = BSimServerDialog::new();
        assert_eq!(dialog.title, "BSim Server Manager");
        assert!(!dialog.visible);
        assert_eq!(dialog.preferred_width, 600);

        dialog.show();
        assert!(dialog.visible);
        dialog.dismiss();
        assert!(!dialog.visible);
    }

    #[test]
    fn test_bsim_server_dialog_add_server() {
        let mut dialog = BSimServerDialog::new();
        dialog.add_server(BSimServerTableEntry {
            name: "test".into(),
            backend_type: "postgresql".into(),
            hostname: "localhost".into(),
            port: 5432,
            database: "bsim".into(),
            connected: false,
            last_error: None,
        });
        assert_eq!(dialog.server_model.len(), 1);
        assert_eq!(dialog.last_added, Some("test".into()));
    }

    #[test]
    fn test_bsim_server_dialog_toggle_connection() {
        let mut dialog = BSimServerDialog::new();
        assert!(!dialog.db_connection_active);
        dialog.toggle_connection();
        assert!(dialog.db_connection_active);
    }

    #[test]
    fn test_bsim_overview_dialog() {
        let mut dialog = BSimOverviewDialog::new();
        assert!(dialog.visible == false);
        assert_eq!(dialog.entry_count(), 0);

        dialog.add_entry(BSimOverviewEntry {
            server_name: "server1".into(),
            executable_name: "libc.so".into(),
            architecture: "x86".into(),
            function_count: 1000,
            db_type: "postgresql".into(),
        });
        assert_eq!(dialog.entry_count(), 1);

        dialog.select(0);
        assert!(dialog.selected().is_some());
        assert_eq!(dialog.selected().unwrap().executable_name, "libc.so");

        dialog.show();
        assert!(dialog.visible);
    }

    #[test]
    fn test_bsim_overview_dialog_select_out_of_bounds() {
        let mut dialog = BSimOverviewDialog::new();
        dialog.select(9999); // no entries
        assert!(dialog.selected().is_none());
    }

    #[test]
    fn test_filter_widget() {
        let widget = FilterWidget::new("architecture", "x86");
        assert!(widget.enabled);
        assert!(!widget.negated);
        assert_eq!(widget.display_label(), "architecture: x86");
    }

    #[test]
    fn test_filter_widget_negated() {
        let widget = FilterWidget::negated("architecture", "arm");
        assert!(widget.negated);
        assert_eq!(widget.display_label(), "NOT architecture: arm");
    }

    #[test]
    fn test_filter_widget_toggle() {
        let mut widget = FilterWidget::new("compiler", "gcc");
        assert!(widget.enabled);
        widget.toggle();
        assert!(!widget.enabled);
    }

    #[test]
    fn test_bsim_search_plugin() {
        let mut plugin = BSimSearchPlugin::new();
        assert_eq!(plugin.name, "BSimSearchPlugin");
        assert!(plugin.enabled);
        assert_eq!(plugin.filter_widgets.len(), 0);

        plugin.add_filter(FilterWidget::new("architecture", "x86"));
        plugin.add_filter(FilterWidget::new("compiler", "gcc"));
        assert_eq!(plugin.filter_widgets.len(), 2);
        assert_eq!(plugin.active_filter_count(), 2);

        plugin.remove_filter("architecture");
        assert_eq!(plugin.filter_widgets.len(), 1);
    }

    #[test]
    fn test_bsim_search_plugin_search() {
        let mut plugin = BSimSearchPlugin::new();
        assert!(!plugin.search_state().is_searching());

        plugin.start_search();
        assert!(plugin.search_state().is_searching());
    }

    #[test]
    fn test_bsim_search_plugin_dialogs() {
        let mut plugin = BSimSearchPlugin::new();
        plugin.open_server_dialog();
        assert!(plugin.server_dialog.visible);

        plugin.open_overview_dialog();
        assert!(plugin.overview_dialog.visible);
    }
}
