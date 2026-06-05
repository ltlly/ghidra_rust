//! BSim server cache and connection pool status.
//!
//! Ports `ghidra.features.bsim.gui.search.dialog.BSimServerCache` and
//! `ghidra.features.bsim.gui.search.dialog.ConnectionPoolStatus`.
//!
//! Caches BSim server connections to avoid repeated connection setup
//! and monitors the health of the connection pool.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::{BSimServerInfo, ConnectionType};

// ============================================================================
// ConnectionPoolStatus
// ============================================================================

/// Status of a BSim connection pool.
///
/// Port of `ghidra.features.bsim.gui.search.dialog.ConnectionPoolStatus`.
#[derive(Debug, Clone)]
pub struct ConnectionPoolStatus {
    /// Number of active (in-use) connections.
    pub active_count: usize,
    /// Number of idle (available) connections.
    pub idle_count: usize,
    /// Maximum pool size.
    pub max_pool_size: usize,
    /// Total number of connections created since startup.
    pub total_created: usize,
    /// Total number of connection errors.
    pub total_errors: usize,
    /// Average connection latency in milliseconds.
    pub avg_latency_ms: f64,
    /// Whether the pool is healthy.
    pub healthy: bool,
    /// Last error message (if any).
    pub last_error: Option<String>,
}

impl ConnectionPoolStatus {
    /// Create a new pool status.
    pub fn new(max_pool_size: usize) -> Self {
        Self {
            active_count: 0,
            idle_count: 0,
            max_pool_size,
            total_created: 0,
            total_errors: 0,
            avg_latency_ms: 0.0,
            healthy: true,
            last_error: None,
        }
    }

    /// Total number of connections (active + idle).
    pub fn total_connections(&self) -> usize {
        self.active_count + self.idle_count
    }

    /// Pool utilization as a ratio (0.0 to 1.0).
    pub fn utilization(&self) -> f64 {
        if self.max_pool_size == 0 {
            return 0.0;
        }
        self.total_connections() as f64 / self.max_pool_size as f64
    }

    /// Whether the pool has available idle connections.
    pub fn has_available(&self) -> bool {
        self.idle_count > 0
    }

    /// Whether the pool can create more connections.
    pub fn can_expand(&self) -> bool {
        self.total_connections() < self.max_pool_size
    }

    /// Record a successful connection creation.
    pub fn record_connection_created(&mut self, latency_ms: f64) {
        self.total_created += 1;
        self.idle_count += 1;
        // Running average.
        let n = self.total_created as f64;
        self.avg_latency_ms = self.avg_latency_ms * (n - 1.0) / n + latency_ms / n;
    }

    /// Record a connection being acquired from the pool.
    pub fn record_connection_acquired(&mut self) {
        if self.idle_count > 0 {
            self.idle_count -= 1;
            self.active_count += 1;
        }
    }

    /// Record a connection being returned to the pool.
    pub fn record_connection_released(&mut self) {
        if self.active_count > 0 {
            self.active_count -= 1;
            self.idle_count += 1;
        }
    }

    /// Record a connection error.
    pub fn record_error(&mut self, message: impl Into<String>) {
        self.total_errors += 1;
        self.last_error = Some(message.into());
        if self.total_errors > 10 {
            self.healthy = false;
        }
    }

    /// Reset the pool to healthy state.
    pub fn reset_health(&mut self) {
        self.healthy = true;
        self.total_errors = 0;
        self.last_error = None;
    }
}

impl Default for ConnectionPoolStatus {
    fn default() -> Self {
        Self::new(10)
    }
}

// ============================================================================
// CachedConnection
// ============================================================================

/// A cached connection entry with metadata.
#[derive(Debug, Clone)]
struct CachedConnection {
    /// Server info for this connection.
    server_info: BSimServerInfo,
    /// When this connection was last used.
    last_used: Instant,
    /// When this connection was created.
    created_at: Instant,
    /// Number of times this connection has been used.
    use_count: usize,
    /// Whether the connection is currently valid.
    valid: bool,
}

// ============================================================================
// BSimServerCache
// ============================================================================

/// Cache for BSim server connections.
///
/// Port of `ghidra.features.bsim.gui.search.dialog.BSimServerCache`.
///
/// Caches `BSimServerInfo` entries keyed by URL to avoid repeated
/// connection setup. Supports TTL-based expiration and pool management.
#[derive(Debug)]
pub struct BSimServerCache {
    /// Cache entries keyed by server URL.
    entries: HashMap<String, CachedConnection>,
    /// Maximum cache size.
    max_size: usize,
    /// Time-to-live for cache entries.
    ttl: Duration,
    /// Connection pool status.
    pub pool_status: ConnectionPoolStatus,
    /// Number of cache hits.
    cache_hits: usize,
    /// Number of cache misses.
    cache_misses: usize,
}

impl BSimServerCache {
    /// Create a new server cache with default settings.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            max_size: 20,
            ttl: Duration::from_secs(3600),
            pool_status: ConnectionPoolStatus::new(10),
            cache_hits: 0,
            cache_misses: 0,
        }
    }

    /// Create a server cache with a custom max size and TTL.
    pub fn with_config(max_size: usize, ttl_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            max_size,
            ttl: Duration::from_secs(ttl_secs),
            pool_status: ConnectionPoolStatus::new(max_size),
            cache_hits: 0,
            cache_misses: 0,
        }
    }

    /// Look up a cached server connection by URL.
    pub fn get(&mut self, url: &str) -> Option<&BSimServerInfo> {
        self.evict_expired();
        if let Some(entry) = self.entries.get(url) {
            if entry.valid {
                self.cache_hits += 1;
                return Some(&entry.server_info);
            }
        }
        self.cache_misses += 1;
        None
    }

    /// Insert a server connection into the cache.
    pub fn insert(&mut self, server_info: BSimServerInfo) {
        // Evict if at capacity.
        if self.entries.len() >= self.max_size && !self.entries.contains_key(&server_info.url) {
            self.evict_oldest();
        }
        let now = Instant::now();
        self.entries.insert(
            server_info.url.clone(),
            CachedConnection {
                server_info,
                last_used: now,
                created_at: now,
                use_count: 1,
                valid: true,
            },
        );
    }

    /// Remove a cached entry by URL.
    pub fn remove(&mut self, url: &str) -> Option<BSimServerInfo> {
        self.entries.remove(url).map(|e| e.server_info)
    }

    /// Check if a URL is cached.
    pub fn contains(&self, url: &str) -> bool {
        self.entries.get(url).map_or(false, |e| e.valid)
    }

    /// Get all cached server URLs.
    pub fn cached_urls(&self) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|(_, e)| e.valid)
            .map(|(url, _)| url.as_str())
            .collect()
    }

    /// Number of entries in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear the cache.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Cache hit rate (hits / (hits + misses)).
    pub fn hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            return 0.0;
        }
        self.cache_hits as f64 / total as f64
    }

    /// Invalidate a cached entry (mark as invalid but don't remove).
    pub fn invalidate(&mut self, url: &str) {
        if let Some(entry) = self.entries.get_mut(url) {
            entry.valid = false;
        }
    }

    /// Invalidate all cached entries.
    pub fn invalidate_all(&mut self) {
        for entry in self.entries.values_mut() {
            entry.valid = false;
        }
    }

    /// Evict expired entries.
    fn evict_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| {
            entry.valid && now.duration_since(entry.last_used) < self.ttl
        });
    }

    /// Evict the oldest entry.
    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_used)
            .map(|(k, _)| k.clone())
        {
            self.entries.remove(&oldest_key);
        }
    }
}

impl Default for BSimServerCache {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// BSimServerManager
// ============================================================================

/// Manages BSim server connections and provides connection lifecycle.
///
/// Port of `ghidra.features.bsim.gui.BSimServerManager`.
#[derive(Debug)]
pub struct BSimServerManager {
    /// The server connection cache.
    pub cache: BSimServerCache,
    /// Known server configurations.
    known_servers: Vec<BSimServerInfo>,
    /// The default server URL (if set).
    default_server_url: Option<String>,
}

impl BSimServerManager {
    /// Create a new server manager.
    pub fn new() -> Self {
        Self {
            cache: BSimServerCache::new(),
            known_servers: Vec::new(),
            default_server_url: None,
        }
    }

    /// Add a server configuration.
    pub fn add_server(&mut self, server: BSimServerInfo) {
        self.cache.insert(server.clone());
        if !self.known_servers.iter().any(|s| s.url == server.url) {
            self.known_servers.push(server);
        }
    }

    /// Remove a server configuration.
    pub fn remove_server(&mut self, url: &str) {
        self.cache.remove(url);
        self.known_servers.retain(|s| s.url != url);
        if self.default_server_url.as_deref() == Some(url) {
            self.default_server_url = None;
        }
    }

    /// Get all known servers.
    pub fn known_servers(&self) -> &[BSimServerInfo] {
        &self.known_servers
    }

    /// Set the default server.
    pub fn set_default_server(&mut self, url: impl Into<String>) {
        self.default_server_url = Some(url.into());
    }

    /// Get the default server.
    pub fn default_server(&self) -> Option<&BSimServerInfo> {
        self.default_server_url.as_ref().and_then(|url| {
            self.known_servers.iter().find(|s| &s.url == url)
        })
    }

    /// Get a server by URL (from cache or known servers).
    pub fn get_server(&mut self, url: &str) -> Option<&BSimServerInfo> {
        if let Some(info) = self.cache.get(url) {
            return Some(info);
        }
        self.known_servers.iter().find(|s| s.url == url)
    }
}

impl Default for BSimServerManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// BSimServerManagerListener
// ============================================================================

/// Listener for BSim server manager events.
///
/// Port of `ghidra.features.bsim.gui.search.dialog.BSimServerManagerListener`.
///
/// Notified when servers are added, removed, or when the default
/// server changes.
pub trait BSimServerManagerListener: Send + Sync {
    /// Called when a server is added.
    fn server_added(&self, server: &BSimServerInfo);

    /// Called when a server is removed.
    fn server_removed(&self, url: &str);

    /// Called when the default server changes.
    fn default_server_changed(&self, url: Option<&str>);
}

/// No-op listener that discards all events.
#[derive(Debug, Clone, Default)]
pub struct NullServerManagerListener;

impl BSimServerManagerListener for NullServerManagerListener {
    fn server_added(&self, _server: &BSimServerInfo) {}
    fn server_removed(&self, _url: &str) {}
    fn default_server_changed(&self, _url: Option<&str>) {}
}

// ============================================================================
// BSimServerTableModel
// ============================================================================

/// Table model for displaying BSim server configurations.
///
/// Port of `ghidra.features.bsim.gui.search.dialog.BSimServerTableModel`.
///
/// Provides row/column access for displaying server info in a table.
#[derive(Debug, Clone, Default)]
pub struct BSimServerTableModel {
    /// Column names.
    pub columns: Vec<String>,
    /// Server entries.
    entries: Vec<BSimServerInfo>,
}

impl BSimServerTableModel {
    /// Create a new server table model with default columns.
    pub fn new() -> Self {
        Self {
            columns: vec![
                "URL".to_string(),
                "Database".to_string(),
                "Type".to_string(),
                "SSL".to_string(),
            ],
            entries: Vec::new(),
        }
    }

    /// Add a server entry.
    pub fn add_entry(&mut self, server: BSimServerInfo) {
        self.entries.push(server);
    }

    /// Remove a server entry by URL.
    pub fn remove_entry(&mut self, url: &str) -> bool {
        let len_before = self.entries.len();
        self.entries.retain(|s| s.url != url);
        self.entries.len() < len_before
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.entries.len()
    }

    /// Get the number of columns.
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Get a cell value as a string.
    pub fn get_value_at(&self, row: usize, col: usize) -> Option<String> {
        let entry = self.entries.get(row)?;
        match col {
            0 => Some(entry.url.clone()),
            1 => Some(entry.database_name.clone()),
            2 => Some(format!("{:?}", entry.connection_type)),
            3 => Some(if entry.use_ssl { "Yes" } else { "No" }.to_string()),
            _ => None,
        }
    }

    /// Get a server entry by row index.
    pub fn get_entry(&self, row: usize) -> Option<&BSimServerInfo> {
        self.entries.get(row)
    }

    /// Get all entries.
    pub fn entries(&self) -> &[BSimServerInfo] {
        &self.entries
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ============================================================================
// CreateBsimServerInfoDialog
// ============================================================================

/// State for the "create BSim server info" dialog.
///
/// Port of `ghidra.features.bsim.gui.search.dialog.CreateBsimServerInfoDialog`.
///
/// Manages the form state for creating a new BSim server configuration.
#[derive(Debug, Clone)]
pub struct CreateBsimServerInfoDialog {
    /// Server URL being configured.
    pub url: String,
    /// Database name.
    pub database_name: String,
    /// Connection type.
    pub connection_type: ConnectionType,
    /// Whether SSL is enabled.
    pub use_ssl: bool,
    /// Username (optional).
    pub username: String,
    /// Whether the dialog was confirmed.
    pub confirmed: bool,
}

impl CreateBsimServerInfoDialog {
    /// Create a new dialog state with defaults.
    pub fn new() -> Self {
        Self {
            url: String::new(),
            database_name: String::new(),
            connection_type: ConnectionType::PostgreSQL,
            use_ssl: false,
            username: String::new(),
            confirmed: false,
        }
    }

    /// Set the URL.
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = url.into();
        self
    }

    /// Set the database name.
    pub fn with_database(mut self, name: impl Into<String>) -> Self {
        self.database_name = name.into();
        self
    }

    /// Set the connection type.
    pub fn with_connection_type(mut self, ct: ConnectionType) -> Self {
        self.connection_type = ct;
        self
    }

    /// Confirm the dialog.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Create a BSimServerInfo from the dialog state.
    pub fn to_server_info(&self) -> BSimServerInfo {
        BSimServerInfo {
            url: self.url.clone(),
            database_name: self.database_name.clone(),
            connection_type: self.connection_type,
            use_ssl: self.use_ssl,
            username: if self.username.is_empty() {
                None
            } else {
                Some(self.username.clone())
            },
        }
    }

    /// Whether the form is valid (URL and database name are non-empty).
    pub fn is_valid(&self) -> bool {
        !self.url.is_empty() && !self.database_name.is_empty()
    }
}

impl Default for CreateBsimServerInfoDialog {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SelectedFunctionsTableDialog
// ============================================================================

/// State for the "selected functions table" dialog.
///
/// Port of `ghidra.features.bsim.gui.search.dialog.SelectedFunctionsTableDialog`.
///
/// Displays and manages the set of functions selected for BSim querying.
#[derive(Debug, Clone, Default)]
pub struct SelectedFunctionsTableDialog {
    /// Selected function names.
    pub function_names: Vec<String>,
    /// Whether the dialog was confirmed.
    pub confirmed: bool,
    /// Title for the dialog.
    pub title: String,
}

impl SelectedFunctionsTableDialog {
    /// Create a new dialog.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            ..Default::default()
        }
    }

    /// Add a function name.
    pub fn add_function(&mut self, name: impl Into<String>) {
        self.function_names.push(name.into());
    }

    /// Remove a function name.
    pub fn remove_function(&mut self, name: &str) -> bool {
        let len_before = self.function_names.len();
        self.function_names.retain(|n| n != name);
        self.function_names.len() < len_before
    }

    /// Get the number of selected functions.
    pub fn function_count(&self) -> usize {
        self.function_names.len()
    }

    /// Confirm the dialog.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Get the selected function names as a slice.
    pub fn functions(&self) -> &[String] {
        &self.function_names
    }

    /// Clear all selected functions.
    pub fn clear(&mut self) {
        self.function_names.clear();
    }
}

// ============================================================================
// BSimExecutablesSummaryModel
// ============================================================================

/// Summary model for executables in BSim search results.
///
/// Port of `ghidra.features.bsim.gui.search.results.BSimExecutablesSummaryModel`.
///
/// Groups search results by executable and provides summary statistics.
#[derive(Debug, Clone, Default)]
pub struct BSimExecutablesSummaryModel {
    /// Per-executable summary entries.
    pub entries: Vec<ExecutableSummaryEntry>,
    /// Total matches across all executables.
    pub total_matches: usize,
    /// Total unique executables.
    pub total_executables: usize,
}

/// Summary for a single executable in BSim results.
#[derive(Debug, Clone)]
pub struct ExecutableSummaryEntry {
    /// Executable name.
    pub executable_name: String,
    /// Architecture string.
    pub architecture: String,
    /// Compiler name.
    pub compiler: String,
    /// Number of matches from this executable.
    pub match_count: usize,
    /// Average similarity score.
    pub avg_similarity: f64,
    /// Maximum similarity score.
    pub max_similarity: f64,
    /// Whether this entry is selected for display.
    pub selected: bool,
}

impl BSimExecutablesSummaryModel {
    /// Create a new empty summary model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a match result to the summary.
    pub fn add_match(
        &mut self,
        executable_name: &str,
        architecture: &str,
        compiler: &str,
        similarity: f64,
    ) {
        self.total_matches += 1;

        // Find or create entry.
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| e.executable_name == executable_name)
        {
            entry.match_count += 1;
            let n = entry.match_count as f64;
            entry.avg_similarity =
                entry.avg_similarity * (n - 1.0) / n + similarity / n;
            if similarity > entry.max_similarity {
                entry.max_similarity = similarity;
            }
        } else {
            self.total_executables += 1;
            self.entries.push(ExecutableSummaryEntry {
                executable_name: executable_name.to_string(),
                architecture: architecture.to_string(),
                compiler: compiler.to_string(),
                match_count: 1,
                avg_similarity: similarity,
                max_similarity: similarity,
                selected: true,
            });
        }
    }

    /// Get entries sorted by match count (descending).
    pub fn sorted_by_match_count(&self) -> Vec<&ExecutableSummaryEntry> {
        let mut entries: Vec<&ExecutableSummaryEntry> = self.entries.iter().collect();
        entries.sort_by(|a, b| b.match_count.cmp(&a.match_count));
        entries
    }

    /// Get entries sorted by max similarity (descending).
    pub fn sorted_by_similarity(&self) -> Vec<&ExecutableSummaryEntry> {
        let mut entries: Vec<&ExecutableSummaryEntry> = self.entries.iter().collect();
        entries.sort_by(|a, b| {
            b.max_similarity
                .partial_cmp(&a.max_similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        entries
    }

    /// Get only selected entries.
    pub fn selected_entries(&self) -> Vec<&ExecutableSummaryEntry> {
        self.entries.iter().filter(|e| e.selected).collect()
    }

    /// Total matches from selected entries.
    pub fn selected_match_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.selected)
            .map(|e| e.match_count)
            .sum()
    }
}

// ============================================================================
// BSimStatusRenderer
// ============================================================================

/// Renders BSim result status for display.
///
/// Port of `ghidra.features.bsim.gui.search.results.BSimStatusRenderer`.
#[derive(Debug, Clone)]
pub struct BSimStatusRenderer;

impl BSimStatusRenderer {
    /// Get a display icon identifier for a result status.
    pub fn status_icon(status: &super::BSimResultStatus) -> &'static str {
        match status {
            super::BSimResultStatus::Pending => "icon.pending",
            super::BSimResultStatus::Applied => "icon.check",
            super::BSimResultStatus::Ignored => "icon.ignore",
            super::BSimResultStatus::Rejected => "icon.error",
        }
    }

    /// Get a CSS color for a result status.
    pub fn status_color(status: &super::BSimResultStatus) -> &'static str {
        match status {
            super::BSimResultStatus::Pending => "#808080",
            super::BSimResultStatus::Applied => "#008000",
            super::BSimResultStatus::Ignored => "#808080",
            super::BSimResultStatus::Rejected => "#FF0000",
        }
    }

    /// Get a display label for a result status.
    pub fn status_label(status: &super::BSimResultStatus) -> &'static str {
        match status {
            super::BSimResultStatus::Pending => "Pending",
            super::BSimResultStatus::Applied => "Applied",
            super::BSimResultStatus::Ignored => "Ignored",
            super::BSimResultStatus::Rejected => "Rejected",
        }
    }
}

// ============================================================================
// BSimMatchResultsModel
// ============================================================================

/// Model for BSim match results, supporting filtering, sorting, and paging.
///
/// Port of `ghidra.features.bsim.gui.search.results.BSimMatchResultsModel`.
#[derive(Debug, Clone, Default)]
pub struct BSimMatchResultsModel {
    /// All match results.
    results: Vec<super::BSimMatchResult>,
    /// Current page index (0-based).
    pub page: usize,
    /// Results per page.
    pub page_size: usize,
    /// Minimum similarity filter.
    pub min_similarity_filter: Option<f64>,
}

impl BSimMatchResultsModel {
    /// Create a new empty results model.
    pub fn new() -> Self {
        Self {
            page_size: 100,
            ..Default::default()
        }
    }

    /// Add a result.
    pub fn push(&mut self, result: super::BSimMatchResult) {
        self.results.push(result);
    }

    /// Get the total number of results (before filtering).
    pub fn total_count(&self) -> usize {
        self.results.len()
    }

    /// Get filtered results.
    pub fn filtered_results(&self) -> Vec<&super::BSimMatchResult> {
        self.results
            .iter()
            .filter(|r| {
                if let Some(min_sim) = self.min_similarity_filter {
                    r.similarity >= min_sim
                } else {
                    true
                }
            })
            .collect()
    }

    /// Get the current page of filtered results.
    pub fn current_page(&self) -> Vec<&super::BSimMatchResult> {
        let filtered = self.filtered_results();
        let start = self.page * self.page_size;
        filtered
            .into_iter()
            .skip(start)
            .take(self.page_size)
            .collect()
    }

    /// Total number of pages (after filtering).
    pub fn total_pages(&self) -> usize {
        let count = self.filtered_results().len();
        if count == 0 {
            1
        } else {
            (count + self.page_size - 1) / self.page_size
        }
    }

    /// Sort results by similarity (descending).
    pub fn sort_by_similarity(&mut self) {
        self.results.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    /// Sort results by name (ascending).
    pub fn sort_by_name(&mut self) {
        self.results
            .sort_by(|a, b| a.matched_function_name.cmp(&b.matched_function_name));
    }

    /// Get all results.
    pub fn all_results(&self) -> &[super::BSimMatchResult] {
        &self.results
    }

    /// Clear all results.
    pub fn clear(&mut self) {
        self.results.clear();
        self.page = 0;
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_server(url: &str) -> BSimServerInfo {
        BSimServerInfo {
            url: url.to_string(),
            database_name: "test_db".to_string(),
            connection_type: ConnectionType::PostgreSQL,
            use_ssl: false,
            username: None,
        }
    }

    // --- ConnectionPoolStatus tests ---

    #[test]
    fn pool_status_defaults() {
        let status = ConnectionPoolStatus::new(10);
        assert_eq!(status.max_pool_size, 10);
        assert_eq!(status.total_connections(), 0);
        assert!(status.healthy);
    }

    #[test]
    fn pool_status_utilization() {
        let mut status = ConnectionPoolStatus::new(10);
        status.record_connection_created(5.0);
        status.record_connection_acquired();
        assert_eq!(status.active_count, 1);
        assert_eq!(status.idle_count, 0);
        assert!((status.utilization() - 0.1).abs() < 1e-6);
    }

    #[test]
    fn pool_status_release() {
        let mut status = ConnectionPoolStatus::new(10);
        status.record_connection_created(5.0);
        status.record_connection_acquired();
        status.record_connection_released();
        assert_eq!(status.active_count, 0);
        assert_eq!(status.idle_count, 1);
    }

    #[test]
    fn pool_status_errors() {
        let mut status = ConnectionPoolStatus::new(10);
        for _ in 0..11 {
            status.record_error("timeout");
        }
        assert!(!status.healthy);
        assert_eq!(status.total_errors, 11);
    }

    #[test]
    fn pool_status_reset_health() {
        let mut status = ConnectionPoolStatus::new(10);
        status.record_error("fail");
        status.reset_health();
        assert!(status.healthy);
        assert_eq!(status.total_errors, 0);
    }

    // --- BSimServerCache tests ---

    #[test]
    fn server_cache_insert_get() {
        let mut cache = BSimServerCache::new();
        let server = make_server("localhost:5432");
        cache.insert(server);
        assert!(cache.contains("localhost:5432"));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn server_cache_hit_rate() {
        let mut cache = BSimServerCache::new();
        let server = make_server("localhost:5432");
        cache.insert(server);
        cache.get("localhost:5432"); // hit
        cache.get("other:5432"); // miss
        assert!((cache.hit_rate() - 0.5).abs() < 1e-6);
    }

    #[test]
    fn server_cache_eviction() {
        let mut cache = BSimServerCache::with_config(2, 3600);
        cache.insert(make_server("a:5432"));
        cache.insert(make_server("b:5432"));
        cache.insert(make_server("c:5432"));
        assert_eq!(cache.len(), 2);
        // "a" should have been evicted as the oldest.
        assert!(!cache.contains("a:5432"));
    }

    #[test]
    fn server_cache_invalidate() {
        let mut cache = BSimServerCache::new();
        cache.insert(make_server("localhost:5432"));
        cache.invalidate("localhost:5432");
        assert!(!cache.contains("localhost:5432"));
        assert_eq!(cache.len(), 1); // still in the map but invalid
    }

    #[test]
    fn server_cache_clear() {
        let mut cache = BSimServerCache::new();
        cache.insert(make_server("a:5432"));
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn server_cache_cached_urls() {
        let mut cache = BSimServerCache::new();
        cache.insert(make_server("a:5432"));
        cache.insert(make_server("b:5432"));
        let urls = cache.cached_urls();
        assert_eq!(urls.len(), 2);
    }

    // --- BSimServerManager tests ---

    #[test]
    fn server_manager_add_remove() {
        let mut mgr = BSimServerManager::new();
        mgr.add_server(make_server("a:5432"));
        mgr.add_server(make_server("b:5432"));
        assert_eq!(mgr.known_servers().len(), 2);
        mgr.remove_server("a:5432");
        assert_eq!(mgr.known_servers().len(), 1);
    }

    #[test]
    fn server_manager_default() {
        let mut mgr = BSimServerManager::new();
        mgr.add_server(make_server("a:5432"));
        mgr.set_default_server("a:5432");
        assert!(mgr.default_server().is_some());
    }

    // --- BSimExecutablesSummaryModel tests ---

    #[test]
    fn summary_model_add_match() {
        let mut model = BSimExecutablesSummaryModel::new();
        model.add_match("libc.so", "x86:LE:64", "gcc", 0.95);
        model.add_match("libc.so", "x86:LE:64", "gcc", 0.80);
        model.add_match("libm.so", "x86:LE:64", "gcc", 0.90);
        assert_eq!(model.total_matches, 3);
        assert_eq!(model.total_executables, 2);
    }

    #[test]
    fn summary_model_sorted_by_match_count() {
        let mut model = BSimExecutablesSummaryModel::new();
        model.add_match("a", "x86", "gcc", 0.5);
        model.add_match("b", "x86", "gcc", 0.5);
        model.add_match("b", "x86", "gcc", 0.5);
        let sorted = model.sorted_by_match_count();
        assert_eq!(sorted[0].executable_name, "b");
        assert_eq!(sorted[0].match_count, 2);
    }

    #[test]
    fn summary_model_selected_entries() {
        let mut model = BSimExecutablesSummaryModel::new();
        model.add_match("a", "x86", "gcc", 0.5);
        model.add_match("b", "x86", "gcc", 0.5);
        model.entries[0].selected = false;
        assert_eq!(model.selected_entries().len(), 1);
        assert_eq!(model.selected_match_count(), 1);
    }

    // --- BSimStatusRenderer tests ---

    #[test]
    fn status_renderer_labels() {
        assert_eq!(
            BSimStatusRenderer::status_label(&crate::bsim::gui::BSimResultStatus::Pending),
            "Pending"
        );
        assert_eq!(
            BSimStatusRenderer::status_label(&crate::bsim::gui::BSimResultStatus::Applied),
            "Applied"
        );
    }

    #[test]
    fn status_renderer_colors() {
        assert_eq!(
            BSimStatusRenderer::status_color(&crate::bsim::gui::BSimResultStatus::Applied),
            "#008000"
        );
    }

    // --- BSimMatchResultsModel tests ---

    #[test]
    fn match_results_model_paging() {
        let mut model = BSimMatchResultsModel::new();
        model.page_size = 2;
        for i in 0..5 {
            model.push(crate::bsim::gui::BSimMatchResult {
                query_hash: [0u8; 32],
                matched_function_name: format!("fn_{}", i),
                matched_address: format!("0x{:x}", i * 0x1000),
                similarity: 0.5 + i as f64 * 0.1,
                confidence: 0.8,
                status: crate::bsim::gui::BSimResultStatus::Pending,
            });
        }
        assert_eq!(model.total_count(), 5);
        assert_eq!(model.total_pages(), 3); // ceil(5/2)
        assert_eq!(model.current_page().len(), 2); // page 0

        model.page = 2;
        assert_eq!(model.current_page().len(), 1); // last page has 1
    }

    #[test]
    fn match_results_model_filter() {
        let mut model = BSimMatchResultsModel::new();
        model.push(crate::bsim::gui::BSimMatchResult {
            query_hash: [0u8; 32],
            matched_function_name: "a".to_string(),
            matched_address: "0x1000".to_string(),
            similarity: 0.9,
            confidence: 0.8,
            status: crate::bsim::gui::BSimResultStatus::Pending,
        });
        model.push(crate::bsim::gui::BSimMatchResult {
            query_hash: [0u8; 32],
            matched_function_name: "b".to_string(),
            matched_address: "0x2000".to_string(),
            similarity: 0.3,
            confidence: 0.5,
            status: crate::bsim::gui::BSimResultStatus::Pending,
        });

        model.min_similarity_filter = Some(0.5);
        assert_eq!(model.filtered_results().len(), 1);
    }

    #[test]
    fn match_results_model_sort() {
        let mut model = BSimMatchResultsModel::new();
        model.push(crate::bsim::gui::BSimMatchResult {
            query_hash: [0u8; 32],
            matched_function_name: "z".to_string(),
            matched_address: "0x1000".to_string(),
            similarity: 0.5,
            confidence: 0.8,
            status: crate::bsim::gui::BSimResultStatus::Pending,
        });
        model.push(crate::bsim::gui::BSimMatchResult {
            query_hash: [0u8; 32],
            matched_function_name: "a".to_string(),
            matched_address: "0x2000".to_string(),
            similarity: 0.9,
            confidence: 0.8,
            status: crate::bsim::gui::BSimResultStatus::Pending,
        });

        model.sort_by_similarity();
        assert_eq!(model.all_results()[0].similarity, 0.9);

        model.sort_by_name();
        assert_eq!(model.all_results()[0].matched_function_name, "a");
    }

    // --- BSimServerManagerListener tests ---

    #[test]
    fn null_server_manager_listener() {
        let listener = NullServerManagerListener;
        let server = make_server("localhost:5432");
        listener.server_added(&server);
        listener.server_removed("localhost:5432");
        listener.default_server_changed(Some("localhost:5432"));
    }

    // --- BSimServerTableModel tests ---

    #[test]
    fn server_table_model_creation() {
        let model = BSimServerTableModel::new();
        assert_eq!(model.column_count(), 4);
        assert_eq!(model.row_count(), 0);
    }

    #[test]
    fn server_table_model_add_remove() {
        let mut model = BSimServerTableModel::new();
        model.add_entry(make_server("a:5432"));
        model.add_entry(make_server("b:5432"));
        assert_eq!(model.row_count(), 2);

        model.remove_entry("a:5432");
        assert_eq!(model.row_count(), 1);
        assert!(!model.remove_entry("nonexistent"));
    }

    #[test]
    fn server_table_model_values() {
        let mut model = BSimServerTableModel::new();
        model.add_entry(make_server("localhost:5432"));
        assert_eq!(model.get_value_at(0, 0), Some("localhost:5432".to_string()));
        assert_eq!(model.get_value_at(0, 1), Some("test_db".to_string()));
        assert_eq!(model.get_value_at(0, 3), Some("No".to_string()));
        assert!(model.get_value_at(0, 99).is_none());
        assert!(model.get_value_at(99, 0).is_none());
    }

    #[test]
    fn server_table_model_clear() {
        let mut model = BSimServerTableModel::new();
        model.add_entry(make_server("a:5432"));
        model.clear();
        assert_eq!(model.row_count(), 0);
    }

    // --- CreateBsimServerInfoDialog tests ---

    #[test]
    fn create_dialog_defaults() {
        let dialog = CreateBsimServerInfoDialog::new();
        assert!(dialog.url.is_empty());
        assert!(!dialog.confirmed);
        assert!(!dialog.is_valid());
    }

    #[test]
    fn create_dialog_builder() {
        let dialog = CreateBsimServerInfoDialog::new()
            .with_url("localhost:5432")
            .with_database("bsim_db")
            .with_connection_type(ConnectionType::Elastic);
        assert_eq!(dialog.url, "localhost:5432");
        assert_eq!(dialog.database_name, "bsim_db");
        assert!(dialog.is_valid());
    }

    #[test]
    fn create_dialog_confirm() {
        let mut dialog = CreateBsimServerInfoDialog::new()
            .with_url("localhost:5432")
            .with_database("bsim");
        dialog.confirm();
        assert!(dialog.confirmed);
    }

    #[test]
    fn create_dialog_to_server_info() {
        let dialog = CreateBsimServerInfoDialog::new()
            .with_url("localhost:5432")
            .with_database("bsim");
        let info = dialog.to_server_info();
        assert_eq!(info.url, "localhost:5432");
        assert_eq!(info.database_name, "bsim");
        assert!(info.username.is_none());
    }

    #[test]
    fn create_dialog_to_server_info_with_username() {
        let mut dialog = CreateBsimServerInfoDialog::new()
            .with_url("localhost:5432")
            .with_database("bsim");
        dialog.username = "admin".to_string();
        let info = dialog.to_server_info();
        assert_eq!(info.username, Some("admin".to_string()));
    }

    // --- SelectedFunctionsTableDialog tests ---

    #[test]
    fn selected_functions_dialog() {
        let mut dialog = SelectedFunctionsTableDialog::new("Select Functions");
        assert_eq!(dialog.title, "Select Functions");
        assert_eq!(dialog.function_count(), 0);

        dialog.add_function("main");
        dialog.add_function("foo");
        assert_eq!(dialog.function_count(), 2);
    }

    #[test]
    fn selected_functions_dialog_remove() {
        let mut dialog = SelectedFunctionsTableDialog::new("test");
        dialog.add_function("main");
        dialog.add_function("foo");
        dialog.remove_function("main");
        assert_eq!(dialog.function_count(), 1);
        assert!(!dialog.remove_function("nonexistent"));
    }

    #[test]
    fn selected_functions_dialog_confirm() {
        let mut dialog = SelectedFunctionsTableDialog::new("test");
        assert!(!dialog.confirmed);
        dialog.confirm();
        assert!(dialog.confirmed);
    }

    #[test]
    fn selected_functions_dialog_clear() {
        let mut dialog = SelectedFunctionsTableDialog::new("test");
        dialog.add_function("f1");
        dialog.add_function("f2");
        dialog.clear();
        assert!(dialog.functions().is_empty());
    }

    #[test]
    fn selected_functions_dialog_functions() {
        let mut dialog = SelectedFunctionsTableDialog::new("test");
        dialog.add_function("main");
        dialog.add_function("foo");
        let funcs = dialog.functions();
        assert_eq!(funcs.len(), 2);
        assert_eq!(funcs[0], "main");
        assert_eq!(funcs[1], "foo");
    }
}
