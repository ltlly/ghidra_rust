//! BSim GUI components: filters, overview, search dialogs.
//!
//! Ports `ghidra.features.bsim.gui` and sub-packages.

pub mod filters;
pub mod filter_types;
pub mod overview;
pub mod search_dialog;
pub mod search_results;

/// BSim search settings.
#[derive(Debug, Clone)]
pub struct BSimSearchSettings {
    /// Minimum similarity threshold (0.0 ..= 1.0).
    pub min_similarity: f64,
    /// Maximum number of results.
    pub max_results: usize,
    /// Whether to search across all executables.
    pub search_all_executables: bool,
    /// Executable names to restrict the search to.
    pub target_executables: Vec<String>,
}

impl Default for BSimSearchSettings {
    fn default() -> Self {
        Self {
            min_similarity: 0.7,
            max_results: 100,
            search_all_executables: true,
            target_executables: Vec::new(),
        }
    }
}

impl BSimSearchSettings {
    /// Create settings with the given minimum similarity.
    pub fn with_similarity(min_similarity: f64) -> Self {
        Self {
            min_similarity,
            ..Default::default()
        }
    }

    /// Create settings with the given max results.
    pub fn with_max_results(mut self, max_results: usize) -> Self {
        self.max_results = max_results;
        self
    }
}

/// BSim match result for a single function.
#[derive(Debug, Clone)]
pub struct BSimMatchResult {
    /// The source function signature hash.
    pub query_hash: [u8; 32],
    /// The matching function's name.
    pub matched_function_name: String,
    /// The matching function's entry point address (as string).
    pub matched_address: String,
    /// Similarity score.
    pub similarity: f64,
    /// Confidence score.
    pub confidence: f64,
    /// Status of this result (applied, ignored, etc.).
    pub status: BSimResultStatus,
}

/// Status of a BSim match result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BSimResultStatus {
    /// Not yet acted upon.
    Pending,
    /// The result was applied (name/namespace transferred).
    Applied,
    /// The result was ignored by the user.
    Ignored,
    /// The result was rejected (low quality, wrong match, etc.).
    Rejected,
}

impl Default for BSimResultStatus {
    fn default() -> Self {
        Self::Pending
    }
}

/// A BSim server connection info.
#[derive(Debug, Clone)]
pub struct BSimServerInfo {
    /// Server URL.
    pub url: String,
    /// Database name.
    pub database_name: String,
    /// Connection type.
    pub connection_type: ConnectionType,
    /// Whether to use SSL.
    pub use_ssl: bool,
    /// Username (if authenticated).
    pub username: Option<String>,
}

/// Connection type for BSim servers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// PostgreSQL connection.
    PostgreSQL,
    /// ElasticSearch connection.
    Elastic,
    /// File-based database.
    File,
}

impl Default for ConnectionType {
    fn default() -> Self {
        Self::PostgreSQL
    }
}

/// A BSim executable overview row.
#[derive(Debug, Clone)]
pub struct BSimOverviewRow {
    /// Executable name.
    pub name: String,
    /// Architecture.
    pub architecture: String,
    /// Compiler.
    pub compiler: String,
    /// Number of functions.
    pub function_count: usize,
    /// MD5 hash.
    pub md5: String,
    /// Date added.
    pub date_added: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_settings_defaults() {
        let s = BSimSearchSettings::default();
        assert_eq!(s.min_similarity, 0.7);
        assert_eq!(s.max_results, 100);
        assert!(s.search_all_executables);
    }

    #[test]
    fn search_settings_builder() {
        let s = BSimSearchSettings::with_similarity(0.9).with_max_results(10);
        assert_eq!(s.min_similarity, 0.9);
        assert_eq!(s.max_results, 10);
    }

    #[test]
    fn match_result_status() {
        let mut r = BSimMatchResult {
            query_hash: [0u8; 32],
            matched_function_name: "malloc".to_string(),
            matched_address: "0x1000".to_string(),
            similarity: 0.95,
            confidence: 0.85,
            status: BSimResultStatus::Pending,
        };
        assert_eq!(r.status, BSimResultStatus::Pending);
        r.status = BSimResultStatus::Applied;
        assert_eq!(r.status, BSimResultStatus::Applied);
    }

    #[test]
    fn server_info() {
        let info = BSimServerInfo {
            url: "localhost:5432".to_string(),
            database_name: "test_bsim".to_string(),
            connection_type: ConnectionType::PostgreSQL,
            use_ssl: false,
            username: Some("admin".to_string()),
        };
        assert_eq!(info.connection_type, ConnectionType::PostgreSQL);
    }

    #[test]
    fn overview_row() {
        let row = BSimOverviewRow {
            name: "libc.so".to_string(),
            architecture: "x86:LE:64:default".to_string(),
            compiler: "gcc".to_string(),
            function_count: 1500,
            md5: "abc123".to_string(),
            date_added: "2024-01-01".to_string(),
        };
        assert_eq!(row.function_count, 1500);
    }
}
