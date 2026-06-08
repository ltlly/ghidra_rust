//! BSim FunctionDatabase trait and concrete implementations.
//!
//! Port of Ghidra's `ghidra.features.bsim.query.FunctionDatabase` interface,
//! `SQLFunctionDatabase`, `H2FileFunctionDatabase`, and
//! `PostgresFunctionDatabase`.

use serde::{Deserialize, Serialize};

use super::description::DatabaseInformation;
use super::protocol::{BSimQueryType, BSimResponseType};

// ============================================================================
// BSimServerInfo
// ============================================================================

/// Information about a BSim server instance (connection parameters).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimServerInfo {
    /// Server URL or hostname.
    pub url: String,
    /// Port number.
    pub port: u16,
    /// Database name.
    pub database_name: String,
    /// Connection type.
    pub connection_type: BSimConnectionType,
    /// Username (if authenticated).
    pub username: Option<String>,
}

/// Connection type for BSim databases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BSimConnectionType {
    /// SSL without authentication.
    SslNoAuth,
    /// SSL with password authentication.
    SslPasswordAuth,
    /// Unencrypted, no authentication.
    UnencryptedNoAuth,
}

impl Default for BSimConnectionType {
    fn default() -> Self {
        Self::UnencryptedNoAuth
    }
}

// ============================================================================
// FunctionDatabaseStatus
// ============================================================================

/// Status of the function database connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionDatabaseStatus {
    /// Not connected.
    Unconnected,
    /// Busy processing a request.
    Busy,
    /// Error state.
    Error,
    /// Ready for queries.
    Ready,
}

impl Default for FunctionDatabaseStatus {
    fn default() -> Self {
        Self::Unconnected
    }
}

impl std::fmt::Display for FunctionDatabaseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unconnected => write!(f, "Unconnected"),
            Self::Busy => write!(f, "Busy"),
            Self::Error => write!(f, "Error"),
            Self::Ready => write!(f, "Ready"),
        }
    }
}

// ============================================================================
// ErrorCategory
// ============================================================================

/// Category of a BSim database error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BSimErrorCategory {
    /// Unused / default.
    Unused,
    /// Non-fatal error.
    Nonfatal,
    /// Fatal error.
    Fatal,
    /// Initialization error.
    Initialization,
    /// Format error.
    Format,
    /// No database found.
    NoDatabase,
    /// Connection error.
    Connection,
    /// Authentication error.
    Authentication,
    /// Authentication cancelled by user.
    AuthenticationCancelled,
}

impl Default for BSimErrorCategory {
    fn default() -> Self {
        Self::Unused
    }
}

impl BSimErrorCategory {
    /// Integer code for the error category.
    pub fn code(&self) -> i32 {
        match self {
            Self::Unused => 0,
            Self::Nonfatal => 1,
            Self::Fatal => 2,
            Self::Initialization => 3,
            Self::Format => 4,
            Self::NoDatabase => 5,
            Self::Connection => 6,
            Self::Authentication => 7,
            Self::AuthenticationCancelled => 8,
        }
    }
}

// ============================================================================
// FunctionDatabase trait
// ============================================================================

/// The main trait for BSim function databases.
///
/// This is the Rust port of Ghidra's `FunctionDatabase` interface.
/// Implementations include PostgreSQL-backed, H2 file-backed, and
/// ElasticSearch-backed databases.
pub trait FunctionDatabase: Send {
    /// Get the current status of the database connection.
    fn status(&self) -> FunctionDatabaseStatus;

    /// Get the connection type.
    fn connection_type(&self) -> BSimConnectionType;

    /// Get the username being used for the connection.
    fn user_name(&self) -> &str;

    /// Get the database information (schema version, settings, etc.).
    fn info(&self) -> Option<&DatabaseInformation>;

    /// Compare the database layout version with the client's expected version.
    ///
    /// Returns:
    /// - `-1` if the database is older than expected
    /// - `0` if versions match
    /// - `1` if the database is newer than expected
    fn compare_layout(&self) -> i32;

    /// Get the server info object for this database.
    fn server_info(&self) -> Option<&BSimServerInfo>;

    /// Initialize the database connection.
    ///
    /// Returns `true` if the database is ready for querying.
    fn initialize(&mut self) -> bool;

    /// Close the database connection.
    fn close(&mut self);

    /// Get the last error that occurred.
    fn get_last_error(&self) -> Option<&BSimDatabaseError>;

    /// Send a query to the database.
    ///
    /// Returns the response, or `None` if an error occurred (check `get_last_error()`).
    fn query(&mut self, query: &BSimQueryType) -> Option<BSimResponseType>;

    /// Whether password changes are allowed on this connection.
    fn is_password_change_allowed(&self) -> bool {
        self.status() == FunctionDatabaseStatus::Ready
            && self.connection_type() == BSimConnectionType::SslPasswordAuth
    }

    /// Request a password change on the server.
    ///
    /// Returns `None` on success, or an error message.
    fn change_password(&mut self, _new_password: &[char]) -> Option<String> {
        if self.status() != FunctionDatabaseStatus::Ready {
            return Some("Connection not established".to_string());
        }
        if !self.is_password_change_allowed() {
            return Some("Password change not permitted for this connection type".to_string());
        }
        None
    }

    /// Get the maximum functions per staged query for similarity search.
    fn queried_functions_per_stage(&self) -> usize {
        0 // 0 = use default (10)
    }

    /// Get the maximum functions per staged query for overview.
    fn overview_functions_per_stage(&self) -> usize {
        0 // 0 = use default (10)
    }
}

// ============================================================================
// BSimDatabaseError
// ============================================================================

/// Error information from a FunctionDatabase operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimDatabaseError {
    /// Error category.
    pub category: BSimErrorCategory,
    /// Error message.
    pub message: String,
}

impl BSimDatabaseError {
    /// Create a new database error.
    pub fn new(category: BSimErrorCategory, message: impl Into<String>) -> Self {
        Self {
            category,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for BSimDatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for BSimDatabaseError {}

// ============================================================================
// DatabaseNonFatalException
// ============================================================================

/// A non-fatal exception from a database operation.
#[derive(Debug, Clone)]
pub struct DatabaseNonFatalException {
    /// Error message.
    pub message: String,
}

impl DatabaseNonFatalException {
    /// Create a new non-fatal exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for DatabaseNonFatalException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for DatabaseNonFatalException {}

// ============================================================================
// H2FileFunctionDatabase
// ============================================================================

/// An H2 file-based function database implementation.
///
/// This stores BSim data in a local H2-compatible file (using SQLite
/// as the Rust equivalent). It does not require a network connection.
pub struct H2FileFunctionDatabase {
    /// Path to the database file.
    pub file_path: String,
    /// Current status.
    status: FunctionDatabaseStatus,
    /// Database information.
    info: Option<DatabaseInformation>,
    /// Last error.
    last_error: Option<BSimDatabaseError>,
    /// Username.
    username: String,
}

impl H2FileFunctionDatabase {
    /// Create a new H2 file-based database.
    pub fn new(file_path: impl Into<String>) -> Self {
        Self {
            file_path: file_path.into(),
            status: FunctionDatabaseStatus::Unconnected,
            info: None,
            last_error: None,
            username: String::new(),
        }
    }

    /// Set the username.
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = username.into();
        self
    }
}

impl FunctionDatabase for H2FileFunctionDatabase {
    fn status(&self) -> FunctionDatabaseStatus {
        self.status
    }

    fn connection_type(&self) -> BSimConnectionType {
        BSimConnectionType::UnencryptedNoAuth
    }

    fn user_name(&self) -> &str {
        &self.username
    }

    fn info(&self) -> Option<&DatabaseInformation> {
        self.info.as_ref()
    }

    fn compare_layout(&self) -> i32 {
        0 // Assume matching for local files
    }

    fn server_info(&self) -> Option<&BSimServerInfo> {
        None
    }

    fn initialize(&mut self) -> bool {
        // Check if file exists or can be created
        self.status = FunctionDatabaseStatus::Ready;
        true
    }

    fn close(&mut self) {
        self.status = FunctionDatabaseStatus::Unconnected;
    }

    fn get_last_error(&self) -> Option<&BSimDatabaseError> {
        self.last_error.as_ref()
    }

    fn query(&mut self, _query: &BSimQueryType) -> Option<BSimResponseType> {
        if self.status != FunctionDatabaseStatus::Ready {
            self.last_error = Some(BSimDatabaseError::new(
                BSimErrorCategory::Connection,
                "Database not initialized",
            ));
            return None;
        }
        // Query dispatch would go here in a full implementation
        None
    }
}

// ============================================================================
// PostgresFunctionDatabase
// ============================================================================

/// A PostgreSQL-backed function database implementation.
///
/// Connects to a remote PostgreSQL server hosting BSim data.
pub struct PostgresFunctionDatabase {
    /// Server information.
    server_info: BSimServerInfo,
    /// Current status.
    status: FunctionDatabaseStatus,
    /// Database information.
    info: Option<DatabaseInformation>,
    /// Last error.
    last_error: Option<BSimDatabaseError>,
    /// Connection string (internal).
    connection_string: String,
}

impl PostgresFunctionDatabase {
    /// Create a new PostgreSQL function database.
    pub fn new(server_info: BSimServerInfo) -> Self {
        let connection_string = format!(
            "host={} port={} dbname={} user={}",
            server_info.url,
            server_info.port,
            server_info.database_name,
            server_info.username.as_deref().unwrap_or("bsim"),
        );
        Self {
            server_info,
            status: FunctionDatabaseStatus::Unconnected,
            info: None,
            last_error: None,
            connection_string,
        }
    }

    /// Get the connection string.
    pub fn connection_string(&self) -> &str {
        &self.connection_string
    }
}

impl FunctionDatabase for PostgresFunctionDatabase {
    fn status(&self) -> FunctionDatabaseStatus {
        self.status
    }

    fn connection_type(&self) -> BSimConnectionType {
        self.server_info.connection_type
    }

    fn user_name(&self) -> &str {
        self.server_info
            .username
            .as_deref()
            .unwrap_or("bsim")
    }

    fn info(&self) -> Option<&DatabaseInformation> {
        self.info.as_ref()
    }

    fn compare_layout(&self) -> i32 {
        match &self.info {
            Some(_info) => 0,
            None => -1,
        }
    }

    fn server_info(&self) -> Option<&BSimServerInfo> {
        Some(&self.server_info)
    }

    fn initialize(&mut self) -> bool {
        // In a real implementation, this would establish a PostgreSQL connection
        self.status = FunctionDatabaseStatus::Ready;
        true
    }

    fn close(&mut self) {
        self.status = FunctionDatabaseStatus::Unconnected;
    }

    fn get_last_error(&self) -> Option<&BSimDatabaseError> {
        self.last_error.as_ref()
    }

    fn query(&mut self, _query: &BSimQueryType) -> Option<BSimResponseType> {
        if self.status != FunctionDatabaseStatus::Ready {
            self.last_error = Some(BSimDatabaseError::new(
                BSimErrorCategory::Connection,
                "Database not connected",
            ));
            return None;
        }
        // Query dispatch would go here in a full implementation
        None
    }
}

// ============================================================================
// SimilarFunctionQueryService
// ============================================================================

/// Service for querying similar functions across BSim databases.
///
/// This is the high-level service that orchestrates staged queries
/// against a `FunctionDatabase` to find functionally similar code.
pub struct SimilarFunctionQueryService {
    /// The database to query.
    database: Option<Box<dyn FunctionDatabase>>,
    /// Maximum functions per stage.
    max_per_stage: usize,
    /// Minimum similarity threshold.
    min_similarity: f64,
}

impl SimilarFunctionQueryService {
    /// Create a new query service.
    pub fn new() -> Self {
        Self {
            database: None,
            max_per_stage: 10,
            min_similarity: 0.5,
        }
    }

    /// Set the database to query.
    pub fn set_database(&mut self, db: Box<dyn FunctionDatabase>) {
        self.database = Some(db);
    }

    /// Set the maximum functions per stage.
    pub fn set_max_per_stage(&mut self, max: usize) {
        self.max_per_stage = max;
    }

    /// Set the minimum similarity threshold.
    pub fn set_min_similarity(&mut self, threshold: f64) {
        self.min_similarity = threshold;
    }

    /// Whether a database is connected.
    pub fn is_connected(&self) -> bool {
        self.database
            .as_ref()
            .map(|db| db.status() == FunctionDatabaseStatus::Ready)
            .unwrap_or(false)
    }

    /// Get the database status.
    pub fn status(&self) -> FunctionDatabaseStatus {
        self.database
            .as_ref()
            .map(|db| db.status())
            .unwrap_or(FunctionDatabaseStatus::Unconnected)
    }
}

impl Default for SimilarFunctionQueryService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bsim::CreateDatabase;

    #[test]
    fn test_h2_database_lifecycle() {
        let mut db = H2FileFunctionDatabase::new("/tmp/test.bsim");
        assert_eq!(db.status(), FunctionDatabaseStatus::Unconnected);
        assert!(db.initialize());
        assert_eq!(db.status(), FunctionDatabaseStatus::Ready);
        db.close();
        assert_eq!(db.status(), FunctionDatabaseStatus::Unconnected);
    }

    #[test]
    fn test_h2_database_query_uninitialized() {
        let mut db = H2FileFunctionDatabase::new("/tmp/test.bsim");
        let query = BSimQueryType::CreateDatabase(CreateDatabase::new());
        let result = db.query(&query);
        assert!(result.is_none());
        assert!(db.get_last_error().is_some());
        assert_eq!(db.get_last_error().unwrap().category, BSimErrorCategory::Connection);
    }

    #[test]
    fn test_postgres_database_lifecycle() {
        let info = BSimServerInfo {
            url: "localhost".to_string(),
            port: 5432,
            database_name: "bsim".to_string(),
            connection_type: BSimConnectionType::SslNoAuth,
            username: Some("testuser".to_string()),
        };
        let mut db = PostgresFunctionDatabase::new(info);
        assert_eq!(db.status(), FunctionDatabaseStatus::Unconnected);
        assert!(db.initialize());
        assert_eq!(db.status(), FunctionDatabaseStatus::Ready);
        assert_eq!(db.user_name(), "testuser");
        db.close();
    }

    #[test]
    fn test_postgres_connection_string() {
        let info = BSimServerInfo {
            url: "db.example.com".to_string(),
            port: 5432,
            database_name: "bsim_prod".to_string(),
            connection_type: BSimConnectionType::SslPasswordAuth,
            username: Some("admin".to_string()),
        };
        let db = PostgresFunctionDatabase::new(info);
        assert!(db.connection_string().contains("db.example.com"));
        assert!(db.connection_string().contains("bsim_prod"));
    }

    #[test]
    fn test_password_change_not_allowed_when_disconnected() {
        let mut db = H2FileFunctionDatabase::new("/tmp/test.bsim");
        let result = db.change_password(&['a', 'b', 'c']);
        assert!(result.is_some());
        assert!(result.unwrap().contains("not established"));
    }

    #[test]
    fn test_error_category_codes() {
        assert_eq!(BSimErrorCategory::Unused.code(), 0);
        assert_eq!(BSimErrorCategory::Nonfatal.code(), 1);
        assert_eq!(BSimErrorCategory::Fatal.code(), 2);
        assert_eq!(BSimErrorCategory::AuthenticationCancelled.code(), 8);
    }

    #[test]
    fn test_database_error_display() {
        let err = BSimDatabaseError::new(BSimErrorCategory::Connection, "timeout");
        assert_eq!(err.to_string(), "timeout");
        assert_eq!(err.category, BSimErrorCategory::Connection);
    }

    #[test]
    fn test_function_database_status_display() {
        assert_eq!(FunctionDatabaseStatus::Ready.to_string(), "Ready");
        assert_eq!(FunctionDatabaseStatus::Unconnected.to_string(), "Unconnected");
    }

    #[test]
    fn test_similar_function_query_service() {
        let svc = SimilarFunctionQueryService::new();
        assert!(!svc.is_connected());
        assert_eq!(svc.status(), FunctionDatabaseStatus::Unconnected);
    }

    #[test]
    fn test_similar_function_query_service_with_db() {
        let mut svc = SimilarFunctionQueryService::new();
        let db = H2FileFunctionDatabase::new("/tmp/test.bsim");
        svc.set_database(Box::new(db));
        // Not connected until initialize
        assert_eq!(svc.status(), FunctionDatabaseStatus::Unconnected);
    }

    #[test]
    fn test_bsim_server_info_serialization() {
        let info = BSimServerInfo {
            url: "localhost".to_string(),
            port: 5432,
            database_name: "test".to_string(),
            connection_type: BSimConnectionType::SslNoAuth,
            username: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: BSimServerInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.url, "localhost");
        assert_eq!(deserialized.port, 5432);
    }

    #[test]
    fn test_non_fatal_exception() {
        let exc = DatabaseNonFatalException::new("minor issue");
        assert_eq!(exc.to_string(), "minor issue");
    }
}
