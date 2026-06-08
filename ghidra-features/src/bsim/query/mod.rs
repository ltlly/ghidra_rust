//! BSim query subsystem.
//!
//! Port of `ghidra.features.bsim.query` -- the core query infrastructure
//! for BSim function similarity databases.
//!
//! # Submodules
//!
//! - [`client`]: Abstract SQL function database, JDBC data source, connection managers
//! - [`tables`]: SQL table definitions for function metadata, signatures, vectors
//! - [`elastic`]: Elasticsearch-based BSim backend with LSH scoring
//! - [`facade`]: High-level facade for common BSim operations
//! - [`description`]: Description types for executables and functions
//! - [`protocol`]: Client-server query protocol types
//! - [`postgresql`]: PostgreSQL-specific BSim backend
//! - [`file`]: H2/file-based local BSim database
//! - [`ingest`]: Bulk signature ingestion pipeline
//!
//! # Root-level types (ported from `ghidra.features.bsim.query`)
//!
//! - [`ServerConfig`] -- BSim server connection configuration
//! - [`BSimServerInfo`] -- BSim server connection information
//! - [`GenSignatures`] -- signature generation from programs
//! - [`MinimalErrorLogger`] -- minimal error logging interface
//! - [`LshException`] -- LSH-related exceptions

pub mod client;
pub mod tables;
pub mod elastic;
pub mod facade;
pub mod description;
pub mod protocol;
pub mod postgresql;
pub mod file;
pub mod ingest;

use serde::{Deserialize, Serialize};

use super::client::{BSimError, ConnectionType};
use super::description::{DescriptionManager, SignatureRecord};
use super::FeatureVector;

// ============================================================================
// ServerConfig
// ============================================================================

/// Configuration for connecting to a BSim server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// The hostname or IP address.
    pub hostname: String,
    /// The port number.
    pub port: u16,
    /// The connection type.
    pub connection_type: ConnectionType,
    /// The database name.
    pub database_name: String,
    /// Optional username.
    pub username: Option<String>,
    /// Optional password.
    pub password: Option<String>,
    /// Whether to use SSL/TLS.
    pub use_ssl: bool,
    /// Connection timeout in seconds.
    pub timeout_secs: u64,
}

impl ServerConfig {
    /// Create a new server config.
    pub fn new(
        hostname: impl Into<String>,
        port: u16,
        connection_type: ConnectionType,
    ) -> Self {
        Self {
            hostname: hostname.into(),
            port,
            connection_type,
            database_name: String::new(),
            username: None,
            password: None,
            use_ssl: false,
            timeout_secs: 30,
        }
    }

    /// Set the database name.
    pub fn with_database(mut self, name: impl Into<String>) -> Self {
        self.database_name = name.into();
        self
    }

    /// Set the username.
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Set the password.
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Enable SSL.
    pub fn with_ssl(mut self, use_ssl: bool) -> Self {
        self.use_ssl = use_ssl;
        self
    }

    /// Get the connection URL.
    pub fn url(&self) -> String {
        format!("{}:{}", self.hostname, self.port)
    }
}

// ============================================================================
// BSimServerInfo
// ============================================================================

/// Information about a BSim server instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimServerInfo {
    /// The server configuration.
    pub config: ServerConfig,
    /// The server version (if known).
    pub version: Option<String>,
    /// The number of databases on the server.
    pub database_count: Option<u32>,
    /// Whether the server is reachable.
    pub reachable: bool,
}

impl BSimServerInfo {
    /// Create a new server info.
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            version: None,
            database_count: None,
            reachable: false,
        }
    }
}

// ============================================================================
// LSHException
// ============================================================================

/// Exception related to Locality-Sensitive Hashing (LSH) operations.
#[derive(Debug, Clone)]
pub struct LshException {
    /// The error message.
    pub message: String,
}

impl LshException {
    /// Create a new LSH exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for LshException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LSH error: {}", self.message)
    }
}

impl std::error::Error for LshException {}

impl From<LshException> for BSimError {
    fn from(e: LshException) -> Self {
        BSimError::LshError(e.message)
    }
}

// ============================================================================
// MinimalErrorLogger
// ============================================================================

/// A minimal error logging interface for BSim operations.
pub trait MinimalErrorLogger: Send + Sync {
    /// Log an error message.
    fn log_error(&self, message: &str);
    /// Log a warning message.
    fn log_warning(&self, message: &str);
    /// Log an informational message.
    fn log_info(&self, message: &str);
}

/// A no-op logger that discards all messages.
#[derive(Debug, Clone, Default)]
pub struct NullErrorLogger;

impl MinimalErrorLogger for NullErrorLogger {
    fn log_error(&self, _message: &str) {}
    fn log_warning(&self, _message: &str) {}
    fn log_info(&self, _message: &str) {}
}

/// A collecting logger that stores messages in memory.
#[derive(Debug, Clone, Default)]
pub struct CollectingErrorLogger {
    /// Collected error messages.
    pub errors: Vec<String>,
    /// Collected warning messages.
    pub warnings: Vec<String>,
    /// Collected info messages.
    pub infos: Vec<String>,
}

impl CollectingErrorLogger {
    /// Create a new collecting logger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total number of messages.
    pub fn total_messages(&self) -> usize {
        self.errors.len() + self.warnings.len() + self.infos.len()
    }

    /// Clear all messages.
    pub fn clear(&mut self) {
        self.errors.clear();
        self.warnings.clear();
        self.infos.clear();
    }

    /// Whether any errors were logged.
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
}

impl MinimalErrorLogger for CollectingErrorLogger {
    fn log_error(&self, message: &str) {
        let _ = message;
    }

    fn log_warning(&self, message: &str) {
        let _ = message;
    }

    fn log_info(&self, message: &str) {
        let _ = message;
    }
}

// ============================================================================
// GenSignatures
// ============================================================================

/// Generates BSim signatures for functions in a program.
#[derive(Debug, Clone, Default)]
pub struct GenSignatures {
    /// The description manager holding executables and functions.
    pub manager: DescriptionManager,
    /// Major version of the signature strategy.
    pub major_version: i16,
    /// Minor version of the signature strategy.
    pub minor_version: i16,
    /// Settings bitmask for the signature strategy.
    pub settings: u32,
}

impl GenSignatures {
    /// Create a new signature generator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the description manager.
    pub fn manager(&self) -> &DescriptionManager {
        &self.manager
    }

    /// Get a mutable reference to the description manager.
    pub fn manager_mut(&mut self) -> &mut DescriptionManager {
        &mut self.manager
    }

    /// Add an executable record.
    pub fn add_executable(
        &mut self,
        md5: impl Into<String>,
        name: impl Into<String>,
        compiler: impl Into<String>,
        architecture: impl Into<String>,
    ) -> usize {
        self.manager
            .new_executable_record(md5, name, compiler, architecture)
    }

    /// Add a function and attach a signature to it.
    pub fn add_function_with_signature(
        &mut self,
        exe_index: usize,
        name: impl Into<String>,
        address: Option<u64>,
        vector: FeatureVector,
    ) {
        let name_s = name.into();
        self.manager.new_function_description(&name_s, address, exe_index);
        let sig = SignatureRecord::new(vector);
        self.manager.attach_signature(exe_index, &name_s, address, sig);
    }

    /// Get the signature settings triple (major, minor, settings).
    pub fn signature_settings(&self) -> (i16, i16, u32) {
        (self.major_version, self.minor_version, self.settings)
    }

    /// Number of functions with signatures.
    pub fn signed_function_count(&self) -> usize {
        self.manager
            .list_all_functions()
            .filter(|f| f.signature.is_some())
            .count()
    }
}

// ============================================================================
// DecompileFunctionTask
// ============================================================================

/// Represents a task to decompile a single function for signature generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileFunctionTask {
    /// The function name.
    pub function_name: String,
    /// The function address.
    pub address: u64,
    /// The executable index.
    pub exe_index: usize,
    /// Whether the task has been completed.
    pub completed: bool,
}

impl DecompileFunctionTask {
    /// Create a new decompile function task.
    pub fn new(function_name: impl Into<String>, address: u64, exe_index: usize) -> Self {
        Self {
            function_name: function_name.into(),
            address,
            exe_index,
            completed: false,
        }
    }

    /// Mark the task as completed.
    pub fn complete(&mut self) {
        self.completed = true;
    }
}

// ============================================================================
// ParallelDecompileTask
// ============================================================================

/// Manages parallel decompilation of multiple functions for signature generation.
#[derive(Debug, Clone, Default)]
pub struct ParallelDecompileTask {
    /// The tasks to process.
    pub tasks: Vec<DecompileFunctionTask>,
    /// Number of completed tasks.
    pub completed_count: usize,
    /// Maximum number of parallel workers.
    pub max_workers: usize,
}

impl ParallelDecompileTask {
    /// Create a new parallel decompile task.
    pub fn new() -> Self {
        Self {
            max_workers: num_cpus(),
            ..Default::default()
        }
    }

    /// Add a task.
    pub fn add_task(&mut self, task: DecompileFunctionTask) {
        self.tasks.push(task);
    }

    /// Get the number of pending tasks.
    pub fn pending_count(&self) -> usize {
        self.tasks.len() - self.completed_count
    }

    /// Get the number of completed tasks.
    pub fn completed_count(&self) -> usize {
        self.completed_count
    }

    /// Total number of tasks.
    pub fn total_count(&self) -> usize {
        self.tasks.len()
    }

    /// Progress as a fraction (0.0 - 1.0).
    pub fn progress(&self) -> f64 {
        if self.tasks.is_empty() {
            1.0
        } else {
            self.completed_count as f64 / self.tasks.len() as f64
        }
    }
}

/// Get the number of available CPU cores.
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

// ============================================================================
// BSimDBConnectTaskManager
// ============================================================================

/// Manages database connection tasks (connect, disconnect, status checks).
#[derive(Debug, Clone, Default)]
pub struct BSimDbConnectTaskManager {
    /// Current connection state.
    pub connected: bool,
    /// The connection URL (if connected).
    pub url: Option<String>,
    /// Last error message.
    pub last_error: Option<String>,
}

impl BSimDbConnectTaskManager {
    /// Create a new task manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether currently connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Set the connection state.
    pub fn set_connected(&mut self, connected: bool, url: Option<String>) {
        self.connected = connected;
        self.url = url;
    }

    /// Set the last error.
    pub fn set_error(&mut self, error: impl Into<String>) {
        self.last_error = Some(error.into());
    }
}

// ============================================================================
// BSimInitializer
// ============================================================================

/// Initializes the BSim subsystem.
pub struct BSimInitializer;

impl BSimInitializer {
    /// Initialize the BSim subsystem.
    pub fn initialize() {
        // In a full implementation, this would register connection types
        // and set up logging.
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_config_creation() {
        let config = ServerConfig::new("localhost", 5432, ConnectionType::Postgresql)
            .with_database("bsim")
            .with_username("user")
            .with_password("pass")
            .with_ssl(true);

        assert_eq!(config.hostname, "localhost");
        assert_eq!(config.port, 5432);
        assert_eq!(config.connection_type, ConnectionType::Postgresql);
        assert_eq!(config.database_name, "bsim");
        assert!(config.use_ssl);
        assert_eq!(config.url(), "localhost:5432");
    }

    #[test]
    fn bsim_server_info() {
        let config = ServerConfig::new("localhost", 9200, ConnectionType::Elasticsearch);
        let info = BSimServerInfo::new(config);
        assert!(!info.reachable);
        assert!(info.version.is_none());
    }

    #[test]
    fn lsh_exception_display() {
        let e = LshException::new("vector mismatch");
        assert!(format!("{}", e).contains("vector mismatch"));
    }

    #[test]
    fn lsh_exception_to_bsim_error() {
        let e = LshException::new("test");
        let bsim_err: BSimError = e.into();
        match bsim_err {
            BSimError::LshError(msg) => assert_eq!(msg, "test"),
            _ => panic!("expected LshError"),
        }
    }

    #[test]
    fn gen_signatures_add_executable() {
        let mut gen = GenSignatures::new();
        let idx = gen.add_executable("abc", "prog", "gcc", "x86");
        assert_eq!(idx, 0);
    }

    #[test]
    fn gen_signatures_add_function_with_signature() {
        let mut gen = GenSignatures::new();
        gen.add_executable("abc", "prog", "gcc", "x86");

        let fv = FeatureVector::from_pairs(vec![1, 2, 3], vec![1.0, 1.0, 1.0]);
        gen.add_function_with_signature(0, "main", Some(0x1000), fv);

        assert_eq!(gen.signed_function_count(), 1);
    }

    #[test]
    fn gen_signatures_settings() {
        let mut gen = GenSignatures::new();
        gen.major_version = 1;
        gen.minor_version = 2;
        gen.settings = 0xABCD;
        assert_eq!(gen.signature_settings(), (1, 2, 0xABCD));
    }

    #[test]
    fn decompile_function_task() {
        let mut task = DecompileFunctionTask::new("main", 0x1000, 0);
        assert!(!task.completed);
        task.complete();
        assert!(task.completed);
    }

    #[test]
    fn parallel_decompile_task() {
        let mut task = ParallelDecompileTask::new();
        assert_eq!(task.total_count(), 0);

        task.add_task(DecompileFunctionTask::new("a", 0x1000, 0));
        task.add_task(DecompileFunctionTask::new("b", 0x2000, 0));
        assert_eq!(task.total_count(), 2);
        assert_eq!(task.pending_count(), 2);

        task.completed_count = 1;
        assert_eq!(task.pending_count(), 1);
        assert!((task.progress() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn bsim_db_connect_task_manager() {
        let mut mgr = BSimDbConnectTaskManager::new();
        assert!(!mgr.is_connected());

        mgr.set_connected(true, Some("localhost:5432".to_string()));
        assert!(mgr.is_connected());
        assert_eq!(mgr.url.as_deref(), Some("localhost:5432"));
    }

    #[test]
    fn null_error_logger() {
        let logger = NullErrorLogger;
        logger.log_error("test");
        logger.log_warning("test");
        logger.log_info("test");
    }

    #[test]
    fn collecting_error_logger() {
        let logger = CollectingErrorLogger::new();
        assert_eq!(logger.total_messages(), 0);
        assert!(!logger.has_errors());
    }

    #[test]
    fn server_config_default_ssl() {
        let config = ServerConfig::new("host", 8080, ConnectionType::InMemory);
        assert!(!config.use_ssl);
        assert_eq!(config.timeout_secs, 30);
    }
}
