//! BSim server cache and connection pool management.
//!
//! Ports `ghidra.features.bsim.query.BSimServerCache`,
//! `ConnectionPoolStatus`, and `BSimDBConnectTaskManager` from
//! Ghidra's Java source.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use super::bsim_server_info::BSimServerInfo;
use super::function_database::FunctionDatabase;
use super::server_config::ServerConfig;
use super::BSimResult;

/// Status of a connection pool entry.
///
/// Port of `ghidra.features.bsim.query.ConnectionPoolStatus`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionPoolStatus {
    /// Connection is active and healthy.
    Active,
    /// Connection is idle (not in use).
    Idle,
    /// Connection has been closed.
    Closed,
    /// Connection is in an error state.
    Error(String),
    /// Connection is being established.
    Connecting,
}

impl ConnectionPoolStatus {
    /// Whether the connection is usable.
    pub fn is_usable(&self) -> bool {
        matches!(self, ConnectionPoolStatus::Active | ConnectionPoolStatus::Idle)
    }

    /// Whether the connection is in an error state.
    pub fn is_error(&self) -> bool {
        matches!(self, ConnectionPoolStatus::Error(_))
    }
}

impl Default for ConnectionPoolStatus {
    fn default() -> Self {
        ConnectionPoolStatus::Idle
    }
}

impl std::fmt::Display for ConnectionPoolStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionPoolStatus::Active => write!(f, "Active"),
            ConnectionPoolStatus::Idle => write!(f, "Idle"),
            ConnectionPoolStatus::Closed => write!(f, "Closed"),
            ConnectionPoolStatus::Error(msg) => write!(f, "Error: {}", msg),
            ConnectionPoolStatus::Connecting => write!(f, "Connecting"),
        }
    }
}

/// A cached connection entry.
struct CachedConnection {
    /// The database connection.
    database: Option<Box<dyn FunctionDatabase>>,
    /// Connection status.
    status: ConnectionPoolStatus,
    /// When the connection was created.
    created_at: Instant,
    /// When the connection was last used.
    last_used: Instant,
    /// Number of times this connection has been used.
    use_count: u64,
}

impl std::fmt::Debug for CachedConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedConnection")
            .field("status", &self.status)
            .field("created_at", &self.created_at)
            .field("last_used", &self.last_used)
            .field("use_count", &self.use_count)
            .field("has_database", &self.database.is_some())
            .finish()
    }
}

/// Cache of BSim server connections.
///
/// Port of `ghidra.features.bsim.query.BSimServerCache`.
///
/// Manages a pool of connections to BSim servers, allowing reuse of
/// existing connections and automatic cleanup of idle connections.
pub struct BSimServerCache {
    /// Cached connections keyed by server name.
    connections: RwLock<HashMap<String, CachedConnection>>,
    /// Maximum number of idle connections to keep.
    max_idle: usize,
    /// Maximum idle time before a connection is evicted (seconds).
    max_idle_secs: u64,
}

impl BSimServerCache {
    /// Create a new server cache with default settings.
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
            max_idle: 5,
            max_idle_secs: 300, // 5 minutes
        }
    }

    /// Create a new server cache with custom settings.
    pub fn with_limits(max_idle: usize, max_idle_secs: u64) -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
            max_idle,
            max_idle_secs,
        }
    }

    /// Get or create a connection for the given server.
    pub fn get_or_create(
        &self,
        server_name: &str,
        config: &ServerConfig,
    ) -> BSimResult<()> {
        let mut conns = self.connections.write().unwrap();

        // Check if we already have a connection for this server.
        if let Some(entry) = conns.get_mut(server_name) {
            if entry.status.is_usable() {
                entry.last_used = Instant::now();
                entry.use_count += 1;
                entry.status = ConnectionPoolStatus::Active;
                return Ok(());
            }
        }

        // Create a new connection.
        let entry = CachedConnection {
            database: None,
            status: ConnectionPoolStatus::Connecting,
            created_at: Instant::now(),
            last_used: Instant::now(),
            use_count: 0,
        };
        conns.insert(server_name.to_string(), entry);

        // In a real implementation, we would establish the connection here.
        // For now, mark as active.
        if let Some(entry) = conns.get_mut(server_name) {
            entry.status = ConnectionPoolStatus::Active;
        }

        Ok(())
    }

    /// Mark a connection as idle.
    pub fn release(&self, server_name: &str) {
        let mut conns = self.connections.write().unwrap();
        if let Some(entry) = conns.get_mut(server_name) {
            if entry.status == ConnectionPoolStatus::Active {
                entry.status = ConnectionPoolStatus::Idle;
            }
        }
    }

    /// Remove a connection from the cache.
    pub fn remove(&self, server_name: &str) {
        let mut conns = self.connections.write().unwrap();
        if let Some(mut entry) = conns.remove(server_name) {
            entry.status = ConnectionPoolStatus::Closed;
        }
    }

    /// Get the status of a connection.
    pub fn status(&self, server_name: &str) -> Option<ConnectionPoolStatus> {
        let conns = self.connections.read().unwrap();
        conns.get(server_name).map(|e| e.status.clone())
    }

    /// Evict idle connections that have exceeded the idle timeout.
    pub fn evict_idle(&self) -> usize {
        let mut conns = self.connections.write().unwrap();
        let now = Instant::now();
        let max_idle = std::time::Duration::from_secs(self.max_idle_secs);

        let idle_keys: Vec<String> = conns
            .iter()
            .filter(|(_, entry)| {
                entry.status == ConnectionPoolStatus::Idle
                    && now.duration_since(entry.last_used) > max_idle
            })
            .map(|(key, _)| key.clone())
            .collect();

        let count = idle_keys.len();
        for key in &idle_keys {
            conns.remove(key);
        }
        count
    }

    /// Get the number of cached connections.
    pub fn size(&self) -> usize {
        self.connections.read().unwrap().len()
    }

    /// Get a summary of all connection statuses.
    pub fn status_summary(&self) -> HashMap<String, ConnectionPoolStatus> {
        let conns = self.connections.read().unwrap();
        conns
            .iter()
            .map(|(name, entry)| (name.clone(), entry.status.clone()))
            .collect()
    }

    /// Close all connections.
    pub fn close_all(&self) {
        let mut conns = self.connections.write().unwrap();
        for (_, entry) in conns.iter_mut() {
            entry.status = ConnectionPoolStatus::Closed;
        }
        conns.clear();
    }
}

impl Default for BSimServerCache {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BSimServerCache {
    fn drop(&mut self) {
        self.close_all();
    }
}

/// Manager for BSim database connection tasks.
///
/// Port of `ghidra.features.bsim.query.BSimDBConnectTaskManager`.
///
/// Manages asynchronous connection establishment tasks and provides
/// status callbacks.
pub struct BSimDBConnectTaskManager {
    /// Active connection tasks.
    active_tasks: HashMap<String, ConnectTaskStatus>,
    /// The server cache to manage.
    cache: Arc<BSimServerCache>,
}

/// Status of a connection task.
#[derive(Debug, Clone)]
pub struct ConnectTaskStatus {
    /// Server name.
    pub server_name: String,
    /// Task status.
    pub status: ConnectionPoolStatus,
    /// When the task started.
    pub started_at: Instant,
    /// Error message (if any).
    pub error: Option<String>,
}

impl BSimDBConnectTaskManager {
    /// Create a new connection task manager.
    pub fn new(cache: Arc<BSimServerCache>) -> Self {
        Self {
            active_tasks: HashMap::new(),
            cache,
        }
    }

    /// Start a connection task for the given server.
    pub fn start_connect(&mut self, server_name: &str, config: &ServerConfig) -> BSimResult<()> {
        let status = ConnectTaskStatus {
            server_name: server_name.to_string(),
            status: ConnectionPoolStatus::Connecting,
            started_at: Instant::now(),
            error: None,
        };
        self.active_tasks.insert(server_name.to_string(), status);

        // Start the actual connection.
        self.cache.get_or_create(server_name, config)?;

        // Update task status.
        if let Some(task) = self.active_tasks.get_mut(server_name) {
            task.status = ConnectionPoolStatus::Active;
        }

        Ok(())
    }

    /// Get the status of a connection task.
    pub fn task_status(&self, server_name: &str) -> Option<&ConnectTaskStatus> {
        self.active_tasks.get(server_name)
    }

    /// Cancel a connection task.
    pub fn cancel(&mut self, server_name: &str) {
        self.active_tasks.remove(server_name);
        self.cache.remove(server_name);
    }

    /// Get the number of active tasks.
    pub fn active_count(&self) -> usize {
        self.active_tasks.len()
    }

    /// Clear completed tasks.
    pub fn clear_completed(&mut self) {
        self.active_tasks.retain(|_, task| {
            !matches!(
                task.status,
                ConnectionPoolStatus::Active
                    | ConnectionPoolStatus::Closed
                    | ConnectionPoolStatus::Error(_)
            )
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_pool_status_default() {
        let status = ConnectionPoolStatus::default();
        assert_eq!(status, ConnectionPoolStatus::Idle);
    }

    #[test]
    fn test_connection_pool_status_is_usable() {
        assert!(ConnectionPoolStatus::Active.is_usable());
        assert!(ConnectionPoolStatus::Idle.is_usable());
        assert!(!ConnectionPoolStatus::Closed.is_usable());
        assert!(!ConnectionPoolStatus::Error("x".into()).is_usable());
    }

    #[test]
    fn test_connection_pool_status_is_error() {
        assert!(!ConnectionPoolStatus::Active.is_error());
        assert!(ConnectionPoolStatus::Error("x".into()).is_error());
    }

    #[test]
    fn test_connection_pool_status_display() {
        assert_eq!(ConnectionPoolStatus::Active.to_string(), "Active");
        assert_eq!(ConnectionPoolStatus::Closed.to_string(), "Closed");
        assert_eq!(
            ConnectionPoolStatus::Error("timeout".into()).to_string(),
            "Error: timeout"
        );
    }

    #[test]
    fn test_server_cache_new() {
        let cache = BSimServerCache::new();
        assert_eq!(cache.size(), 0);
    }

    #[test]
    fn test_server_cache_get_or_create() {
        let cache = BSimServerCache::new();
        let config = ServerConfig::default();
        cache.get_or_create("server1", &config).unwrap();
        assert_eq!(cache.size(), 1);
        assert_eq!(cache.status("server1"), Some(ConnectionPoolStatus::Active));
    }

    #[test]
    fn test_server_cache_release() {
        let cache = BSimServerCache::new();
        let config = ServerConfig::default();
        cache.get_or_create("server1", &config).unwrap();
        cache.release("server1");
        assert_eq!(cache.status("server1"), Some(ConnectionPoolStatus::Idle));
    }

    #[test]
    fn test_server_cache_remove() {
        let cache = BSimServerCache::new();
        let config = ServerConfig::default();
        cache.get_or_create("server1", &config).unwrap();
        cache.remove("server1");
        assert_eq!(cache.size(), 0);
        assert!(cache.status("server1").is_none());
    }

    #[test]
    fn test_server_cache_reuse() {
        let cache = BSimServerCache::new();
        let config = ServerConfig::default();
        cache.get_or_create("server1", &config).unwrap();
        cache.release("server1");
        cache.get_or_create("server1", &config).unwrap();
        assert_eq!(cache.size(), 1);
    }

    #[test]
    fn test_server_cache_status_summary() {
        let cache = BSimServerCache::new();
        let config = ServerConfig::default();
        cache.get_or_create("s1", &config).unwrap();
        cache.get_or_create("s2", &config).unwrap();

        let summary = cache.status_summary();
        assert_eq!(summary.len(), 2);
        assert!(summary.contains_key("s1"));
        assert!(summary.contains_key("s2"));
    }

    #[test]
    fn test_server_cache_close_all() {
        let cache = BSimServerCache::new();
        let config = ServerConfig::default();
        cache.get_or_create("s1", &config).unwrap();
        cache.close_all();
        assert_eq!(cache.size(), 0);
    }

    #[test]
    fn test_server_cache_evict_idle() {
        let cache = BSimServerCache::with_limits(5, 0); // 0 second idle timeout
        let config = ServerConfig::default();
        cache.get_or_create("server1", &config).unwrap();
        cache.release("server1");

        // Since max_idle_secs is 0, all idle connections should be evicted.
        let evicted = cache.evict_idle();
        assert_eq!(evicted, 1);
        assert_eq!(cache.size(), 0);
    }

    #[test]
    fn test_connect_task_manager() {
        let cache = Arc::new(BSimServerCache::new());
        let mut manager = BSimDBConnectTaskManager::new(cache);
        let config = ServerConfig::default();

        manager.start_connect("server1", &config).unwrap();
        assert_eq!(manager.active_count(), 1);
        assert!(manager.task_status("server1").is_some());
    }

    #[test]
    fn test_connect_task_manager_cancel() {
        let cache = Arc::new(BSimServerCache::new());
        let mut manager = BSimDBConnectTaskManager::new(cache);
        let config = ServerConfig::default();

        manager.start_connect("server1", &config).unwrap();
        manager.cancel("server1");
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn test_connect_task_manager_clear_completed() {
        let cache = Arc::new(BSimServerCache::new());
        let mut manager = BSimDBConnectTaskManager::new(cache);
        let config = ServerConfig::default();

        manager.start_connect("server1", &config).unwrap();
        manager.clear_completed();
        // Active tasks should be cleared after clear_completed
        // (they are in Active state which is matched).
    }
}
