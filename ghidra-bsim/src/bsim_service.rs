//! BSim Service -- manages database connections and query dispatch.
//!
//! Ports Ghidra's `ghidra.features.bsim.query.BSimService`. In the Java
//! version this is a `Service` registered with the tool's service manager so
//! other plugins can discover and use BSim functionality.  In Rust we
//! provide the same logical contract: a service that owns one or more
//! database connections, routes queries to the appropriate backend, and
//! manages the lifecycle of those connections.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::query::server_config::ServerConfig;
use crate::query::function_database::FunctionDatabase;
use crate::query::description::{
    BSimExecutableInfo, BSimFunctionDescription, BSimResultSet, SimilarityMetric,
};
use crate::query::bsim_server_info::BSimServerInfo;
use crate::query::BSimResult;

/// Unique handle for a managed database connection.
pub type ConnectionId = u64;

/// A named, managed connection to a BSim backend.
struct ManagedConnection {
    /// Server info for this connection.
    server_info: BSimServerInfo,
    /// The underlying database handle.
    database: Box<dyn FunctionDatabase>,
    /// Whether the connection is currently open.
    is_open: bool,
}

impl std::fmt::Debug for ManagedConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedConnection")
            .field("server_info", &self.server_info)
            .field("is_open", &self.is_open)
            .finish()
    }
}

/// BSim Service -- central coordinator for BSim database operations.
///
/// Manages a pool of named connections to BSim backends, routes queries, and
/// handles connection lifecycle (open / close / reconnect).
///
/// # Usage
///
/// ```ignore
/// let mut service = BSimService::new();
/// let id = service.connect(ServerConfig::postgresql("localhost", "bsim"))?;
/// service.open(id)?;
/// let results = service.query_similar(id, &func_desc, SimilarityMetric::Cosine, 100, 0.5)?;
/// service.close(id)?;
/// ```
pub struct BSimService {
    /// Registered connections keyed by id.
    connections: HashMap<ConnectionId, ManagedConnection>,
    /// Monotonically increasing connection counter.
    next_id: ConnectionId,
    /// Human-readable name for this service instance.
    name: String,
}

impl BSimService {
    /// Create a new BSim service.
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            next_id: 1,
            name: "BSimService".to_string(),
        }
    }

    /// Create a BSim service with a custom name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Get the service name.
    pub fn name(&self) -> &str {
        &self.name
    }

    // ------------------------------------------------------------------
    // Connection management
    // ------------------------------------------------------------------

    /// Register a new connection with the given server configuration.
    ///
    /// Returns a [`ConnectionId`] that can be used to reference this
    /// connection in subsequent calls.  The connection starts in the
    /// *closed* state; call [`open`](Self::open) before querying.
    pub fn connect(
        &mut self,
        config: ServerConfig,
        database: Box<dyn FunctionDatabase>,
    ) -> ConnectionId {
        let id = self.next_id;
        self.next_id += 1;
        let server_info = BSimServerInfo::new(&config.database, config.clone());
        self.connections.insert(
            id,
            ManagedConnection {
                server_info,
                database,
                is_open: false,
            },
        );
        id
    }

    /// Disconnect and remove a connection.
    pub fn disconnect(&mut self, id: ConnectionId) -> BSimResult<()> {
        let conn = self.connections.get_mut(&id);
        match conn {
            Some(c) => {
                if c.is_open {
                    c.database.close()?;
                }
                self.connections.remove(&id);
                Ok(())
            }
            None => Err(crate::query::BSimError::NotFound(format!(
                "Connection {} not found",
                id
            ))),
        }
    }

    /// Open a managed connection.
    pub fn open(&mut self, id: ConnectionId) -> BSimResult<()> {
        let conn = self.get_connection_mut(id)?;
        if !conn.is_open {
            conn.database.open()?;
            conn.is_open = true;
        }
        Ok(())
    }

    /// Close a managed connection.
    pub fn close(&mut self, id: ConnectionId) -> BSimResult<()> {
        let conn = self.get_connection_mut(id)?;
        if conn.is_open {
            conn.database.close()?;
            conn.is_open = false;
        }
        Ok(())
    }

    /// Check whether a connection is open.
    pub fn is_open(&self, id: ConnectionId) -> BSimResult<bool> {
        let conn = self.get_connection(id)?;
        Ok(conn.is_open)
    }

    /// Get the number of managed connections.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// List all connection ids.
    pub fn connection_ids(&self) -> Vec<ConnectionId> {
        self.connections.keys().copied().collect()
    }

    /// Get the server info for a connection.
    pub fn server_info(&self, id: ConnectionId) -> BSimResult<&BSimServerInfo> {
        Ok(&self.get_connection(id)?.server_info)
    }

    // ------------------------------------------------------------------
    // Query operations
    // ------------------------------------------------------------------

    /// Query for functions similar to the given description on a specific
    /// connection.
    pub fn query_similar(
        &self,
        id: ConnectionId,
        description: &BSimFunctionDescription,
        metric: SimilarityMetric,
        max_results: usize,
        min_similarity: f64,
    ) -> BSimResult<BSimResultSet> {
        let conn = self.get_connection(id)?;
        if !conn.is_open {
            return Err(crate::query::BSimError::ConnectionError(
                "Connection is not open".to_string(),
            ));
        }
        conn.database
            .query_similar(description, metric, max_results, min_similarity)
    }

    /// Ingest function descriptions into the database on a specific
    /// connection.
    pub fn ingest_functions(
        &mut self,
        id: ConnectionId,
        functions: &[BSimFunctionDescription],
    ) -> BSimResult<usize> {
        let conn = self.get_connection_mut(id)?;
        if !conn.is_open {
            return Err(crate::query::BSimError::ConnectionError(
                "Connection is not open".to_string(),
            ));
        }
        conn.database.ingest_functions(functions)
    }

    /// Register an executable on a specific connection.
    pub fn register_executable(
        &mut self,
        id: ConnectionId,
        info: &BSimExecutableInfo,
    ) -> BSimResult<()> {
        let conn = self.get_connection_mut(id)?;
        if !conn.is_open {
            return Err(crate::query::BSimError::ConnectionError(
                "Connection is not open".to_string(),
            ));
        }
        conn.database.register_executable(info)
    }

    /// Get the total function count for a connection.
    pub fn function_count(&self, id: ConnectionId) -> BSimResult<usize> {
        let conn = self.get_connection(id)?;
        if !conn.is_open {
            return Err(crate::query::BSimError::ConnectionError(
                "Connection is not open".to_string(),
            ));
        }
        conn.database.function_count()
    }

    /// Get the total executable count for a connection.
    pub fn executable_count(&self, id: ConnectionId) -> BSimResult<usize> {
        let conn = self.get_connection(id)?;
        if !conn.is_open {
            return Err(crate::query::BSimError::ConnectionError(
                "Connection is not open".to_string(),
            ));
        }
        conn.database.executable_count()
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn get_connection(&self, id: ConnectionId) -> BSimResult<&ManagedConnection> {
        self.connections.get(&id).ok_or_else(|| {
            crate::query::BSimError::NotFound(format!("Connection {} not found", id))
        })
    }

    fn get_connection_mut(&mut self, id: ConnectionId) -> BSimResult<&mut ManagedConnection> {
        self.connections.get_mut(&id).ok_or_else(|| {
            crate::query::BSimError::NotFound(format!("Connection {} not found", id))
        })
    }
}

impl Default for BSimService {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BSimService {
    fn drop(&mut self) {
        for (_, mut conn) in self.connections.drain() {
            let _ = conn.database.close();
        }
    }
}

/// Thread-safe shared handle to a [`BSimService`].
pub type SharedBSimService = Arc<RwLock<BSimService>>;

/// Create a new shared service handle.
pub fn new_shared_service() -> SharedBSimService {
    Arc::new(RwLock::new(BSimService::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::function_database::StubFunctionDatabase;

    fn make_service_with_conn() -> (BSimService, ConnectionId) {
        let mut svc = BSimService::new();
        let config = ServerConfig::postgresql("localhost", "testdb");
        let db = Box::new(StubFunctionDatabase::new());
        let id = svc.connect(config, db);
        (svc, id)
    }

    #[test]
    fn test_service_new() {
        let svc = BSimService::new();
        assert_eq!(svc.name(), "BSimService");
        assert_eq!(svc.connection_count(), 0);
    }

    #[test]
    fn test_service_with_name() {
        let svc = BSimService::new().with_name("Custom");
        assert_eq!(svc.name(), "Custom");
    }

    #[test]
    fn test_connect_disconnect() {
        let (mut svc, id) = make_service_with_conn();
        assert_eq!(svc.connection_count(), 1);
        svc.disconnect(id).unwrap();
        assert_eq!(svc.connection_count(), 0);
    }

    #[test]
    fn test_open_close() {
        let (mut svc, id) = make_service_with_conn();
        assert!(!svc.is_open(id).unwrap());

        svc.open(id).unwrap();
        assert!(svc.is_open(id).unwrap());

        svc.close(id).unwrap();
        assert!(!svc.is_open(id).unwrap());
    }

    #[test]
    fn test_open_idempotent() {
        let (mut svc, id) = make_service_with_conn();
        svc.open(id).unwrap();
        svc.open(id).unwrap();
        assert!(svc.is_open(id).unwrap());
    }

    #[test]
    fn test_close_idempotent() {
        let (mut svc, id) = make_service_with_conn();
        svc.close(id).unwrap();
        assert!(!svc.is_open(id).unwrap());
    }

    #[test]
    fn test_query_similar() {
        let (mut svc, id) = make_service_with_conn();
        svc.open(id).unwrap();

        let func = BSimFunctionDescription::new("exe1", "func1", 0x1000);
        let results = svc
            .query_similar(id, &func, SimilarityMetric::Cosine, 10, 0.5)
            .unwrap();
        assert_eq!(results.total_matches, 0); // stub has no data
    }

    #[test]
    fn test_query_on_closed_conn_errors() {
        let (svc, id) = make_service_with_conn();
        let func = BSimFunctionDescription::new("exe1", "func1", 0x1000);
        let result = svc.query_similar(id, &func, SimilarityMetric::Cosine, 10, 0.5);
        assert!(result.is_err());
    }

    #[test]
    fn test_ingest_and_query() {
        let (mut svc, id) = make_service_with_conn();
        svc.open(id).unwrap();

        let funcs = vec![
            BSimFunctionDescription::new("exe1", "func1", 0x1000),
            BSimFunctionDescription::new("exe1", "func2", 0x2000),
        ];
        let count = svc.ingest_functions(id, &funcs).unwrap();
        assert_eq!(count, 2);

        let total = svc.function_count(id).unwrap();
        assert_eq!(total, 2);
    }

    #[test]
    fn test_register_executable() {
        let (mut svc, id) = make_service_with_conn();
        svc.open(id).unwrap();

        let info = BSimExecutableInfo::new("exe1", "test.exe");
        svc.register_executable(id, &info).unwrap();
        assert_eq!(svc.executable_count(id).unwrap(), 1);
    }

    #[test]
    fn test_connection_not_found() {
        let svc = BSimService::new();
        assert!(svc.is_open(999).is_err());
        assert!(svc.server_info(999).is_err());
    }

    #[test]
    fn test_connection_ids() {
        let (mut svc, id1) = make_service_with_conn();
        let config = ServerConfig::elasticsearch("es", 9200);
        let db = Box::new(StubFunctionDatabase::new());
        let id2 = svc.connect(config, db);

        let ids = svc.connection_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }

    #[test]
    fn test_server_info() {
        let (svc, id) = make_service_with_conn();
        let info = svc.server_info(id).unwrap();
        assert_eq!(info.name, "testdb");
    }

    #[test]
    fn test_shared_service() {
        let shared = new_shared_service();
        {
            let mut s = shared.write().unwrap();
            assert_eq!(s.connection_count(), 0);
        }
    }

    #[test]
    fn test_default_trait() {
        let svc = BSimService::default();
        assert_eq!(svc.connection_count(), 0);
    }
}
