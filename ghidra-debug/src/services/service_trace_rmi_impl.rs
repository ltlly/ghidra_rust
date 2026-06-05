//! TraceRmi service implementation.
//!
//! Ported from Ghidra's `TraceRmiService` and `TraceRmiLauncherService`
//! implementations. Provides the server-side RMI infrastructure for
//! managing connections from debug backends.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::api::tracermi::{
    ConnectMode, ConnectionState, RemoteMethodDescriptor, RemoteMethodRegistry,
    TraceRmiAcceptor, TraceRmiError, TraceRmiResult,
    TraceRmiServiceListener, TraceRmiServiceListenerSet,
};
use crate::api::launch_result::{LaunchConfigurator, LaunchResult, PromptMode};

/// The state of the TraceRmi service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServiceState {
    /// The service is not started.
    Stopped,
    /// The service is listening for connections.
    Listening,
    /// The service is accepting a connection.
    Accepting,
    /// The service has active connections.
    Active,
    /// The service is shutting down.
    ShuttingDown,
}

/// Configuration for a TraceRmi service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRmiServiceConfig {
    /// The listen address.
    pub listen_address: String,
    /// The port (0 for auto-assign).
    pub port: u16,
    /// Maximum number of concurrent connections.
    pub max_connections: usize,
    /// Connection timeout.
    pub connection_timeout: Duration,
    /// Method invocation timeout.
    pub method_timeout: Duration,
    /// Whether to auto-accept connections.
    pub auto_accept: bool,
}

impl Default for TraceRmiServiceConfig {
    fn default() -> Self {
        Self {
            listen_address: "127.0.0.1".into(),
            port: 0,
            max_connections: 16,
            connection_timeout: Duration::from_secs(30),
            method_timeout: Duration::from_secs(60),
            auto_accept: false,
        }
    }
}

/// A tracked connection within the service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConnection {
    /// The connection ID.
    pub id: u64,
    /// The remote address.
    pub remote_address: String,
    /// The connection state.
    pub state: ConnectionState,
    /// The number of targets published.
    pub target_count: usize,
    /// Whether any target has an open transaction.
    pub is_busy: bool,
    /// The method registry for this connection.
    pub methods: RemoteMethodRegistry,
}

impl ServiceConnection {
    /// Create a new service connection record.
    pub fn new(id: u64, remote_address: String, methods: RemoteMethodRegistry) -> Self {
        Self {
            id,
            remote_address,
            state: ConnectionState::Negotiating,
            target_count: 0,
            is_busy: false,
            methods,
        }
    }
}

/// The TraceRmi service for managing debug backend connections.
///
/// Ported from Ghidra's `TraceRmiService`. This is the main service
/// that listens for incoming connections, manages acceptors, and
/// tracks connection lifecycle.
pub struct TraceRmiService {
    /// Service configuration.
    config: TraceRmiServiceConfig,
    /// Current service state.
    state: RwLock<ServiceState>,
    /// Active connections.
    connections: RwLock<HashMap<u64, ServiceConnection>>,
    /// Listeners for service events.
    listeners: TraceRmiServiceListenerSet,
    /// Active acceptors.
    acceptors: Mutex<Vec<TraceRmiAcceptor>>,
    /// Next connection ID.
    next_connection_id: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for TraceRmiService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceRmiService")
            .field("state", &self.state)
            .field("connections", &self.connections)
            .finish()
    }
}

impl TraceRmiService {
    /// Create a new TraceRmi service.
    pub fn new(config: TraceRmiServiceConfig) -> Self {
        Self {
            config,
            state: RwLock::new(ServiceState::Stopped),
            connections: RwLock::new(HashMap::new()),
            listeners: TraceRmiServiceListenerSet::new(),
            acceptors: Mutex::new(Vec::new()),
            next_connection_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Get the current service state.
    pub fn state(&self) -> ServiceState {
        *self.state.read().unwrap()
    }

    /// Add a listener.
    pub fn add_listener(&mut self, listener: Box<dyn TraceRmiServiceListener>) {
        self.listeners.add(listener);
    }

    /// Start the service.
    pub fn start(&self) -> TraceRmiResult<()> {
        let mut state = self.state.write().unwrap();
        if *state != ServiceState::Stopped {
            return Err(TraceRmiError::Connection("Service already started".into()));
        }
        *state = ServiceState::Listening;
        self.listeners
            .notify_server_started(&self.config.listen_address);
        Ok(())
    }

    /// Stop the service.
    pub fn stop(&self) {
        {
            let mut state = self.state.write().unwrap();
            *state = ServiceState::ShuttingDown;
        }

        // Cancel all acceptors
        let mut acceptors = self.acceptors.lock().unwrap();
        acceptors.clear();

        // Close all connections
        let mut connections = self.connections.write().unwrap();
        connections.clear();

        {
            let mut state = self.state.write().unwrap();
            *state = ServiceState::Stopped;
        }
        self.listeners.notify_server_stopped();
    }

    /// Get the number of active connections.
    pub fn connection_count(&self) -> usize {
        self.connections.read().unwrap().len()
    }

    /// Get info about a connection.
    pub fn get_connection(&self, id: u64) -> Option<ServiceConnection> {
        self.connections.read().unwrap().get(&id).cloned()
    }

    /// Get all connection IDs.
    pub fn connection_ids(&self) -> Vec<u64> {
        self.connections.read().unwrap().keys().copied().collect()
    }

    /// Register a connection (simulates accepting a connection).
    pub fn register_connection(
        &self,
        remote_address: String,
        methods: RemoteMethodRegistry,
    ) -> u64 {
        let id = self
            .next_connection_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let conn = ServiceConnection::new(id, remote_address, methods);
        self.connections.write().unwrap().insert(id, conn);
        self.listeners.notify_connected(id, ConnectMode::AcceptOne);
        id
    }

    /// Remove a connection.
    pub fn remove_connection(&self, id: u64) {
        self.connections.write().unwrap().remove(&id);
        self.listeners.notify_disconnected(id);
    }

    /// Notify that a target was published on a connection.
    pub fn notify_target_published(&self, connection_id: u64, target_key: &str) {
        let mut conns = self.connections.write().unwrap();
        if let Some(conn) = conns.get_mut(&connection_id) {
            conn.target_count += 1;
            conn.state = ConnectionState::Connected;
        }
        self.listeners
            .notify_target_published(connection_id, target_key);
    }

    /// Get the service configuration.
    pub fn config(&self) -> &TraceRmiServiceConfig {
        &self.config
    }
}

/// A launcher service for managing TraceRmi launch offers.
///
/// Ported from Ghidra's `TraceRmiLauncherService`.
#[derive(Debug)]
pub struct TraceRmiLauncherService {
    /// Registered launch offers.
    offers: RwLock<HashMap<String, LaunchOfferEntry>>,
    /// Default configurator.
    default_configurator: LaunchConfigurator,
}

/// An entry in the launcher's offer registry.
#[derive(Debug, Clone)]
pub struct LaunchOfferEntry {
    /// The offer display name.
    pub display_name: String,
    /// The offer scheme.
    pub scheme: String,
    /// The offer description.
    pub description: String,
    /// The offer's priority.
    pub priority: u32,
    /// Whether this offer is enabled.
    pub enabled: bool,
    /// Required image support.
    pub requires_image: bool,
}

impl LaunchOfferEntry {
    /// Create a new launch offer entry.
    pub fn new(
        display_name: impl Into<String>,
        scheme: impl Into<String>,
    ) -> Self {
        Self {
            display_name: display_name.into(),
            scheme: scheme.into(),
            description: String::new(),
            priority: 0,
            enabled: true,
            requires_image: false,
        }
    }

    /// Set the priority.
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Set whether the offer is enabled.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Set whether the offer requires an image.
    pub fn with_requires_image(mut self, requires: bool) -> Self {
        self.requires_image = requires;
        self
    }
}

impl TraceRmiLauncherService {
    /// Create a new launcher service.
    pub fn new() -> Self {
        Self {
            offers: RwLock::new(HashMap::new()),
            default_configurator: LaunchConfigurator::nop(),
        }
    }

    /// Register a launch offer.
    pub fn register_offer(&self, scheme: impl Into<String>, entry: LaunchOfferEntry) {
        self.offers.write().unwrap().insert(scheme.into(), entry);
    }

    /// Get a launch offer by scheme.
    pub fn get_offer(&self, scheme: &str) -> Option<LaunchOfferEntry> {
        self.offers.read().unwrap().get(scheme).cloned()
    }

    /// Get all offer schemes.
    pub fn offer_schemes(&self) -> Vec<String> {
        self.offers.read().unwrap().keys().cloned().collect()
    }

    /// Get enabled offers sorted by priority.
    pub fn enabled_offers(&self) -> Vec<LaunchOfferEntry> {
        let mut offers: Vec<_> = self
            .offers
            .read()
            .unwrap()
            .values()
            .filter(|o| o.enabled)
            .cloned()
            .collect();
        offers.sort_by_key(|o| o.priority);
        offers
    }

    /// Whether any offers are available.
    pub fn has_offers(&self) -> bool {
        !self.offers.read().unwrap().is_empty()
    }

    /// Get the default configurator.
    pub fn default_configurator(&self) -> &LaunchConfigurator {
        &self.default_configurator
    }
}

impl Default for TraceRmiLauncherService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_config_default() {
        let config = TraceRmiServiceConfig::default();
        assert_eq!(config.listen_address, "127.0.0.1");
        assert_eq!(config.port, 0);
        assert_eq!(config.max_connections, 16);
        assert!(!config.auto_accept);
    }

    #[test]
    fn test_service_state() {
        assert_ne!(ServiceState::Stopped, ServiceState::Listening);
        assert_ne!(ServiceState::Active, ServiceState::ShuttingDown);
    }

    #[test]
    fn test_service_lifecycle() {
        let config = TraceRmiServiceConfig::default();
        let service = TraceRmiService::new(config);

        assert_eq!(service.state(), ServiceState::Stopped);
        assert_eq!(service.connection_count(), 0);

        service.start().unwrap();
        assert_eq!(service.state(), ServiceState::Listening);

        let id = service.register_connection(
            "192.168.1.1:1234".into(),
            RemoteMethodRegistry::new(),
        );
        assert_eq!(service.connection_count(), 1);

        let conn = service.get_connection(id).unwrap();
        assert_eq!(conn.id, id);

        service.notify_target_published(id, "trace-0");
        service.remove_connection(id);
        assert_eq!(service.connection_count(), 0);

        service.stop();
        assert_eq!(service.state(), ServiceState::Stopped);
    }

    #[test]
    fn test_service_start_twice() {
        let config = TraceRmiServiceConfig::default();
        let service = TraceRmiService::new(config);
        service.start().unwrap();
        assert!(service.start().is_err());
    }

    #[test]
    fn test_service_connection_ids() {
        let config = TraceRmiServiceConfig::default();
        let service = TraceRmiService::new(config);
        service.start().unwrap();

        let id1 = service.register_connection("addr1".into(), RemoteMethodRegistry::new());
        let id2 = service.register_connection("addr2".into(), RemoteMethodRegistry::new());
        let ids = service.connection_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }

    #[test]
    fn test_service_connection_entry() {
        let methods = RemoteMethodRegistry::new();
        let conn = ServiceConnection::new(1, "127.0.0.1:1234".into(), methods);
        assert_eq!(conn.id, 1);
        assert_eq!(conn.state, ConnectionState::Negotiating);
        assert_eq!(conn.target_count, 0);
    }

    #[test]
    fn test_launcher_service() {
        let launcher = TraceRmiLauncherService::new();
        assert!(!launcher.has_offers());
        assert!(launcher.offer_schemes().is_empty());

        launcher.register_offer(
            "gdb",
            LaunchOfferEntry::new("GDB", "gdb")
                .with_priority(10)
                .with_requires_image(true),
        );
        launcher.register_offer(
            "lldb",
            LaunchOfferEntry::new("LLDB", "lldb").with_priority(20),
        );

        assert!(launcher.has_offers());
        assert_eq!(launcher.offer_schemes().len(), 2);

        let gdb = launcher.get_offer("gdb").unwrap();
        assert_eq!(gdb.display_name, "GDB");
        assert!(gdb.requires_image);

        let enabled = launcher.enabled_offers();
        assert_eq!(enabled.len(), 2);
        assert_eq!(enabled[0].scheme, "gdb"); // lower priority first
    }

    #[test]
    fn test_launcher_offer_entry() {
        let entry = LaunchOfferEntry::new("test", "test")
            .with_priority(5)
            .with_enabled(false)
            .with_requires_image(true);
        assert_eq!(entry.priority, 5);
        assert!(!entry.enabled);
        assert!(entry.requires_image);
    }

    #[test]
    fn test_service_config_serde() {
        let config = TraceRmiServiceConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: TraceRmiServiceConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.listen_address, "127.0.0.1");
    }
}
