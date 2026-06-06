//! Trace RMI Service - managing connections and listeners.
//!
//! Ported from Ghidra's `TraceRmiService`, `TraceRmiServiceListener`, and
//! associated types in `ghidra.debug.api.tracermi`.

use std::collections::HashMap;
use std::net::SocketAddr;


// ---------------------------------------------------------------------------
// ConnectMode
// ---------------------------------------------------------------------------

/// The mechanism for creating a Trace RMI connection.
///
/// Ported from `ghidra.debug.api.tracermi.TraceRmiServiceListener.ConnectMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectMode {
    /// Connection established via `TraceRmiService.connect()`.
    Connect,
    /// Connection established via `TraceRmiService.acceptOne()`.
    AcceptOne,
    /// Connection established by the server.
    Server,
}

// ---------------------------------------------------------------------------
// TraceRmiServiceListener (Rust version)
// ---------------------------------------------------------------------------

/// An event emitted by the Trace RMI service.
///
/// This is the Rust equivalent of Java's `TraceRmiServiceListener` callback
/// interface, using an enum-based approach.
#[derive(Debug, Clone)]
pub enum TraceRmiServiceEvent {
    /// The server has been started on the given address.
    ServerStarted { address: SocketAddr },
    /// The server has been stopped.
    ServerStopped,
    /// A new connection has been established.
    Connected {
        connection_id: String,
        mode: ConnectMode,
        acceptor_id: Option<String>,
    },
    /// A connection was lost or closed.
    Disconnected { connection_id: String },
    /// The service is waiting for an inbound connection.
    WaitingAccept { acceptor_id: String },
    /// The client cancelled an inbound acceptor.
    AcceptCancelled { acceptor_id: String },
    /// The service failed to complete an inbound connection.
    AcceptFailed {
        acceptor_id: String,
        error: String,
    },
    /// A new target was created by a Trace RMI connection.
    TargetPublished {
        connection_id: String,
        target_key: String,
    },
    /// A target was withdrawn.
    TargetWithdrawn {
        connection_id: String,
        target_key: String,
    },
    /// A transaction was opened for the given target.
    TransactionOpened {
        connection_id: String,
        target_key: String,
    },
    /// A transaction was closed for the given target.
    TransactionClosed {
        connection_id: String,
        target_key: String,
        aborted: bool,
    },
}

/// Callback trait for Trace RMI Service events.
///
/// Ported from `ghidra.debug.api.tracermi.TraceRmiServiceListener`.
pub trait TraceRmiServiceEventHandler: Send + Sync {
    /// Handle a service event.
    fn handle_event(&self, event: &TraceRmiServiceEvent);
}

// ---------------------------------------------------------------------------
// TraceRmiServiceState
// ---------------------------------------------------------------------------

/// Tracks the state of Trace RMI connections and targets.
///
/// This is the Rust-side state tracker that the Java service manages internally.
#[derive(Debug)]
pub struct TraceRmiServiceState {
    server_address: Option<SocketAddr>,
    server_running: bool,
    connections: HashMap<String, ConnectionInfo>,
    targets: HashMap<String, TargetConnection>,
    next_connection_id: u64,
}

/// Information about a connection.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Connection ID.
    pub id: String,
    /// Remote address.
    pub remote_address: Option<SocketAddr>,
    /// How the connection was established.
    pub mode: ConnectMode,
    /// Associated acceptor ID (for AcceptOne/Server modes).
    pub acceptor_id: Option<String>,
    /// Whether the connection is still active.
    pub active: bool,
    /// Connection creation time (millis since epoch).
    pub created_at: i64,
}

/// Maps a target key to its owning connection.
#[derive(Debug, Clone)]
pub struct TargetConnection {
    /// Target key.
    pub target_key: String,
    /// Connection ID.
    pub connection_id: String,
    /// Whether a transaction is open.
    pub transaction_open: bool,
}

impl TraceRmiServiceState {
    /// Create a new service state.
    pub fn new() -> Self {
        Self {
            server_address: None,
            server_running: false,
            connections: HashMap::new(),
            targets: HashMap::new(),
            next_connection_id: 1,
        }
    }

    /// Get the server address.
    pub fn server_address(&self) -> Option<SocketAddr> {
        self.server_address
    }

    /// Set the server address.
    pub fn set_server_address(&mut self, addr: Option<SocketAddr>) {
        self.server_address = addr;
    }

    /// Whether the server is running.
    pub fn is_server_running(&self) -> bool {
        self.server_running
    }

    /// Set server running state.
    pub fn set_server_running(&mut self, running: bool) {
        self.server_running = running;
    }

    /// Add a connection.
    pub fn add_connection(&mut self, mode: ConnectMode, remote: Option<SocketAddr>, acceptor_id: Option<String>) -> String {
        let id = format!("conn-{}", self.next_connection_id);
        self.next_connection_id += 1;
        let info = ConnectionInfo {
            id: id.clone(),
            remote_address: remote,
            mode,
            acceptor_id,
            active: true,
            created_at: 0, // Would use actual time in production
        };
        self.connections.insert(id.clone(), info);
        id
    }

    /// Remove (disconnect) a connection.
    pub fn remove_connection(&mut self, connection_id: &str) -> Option<ConnectionInfo> {
        let info = self.connections.get_mut(connection_id)?;
        info.active = false;
        // Also remove associated targets
        self.targets.retain(|_, tc| tc.connection_id != connection_id);
        self.connections.remove(connection_id)
    }

    /// Get a connection by ID.
    pub fn get_connection(&self, connection_id: &str) -> Option<&ConnectionInfo> {
        self.connections.get(connection_id)
    }

    /// Get all active connections.
    pub fn active_connections(&self) -> Vec<&ConnectionInfo> {
        self.connections.values().filter(|c| c.active).collect()
    }

    /// Get all connection IDs.
    pub fn connection_ids(&self) -> Vec<String> {
        self.connections.keys().cloned().collect()
    }

    /// Register a target with its connection.
    pub fn register_target(&mut self, target_key: &str, connection_id: &str) {
        self.targets.insert(
            target_key.to_string(),
            TargetConnection {
                target_key: target_key.to_string(),
                connection_id: connection_id.to_string(),
                transaction_open: false,
            },
        );
    }

    /// Unregister a target.
    pub fn unregister_target(&mut self, target_key: &str) -> Option<TargetConnection> {
        self.targets.remove(target_key)
    }

    /// Get the connection for a target.
    pub fn target_connection(&self, target_key: &str) -> Option<&TargetConnection> {
        self.targets.get(target_key)
    }

    /// Get all target keys.
    pub fn target_keys(&self) -> Vec<String> {
        self.targets.keys().cloned().collect()
    }

    /// Begin a transaction for a target.
    pub fn begin_transaction(&mut self, target_key: &str) -> Result<(), String> {
        let tc = self.targets.get_mut(target_key).ok_or("Target not found")?;
        if tc.transaction_open {
            return Err("Transaction already open".into());
        }
        tc.transaction_open = true;
        Ok(())
    }

    /// End a transaction for a target.
    pub fn end_transaction(&mut self, target_key: &str, aborted: bool) -> Result<(), String> {
        let tc = self.targets.get_mut(target_key).ok_or("Target not found")?;
        if !tc.transaction_open {
            return Err("No transaction open".into());
        }
        tc.transaction_open = aborted; // Reset
        if aborted {
            tc.transaction_open = false;
        } else {
            tc.transaction_open = false;
        }
        Ok(())
    }
}

impl Default for TraceRmiServiceState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connect_mode_variants() {
        assert_ne!(ConnectMode::Connect, ConnectMode::AcceptOne);
        assert_ne!(ConnectMode::AcceptOne, ConnectMode::Server);
        assert_eq!(ConnectMode::Connect, ConnectMode::Connect);
    }

    #[test]
    fn test_service_state_new() {
        let state = TraceRmiServiceState::new();
        assert!(!state.is_server_running());
        assert!(state.server_address().is_none());
        assert!(state.active_connections().is_empty());
    }

    #[test]
    fn test_service_state_server() {
        let mut state = TraceRmiServiceState::new();
        let addr: SocketAddr = "127.0.0.1:23946".parse().unwrap();
        state.set_server_address(Some(addr));
        assert_eq!(state.server_address(), Some(addr));

        state.set_server_running(true);
        assert!(state.is_server_running());
    }

    #[test]
    fn test_service_state_connections() {
        let mut state = TraceRmiServiceState::new();
        let c1 = state.add_connection(ConnectMode::Connect, None, None);
        let c2 = state.add_connection(ConnectMode::Server, None, None);

        assert_eq!(state.active_connections().len(), 2);
        assert!(state.get_connection(&c1).is_some());
        assert_eq!(state.get_connection(&c1).unwrap().mode, ConnectMode::Connect);

        state.remove_connection(&c1);
        assert_eq!(state.active_connections().len(), 1);
        assert!(state.get_connection(&c1).is_none());
    }

    #[test]
    fn test_service_state_targets() {
        let mut state = TraceRmiServiceState::new();
        let conn_id = state.add_connection(ConnectMode::Connect, None, None);

        state.register_target("target-1", &conn_id);
        state.register_target("target-2", &conn_id);

        assert_eq!(state.target_keys().len(), 2);
        assert!(state.target_connection("target-1").is_some());
        assert_eq!(
            state.target_connection("target-1").unwrap().connection_id,
            conn_id
        );

        state.remove_connection(&conn_id);
        // Targets associated with the connection should be removed
        assert!(state.target_keys().is_empty());
    }

    #[test]
    fn test_service_state_transactions() {
        let mut state = TraceRmiServiceState::new();
        let conn_id = state.add_connection(ConnectMode::Connect, None, None);
        state.register_target("t1", &conn_id);

        assert!(!state.target_connection("t1").unwrap().transaction_open);

        state.begin_transaction("t1").unwrap();
        assert!(state.target_connection("t1").unwrap().transaction_open);

        // Cannot begin twice
        assert!(state.begin_transaction("t1").is_err());

        state.end_transaction("t1", false).unwrap();
        assert!(!state.target_connection("t1").unwrap().transaction_open);
    }

    #[test]
    fn test_service_state_transaction_abort() {
        let mut state = TraceRmiServiceState::new();
        let conn_id = state.add_connection(ConnectMode::Connect, None, None);
        state.register_target("t1", &conn_id);

        state.begin_transaction("t1").unwrap();
        state.end_transaction("t1", true).unwrap();
        assert!(!state.target_connection("t1").unwrap().transaction_open);
    }

    #[test]
    fn test_service_state_nonexistent() {
        let mut state = TraceRmiServiceState::new();
        assert!(state.get_connection("nope").is_none());
        assert!(state.target_connection("nope").is_none());
        assert!(state.begin_transaction("nope").is_err());
        assert!(state.end_transaction("nope", false).is_err());
        assert!(state.unregister_target("nope").is_none());
    }

    #[test]
    fn test_service_state_default() {
        let state = TraceRmiServiceState::default();
        assert!(!state.is_server_running());
    }

    #[test]
    fn test_trace_rmi_service_event_variants() {
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let events = vec![
            TraceRmiServiceEvent::ServerStarted { address: addr },
            TraceRmiServiceEvent::ServerStopped,
            TraceRmiServiceEvent::Connected {
                connection_id: "c1".into(),
                mode: ConnectMode::Connect,
                acceptor_id: None,
            },
            TraceRmiServiceEvent::Disconnected {
                connection_id: "c1".into(),
            },
            TraceRmiServiceEvent::TargetPublished {
                connection_id: "c1".into(),
                target_key: "t1".into(),
            },
            TraceRmiServiceEvent::TransactionClosed {
                connection_id: "c1".into(),
                target_key: "t1".into(),
                aborted: false,
            },
        ];
        assert_eq!(events.len(), 6);
    }

    #[test]
    fn test_connection_info_clone() {
        let info = ConnectionInfo {
            id: "c1".into(),
            remote_address: None,
            mode: ConnectMode::Server,
            acceptor_id: Some("a1".into()),
            active: true,
            created_at: 0,
        };
        let cloned = info.clone();
        assert_eq!(cloned.id, "c1");
        assert_eq!(cloned.mode, ConnectMode::Server);
        assert!(cloned.active);
    }

    #[test]
    fn test_target_connection_clone() {
        let tc = TargetConnection {
            target_key: "t1".into(),
            connection_id: "c1".into(),
            transaction_open: false,
        };
        let cloned = tc.clone();
        assert_eq!(cloned.target_key, "t1");
        assert!(!cloned.transaction_open);
    }
}
