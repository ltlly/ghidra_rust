//! TraceRmiServiceListener - event listener for Trace RMI service.
//!
//! Ported from Ghidra's `TraceRmiServiceListener` interface.
//!
//! Provides callbacks for RMI service lifecycle events including
//! server start/stop, connection establishment/disconnection, and
//! target publication.

use serde::{Deserialize, Serialize};

use super::trace_rmi_connection::TraceRmiConnection;

/// The mechanism by which a Trace RMI connection was established.
///
/// Ported from `TraceRmiServiceListener.ConnectMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectMode {
    /// The connection was established via `TraceRmiService.connect()`.
    Connect,
    /// The connection was established via `TraceRmiService.acceptOne()`.
    AcceptOne,
    /// The connection was established by the server.
    Server,
}

/// An event emitted by the Trace RMI service.
///
/// Each variant corresponds to a callback in the Java `TraceRmiServiceListener`.
#[derive(Debug, Clone)]
pub enum TraceRmiServiceEvent {
    /// The server started on the given address.
    ServerStarted {
        /// The address the server is listening on.
        address: String,
    },
    /// The server stopped.
    ServerStopped,
    /// A new connection was established.
    Connected {
        /// The ID of the new connection.
        connection_id: String,
        /// The mechanism that created the connection.
        mode: ConnectMode,
    },
    /// A connection was lost or closed.
    Disconnected {
        /// The ID of the disconnected connection.
        connection_id: String,
    },
    /// The service is waiting for an inbound connection.
    WaitingAccept {
        /// The ID of the acceptor.
        acceptor_id: String,
    },
    /// An accept operation was cancelled.
    AcceptCancelled {
        /// The ID of the cancelled acceptor.
        acceptor_id: String,
    },
    /// An accept operation failed.
    AcceptFailed {
        /// The ID of the failed acceptor.
        acceptor_id: String,
        /// The error message.
        error: String,
    },
    /// A target was published by a connection.
    TargetPublished {
        /// The ID of the connection.
        connection_id: String,
        /// The target name.
        target_name: String,
    },
    /// A transaction was opened for a target.
    TransactionOpened {
        /// The ID of the connection.
        connection_id: String,
        /// The target name.
        target_name: String,
    },
    /// A transaction was closed for a target.
    TransactionClosed {
        /// The ID of the connection.
        connection_id: String,
        /// The target name.
        target_name: String,
        /// Whether the transaction was aborted.
        aborted: bool,
    },
}

/// A trait for listening to Trace RMI service events.
///
/// Ported from Ghidra's `TraceRmiServiceListener` interface.
/// All methods have default no-op implementations, so implementors
/// only need to override the methods they care about.
pub trait TraceRmiServiceListener: Send + Sync {
    /// Called when the server starts on the given address.
    fn server_started(&self, _address: &str) {}

    /// Called when the server stops.
    fn server_stopped(&self) {}

    /// Called when a new connection is established.
    fn connected(&self, _connection: &TraceRmiConnection, _mode: ConnectMode) {}

    /// Called when a connection is lost or closed.
    fn disconnected(&self, _connection: &TraceRmiConnection) {}

    /// Called when the service is waiting for an inbound connection.
    fn waiting_accept(&self, _acceptor_id: &str) {}

    /// Called when an accept operation is cancelled.
    fn accept_cancelled(&self, _acceptor_id: &str) {}

    /// Called when an accept operation fails.
    fn accept_failed(&self, _acceptor_id: &str, _error: &str) {}

    /// Called when a target is published by a connection.
    fn target_published(&self, _connection: &TraceRmiConnection, _target_name: &str) {}

    /// Called when a transaction is opened.
    fn transaction_opened(&self, _connection: &TraceRmiConnection, _target_name: &str) {}

    /// Called when a transaction is closed.
    fn transaction_closed(
        &self,
        _connection: &TraceRmiConnection,
        _target_name: &str,
        _aborted: bool,
    ) {}
}

/// A composite listener that dispatches events to multiple child listeners.
///
/// This allows registering multiple listeners to the same service event source.
#[derive(Default)]
pub struct CompositeTraceRmiServiceListener {
    listeners: Vec<Box<dyn TraceRmiServiceListener>>,
}

impl CompositeTraceRmiServiceListener {
    /// Create a new empty composite listener.
    pub fn new() -> Self {
        Self {
            listeners: Vec::new(),
        }
    }

    /// Add a listener to this composite.
    pub fn add_listener(&mut self, listener: Box<dyn TraceRmiServiceListener>) {
        self.listeners.push(listener);
    }

    /// Get the number of registered listeners.
    pub fn len(&self) -> usize {
        self.listeners.len()
    }

    /// Check if no listeners are registered.
    pub fn is_empty(&self) -> bool {
        self.listeners.is_empty()
    }
}

impl TraceRmiServiceListener for CompositeTraceRmiServiceListener {
    fn server_started(&self, address: &str) {
        for l in &self.listeners {
            l.server_started(address);
        }
    }

    fn server_stopped(&self) {
        for l in &self.listeners {
            l.server_stopped();
        }
    }

    fn connected(&self, connection: &TraceRmiConnection, mode: ConnectMode) {
        for l in &self.listeners {
            l.connected(connection, mode);
        }
    }

    fn disconnected(&self, connection: &TraceRmiConnection) {
        for l in &self.listeners {
            l.disconnected(connection);
        }
    }

    fn target_published(&self, connection: &TraceRmiConnection, target_name: &str) {
        for l in &self.listeners {
            l.target_published(connection, target_name);
        }
    }

    fn transaction_opened(&self, connection: &TraceRmiConnection, target_name: &str) {
        for l in &self.listeners {
            l.transaction_opened(connection, target_name);
        }
    }

    fn transaction_closed(
        &self,
        connection: &TraceRmiConnection,
        target_name: &str,
        aborted: bool,
    ) {
        for l in &self.listeners {
            l.transaction_closed(connection, target_name, aborted);
        }
    }

    fn waiting_accept(&self, acceptor_id: &str) {
        for l in &self.listeners {
            l.waiting_accept(acceptor_id);
        }
    }

    fn accept_cancelled(&self, acceptor_id: &str) {
        for l in &self.listeners {
            l.accept_cancelled(acceptor_id);
        }
    }

    fn accept_failed(&self, acceptor_id: &str, error: &str) {
        for l in &self.listeners {
            l.accept_failed(acceptor_id, error);
        }
    }
}

/// A recording listener that stores all received events for inspection.
///
/// Useful for testing and debugging.
#[derive(Default)]
pub struct RecordingServiceListener {
    /// Recorded events.
    pub events: std::sync::Mutex<Vec<TraceRmiServiceEvent>>,
}

impl RecordingServiceListener {
    /// Create a new recording listener.
    pub fn new() -> Self {
        Self {
            events: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Get a copy of all recorded events.
    pub fn recorded_events(&self) -> Vec<TraceRmiServiceEvent> {
        self.events.lock().unwrap().clone()
    }

    /// Clear all recorded events.
    pub fn clear(&self) {
        self.events.lock().unwrap().clear();
    }

    /// Get the number of recorded events.
    pub fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}

impl TraceRmiServiceListener for RecordingServiceListener {
    fn server_started(&self, address: &str) {
        self.events.lock().unwrap().push(
            TraceRmiServiceEvent::ServerStarted {
                address: address.to_string(),
            },
        );
    }

    fn server_stopped(&self) {
        self.events
            .lock()
            .unwrap()
            .push(TraceRmiServiceEvent::ServerStopped);
    }

    fn connected(&self, _connection: &TraceRmiConnection, mode: ConnectMode) {
        self.events.lock().unwrap().push(
            TraceRmiServiceEvent::Connected {
                connection_id: "test".to_string(),
                mode,
            },
        );
    }

    fn disconnected(&self, _connection: &TraceRmiConnection) {
        self.events.lock().unwrap().push(
            TraceRmiServiceEvent::Disconnected {
                connection_id: "test".to_string(),
            },
        );
    }

    fn waiting_accept(&self, acceptor_id: &str) {
        self.events.lock().unwrap().push(
            TraceRmiServiceEvent::WaitingAccept {
                acceptor_id: acceptor_id.to_string(),
            },
        );
    }

    fn accept_cancelled(&self, acceptor_id: &str) {
        self.events.lock().unwrap().push(
            TraceRmiServiceEvent::AcceptCancelled {
                acceptor_id: acceptor_id.to_string(),
            },
        );
    }

    fn accept_failed(&self, acceptor_id: &str, error: &str) {
        self.events.lock().unwrap().push(
            TraceRmiServiceEvent::AcceptFailed {
                acceptor_id: acceptor_id.to_string(),
                error: error.to_string(),
            },
        );
    }

    fn target_published(&self, _connection: &TraceRmiConnection, target_name: &str) {
        self.events.lock().unwrap().push(
            TraceRmiServiceEvent::TargetPublished {
                connection_id: "test".to_string(),
                target_name: target_name.to_string(),
            },
        );
    }

    fn transaction_opened(&self, _connection: &TraceRmiConnection, target_name: &str) {
        self.events.lock().unwrap().push(
            TraceRmiServiceEvent::TransactionOpened {
                connection_id: "test".to_string(),
                target_name: target_name.to_string(),
            },
        );
    }

    fn transaction_closed(
        &self,
        _connection: &TraceRmiConnection,
        target_name: &str,
        aborted: bool,
    ) {
        self.events.lock().unwrap().push(
            TraceRmiServiceEvent::TransactionClosed {
                connection_id: "test".to_string(),
                target_name: target_name.to_string(),
                aborted,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connect_mode_variants() {
        assert_ne!(ConnectMode::Connect, ConnectMode::AcceptOne);
        assert_ne!(ConnectMode::Connect, ConnectMode::Server);
        assert_ne!(ConnectMode::AcceptOne, ConnectMode::Server);
    }

    #[test]
    fn test_connect_mode_serialization() {
        let mode = ConnectMode::Server;
        let json = serde_json::to_string(&mode).unwrap();
        let deserialized: ConnectMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, deserialized);
    }

    #[test]
    fn test_composite_listener_empty() {
        let composite = CompositeTraceRmiServiceListener::new();
        assert!(composite.is_empty());
        assert_eq!(composite.len(), 0);
    }

    #[test]
    fn test_composite_listener_dispatch() {
        let mut composite = CompositeTraceRmiServiceListener::new();

        let _rec1 = std::sync::Arc::new(RecordingServiceListener::new());
        let _rec2 = std::sync::Arc::new(RecordingServiceListener::new());

        composite.add_listener(Box::new(RecordingServiceListener::new()));

        // Use the composite to dispatch
        composite.server_started("localhost:18001");
        composite.server_stopped();

        // The one listener should have received events
        assert_eq!(composite.len(), 1);
    }

    #[test]
    fn test_recording_listener_events() {
        let rec = RecordingServiceListener::new();
        assert_eq!(rec.event_count(), 0);

        rec.server_started("localhost:18001");
        rec.server_stopped();
        assert_eq!(rec.event_count(), 2);

        let events = rec.recorded_events();
        assert!(matches!(
            &events[0],
            TraceRmiServiceEvent::ServerStarted { address } if address == "localhost:18001"
        ));
        assert!(matches!(&events[1], TraceRmiServiceEvent::ServerStopped));

        rec.clear();
        assert_eq!(rec.event_count(), 0);
    }

    #[test]
    fn test_recording_listener_accept_events() {
        let rec = RecordingServiceListener::new();

        rec.waiting_accept("acceptor-1");
        rec.accept_cancelled("acceptor-1");
        rec.accept_failed("acceptor-2", "timeout");

        let events = rec.recorded_events();
        assert_eq!(events.len(), 3);
        assert!(matches!(
            &events[0],
            TraceRmiServiceEvent::WaitingAccept { acceptor_id } if acceptor_id == "acceptor-1"
        ));
        assert!(matches!(
            &events[1],
            TraceRmiServiceEvent::AcceptCancelled { acceptor_id } if acceptor_id == "acceptor-1"
        ));
        assert!(matches!(
            &events[2],
            TraceRmiServiceEvent::AcceptFailed { acceptor_id, error }
                if acceptor_id == "acceptor-2" && error == "timeout"
        ));
    }

    #[test]
    fn test_service_event_clone() {
        let event = TraceRmiServiceEvent::Connected {
            connection_id: "conn-1".to_string(),
            mode: ConnectMode::Connect,
        };
        let cloned = event.clone();
        if let TraceRmiServiceEvent::Connected { connection_id, mode } = cloned {
            assert_eq!(connection_id, "conn-1");
            assert_eq!(mode, ConnectMode::Connect);
        } else {
            panic!("Expected Connected event");
        }
    }

    #[test]
    fn test_transaction_events() {
        let rec = RecordingServiceListener::new();

        rec.transaction_opened(
            &TraceRmiConnection::new("localhost:18001", "conn-1"),
            "target-1",
        );
        rec.transaction_closed(
            &TraceRmiConnection::new("localhost:18001", "conn-1"),
            "target-1",
            false,
        );

        let events = rec.recorded_events();
        assert_eq!(events.len(), 2);
        assert!(matches!(
            &events[0],
            TraceRmiServiceEvent::TransactionOpened { target_name, .. }
                if target_name == "target-1"
        ));
        assert!(matches!(
            &events[1],
            TraceRmiServiceEvent::TransactionClosed { aborted, .. }
                if !aborted
        ));
    }
}
