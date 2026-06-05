//! RMI client for trace-based debugging.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.client.tracermi` package.
//!
//! Provides the client-side types for communicating with debug backends
//! over a protobuf-encoded socket channel: `RmiClient`, `ProtobufSocket`,
//! `RmiBatch`, `RmiTrace`, `RmiTraceObject`, `RmiTransaction`, etc.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

// ---------------------------------------------------------------------------
// ProtobufSocket
// ---------------------------------------------------------------------------

/// Connection state of a protobuf socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocketState {
    /// Not yet connected.
    Disconnected,
    /// Connection is being established.
    Connecting,
    /// Connected and ready.
    Connected,
    /// Connection has been closed.
    Closed,
    /// An error occurred.
    Error,
}

/// Configuration for a protobuf socket connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtobufSocketConfig {
    /// Remote host.
    pub host: String,
    /// Remote port.
    pub port: u16,
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Read timeout per message.
    pub read_timeout: Duration,
    /// Maximum message length in bytes.
    pub max_message_length: usize,
}

impl Default for ProtobufSocketConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 0,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(30),
            max_message_length: 64 * 1024 * 1024, // 64 MiB
        }
    }
}

/// A generic protobuf-encoded socket wrapper.
///
/// Ported from Ghidra's `ProtobufSocket<M>`. Manages the connection state
/// and provides send/receive abstractions for length-delimited protobuf messages.
#[derive(Debug, Clone)]
pub struct ProtobufSocket {
    /// The connection configuration.
    pub config: ProtobufSocketConfig,
    /// Current state.
    pub state: SocketState,
    /// Number of messages sent.
    pub messages_sent: u64,
    /// Number of messages received.
    pub messages_received: u64,
}

impl ProtobufSocket {
    /// Create a new socket with the given configuration.
    pub fn new(config: ProtobufSocketConfig) -> Self {
        Self {
            config,
            state: SocketState::Disconnected,
            messages_sent: 0,
            messages_received: 0,
        }
    }

    /// Mark the socket as connected.
    pub fn set_connected(&mut self) {
        self.state = SocketState::Connected;
    }

    /// Mark the socket as closed.
    pub fn close(&mut self) {
        self.state = SocketState::Closed;
    }

    /// Whether the socket is connected.
    pub fn is_connected(&self) -> bool {
        self.state == SocketState::Connected
    }

    /// Record that a message was sent.
    pub fn record_send(&mut self) {
        self.messages_sent += 1;
    }

    /// Record that a message was received.
    pub fn record_receive(&mut self) {
        self.messages_received += 1;
    }

    /// The remote address as a string.
    pub fn remote_address(&self) -> String {
        format!("{}:{}", self.config.host, self.config.port)
    }
}

// ---------------------------------------------------------------------------
// RmiBatch
// ---------------------------------------------------------------------------

/// Represents a batch of RMI requests to be executed atomically.
///
/// Ported from Ghidra's `RmiBatch`. All requests appended to a batch
/// are sent together and their completion is tracked collectively.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RmiBatch {
    /// IDs of requests in this batch.
    pub request_ids: Vec<u64>,
    /// Whether the batch is still collecting requests.
    pub active: bool,
    /// Optional description.
    pub description: Option<String>,
}

impl RmiBatch {
    /// Create a new empty active batch.
    pub fn new() -> Self {
        Self {
            active: true,
            ..Default::default()
        }
    }

    /// Create a batch with a description.
    pub fn with_description(desc: impl Into<String>) -> Self {
        Self {
            description: Some(desc.into()),
            active: true,
            ..Default::default()
        }
    }

    /// Append a request ID to the batch.
    pub fn append(&mut self, request_id: u64) {
        self.request_ids.push(request_id);
    }

    /// Close the batch (no more requests).
    pub fn close(&mut self) {
        self.active = false;
    }

    /// Number of requests in this batch.
    pub fn len(&self) -> usize {
        self.request_ids.len()
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.request_ids.is_empty()
    }
}

// ---------------------------------------------------------------------------
// RmiTransaction
// ---------------------------------------------------------------------------

/// A transaction context for RMI trace operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RmiTransaction {
    /// The trace ID this transaction operates on.
    pub trace_id: u32,
    /// Transaction ID.
    pub tx_id: u32,
    /// Description of what this transaction does.
    pub description: String,
    /// Whether this transaction is undoable.
    pub undoable: bool,
    /// Whether the transaction is currently open.
    pub is_open: bool,
}

impl RmiTransaction {
    /// Create a new transaction.
    pub fn new(trace_id: u32, tx_id: u32, description: impl Into<String>, undoable: bool) -> Self {
        Self {
            trace_id,
            tx_id,
            description: description.into(),
            undoable,
            is_open: true,
        }
    }

    /// Close this transaction.
    pub fn close(&mut self) {
        self.is_open = false;
    }
}

// ---------------------------------------------------------------------------
// RmiTrace
// ---------------------------------------------------------------------------

/// A trace handle on the RMI client side.
///
/// Ported from Ghidra's `RmiTrace`. Represents a remote trace object
/// and provides methods to manipulate it through the RMI protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RmiTrace {
    /// The client-side trace ID.
    pub trace_id: u32,
    /// Path to the trace file on the remote side.
    pub path: String,
    /// Language ID.
    pub language_id: String,
    /// Compiler spec ID.
    pub compiler_spec_id: String,
    /// Open transactions on this trace.
    pub transactions: BTreeMap<u32, RmiTransaction>,
    /// Next transaction ID.
    pub next_tx_id: u32,
    /// Whether this trace is open.
    pub is_open: bool,
}

impl RmiTrace {
    /// Create a new trace handle.
    pub fn new(
        trace_id: u32,
        path: impl Into<String>,
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> Self {
        Self {
            trace_id,
            path: path.into(),
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
            transactions: BTreeMap::new(),
            next_tx_id: 1,
            is_open: true,
        }
    }

    /// Start a new transaction.
    pub fn start_tx(&mut self, description: impl Into<String>, undoable: bool) -> u32 {
        let tx_id = self.next_tx_id;
        self.next_tx_id += 1;
        let tx = RmiTransaction::new(self.trace_id, tx_id, description, undoable);
        self.transactions.insert(tx_id, tx);
        tx_id
    }

    /// End a transaction.
    pub fn end_tx(&mut self, tx_id: u32) -> Option<RmiTransaction> {
        self.transactions.remove(&tx_id)
    }

    /// Close this trace.
    pub fn close(&mut self) {
        self.is_open = false;
        self.transactions.clear();
    }
}

// ---------------------------------------------------------------------------
// RmiTraceObject / RmiTraceObjectValue
// ---------------------------------------------------------------------------

/// A trace object managed by the RMI client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RmiTraceObject {
    /// Object ID on the remote side.
    pub object_id: u32,
    /// The key path of this object.
    pub key_path: Vec<String>,
    /// Attributes.
    pub attributes: BTreeMap<String, serde_json::Value>,
    /// Child objects.
    pub children: BTreeMap<String, RmiTraceObjectValue>,
}

/// A value entry in a trace object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RmiTraceObjectValue {
    /// The entry key.
    pub entry_key: String,
    /// Whether this value is an object reference.
    pub is_object: bool,
    /// If `is_object`, the object ID.
    pub object_id: Option<u32>,
    /// The primitive value (if not an object).
    pub value: Option<serde_json::Value>,
    /// Lifespan of this value (snap range).
    pub lifespan: Option<(i64, i64)>,
}

// ---------------------------------------------------------------------------
// MemoryMapper / RegisterMapper
// ---------------------------------------------------------------------------

/// Maps memory between the RMI client and a remote trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryMapper {
    /// Source space name -> destination space name.
    pub space_mappings: BTreeMap<String, String>,
    /// Address offset translations.
    pub offset_translations: BTreeMap<String, i64>,
}

impl MemoryMapper {
    /// Create a new empty memory mapper.
    pub fn new() -> Self {
        Self::default()
    }

    /// Map a source space to a destination space.
    pub fn map_space(&mut self, from: impl Into<String>, to: impl Into<String>) {
        self.space_mappings.insert(from.into(), to.into());
    }

    /// Get the destination space for a source space.
    pub fn get_mapped_space(&self, from: &str) -> Option<&str> {
        self.space_mappings.get(from).map(|s| s.as_str())
    }

    /// Set an address offset translation for a space.
    pub fn set_offset_translation(&mut self, space: impl Into<String>, delta: i64) {
        self.offset_translations.insert(space.into(), delta);
    }
}

/// Maps registers between the RMI client and a remote trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterMapper {
    /// Remote register name -> local register name.
    pub register_mappings: BTreeMap<String, String>,
}

impl RegisterMapper {
    /// Create a new empty register mapper.
    pub fn new() -> Self {
        Self::default()
    }

    /// Map a remote register name to a local name.
    pub fn map_register(&mut self, remote: impl Into<String>, local: impl Into<String>) {
        self.register_mappings.insert(remote.into(), local.into());
    }

    /// Get the local name for a remote register.
    pub fn get_local_name(&self, remote: &str) -> Option<&str> {
        self.register_mappings.get(remote).map(|s| s.as_str())
    }
}

// ---------------------------------------------------------------------------
// RmiClient
// ---------------------------------------------------------------------------

/// Configuration for an RMI client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RmiClientConfig {
    /// Description of the client.
    pub description: String,
    /// Socket configuration.
    pub socket: ProtobufSocketConfig,
    /// Whether to auto-reconnect on disconnect.
    pub auto_reconnect: bool,
    /// Maximum number of reconnect attempts.
    pub max_reconnect_attempts: u32,
}

impl Default for RmiClientConfig {
    fn default() -> Self {
        Self {
            description: String::new(),
            socket: ProtobufSocketConfig::default(),
            auto_reconnect: false,
            max_reconnect_attempts: 3,
        }
    }
}

/// The RMI client, managing communication with a debug backend.
///
/// Ported from Ghidra's `RmiClient`.
#[derive(Debug, Clone)]
pub struct RmiClient {
    /// The socket connection.
    pub socket: ProtobufSocket,
    /// Active traces.
    pub traces: BTreeMap<u32, RmiTrace>,
    /// The current batch (if batching).
    pub current_batch: Option<RmiBatch>,
    /// The next trace ID to assign.
    pub next_trace_id: u32,
    /// Client description.
    pub description: String,
}

impl RmiClient {
    /// Create a new RMI client.
    pub fn new(config: RmiClientConfig) -> Self {
        Self {
            socket: ProtobufSocket::new(config.socket),
            traces: BTreeMap::new(),
            current_batch: None,
            next_trace_id: 1,
            description: config.description,
        }
    }

    /// Get the description.
    pub fn get_description(&self) -> &str {
        &self.description
    }

    /// Create a new trace on the remote side.
    pub fn create_trace(
        &mut self,
        path: impl Into<String>,
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> u32 {
        let trace_id = self.next_trace_id;
        self.next_trace_id += 1;
        let trace = RmiTrace::new(trace_id, path, language_id, compiler_spec_id);
        self.traces.insert(trace_id, trace);
        trace_id
    }

    /// Close a trace on the remote side.
    pub fn close_trace(&mut self, trace_id: u32) {
        if let Some(trace) = self.traces.get_mut(&trace_id) {
            trace.close();
        }
        self.traces.remove(&trace_id);
    }

    /// Get a trace by ID.
    pub fn get_trace(&self, trace_id: u32) -> Option<&RmiTrace> {
        self.traces.get(&trace_id)
    }

    /// Get a mutable trace by ID.
    pub fn get_trace_mut(&mut self, trace_id: u32) -> Option<&mut RmiTrace> {
        self.traces.get_mut(&trace_id)
    }

    /// Start a batch.
    pub fn start_batch(&mut self, description: Option<String>) {
        self.current_batch = Some(RmiBatch::with_description(description.unwrap_or_default()));
    }

    /// End the current batch.
    pub fn end_batch(&mut self) -> Option<RmiBatch> {
        let mut batch = self.current_batch.take()?;
        batch.close();
        Some(batch)
    }

    /// Close the client.
    pub fn close(&mut self) {
        for trace in self.traces.values_mut() {
            trace.close();
        }
        self.traces.clear();
        self.socket.close();
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protobuf_socket() {
        let config = ProtobufSocketConfig::default();
        let mut socket = ProtobufSocket::new(config);
        assert_eq!(socket.state, SocketState::Disconnected);
        assert!(!socket.is_connected());

        socket.set_connected();
        assert!(socket.is_connected());
        assert_eq!(socket.state, SocketState::Connected);

        socket.close();
        assert_eq!(socket.state, SocketState::Closed);
    }

    #[test]
    fn test_protobuf_socket_stats() {
        let config = ProtobufSocketConfig::default();
        let mut socket = ProtobufSocket::new(config);
        socket.record_send();
        socket.record_send();
        socket.record_receive();
        assert_eq!(socket.messages_sent, 2);
        assert_eq!(socket.messages_received, 1);
    }

    #[test]
    fn test_rmi_batch() {
        let mut batch = RmiBatch::new();
        assert!(batch.is_empty());
        batch.append(1);
        batch.append(2);
        assert_eq!(batch.len(), 2);
        assert!(batch.active);

        batch.close();
        assert!(!batch.active);
    }

    #[test]
    fn test_rmi_batch_with_description() {
        let batch = RmiBatch::with_description("test batch");
        assert_eq!(batch.description.as_deref(), Some("test batch"));
        assert!(batch.active);
    }

    #[test]
    fn test_rmi_transaction() {
        let mut tx = RmiTransaction::new(1, 1, "write memory", true);
        assert!(tx.is_open);
        assert!(tx.undoable);

        tx.close();
        assert!(!tx.is_open);
    }

    #[test]
    fn test_rmi_trace() {
        let mut trace = RmiTrace::new(1, "/tmp/test.trace", "x86:LE:64:default", "default");
        assert!(trace.is_open);
        assert_eq!(trace.transactions.len(), 0);

        let tx_id = trace.start_tx("modify", false);
        assert_eq!(trace.transactions.len(), 1);
        let tx = trace.end_tx(tx_id).unwrap();
        assert_eq!(tx.description, "modify");

        trace.close();
        assert!(!trace.is_open);
    }

    #[test]
    fn test_rmi_trace_auto_tx_ids() {
        let mut trace = RmiTrace::new(1, "/tmp/t", "lang", "cs");
        let id1 = trace.start_tx("a", false);
        let id2 = trace.start_tx("b", false);
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }

    #[test]
    fn test_rmi_trace_object() {
        let obj = RmiTraceObject {
            object_id: 1,
            key_path: vec!["Threads".into(), "t1".into()],
            attributes: BTreeMap::new(),
            children: BTreeMap::new(),
        };
        assert_eq!(obj.key_path.len(), 2);
    }

    #[test]
    fn test_rmi_trace_object_value() {
        let val = RmiTraceObjectValue {
            entry_key: "pid".into(),
            is_object: false,
            object_id: None,
            value: Some(serde_json::json!(1234)),
            lifespan: Some((0, i64::MAX)),
        };
        assert_eq!(val.entry_key, "pid");
        assert!(!val.is_object);
    }

    #[test]
    fn test_memory_mapper() {
        let mut mapper = MemoryMapper::new();
        mapper.map_space("ram", "memory");
        mapper.set_offset_translation("ram", 0x400000);
        assert_eq!(mapper.get_mapped_space("ram"), Some("memory"));
        assert!(mapper.get_mapped_space("register").is_none());
    }

    #[test]
    fn test_register_mapper() {
        let mut mapper = RegisterMapper::new();
        mapper.map_register("rax", "RAX");
        assert_eq!(mapper.get_local_name("rax"), Some("RAX"));
        assert!(mapper.get_local_name("rbx").is_none());
    }

    #[test]
    fn test_rmi_client() {
        let config = RmiClientConfig::default();
        let mut client = RmiClient::new(config);
        assert!(client.traces.is_empty());

        let trace_id = client.create_trace("/tmp/test.trace", "x86:LE:64:default", "default");
        assert_eq!(trace_id, 1);
        assert!(client.get_trace(trace_id).is_some());

        client.close_trace(trace_id);
        assert!(client.get_trace(trace_id).is_none());
    }

    #[test]
    fn test_rmi_client_batch() {
        let config = RmiClientConfig::default();
        let mut client = RmiClient::new(config);
        assert!(client.current_batch.is_none());

        client.start_batch(Some("test".into()));
        assert!(client.current_batch.is_some());

        let batch = client.end_batch().unwrap();
        assert_eq!(batch.description.as_deref(), Some("test"));
    }

    #[test]
    fn test_rmi_client_close() {
        let config = RmiClientConfig::default();
        let mut client = RmiClient::new(config);
        client.create_trace("/tmp/a", "lang", "cs");
        client.create_trace("/tmp/b", "lang", "cs");
        client.close();
        assert!(client.traces.is_empty());
        assert_eq!(client.socket.state, SocketState::Closed);
    }

    #[test]
    fn test_rmi_client_description() {
        let config = RmiClientConfig {
            description: "GDB via RMI".into(),
            ..Default::default()
        };
        let client = RmiClient::new(config);
        assert_eq!(client.get_description(), "GDB via RMI");
    }

    #[test]
    fn test_protobuf_socket_config_default() {
        let config = ProtobufSocketConfig::default();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.max_message_length, 64 * 1024 * 1024);
    }

    #[test]
    fn test_protobuf_socket_remote_address() {
        let config = ProtobufSocketConfig {
            host: "10.0.0.1".into(),
            port: 1234,
            ..Default::default()
        };
        let socket = ProtobufSocket::new(config);
        assert_eq!(socket.remote_address(), "10.0.0.1:1234");
    }
}
