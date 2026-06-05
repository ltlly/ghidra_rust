//! Full TraceRmi connection implementation.
//!
//! Provides a concrete implementation of the TraceRmi connection with
//! method invocation, target tracking, and transaction management.
//! Ported from Ghidra's TraceRmiConnection implementation patterns.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::tracermi::{
    ConnectionState, RemoteAsyncResult, RemoteMethodDescriptor, RemoteMethodRegistry,
    AsyncStatus, TraceRmiAcceptor, TraceRmiError, TraceRmiResult, SchemaName,
};
use super::launch_result::{LaunchResult, LaunchConfigurator};

/// A unique identifier for a trace target.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TargetKey(pub String);

impl TargetKey {
    /// Create a new target key.
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    /// Get the key as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TargetKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Information about a published target.
#[derive(Debug)]
pub struct TargetInfo {
    /// The target key.
    pub key: TargetKey,
    /// The last snapshot number created for this target.
    last_snapshot: AtomicU64,
    /// Whether a transaction is currently open.
    has_transaction: AtomicBool,
}

impl TargetInfo {
    /// Create new target info.
    pub fn new(key: TargetKey) -> Self {
        Self {
            key,
            last_snapshot: AtomicU64::new(0),
            has_transaction: AtomicBool::new(false),
        }
    }

    /// Get the last snapshot number.
    pub fn get_last_snapshot(&self) -> u64 {
        self.last_snapshot.load(Ordering::SeqCst)
    }

    /// Set the last snapshot number.
    pub fn set_last_snapshot(&self, snap: u64) {
        self.last_snapshot.store(snap, Ordering::SeqCst);
    }

    /// Whether this target has an active transaction.
    pub fn is_busy(&self) -> bool {
        self.has_transaction.load(Ordering::SeqCst)
    }

    /// Set the transaction state.
    pub fn set_busy(&self, busy: bool) {
        self.has_transaction.store(busy, Ordering::SeqCst);
    }
}

/// A full TraceRmi connection implementation.
///
/// Ported from Ghidra's TraceRmiConnection. Manages the bidirectional
/// communication channel with a debug backend, including method registry,
/// target tracking, and connection lifecycle.
#[derive(Debug)]
pub struct TraceRmiConnectionImpl {
    /// Connection description.
    description: String,
    /// Remote address.
    remote_address: String,
    /// Connection state.
    state: RwLock<ConnectionState>,
    /// Method registry.
    methods: RemoteMethodRegistry,
    /// Published targets.
    targets: RwLock<HashMap<TargetKey, Arc<TargetInfo>>>,
    /// Connection ID.
    connection_id: u64,
    /// Whether the connection is closed.
    closed: AtomicBool,
    /// Pending async results.
    pending_results: Mutex<HashMap<u64, RemoteAsyncResult>>,
    /// Next request ID.
    next_request_id: AtomicU64,
}

impl TraceRmiConnectionImpl {
    /// Create a new connection.
    pub fn new(
        connection_id: u64,
        description: impl Into<String>,
        remote_address: impl Into<String>,
        methods: RemoteMethodRegistry,
    ) -> Self {
        Self {
            description: description.into(),
            remote_address: remote_address.into(),
            state: RwLock::new(ConnectionState::Negotiating),
            methods,
            targets: RwLock::new(HashMap::new()),
            connection_id,
            closed: AtomicBool::new(false),
            pending_results: Mutex::new(HashMap::new()),
            next_request_id: AtomicU64::new(1),
        }
    }

    /// Get the connection ID.
    pub fn connection_id(&self) -> u64 {
        self.connection_id
    }

    /// Get the description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get the remote address.
    pub fn remote_address(&self) -> &str {
        &self.remote_address
    }

    /// Get the current connection state.
    pub fn state(&self) -> ConnectionState {
        *self.state.read().unwrap()
    }

    /// Set the connection state.
    pub fn set_state(&self, state: ConnectionState) {
        *self.state.write().unwrap() = state;
    }

    /// Get the method registry.
    pub fn methods(&self) -> &RemoteMethodRegistry {
        &self.methods
    }

    /// Check if the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Whether the connection is currently busy (any target has an open transaction).
    pub fn is_busy(&self) -> bool {
        let targets = self.targets.read().unwrap();
        targets.values().any(|t| t.is_busy())
    }

    /// Whether a specific target has an open transaction.
    pub fn is_target_busy(&self, target_key: &TargetKey) -> bool {
        let targets = self.targets.read().unwrap();
        targets.get(target_key).map_or(false, |t| t.is_busy())
    }

    /// Publish a target from the back-end.
    pub fn publish_target(&self, key: TargetKey) -> Arc<TargetInfo> {
        let info = Arc::new(TargetInfo::new(key.clone()));
        let mut targets = self.targets.write().unwrap();
        targets.insert(key, info.clone());
        info
    }

    /// Withdraw a target.
    pub fn withdraw_target(&self, key: &TargetKey) -> Option<Arc<TargetInfo>> {
        let mut targets = self.targets.write().unwrap();
        targets.remove(key)
    }

    /// Get all published targets.
    pub fn get_targets(&self) -> Vec<Arc<TargetInfo>> {
        let targets = self.targets.read().unwrap();
        targets.values().cloned().collect()
    }

    /// Check if a key is a published target.
    pub fn is_target(&self, key: &TargetKey) -> bool {
        let targets = self.targets.read().unwrap();
        targets.contains_key(key)
    }

    /// Get the last snapshot for a target.
    pub fn get_last_snapshot(&self, key: &TargetKey) -> Option<u64> {
        let targets = self.targets.read().unwrap();
        targets.get(key).map(|t| t.get_last_snapshot())
    }

    /// Create an async method invocation result.
    pub fn invoke_async(
        &self,
        method_name: &str,
        _arguments: BTreeMap<String, serde_json::Value>,
    ) -> TraceRmiResult<RemoteAsyncResult> {
        if self.is_closed() {
            return Err(TraceRmiError::ConnectionClosed);
        }

        let method = self.methods.get(method_name);
        if method.is_none() {
            return Err(TraceRmiError::InvalidArguments(
                format!("Unknown method: {}", method_name),
            ));
        }

        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let result = RemoteAsyncResult::new(
            request_id,
            method_name,
            Duration::from_secs(30),
        );

        let mut pending = self.pending_results.lock().unwrap();
        pending.insert(request_id, result.clone());

        Ok(result)
    }

    /// Complete a pending async result.
    pub fn complete_request(&self, request_id: u64, value: serde_json::Value) {
        let mut pending = self.pending_results.lock().unwrap();
        if let Some(result) = pending.get_mut(&request_id) {
            result.complete(value);
        }
    }

    /// Fail a pending async result.
    pub fn fail_request(&self, request_id: u64, error: impl Into<String>) {
        let mut pending = self.pending_results.lock().unwrap();
        if let Some(result) = pending.get_mut(&request_id) {
            result.fail(error);
        }
    }

    /// Close the connection, withdrawing all targets.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.set_state(ConnectionState::Closed);

        let mut targets = self.targets.write().unwrap();
        targets.clear();

        let mut pending = self.pending_results.lock().unwrap();
        for result in pending.values_mut() {
            result.cancel();
        }
        pending.clear();
    }

    /// Force close transactions on a specific target.
    pub fn forcibly_close_transactions(&self, key: &TargetKey) {
        let targets = self.targets.read().unwrap();
        if let Some(target) = targets.get(key) {
            target.set_busy(false);
        }
    }

    /// Wait for the connection to be closed (with timeout).
    pub fn wait_closed(&self, timeout: Duration) -> bool {
        let start = Instant::now();
        while !self.is_closed() {
            if start.elapsed() > timeout {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        true
    }
}

/// A mock connection for testing.
#[derive(Debug)]
pub struct MockTraceRmiConnection {
    inner: TraceRmiConnectionImpl,
}

impl MockTraceRmiConnection {
    /// Create a mock connection with standard debug methods.
    pub fn new_debug() -> Self {
        let mut methods = RemoteMethodRegistry::new();
        methods.register(
            RemoteMethodDescriptor::new("step", super::action_name::ActionName::Step, "Step")
                .with_description("Single-step the target")
                .with_parameter(super::tracermi::RemoteParameter::optional(
                    "thread",
                    SchemaName::new("trace", "Thread"),
                    "Thread",
                    serde_json::Value::Null,
                )),
        );
        methods.register(
            RemoteMethodDescriptor::new(
                "continue",
                super::action_name::ActionName::Continue,
                "Continue",
            )
            .with_description("Resume execution"),
        );
        methods.register(
            RemoteMethodDescriptor::new(
                "execute",
                super::action_name::ActionName::Custom("execute".into()),
                "Execute",
            )
            .with_description("Execute a command")
            .with_parameter(super::tracermi::RemoteParameter::required(
                "cmd",
                SchemaName::new("primitive", "string"),
                "Command",
            ))
            .with_ret_type(SchemaName::new("primitive", "string")),
        );

        Self {
            inner: TraceRmiConnectionImpl::new(
                1,
                "Mock Debug Connection",
                "mock://localhost",
                methods,
            ),
        }
    }

    /// Get the inner connection.
    pub fn inner(&self) -> &TraceRmiConnectionImpl {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_key() {
        let key = TargetKey::new("trace-0");
        assert_eq!(key.as_str(), "trace-0");
        assert_eq!(key.to_string(), "trace-0");
    }

    #[test]
    fn test_target_info() {
        let info = TargetInfo::new(TargetKey::new("t1"));
        assert_eq!(info.get_last_snapshot(), 0);
        assert!(!info.is_busy());

        info.set_last_snapshot(42);
        assert_eq!(info.get_last_snapshot(), 42);

        info.set_busy(true);
        assert!(info.is_busy());
    }

    #[test]
    fn test_connection_lifecycle() {
        let conn = MockTraceRmiConnection::new_debug();
        let inner = conn.inner();

        assert_eq!(inner.connection_id(), 1);
        assert_eq!(inner.description(), "Mock Debug Connection");
        assert!(!inner.is_closed());
        assert_eq!(inner.state(), ConnectionState::Negotiating);

        inner.set_state(ConnectionState::Connected);
        assert_eq!(inner.state(), ConnectionState::Connected);
    }

    #[test]
    fn test_connection_methods() {
        let conn = MockTraceRmiConnection::new_debug();
        let inner = conn.inner();

        assert!(inner.methods().get("step").is_some());
        assert!(inner.methods().get("continue").is_some());
        assert!(inner.methods().get("execute").is_some());
        assert!(inner.methods().get("missing").is_none());
    }

    #[test]
    fn test_connection_targets() {
        let conn = MockTraceRmiConnection::new_debug();
        let inner = conn.inner();

        assert!(inner.get_targets().is_empty());

        let key = TargetKey::new("trace-0");
        inner.publish_target(key.clone());
        assert!(inner.is_target(&key));
        assert_eq!(inner.get_targets().len(), 1);
        assert!(!inner.is_busy());

        let snap = inner.get_last_snapshot(&key);
        assert_eq!(snap, Some(0));

        inner.withdraw_target(&key);
        assert!(!inner.is_target(&key));
    }

    #[test]
    fn test_connection_invoke() {
        let conn = MockTraceRmiConnection::new_debug();
        let inner = conn.inner();
        inner.set_state(ConnectionState::Connected);

        let args = BTreeMap::new();
        let result = inner.invoke_async("step", args);
        assert!(result.is_ok());

        let result = inner.invoke_async("missing", BTreeMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_connection_invoke_after_close() {
        let conn = MockTraceRmiConnection::new_debug();
        let inner = conn.inner();

        inner.close();
        assert!(inner.is_closed());
        assert_eq!(inner.state(), ConnectionState::Closed);

        let result = inner.invoke_async("step", BTreeMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_connection_busy() {
        let conn = MockTraceRmiConnection::new_debug();
        let inner = conn.inner();

        let key = TargetKey::new("t1");
        let info = inner.publish_target(key.clone());
        assert!(!inner.is_busy());

        info.set_busy(true);
        assert!(inner.is_busy());
        assert!(inner.is_target_busy(&key));

        inner.forcibly_close_transactions(&key);
        assert!(!inner.is_busy());
    }

    #[test]
    fn test_connection_close_clears_targets() {
        let conn = MockTraceRmiConnection::new_debug();
        let inner = conn.inner();

        inner.publish_target(TargetKey::new("t1"));
        inner.publish_target(TargetKey::new("t2"));
        assert_eq!(inner.get_targets().len(), 2);

        inner.close();
        assert!(inner.get_targets().is_empty());
        assert!(inner.is_closed());
    }

    #[test]
    fn test_connection_wait_closed() {
        let conn = MockTraceRmiConnection::new_debug();
        let inner = conn.inner();

        // Already closed
        inner.close();
        assert!(inner.wait_closed(Duration::from_millis(100)));
    }

    #[test]
    fn test_complete_and_fail_requests() {
        let conn = MockTraceRmiConnection::new_debug();
        let inner = conn.inner();
        inner.set_state(ConnectionState::Connected);

        let result = inner.invoke_async("step", BTreeMap::new()).unwrap();
        assert!(result.is_pending());

        inner.complete_request(result.request_id, serde_json::json!("ok"));
        let pending = inner.pending_results.lock().unwrap();
        let completed = pending.get(&result.request_id).unwrap();
        assert!(completed.is_completed());
        drop(pending);

        let result2 = inner.invoke_async("step", BTreeMap::new()).unwrap();
        inner.fail_request(result2.request_id, "error");
        let pending = inner.pending_results.lock().unwrap();
        let failed = pending.get(&result2.request_id).unwrap();
        assert_eq!(failed.status, AsyncStatus::Failed);
    }

    #[test]
    fn test_target_key_display() {
        let key = TargetKey::new("my-trace");
        assert_eq!(format!("{}", key), "my-trace");
    }
}
