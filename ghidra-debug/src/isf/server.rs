//! ISF server and connection handler.
//!
//! Ported from Ghidra's `ghidra.dbg.isf` package.
//!
//! The ISF server listens on a TCP port and handles protobuf-encoded
//! requests for data type information, serving as a bridge between
//! Ghidra's data type managers and external debug clients.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// ISF Error
// ---------------------------------------------------------------------------

/// An error from ISF processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsfError {
    /// Error code.
    pub code: i32,
    /// Error message.
    pub message: String,
}

impl IsfError {
    /// Create a new ISF error.
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// A generic internal error.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(500, message)
    }

    /// A not-found error.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(404, message)
    }
}

impl std::fmt::Display for IsfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ISF error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for IsfError {}

// ---------------------------------------------------------------------------
// ISF Message Types
// ---------------------------------------------------------------------------

/// Top-level message sent between ISF client and server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IsfRequest {
    /// List available namespaces.
    ListNamespaces,
    /// List data types in a namespace.
    ListTypes {
        /// The namespace.
        namespace: String,
    },
    /// Get a specific data type by name.
    GetType {
        /// The namespace.
        namespace: String,
        /// The type name.
        type_name: String,
    },
    /// Get all data types in a namespace.
    GetAllTypes {
        /// The namespace.
        namespace: String,
    },
    /// Ping (health check).
    Ping,
}

/// Response from the ISF server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IsfResponse {
    /// List of namespaces.
    Namespaces(Vec<String>),
    /// List of type names.
    TypeNames(Vec<String>),
    /// A single data type definition.
    TypeDef(IsfTypeDef),
    /// All data types.
    AllTypes(Vec<IsfTypeDef>),
    /// Pong.
    Pong,
    /// Error.
    Error(IsfError),
}

// ---------------------------------------------------------------------------
// ISF Type Definition
// ---------------------------------------------------------------------------

/// The kind of an ISF data type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsfTypeKind {
    /// Built-in type (int, float, void, etc.),
    BuiltIn,
    /// Structure or class.
    Composite,
    /// Enumeration.
    Enum,
    /// Pointer.
    Pointer,
    /// Typedef / alias.
    Typedef,
    /// Function signature.
    Function,
    /// Array.
    Array,
    /// Bit field.
    BitField,
}

/// A data type definition in ISF format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsfTypeDef {
    /// Unique type ID.
    pub type_id: u64,
    /// Type name.
    pub name: String,
    /// Type kind.
    pub kind: IsfTypeKind,
    /// Size in bytes (0 for void/incomplete types).
    pub size: u64,
    /// Alignment in bytes.
    pub alignment: u64,
    /// Components (fields, parameters, etc.).
    pub components: Vec<IsfComponent>,
    /// Additional properties.
    pub properties: BTreeMap<String, serde_json::Value>,
}

/// A component (field/parameter) of an ISF data type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsfComponent {
    /// Component name.
    pub name: String,
    /// Byte offset within the parent.
    pub offset: u64,
    /// The type ID of this component.
    pub type_id: u64,
    /// Size in bytes.
    pub size: u64,
}

// ---------------------------------------------------------------------------
// IsfClientHandler
// ---------------------------------------------------------------------------

/// Handles ISF protocol messages from a connected client.
///
/// Ported from Ghidra's `IsfClientHandler`.
#[derive(Debug, Clone, Default)]
pub struct IsfClientHandler {
    /// Available namespaces and their type definitions.
    pub namespaces: BTreeMap<String, Vec<IsfTypeDef>>,
    /// Global type ID counter.
    pub next_type_id: u64,
    /// Number of requests processed.
    pub requests_processed: u64,
}

impl IsfClientHandler {
    /// Create a new handler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a request and produce a response.
    pub fn process_message(&mut self, request: &IsfRequest) -> IsfResponse {
        self.requests_processed += 1;
        match request {
            IsfRequest::ListNamespaces => {
                IsfResponse::Namespaces(self.namespaces.keys().cloned().collect())
            }
            IsfRequest::ListTypes { namespace } => {
                match self.namespaces.get(namespace) {
                    Some(types) => {
                        IsfResponse::TypeNames(types.iter().map(|t| t.name.clone()).collect())
                    }
                    None => IsfResponse::Error(IsfError::not_found(format!(
                        "Namespace '{}' not found",
                        namespace
                    ))),
                }
            }
            IsfRequest::GetType {
                namespace,
                type_name,
            } => match self.namespaces.get(namespace) {
                Some(types) => match types.iter().find(|t| t.name == *type_name) {
                    Some(t) => IsfResponse::TypeDef(t.clone()),
                    None => IsfResponse::Error(IsfError::not_found(format!(
                        "Type '{}' not found in namespace '{}'",
                        type_name, namespace
                    ))),
                },
                None => IsfResponse::Error(IsfError::not_found(format!(
                    "Namespace '{}' not found",
                    namespace
                ))),
            },
            IsfRequest::GetAllTypes { namespace } => match self.namespaces.get(namespace) {
                Some(types) => IsfResponse::AllTypes(types.clone()),
                None => IsfResponse::Error(IsfError::not_found(format!(
                    "Namespace '{}' not found",
                    namespace
                ))),
            },
            IsfRequest::Ping => IsfResponse::Pong,
        }
    }

    /// Add a type definition.
    pub fn add_type(&mut self, namespace: impl Into<String>, type_def: IsfTypeDef) {
        self.namespaces
            .entry(namespace.into())
            .or_default()
            .push(type_def);
    }

    /// Allocate a new type ID.
    pub fn alloc_type_id(&mut self) -> u64 {
        let id = self.next_type_id;
        self.next_type_id += 1;
        id
    }
}

// ---------------------------------------------------------------------------
// IsfConnectionHandler
// ---------------------------------------------------------------------------

/// A connection handler that reads ISF requests and dispatches them.
///
/// Ported from Ghidra's `IsfConnectionHandler`.
#[derive(Debug, Clone)]
pub struct IsfConnectionHandler {
    /// Remote address.
    pub remote_address: String,
    /// Whether this connection is active.
    pub active: bool,
    /// Number of messages processed on this connection.
    pub messages_processed: u64,
}

impl IsfConnectionHandler {
    /// Create a new connection handler.
    pub fn new(remote_address: impl Into<String>) -> Self {
        Self {
            remote_address: remote_address.into(),
            active: true,
            messages_processed: 0,
        }
    }

    /// Close this connection.
    pub fn close(&mut self) {
        self.active = false;
    }

    /// Record that a message was processed.
    pub fn record_message(&mut self) {
        self.messages_processed += 1;
    }
}

// ---------------------------------------------------------------------------
// IsfServer
// ---------------------------------------------------------------------------

/// Configuration for the ISF server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsfServerConfig {
    /// The port to listen on.
    pub port: u16,
    /// Bind address.
    pub bind_address: String,
    /// Maximum number of concurrent connections.
    pub max_connections: usize,
}

impl Default for IsfServerConfig {
    fn default() -> Self {
        Self {
            port: 54321,
            bind_address: "127.0.0.1".into(),
            max_connections: 10,
        }
    }
}

/// The ISF server.
///
/// Ported from Ghidra's `IsfServer`. Listens for connections and serves
/// data type information through the ISF protocol.
#[derive(Debug, Clone)]
pub struct IsfServer {
    /// Server configuration.
    pub config: IsfServerConfig,
    /// The client handler (shared state).
    pub handler: IsfClientHandler,
    /// Active connection handlers.
    pub connections: Vec<IsfConnectionHandler>,
    /// Whether the server is running.
    pub running: bool,
}

impl IsfServer {
    /// Create a new ISF server.
    pub fn new(config: IsfServerConfig) -> Self {
        Self {
            config,
            handler: IsfClientHandler::new(),
            connections: Vec::new(),
            running: false,
        }
    }

    /// Start the server.
    pub fn start(&mut self) {
        self.running = true;
    }

    /// Stop the server.
    pub fn stop(&mut self) {
        self.running = false;
        for conn in &mut self.connections {
            conn.close();
        }
        self.connections.clear();
    }

    /// Accept a new connection.
    pub fn accept_connection(&mut self, remote_address: impl Into<String>) {
        self.connections
            .push(IsfConnectionHandler::new(remote_address));
    }

    /// The local address as a string.
    pub fn local_address(&self) -> String {
        format!("{}:{}", self.config.bind_address, self.config.port)
    }

    /// Number of active connections.
    pub fn connection_count(&self) -> usize {
        self.connections.iter().filter(|c| c.active).count()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isf_error() {
        let err = IsfError::not_found("type missing");
        assert_eq!(err.code, 404);
        assert!(err.to_string().contains("type missing"));
    }

    #[test]
    fn test_isf_client_handler_ping() {
        let mut handler = IsfClientHandler::new();
        let resp = handler.process_message(&IsfRequest::Ping);
        assert!(matches!(resp, IsfResponse::Pong));
        assert_eq!(handler.requests_processed, 1);
    }

    #[test]
    fn test_isf_client_handler_namespaces() {
        let mut handler = IsfClientHandler::new();
        handler.add_type("linux", IsfTypeDef {
            type_id: 1,
            name: "task_struct".into(),
            kind: IsfTypeKind::Composite,
            size: 6000,
            alignment: 8,
            components: vec![],
            properties: BTreeMap::new(),
        });

        let resp = handler.process_message(&IsfRequest::ListNamespaces);
        if let IsfResponse::Namespaces(names) = resp {
            assert!(names.contains(&"linux".to_string()));
        } else {
            panic!("Expected Namespaces response");
        }
    }

    #[test]
    fn test_isf_client_handler_get_type() {
        let mut handler = IsfClientHandler::new();
        handler.add_type("linux", IsfTypeDef {
            type_id: 1,
            name: "pid_t".into(),
            kind: IsfTypeKind::BuiltIn,
            size: 4,
            alignment: 4,
            components: vec![],
            properties: BTreeMap::new(),
        });

        let resp = handler.process_message(&IsfRequest::GetType {
            namespace: "linux".into(),
            type_name: "pid_t".into(),
        });
        if let IsfResponse::TypeDef(td) = resp {
            assert_eq!(td.name, "pid_t");
            assert_eq!(td.kind, IsfTypeKind::BuiltIn);
        } else {
            panic!("Expected TypeDef response");
        }
    }

    #[test]
    fn test_isf_client_handler_get_type_not_found() {
        let mut handler = IsfClientHandler::new();
        let resp = handler.process_message(&IsfRequest::GetType {
            namespace: "linux".into(),
            type_name: "nonexistent".into(),
        });
        assert!(matches!(resp, IsfResponse::Error(_)));
    }

    #[test]
    fn test_isf_client_handler_namespace_not_found() {
        let mut handler = IsfClientHandler::new();
        let resp = handler.process_message(&IsfRequest::ListTypes {
            namespace: "nonexistent".into(),
        });
        assert!(matches!(resp, IsfResponse::Error(_)));
    }

    #[test]
    fn test_isf_client_handler_get_all_types() {
        let mut handler = IsfClientHandler::new();
        handler.add_type("ns", IsfTypeDef {
            type_id: 1,
            name: "int".into(),
            kind: IsfTypeKind::BuiltIn,
            size: 4,
            alignment: 4,
            components: vec![],
            properties: BTreeMap::new(),
        });
        handler.add_type("ns", IsfTypeDef {
            type_id: 2,
            name: "char".into(),
            kind: IsfTypeKind::BuiltIn,
            size: 1,
            alignment: 1,
            components: vec![],
            properties: BTreeMap::new(),
        });

        let resp = handler.process_message(&IsfRequest::GetAllTypes {
            namespace: "ns".into(),
        });
        if let IsfResponse::AllTypes(types) = resp {
            assert_eq!(types.len(), 2);
        } else {
            panic!("Expected AllTypes response");
        }
    }

    #[test]
    fn test_isf_type_def() {
        let td = IsfTypeDef {
            type_id: 1,
            name: "point_t".into(),
            kind: IsfTypeKind::Composite,
            size: 8,
            alignment: 4,
            components: vec![
                IsfComponent {
                    name: "x".into(),
                    offset: 0,
                    type_id: 2,
                    size: 4,
                },
                IsfComponent {
                    name: "y".into(),
                    offset: 4,
                    type_id: 2,
                    size: 4,
                },
            ],
            properties: BTreeMap::new(),
        };
        assert_eq!(td.components.len(), 2);
        assert_eq!(td.components[0].offset, 0);
        assert_eq!(td.components[1].offset, 4);
    }

    #[test]
    fn test_isf_connection_handler() {
        let mut conn = IsfConnectionHandler::new("10.0.0.1:1234");
        assert!(conn.active);
        conn.record_message();
        conn.record_message();
        assert_eq!(conn.messages_processed, 2);
        conn.close();
        assert!(!conn.active);
    }

    #[test]
    fn test_isf_server() {
        let config = IsfServerConfig {
            port: 54321,
            bind_address: "127.0.0.1".into(),
            max_connections: 5,
        };
        let mut server = IsfServer::new(config);
        assert!(!server.running);
        assert_eq!(server.local_address(), "127.0.0.1:54321");

        server.start();
        assert!(server.running);

        server.accept_connection("10.0.0.1:9999");
        assert_eq!(server.connection_count(), 1);

        server.stop();
        assert!(!server.running);
        assert_eq!(server.connection_count(), 0);
    }

    #[test]
    fn test_isf_server_handler_shared_state() {
        let mut server = IsfServer::new(IsfServerConfig::default());
        server.handler.add_type("test", IsfTypeDef {
            type_id: 1,
            name: "my_type".into(),
            kind: IsfTypeKind::BuiltIn,
            size: 4,
            alignment: 4,
            components: vec![],
            properties: BTreeMap::new(),
        });

        let resp = server.handler.process_message(&IsfRequest::GetType {
            namespace: "test".into(),
            type_name: "my_type".into(),
        });
        assert!(matches!(resp, IsfResponse::TypeDef(_)));
    }

    #[test]
    fn test_type_id_allocation() {
        let mut handler = IsfClientHandler::new();
        assert_eq!(handler.alloc_type_id(), 0);
        assert_eq!(handler.alloc_type_id(), 1);
        assert_eq!(handler.alloc_type_id(), 2);
    }

    #[test]
    fn test_isf_type_kind_variants() {
        let kinds = [
            IsfTypeKind::BuiltIn,
            IsfTypeKind::Composite,
            IsfTypeKind::Enum,
            IsfTypeKind::Pointer,
            IsfTypeKind::Typedef,
            IsfTypeKind::Function,
            IsfTypeKind::Array,
            IsfTypeKind::BitField,
        ];
        for kind in &kinds {
            // Ensure each variant can be serialized/deserialized
            let json = serde_json::to_string(kind).unwrap();
            let back: IsfTypeKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }
}
