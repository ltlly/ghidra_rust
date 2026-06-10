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

    /// A bad-request error.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(400, message)
    }

    /// A not-supported error.
    pub fn not_supported(message: impl Into<String>) -> Self {
        Self::new(501, message)
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

/// Top-level request sent from an ISF client to the server.
///
/// Ported from the protobuf `RootMessage.MsgCase` in Ghidra's ISF protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IsfRequest {
    /// Health-check ping.
    Ping,
    /// List available namespaces (data type managers).
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
    /// Full ISF JSON export of a namespace (types + symbols).
    FullExport {
        /// The namespace to export.
        namespace: String,
    },
    /// Look up a specific type by key within a namespace.
    LookType {
        /// The namespace.
        namespace: String,
        /// The type key / path name.
        key: String,
    },
    /// Look up a symbol by name within a namespace.
    LookSymbol {
        /// The namespace.
        namespace: String,
        /// The symbol name.
        key: String,
    },
    /// Look up a symbol by address within a namespace.
    LookAddress {
        /// The namespace.
        namespace: String,
        /// The address key (hex string).
        key: String,
    },
    /// Enumerate all types in a namespace.
    EnumTypes {
        /// The namespace.
        namespace: String,
    },
    /// Enumerate all symbols in a namespace.
    EnumSymbols {
        /// The namespace.
        namespace: String,
    },
}

/// Response from the ISF server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IsfResponse {
    /// Pong reply to a Ping.
    Pong,
    /// List of namespaces.
    Namespaces(Vec<String>),
    /// List of type names.
    TypeNames(Vec<String>),
    /// A single data type definition.
    TypeDef(IsfTypeDef),
    /// All data types.
    AllTypes(Vec<IsfTypeDef>),
    /// Full ISF JSON export string.
    FullExport(String),
    /// Look-up result as ISF JSON string.
    LookTypeResult(String),
    /// Symbol look-up result as ISF JSON string.
    LookSymbolResult(String),
    /// Address look-up result as ISF JSON string.
    LookAddressResult(String),
    /// Enumerated types as ISF JSON string.
    EnumTypesResult(String),
    /// Enumerated symbols as ISF JSON string.
    EnumSymbolsResult(String),
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
// IsfClientHandler (synchronous, non-network version)
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
            IsfRequest::FullExport { namespace } => match self.namespaces.get(namespace) {
                Some(types) => {
                    let json = self.export_namespace_json(namespace, types);
                    IsfResponse::FullExport(json)
                }
                None => IsfResponse::Error(IsfError::not_found(format!(
                    "Namespace '{}' not found",
                    namespace
                ))),
            },
            IsfRequest::LookType { namespace, key } => match self.namespaces.get(namespace) {
                Some(types) => match types.iter().find(|t| t.name == *key) {
                    Some(td) => {
                        let json = serde_json::to_string(td)
                            .unwrap_or_else(|_| "{}".to_string());
                        IsfResponse::LookTypeResult(json)
                    }
                    None => IsfResponse::Error(IsfError::not_found(format!(
                        "Type '{}' not found in namespace '{}'",
                        key, namespace
                    ))),
                },
                None => IsfResponse::Error(IsfError::not_found(format!(
                    "Namespace '{}' not found",
                    namespace
                ))),
            },
            IsfRequest::LookSymbol { namespace: _, key: _ } => {
                // Symbols are not yet stored in the type store; return empty.
                IsfResponse::LookSymbolResult("{}".to_string())
            }
            IsfRequest::LookAddress { namespace: _, key: _ } => {
                // Address look-up requires a program model; return empty.
                IsfResponse::LookAddressResult("{}".to_string())
            }
            IsfRequest::EnumTypes { namespace } => match self.namespaces.get(namespace) {
                Some(types) => {
                    let json = self.export_namespace_json(namespace, types);
                    IsfResponse::EnumTypesResult(json)
                }
                None => IsfResponse::Error(IsfError::not_found(format!(
                    "Namespace '{}' not found",
                    namespace
                ))),
            },
            IsfRequest::EnumSymbols { namespace: _ } => {
                IsfResponse::EnumSymbolsResult("{}".to_string())
            }
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

    /// Export a namespace as an ISF JSON string.
    fn export_namespace_json(
        &self,
        namespace: &str,
        types: &[IsfTypeDef],
    ) -> String {
        let mut base_types = serde_json::Map::new();
        let mut user_types = serde_json::Map::new();
        let mut enums_map = serde_json::Map::new();

        for td in types {
            let json_val = serde_json::to_value(td).unwrap_or(serde_json::Value::Null);
            match td.kind {
                IsfTypeKind::BuiltIn | IsfTypeKind::Pointer => {
                    base_types.insert(td.name.clone(), json_val);
                }
                IsfTypeKind::Enum => {
                    enums_map.insert(td.name.clone(), json_val);
                }
                _ => {
                    user_types.insert(td.name.clone(), json_val);
                }
            }
        }

        let mut root = serde_json::Map::new();
        root.insert(
            "metadata".to_string(),
            serde_json::json!({ "format": "6.2.0", "namespace": namespace }),
        );
        root.insert(
            "base_types".to_string(),
            serde_json::Value::Object(base_types),
        );
        root.insert(
            "user_types".to_string(),
            serde_json::Value::Object(user_types),
        );
        root.insert("enums".to_string(), serde_json::Value::Object(enums_map));
        root.insert("symbols".to_string(), serde_json::json!({}));

        serde_json::to_string(&root).unwrap_or_else(|_| "{}".to_string())
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
// IsfServer (non-network, synchronous version)
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
    fn test_isf_error_variants() {
        let err = IsfError::internal("oops");
        assert_eq!(err.code, 500);

        let err = IsfError::bad_request("bad");
        assert_eq!(err.code, 400);

        let err = IsfError::not_supported("nope");
        assert_eq!(err.code, 501);
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
    fn test_isf_client_handler_full_export() {
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

        let resp = handler.process_message(&IsfRequest::FullExport {
            namespace: "ns".into(),
        });
        if let IsfResponse::FullExport(json) = resp {
            assert!(json.contains("base_types"));
            assert!(json.contains("int"));
            assert!(json.contains("metadata"));
        } else {
            panic!("Expected FullExport response");
        }
    }

    #[test]
    fn test_isf_client_handler_look_type() {
        let mut handler = IsfClientHandler::new();
        handler.add_type("ns", IsfTypeDef {
            type_id: 1,
            name: "my_type".into(),
            kind: IsfTypeKind::Composite,
            size: 16,
            alignment: 8,
            components: vec![],
            properties: BTreeMap::new(),
        });

        let resp = handler.process_message(&IsfRequest::LookType {
            namespace: "ns".into(),
            key: "my_type".into(),
        });
        if let IsfResponse::LookTypeResult(json) = resp {
            assert!(json.contains("my_type"));
        } else {
            panic!("Expected LookTypeResult response");
        }
    }

    #[test]
    fn test_isf_client_handler_look_type_not_found() {
        let mut handler = IsfClientHandler::new();
        let resp = handler.process_message(&IsfRequest::LookType {
            namespace: "ns".into(),
            key: "missing".into(),
        });
        assert!(matches!(resp, IsfResponse::Error(_)));
    }

    #[test]
    fn test_isf_client_handler_enum_types() {
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

        let resp = handler.process_message(&IsfRequest::EnumTypes {
            namespace: "ns".into(),
        });
        if let IsfResponse::EnumTypesResult(json) = resp {
            assert!(json.contains("base_types"));
        } else {
            panic!("Expected EnumTypesResult response");
        }
    }

    #[test]
    fn test_isf_client_handler_enum_symbols() {
        let mut handler = IsfClientHandler::new();
        let resp = handler.process_message(&IsfRequest::EnumSymbols {
            namespace: "ns".into(),
        });
        if let IsfResponse::EnumSymbolsResult(json) = resp {
            assert_eq!(json, "{}");
        } else {
            panic!("Expected EnumSymbolsResult response");
        }
    }

    #[test]
    fn test_isf_client_handler_look_symbol() {
        let mut handler = IsfClientHandler::new();
        let resp = handler.process_message(&IsfRequest::LookSymbol {
            namespace: "ns".into(),
            key: "main".into(),
        });
        if let IsfResponse::LookSymbolResult(json) = resp {
            assert_eq!(json, "{}");
        } else {
            panic!("Expected LookSymbolResult response");
        }
    }

    #[test]
    fn test_isf_client_handler_look_address() {
        let mut handler = IsfClientHandler::new();
        let resp = handler.process_message(&IsfRequest::LookAddress {
            namespace: "ns".into(),
            key: "0x401000".into(),
        });
        if let IsfResponse::LookAddressResult(json) = resp {
            assert_eq!(json, "{}");
        } else {
            panic!("Expected LookAddressResult response");
        }
    }

    #[test]
    fn test_isf_client_handler_full_export_not_found() {
        let mut handler = IsfClientHandler::new();
        let resp = handler.process_message(&IsfRequest::FullExport {
            namespace: "missing".into(),
        });
        assert!(matches!(resp, IsfResponse::Error(_)));
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

    #[test]
    fn test_export_namespace_json_categorization() {
        let mut handler = IsfClientHandler::new();
        handler.add_type("ns", IsfTypeDef {
            type_id: 1, name: "int".into(), kind: IsfTypeKind::BuiltIn,
            size: 4, alignment: 4, components: vec![], properties: BTreeMap::new(),
        });
        handler.add_type("ns", IsfTypeDef {
            type_id: 2, name: "my_struct".into(), kind: IsfTypeKind::Composite,
            size: 16, alignment: 8, components: vec![], properties: BTreeMap::new(),
        });
        handler.add_type("ns", IsfTypeDef {
            type_id: 3, name: "color".into(), kind: IsfTypeKind::Enum,
            size: 4, alignment: 4, components: vec![], properties: BTreeMap::new(),
        });
        handler.add_type("ns", IsfTypeDef {
            type_id: 4, name: "int_ptr".into(), kind: IsfTypeKind::Pointer,
            size: 8, alignment: 8, components: vec![], properties: BTreeMap::new(),
        });

        let types = handler.namespaces.get("ns").unwrap();
        let json = handler.export_namespace_json("ns", types);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // base_types should contain int and int_ptr
        let base = parsed.get("base_types").unwrap().as_object().unwrap();
        assert!(base.contains_key("int"));
        assert!(base.contains_key("int_ptr"));

        // user_types should contain my_struct
        let user = parsed.get("user_types").unwrap().as_object().unwrap();
        assert!(user.contains_key("my_struct"));

        // enums should contain color
        let enums = parsed.get("enums").unwrap().as_object().unwrap();
        assert!(enums.contains_key("color"));
    }
}
