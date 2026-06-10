//! ISF client handler for per-connection message processing.
//!
//! Ported from Ghidra's `IsfClientHandler` in the `ghidra.dbg.isf` package.
//!
//! Each connected client gets its own handler instance that manages:
//! - Protocol state (handshake, active, closed)
//! - Message framing (length-prefixed JSON over TCP)
//! - Request dispatch against a shared data type store
//! - Connection lifecycle and statistics

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;

use super::server::{IsfComponent, IsfError, IsfRequest, IsfResponse, IsfTypeDef, IsfTypeKind};

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Magic bytes sent by the client to initiate an ISF session.
const ISF_MAGIC: &[u8; 4] = b"ISF\x00";

/// Protocol version supported by this handler.
const PROTOCOL_VERSION: u32 = 1;

/// Maximum message size in bytes (16 MiB).
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// ClientHandlerError
// ---------------------------------------------------------------------------

/// Errors that can occur during client handler operations.
#[derive(Debug)]
pub enum ClientHandlerError {
    /// I/O error on the underlying stream.
    Io(io::Error),
    /// Message exceeds the maximum allowed size.
    MessageTooLarge { size: usize, max: usize },
    /// Invalid magic bytes during handshake.
    InvalidMagic([u8; 4]),
    /// Unsupported protocol version.
    UnsupportedVersion(u32),
    /// Serialization / deserialization error.
    Serde(serde_json::Error),
    /// The connection was closed by the remote end.
    ConnectionClosed,
}

impl fmt::Display for ClientHandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "ISF client I/O error: {}", e),
            Self::MessageTooLarge { size, max } => {
                write!(f, "ISF message too large: {} bytes (max {})", size, max)
            }
            Self::InvalidMagic(bytes) => {
                write!(
                    f,
                    "Invalid ISF magic bytes: {:02x} {:02x} {:02x} {:02x}",
                    bytes[0], bytes[1], bytes[2], bytes[3]
                )
            }
            Self::UnsupportedVersion(v) => {
                write!(f, "Unsupported ISF protocol version: {}", v)
            }
            Self::Serde(e) => write!(f, "ISF serde error: {}", e),
            Self::ConnectionClosed => write!(f, "ISF connection closed by remote"),
        }
    }
}

impl std::error::Error for ClientHandlerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Serde(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ClientHandlerError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for ClientHandlerError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serde(e)
    }
}

// ---------------------------------------------------------------------------
// Connection state
// ---------------------------------------------------------------------------

/// The state of a client handler's connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandlerState {
    /// Waiting for the handshake magic bytes and version.
    Handshake,
    /// Actively processing requests.
    Active,
    /// Connection has been closed.
    Closed,
}

// ---------------------------------------------------------------------------
// IsfClientHandler
// ---------------------------------------------------------------------------

/// Handles ISF protocol messages for a single connected client.
///
/// Ported from Ghidra's `IsfClientHandler`. Each instance wraps a TCP
/// stream and maintains its own protocol state. The handler processes
/// length-prefixed JSON messages and dispatches them to the shared data
/// type store.
///
/// # Protocol
///
/// 1. Client sends 4-byte magic (`ISF\x00`) + 4-byte version (big-endian u32).
/// 2. Server responds with a `HandshakeAck` (version echo + status).
/// 3. Client sends requests as: 4-byte length (big-endian u32) + JSON payload.
/// 4. Server responds with the same framing for each response.
#[derive(Debug)]
pub struct IsfClientHandler {
    /// Unique handler ID assigned by the server.
    pub handler_id: u64,
    /// Remote peer address.
    pub remote_addr: String,
    /// Current connection state.
    pub state: HandlerState,
    /// The underlying TCP stream (None after close).
    stream: Option<TcpStream>,
    /// Data type store: namespace -> type definitions.
    types: BTreeMap<String, Vec<IsfTypeDef>>,
    /// Counter for allocated type IDs.
    next_type_id: u64,
    /// Total requests processed by this handler.
    pub requests_processed: u64,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Total bytes sent.
    pub bytes_sent: u64,
}

impl IsfClientHandler {
    /// Create a new handler for an accepted TCP stream.
    pub fn new(handler_id: u64, stream: TcpStream) -> io::Result<Self> {
        let remote_addr = stream.peer_addr()?.to_string();
        Ok(Self {
            handler_id,
            remote_addr,
            state: HandlerState::Handshake,
            stream: Some(stream),
            types: BTreeMap::new(),
            next_type_id: 0,
            requests_processed: 0,
            bytes_received: 0,
            bytes_sent: 0,
        })
    }

    // -- Data store operations -------------------------------------------------

    /// Add a type definition to a namespace.
    pub fn add_type(&mut self, namespace: impl Into<String>, type_def: IsfTypeDef) {
        self.types.entry(namespace.into()).or_default().push(type_def);
    }

    /// Allocate a new unique type ID.
    pub fn alloc_type_id(&mut self) -> u64 {
        let id = self.next_type_id;
        self.next_type_id += 1;
        id
    }

    /// Get a reference to the type store.
    pub fn types(&self) -> &BTreeMap<String, Vec<IsfTypeDef>> {
        &self.types
    }

    /// Get a mutable reference to the type store.
    pub fn types_mut(&mut self) -> &mut BTreeMap<String, Vec<IsfTypeDef>> {
        &mut self.types
    }

    // -- Protocol operations ---------------------------------------------------

    /// Perform the server-side handshake with the client.
    ///
    /// Reads the magic bytes and version, then sends back an acknowledgment.
    /// On success the handler transitions to `Active` state.
    pub fn handshake(&mut self) -> Result<(), ClientHandlerError> {
        let stream = self.stream.as_mut().ok_or(ClientHandlerError::ConnectionClosed)?;

        // Read 4 bytes magic
        let mut magic = [0u8; 4];
        stream.read_exact(&mut magic)?;
        self.bytes_received += 4;

        if magic != *ISF_MAGIC {
            return Err(ClientHandlerError::InvalidMagic(magic));
        }

        // Read 4 bytes version (big-endian)
        let mut ver_buf = [0u8; 4];
        stream.read_exact(&mut ver_buf)?;
        self.bytes_received += 4;
        let version = u32::from_be_bytes(ver_buf);

        if version > PROTOCOL_VERSION {
            return Err(ClientHandlerError::UnsupportedVersion(version));
        }

        // Send ack: version (4 bytes) + status ok (1 byte)
        let ack_version = version.min(PROTOCOL_VERSION);
        stream.write_all(&ack_version.to_be_bytes())?;
        stream.write_all(&[0u8])?; // status OK
        stream.flush()?;
        self.bytes_sent += 5;

        self.state = HandlerState::Active;
        Ok(())
    }

    /// Read a single ISF request from the stream.
    ///
    /// Returns `None` if the connection was cleanly closed.
    pub fn read_request(&mut self) -> Result<Option<IsfRequest>, ClientHandlerError> {
        let stream = self.stream.as_mut().ok_or(ClientHandlerError::ConnectionClosed)?;

        // Read 4-byte length prefix
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                self.state = HandlerState::Closed;
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        }
        self.bytes_received += 4;

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_MESSAGE_SIZE {
            return Err(ClientHandlerError::MessageTooLarge {
                size: len,
                max: MAX_MESSAGE_SIZE,
            });
        }

        // Read the JSON payload
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;
        self.bytes_received += len as u64;

        let request: IsfRequest = serde_json::from_slice(&buf)?;
        Ok(Some(request))
    }

    /// Write an ISF response to the stream.
    pub fn write_response(&mut self, response: &IsfResponse) -> Result<(), ClientHandlerError> {
        let stream = self.stream.as_mut().ok_or(ClientHandlerError::ConnectionClosed)?;

        let payload = serde_json::to_vec(response)?;
        let len = (payload.len() as u32).to_be_bytes();
        stream.write_all(&len)?;
        stream.write_all(&payload)?;
        stream.flush()?;
        self.bytes_sent += 4 + payload.len() as u64;

        Ok(())
    }

    /// Process a single request: read from stream, dispatch, write response.
    ///
    /// Returns `Ok(true)` if a request was processed, `Ok(false)` if the
    /// connection was closed.
    pub fn process_next(&mut self) -> Result<bool, ClientHandlerError> {
        let request = match self.read_request()? {
            Some(r) => r,
            None => return Ok(false),
        };

        let response = self.dispatch(&request);
        self.write_response(&response)?;
        self.requests_processed += 1;
        Ok(true)
    }

    /// Run the handler's main loop: handshake, then process requests until close.
    ///
    /// Returns the total number of requests processed.
    pub fn run(&mut self) -> Result<u64, ClientHandlerError> {
        self.handshake()?;

        loop {
            if !self.process_next()? {
                break;
            }
        }

        Ok(self.requests_processed)
    }

    /// Dispatch a request against the local type store and produce a response.
    pub fn dispatch(&self, request: &IsfRequest) -> IsfResponse {
        match request {
            IsfRequest::ListNamespaces => {
                IsfResponse::Namespaces(self.types.keys().cloned().collect())
            }
            IsfRequest::ListTypes { namespace } => match self.types.get(namespace) {
                Some(type_list) => {
                    IsfResponse::TypeNames(type_list.iter().map(|t| t.name.clone()).collect())
                }
                None => IsfResponse::Error(IsfError::not_found(format!(
                    "Namespace '{}' not found",
                    namespace
                ))),
            },
            IsfRequest::GetType {
                namespace,
                type_name,
            } => match self.types.get(namespace) {
                Some(type_list) => match type_list.iter().find(|t| t.name == *type_name) {
                    Some(td) => IsfResponse::TypeDef(td.clone()),
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
            IsfRequest::GetAllTypes { namespace } => match self.types.get(namespace) {
                Some(type_list) => IsfResponse::AllTypes(type_list.clone()),
                None => IsfResponse::Error(IsfError::not_found(format!(
                    "Namespace '{}' not found",
                    namespace
                ))),
            },
            IsfRequest::Ping => IsfResponse::Pong,
        }
    }

    /// Close the handler's stream and transition to `Closed` state.
    pub fn close(&mut self) {
        self.stream = None;
        self.state = HandlerState::Closed;
    }

    /// Whether the handler is in `Active` state.
    pub fn is_active(&self) -> bool {
        self.state == HandlerState::Active
    }

    /// Whether the handler is in `Closed` state.
    pub fn is_closed(&self) -> bool {
        self.state == HandlerState::Closed
    }

    // -- Builder / convenience -------------------------------------------------

    /// Create a built-in type definition and add it to the given namespace.
    pub fn add_builtin(
        &mut self,
        namespace: impl Into<String>,
        name: impl Into<String>,
        size: u64,
        is_signed: bool,
        is_float: bool,
    ) -> u64 {
        let id = self.alloc_type_id();
        let mut props = BTreeMap::new();
        props.insert("signed".into(), serde_json::json!(is_signed));
        props.insert("float".into(), serde_json::json!(is_float));

        self.add_type(
            namespace,
            IsfTypeDef {
                type_id: id,
                name: name.into(),
                kind: IsfTypeKind::BuiltIn,
                size,
                alignment: size,
                components: vec![],
                properties: props,
            },
        );
        id
    }

    /// Create a composite (struct/union) type definition.
    pub fn add_composite(
        &mut self,
        namespace: impl Into<String>,
        name: impl Into<String>,
        size: u64,
        alignment: u64,
        is_union: bool,
        fields: Vec<IsfComponent>,
    ) -> u64 {
        let id = self.alloc_type_id();
        let mut props = BTreeMap::new();
        props.insert("union".into(), serde_json::json!(is_union));

        self.add_type(
            namespace,
            IsfTypeDef {
                type_id: id,
                name: name.into(),
                kind: IsfTypeKind::Composite,
                size,
                alignment,
                components: fields,
                properties: props,
            },
        );
        id
    }

    /// Create an enumeration type definition.
    pub fn add_enum(
        &mut self,
        namespace: impl Into<String>,
        name: impl Into<String>,
        size: u64,
        values: BTreeMap<String, i64>,
    ) -> u64 {
        let id = self.alloc_type_id();
        let mut props = BTreeMap::new();
        for (k, v) in &values {
            props.insert(format!("enum.{}", k), serde_json::json!(v));
        }

        self.add_type(
            namespace,
            IsfTypeDef {
                type_id: id,
                name: name.into(),
                kind: IsfTypeKind::Enum,
                size,
                alignment: size,
                components: vec![],
                properties: props,
            },
        );
        id
    }

    /// Create a pointer type definition.
    pub fn add_pointer(
        &mut self,
        namespace: impl Into<String>,
        name: impl Into<String>,
        size: u64,
        pointee_type_id: u64,
    ) -> u64 {
        let id = self.alloc_type_id();
        let mut props = BTreeMap::new();
        props.insert("pointee".into(), serde_json::json!(pointee_type_id));

        self.add_type(
            namespace,
            IsfTypeDef {
                type_id: id,
                name: name.into(),
                kind: IsfTypeKind::Pointer,
                size,
                alignment: size,
                components: vec![],
                properties: props,
            },
        );
        id
    }

    /// Create a typedef definition.
    pub fn add_typedef(
        &mut self,
        namespace: impl Into<String>,
        name: impl Into<String>,
        base_type_id: u64,
        size: u64,
    ) -> u64 {
        let id = self.alloc_type_id();
        let mut props = BTreeMap::new();
        props.insert("base".into(), serde_json::json!(base_type_id));

        self.add_type(
            namespace,
            IsfTypeDef {
                type_id: id,
                name: name.into(),
                kind: IsfTypeKind::Typedef,
                size,
                alignment: 1,
                components: vec![],
                properties: props,
            },
        );
        id
    }

    /// Create a function signature type definition.
    pub fn add_function(
        &mut self,
        namespace: impl Into<String>,
        name: impl Into<String>,
        return_type_id: u64,
        parameters: Vec<IsfComponent>,
        is_variadic: bool,
        calling_convention: impl Into<String>,
    ) -> u64 {
        let id = self.alloc_type_id();
        let mut props = BTreeMap::new();
        props.insert("return_type".into(), serde_json::json!(return_type_id));
        props.insert("variadic".into(), serde_json::json!(is_variadic));
        props.insert(
            "calling_convention".into(),
            serde_json::json!(calling_convention.into()),
        );

        self.add_type(
            namespace,
            IsfTypeDef {
                type_id: id,
                name: name.into(),
                kind: IsfTypeKind::Function,
                size: 0,
                alignment: 0,
                components: parameters,
                properties: props,
            },
        );
        id
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a handler from a connected pair without actually doing
    /// the TCP handshake (for unit-testing dispatch logic).
    fn test_handler() -> IsfClientHandler {
        // We use a loopback pair for a realistic stream.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (stream, _) = listener.accept().unwrap();
        // Put the stream in non-blocking mode so tests don't hang.
        stream.set_nonblocking(true).unwrap();
        client.set_nonblocking(true).unwrap();
        IsfClientHandler::new(1, stream).unwrap()
    }

    #[test]
    fn test_handler_creation() {
        let h = test_handler();
        assert_eq!(h.state, HandlerState::Handshake);
        assert_eq!(h.handler_id, 1);
        assert_eq!(h.requests_processed, 0);
    }

    #[test]
    fn test_dispatch_ping() {
        let h = test_handler();
        let resp = h.dispatch(&IsfRequest::Ping);
        assert!(matches!(resp, IsfResponse::Pong));
    }

    #[test]
    fn test_dispatch_list_namespaces_empty() {
        let h = test_handler();
        let resp = h.dispatch(&IsfRequest::ListNamespaces);
        if let IsfResponse::Namespaces(ns) = resp {
            assert!(ns.is_empty());
        } else {
            panic!("Expected Namespaces");
        }
    }

    #[test]
    fn test_dispatch_list_namespaces() {
        let mut h = test_handler();
        h.add_type("linux", IsfTypeDef {
            type_id: 1,
            name: "task_struct".into(),
            kind: IsfTypeKind::Composite,
            size: 6000,
            alignment: 8,
            components: vec![],
            properties: BTreeMap::new(),
        });

        let resp = h.dispatch(&IsfRequest::ListNamespaces);
        if let IsfResponse::Namespaces(ns) = resp {
            assert!(ns.contains(&"linux".to_string()));
        } else {
            panic!("Expected Namespaces");
        }
    }

    #[test]
    fn test_dispatch_get_type() {
        let mut h = test_handler();
        h.add_type("linux", IsfTypeDef {
            type_id: 1,
            name: "pid_t".into(),
            kind: IsfTypeKind::BuiltIn,
            size: 4,
            alignment: 4,
            components: vec![],
            properties: BTreeMap::new(),
        });

        let resp = h.dispatch(&IsfRequest::GetType {
            namespace: "linux".into(),
            type_name: "pid_t".into(),
        });
        if let IsfResponse::TypeDef(td) = resp {
            assert_eq!(td.name, "pid_t");
            assert_eq!(td.kind, IsfTypeKind::BuiltIn);
        } else {
            panic!("Expected TypeDef");
        }
    }

    #[test]
    fn test_dispatch_get_type_not_found() {
        let h = test_handler();
        let resp = h.dispatch(&IsfRequest::GetType {
            namespace: "missing".into(),
            type_name: "nope".into(),
        });
        assert!(matches!(resp, IsfResponse::Error(_)));
    }

    #[test]
    fn test_dispatch_list_types() {
        let mut h = test_handler();
        h.add_type("ns", IsfTypeDef {
            type_id: 1,
            name: "int".into(),
            kind: IsfTypeKind::BuiltIn,
            size: 4,
            alignment: 4,
            components: vec![],
            properties: BTreeMap::new(),
        });
        h.add_type("ns", IsfTypeDef {
            type_id: 2,
            name: "char".into(),
            kind: IsfTypeKind::BuiltIn,
            size: 1,
            alignment: 1,
            components: vec![],
            properties: BTreeMap::new(),
        });

        let resp = h.dispatch(&IsfRequest::ListTypes {
            namespace: "ns".into(),
        });
        if let IsfResponse::TypeNames(names) = resp {
            assert_eq!(names.len(), 2);
            assert!(names.contains(&"int".to_string()));
            assert!(names.contains(&"char".to_string()));
        } else {
            panic!("Expected TypeNames");
        }
    }

    #[test]
    fn test_dispatch_get_all_types() {
        let mut h = test_handler();
        h.add_type("ns", IsfTypeDef {
            type_id: 1,
            name: "a".into(),
            kind: IsfTypeKind::BuiltIn,
            size: 4,
            alignment: 4,
            components: vec![],
            properties: BTreeMap::new(),
        });
        h.add_type("ns", IsfTypeDef {
            type_id: 2,
            name: "b".into(),
            kind: IsfTypeKind::BuiltIn,
            size: 8,
            alignment: 8,
            components: vec![],
            properties: BTreeMap::new(),
        });

        let resp = h.dispatch(&IsfRequest::GetAllTypes {
            namespace: "ns".into(),
        });
        if let IsfResponse::AllTypes(types) = resp {
            assert_eq!(types.len(), 2);
        } else {
            panic!("Expected AllTypes");
        }
    }

    #[test]
    fn test_alloc_type_id() {
        let mut h = test_handler();
        assert_eq!(h.alloc_type_id(), 0);
        assert_eq!(h.alloc_type_id(), 1);
        assert_eq!(h.alloc_type_id(), 2);
    }

    #[test]
    fn test_add_builtin_convenience() {
        let mut h = test_handler();
        let id = h.add_builtin("ns", "unsigned int", 4, false, false);
        assert_eq!(id, 0);

        let resp = h.dispatch(&IsfRequest::GetType {
            namespace: "ns".into(),
            type_name: "unsigned int".into(),
        });
        if let IsfResponse::TypeDef(td) = resp {
            assert_eq!(td.kind, IsfTypeKind::BuiltIn);
            assert_eq!(td.properties["signed"], serde_json::json!(false));
        } else {
            panic!("Expected TypeDef");
        }
    }

    #[test]
    fn test_add_composite_convenience() {
        let mut h = test_handler();
        let id = h.add_composite(
            "ns",
            "point_t",
            8,
            4,
            false,
            vec![
                IsfComponent { name: "x".into(), offset: 0, type_id: 1, size: 4 },
                IsfComponent { name: "y".into(), offset: 4, type_id: 1, size: 4 },
            ],
        );
        assert_eq!(id, 0);

        let resp = h.dispatch(&IsfRequest::GetAllTypes {
            namespace: "ns".into(),
        });
        if let IsfResponse::AllTypes(types) = resp {
            assert_eq!(types[0].components.len(), 2);
        } else {
            panic!("Expected AllTypes");
        }
    }

    #[test]
    fn test_add_enum_convenience() {
        let mut h = test_handler();
        let mut vals = BTreeMap::new();
        vals.insert("RED".into(), 0);
        vals.insert("GREEN".into(), 1);
        vals.insert("BLUE".into(), 2);
        let id = h.add_enum("ns", "color_t", 4, vals);
        assert_eq!(id, 0);

        let resp = h.dispatch(&IsfRequest::GetType {
            namespace: "ns".into(),
            type_name: "color_t".into(),
        });
        if let IsfResponse::TypeDef(td) = resp {
            assert_eq!(td.kind, IsfTypeKind::Enum);
            assert_eq!(td.properties["enum.RED"], serde_json::json!(0));
        } else {
            panic!("Expected TypeDef");
        }
    }

    #[test]
    fn test_add_pointer_convenience() {
        let mut h = test_handler();
        let id = h.add_pointer("ns", "int *", 8, 1);
        assert_eq!(id, 0);

        let resp = h.dispatch(&IsfRequest::GetType {
            namespace: "ns".into(),
            type_name: "int *".into(),
        });
        if let IsfResponse::TypeDef(td) = resp {
            assert_eq!(td.kind, IsfTypeKind::Pointer);
            assert_eq!(td.properties["pointee"], serde_json::json!(1));
        } else {
            panic!("Expected TypeDef");
        }
    }

    #[test]
    fn test_add_typedef_convenience() {
        let mut h = test_handler();
        let id = h.add_typedef("ns", "pid_t", 1, 4);
        assert_eq!(id, 0);

        let resp = h.dispatch(&IsfRequest::GetType {
            namespace: "ns".into(),
            type_name: "pid_t".into(),
        });
        if let IsfResponse::TypeDef(td) = resp {
            assert_eq!(td.kind, IsfTypeKind::Typedef);
            assert_eq!(td.properties["base"], serde_json::json!(1));
        } else {
            panic!("Expected TypeDef");
        }
    }

    #[test]
    fn test_add_function_convenience() {
        let mut h = test_handler();
        let id = h.add_function(
            "ns",
            "main",
            1,
            vec![IsfComponent { name: "argc".into(), offset: 0, type_id: 1, size: 4 }],
            false,
            "cdecl",
        );
        assert_eq!(id, 0);

        let resp = h.dispatch(&IsfRequest::GetType {
            namespace: "ns".into(),
            type_name: "main".into(),
        });
        if let IsfResponse::TypeDef(td) = resp {
            assert_eq!(td.kind, IsfTypeKind::Function);
            assert_eq!(td.components.len(), 1);
            assert_eq!(td.properties["variadic"], serde_json::json!(false));
            assert_eq!(td.properties["calling_convention"], serde_json::json!("cdecl"));
        } else {
            panic!("Expected TypeDef");
        }
    }

    #[test]
    fn test_close_transitions_to_closed() {
        let mut h = test_handler();
        assert_eq!(h.state, HandlerState::Handshake);
        h.close();
        assert_eq!(h.state, HandlerState::Closed);
        assert!(h.is_closed());
        assert!(!h.is_active());
    }

    #[test]
    fn test_error_display() {
        let err = ClientHandlerError::MessageTooLarge { size: 100, max: 50 };
        assert!(err.to_string().contains("too large"));

        let err = ClientHandlerError::InvalidMagic([0, 0, 0, 0]);
        assert!(err.to_string().contains("Invalid"));

        let err = ClientHandlerError::UnsupportedVersion(99);
        assert!(err.to_string().contains("99"));

        let err = ClientHandlerError::ConnectionClosed;
        assert!(err.to_string().contains("closed"));
    }

    #[test]
    fn test_handler_state_serde() {
        let states = [HandlerState::Handshake, HandlerState::Active, HandlerState::Closed];
        for state in &states {
            let json = serde_json::to_string(state).unwrap();
            let back: HandlerState = serde_json::from_str(&json).unwrap();
            assert_eq!(*state, back);
        }
    }
}
