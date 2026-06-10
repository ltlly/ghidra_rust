//! ISF (Interchange Schema Format) server and data type objects.
//!
//! Ported from Ghidra's `Debugger-isf` module.
//!
//! This module provides:
//! - **`isf_client_handler`**: Per-connection ISF protocol handler with
//!   handshake, message framing, request dispatch, and type store
//!   management. Ported from `IsfClientHandler`.
//! - **`isf_server`**: TCP server with connection management, graceful
//!   shutdown, and statistics. Ported from `IsfServer`.
//! - **`server`**: Shared ISF types, request/response enums, error type,
//!   and the combined server+handler structures.
//! - **`types`**: ISF data type representations (builtins, composites,
//!   enums, pointers, typedefs, functions, etc.).

pub mod isf_client_handler;
pub mod isf_server;
pub mod server;
pub mod types;
