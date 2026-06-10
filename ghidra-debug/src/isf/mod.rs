//! ISF (Interchange Schema Format) server and data type objects.
//!
//! Ported from Ghidra's `Debugger-isf` module.
//!
//! This module provides:
//! - **`isf_client_handler`**: Per-connection ISF protocol handler with
//!   handshake, message framing, request dispatch, and type store
//!   management. Supports all ISF request types: Ping, ListNamespaces,
//!   ListTypes, GetType, GetAllTypes, FullExport, LookType, LookSymbol,
//!   LookAddress, EnumTypes, EnumSymbols. Ported from `IsfClientHandler`.
//! - **`isf_server`**: TCP server with connection management, graceful
//!   shutdown, statistics, namespace tracking, and a CLI launcher.
//!   Ported from `IsfServer` and `IsfServerLauncher`.
//! - **`server`**: Shared ISF types, request/response enums, error type,
//!   and the combined server+handler structures.
//! - **`types`**: ISF data type representations (builtins, composites,
//!   enums, pointers, typedefs, functions, arrays, bit fields, function
//!   pointers, dynamic components, typed objects, settings, producers,
//!   and utility functions). Ported from the `ISF` sub-package.

pub mod isf_client_handler;
pub mod isf_server;
pub mod server;
pub mod types;
