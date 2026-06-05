//! ISF (Interchange Schema Format) server and data type objects.
//!
//! Ported from Ghidra's `Debugger-isf` module.
//!
//! This module provides:
//! - **`server`**: The ISF server and connection handler for serving
//!   data type information over protobuf-encoded sockets.
//! - **`types`**: ISF data type representations (builtins, composites,
//!   enums, pointers, typedefs, functions, etc.).

pub mod server;
pub mod types;
