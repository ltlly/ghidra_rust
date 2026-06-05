//! Trace RMI (Remote Method Invocation) client and service.
//!
//! Ported from Ghidra's `Debugger-rmi-trace` module.
//!
//! This module provides:
//! - **`client`**: RMI client for communicating with external debug backends
//!   over protobuf-encoded sockets. Includes `ProtobufSocket`, `RmiClient`,
//!   `RmiBatch`, `RmiTrace`, `RmiTraceObject`, and related types.
//! - **`service`**: Server-side RMI handler and connection management,
//!   including `TraceRmiHandler`, `TraceRmiServer`, `TraceRmiTarget`, etc.
//! - **`gui`**: GUI types for the RMI connection manager and launcher.

pub mod client;
pub mod gui;
pub mod service;
