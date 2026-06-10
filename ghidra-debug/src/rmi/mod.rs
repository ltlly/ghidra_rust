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
//! - **`debugger_client`**: Debugger client abstraction providing a
//!   `DebuggerClientBackend` trait for uniform interaction with any debug
//!   agent (GDB, LLDB, dbgeng, drgn, x64dbg). Includes command/response
//!   types, events, `DebuggerCommandType`, `DebuggerClientBackendRegistry`,
//!   `DebuggerClientSession`, and the `DebuggerClient` coordinator.
//! - **`trace_debugger_client`**: Trace debugger client bridging debugger
//!   backends with trace storage. Manages `TraceDebuggerSession` instances
//!   that translate backend events into trace object mutations. Includes
//!   the `TraceRmiMethodType` protocol enumeration, `TraceRmiResolution`,
//!   `TraceRmiValueKind`, `TraceRmiRequest`/`TraceRmiReply` messages,
//!   `TraceRmiReplyHandler`, and the `TraceDebuggerClient` coordinator.
//! - **`tracermi_service`**: Trace RMI service management with
//!   `TraceRmiServiceState` tracking connections and targets.

pub mod client;
pub mod debugger_client;
pub mod gui;
pub mod service;
pub mod trace_debugger_client;
pub mod tracermi_service;
