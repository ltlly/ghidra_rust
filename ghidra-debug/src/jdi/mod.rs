//! JDI (Java Debug Interface) manager and event types.
//!
//! Ported from Ghidra's `Debugger-jpda` module.
//!
//! This module provides the Rust equivalents of Ghidra's JDI management:
//! - **`manager`**: JDI manager interface, event listeners, state listeners,
//!   thread info, and breakpoint types.
//! - **`rmi`**: JDI-specific RMI launch offers and connector types.
//! - **`jdi_debugger_client`**: Debugger client for connecting to and
//!   controlling JVM debug targets via JDWP.
//! - **`jdi_event_handling`**: JDI event set processing, event dispatch,
//!   event requests, and filter modifiers.

pub mod jdi_debugger_client;
pub mod jdi_event_handling;
pub mod manager;
pub mod rmi;
