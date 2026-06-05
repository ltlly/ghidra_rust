//! JDI (Java Debug Interface) manager and event types.
//!
//! Ported from Ghidra's `Debugger-jpda` module.
//!
//! This module provides the Rust equivalents of Ghidra's JDI management:
//! - **`manager`**: JDI manager interface, event listeners, state listeners,
//!   thread info, and breakpoint types.
//! - **`rmi`**: JDI-specific RMI launch offers and connector types.

pub mod manager;
pub mod rmi;
