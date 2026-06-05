//! Database-backed target object implementation details.
//!
//! Ported from Ghidra's `ghidra.trace.database.target` package.
//!
//! Provides:
//! - `iface`: Database-backed implementations of target object interfaces
//!   (Activatable, Aggregate, Environment, EventScope, ExecutionStateful,
//!   FocusScope, Method, Togglable).
//! - `value_storage`: ValueBox, ValueShape, ValueSpace, ValueTriple types.
//! - `visitors`: Tree traversal visitors for the target object hierarchy.

pub mod iface;
pub mod value_storage;
pub mod visitors;
