//! Database-backed target object implementation details.
//!
//! Ported from Ghidra's `ghidra.trace.database.target` package.
//!
//! Provides:
//! - `value_storage`: ValueBox, ValueShape, ValueSpace, ValueTriple types.
//! - `visitors`: Tree traversal visitors for the target object hierarchy.

pub mod value_storage;
pub mod visitors;
