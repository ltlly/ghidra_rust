//! Trace utility types: data adapters, iterators, and coordinate helpers.
//!
//! Ported from Ghidra's `ghidra.trace.util` and related packages in
//! Framework-TraceModeling.

pub mod coordinates;

pub use coordinates::DebuggerCoordinates as DebugCoordinates;
pub use coordinates::LifespanEnumerator;
