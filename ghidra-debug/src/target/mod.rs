//! Debug target model types.
//!
//! The target model represents the directory-like tree of objects that a
//! debugger exposes. Ported from Ghidra's `TraceObject`, `KeyPath`, and
//! related target model types.

pub mod key_path;
pub mod trace_object;

pub use key_path::KeyPath;
pub use trace_object::{ObjectEntry, ObjectValue, TraceObject, TraceObjectManager};
