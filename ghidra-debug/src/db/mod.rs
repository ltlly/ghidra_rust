//! Database-backed trace storage.
//!
//! Provides a SQLite-backed implementation of the trace model, ported from
//! Ghidra's `DBTrace` and associated managers.

pub mod trace_db;
pub mod trace_db_bookmark;
pub mod trace_db_memory;
pub mod trace_db_symbol;

pub use trace_db::TraceDatabase;
