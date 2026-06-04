//! Database-backed trace storage.
//!
//! Provides a SQLite-backed implementation of the trace model, ported from
//! Ghidra's `DBTrace` and associated managers.

pub mod trace_db;

pub use trace_db::TraceDatabase;
