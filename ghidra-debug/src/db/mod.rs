//! Database-backed trace storage.
//!
//! Provides a SQLite-backed implementation of the trace model, ported from
//! Ghidra's `DBTrace` and associated managers.

pub mod trace_db;
pub mod trace_db_bookmark;
pub mod trace_db_context;
pub mod trace_db_data;
pub mod trace_db_listing;
pub mod trace_db_map;
pub mod trace_db_memory;
pub mod trace_db_module;
pub mod trace_db_program;
pub mod trace_db_property;
pub mod trace_db_space;
pub mod trace_db_stack;
pub mod trace_db_symbol;
pub mod trace_db_target;
pub mod trace_db_thread;
pub mod trace_db_time;

pub use trace_db::TraceDatabase;
