//! Ghidra database module.
//!
//! Replaces Ghidra's custom B-tree database with a SQLite backend via rusqlite.
//! Maps Ghidra's DB concepts to SQL concepts:
//! - [`Database`] wraps a thread-safe SQLite connection (`Arc<RwLock<Connection>>`)
//! - [`DBHandle`] provides connection pooling
//! - [`Table`] maps to a SQL table
//! - [`Schema`] defines the column layout (CREATE TABLE)
//! - [`Field`] maps Ghidra field types to SQLite column types
//! - [`FieldValue`] is a typed database value enum
//! - [`DBRecord`] wraps a row with typed accessors
//! - [`Transaction`] provides RAII-style commit/rollback
//! - [`BufferFile`] stores large binary data
//! - [`ChainedBuffer`] handles variable-length record chains

pub mod buffer;
pub mod db;
pub mod transaction;

pub use buffer::{Buffer, ChainedBuffer as LegacyChainedBuffer};
pub use db::{
    convert_db_error, BufferFile, ChainedBuffer, DBHandle, DBListener, DBRecord, Database,
    DbError, DbResult, Field, FieldType, FieldValue, GhidraTransaction, Index, IndexType,
    LruCache, NoopDbListener, PooledConnection, Schema, Table, UndoEntry,
};
pub use transaction::{
    NoopTransactionListener, SavepointGuard, Transaction, TransactionListener, TransactionOpenMode,
};
