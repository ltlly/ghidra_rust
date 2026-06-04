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
//! - [`ChainedBuffer`] handles variable-length record chains//! - [`GhidraRecord`] is the port of Java `DBRecord` with Ghidra field system
//! - [`TableRecord`] is the port of Java `TableRecord` (table metadata)
//! - [`SparseRecord`] is the port of Java `SparseRecord` (sparse columns)
//! - [`GhidraField`] is the port of Java `Field` hierarchy (all field types)
//! - Iterator traits: [`RecordIterator`], [`DbFieldIterator`], [`DbLongIterator`]
//! - [`GhidraIndexTable`] manages secondary indexes
//! - [`GhidraMasterTable`] manages the master table metadata
//! - [`ObjectStorageAdapter`] provides key-value storage
//! - [`DBChangeSet`] tracks database changes
//! - [`DatabaseParms`] stores database parameters
//! - [`TableStatistics`] provides table diagnostics
//! - [`DbObject`] / [`DbCache`] — base trait and cache for DB objects
//! - [`ManagerDB`] — lifecycle trait for program sub-managers
//! - [`ListingDB`] — code unit listing storage
//! - [`DBStringMapAdapter`] — string-to-string map backed by a table
//! - [`IntRangeMapDB`] — address range to int value mapping
//! - [`SpecExtension`] — compiler spec extension management
//! - [`ProgramCompilerSpec`] — program-specific compiler spec with extensions
//! - [`ProgramAddressFactory`] — address factory with overlay support
//! - [`ProgramDBChangeSet`] — full program change tracking
//! - [`DataTypeArchiveDBChangeSet`] — data type archive change tracking
//! - [`DataTypeManagerDB`] — database-backed data type manager
//! - [`ProgramDataTypeManager`] — program-bound data type manager

pub mod buffer;
pub mod db;
pub mod transaction;

// New modules porting Java DB framework types
pub mod db_change_set;
pub mod db_parms;
pub mod error;
pub mod field;
pub mod index_table;
pub mod iterator;
pub mod master_table;
pub mod object_storage;
pub mod record;
pub mod record_translator;
pub mod table_statistics;

// New modules porting Java SoftwareModeling database types
pub mod data_type_archive;
pub mod db_object;
pub mod db_string_map;
pub mod int_range_map;
pub mod listing_db;
pub mod manager_db;
pub mod program_address_factory;
pub mod program_change_set;
pub mod spec_extension;

// ---- Re-exports from original modules ----

pub use buffer::{Buffer, ChainedBuffer as LegacyChainedBuffer};
pub use db::{
    convert_db_error, BufferFile, ChainedBuffer, DBHandle, DBListener, DBRecord, Database,
    DbError, DbResult, Field, FieldType, FieldValue, GhidraTransaction, Index, IndexType,
    LruCache, NoopDbListener, PooledConnection, Schema, Table, UndoEntry,
};
pub use transaction::{
    NoopTransactionListener, SavepointGuard, Transaction, TransactionListener, TransactionOpenMode,
};

// ---- Re-exports from new modules ----

// Error types
pub use error::{
    DBRollbackException, IllegalFieldAccessException, NoTransactionException,
    TerminatedTransactionException, UnsupportedFieldException,
};

// Field type system
pub use field::{
    GhidraField, BINARY_OBJ_TYPE, BOOLEAN_TYPE, BYTE_TYPE, FIELD_EXTENSION_INDICATOR,
    FIELD_TYPE_MASK, FIXED_10_TYPE, INDEX_FIELD_TYPE_SHIFT, INDEX_PRIMARY_KEY_TYPE_MASK,
    INT_TYPE, LEGACY_INDEX_LONG_TYPE, LONG_TYPE, SHORT_TYPE, STRING_TYPE,
};

// Record types
pub use record::{GhidraRecord, SparseRecord, TableRecord};

// Iterator traits and implementations
pub use iterator::{
    ConstrainedRecordIterator, DbFieldIterator, DbLongIterator, KeyToRecordIterator,
    RecordIterator, SqlFieldIterator, SqlLongIterator, SqlRecordIterator,
};

// Secondary index management
pub use index_table::GhidraIndexTable;

// Master table management
pub use master_table::GhidraMasterTable;

// Object storage
pub use object_storage::ObjectStorageAdapter;

// Table statistics
pub use table_statistics::TableStatistics;

// Record translation
pub use record_translator::{
    ColumnMappingTranslator, ConvertedRecordIterator, RecordTranslator, TranslatedRecordIterator,
};

// Change set
pub use db_change_set::DBChangeSet;

// Database parameters
pub use db_parms::DatabaseParms;

// ---- Re-exports from SoftwareModeling database modules ----

// DbObject / DbCache
pub use db_object::{DbCache, DbObject};

// ManagerDB trait
pub use manager_db::{ManagerDB, OpenMode, ProgramContext};

// ListingDB
pub use listing_db::{CodeUnitKind, ListingCodeUnit, ListingDB, ListingManager};

// DBStringMapAdapter
pub use db_string_map::DBStringMapAdapter;

// IntRangeMap trait and DB implementation
pub use int_range_map::{IntRangeMap, IntRangeMapDB};

// Spec extensions and ProgramCompilerSpec
pub use spec_extension::{
    ExtensionDocInfo, ExtensionType, ProgramCompilerSpec, SpecExtension,
};

// ProgramAddressFactory
pub use program_address_factory::{OverlaySpaceInfo, ProgramAddressFactory};

// Program and data type archive change sets
pub use program_change_set::{DataTypeArchiveDBChangeSet, ProgramDBChangeSet};

// Data type archive / manager
pub use data_type_archive::{
    CategoryEntry, DataTypeEntry, DataTypeManagerDB, ProgramDataTypeManager, SourceArchiveEntry,
};
pub use program_change_set::DataTypeArchiveDBChangeSet as DataTypeArchiveChangeSet;
