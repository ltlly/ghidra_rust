//! SQLite-backed database implementation for Ghidra Rust.
//!
//! Wraps `rusqlite::Connection` with thread-safety via `Arc<RwLock<Connection>>`,
//! connection pooling, LRU record caching, index management (primary, unique,
//! full-text search via FTS5), and large binary buffer storage.
//!
//! ## Architecture
//!
//! | Ghidra concept | Rust type                                        |
//! |---------------|--------------------------------------------------|
//! | Table         | [`Table`]                                        |
//! | Schema        | [`Schema`]                                       |
//! | Record        | [`DBRecord`]                                     |
//! | DBHandle      | [`DBHandle`] (pool) / [`Database`] (single conn) |
//! | BufferFile    | [`BufferFile`]                                   |
//! | ChainedBuffer | [`ChainedBuffer`]                                |

use rusqlite::{
    self,
    backup,
    params,
    Connection as SqliteConnection,
    Result as SqlResult,
    Row as SqlRow,
};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

// Re-export Connection so downstream crates can use it.
pub use rusqlite::Connection;

// Forward-declare: transaction types live in sibling module but we
// provide begin_transaction() on Database.
use super::transaction::{Transaction, TransactionOpenMode};

// ============================================================================
// Error types
// ============================================================================

/// Error type for database operations.
#[derive(Debug)]
pub enum DbError {
    /// Wraps a rusqlite error.
    Sqlite(rusqlite::Error),
    /// Requested entity not found.
    NotFound(String),
    /// Schema violation (missing column, type mismatch, etc.).
    Schema(String),
    /// I/O error (file read/write).
    Io(std::io::Error),
    /// Lock contention or poisoned mutex.
    Lock(String),
    /// Backup/restore failure.
    Backup(String),
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "SQLite error: {}", e),
            Self::NotFound(s) => write!(f, "Not found: {}", s),
            Self::Schema(s) => write!(f, "Schema error: {}", s),
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::Lock(s) => write!(f, "Lock error: {}", s),
            Self::Backup(s) => write!(f, "Backup error: {}", s),
        }
    }
}

impl std::error::Error for DbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for DbError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

impl From<std::io::Error> for DbError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Result type alias for database operations.
pub type DbResult<T> = Result<T, DbError>;

/// Convert a rusqlite error into a [`DbError`].
pub fn convert_db_error(e: rusqlite::Error) -> DbError {
    DbError::Sqlite(e)
}

// ============================================================================
// Field types
// ============================================================================

/// Column data type for schema definitions.
///
/// Maps to SQLite storage classes: `INTEGER`, `TEXT`, `BLOB`, `REAL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldType {
    /// 32-bit signed integer.
    Int,
    /// 64-bit signed integer.
    Long,
    /// Variable-length text.
    String,
    /// Boolean stored as INTEGER (0/1).
    Bool,
    /// Raw binary / BLOB.
    Blob,
    /// 32-bit IEEE-754 float.
    Float,
    /// 64-bit IEEE-754 double.
    Double,
    /// 16-bit signed integer.
    Short,
    /// Raw binary (alias for Blob).
    Binary,
}

impl FieldType {
    /// Return the SQLite type name used in `CREATE TABLE` DDL.
    pub fn to_sql_type(&self) -> &'static str {
        match self {
            FieldType::Int | FieldType::Long | FieldType::Bool | FieldType::Short => "INTEGER",
            FieldType::String => "TEXT",
            FieldType::Blob | FieldType::Binary => "BLOB",
            FieldType::Float | FieldType::Double => "REAL",
        }
    }

    /// Try to infer a [`FieldType`] from a SQLite type name (case-insensitive).
    pub fn from_sql_type(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "INTEGER" | "INT" | "BIGINT" | "SMALLINT" | "TINYINT" => Some(FieldType::Int),
            "TEXT" | "VARCHAR" | "CHAR" | "CLOB" | "NVARCHAR" | "NCHAR" => {
                Some(FieldType::String)
            }
            "BLOB" => Some(FieldType::Blob),
            "REAL" | "FLOAT" | "DOUBLE" | "NUMERIC" | "DECIMAL" => Some(FieldType::Float),
            "BOOLEAN" | "BOOL" => Some(FieldType::Bool),
            _ => None,
        }
    }

    /// Returns true if this type stores integral values.
    pub fn is_integer(&self) -> bool {
        matches!(
            self,
            FieldType::Int | FieldType::Long | FieldType::Bool | FieldType::Short
        )
    }

    /// Returns true if this type stores text values.
    pub fn is_text(&self) -> bool {
        matches!(self, FieldType::String)
    }

    /// Returns true if this type stores binary values.
    pub fn is_binary(&self) -> bool {
        matches!(self, FieldType::Blob | FieldType::Binary)
    }

    /// Returns true if this type stores floating-point values.
    pub fn is_float(&self) -> bool {
        matches!(self, FieldType::Float | FieldType::Double)
    }
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldType::Int => write!(f, "INTEGER"),
            FieldType::Long => write!(f, "INTEGER"),
            FieldType::String => write!(f, "TEXT"),
            FieldType::Bool => write!(f, "INTEGER"),
            FieldType::Blob => write!(f, "BLOB"),
            FieldType::Float => write!(f, "REAL"),
            FieldType::Double => write!(f, "REAL"),
            FieldType::Short => write!(f, "INTEGER"),
            FieldType::Binary => write!(f, "BLOB"),
        }
    }
}

// ============================================================================
// FieldValue — typed value enum with conversions
// ============================================================================

/// A typed database value. Represents concrete data in a [`DBRecord`] column.
///
/// Provides conversion helpers (`as_int`, `as_long`, `as_string`, …) and
/// implements [`rusqlite::types::ToSql`] so values can be passed directly as
/// query parameters.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    /// 32-bit signed integer.
    Int(i32),
    /// 64-bit signed integer.
    Long(i64),
    /// 16-bit signed integer.
    Short(i16),
    /// UTF-8 text string.
    String(String),
    /// Raw byte vector.
    Binary(Vec<u8>),
    /// Boolean (stored as integer 0/1).
    Boolean(bool),
    /// 32-bit IEEE-754 float.
    Float(f32),
    /// 64-bit IEEE-754 double.
    Double(f64),
    /// SQL NULL.
    Null,
}

impl FieldValue {
    /// Return the [`FieldType`] that best matches this value.
    pub fn field_type(&self) -> FieldType {
        match self {
            FieldValue::Int(_) => FieldType::Int,
            FieldValue::Long(_) => FieldType::Long,
            FieldValue::Short(_) => FieldType::Short,
            FieldValue::String(_) => FieldType::String,
            FieldValue::Binary(_) => FieldType::Binary,
            FieldValue::Boolean(_) => FieldType::Bool,
            FieldValue::Float(_) => FieldType::Float,
            FieldValue::Double(_) => FieldType::Double,
            FieldValue::Null => FieldType::Int,
        }
    }

    /// Convert this value into a SQLite [`rusqlite::types::Value`].
    pub fn to_sql_value(&self) -> rusqlite::types::Value {
        match self {
            FieldValue::Int(v) => rusqlite::types::Value::Integer(*v as i64),
            FieldValue::Long(v) => rusqlite::types::Value::Integer(*v),
            FieldValue::Short(v) => rusqlite::types::Value::Integer(*v as i64),
            FieldValue::String(v) => rusqlite::types::Value::Text(v.clone()),
            FieldValue::Binary(v) => rusqlite::types::Value::Blob(v.clone()),
            FieldValue::Boolean(v) => rusqlite::types::Value::Integer(if *v { 1 } else { 0 }),
            FieldValue::Float(v) => rusqlite::types::Value::Real(*v as f64),
            FieldValue::Double(v) => rusqlite::types::Value::Real(*v),
            FieldValue::Null => rusqlite::types::Value::Null,
        }
    }

    /// Build a [`FieldValue`] from a raw SQLite value and expected type.
    pub fn from_sql_value(value: &rusqlite::types::Value, field_type: FieldType) -> Self {
        match (value, field_type) {
            (rusqlite::types::Value::Null, _) => FieldValue::Null,
            (rusqlite::types::Value::Integer(v), FieldType::Int) => FieldValue::Int(*v as i32),
            (rusqlite::types::Value::Integer(v), FieldType::Long) => FieldValue::Long(*v),
            (rusqlite::types::Value::Integer(v), FieldType::Short) => FieldValue::Short(*v as i16),
            (rusqlite::types::Value::Integer(v), FieldType::Bool) => FieldValue::Boolean(*v != 0),
            (rusqlite::types::Value::Integer(v), _) => FieldValue::Long(*v),
            (rusqlite::types::Value::Real(v), FieldType::Float) => FieldValue::Float(*v as f32),
            (rusqlite::types::Value::Real(v), _) => FieldValue::Double(*v),
            (rusqlite::types::Value::Text(v), _) => FieldValue::String(v.clone()),
            (rusqlite::types::Value::Blob(v), _) => FieldValue::Binary(v.clone()),
        }
    }

    // ---- typed accessors ----

    /// Extract as `i32`.
    pub fn as_int(&self) -> Option<i32> {
        match self {
            FieldValue::Int(v) => Some(*v),
            FieldValue::Long(v) => Some(*v as i32),
            FieldValue::Short(v) => Some(*v as i32),
            FieldValue::Boolean(v) => Some(if *v { 1 } else { 0 }),
            _ => None,
        }
    }

    /// Extract as `i64`.
    pub fn as_long(&self) -> Option<i64> {
        match self {
            FieldValue::Long(v) => Some(*v),
            FieldValue::Int(v) => Some(*v as i64),
            FieldValue::Short(v) => Some(*v as i64),
            FieldValue::Boolean(v) => Some(if *v { 1 } else { 0 }),
            _ => None,
        }
    }

    /// Extract as `i16`.
    pub fn as_short(&self) -> Option<i16> {
        match self {
            FieldValue::Short(v) => Some(*v),
            FieldValue::Int(v) => Some(*v as i16),
            FieldValue::Long(v) => Some(*v as i16),
            _ => None,
        }
    }

    /// Extract as `&str`.
    pub fn as_string(&self) -> Option<&str> {
        match self {
            FieldValue::String(v) => Some(v.as_str()),
            _ => None,
        }
    }

    /// Extract as `&[u8]`.
    pub fn as_binary(&self) -> Option<&[u8]> {
        match self {
            FieldValue::Binary(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    /// Extract as `bool`.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            FieldValue::Boolean(v) => Some(*v),
            FieldValue::Int(v) => Some(*v != 0),
            FieldValue::Long(v) => Some(*v != 0),
            _ => None,
        }
    }

    /// Extract as `f32`.
    pub fn as_float(&self) -> Option<f32> {
        match self {
            FieldValue::Float(v) => Some(*v),
            FieldValue::Double(v) => Some(*v as f32),
            _ => None,
        }
    }

    /// Extract as `f64`.
    pub fn as_double(&self) -> Option<f64> {
        match self {
            FieldValue::Double(v) => Some(*v),
            FieldValue::Float(v) => Some(*v as f64),
            _ => None,
        }
    }

    /// Returns `true` if the value is `Null`.
    pub fn is_null(&self) -> bool {
        matches!(self, FieldValue::Null)
    }

    /// Consume self and return the inner `String` if applicable.
    pub fn into_string(self) -> Option<String> {
        match self {
            FieldValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Consume self and return the inner `Vec<u8>` if applicable.
    pub fn into_binary(self) -> Option<Vec<u8>> {
        match self {
            FieldValue::Binary(b) => Some(b),
            _ => None,
        }
    }
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldValue::Int(v) => write!(f, "{}", v),
            FieldValue::Long(v) => write!(f, "{}", v),
            FieldValue::Short(v) => write!(f, "{}", v),
            FieldValue::String(v) => write!(f, "'{}'", v),
            FieldValue::Binary(v) => write!(f, "x'{}'", hex::encode(v)),
            FieldValue::Boolean(v) => write!(f, "{}", if *v { 1 } else { 0 }),
            FieldValue::Float(v) => write!(f, "{}", v),
            FieldValue::Double(v) => write!(f, "{}", v),
            FieldValue::Null => write!(f, "NULL"),
        }
    }
}

// Quick hex encoder so we don't pull in the `hex` crate.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl rusqlite::types::ToSql for FieldValue {
    fn to_sql(&self) -> SqlResult<rusqlite::types::ToSqlOutput<'_>> {
        match self {
            FieldValue::Null => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Null,
            )),
            FieldValue::Int(v) => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Integer(*v as i64),
            )),
            FieldValue::Long(v) => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Integer(*v),
            )),
            FieldValue::Short(v) => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Integer(*v as i64),
            )),
            FieldValue::String(v) => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Text(v.clone()),
            )),
            FieldValue::Binary(v) => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Blob(v.clone()),
            )),
            FieldValue::Boolean(v) => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Integer(if *v { 1 } else { 0 }),
            )),
            FieldValue::Float(v) => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Real(*v as f64),
            )),
            FieldValue::Double(v) => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Real(*v),
            )),
        }
    }
}

impl From<i32> for FieldValue {
    fn from(v: i32) -> Self {
        FieldValue::Int(v)
    }
}
impl From<i64> for FieldValue {
    fn from(v: i64) -> Self {
        FieldValue::Long(v)
    }
}
impl From<i16> for FieldValue {
    fn from(v: i16) -> Self {
        FieldValue::Short(v)
    }
}
impl From<String> for FieldValue {
    fn from(v: String) -> Self {
        FieldValue::String(v)
    }
}
impl From<&str> for FieldValue {
    fn from(v: &str) -> Self {
        FieldValue::String(v.to_owned())
    }
}
impl From<Vec<u8>> for FieldValue {
    fn from(v: Vec<u8>) -> Self {
        FieldValue::Binary(v)
    }
}
impl From<bool> for FieldValue {
    fn from(v: bool) -> Self {
        FieldValue::Boolean(v)
    }
}
impl From<f32> for FieldValue {
    fn from(v: f32) -> Self {
        FieldValue::Float(v)
    }
}
impl From<f64> for FieldValue {
    fn from(v: f64) -> Self {
        FieldValue::Double(v)
    }
}

// ============================================================================
// Schema & Field definitions
// ============================================================================

/// A column definition inside a table [`Schema`].
///
/// ```rust
/// # use ghidra_core::database::{Field, FieldType};
/// let f = Field::new("id", FieldType::Int).primary_key().not_null();
/// assert_eq!(f.to_sql_def(), "id INTEGER PRIMARY KEY NOT NULL");
/// ```
#[derive(Debug, Clone)]
pub struct Field {
    /// Column name.
    pub name: String,
    /// Column data type.
    pub field_type: FieldType,
    /// Whether an index should be created on this column.
    pub indexed: bool,
    /// Whether this column is part of the primary key.
    pub primary_key: bool,
    /// Whether a UNIQUE constraint applies.
    pub unique: bool,
    /// If false, the column is `NOT NULL`.
    pub nullable: bool,
    /// Default value expression (stored as a SQL fragment).
    pub default_value: Option<FieldValue>,
}

impl Field {
    /// Create a nullable, non-indexed, non-primary-key column.
    pub fn new(name: impl Into<String>, field_type: FieldType) -> Self {
        Self {
            name: name.into(),
            field_type,
            indexed: false,
            primary_key: false,
            unique: false,
            nullable: true,
            default_value: None,
        }
    }

    /// Mark this column as the primary key (implies `NOT NULL`).
    pub fn primary_key(mut self) -> Self {
        self.primary_key = true;
        self.nullable = false;
        self
    }

    /// Mark that an index should be created on this column.
    pub fn indexed(mut self) -> Self {
        self.indexed = true;
        self
    }

    /// Add a UNIQUE constraint.
    pub fn unique(mut self) -> Self {
        self.unique = true;
        self
    }

    /// Disallow NULL values.
    pub fn not_null(mut self) -> Self {
        self.nullable = false;
        self
    }

    /// Attach a default value.
    pub fn default(mut self, value: FieldValue) -> Self {
        self.default_value = Some(value);
        self
    }

    /// Generate the SQL column-definition fragment for `CREATE TABLE`.
    pub fn to_sql_def(&self) -> String {
        let mut def = format!("{} {}", self.name, self.field_type.to_sql_type());
        if self.primary_key {
            def.push_str(" PRIMARY KEY");
            // AUTOINCREMENT is implicit for INTEGER PRIMARY KEY in SQLite.
            if self.field_type.is_integer() {
                def.push_str(" AUTOINCREMENT");
            }
        }
        if !self.nullable {
            def.push_str(" NOT NULL");
        }
        if self.unique && !self.primary_key {
            def.push_str(" UNIQUE");
        }
        if let Some(ref default) = self.default_value {
            def.push_str(&format!(" DEFAULT {}", default));
        }
        def
    }
}

/// A complete table schema: name, columns, and version.
#[derive(Debug, Clone)]
pub struct Schema {
    /// Table name.
    pub table_name: String,
    /// Ordered column definitions.
    pub fields: Vec<Field>,
    /// Schema version (for migrations).
    pub version: i32,
}

impl Schema {
    /// Create an empty schema with a name and version.
    pub fn new(table_name: impl Into<String>, version: i32) -> Self {
        Self {
            table_name: table_name.into(),
            fields: Vec::new(),
            version,
        }
    }

    /// Add a column definition (builder pattern).
    pub fn add_field(&mut self, field: Field) -> &mut Self {
        self.fields.push(field);
        self
    }

    /// Add a column (consume-and-return builder pattern).
    pub fn with_field(mut self, field: Field) -> Self {
        self.fields.push(field);
        self
    }

    /// Return the names of all primary-key columns.
    pub fn primary_keys(&self) -> Vec<&str> {
        self.fields
            .iter()
            .filter(|f| f.primary_key)
            .map(|f| f.name.as_str())
            .collect()
    }

    /// Look up the index of a column by name.
    pub fn field_index(&self, name: &str) -> Option<usize> {
        self.fields.iter().position(|f| f.name == name)
    }

    /// Get a column definition by name.
    pub fn get_field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Return column names as a comma-separated string.
    pub fn column_list(&self) -> String {
        self.fields
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Return positional parameter placeholders (`?1, ?2, …`) matching the
    /// field count.
    pub fn placeholders(&self) -> String {
        (1..=self.fields.len())
            .map(|i| format!("?{}", i))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Generate the `CREATE TABLE IF NOT EXISTS …` DDL.
    pub fn to_create_table_sql(&self) -> String {
        let col_defs: Vec<String> = self.fields.iter().map(|f| f.to_sql_def()).collect();
        format!(
            "CREATE TABLE IF NOT EXISTS {} ({})",
            self.table_name,
            col_defs.join(", ")
        )
    }
}

// ============================================================================
// DBRecord — a database row with typed access
// ============================================================================

/// A database record: a row of [`FieldValue`]s keyed by the owning [`Schema`].
#[derive(Debug, Clone)]
pub struct DBRecord {
    schema: Schema,
    values: Vec<FieldValue>,
}

impl DBRecord {
    /// Create an empty record (all fields `Null`) for the given schema.
    pub fn new(schema: Schema) -> Self {
        let len = schema.fields.len();
        Self {
            schema,
            values: vec![FieldValue::Null; len],
        }
    }

    /// Build a [`DBRecord`] from a [`rusqlite::Row`] using the schema's type
    /// hints for each column.
    pub fn from_row(schema: Schema, row: &SqlRow) -> SqlResult<Self> {
        let mut values = Vec::with_capacity(schema.fields.len());
        for (i, field) in schema.fields.iter().enumerate() {
            let val: rusqlite::types::Value = row.get(i)?;
            values.push(FieldValue::from_sql_value(&val, field.field_type));
        }
        Ok(Self { schema, values })
    }

    /// Build from a row using explicit field types (no full schema).
    pub fn from_row_any(row: &SqlRow, field_types: &[FieldType]) -> SqlResult<Self> {
        let fields: Vec<Field> = field_types
            .iter()
            .enumerate()
            .map(|(i, &ft)| Field::new(format!("col_{}", i), ft))
            .collect();
        let schema = Schema {
            fields,
            ..Schema::new("_ad_hoc", 1)
        };
        Self::from_row(schema, row)
    }

    // ---- generic accessors ----

    /// Get a value by column name.
    pub fn get(&self, field_name: &str) -> DbResult<&FieldValue> {
        let idx = self.field_index(field_name)?;
        Ok(&self.values[idx])
    }

    /// Get a value by column index.
    pub fn get_at(&self, index: usize) -> Option<&FieldValue> {
        self.values.get(index)
    }

    /// Set a value by column name.
    pub fn set(&mut self, field_name: &str, value: FieldValue) -> DbResult<()> {
        let idx = self.field_index(field_name)?;
        self.values[idx] = value;
        Ok(())
    }

    /// Set a value by column index.
    pub fn set_at(&mut self, index: usize, value: FieldValue) -> Option<()> {
        if index < self.values.len() {
            self.values[index] = value;
            Some(())
        } else {
            None
        }
    }

    // ---- typed accessors ----

    /// Read a column as `i32`.
    pub fn get_int(&self, field_name: &str) -> DbResult<i32> {
        self.get(field_name)?
            .as_int()
            .ok_or_else(|| DbError::Schema(format!("Field '{}' is not an int", field_name)))
    }

    /// Read a column as `i64`.
    pub fn get_long(&self, field_name: &str) -> DbResult<i64> {
        self.get(field_name)?
            .as_long()
            .ok_or_else(|| DbError::Schema(format!("Field '{}' is not a long", field_name)))
    }

    /// Read a column as `String`.
    pub fn get_string(&self, field_name: &str) -> DbResult<String> {
        self.get(field_name)?
            .as_string()
            .map(|s| s.to_owned())
            .ok_or_else(|| DbError::Schema(format!("Field '{}' is not a string", field_name)))
    }

    /// Read a column as `bool`.
    pub fn get_bool(&self, field_name: &str) -> DbResult<bool> {
        self.get(field_name)?
            .as_bool()
            .ok_or_else(|| DbError::Schema(format!("Field '{}' is not a bool", field_name)))
    }

    /// Read a column as `f32`.
    pub fn get_float(&self, field_name: &str) -> DbResult<f32> {
        self.get(field_name)?
            .as_float()
            .ok_or_else(|| DbError::Schema(format!("Field '{}' is not a float", field_name)))
    }

    /// Read a column as `f64`.
    pub fn get_double(&self, field_name: &str) -> DbResult<f64> {
        self.get(field_name)?
            .as_double()
            .ok_or_else(|| DbError::Schema(format!("Field '{}' is not a double", field_name)))
    }

    /// Read a column as `Vec<u8>`.
    pub fn get_binary(&self, field_name: &str) -> DbResult<Vec<u8>> {
        self.get(field_name)?
            .as_binary()
            .map(|b| b.to_vec())
            .ok_or_else(|| DbError::Schema(format!("Field '{}' is not binary", field_name)))
    }

    /// Get the schema this record belongs to.
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    /// Get all values.
    pub fn values(&self) -> &[FieldValue] {
        &self.values
    }

    /// Get mutable access to values.
    pub fn values_mut(&mut self) -> &mut [FieldValue] {
        &mut self.values
    }

    /// Number of columns.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// True if no columns.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    fn field_index(&self, field_name: &str) -> DbResult<usize> {
        self.schema
            .field_index(field_name)
            .ok_or_else(|| DbError::NotFound(format!("Field '{}' not found in schema", field_name)))
    }
}

// ============================================================================
// Table
// ============================================================================

/// Reflects a database table: its name, schema, primary key, and row count.
#[derive(Debug, Clone)]
pub struct Table {
    /// Table name.
    pub name: String,
    /// Column schema.
    pub schema: Schema,
    /// Primary-key column names (in order).
    pub primary_key: Vec<String>,
    /// Cached row count (may be stale; call `refresh_row_count` to update).
    pub row_count: usize,
}

impl Table {
    /// Create a [`Table`] from a [`Schema`].
    pub fn new(schema: Schema) -> Self {
        let primary_key = schema
            .primary_keys()
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        Self {
            name: schema.table_name.clone(),
            schema,
            primary_key,
            row_count: 0,
        }
    }

    /// Return the primary-key column names as a comma-separated SQL fragment.
    pub fn primary_key_sql(&self) -> String {
        self.primary_key.join(", ")
    }

    /// True if this table uses a composite (multi-column) primary key.
    pub fn has_composite_key(&self) -> bool {
        self.primary_key.len() > 1
    }

    /// Look up a column definition by name.
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.schema.get_field(name)
    }

    /// All column names as a comma-separated list.
    pub fn column_list(&self) -> String {
        self.schema.column_list()
    }

    /// Positional parameter placeholders matching the field count.
    pub fn placeholders(&self) -> String {
        self.schema.placeholders()
    }

    /// Generate the `CREATE TABLE` DDL for this table.
    pub fn to_create_table_sql(&self) -> String {
        self.schema.to_create_table_sql()
    }
}

// ============================================================================
// Index management
// ============================================================================

/// Kind of database index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexType {
    /// Primary-key index (created automatically by SQLite).
    Primary,
    /// Unique constraint index.
    Unique,
    /// Ordinary (non-unique) index for query acceleration.
    Index,
    /// Full-text search index (FTS5 virtual table).
    FullTextSearch,
}

/// Represents a database index — normal, unique, or FTS5.
#[derive(Debug, Clone)]
pub struct Index {
    /// Index name.
    pub name: String,
    /// The table this index belongs to.
    pub table_name: String,
    /// Indexed column names (in order).
    pub columns: Vec<String>,
    /// Index kind.
    pub index_type: IndexType,
    /// Whether the index enforces uniqueness.
    pub unique: bool,
}

impl Index {
    /// Create a plain (non-unique) index with an auto-generated name.
    pub fn new(table_name: &str, columns: Vec<String>) -> Self {
        let name = format!("idx_{}_{}", table_name, columns.join("_"));
        Self {
            name,
            table_name: table_name.to_string(),
            columns,
            index_type: IndexType::Index,
            unique: false,
        }
    }

    /// Mark this index as unique.
    pub fn unique(mut self) -> Self {
        self.unique = true;
        self.index_type = IndexType::Unique;
        self.name = format!(
            "udx_{}",
            self.name.strip_prefix("idx_").unwrap_or(&self.name)
        );
        self
    }

    /// Mark this as a primary-key index.
    pub fn primary(mut self) -> Self {
        self.index_type = IndexType::Primary;
        self
    }

    /// Generate `CREATE INDEX` (or `CREATE VIRTUAL TABLE … USING fts5`) SQL.
    pub fn to_create_sql(&self) -> String {
        match self.index_type {
            IndexType::FullTextSearch => {
                format!(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS {}_fts USING fts5({})",
                    self.table_name,
                    self.columns.join(", ")
                )
            }
            _ => {
                let unique_kw = if self.unique { "UNIQUE " } else { "" };
                format!(
                    "CREATE {unique_kw}INDEX IF NOT EXISTS {name} ON {table} ({cols})",
                    name = self.name,
                    table = self.table_name,
                    cols = self.columns.join(", "),
                )
            }
        }
    }

    /// Generate `DROP INDEX` SQL.
    pub fn to_drop_sql(&self) -> String {
        if self.index_type == IndexType::FullTextSearch {
            format!("DROP TABLE IF EXISTS {}_fts", self.table_name)
        } else {
            format!("DROP INDEX IF EXISTS {}", self.name)
        }
    }
}

// ============================================================================
// LRU cache for record caching
// ============================================================================

/// A simple LRU (Least-Recently-Used) cache.
///
/// Used internally by [`Database`] to cache frequently-accessed [`DBRecord`]s.
pub struct LruCache<K, V> {
    capacity: usize,
    map: HashMap<K, V>,
    order: VecDeque<K>,
}

impl<K: Clone + std::hash::Hash + Eq, V> LruCache<K, V> {
    /// Create a new LRU cache with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            map: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
        }
    }

    /// Look up a value by key (does NOT update recency).
    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    /// Look up a mutable value by key (does NOT update recency).
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.map.get_mut(key)
    }

    /// Insert a key-value pair, evicting the least-recently-used entry if at capacity.
    /// Returns the evicted value, if any.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        if self.map.contains_key(&key) {
            // Move to front of recency list.
            self.order.retain(|k| k != &key);
            self.order.push_front(key.clone());
            return self.map.insert(key, value);
        }

        let evicted = if self.map.len() >= self.capacity {
            self.order.pop_back().and_then(|old_key| self.map.remove(&old_key))
        } else {
            None
        };

        self.order.push_front(key.clone());
        self.map.insert(key, value);
        evicted
    }

    /// Remove an entry by key.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.order.retain(|k| k != key);
        self.map.remove(key)
    }

    /// Returns true if the key is present.
    pub fn contains(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    /// Number of entries currently cached.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Maximum number of entries.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Remove all entries.
    pub fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }

    /// Iterate over (key, value) pairs in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.map.iter()
    }
}

impl<K: Clone + std::hash::Hash + Eq + fmt::Debug, V: fmt::Debug> fmt::Debug for LruCache<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LruCache")
            .field("capacity", &self.capacity)
            .field("len", &self.map.len())
            .field("entries", &self.map)
            .finish()
    }
}

// ============================================================================
// Database — thread-safe SQLite wrapper
// ============================================================================

/// Internal type alias: shared ownership of a SQLite connection behind a RWLock.
type SharedConnection = Arc<RwLock<SqliteConnection>>;

/// A thread-safe database handle wrapping a single SQLite connection.
///
/// The connection is stored behind `Arc<RwLock<Connection>>` so multiple
/// readers can concurrently query the database. Write operations acquire
/// an exclusive lock.
///
/// For connection pooling, see [`DBHandle`].
pub struct Database {
    conn: SharedConnection,
    path: PathBuf,
    tables: Vec<Table>,
    /// LRU record cache keyed by `"table_name:primary_key_value"`.
    record_cache: Mutex<LruCache<String, DBRecord>>,
}

impl Database {
    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    /// Open an existing SQLite database at `path`, creating it if absent.
    pub fn open<P: AsRef<Path>>(path: P) -> SqlResult<Self> {
        let conn = SqliteConnection::open(path.as_ref())?;
        Self::init_pragmas(&conn)?;
        Ok(Self {
            conn: Arc::new(RwLock::new(conn)),
            path: path.as_ref().to_path_buf(),
            tables: Vec::new(),
            record_cache: Mutex::new(LruCache::new(1024)),
        })
    }

    /// Create a new temporary in-memory database.
    pub fn in_memory() -> SqlResult<Self> {
        let conn = SqliteConnection::open_in_memory()?;
        Self::init_pragmas(&conn)?;
        Ok(Self {
            conn: Arc::new(RwLock::new(conn)),
            path: PathBuf::from(":memory:"),
            tables: Vec::new(),
            record_cache: Mutex::new(LruCache::new(512)),
        })
    }

    fn init_pragmas(conn: &SqliteConnection) -> SqlResult<()> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA foreign_keys=ON;
             PRAGMA cache_size=-8192;",
        )
    }

    // ------------------------------------------------------------------
    // Lock accessors
    // ------------------------------------------------------------------

    /// Acquire a shared (read) lock on the underlying connection.
    pub fn read(&self) -> DbResult<RwLockReadGuard<SqliteConnection>> {
        self.conn
            .read()
            .map_err(|e| DbError::Lock(format!("Failed to acquire read lock: {}", e)))
    }

    /// Acquire an exclusive (write) lock on the underlying connection.
    pub fn write(&self) -> DbResult<RwLockWriteGuard<SqliteConnection>> {
        self.conn
            .write()
            .map_err(|e| DbError::Lock(format!("Failed to acquire write lock: {}", e)))
    }

    /// Get a write-locked reference to the underlying connection.
    /// This is a convenience shorthand used by downstream crates.
    pub fn conn(&self) -> RwLockWriteGuard<SqliteConnection> {
        self.conn.write().expect("Database: failed to acquire write lock")
    }

    /// Clone the inner `Arc` so callers can hold their own reference.
    pub fn shared_conn(&self) -> SharedConnection {
        Arc::clone(&self.conn)
    }

    /// Get the filesystem path of the database (or `":memory:"`).
    pub fn path(&self) -> &Path {
        &self.path
    }

    // ------------------------------------------------------------------
    // Transaction support
    // ------------------------------------------------------------------

    /// Begin a transaction, acquiring the write lock.
    ///
    /// The returned [`Transaction`] will automatically roll back on drop
    /// unless [`Transaction::commit`] is called.
    pub fn begin_transaction(&self, mode: TransactionOpenMode) -> DbResult<Transaction<'_>> {
        let guard = self.write()?;
        Transaction::begin(guard, mode)
    }

    // ------------------------------------------------------------------
    // Table management
    // ------------------------------------------------------------------

    /// Look up a registered table by name.
    pub fn get_table(&self, name: &str) -> Option<&Table> {
        self.tables.iter().find(|t| t.name == name)
    }

    /// Get a mutable reference to a registered table.
    pub fn get_table_mut(&mut self, name: &str) -> Option<&mut Table> {
        self.tables.iter_mut().find(|t| t.name == name)
    }

    /// List all registered tables.
    pub fn tables(&self) -> &[Table] {
        &self.tables
    }

    /// Create a table from a [`Schema`].
    pub fn create_table(&mut self, schema: Schema) -> DbResult<()> {
        let sql = schema.to_create_table_sql();
        {
            let conn = self.write()?;
            conn.execute(&sql, [])?;
        }
        let table = Table::new(schema);
        self.tables.push(table);
        Ok(())
    }

    /// Convenience: create several tables at once.
    pub fn create_tables(&mut self, schemas: Vec<Schema>) -> DbResult<()> {
        for schema in schemas {
            self.create_table(schema)?;
        }
        Ok(())
    }

    /// Delete a table and all its rows.
    pub fn delete_table(&mut self, name: &str) -> DbResult<()> {
        let sql = format!("DROP TABLE IF EXISTS {}", name);
        {
            let conn = self.write()?;
            conn.execute(&sql, [])?;
        }
        self.tables.retain(|t| t.name != name);
        Ok(())
    }

    /// Check whether a table exists in SQLite's catalog.
    pub fn table_exists(&self, name: &str) -> DbResult<bool> {
        let conn = self.read()?;
        let mut stmt = conn.prepare(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
        )?;
        let count: i64 = stmt.query_row(params![name], |row| row.get(0))?;
        Ok(count > 0)
    }

    /// Re-scan the catalog and refresh the internal table list.
    pub fn refresh_tables(&mut self) -> DbResult<()> {
        self.tables.clear();
        let conn = self.read()?;
        let mut stmt = conn.prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )?;
        let names: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .collect();
        drop(stmt);
        drop(conn);

        for name in names {
            let fields = self.get_table_columns(&name)?;
            let schema = Schema {
                table_name: name.clone(),
                fields,
                version: 1,
            };
            self.tables.push(Table::new(schema));
        }
        Ok(())
    }

    /// Retrieve column definitions for an existing table via `PRAGMA table_info`.
    pub fn get_table_columns(&self, table_name: &str) -> DbResult<Vec<Field>> {
        let conn = self.read()?;
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", table_name))?;
        let fields: Vec<Field> = stmt
            .query_map([], |row| {
                let name: String = row.get(1)?;
                let type_name: String = row.get(2)?;
                let not_null: bool = row.get(3)?;
                let pk: bool = row.get(5)?;
                let ft = FieldType::from_sql_type(&type_name).unwrap_or(FieldType::Blob);
                Ok(Field {
                    name,
                    field_type: ft,
                    indexed: false,
                    primary_key: pk,
                    unique: false,
                    nullable: !not_null,
                    default_value: None,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(fields)
    }

    /// Retrieve a table's row count.
    pub fn row_count(&self, table_name: &str) -> DbResult<usize> {
        let conn = self.read()?;
        let sql = format!("SELECT COUNT(*) FROM {}", table_name);
        let count: i64 = conn.query_row(&sql, [], |row| row.get(0))?;
        Ok(count as usize)
    }

    // ------------------------------------------------------------------
    // CRUD operations
    // ------------------------------------------------------------------

    /// Insert (or replace) a record. Returns the `rowid` of the inserted row.
    pub fn insert(&self, table_name: &str, record: &DBRecord) -> DbResult<i64> {
        let table = self
            .get_table(table_name)
            .ok_or_else(|| DbError::NotFound(format!("Table '{}' not found", table_name)))?
            .clone();
        let sql = format!(
            "INSERT OR REPLACE INTO {} ({}) VALUES ({})",
            table_name,
            table.column_list(),
            table.placeholders()
        );

        let conn = self.write()?;
        let _rows = execute_values(&conn, &sql, record.values())?;
        Ok(conn.last_insert_rowid())
    }

    /// Update records matching a WHERE clause.
    pub fn update(
        &self,
        table_name: &str,
        set_columns: &[&str],
        set_values: &[FieldValue],
        where_clause: &str,
        where_params: &[FieldValue],
    ) -> DbResult<usize> {
        // Verify table exists.
        let _table = self
            .get_table(table_name)
            .ok_or_else(|| DbError::NotFound(format!("Table '{}' not found", table_name)))?;
        let assignments: Vec<String> = set_columns
            .iter()
            .enumerate()
            .map(|(i, col)| format!("{} = ?{}", col, i + 1))
            .collect();
        let sql = format!(
            "UPDATE {} SET {} WHERE {}",
            table_name,
            assignments.join(", "),
            where_clause
        );

        let mut all_params: Vec<FieldValue> = Vec::new();
        all_params.extend_from_slice(set_values);
        all_params.extend_from_slice(where_params);

        let conn = self.write()?;
        Ok(execute_values(&conn, &sql, &all_params)?)
    }

    /// Query records from a table.
    pub fn query(
        &self,
        table_name: &str,
        where_clause: Option<&str>,
        params: &[FieldValue],
    ) -> DbResult<Vec<DBRecord>> {
        let table = self
            .get_table(table_name)
            .ok_or_else(|| DbError::NotFound(format!("Table '{}' not found", table_name)))?
            .clone();
        let schema = table.schema.clone();

        let sql = match where_clause {
            Some(w) => format!("SELECT * FROM {} WHERE {}", table_name, w),
            None => format!("SELECT * FROM {}", table_name),
        };

        let conn = self.read()?;
        let mut stmt = conn.prepare(&sql)?;
        let records: Vec<DBRecord> = stmt
            .query_map(params_to_slice(params).as_slice(), |row| {
                DBRecord::from_row(schema.clone(), row)
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(records)
    }

    /// Execute a raw SQL statement. Returns the number of rows modified.
    pub fn execute(&self, sql: &str, params: &[FieldValue]) -> DbResult<usize> {
        let conn = self.write()?;
        Ok(execute_values(&conn, sql, params)?)
    }

    /// Execute a batch of SQL statements (no parameters).
    pub fn execute_batch(&self, sql: &str) -> DbResult<()> {
        let conn = self.write()?;
        conn.execute_batch(sql)?;
        Ok(())
    }

    /// Execute a read-only query with a custom row mapper.
    pub fn query_map<T, F>(
        &self,
        sql: &str,
        params: &[FieldValue],
        f: F,
    ) -> DbResult<Vec<T>>
    where
        F: Fn(&SqlRow) -> SqlResult<T>,
    {
        let conn = self.read()?;
        let mut stmt = conn.prepare(sql)?;
        let results: Vec<T> = stmt
            .query_map(params_to_slice(params).as_slice(), f)?
            .filter_map(|r| r.ok())
            .collect();
        Ok(results)
    }

    /// Query a single optional row.
    pub fn query_one(
        &self,
        table_name: &str,
        where_clause: &str,
        params: &[FieldValue],
    ) -> DbResult<Option<DBRecord>> {
        let results = self.query(table_name, Some(where_clause), params)?;
        Ok(results.into_iter().next())
    }

    /// Delete rows matching a WHERE clause. Returns the number of rows
    /// deleted.
    pub fn delete(
        &self,
        table_name: &str,
        where_clause: &str,
        params: &[FieldValue],
    ) -> DbResult<usize> {
        let sql = format!("DELETE FROM {} WHERE {}", table_name, where_clause);
        let conn = self.write()?;
        Ok(execute_values(&conn, &sql, params)?)
    }

    // ------------------------------------------------------------------
    // Index management
    // ------------------------------------------------------------------

    /// Create an index.
    pub fn create_index(&self, index: &Index) -> DbResult<()> {
        let sql = index.to_create_sql();
        let conn = self.write()?;
        conn.execute(&sql, [])?;
        Ok(())
    }

    /// Drop an index.
    pub fn drop_index(&self, index: &Index) -> DbResult<()> {
        let sql = index.to_drop_sql();
        let conn = self.write()?;
        conn.execute(&sql, [])?;
        Ok(())
    }

    /// Create a full-text search (FTS5) virtual table shadowing a table.
    pub fn create_fts_index(&self, table_name: &str, columns: &[&str]) -> DbResult<()> {
        let col_list = columns.join(", ");
        let sql = format!(
            "CREATE VIRTUAL TABLE IF NOT EXISTS {}_fts USING fts5({})",
            table_name, col_list
        );
        let conn = self.write()?;
        conn.execute(&sql, [])?;
        Ok(())
    }

    /// Perform a full-text search and return matching row IDs.
    pub fn fts_search(&self, table_name: &str, query: &str) -> DbResult<Vec<i64>> {
        let sql = format!("SELECT rowid FROM {}_fts WHERE {}_fts MATCH ?1", table_name, table_name);
        let conn = self.read()?;
        let mut stmt = conn.prepare(&sql)?;
        let ids: Vec<i64> = stmt
            .query_map(params![query], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(ids)
    }

    // ------------------------------------------------------------------
    // Maintenance
    // ------------------------------------------------------------------

    /// Vacuum the database to reclaim disk space.
    pub fn vacuum(&self) -> DbResult<()> {
        let conn = self.write()?;
        conn.execute("VACUUM", [])?;
        Ok(())
    }

    /// Run `PRAGMA integrity_check` and return diagnostics.
    pub fn integrity_check(&self) -> DbResult<Vec<String>> {
        let conn = self.read()?;
        let mut stmt = conn.prepare("PRAGMA integrity_check")?;
        let results: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(results)
    }

    /// Backup this database to a file.
    pub fn backup_to<P: AsRef<Path>>(&self, dst_path: P) -> DbResult<()> {
        let mut dst = SqliteConnection::open(dst_path)?;
        {
            let src_guard = self.read()?;
            let backup = backup::Backup::new(&*src_guard, &mut dst)
                .map_err(|e| DbError::Backup(format!("Failed to create backup: {}", e)))?;
            backup
                .step(-1)
                .map_err(|e| DbError::Backup(format!("Backup step failed: {}", e)))?;
        }
        Ok(())
    }

    /// Restore from a backup file into this database.
    pub fn restore_from<P: AsRef<Path>>(&self, src_path: P) -> DbResult<()> {
        let src = SqliteConnection::open(src_path)?;
        {
            let mut dst_guard = self.write()?;
            let backup = backup::Backup::new(&src, &mut *dst_guard)
                .map_err(|e| DbError::Backup(format!("Failed to create restore backup: {}", e)))?;
            backup
                .step(-1)
                .map_err(|e| DbError::Backup(format!("Restore step failed: {}", e)))?;
        }
        Ok(())
    }

    /// Get the on-disk size of the database file in bytes (0 for in-memory).
    pub fn file_size(&self) -> DbResult<u64> {
        if self.path == PathBuf::from(":memory:") {
            return Ok(0);
        }
        let meta = fs::metadata(&self.path)?;
        Ok(meta.len())
    }

    /// Close the database. Fails if the connection is still referenced
    /// elsewhere.
    pub fn close(self) -> DbResult<()> {
        if let Ok(conn) = Arc::try_unwrap(self.conn) {
            let conn = conn
                .into_inner()
                .map_err(|_| DbError::Lock("Cannot close: connection still in use".into()))?;
            conn.close()
                .map_err(|(_, e)| DbError::Sqlite(e))?;
        } else {
            return Err(DbError::Lock(
                "Cannot close: shared connection has outstanding references".into(),
            ));
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Record caching
    // ------------------------------------------------------------------

    /// Cache a record under the given key.
    pub fn cache_record(&self, key: String, record: DBRecord) {
        if let Ok(mut cache) = self.record_cache.lock() {
            cache.insert(key, record);
        }
    }

    /// Look up a cached record by key.
    pub fn get_cached_record(&self, key: &str) -> Option<DBRecord> {
        self.record_cache
            .lock()
            .ok()?
            .get(&key.to_owned())
            .cloned()
    }

    /// Remove a specific cached record.
    pub fn evict_cached(&self, key: &str) {
        if let Ok(mut cache) = self.record_cache.lock() {
            cache.remove(&key.to_owned());
        }
    }

    /// Clear all cached records.
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.record_cache.lock() {
            cache.clear();
        }
    }

    /// Return the number of records currently cached.
    pub fn cache_len(&self) -> usize {
        self.record_cache
            .lock()
            .map(|c| c.len())
            .unwrap_or(0)
    }
}

impl fmt::Debug for Database {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Database")
            .field("path", &self.path)
            .field("tables", &self.tables.len())
            .finish()
    }
}

// ============================================================================
// DBHandle — connection-pool manager
// ============================================================================

/// A connection checked out from the pool.
pub struct PooledConnection {
    conn: Arc<Mutex<SqliteConnection>>,
    id: usize,
}

impl PooledConnection {
    /// Execute a read-only closure with the locked connection.
    pub fn with_conn<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&SqliteConnection) -> T,
    {
        let guard = self.conn.lock().expect("Poisoned mutex");
        f(&*guard)
    }

    /// Execute a mutating closure with the locked connection.
    pub fn with_conn_mut<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&SqliteConnection) -> T,
    {
        let guard = self.conn.lock().expect("Poisoned mutex");
        f(&*guard)
    }

    /// The pool-internal ID of this connection.
    pub fn id(&self) -> usize {
        self.id
    }
}

/// A thread-safe connection pool for SQLite.
///
/// Each connection in the pool is wrapped in `Arc<Mutex<Connection>>`.
/// Connections are distributed round-robin to spread load.
pub struct DBHandle {
    path: PathBuf,
    pool: Vec<Arc<Mutex<SqliteConnection>>>,
    pool_size: usize,
    next: AtomicUsize,
}

impl DBHandle {
    /// Open a database and create a pool of `pool_size` connections (minimum 1).
    pub fn open<P: AsRef<Path>>(path: P, pool_size: usize) -> SqlResult<Self> {
        let pool_size = pool_size.max(1);
        let mut pool = Vec::with_capacity(pool_size);
        let pragmas = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;";
        for _ in 0..pool_size {
            let conn = SqliteConnection::open(path.as_ref())?;
            conn.execute_batch(pragmas)?;
            pool.push(Arc::new(Mutex::new(conn)));
        }
        Ok(Self {
            path: path.as_ref().to_path_buf(),
            pool,
            pool_size,
            next: AtomicUsize::new(0),
        })
    }

    /// Create an in-memory database with a connection pool.
    pub fn in_memory(pool_size: usize) -> SqlResult<Self> {
        Self::open(":memory:", pool_size)
    }

    /// Get a connection from the pool (round-robin).
    pub fn get_conn(&self) -> PooledConnection {
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.pool_size;
        PooledConnection {
            conn: Arc::clone(&self.pool[idx]),
            id: idx,
        }
    }

    /// Execute a read operation on any pooled connection.
    pub fn read<F, T>(&self, f: F) -> DbResult<T>
    where
        F: FnOnce(&SqliteConnection) -> DbResult<T>,
    {
        let pooled = self.get_conn();
        let guard = pooled
            .conn
            .lock()
            .map_err(|e| DbError::Lock(format!("Mutex poisoned: {}", e)))?;
        f(&*guard)
    }

    /// Execute a write operation on any pooled connection.
    pub fn write<F, T>(&self, f: F) -> DbResult<T>
    where
        F: FnOnce(&SqliteConnection) -> DbResult<T>,
    {
        let pooled = self.get_conn();
        let guard = pooled
            .conn
            .lock()
            .map_err(|e| DbError::Lock(format!("Mutex poisoned: {}", e)))?;
        f(&*guard)
    }

    /// Execute a parameterised SQL statement. Returns rows modified.
    pub fn execute(&self, sql: &str, params: &[FieldValue]) -> DbResult<usize> {
        self.write(|conn| Ok(execute_values(conn, sql, params)?))
    }

    /// Execute a batch of SQL (no params).
    pub fn execute_batch(&self, sql: &str) -> DbResult<()> {
        self.write(|conn| {
            conn.execute_batch(sql)?;
            Ok(())
        })
    }

    /// Query with a custom row mapper.
    pub fn query<T, F>(&self, sql: &str, params: &[FieldValue], mapper: F) -> DbResult<Vec<T>>
    where
        F: Fn(&SqlRow) -> SqlResult<T>,
    {
        self.read(|conn| {
            let mut stmt = conn.prepare(sql)?;
            let results: Vec<T> = stmt
                .query_map(params_to_slice(params).as_slice(), |row| mapper(row))?
                .filter_map(|r| r.ok())
                .collect();
            Ok(results)
        })
    }

    /// Create a table from a schema.
    pub fn create_table(&self, schema: &Schema) -> DbResult<()> {
        let sql = schema.to_create_table_sql();
        self.execute_batch(&sql)
    }

    /// Delete a table.
    pub fn delete_table(&self, table_name: &str) -> DbResult<()> {
        let sql = format!("DROP TABLE IF EXISTS {}", table_name);
        self.execute_batch(&sql)
    }

    /// Check whether a table exists.
    pub fn table_exists(&self, table_name: &str) -> DbResult<bool> {
        self.read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            )?;
            let count: i64 = stmt.query_row(params![table_name], |row| row.get(0))?;
            Ok(count > 0)
        })
    }

    /// Return the names of all user tables.
    pub fn table_names(&self) -> DbResult<Vec<String>> {
        self.read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )?;
            let names: Vec<String> = stmt
                .query_map([], |row| row.get::<_, String>(0))?
                .filter_map(|r| r.ok())
                .collect();
            Ok(names)
        })
    }

    /// Create an index.
    pub fn create_index(&self, index: &Index) -> DbResult<()> {
        let sql = index.to_create_sql();
        self.execute_batch(&sql)
    }

    /// Drop an index.
    pub fn drop_index(&self, index: &Index) -> DbResult<()> {
        let sql = index.to_drop_sql();
        self.execute_batch(&sql)
    }

    /// Vacuum.
    pub fn vacuum(&self) -> DbResult<()> {
        self.execute_batch("VACUUM")
    }

    /// Backup to a file.
    pub fn backup_to<P: AsRef<Path>>(&self, dst_path: P) -> DbResult<()> {
        let mut dst = SqliteConnection::open(dst_path)?;
        self.read(|conn| {
            let backup = backup::Backup::new(conn, &mut dst)
                .map_err(|e| DbError::Backup(format!("{}", e)))?;
            backup
                .step(-1)
                .map_err(|e| DbError::Backup(format!("{}", e)))?;
            Ok(())
        })
    }

    /// Get the filesystem path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of connections in the pool.
    pub fn pool_size(&self) -> usize {
        self.pool_size
    }

    /// Close all connections.
    pub fn close(self) -> DbResult<()> {
        for conn_arc in self.pool {
            if let Ok(conn) = Arc::try_unwrap(conn_arc) {
                let conn = conn
                    .into_inner()
                    .map_err(|_| DbError::Lock("Mutex poisoned".into()))?;
                conn.close()
                    .map_err(|(_, e)| DbError::Sqlite(e))?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for DBHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DBHandle")
            .field("path", &self.path)
            .field("pool_size", &self.pool_size)
            .finish()
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Execute a SQL statement with a dynamic slice of [`FieldValue`] parameters.
fn execute_values(conn: &SqliteConnection, sql: &str, values: &[FieldValue]) -> SqlResult<usize> {
    if values.is_empty() {
        conn.execute(sql, [])
    } else {
        let refs: Vec<&dyn rusqlite::types::ToSql> = values.iter().map(|v| v as &dyn rusqlite::types::ToSql).collect();
        conn.execute(sql, refs.as_slice())
    }
}

/// Build a `&[&dyn ToSql]` slice from a slice of [`FieldValue`].
fn params_to_slice(values: &[FieldValue]) -> Vec<&dyn rusqlite::types::ToSql> {
    values.iter().map(|v| v as &dyn rusqlite::types::ToSql).collect()
}

// ============================================================================
// BufferFile — large binary data storage
// ============================================================================

/// Stores large binary data, either fully in-memory or backed by a filesystem
/// file.
pub struct BufferFile {
    buffer_id: i64,
    data: Vec<u8>,
    file_path: Option<PathBuf>,
    dirty: bool,
    max_memory_size: usize,
}

impl BufferFile {
    /// Create an empty in-memory buffer.
    pub fn new(buffer_id: i64, initial_capacity: usize) -> Self {
        Self {
            buffer_id,
            data: Vec::with_capacity(initial_capacity),
            file_path: None,
            dirty: false,
            max_memory_size: 256 * 1024,
        }
    }

    /// Create a buffer and load its content from a file.
    pub fn from_file<P: AsRef<Path>>(buffer_id: i64, path: P) -> io::Result<Self> {
        let data = fs::read(path.as_ref())?;
        Ok(Self {
            buffer_id,
            data,
            file_path: Some(path.as_ref().to_path_buf()),
            dirty: false,
            max_memory_size: 256 * 1024,
        })
    }

    /// Unique buffer identifier.
    pub fn id(&self) -> i64 {
        self.buffer_id
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Read bytes at `offset` into `buf`. Returns bytes actually read.
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> DbResult<usize> {
        let available = self.data.len().saturating_sub(offset);
        let len = buf.len().min(available);
        if len > 0 {
            buf[..len].copy_from_slice(&self.data[offset..offset + len]);
        }
        Ok(len)
    }

    /// Read a single byte.
    pub fn read_byte(&self, offset: usize) -> DbResult<u8> {
        self.data
            .get(offset)
            .copied()
            .ok_or_else(|| DbError::NotFound(format!("Offset {} out of bounds", offset)))
    }

    /// Write `buf` at `offset`, growing if necessary.
    pub fn write(&mut self, offset: usize, buf: &[u8]) -> DbResult<usize> {
        self.dirty = true;
        let required = offset + buf.len();
        if required > self.data.len() {
            self.data.resize(required, 0);
        }
        self.data[offset..offset + buf.len()].copy_from_slice(buf);
        Ok(buf.len())
    }

    /// Append bytes to the end.
    pub fn append(&mut self, buf: &[u8]) -> DbResult<usize> {
        self.dirty = true;
        self.data.extend_from_slice(buf);
        Ok(buf.len())
    }

    /// View the raw data as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// View the raw data as a mutable slice (marks dirty).
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.dirty = true;
        &mut self.data
    }

    /// True if there are unsaved changes that would be lost on drop.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Flush in-memory data to the backing file.
    pub fn flush(&mut self) -> io::Result<()> {
        if self.dirty {
            if let Some(ref path) = self.file_path {
                fs::write(path, &self.data)?;
            }
            self.dirty = false;
        }
        Ok(())
    }

    /// Assign a backing file path.
    pub fn set_file_path<P: AsRef<Path>>(&mut self, path: P) {
        self.file_path = Some(path.as_ref().to_path_buf());
    }

    /// Get the backing file path, if any.
    pub fn file_path(&self) -> Option<&Path> {
        self.file_path.as_deref()
    }

    /// Clear all data (marks dirty).
    pub fn clear(&mut self) {
        self.data.clear();
        self.dirty = true;
    }

    /// Truncate to a new length.
    pub fn truncate(&mut self, new_len: usize) {
        self.data.truncate(new_len);
        self.dirty = true;
    }

    /// Allocated capacity.
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    /// Shrink allocated capacity to current length.
    pub fn shrink_to_fit(&mut self) {
        self.data.shrink_to_fit();
    }

    /// Threshold above which data should spill to disk.
    pub fn set_max_memory_size(&mut self, size: usize) {
        self.max_memory_size = size;
    }

    /// Current spill threshold.
    pub fn max_memory_size(&self) -> usize {
        self.max_memory_size
    }

    /// Consume self and return the raw bytes.
    pub fn into_inner(self) -> Vec<u8> {
        self.data
    }
}

impl fmt::Debug for BufferFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BufferFile")
            .field("buffer_id", &self.buffer_id)
            .field("len", &self.data.len())
            .field("file_path", &self.file_path)
            .field("dirty", &self.dirty)
            .finish()
    }
}

// ============================================================================
// ChainedBuffer — variable-length record chain
// ============================================================================

/// ChainedBuffer stores variable-length data as a linked list of fixed-size
/// blocks, mirroring Ghidra's `ChainedBuffer` for efficient storage of
/// variable-length records.
pub struct ChainedBuffer {
    buffer_id: i64,
    block_size: usize,
    blocks: Vec<Vec<u8>>,
    total_size: usize,
    dirty: bool,
}

impl ChainedBuffer {
    /// Create a chained buffer with fixed `block_size` (minimum 1).
    pub fn new(buffer_id: i64, block_size: usize) -> Self {
        Self {
            buffer_id,
            block_size: block_size.max(1),
            blocks: Vec::new(),
            total_size: 0,
            dirty: false,
        }
    }

    /// Create a chained buffer and populate it from a byte slice.
    pub fn from_data(buffer_id: i64, block_size: usize, data: &[u8]) -> Self {
        let mut buf = Self::new(buffer_id, block_size);
        if !data.is_empty() {
            buf.ensure_size(data.len());
            let _ = buf.write(0, data);
            buf.dirty = false;
        }
        buf
    }

    /// Unique buffer identifier.
    pub fn buffer_id(&self) -> i64 {
        self.buffer_id
    }

    /// Total length of stored data in bytes.
    pub fn len(&self) -> usize {
        self.total_size
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.total_size == 0
    }

    /// Fixed block size.
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Number of allocated blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Read data starting at `offset` into `buf`. Returns bytes actually read.
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> DbResult<usize> {
        if offset >= self.total_size {
            return Ok(0);
        }

        let mut bytes_read = 0;
        let mut remaining = buf.len().min(self.total_size - offset);
        let mut current_offset = offset;

        while remaining > 0 {
            let block_idx = current_offset / self.block_size;
            let block_offset = current_offset % self.block_size;
            if block_idx >= self.blocks.len() {
                break;
            }
            let block = &self.blocks[block_idx];
            let to_read = remaining.min(self.block_size - block_offset);
            buf[bytes_read..bytes_read + to_read]
                .copy_from_slice(&block[block_offset..block_offset + to_read]);
            bytes_read += to_read;
            remaining -= to_read;
            current_offset += to_read;
        }

        Ok(bytes_read)
    }

    /// Read all data into a contiguous `Vec<u8>`.
    pub fn read_all(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.total_size);
        for block in &self.blocks {
            result.extend_from_slice(block);
        }
        result.truncate(self.total_size);
        result
    }

    /// Read a single byte.
    pub fn read_byte(&self, offset: usize) -> DbResult<u8> {
        if offset >= self.total_size {
            return Err(DbError::NotFound(format!(
                "Offset {} out of bounds (total size {})",
                offset, self.total_size
            )));
        }
        let block_idx = offset / self.block_size;
        let block_offset = offset % self.block_size;
        Ok(self.blocks[block_idx][block_offset])
    }

    /// Write data at `offset`, growing the chain if needed.
    pub fn write(&mut self, offset: usize, data: &[u8]) -> DbResult<usize> {
        self.dirty = true;
        let required_size = offset + data.len();
        self.ensure_size(required_size);

        let mut bytes_written = 0;
        let mut remaining = data.len();
        let mut current_offset = offset;

        while remaining > 0 {
            let block_idx = current_offset / self.block_size;
            let block_offset = current_offset % self.block_size;
            let to_write = remaining.min(self.block_size - block_offset);
            let src = &data[bytes_written..bytes_written + to_write];
            let dst = &mut self.blocks[block_idx][block_offset..block_offset + to_write];
            dst.copy_from_slice(src);
            bytes_written += to_write;
            remaining -= to_write;
            current_offset += to_write;
        }

        Ok(bytes_written)
    }

    /// Append data to the end of the chain.
    pub fn append(&mut self, data: &[u8]) -> DbResult<usize> {
        let offset = self.total_size;
        self.write(offset, data)
    }

    /// Get a specific block (returns the full block, possibly with padding).
    pub fn get_block(&self, index: usize) -> Option<&[u8]> {
        self.blocks.get(index).map(|b| b.as_slice())
    }

    /// Set an entire block. Pads/truncates to `block_size`.
    pub fn set_block(&mut self, index: usize, data: Vec<u8>) -> DbResult<()> {
        self.dirty = true;
        if index >= self.blocks.len() {
            self.blocks.resize(index + 1, vec![0; self.block_size]);
        }
        let mut padded = vec![0; self.block_size];
        let copy_len = data.len().min(self.block_size);
        padded[..copy_len].copy_from_slice(&data[..copy_len]);
        self.blocks[index] = padded;
        let end = (index + 1) * self.block_size;
        if end > self.total_size {
            self.total_size = end;
        }
        Ok(())
    }

    /// Clear all data.
    pub fn clear(&mut self) {
        self.blocks.clear();
        self.total_size = 0;
        self.dirty = true;
    }

    /// Truncate to `new_size` bytes.
    pub fn truncate(&mut self, new_size: usize) {
        let blocks_needed = if new_size == 0 {
            0
        } else {
            (new_size + self.block_size - 1) / self.block_size
        };
        self.blocks.truncate(blocks_needed);
        self.total_size = new_size;
        self.dirty = true;
    }

    /// Check whether the buffer has been modified since last `mark_clean`.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Reset the dirty flag.
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Iterate over all blocks.
    pub fn iter_blocks(&self) -> impl Iterator<Item = &[u8]> {
        self.blocks.iter().map(|b| b.as_slice())
    }

    // ---- internals ----

    fn ensure_size(&mut self, size: usize) {
        if size <= self.total_size {
            return;
        }
        let blocks_needed = (size + self.block_size - 1) / self.block_size;
        while self.blocks.len() < blocks_needed {
            self.blocks.push(vec![0; self.block_size]);
        }
        self.total_size = size;
    }
}

impl fmt::Debug for ChainedBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainedBuffer")
            .field("buffer_id", &self.buffer_id)
            .field("block_size", &self.block_size)
            .field("blocks", &self.blocks.len())
            .field("total_size", &self.total_size)
            .field("dirty", &self.dirty)
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Field / FieldValue --------------------------------------------------

    #[test]
    fn test_field_type_to_sql() {
        assert_eq!(FieldType::Int.to_sql_type(), "INTEGER");
        assert_eq!(FieldType::String.to_sql_type(), "TEXT");
        assert_eq!(FieldType::Blob.to_sql_type(), "BLOB");
        assert_eq!(FieldType::Float.to_sql_type(), "REAL");
    }

    #[test]
    fn test_field_value_conversions() {
        let v = FieldValue::Int(42);
        assert_eq!(v.as_int(), Some(42));
        assert_eq!(v.as_long(), Some(42));

        let v = FieldValue::String("hello".into());
        assert_eq!(v.as_string(), Some("hello"));

        let v = FieldValue::Boolean(true);
        assert!(v.as_bool().unwrap());

        let v = FieldValue::Double(3.14);
        assert!((v.as_double().unwrap() - 3.14).abs() < 0.001);

        assert!(FieldValue::Null.is_null());
    }

    #[test]
    fn test_field_value_from_impls() {
        let v: FieldValue = 42i32.into();
        assert_eq!(v, FieldValue::Int(42));

        let v: FieldValue = "text".into();
        assert_eq!(v, FieldValue::String("text".into()));

        let v: FieldValue = true.into();
        assert_eq!(v, FieldValue::Boolean(true));
    }

    #[test]
    fn test_field_to_sql_def() {
        let f = Field::new("id", FieldType::Int)
            .primary_key()
            .not_null();
        let def = f.to_sql_def();
        assert!(def.contains("PRIMARY KEY"));
        assert!(def.contains("NOT NULL"));

        let f = Field::new("name", FieldType::String)
            .unique()
            .not_null();
        let def = f.to_sql_def();
        assert!(def.contains("UNIQUE"));
    }

    // -- Schema --------------------------------------------------------------

    #[test]
    fn test_schema_builder() {
        let schema = Schema::new("users", 2)
            .with_field(Field::new("id", FieldType::Int).primary_key())
            .with_field(Field::new("email", FieldType::String).unique());
        assert_eq!(schema.table_name, "users");
        assert_eq!(schema.version, 2);
        assert_eq!(schema.fields.len(), 2);
        assert_eq!(schema.primary_keys(), vec!["id"]);
        assert_eq!(schema.field_index("email"), Some(1));
    }

    #[test]
    fn test_create_table_sql() {
        let schema = Schema::new("items", 1)
            .with_field(Field::new("id", FieldType::Int).primary_key())
            .with_field(Field::new("label", FieldType::String));
        let sql = schema.to_create_table_sql();
        assert!(sql.starts_with("CREATE TABLE IF NOT EXISTS items"));
        assert!(sql.contains("id INTEGER PRIMARY KEY"));
        assert!(sql.contains("label TEXT"));
    }

    // -- DBRecord ------------------------------------------------------------

    #[test]
    fn test_record_get_set() {
        let schema = Schema::new("t", 1)
            .with_field(Field::new("a", FieldType::Int))
            .with_field(Field::new("b", FieldType::String));
        let mut rec = DBRecord::new(schema);
        rec.set("a", FieldValue::Int(10)).unwrap();
        rec.set("b", FieldValue::String("x".into())).unwrap();
        assert_eq!(rec.get_int("a").unwrap(), 10);
        assert_eq!(rec.get_string("b").unwrap(), "x");
    }

    // -- Table ---------------------------------------------------------------

    #[test]
    fn test_table_from_schema() {
        let schema = Schema::new("data", 1)
            .with_field(Field::new("key", FieldType::Long).primary_key())
            .with_field(Field::new("value", FieldType::Binary));
        let table = Table::new(schema);
        assert_eq!(table.name, "data");
        assert_eq!(table.primary_key, vec!["key"]);
        assert!(!table.has_composite_key());
    }

    // -- Index ---------------------------------------------------------------

    #[test]
    fn test_index_sql() {
        let idx = Index::new("users", vec!["email".into()]).unique();
        let sql = idx.to_create_sql();
        assert!(sql.contains("UNIQUE INDEX"));
        assert!(sql.contains("users"));
        assert!(sql.contains("email"));

        let drop_sql = idx.to_drop_sql();
        assert!(drop_sql.contains("DROP INDEX"));
    }

    // -- LruCache ------------------------------------------------------------

    #[test]
    fn test_lru_cache_eviction() {
        let mut cache: LruCache<i32, String> = LruCache::new(3);
        cache.insert(1, "one".into());
        cache.insert(2, "two".into());
        cache.insert(3, "three".into());
        assert_eq!(cache.len(), 3);

        // Evict key 1 by inserting key 4.
        cache.insert(4, "four".into());
        assert!(cache.get(&1).is_none());
        assert_eq!(cache.get(&4).unwrap(), "four");
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn test_lru_cache_update_moves_to_front() {
        let mut cache: LruCache<i32, String> = LruCache::new(2);
        cache.insert(1, "one".into());
        cache.insert(2, "two".into());
        // Update key 1 — should not evict it.
        cache.insert(1, "ONE".into());
        cache.insert(3, "three".into()); // should evict 2, not 1
        assert!(cache.contains(&1));
        assert!(!cache.contains(&2));
        assert!(cache.contains(&3));
    }

    // -- Database ------------------------------------------------------------

    #[test]
    fn test_database_in_memory() {
        let mut db = Database::in_memory().unwrap();
        let schema = Schema::new("test_items", 1)
            .with_field(Field::new("id", FieldType::Int).primary_key())
            .with_field(Field::new("name", FieldType::String));
        db.create_table(schema).unwrap();
        assert!(db.table_exists("test_items").unwrap());
    }

    #[test]
    fn test_insert_query() {
        let mut db = Database::in_memory().unwrap();
        let schema = Schema::new("people", 1)
            .with_field(Field::new("id", FieldType::Int).primary_key())
            .with_field(Field::new("name", FieldType::String));
        db.create_table(schema.clone()).unwrap();

        let mut rec = DBRecord::new(schema.clone());
        rec.set("id", FieldValue::Int(1)).unwrap();
        rec.set("name", FieldValue::String("Alice".into())).unwrap();
        db.insert("people", &rec).unwrap();

        let rows = db.query("people", None, &[]).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get_string("name").unwrap(), "Alice");
    }

    #[test]
    fn test_create_index() {
        let mut db = Database::in_memory().unwrap();
        let schema = Schema::new("users", 1)
            .with_field(Field::new("id", FieldType::Int).primary_key())
            .with_field(Field::new("email", FieldType::String));
        db.create_table(schema).unwrap();

        let idx = Index::new("users", vec!["email".into()]).unique();
        db.create_index(&idx).unwrap();
    }

    #[test]
    fn test_vacuum() {
        let db = Database::in_memory().unwrap();
        // Vacuum on in-memory is a no-op but should not error.
        db.vacuum().unwrap();
    }

    #[test]
    fn test_record_cache() {
        let mut db = Database::in_memory().unwrap();
        let schema = Schema::new("cache_test", 1)
            .with_field(Field::new("k", FieldType::String));
        db.create_table(schema.clone()).unwrap();

        let rec = DBRecord::new(schema);
        db.cache_record("mykey".into(), rec);
        let cached = db.get_cached_record("mykey");
        assert!(cached.is_some());
        assert_eq!(db.cache_len(), 1);

        db.evict_cached("mykey");
        assert!(db.get_cached_record("mykey").is_none());
    }

    // -- DBHandle ------------------------------------------------------------

    #[test]
    fn test_db_handle_create_table() {
        let handle = DBHandle::in_memory(2).unwrap();
        assert_eq!(handle.pool_size(), 2);

        let schema = Schema::new("handle_test", 1)
            .with_field(Field::new("id", FieldType::Int).primary_key());
        handle.create_table(&schema).unwrap();
        assert!(handle.table_exists("handle_test").unwrap());

        let names = handle.table_names().unwrap();
        assert!(names.contains(&"handle_test".to_string()));
    }

    #[test]
    fn test_db_handle_execute() {
        let handle = DBHandle::in_memory(1).unwrap();
        handle
            .execute_batch("CREATE TABLE t (x INTEGER)")
            .unwrap();
        handle
            .execute("INSERT INTO t (x) VALUES (?1)", &[FieldValue::Int(99)])
            .unwrap();
        let rows: Vec<i64> = handle
            .query("SELECT x FROM t", &[], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, vec![99]);
    }

    // -- BufferFile ----------------------------------------------------------

    #[test]
    fn test_buffer_file_read_write() {
        let mut buf = BufferFile::new(1, 64);
        buf.append(b"hello world").unwrap();
        assert_eq!(buf.len(), 11);

        let mut out = [0u8; 5];
        let n = buf.read(6, &mut out).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&out, b"world");
    }

    #[test]
    fn test_buffer_file_byte_read() {
        let mut buf = BufferFile::new(2, 16);
        buf.append(b"ABC").unwrap();
        assert_eq!(buf.read_byte(0).unwrap(), b'A');
        assert_eq!(buf.read_byte(1).unwrap(), b'B');
        assert_eq!(buf.read_byte(2).unwrap(), b'C');
        assert!(buf.read_byte(3).is_err());
    }

    // -- ChainedBuffer -------------------------------------------------------

    #[test]
    fn test_chained_buffer_basic() {
        let mut cb = ChainedBuffer::new(1, 4);
        cb.append(b"hello world").unwrap();
        assert_eq!(cb.len(), 11);
        assert_eq!(cb.block_count(), 3); // ceil(11/4) = 3
        assert_eq!(cb.read_all(), b"hello world");

        let mut out = [0u8; 6];
        cb.read(6, &mut out).unwrap();
        assert_eq!(&out, b"world");
    }

    #[test]
    fn test_chained_buffer_overwrite() {
        let mut cb = ChainedBuffer::new(2, 4);
        cb.append(b"ABCDEFGH").unwrap();
        cb.write(3, b"XY").unwrap();
        assert_eq!(cb.read_all(), b"ABCXYFGH");
    }

    #[test]
    fn test_chained_buffer_truncate() {
        let mut cb = ChainedBuffer::new(3, 4);
        cb.append(b"12345678").unwrap();
        cb.truncate(4);
        assert_eq!(cb.read_all(), b"1234");
    }
}
