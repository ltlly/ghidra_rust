//! Database record with typed column access.
//!
//! Provides [`DBRecord`] -- a row of [`FieldValue`]s keyed by an owning
//! [`Schema`]. This is the Rust port of Ghidra's Java `DBRecord` used
//! throughout the framework for storing program metadata.

use rusqlite::Result as SqlResult;
use rusqlite::Row as SqlRow;

use super::db::{DbError, DbResult, FieldType, FieldValue};
use super::schema::{Field, Schema};

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

    // ---- primary key accessors (port of Java DBRecord.getKey/setKey) ----

    /// Get the primary key value as a [`FieldValue`].
    ///
    /// Returns the value of the first primary-key column, or `None` if the
    /// schema has no primary key.
    pub fn key(&self) -> Option<&FieldValue> {
        let pks = self.schema.primary_keys();
        let pk_name = pks.first()?;
        self.schema.field_index(pk_name).map(|i| &self.values[i])
    }

    /// Get the primary key as `i64`.
    ///
    /// Panics (or returns `None`) if the primary key is not an integer type.
    pub fn get_key_long(&self) -> Option<i64> {
        self.key()?.as_long()
    }

    /// Get the primary key as `i32`.
    pub fn get_key_int(&self) -> Option<i32> {
        self.key()?.as_int()
    }

    /// Set the primary key value (must match the schema's PK column type).
    pub fn set_key(&mut self, value: FieldValue) -> DbResult<()> {
        let pk_name = self
            .schema
            .primary_keys()
            .first()
            .ok_or_else(|| DbError::Schema("Schema has no primary key".into()))?
            .to_string();
        self.set(&pk_name, value)
    }

    /// Generate a cache key string of the form `"table_name:pk_value"`.
    pub fn cache_key(&self) -> String {
        match self.key() {
            Some(FieldValue::Long(v)) => format!("{}:{}", self.schema.table_name, v),
            Some(FieldValue::Int(v)) => format!("{}:{}", self.schema.table_name, v),
            Some(FieldValue::String(s)) => format!("{}:{}", self.schema.table_name, s),
            _ => format!("{}:{:?}", self.schema.table_name, self.key()),
        }
    }
}
