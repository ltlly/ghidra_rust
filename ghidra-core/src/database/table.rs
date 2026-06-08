//! Database table metadata ported from Java's `db.Table`.
//!
//! Provides [`Table`] -- the in-memory representation of a database table,
//! tracking its name, schema, primary key columns, and cached row count.

use super::db::FieldValue;
use super::db_record::DBRecord;
use super::schema::{Field, Schema};

// ============================================================================
// Table — port of Java `db.Table`
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

    /// Create an empty record with the given primary key value.
    pub fn create_record(&self, key: FieldValue) -> DBRecord {
        self.schema.create_record(key)
    }

    /// Get the number of indexed columns.
    pub fn indexed_columns(&self) -> &[String] {
        &self.primary_key // placeholder; secondary indexes tracked separately
    }

    /// Get the next available key (max_key + 1, or 0 if table is empty).
    ///
    /// Only meaningful for tables with integer primary keys.
    pub fn next_key(&self) -> i64 {
        if self.row_count == 0 {
            0
        } else {
            // This is a rough heuristic; the real value comes from querying.
            self.row_count as i64
        }
    }

    /// Rename this table in-memory. The caller must also rename it in the
    /// database catalog.
    pub fn rename(&mut self, new_name: &str) {
        self.name = new_name.to_string();
        self.schema.table_name = new_name.to_string();
    }

    /// Increment the cached row count (call after insert).
    pub fn increment_row_count(&mut self) {
        self.row_count += 1;
    }

    /// Decrement the cached row count (call after delete).
    pub fn decrement_row_count(&mut self) {
        if self.row_count > 0 {
            self.row_count -= 1;
        }
    }

    /// Set the cached row count.
    pub fn set_row_count(&mut self, count: usize) {
        self.row_count = count;
    }
}
