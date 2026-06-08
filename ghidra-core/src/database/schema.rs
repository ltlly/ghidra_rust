//! Table schema definitions ported from Java's `db.Schema` and `db.Field`.
//!
//! Provides [`Schema`] (column layout + version) and [`Field`] (column
//! definition with type, constraints, and default value).

use std::fmt;

use super::db::{FieldValue, FieldType};

// ============================================================================
// Field (column definition) — port of Java `db.Field`
// ============================================================================

/// A column definition inside a table [`Schema`].
///
/// ```rust
/// # use ghidra_core::database::{Field, FieldType};
/// let f = Field::new("id", FieldType::Int).primary_key().not_null();
/// assert_eq!(f.to_sql_def(), "id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL");
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

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.field_type)
    }
}

impl Default for Field {
    fn default() -> Self {
        Self {
            name: String::new(),
            field_type: FieldType::Blob,
            indexed: false,
            primary_key: false,
            unique: false,
            nullable: true,
            default_value: None,
        }
    }
}

// ============================================================================
// Schema — port of Java `db.Schema`
// ============================================================================

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

    /// Return positional parameter placeholders (`?1, ?2, ...`) matching the
    /// field count.
    pub fn placeholders(&self) -> String {
        (1..=self.fields.len())
            .map(|i| format!("?{}", i))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Generate the `CREATE TABLE IF NOT EXISTS ...` DDL.
    pub fn to_create_table_sql(&self) -> String {
        let col_defs: Vec<String> = self.fields.iter().map(|f| f.to_sql_def()).collect();
        format!(
            "CREATE TABLE IF NOT EXISTS {} ({})",
            self.table_name,
            col_defs.join(", ")
        )
    }

    /// Create an empty record for the specified primary key value.
    ///
    /// Mirrors Java's `Schema.createRecord(long key)`.
    pub fn create_record(&self, key: FieldValue) -> super::db_record::DBRecord {
        let mut rec = super::db_record::DBRecord::new(self.clone());
        if let Some(pk_name) = self.primary_keys().first() {
            let _ = rec.set(pk_name, key);
        }
        rec
    }
}
