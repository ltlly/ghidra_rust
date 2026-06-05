//! Database utility types.
//!
//! Ported from Ghidra's `ghidra.util.database` package.
//!
//! Provides key spans, field spans, directed iterators, and
//! the annotated object framework.

use serde::{Deserialize, Serialize};

/// The direction of iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IterDirection {
    /// Forward (ascending).
    Forward,
    /// Backward (descending).
    Backward,
}

/// A span of contiguous long keys.
///
/// Ported from Ghidra's `KeySpan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySpan {
    /// The minimum key (inclusive).
    pub min: i64,
    /// The maximum key (inclusive).
    pub max: i64,
}

impl KeySpan {
    /// Create a new key span.
    pub fn new(min: i64, max: i64) -> Self {
        assert!(min <= max, "KeySpan: min ({}) > max ({})", min, max);
        Self { min, max }
    }

    /// The number of keys in the span.
    pub fn len(&self) -> i64 {
        self.max - self.min + 1
    }

    /// Whether the span is empty (degenerate).
    pub fn is_empty(&self) -> bool {
        false // A valid span always has at least one key
    }

    /// Whether the span contains the given key.
    pub fn contains(&self, key: i64) -> bool {
        key >= self.min && key <= self.max
    }

    /// Whether this span overlaps with another.
    pub fn overlaps(&self, other: &KeySpan) -> bool {
        self.min <= other.max && other.min <= self.max
    }
}

/// A span of contiguous field indices.
///
/// Ported from Ghidra's `FieldSpan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldSpan {
    /// The column/field index.
    pub column: usize,
    /// Start row (inclusive).
    pub start_row: i64,
    /// End row (inclusive).
    pub end_row: i64,
}

impl FieldSpan {
    /// Create a new field span.
    pub fn new(column: usize, start_row: i64, end_row: i64) -> Self {
        Self {
            column,
            start_row,
            end_row,
        }
    }

    /// Number of rows.
    pub fn num_rows(&self) -> i64 {
        self.end_row - self.start_row + 1
    }
}

/// An annotated column definition for database objects.
///
/// Ported from Ghidra's `DBAnnotatedColumn`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotatedColumn {
    /// Column name.
    pub name: String,
    /// Column type name.
    pub type_name: String,
    /// Whether the column is a primary key.
    pub is_primary_key: bool,
    /// Whether the column is indexed.
    pub is_indexed: bool,
}

impl AnnotatedColumn {
    /// Create a new annotated column.
    pub fn new(name: impl Into<String>, type_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            type_name: type_name.into(),
            is_primary_key: false,
            is_indexed: false,
        }
    }

    /// Set as primary key.
    pub fn primary_key(mut self) -> Self {
        self.is_primary_key = true;
        self
    }

    /// Set as indexed.
    pub fn indexed(mut self) -> Self {
        self.is_indexed = true;
        self
    }
}

/// An annotated field definition for database objects.
///
/// Ported from Ghidra's `DBAnnotatedField`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotatedField {
    /// Field name.
    pub name: String,
    /// Column index.
    pub column_index: usize,
    /// Default value (JSON).
    pub default_value: Option<serde_json::Value>,
}

impl AnnotatedField {
    /// Create a new annotated field.
    pub fn new(name: impl Into<String>, column_index: usize) -> Self {
        Self {
            name: name.into(),
            column_index,
            default_value: None,
        }
    }

    /// Set the default value.
    pub fn with_default(mut self, value: serde_json::Value) -> Self {
        self.default_value = Some(value);
        self
    }
}

/// Object information for annotated database objects.
///
/// Ported from Ghidra's `DBAnnotatedObjectInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotatedObjectInfo {
    /// Table name.
    pub table_name: String,
    /// Columns.
    pub columns: Vec<AnnotatedColumn>,
    /// Fields.
    pub fields: Vec<AnnotatedField>,
}

impl AnnotatedObjectInfo {
    /// Create new object info.
    pub fn new(table_name: impl Into<String>) -> Self {
        Self {
            table_name: table_name.into(),
            columns: Vec::new(),
            fields: Vec::new(),
        }
    }

    /// Add a column.
    pub fn add_column(&mut self, column: AnnotatedColumn) {
        self.columns.push(column);
    }

    /// Add a field.
    pub fn add_field(&mut self, field: AnnotatedField) {
        self.fields.push(field);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_span() {
        let span = KeySpan::new(0, 100);
        assert_eq!(span.len(), 101);
        assert!(span.contains(50));
        assert!(!span.contains(101));
    }

    #[test]
    fn test_key_span_overlaps() {
        let a = KeySpan::new(0, 50);
        let b = KeySpan::new(25, 75);
        let c = KeySpan::new(100, 200);

        assert!(a.overlaps(&b));
        assert!(b.overlaps(&a));
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn test_field_span() {
        let span = FieldSpan::new(0, 10, 20);
        assert_eq!(span.num_rows(), 11);
    }

    #[test]
    fn test_annotated_column() {
        let col = AnnotatedColumn::new("id", "long").primary_key().indexed();
        assert!(col.is_primary_key);
        assert!(col.is_indexed);
    }

    #[test]
    fn test_annotated_field() {
        let field = AnnotatedField::new("name", 1).with_default(serde_json::json!("unnamed"));
        assert_eq!(field.column_index, 1);
        assert!(field.default_value.is_some());
    }

    #[test]
    fn test_annotated_object_info() {
        let mut info = AnnotatedObjectInfo::new("threads");
        info.add_column(AnnotatedColumn::new("key", "long").primary_key());
        info.add_column(AnnotatedColumn::new("name", "string"));
        info.add_field(AnnotatedField::new("thread_name", 1));

        assert_eq!(info.columns.len(), 2);
        assert_eq!(info.fields.len(), 1);
    }
}
