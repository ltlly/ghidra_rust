//! Table column and descriptor definitions for the VT database.

use std::fmt;

/// Represents a column field type in the VT database schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldType {
    /// String field
    String,
    /// Integer field (32-bit)
    Int,
    /// Long field (64-bit)
    Long,
    /// Double field (64-bit float)
    Double,
    /// Boolean field
    Bool,
    /// Binary blob field
    Blob,
}

impl FieldType {
    /// Returns the SQLite type name for this field type.
    pub fn sql_type(&self) -> &'static str {
        match self {
            FieldType::String => "TEXT",
            FieldType::Int => "INTEGER",
            FieldType::Long => "INTEGER",
            FieldType::Double => "REAL",
            FieldType::Bool => "INTEGER",
            FieldType::Blob => "BLOB",
        }
    }
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldType::String => write!(f, "String"),
            FieldType::Int => write!(f, "Int"),
            FieldType::Long => write!(f, "Long"),
            FieldType::Double => write!(f, "Double"),
            FieldType::Bool => write!(f, "Bool"),
            FieldType::Blob => write!(f, "Blob"),
        }
    }
}

/// Represents a single column in a VT database table.
#[derive(Debug, Clone)]
pub struct TableColumn {
    /// The column name
    name: String,
    /// The field type
    field_type: FieldType,
    /// Whether this column is indexed
    indexed: bool,
    /// The ordinal position of the column (0-based)
    ordinal: usize,
}

impl TableColumn {
    /// Create a new table column.
    pub fn new(name: impl Into<String>, field_type: FieldType) -> Self {
        Self {
            name: name.into(),
            field_type,
            indexed: false,
            ordinal: 0,
        }
    }

    /// Create a new indexed table column.
    pub fn indexed(name: impl Into<String>, field_type: FieldType) -> Self {
        Self {
            name: name.into(),
            field_type,
            indexed: true,
            ordinal: 0,
        }
    }

    /// Set the ordinal position.
    pub fn set_ordinal(&mut self, ordinal: usize) {
        self.ordinal = ordinal;
    }

    /// Returns the column name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the field type.
    pub fn field_type(&self) -> FieldType {
        self.field_type
    }

    /// Returns whether this column is indexed.
    pub fn is_indexed(&self) -> bool {
        self.indexed
    }

    /// Returns the ordinal position.
    pub fn column(&self) -> usize {
        self.ordinal
    }
}

impl fmt::Display for TableColumn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.name, self.ordinal)
    }
}

/// Describes the full schema of a VT database table.
#[derive(Debug, Clone)]
pub struct TableDescriptor {
    columns: Vec<TableColumn>,
    table_name: String,
}

impl TableDescriptor {
    /// Create a new table descriptor.
    pub fn new(table_name: impl Into<String>) -> Self {
        Self {
            columns: Vec::new(),
            table_name: table_name.into(),
        }
    }

    /// Add a column to this descriptor.
    pub fn add_column(mut self, name: impl Into<String>, field_type: FieldType) -> Self {
        let ordinal = self.columns.len();
        let mut col = TableColumn::new(name, field_type);
        col.set_ordinal(ordinal);
        self.columns.push(col);
        self
    }

    /// Add an indexed column to this descriptor.
    pub fn add_indexed_column(mut self, name: impl Into<String>, field_type: FieldType) -> Self {
        let ordinal = self.columns.len();
        let mut col = TableColumn::indexed(name, field_type);
        col.set_ordinal(ordinal);
        self.columns.push(col);
        self
    }

    /// Returns the table name.
    pub fn table_name(&self) -> &str {
        &self.table_name
    }

    /// Returns the columns.
    pub fn columns(&self) -> &[TableColumn] {
        &self.columns
    }

    /// Returns indices of indexed columns.
    pub fn indexed_columns(&self) -> Vec<usize> {
        self.columns
            .iter()
            .enumerate()
            .filter(|(_, c)| c.is_indexed())
            .map(|(i, _)| i)
            .collect()
    }

    /// Returns column names.
    pub fn column_names(&self) -> Vec<&str> {
        self.columns.iter().map(|c| c.name()).collect()
    }

    /// Returns column field types.
    pub fn column_fields(&self) -> Vec<FieldType> {
        self.columns.iter().map(|c| c.field_type()).collect()
    }

    /// Generate a CREATE TABLE SQL statement.
    pub fn create_table_sql(&self) -> String {
        let mut sql = format!("CREATE TABLE IF NOT EXISTS {} (", self.table_name);
        let mut first = true;

        // Primary key column (always ID as INTEGER)
        sql.push_str("id INTEGER PRIMARY KEY");
        first = false;

        for col in &self.columns {
            if !first {
                sql.push(',');
            }
            sql.push_str(&format!(" {} {}", col.name, col.field_type.sql_type()));
            first = false;
        }
        sql.push(')');
        sql
    }

    /// Generate CREATE INDEX SQL statements for indexed columns.
    pub fn create_index_sql(&self) -> Vec<String> {
        self.columns
            .iter()
            .filter(|c| c.is_indexed())
            .map(|c| {
                format!(
                    "CREATE INDEX IF NOT EXISTS idx_{}_{} ON {} ({})",
                    self.table_name, c.name, self.table_name, c.name
                )
            })
            .collect()
    }
}

/// Defines the schema for the VT Match Set table.
pub fn match_set_table_descriptor() -> TableDescriptor {
    TableDescriptor::new("vt_match_set")
        .add_column("correlator_name", FieldType::String)
        .add_column("correlator_description", FieldType::String)
        .add_column("source_address_set", FieldType::String)
        .add_column("destination_address_set", FieldType::String)
        .add_column("options_xml", FieldType::String)
}

/// Defines the schema for the VT Match table.
pub fn match_table_descriptor(table_id: i64) -> TableDescriptor {
    TableDescriptor::new(format!("vt_match_{}", table_id))
        .add_indexed_column("association_id", FieldType::Long)
        .add_column("match_set_id", FieldType::Long)
        .add_column("source_address", FieldType::Long)
        .add_column("destination_address", FieldType::Long)
        .add_column("association_type", FieldType::Int)
        .add_column("similarity_score", FieldType::String)
        .add_column("confidence_score", FieldType::String)
        .add_column("source_length", FieldType::Int)
        .add_column("destination_length", FieldType::Int)
        .add_column("length_type", FieldType::String)
        .add_column("tag_key", FieldType::Long)
}

/// Defines the schema for the VT Association table.
pub fn association_table_descriptor() -> TableDescriptor {
    TableDescriptor::new("vt_association")
        .add_column("association_type", FieldType::Int)
        .add_column("source_address", FieldType::Long)
        .add_column("destination_address", FieldType::Long)
        .add_column("status", FieldType::Int)
        .add_column("vote_count", FieldType::Int)
        .add_indexed_column("source_address_idx", FieldType::Long)
        .add_indexed_column("destination_address_idx", FieldType::Long)
}

/// Defines the schema for the VT Tag table.
pub fn tag_table_descriptor() -> TableDescriptor {
    TableDescriptor::new("vt_match_tag")
        .add_indexed_column("name", FieldType::String)
}

/// Defines the schema for the VT Markup Item table.
pub fn markup_item_table_descriptor(table_id: i64) -> TableDescriptor {
    TableDescriptor::new(format!("vt_markup_item_{}", table_id))
        .add_indexed_column("association_id", FieldType::Long)
        .add_column("markup_type_id", FieldType::Int)
        .add_column("source_address", FieldType::Long)
        .add_column("destination_address", FieldType::Long)
        .add_column("destination_address_source", FieldType::String)
        .add_column("source_value", FieldType::String)
        .add_column("destination_value", FieldType::String)
        .add_column("original_destination_value", FieldType::String)
        .add_column("status", FieldType::Int)
        .add_column("status_description", FieldType::String)
}

/// Defines the schema for the VT Address Correlator table.
pub fn address_correlator_table_descriptor() -> TableDescriptor {
    TableDescriptor::new("vt_address_correlator")
        .add_column("correlator_class_name", FieldType::String)
        .add_column("source_entry", FieldType::Long)
        .add_column("destination_entry", FieldType::Long)
        .add_column("mappings_xml", FieldType::String)
        .add_column("confidence", FieldType::Double)
}

/// Defines the schema for the VT Session property table.
pub fn session_property_table_descriptor() -> TableDescriptor {
    TableDescriptor::new("vt_session_property")
        .add_column("key", FieldType::String)
        .add_column("value", FieldType::String)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_column() {
        let mut col = TableColumn::new("name", FieldType::String);
        assert_eq!(col.name(), "name");
        assert_eq!(col.field_type(), FieldType::String);
        assert!(!col.is_indexed());
        col.set_ordinal(3);
        assert_eq!(col.column(), 3);
    }

    #[test]
    fn test_indexed_column() {
        let col = TableColumn::indexed("association_id", FieldType::Long);
        assert!(col.is_indexed());
    }

    #[test]
    fn test_table_descriptor() {
        let desc = TableDescriptor::new("test_table")
            .add_column("col1", FieldType::String)
            .add_indexed_column("col2", FieldType::Long)
            .add_column("col3", FieldType::Int);

        assert_eq!(desc.table_name(), "test_table");
        assert_eq!(desc.columns().len(), 3);
        assert_eq!(desc.indexed_columns(), vec![1]);
        assert_eq!(desc.column_names(), vec!["col1", "col2", "col3"]);
    }

    #[test]
    fn test_create_table_sql() {
        let desc = TableDescriptor::new("test")
            .add_column("name", FieldType::String)
            .add_column("value", FieldType::Int);
        let sql = desc.create_table_sql();
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS test"));
        assert!(sql.contains("id INTEGER PRIMARY KEY"));
        assert!(sql.contains("name TEXT"));
        assert!(sql.contains("value INTEGER"));
    }

    #[test]
    fn test_create_index_sql() {
        let desc = TableDescriptor::new("test")
            .add_indexed_column("assoc_id", FieldType::Long);
        let indexes = desc.create_index_sql();
        assert_eq!(indexes.len(), 1);
        assert!(indexes[0].contains("CREATE INDEX"));
        assert!(indexes[0].contains("idx_test_assoc_id"));
    }

    #[test]
    fn test_field_type_sql() {
        assert_eq!(FieldType::String.sql_type(), "TEXT");
        assert_eq!(FieldType::Int.sql_type(), "INTEGER");
        assert_eq!(FieldType::Long.sql_type(), "INTEGER");
        assert_eq!(FieldType::Double.sql_type(), "REAL");
        assert_eq!(FieldType::Bool.sql_type(), "INTEGER");
        assert_eq!(FieldType::Blob.sql_type(), "BLOB");
    }

    #[test]
    fn test_match_set_table_descriptor() {
        let desc = match_set_table_descriptor();
        assert_eq!(desc.table_name(), "vt_match_set");
        assert!(desc.columns().len() >= 3);
    }

    #[test]
    fn test_match_table_descriptor() {
        let desc = match_table_descriptor(1);
        assert!(desc.table_name().contains("vt_match_1"));
        assert!(desc.indexed_columns().len() >= 1);
    }
}
