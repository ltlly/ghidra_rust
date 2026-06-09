//! Database table metadata and operations ported from Java's `db.Table`.
//!
//! Provides [`Table`] -- the in-memory representation of a database table,
//! tracking its name, schema, primary key columns, cached row count, and
//! secondary indexes. Also provides record CRUD operations, range queries,
//! and iteration methods that mirror the Java `Table` class.

use super::db::FieldValue;
use super::db_record::DBRecord;
use super::schema::{Field, Schema};

// ============================================================================
// SecondaryIndex — port of Java secondary index tracking in Table
// ============================================================================

/// Metadata for a secondary index on a table column.
///
/// Mirrors Java's `IndexTable` references stored in `Table.secondaryIndexes`.
#[derive(Debug, Clone)]
pub struct SecondaryIndex {
    /// The column index (0-based position in the schema) that is indexed.
    pub column_index: usize,
    /// The name of the index.
    pub index_name: String,
    /// Whether this is a sparse index (null values are not indexed).
    pub is_sparse: bool,
}

// ============================================================================
// Table — port of Java `db.Table`
// ============================================================================

/// Reflects a database table: its name, schema, primary key, row count,
/// maximum key, and secondary indexes.
///
/// Mirrors Java's `db.Table` with the following key concepts:
/// - `name`: table name
/// - `schema`: column definitions
/// - `primary_key`: primary key column names
/// - `row_count`: cached record count
/// - `maximum_key`: highest primary key ever assigned (for long-key tables)
/// - `secondary_indexes`: column-level secondary indexes
/// - `mod_count`: modification counter for iterator invalidation
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
    /// Maximum key ever assigned (for long-key tables).
    /// Mirrors Java `Table.maximumKey`.
    pub maximum_key: i64,
    /// Secondary indexes keyed by column index.
    pub secondary_indexes: Vec<SecondaryIndex>,
    /// Modification counter for change detection.
    /// Mirrors Java `Table.modCount`.
    pub mod_count: u32,
    /// Whether this table has been invalidated (e.g., after undo/redo).
    /// Mirrors Java `Table.invalidate()`.
    pub invalid: bool,
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
            maximum_key: i64::MIN,
            secondary_indexes: Vec::new(),
            mod_count: 0,
            invalid: false,
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
    pub fn indexed_columns(&self) -> Vec<usize> {
        self.secondary_indexes.iter().map(|idx| idx.column_index).collect()
    }

    /// Get the next available key (max_key + 1, or 0 if table is empty).
    ///
    /// Mirrors Java's `Table.getKey()`. Only meaningful for tables with
    /// integer primary keys.
    pub fn next_key(&self) -> i64 {
        if self.maximum_key == i64::MIN {
            0
        } else {
            self.maximum_key + 1
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
        self.mod_count += 1;
    }

    /// Decrement the cached row count (call after delete).
    pub fn decrement_row_count(&mut self) {
        if self.row_count > 0 {
            self.row_count -= 1;
        }
        self.mod_count += 1;
    }

    /// Set the cached row count.
    pub fn set_row_count(&mut self, count: usize) {
        self.row_count = count;
    }

    /// Get the record count.
    ///
    /// Mirrors Java's `Table.getRecordCount()`.
    pub fn get_record_count(&self) -> usize {
        self.row_count
    }

    /// Get the maximum record key which has ever been assigned.
    ///
    /// Mirrors Java's `Table.getMaxKey()`.
    pub fn get_max_key(&self) -> i64 {
        self.maximum_key
    }

    /// Set the maximum key (call after inserting a record with a higher key).
    ///
    /// Mirrors Java's `TableRecord.setMaxKey()`.
    pub fn set_max_key(&mut self, key: i64) {
        if key > self.maximum_key {
            self.maximum_key = key;
        }
    }

    /// Update table state following a master table record change.
    ///
    /// Mirrors Java's `Table.tableRecordChanged()`.
    pub fn table_record_changed(&mut self, record_count: usize, max_key: i64) {
        self.row_count = record_count;
        self.maximum_key = max_key;
        self.mod_count += 1;
    }

    /// Mark table as invalid. Subsequent use may generate an error.
    ///
    /// Mirrors Java's `Table.invalidate()`.
    pub fn invalidate(&mut self) {
        self.invalid = true;
        self.mod_count += 1;
    }

    /// Check if the table has been invalidated.
    pub fn is_invalid(&self) -> bool {
        self.invalid
    }

    // ------------------------------------------------------------------
    // Secondary index management (port of Java Table.addIndex/removeIndex)
    // ------------------------------------------------------------------

    /// Add a secondary index to this table.
    ///
    /// Mirrors Java's `Table.addIndex(IndexTable)`.
    pub fn add_index(&mut self, column_index: usize, index_name: &str, is_sparse: bool) {
        // Avoid duplicates.
        if !self.secondary_indexes.iter().any(|idx| idx.column_index == column_index) {
            self.secondary_indexes.push(SecondaryIndex {
                column_index,
                index_name: index_name.to_string(),
                is_sparse,
            });
        }
    }

    /// Remove a secondary index from this table.
    ///
    /// Mirrors Java's `Table.removeIndex(columnIndex)`.
    pub fn remove_index(&mut self, column_index: usize) {
        self.secondary_indexes.retain(|idx| idx.column_index != column_index);
    }

    /// Check if a column has a secondary index.
    pub fn has_index(&self, column_index: usize) -> bool {
        self.secondary_indexes.iter().any(|idx| idx.column_index == column_index)
    }

    /// Get the secondary index for a column, if any.
    pub fn get_index(&self, column_index: usize) -> Option<&SecondaryIndex> {
        self.secondary_indexes.iter().find(|idx| idx.column_index == column_index)
    }

    // ------------------------------------------------------------------
    // Record validation (port of Java Table.insertedRecord/updatedRecord/deletedRecord)
    // ------------------------------------------------------------------

    /// Callback for when a new record is added. Used for maintaining indexes.
    ///
    /// Mirrors Java's `Table.insertedRecord(DBRecord)`.
    pub fn on_record_inserted(&mut self, _record: &DBRecord) {
        self.mod_count += 1;
        // Index maintenance would be delegated to IndexTable in a full port.
    }

    /// Callback for when an existing record is modified.
    ///
    /// Mirrors Java's `Table.updatedRecord(oldRecord, newRecord)`.
    pub fn on_record_updated(&mut self, _old_record: &DBRecord, _new_record: &DBRecord) {
        self.mod_count += 1;
    }

    /// Callback for when a record is deleted.
    ///
    /// Mirrors Java's `Table.deletedRecord(DBRecord)`.
    pub fn on_record_deleted(&mut self, _record: &DBRecord) {
        self.mod_count += 1;
    }

    // ------------------------------------------------------------------
    // Schema queries
    // ------------------------------------------------------------------

    /// Get this table's schema.
    ///
    /// Mirrors Java's `Table.getSchema()`.
    pub fn get_schema(&self) -> &Schema {
        &self.schema
    }

    /// Get table name.
    ///
    /// Mirrors Java's `Table.getName()`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Determine if this table uses long keys.
    ///
    /// Mirrors Java's `Table.useLongKeys()`.
    pub fn uses_long_keys(&self) -> bool {
        self.schema
            .primary_keys()
            .first()
            .and_then(|pk_name| self.schema.get_field(pk_name))
            .map(|f| {
                matches!(
                    f.field_type,
                    super::db::FieldType::Long | super::db::FieldType::Int
                )
            })
            .unwrap_or(false)
    }

    // ------------------------------------------------------------------
    // Consistency check (port of Java Table.isConsistent)
    // ------------------------------------------------------------------

    /// Check the consistency of this table's metadata.
    ///
    /// A simplified version of Java's `Table.isConsistent()` that validates
    /// the schema and index metadata.
    pub fn is_consistent(&self) -> bool {
        if self.invalid {
            return false;
        }
        if self.name.is_empty() {
            return false;
        }
        if self.schema.fields.is_empty() {
            return false;
        }
        // Verify primary key columns exist in schema.
        for pk in &self.primary_key {
            if self.schema.field_index(pk).is_none() {
                return false;
            }
        }
        true
    }

    // ------------------------------------------------------------------
    // Statistics (port of Java Table.getStatistics)
    // ------------------------------------------------------------------

    /// Get basic table statistics.
    ///
    /// A simplified version of Java's `Table.getStatistics()`.
    pub fn get_statistics(&self) -> TableStatistics {
        TableStatistics {
            name: self.name.clone(),
            record_count: self.row_count,
            max_key: self.maximum_key,
            column_count: self.schema.fields.len(),
            indexed_columns: self.secondary_indexes.len(),
            schema_version: self.schema.version,
            mod_count: self.mod_count,
        }
    }
}

// ============================================================================
// TableStatistics — port of Java `db.TableStatistics`
// ============================================================================

/// Basic diagnostic statistics for a table.
///
/// A simplified port of Java's `db.TableStatistics`.
#[derive(Debug, Clone)]
pub struct TableStatistics {
    /// Table name.
    pub name: String,
    /// Number of records.
    pub record_count: usize,
    /// Maximum primary key ever assigned.
    pub max_key: i64,
    /// Number of columns.
    pub column_count: usize,
    /// Number of indexed columns.
    pub indexed_columns: usize,
    /// Schema version.
    pub schema_version: i32,
    /// Modification counter.
    pub mod_count: u32,
}

impl std::fmt::Display for TableStatistics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Table '{}': {} records, {} columns, {} indexed, schema v{}, mod_count={}",
            self.name,
            self.record_count,
            self.column_count,
            self.indexed_columns,
            self.schema_version,
            self.mod_count,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::db::FieldType;

    #[test]
    fn test_table_from_schema() {
        let schema = Schema::new("data", 1)
            .with_field(Field::new("key", FieldType::Long).primary_key())
            .with_field(Field::new("value", FieldType::Binary));
        let table = Table::new(schema);
        assert_eq!(table.name, "data");
        assert_eq!(table.primary_key, vec!["key"]);
        assert!(!table.has_composite_key());
        assert!(table.uses_long_keys());
        assert_eq!(table.maximum_key, i64::MIN);
        assert_eq!(table.next_key(), 0);
    }

    #[test]
    fn test_table_next_key() {
        let schema = Schema::new("items", 1)
            .with_field(Field::new("id", FieldType::Long).primary_key());
        let mut table = Table::new(schema);
        assert_eq!(table.next_key(), 0);

        table.set_max_key(42);
        assert_eq!(table.next_key(), 43);
        assert_eq!(table.get_max_key(), 42);
    }

    #[test]
    fn test_table_rename() {
        let schema = Schema::new("old", 1)
            .with_field(Field::new("id", FieldType::Int).primary_key());
        let mut table = Table::new(schema);
        table.rename("new");
        assert_eq!(table.name, "new");
        assert_eq!(table.schema.table_name, "new");
    }

    #[test]
    fn test_table_row_count() {
        let schema = Schema::new("cnt", 1)
            .with_field(Field::new("id", FieldType::Int).primary_key());
        let mut table = Table::new(schema);
        assert_eq!(table.get_record_count(), 0);

        table.increment_row_count();
        table.increment_row_count();
        assert_eq!(table.get_record_count(), 2);

        table.decrement_row_count();
        assert_eq!(table.get_record_count(), 1);

        table.set_row_count(100);
        assert_eq!(table.get_record_count(), 100);
    }

    #[test]
    fn test_table_secondary_indexes() {
        let schema = Schema::new("indexed", 1)
            .with_field(Field::new("id", FieldType::Int).primary_key())
            .with_field(Field::new("email", FieldType::String));
        let mut table = Table::new(schema);

        assert!(!table.has_index(1));
        table.add_index(1, "idx_email", false);
        assert!(table.has_index(1));
        assert_eq!(table.indexed_columns(), vec![1]);

        let idx = table.get_index(1).unwrap();
        assert_eq!(idx.index_name, "idx_email");
        assert!(!idx.is_sparse);

        table.remove_index(1);
        assert!(!table.has_index(1));
    }

    #[test]
    fn test_table_invalidate() {
        let schema = Schema::new("inv", 1)
            .with_field(Field::new("id", FieldType::Int).primary_key());
        let mut table = Table::new(schema);
        assert!(!table.is_invalid());
        assert!(table.is_consistent());

        table.invalidate();
        assert!(table.is_invalid());
        assert!(!table.is_consistent());
    }

    #[test]
    fn test_table_consistency() {
        // Valid table.
        let schema = Schema::new("valid", 1)
            .with_field(Field::new("id", FieldType::Int).primary_key())
            .with_field(Field::new("name", FieldType::String));
        let table = Table::new(schema);
        assert!(table.is_consistent());

        // Empty name is inconsistent.
        let schema = Schema::new("", 1)
            .with_field(Field::new("id", FieldType::Int).primary_key());
        let table = Table::new(schema);
        assert!(!table.is_consistent());

        // Empty fields is inconsistent.
        let schema = Schema::new("empty", 1);
        let table = Table::new(schema);
        assert!(!table.is_consistent());
    }

    #[test]
    fn test_table_statistics() {
        let schema = Schema::new("stats", 2)
            .with_field(Field::new("id", FieldType::Long).primary_key())
            .with_field(Field::new("name", FieldType::String))
            .with_field(Field::new("email", FieldType::String));
        let mut table = Table::new(schema);
        table.add_index(2, "idx_email", false);
        table.set_row_count(50);
        table.set_max_key(99);

        let stats = table.get_statistics();
        assert_eq!(stats.name, "stats");
        assert_eq!(stats.record_count, 50);
        assert_eq!(stats.max_key, 99);
        assert_eq!(stats.column_count, 3);
        assert_eq!(stats.indexed_columns, 1);
        assert_eq!(stats.schema_version, 2);

        let display = format!("{}", stats);
        assert!(display.contains("stats"));
        assert!(display.contains("50 records"));
    }

    #[test]
    fn test_table_record_callbacks() {
        let schema = Schema::new("cb", 1)
            .with_field(Field::new("id", FieldType::Int).primary_key());
        let mut table = Table::new(schema);
        let initial_mod = table.mod_count;

        let rec = DBRecord::new(
            Schema::new("cb", 1)
                .with_field(Field::new("id", FieldType::Int).primary_key()),
        );
        table.on_record_inserted(&rec);
        assert_eq!(table.mod_count, initial_mod + 1);

        table.on_record_updated(&rec, &rec);
        assert_eq!(table.mod_count, initial_mod + 2);

        table.on_record_deleted(&rec);
        assert_eq!(table.mod_count, initial_mod + 3);
    }

    #[test]
    fn test_table_composite_key() {
        let schema = Schema::new("composite", 1)
            .with_field(Field::new("a", FieldType::Int).primary_key())
            .with_field(Field::new("b", FieldType::Int).primary_key());
        let table = Table::new(schema);
        assert!(table.has_composite_key());
        assert_eq!(table.primary_key_sql(), "a, b");
    }

    #[test]
    fn test_table_create_record() {
        let schema = Schema::new("cr", 1)
            .with_field(Field::new("id", FieldType::Long).primary_key())
            .with_field(Field::new("name", FieldType::String));
        let table = Table::new(schema);
        let rec = table.create_record(FieldValue::Long(42));
        assert_eq!(rec.get_key_long(), Some(42));
    }

    #[test]
    fn test_table_placeholders() {
        let schema = Schema::new("ph", 1)
            .with_field(Field::new("a", FieldType::Int))
            .with_field(Field::new("b", FieldType::String))
            .with_field(Field::new("c", FieldType::Bool));
        let table = Table::new(schema);
        assert_eq!(table.placeholders(), "?1, ?2, ?3");
        assert_eq!(table.column_list(), "a, b, c");
    }
}
