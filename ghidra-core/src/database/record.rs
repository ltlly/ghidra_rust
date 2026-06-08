//! Record types ported from Java's `db` package.
//!
//! Provides [`GhidraRecord`], [`TableRecord`], and [`SparseRecord`] -- the
//! core record types used throughout the Ghidra database framework.
//!
//! - [`GhidraRecord`]: A data record with a primary key and typed field values.
//!   Port of Java `db.DBRecord`.
//! - [`TableRecord`]: Metadata record for a table in the master table.  Port
//!   of Java `db.TableRecord`.
//! - [`SparseRecord`]: A record that supports sparse column storage.  Port
//!   of Java `db.SparseRecord`.

use crate::database::error::IllegalFieldAccessException;
use crate::database::field::GhidraField;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

// ============================================================================
// GhidraRecord (port of Java DBRecord)
// ============================================================================

/// A database record containing a primary key and zero or more data fields.
///
/// Port of Java `db.DBRecord`. The record holds a key ([`GhidraField`]) and
/// a fixed-size array of column values ([`GhidraField`]) corresponding to
/// the table's schema.
#[derive(Debug, Clone)]
pub struct GhidraRecord {
    key: GhidraField,
    field_values: Vec<GhidraField>,
    field_names: Vec<String>,
    dirty: bool,
}

impl GhidraRecord {
    /// Create a new empty record with the given key and column definitions.
    ///
    /// Port of Java `DBRecord(Schema schema, Field key)`.
    pub fn new(key: GhidraField, field_types: &[GhidraField], field_names: &[String]) -> Self {
        let field_values: Vec<GhidraField> = field_types.iter().map(|f| f.new_field()).collect();
        Self {
            key,
            field_values,
            field_names: field_names.to_vec(),
            dirty: false,
        }
    }

    /// Create a record with pre-populated field values.
    pub fn with_values(
        key: GhidraField,
        field_values: Vec<GhidraField>,
        field_names: Vec<String>,
    ) -> Self {
        Self {
            key,
            field_values,
            field_names,
            dirty: false,
        }
    }

    // ---- Key accessors ----

    /// Get the primary key value as a long.
    ///
    /// Port of Java `DBRecord.getKey()`.
    pub fn get_key(&self) -> i64 {
        self.key.get_long_value().unwrap_or(0)
    }

    /// Get the primary key as a Field reference.
    ///
    /// Port of Java `DBRecord.getKeyField()`.
    pub fn get_key_field(&self) -> &GhidraField {
        &self.key
    }

    /// Get the primary key as a mutable Field reference.
    pub fn get_key_field_mut(&mut self) -> &mut GhidraField {
        &mut self.key
    }

    /// Set the primary key from a long value.
    ///
    /// Port of Java `DBRecord.setKey(long)`.
    pub fn set_key_long(&mut self, key: i64) {
        self.key = GhidraField::long(key);
        self.dirty = true;
    }

    /// Set the primary key from a Field.
    ///
    /// Port of Java `DBRecord.setKey(Field)`.
    pub fn set_key(&mut self, key: GhidraField) {
        self.key = key;
        self.dirty = true;
    }

    // ---- Column accessors ----

    /// Get the number of columns.
    ///
    /// Port of Java `DBRecord.getColumnCount()`.
    pub fn get_column_count(&self) -> usize {
        self.field_values.len()
    }

    /// Get a copy of the field value at the given column index.
    ///
    /// Port of Java `DBRecord.getFieldValue(int)`.
    pub fn get_field_value(&self, col_index: usize) -> &GhidraField {
        &self.field_values[col_index]
    }

    /// Get a mutable reference to the field value at the given column index.
    pub fn get_field_value_mut(&mut self, col_index: usize) -> &mut GhidraField {
        &mut self.field_values[col_index]
    }

    /// Set the field value at the given column index.
    ///
    /// Port of Java `DBRecord.setField(int, Field)`.
    pub fn set_field(&mut self, col_index: usize, value: GhidraField) {
        self.field_values[col_index] = value;
        self.dirty = true;
    }

    /// Get the field at the given column index (internal use).
    ///
    /// Port of Java `DBRecord.getField(int)`.
    pub fn get_field(&self, col_index: usize) -> &GhidraField {
        &self.field_values[col_index]
    }

    /// Get all field values.
    ///
    /// Port of Java `DBRecord.getFields()`.
    pub fn get_fields(&self) -> &[GhidraField] {
        &self.field_values
    }

    /// Get all field values (mutable).
    pub fn get_fields_mut(&mut self) -> &mut [GhidraField] {
        &mut self.field_values
    }

    /// Check if a field at the given index equals the specified field.
    ///
    /// Port of Java `DBRecord.fieldEquals(int, Field)`.
    pub fn field_equals(&self, col_index: usize, field: &GhidraField) -> bool {
        self.field_values[col_index].eq(field)
    }

    /// Compare a field value at the given index with another field.
    ///
    /// Port of Java `DBRecord.compareFieldTo(int, Field)`.
    pub fn compare_field_to(&self, col_index: usize, field: &GhidraField) -> Ordering {
        self.field_values[col_index].cmp(field)
    }

    /// Determine if this record has the same schema as another.
    ///
    /// Port of Java `DBRecord.hasSameSchema(DBRecord)`.
    pub fn has_same_schema(&self, other: &GhidraRecord) -> bool {
        if self.field_values.len() != other.field_values.len() {
            return false;
        }
        self.field_values
            .iter()
            .zip(other.field_values.iter())
            .all(|(a, b)| a.is_same_type(b))
    }

    /// Copy this record (deep clone).
    ///
    /// Port of Java `DBRecord.copy()`.
    pub fn copy(&self) -> Self {
        Self {
            key: self.key.copy_field(),
            field_values: self.field_values.iter().map(|f| f.copy_field()).collect(),
            field_names: self.field_names.clone(),
            dirty: false,
        }
    }

    // ---- Typed field accessors ----

    /// Get the long value for the specified column.
    ///
    /// Port of Java `DBRecord.getLongValue(int)`.
    pub fn get_long_value(&self, col_index: usize) -> Result<i64, IllegalFieldAccessException> {
        self.field_values[col_index].get_long_value()
    }

    /// Set the long value for the specified column.
    ///
    /// Port of Java `DBRecord.setLongValue(int, long)`.
    pub fn set_long_value(&mut self, col_index: usize, value: i64) -> Result<(), IllegalFieldAccessException> {
        self.dirty = true;
        self.field_values[col_index].set_long_value(value)
    }

    /// Get the int value for the specified column.
    ///
    /// Port of Java `DBRecord.getIntValue(int)`.
    pub fn get_int_value(&self, col_index: usize) -> Result<i32, IllegalFieldAccessException> {
        self.field_values[col_index].get_int_value()
    }

    /// Set the int value for the specified column.
    ///
    /// Port of Java `DBRecord.setIntValue(int, int)`.
    pub fn set_int_value(&mut self, col_index: usize, value: i32) -> Result<(), IllegalFieldAccessException> {
        self.dirty = true;
        self.field_values[col_index].set_int_value(value)
    }

    /// Get the short value for the specified column.
    ///
    /// Port of Java `DBRecord.getShortValue(int)`.
    pub fn get_short_value(&self, col_index: usize) -> Result<i16, IllegalFieldAccessException> {
        self.field_values[col_index].get_short_value()
    }

    /// Set the short value for the specified column.
    pub fn set_short_value(&mut self, col_index: usize, value: i16) -> Result<(), IllegalFieldAccessException> {
        self.dirty = true;
        self.field_values[col_index].set_short_value(value)
    }

    /// Get the byte value for the specified column.
    ///
    /// Port of Java `DBRecord.getByteValue(int)`.
    pub fn get_byte_value(&self, col_index: usize) -> Result<i8, IllegalFieldAccessException> {
        self.field_values[col_index].get_byte_value()
    }

    /// Set the byte value for the specified column.
    pub fn set_byte_value(&mut self, col_index: usize, value: i8) -> Result<(), IllegalFieldAccessException> {
        self.dirty = true;
        self.field_values[col_index].set_byte_value(value)
    }

    /// Get the boolean value for the specified column.
    ///
    /// Port of Java `DBRecord.getBooleanValue(int)`.
    pub fn get_boolean_value(&self, col_index: usize) -> Result<bool, IllegalFieldAccessException> {
        self.field_values[col_index].get_boolean_value()
    }

    /// Set the boolean value for the specified column.
    pub fn set_boolean_value(&mut self, col_index: usize, value: bool) -> Result<(), IllegalFieldAccessException> {
        self.dirty = true;
        self.field_values[col_index].set_boolean_value(value)
    }

    /// Get the string value for the specified column.
    ///
    /// Port of Java `DBRecord.getString(int)`.
    pub fn get_string_value(&self, col_index: usize) -> Result<Option<&str>, IllegalFieldAccessException> {
        self.field_values[col_index].get_string()
    }

    /// Set the string value for the specified column.
    pub fn set_string_value(&mut self, col_index: usize, value: Option<String>) -> Result<(), IllegalFieldAccessException> {
        self.dirty = true;
        self.field_values[col_index].set_string(value)
    }

    /// Get the binary data for the specified column.
    ///
    /// Port of Java `DBRecord.getBinaryData(int)`.
    pub fn get_binary_data(&self, col_index: usize) -> Option<&[u8]> {
        self.field_values[col_index].get_binary_data()
    }

    /// Set the binary data for the specified column.
    pub fn set_binary_data(&mut self, col_index: usize, data: Option<Vec<u8>>) {
        self.dirty = true;
        self.field_values[col_index].set_binary_data(data);
    }

    /// Set the field at the given index to null.
    ///
    /// Port of Java `DBRecord.setNull(int)`.
    pub fn set_null(&mut self, col_index: usize) {
        self.dirty = true;
        self.field_values[col_index].set_null();
    }

    // ---- Computed length ----

    /// Get the total storage length.
    ///
    /// Port of Java `DBRecord.length()`.
    pub fn length(&self) -> usize {
        self.field_values.iter().map(|f| f.length()).sum()
    }

    /// Whether the record has been modified since the last write.
    ///
    /// Port of Java `DBRecord.isDirty()`.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark the record as clean (not dirty).
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Get the field names from the schema.
    pub fn field_names(&self) -> &[String] {
        &self.field_names
    }
}

impl PartialEq for GhidraRecord {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.field_values == other.field_values
    }
}

impl Eq for GhidraRecord {}

impl Ord for GhidraRecord {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key)
    }
}

impl PartialOrd for GhidraRecord {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for GhidraRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{key:{}}}", self.key)
    }
}

// ============================================================================
// TableRecord (port of Java TableRecord)
// ============================================================================

/// Metadata record for a table stored in the master table.
///
/// Port of Java `db.TableRecord`. Each table in the Ghidra database has
/// an associated `TableRecord` that stores its schema, root buffer ID,
/// record count, and maximum key.
#[derive(Debug, Clone)]
pub struct TableRecord {
    table_num: i64,
    name: String,
    schema_key_field_type: u8,
    schema_field_types: Vec<u8>,
    schema_field_names: Vec<String>,
    root_buffer_id: i32,
    record_count: i32,
    max_key: i64,
    indexed_column: i32,
    dirty: bool,
}

impl TableRecord {
    /// Create a new TableRecord.
    pub fn new(
        table_num: i64,
        name: impl Into<String>,
        key_field_type: u8,
        field_types: Vec<u8>,
        field_names: Vec<String>,
        indexed_column: i32,
    ) -> Self {
        Self {
            table_num,
            name: name.into(),
            schema_key_field_type: key_field_type,
            schema_field_types: field_types,
            schema_field_names: field_names,
            root_buffer_id: -1,
            record_count: 0,
            max_key: i64::MIN,
            indexed_column,
            dirty: true,
        }
    }

    /// Get the table number (unique identifier within the database).
    pub fn get_table_num(&self) -> i64 {
        self.table_num
    }

    /// Get the table name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Set the table name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
        self.dirty = true;
    }

    /// Get the root buffer ID.
    pub fn get_root_buffer_id(&self) -> i32 {
        self.root_buffer_id
    }

    /// Set the root buffer ID.
    pub fn set_root_buffer_id(&mut self, id: i32) {
        self.root_buffer_id = id;
        self.dirty = true;
    }

    /// Get the record count.
    pub fn get_record_count(&self) -> i32 {
        self.record_count
    }

    /// Set the record count.
    pub fn set_record_count(&mut self, count: i32) {
        self.record_count = count;
        self.dirty = true;
    }

    /// Get the maximum key.
    pub fn get_max_key(&self) -> i64 {
        self.max_key
    }

    /// Set the maximum key.
    pub fn set_max_key(&mut self, key: i64) {
        self.max_key = key;
        self.dirty = true;
    }

    /// Get the indexed column (-1 if this is not an index table).
    pub fn get_indexed_column(&self) -> i32 {
        self.indexed_column
    }

    /// Get the key field type byte.
    pub fn get_key_field_type(&self) -> u8 {
        self.schema_key_field_type
    }

    /// Get the encoded field types.
    pub fn get_field_types(&self) -> &[u8] {
        &self.schema_field_types
    }

    /// Get the field names.
    pub fn get_field_names(&self) -> &[String] {
        &self.schema_field_names
    }

    /// Whether this record has been modified.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark this record as clean.
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Invalidate this table record (table was deleted).
    pub fn invalidate(&mut self) {
        self.root_buffer_id = -1;
        self.record_count = 0;
    }
}

impl PartialEq for TableRecord {
    fn eq(&self, other: &Self) -> bool {
        self.table_num == other.table_num
    }
}

impl Eq for TableRecord {}

impl Ord for TableRecord {
    fn cmp(&self, other: &Self) -> Ordering {
        self.table_num.cmp(&other.table_num)
    }
}

impl PartialOrd for TableRecord {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for TableRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TableRecord(num={}, name={}, records={}, maxKey={})",
            self.table_num, self.name, self.record_count, self.max_key
        )
    }
}

// ============================================================================
// SparseRecord (port of Java SparseRecord)
// ============================================================================

/// A record variant that supports sparse column storage.
///
/// Port of Java `db.SparseRecord`. Sparse records use a map instead of a
/// fixed array for columns, so null/empty columns do not consume storage.
#[derive(Debug, Clone)]
pub struct SparseRecord {
    key: GhidraField,
    field_values: BTreeMap<usize, GhidraField>,
    column_count: usize,
    _field_names: Vec<String>,
    dirty: bool,
}

impl SparseRecord {
    /// Create a new sparse record.
    pub fn new(key: GhidraField, column_count: usize, field_names: Vec<String>) -> Self {
        Self {
            key,
            field_values: BTreeMap::new(),
            column_count,
            _field_names: field_names,
            dirty: false,
        }
    }

    /// Get the primary key.
    pub fn get_key_field(&self) -> &GhidraField {
        &self.key
    }

    /// Get the primary key as a long.
    pub fn get_key(&self) -> i64 {
        self.key.get_long_value().unwrap_or(0)
    }

    /// Set the primary key.
    pub fn set_key(&mut self, key: GhidraField) {
        self.key = key;
        self.dirty = true;
    }

    /// Set a field value at the given column index.
    ///
    /// Passing `None` marks the column as null/sparse.
    ///
    /// Port of Java `SparseRecord.setField(int, Field)`.
    pub fn set_field(&mut self, col_index: usize, value: Option<GhidraField>) {
        if let Some(v) = value {
            self.field_values.insert(col_index, v);
        } else {
            self.field_values.remove(&col_index);
        }
        self.dirty = true;
    }

    /// Get a field value at the given column index.
    ///
    /// Returns `None` if the column is null/sparse.
    ///
    /// Port of Java `SparseRecord.getField(int)`.
    pub fn get_field(&self, col_index: usize) -> Option<&GhidraField> {
        self.field_values.get(&col_index)
    }

    /// Get the total column count (including sparse null columns).
    pub fn get_column_count(&self) -> usize {
        self.column_count
    }

    /// Get the number of non-null columns.
    pub fn get_stored_column_count(&self) -> usize {
        self.field_values.len()
    }

    /// Whether the given column is null (sparse).
    pub fn is_null(&self, col_index: usize) -> bool {
        !self.field_values.contains_key(&col_index)
    }

    /// Get the dirty flag.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark clean.
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Iterate over stored (non-null) fields.
    pub fn iter_fields(&self) -> impl Iterator<Item = (usize, &GhidraField)> {
        self.field_values.iter().map(|(&k, v)| (k, v))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghidra_record_basics() {
        let key = GhidraField::long(1);
        let field_types = vec![GhidraField::string(""), GhidraField::int(0)];
        let field_names = vec!["name".to_string(), "age".to_string()];
        let mut rec = GhidraRecord::new(key, &field_types, &field_names);

        assert_eq!(rec.get_key(), 1);
        assert_eq!(rec.get_column_count(), 2);
        assert!(!rec.is_dirty());

        rec.set_string_value(0, Some("Alice".to_string())).unwrap();
        rec.set_int_value(1, 30).unwrap();
        assert!(rec.is_dirty());
        assert_eq!(rec.get_string_value(0).unwrap(), Some("Alice"));
        assert_eq!(rec.get_int_value(1).unwrap(), 30);
    }

    #[test]
    fn test_ghidra_record_comparison() {
        let r1 = GhidraRecord::new(
            GhidraField::long(1),
            &[GhidraField::int(0)],
            &["v".to_string()],
        );
        let r2 = GhidraRecord::new(
            GhidraField::long(2),
            &[GhidraField::int(0)],
            &["v".to_string()],
        );
        assert!(r1 < r2);
    }

    #[test]
    fn test_ghidra_record_copy() {
        let key = GhidraField::long(42);
        let mut rec = GhidraRecord::new(
            key,
            &[GhidraField::string("")],
            &["data".to_string()],
        );
        rec.set_string_value(0, Some("hello".to_string())).unwrap();
        let copy = rec.copy();
        assert_eq!(rec, copy);
    }

    #[test]
    fn test_table_record_basics() {
        let mut tr = TableRecord::new(1, "test_table", 3, vec![3, 4], vec!["id".into(), "name".into()], -1);
        assert_eq!(tr.get_table_num(), 1);
        assert_eq!(tr.get_name(), "test_table");
        assert_eq!(tr.get_root_buffer_id(), -1);

        tr.set_root_buffer_id(42);
        tr.set_record_count(100);
        tr.set_max_key(99);
        assert_eq!(tr.get_root_buffer_id(), 42);
        assert_eq!(tr.get_record_count(), 100);
        assert_eq!(tr.get_max_key(), 99);
        assert!(tr.is_dirty());
    }

    #[test]
    fn test_table_record_ordering() {
        let tr1 = TableRecord::new(1, "a", 3, vec![], vec![], -1);
        let tr2 = TableRecord::new(2, "b", 3, vec![], vec![], -1);
        assert!(tr1 < tr2);
    }

    #[test]
    fn test_table_record_invalidate() {
        let mut tr = TableRecord::new(1, "test", 3, vec![], vec![], -1);
        tr.set_root_buffer_id(10);
        tr.set_record_count(5);
        tr.invalidate();
        assert_eq!(tr.get_root_buffer_id(), -1);
        assert_eq!(tr.get_record_count(), 0);
    }

    #[test]
    fn test_sparse_record_basics() {
        let key = GhidraField::long(1);
        let mut rec = SparseRecord::new(key, 10, vec!["a".into(), "b".into(), "c".into()]);

        assert_eq!(rec.get_column_count(), 10);
        assert_eq!(rec.get_stored_column_count(), 0);
        assert!(rec.is_null(0));

        rec.set_field(0, Some(GhidraField::int(42)));
        assert_eq!(rec.get_stored_column_count(), 1);
        assert!(!rec.is_null(0));
        assert_eq!(rec.get_field(0).unwrap().get_int_value().unwrap(), 42);

        rec.set_field(0, None);
        assert!(rec.is_null(0));
    }

    #[test]
    fn test_sparse_record_iteration() {
        let key = GhidraField::long(1);
        let mut rec = SparseRecord::new(key, 5, vec![]);
        rec.set_field(1, Some(GhidraField::string("hello")));
        rec.set_field(3, Some(GhidraField::int(42)));

        let fields: Vec<(usize, &GhidraField)> = rec.iter_fields().collect();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].0, 1);
        assert_eq!(fields[1].0, 3);
    }
}
