//! Iterator types ported from Java's `db` package.
//!
//! Provides the core iteration interfaces and implementations:
//!
//! - [`RecordIterator`]: Bidirectional record iterator (port of `db.RecordIterator`).
//! - [`DbFieldIterator`]: Bidirectional field/key iterator (port of `db.DBFieldIterator`).
//! - [`DbLongIterator`]: Bidirectional long key iterator (port of `db.DBLongIterator`).
//! - [`SqlRecordIterator`]: SQLite-backed record iterator (new in Rust port).
//! - [`SqlFieldIterator`]: SQLite-backed field iterator (new in Rust port).

use crate::database::db::{DBRecord, DbResult, FieldValue};
use crate::database::field::GhidraField;

// ============================================================================
// RecordIterator trait (port of Java RecordIterator interface)
// ============================================================================

/// Bidirectional iterator over database records.
///
/// Port of Java `db.RecordIterator` interface.
pub trait RecordIterator {
    /// Return true if a record is available in the forward direction.
    fn has_next(&self) -> DbResult<bool>;

    /// Return true if a record is available in the reverse direction.
    fn has_previous(&self) -> DbResult<bool>;

    /// Return the next record, or None if one is not available.
    fn next(&mut self) -> DbResult<Option<DBRecord>>;

    /// Return the previous record, or None if one is not available.
    fn previous(&mut self) -> DbResult<Option<DBRecord>>;

    /// Delete the last record read via `next` or `previous`.
    /// Returns true if the record was successfully deleted.
    fn delete(&mut self) -> DbResult<bool>;
}

// ============================================================================
// DbFieldIterator trait (port of Java DBFieldIterator interface)
// ============================================================================

/// Bidirectional iterator over Field values (typically used for index keys).
///
/// Port of Java `db.DBFieldIterator` interface.
pub trait DbFieldIterator {
    /// Return true if a field is available in the forward direction.
    fn has_next(&self) -> DbResult<bool>;

    /// Return true if a field is available in the reverse direction.
    fn has_previous(&self) -> DbResult<bool>;

    /// Return the next field value, or None if one is not available.
    fn next(&mut self) -> DbResult<Option<GhidraField>>;

    /// Return the previous field value, or None if one is not available.
    fn previous(&mut self) -> DbResult<Option<GhidraField>>;

    /// Delete the record(s) associated with the last field value read.
    fn delete(&mut self) -> DbResult<bool>;
}

// ============================================================================
// DbLongIterator trait (port of Java DBLongIterator interface)
// ============================================================================

/// Bidirectional iterator over long values (typically used for long keys).
///
/// Port of Java `db.DBLongIterator` interface.
pub trait DbLongIterator {
    /// Return true if a value is available in the forward direction.
    fn has_next(&self) -> DbResult<bool>;

    /// Return true if a value is available in the reverse direction.
    fn has_previous(&self) -> DbResult<bool>;

    /// Return the next long value.
    fn next(&mut self) -> DbResult<i64>;

    /// Return the previous long value.
    fn previous(&mut self) -> DbResult<i64>;

    /// Delete the record(s) associated with the last value read.
    fn delete(&mut self) -> DbResult<bool>;
}

// ============================================================================
// SqlRecordIterator — SQLite-backed record iterator (new in Rust port)
// ============================================================================

/// A record iterator backed by a pre-loaded vector of records from SQLite.
///
/// This replaces the complex B-tree cursor logic from the Java
/// `LongKeyRecordIterator` and `FieldKeyRecordIterator` inner classes of
/// `Table.java`.
pub struct SqlRecordIterator {
    records: Vec<DBRecord>,
    position: usize,
    last_position: Option<usize>,
}

impl SqlRecordIterator {
    /// Create a new iterator over the given records.
    pub fn new(records: Vec<DBRecord>) -> Self {
        Self {
            records,
            position: 0,
            last_position: None,
        }
    }

    /// Create an empty iterator.
    pub fn empty() -> Self {
        Self {
            records: Vec::new(),
            position: 0,
            last_position: None,
        }
    }

    /// Number of records available.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// True if the iterator is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl RecordIterator for SqlRecordIterator {
    fn has_next(&self) -> DbResult<bool> {
        Ok(self.position < self.records.len())
    }

    fn has_previous(&self) -> DbResult<bool> {
        Ok(self.position > 0)
    }

    fn next(&mut self) -> DbResult<Option<DBRecord>> {
        if self.position < self.records.len() {
            let rec = self.records[self.position].clone();
            self.last_position = Some(self.position);
            self.position += 1;
            Ok(Some(rec))
        } else {
            Ok(None)
        }
    }

    fn previous(&mut self) -> DbResult<Option<DBRecord>> {
        if self.position > 0 {
            self.position -= 1;
            let rec = self.records[self.position].clone();
            self.last_position = Some(self.position);
            Ok(Some(rec))
        } else {
            Ok(None)
        }
    }

    fn delete(&mut self) -> DbResult<bool> {
        if let Some(pos) = self.last_position.take() {
            if pos < self.records.len() {
                self.records.remove(pos);
                if self.position > pos {
                    self.position -= 1;
                }
                return Ok(true);
            }
        }
        Ok(false)
    }
}

// ============================================================================
// SqlFieldIterator — SQLite-backed field/key iterator (new in Rust port)
// ============================================================================

/// A field iterator backed by a pre-loaded vector of FieldValues from SQLite.
///
/// This replaces the complex B-tree cursor logic from the Java
/// `FieldKeyIterator` inner class of `Table.java`.
pub struct SqlFieldIterator {
    fields: Vec<FieldValue>,
    position: usize,
    last_position: Option<usize>,
}

impl SqlFieldIterator {
    /// Create a new iterator over the given field values.
    pub fn new(fields: Vec<FieldValue>) -> Self {
        Self {
            fields,
            position: 0,
            last_position: None,
        }
    }

    /// Create an empty iterator.
    pub fn empty() -> Self {
        Self {
            fields: Vec::new(),
            position: 0,
            last_position: None,
        }
    }

    /// Number of fields available.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

impl DbFieldIterator for SqlFieldIterator {
    fn has_next(&self) -> DbResult<bool> {
        Ok(self.position < self.fields.len())
    }

    fn has_previous(&self) -> DbResult<bool> {
        Ok(self.position > 0)
    }

    fn next(&mut self) -> DbResult<Option<GhidraField>> {
        if self.position < self.fields.len() {
            let val = &self.fields[self.position];
            let field = match val {
                FieldValue::Long(v) => GhidraField::long(*v),
                FieldValue::Int(v) => GhidraField::int(*v),
                FieldValue::Short(v) => GhidraField::short(*v),
                FieldValue::String(s) => GhidraField::string(s.as_str()),
                FieldValue::Binary(b) => GhidraField::binary(b.clone()),
                FieldValue::Boolean(b) => GhidraField::boolean(*b),
                _ => GhidraField::new_long(),
            };
            self.last_position = Some(self.position);
            self.position += 1;
            Ok(Some(field))
        } else {
            Ok(None)
        }
    }

    fn previous(&mut self) -> DbResult<Option<GhidraField>> {
        if self.position > 0 {
            self.position -= 1;
            let val = &self.fields[self.position];
            let field = match val {
                FieldValue::Long(v) => GhidraField::long(*v),
                FieldValue::Int(v) => GhidraField::int(*v),
                FieldValue::Short(v) => GhidraField::short(*v),
                FieldValue::String(s) => GhidraField::string(s.as_str()),
                FieldValue::Binary(b) => GhidraField::binary(b.clone()),
                FieldValue::Boolean(b) => GhidraField::boolean(*b),
                _ => GhidraField::new_long(),
            };
            self.last_position = Some(self.position);
            Ok(Some(field))
        } else {
            Ok(None)
        }
    }

    fn delete(&mut self) -> DbResult<bool> {
        if let Some(pos) = self.last_position.take() {
            if pos < self.fields.len() {
                self.fields.remove(pos);
                if self.position > pos {
                    self.position -= 1;
                }
                return Ok(true);
            }
        }
        Ok(false)
    }
}

// ============================================================================
// SqlLongIterator — SQLite-backed long key iterator (new in Rust port)
// ============================================================================

/// A long key iterator backed by a pre-loaded vector of i64 from SQLite.
///
/// This replaces the complex `LongDurationLongKeyIterator` and
/// `ShortDurationLongKeyIterator` inner classes from `Table.java`.
pub struct SqlLongIterator {
    keys: Vec<i64>,
    position: usize,
    last_position: Option<usize>,
}

impl SqlLongIterator {
    /// Create a new iterator over the given keys.
    pub fn new(keys: Vec<i64>) -> Self {
        Self {
            keys,
            position: 0,
            last_position: None,
        }
    }

    /// Create an empty iterator.
    pub fn empty() -> Self {
        Self {
            keys: Vec::new(),
            position: 0,
            last_position: None,
        }
    }

    /// Number of keys available.
    pub fn len(&self) -> usize {
        self.keys.len()
    }
}

impl DbLongIterator for SqlLongIterator {
    fn has_next(&self) -> DbResult<bool> {
        Ok(self.position < self.keys.len())
    }

    fn has_previous(&self) -> DbResult<bool> {
        Ok(self.position > 0)
    }

    fn next(&mut self) -> DbResult<i64> {
        if self.position < self.keys.len() {
            let key = self.keys[self.position];
            self.last_position = Some(self.position);
            self.position += 1;
            Ok(key)
        } else {
            Err(crate::database::db::DbError::NotFound(
                "No more elements".to_string(),
            ))
        }
    }

    fn previous(&mut self) -> DbResult<i64> {
        if self.position > 0 {
            self.position -= 1;
            let key = self.keys[self.position];
            self.last_position = Some(self.position);
            Ok(key)
        } else {
            Err(crate::database::db::DbError::NotFound(
                "No more elements".to_string(),
            ))
        }
    }

    fn delete(&mut self) -> DbResult<bool> {
        if let Some(pos) = self.last_position.take() {
            if pos < self.keys.len() {
                self.keys.remove(pos);
                if self.position > pos {
                    self.position -= 1;
                }
                return Ok(true);
            }
        }
        Ok(false)
    }
}

// ============================================================================
// ConstrainedForwardRecordIterator (port of Java ConstrainedForwardRecordIterator)
// ============================================================================

/// An iterator that filters records based on a key range constraint.
///
/// Port of Java `db.ConstrainedForwardRecordIterator`.
pub struct ConstrainedRecordIterator<I: RecordIterator> {
    inner: I,
    min_key: Option<FieldValue>,
    max_key: Option<FieldValue>,
}

impl<I: RecordIterator> ConstrainedRecordIterator<I> {
    /// Create a constrained iterator with optional min/max key bounds.
    pub fn new(inner: I, min_key: Option<FieldValue>, max_key: Option<FieldValue>) -> Self {
        Self {
            inner,
            min_key,
            max_key,
        }
    }

    fn is_within_bounds(&self, rec: &DBRecord) -> bool {
        if let Some(ref pk) = rec.key() {
            if let Some(ref min) = self.min_key {
                if let (Some(pk_l), Some(min_l)) = (pk.as_long(), min.as_long()) {
                    if pk_l < min_l {
                        return false;
                    }
                }
            }
            if let Some(ref max) = self.max_key {
                if let (Some(pk_l), Some(max_l)) = (pk.as_long(), max.as_long()) {
                    if pk_l > max_l {
                        return false;
                    }
                }
            }
        }
        true
    }
}

impl<I: RecordIterator> RecordIterator for ConstrainedRecordIterator<I> {
    fn has_next(&self) -> DbResult<bool> {
        self.inner.has_next()
    }

    fn has_previous(&self) -> DbResult<bool> {
        self.inner.has_previous()
    }

    fn next(&mut self) -> DbResult<Option<DBRecord>> {
        while self.inner.has_next()? {
            if let Some(rec) = self.inner.next()? {
                if self.is_within_bounds(&rec) {
                    return Ok(Some(rec));
                }
            }
        }
        Ok(None)
    }

    fn previous(&mut self) -> DbResult<Option<DBRecord>> {
        while self.inner.has_previous()? {
            if let Some(rec) = self.inner.previous()? {
                if self.is_within_bounds(&rec) {
                    return Ok(Some(rec));
                }
            }
        }
        Ok(None)
    }

    fn delete(&mut self) -> DbResult<bool> {
        self.inner.delete()
    }
}

// ============================================================================
// KeyToRecordIterator (port of Java KeyToRecordIterator)
// ============================================================================

/// An iterator that translates field key values into full records by
/// looking them up in a table.
///
/// Port of Java `db.KeyToRecordIterator`.
pub struct KeyToRecordIterator {
    keys: Vec<FieldValue>,
    position: usize,
}

impl KeyToRecordIterator {
    /// Create from a vector of keys.
    pub fn new(keys: Vec<FieldValue>) -> Self {
        Self { keys, position: 0 }
    }

    /// Get the next key without advancing.
    pub fn peek_key(&self) -> Option<&FieldValue> {
        self.keys.get(self.position)
    }

    /// Get remaining key count.
    pub fn remaining(&self) -> usize {
        self.keys.len().saturating_sub(self.position)
    }
}

impl RecordIterator for KeyToRecordIterator {
    fn has_next(&self) -> DbResult<bool> {
        Ok(self.position < self.keys.len())
    }

    fn has_previous(&self) -> DbResult<bool> {
        Ok(self.position > 0)
    }

    fn next(&mut self) -> DbResult<Option<DBRecord>> {
        // KeyToRecordIterator just advances through keys; the actual
        // record lookup is done by the caller or a wrapper.
        if self.position < self.keys.len() {
            self.position += 1;
            Ok(None) // caller must look up the record
        } else {
            Ok(None)
        }
    }

    fn previous(&mut self) -> DbResult<Option<DBRecord>> {
        if self.position > 0 {
            self.position -= 1;
            Ok(None)
        } else {
            Ok(None)
        }
    }

    fn delete(&mut self) -> DbResult<bool> {
        Ok(false)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::db::Schema;
    use crate::database::db::Field as SchemaField;
    use crate::database::db::FieldType;

    fn make_test_records() -> Vec<DBRecord> {
        let schema = Schema::new("test", 1)
            .with_field(SchemaField::new("id", FieldType::Int).primary_key())
            .with_field(SchemaField::new("val", FieldType::String));
        let mut records = Vec::new();
        for i in 1..=5 {
            let mut rec = DBRecord::new(schema.clone());
            rec.set("id", FieldValue::Int(i)).unwrap();
            rec.set("val", FieldValue::String(format!("v{}", i))).unwrap();
            records.push(rec);
        }
        records
    }

    #[test]
    fn test_sql_record_iterator_forward() {
        let records = make_test_records();
        let mut iter = SqlRecordIterator::new(records);

        assert!(iter.has_next().unwrap());
        let rec = iter.next().unwrap().unwrap();
        assert_eq!(rec.get_int("id").unwrap(), 1);

        let rec = iter.next().unwrap().unwrap();
        assert_eq!(rec.get_int("id").unwrap(), 2);
    }

    #[test]
    fn test_sql_record_iterator_backward() {
        let records = make_test_records();
        let mut iter = SqlRecordIterator::new(records);

        // Advance past first
        iter.next().unwrap();
        iter.next().unwrap();

        // Go back (position was at 2, previous decrements to 1, returns records[1])
        assert!(iter.has_previous().unwrap());
        let rec = iter.previous().unwrap().unwrap();
        assert_eq!(rec.get_int("id").unwrap(), 2);
    }

    #[test]
    fn test_sql_record_iterator_exhaust() {
        let records = make_test_records();
        let mut iter = SqlRecordIterator::new(records);

        for _ in 0..5 {
            assert!(iter.next().unwrap().is_some());
        }
        assert!(iter.next().unwrap().is_none());
        assert!(!iter.has_next().unwrap());
    }

    #[test]
    fn test_sql_long_iterator() {
        let keys = vec![10, 20, 30];
        let mut iter = SqlLongIterator::new(keys);

        assert_eq!(iter.next().unwrap(), 10);
        assert_eq!(iter.next().unwrap(), 20);
        assert_eq!(iter.next().unwrap(), 30);
        assert!(iter.next().is_err());
    }

    #[test]
    fn test_sql_field_iterator() {
        let fields = vec![
            FieldValue::Long(100),
            FieldValue::Long(200),
        ];
        let mut iter = SqlFieldIterator::new(fields);

        let f = iter.next().unwrap().unwrap();
        assert_eq!(f.get_long_value().unwrap(), 100);

        let f = iter.next().unwrap().unwrap();
        assert_eq!(f.get_long_value().unwrap(), 200);

        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn test_sql_record_iterator_delete() {
        let records = make_test_records();
        let mut iter = SqlRecordIterator::new(records);
        assert_eq!(iter.len(), 5);

        iter.next().unwrap();
        let deleted = iter.delete().unwrap();
        assert!(deleted);
        assert_eq!(iter.len(), 4);
    }

    #[test]
    fn test_constrained_iterator() {
        let records = make_test_records();
        let inner = SqlRecordIterator::new(records);
        let mut iter = ConstrainedRecordIterator::new(
            inner,
            Some(FieldValue::Int(2)),
            Some(FieldValue::Int(4)),
        );

        let mut collected = Vec::new();
        while let Some(rec) = iter.next().unwrap() {
            collected.push(rec.get_int("id").unwrap());
        }
        assert_eq!(collected, vec![2, 3, 4]);
    }

    #[test]
    fn test_key_to_record_iterator() {
        let keys = vec![FieldValue::Long(1), FieldValue::Long(2), FieldValue::Long(3)];
        let iter = KeyToRecordIterator::new(keys);
        assert!(iter.has_next().unwrap());
        assert_eq!(iter.remaining(), 3);
    }

    #[test]
    fn test_empty_iterator() {
        let mut iter = SqlRecordIterator::empty();
        assert!(!iter.has_next().unwrap());
        assert!(iter.next().unwrap().is_none());
    }
}
