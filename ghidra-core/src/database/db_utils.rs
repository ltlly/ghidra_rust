//! DatabaseUtils — utility functions for the Ghidra database framework.
//!
//! Port of Java `db.DatabaseUtils`. Provides a collection of database-related
//! utility functions, primarily for bulk record operations.

use crate::database::error::DbResult;
use crate::database::field::GhidraField;
use crate::database::record::GhidraRecord;
use std::collections::BTreeMap;

// ============================================================================
// DatabaseUtils
// ============================================================================

/// Utility functions for database operations.
///
/// Port of Java `db.DatabaseUtils`.
pub struct DatabaseUtils;

impl DatabaseUtils {
    /// Reassign the long key assigned to a contiguous group of records within a table.
    ///
    /// Port of Java `DatabaseUtils.moveRecords(Table, long, long, long)`.
    ///
    /// A shift in the key value is computed as the difference of `old_start`
    /// and `new_start`. Existing records whose keys lie within the new range
    /// will be removed prior to moving the target set of records.
    ///
    /// # Arguments
    /// * `records` - Mutable map of key -> record to operate on
    /// * `old_start` - Old key value for start of range
    /// * `new_start` - New key value for start of range
    /// * `size` - Number of records to move (old_start..old_start+size-1 inclusive)
    ///
    /// # Errors
    /// Returns an error if:
    /// * `size` is zero or negative
    /// * The key ranges would overflow
    /// * A record key cannot be converted to long
    pub fn move_records(
        records: &mut BTreeMap<i64, GhidraRecord>,
        old_start: i64,
        new_start: i64,
        size: i64,
    ) -> DbResult<()> {
        if old_start == new_start {
            return Ok(());
        }
        if size <= 0 {
            return Err(crate::database::db::DbError::Schema(
                "size must be > 0".to_string(),
            ));
        }
        if old_start + size - 1 < 0 || new_start + size - 1 < 0 {
            return Err(crate::database::db::DbError::Schema(
                "Illegal range: end range overflow".to_string(),
            ));
        }

        let key_diff = new_start - old_start;

        // Collect records to move
        let mut to_move = Vec::new();
        for key in old_start..old_start + size {
            if let Some(rec) = records.remove(&key) {
                to_move.push(rec);
            }
        }

        // Remove any existing records in the target range
        for key in new_start..new_start + size {
            records.remove(&key);
        }

        // Insert moved records with shifted keys
        for mut rec in to_move {
            let old_key = rec.get_key();
            rec.set_key_long(old_key + key_diff);
            records.insert(old_key + key_diff, rec);
        }

        Ok(())
    }

    /// Create an empty record map (useful as a "temp table" analog).
    pub fn create_temp_records() -> BTreeMap<i64, GhidraRecord> {
        BTreeMap::new()
    }

    /// Count the number of records in a key range (inclusive).
    pub fn count_records_in_range(
        records: &BTreeMap<i64, GhidraRecord>,
        start_key: i64,
        end_key: i64,
    ) -> usize {
        records.range(start_key..=end_key).count()
    }

    /// Get all records in a key range (inclusive), returning them as a vector.
    pub fn get_records_in_range<'a>(
        records: &'a BTreeMap<i64, GhidraRecord>,
        start_key: i64,
        end_key: i64,
    ) -> Vec<&'a GhidraRecord> {
        records.range(start_key..=end_key).map(|(_, v)| v).collect()
    }

    /// Delete all records in a key range (inclusive).
    /// Returns the number of records deleted.
    pub fn delete_records_in_range(
        records: &mut BTreeMap<i64, GhidraRecord>,
        start_key: i64,
        end_key: i64,
    ) -> usize {
        let keys: Vec<i64> = records.range(start_key..=end_key).map(|(&k, _)| k).collect();
        let count = keys.len();
        for key in keys {
            records.remove(&key);
        }
        count
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(key: i64, value: i32) -> GhidraRecord {
        let key_field = GhidraField::long(key);
        let field_types = vec![GhidraField::int(0)];
        let field_names = vec!["value".to_string()];
        let mut rec = GhidraRecord::new(key_field, &field_types, &field_names);
        rec.set_int_value(0, value).unwrap();
        rec
    }

    #[test]
    fn test_move_records_same_start() {
        let mut records = BTreeMap::new();
        records.insert(1, make_record(1, 10));
        DatabaseUtils::move_records(&mut records, 1, 1, 1).unwrap();
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn test_move_records_basic() {
        let mut records = BTreeMap::new();
        records.insert(1, make_record(1, 10));
        records.insert(2, make_record(2, 20));
        records.insert(3, make_record(3, 30));

        DatabaseUtils::move_records(&mut records, 1, 10, 3).unwrap();

        assert_eq!(records.len(), 3);
        assert!(records.contains_key(&10));
        assert!(records.contains_key(&11));
        assert!(records.contains_key(&12));
        assert!(!records.contains_key(&1));
        assert!(!records.contains_key(&2));
        assert!(!records.contains_key(&3));
    }

    #[test]
    fn test_move_records_overwrite_target() {
        let mut records = BTreeMap::new();
        records.insert(1, make_record(1, 10));
        records.insert(2, make_record(2, 20));
        records.insert(5, make_record(5, 50));

        // Move records 1..2 to position 5 (overwrites record 5)
        DatabaseUtils::move_records(&mut records, 1, 5, 2).unwrap();

        assert_eq!(records.len(), 2);
        assert!(records.contains_key(&5));
        assert!(records.contains_key(&6));
        assert!(!records.contains_key(&1));
    }

    #[test]
    fn test_move_records_invalid_size() {
        let mut records = BTreeMap::new();
        assert!(DatabaseUtils::move_records(&mut records, 0, 10, 0).is_err());
        assert!(DatabaseUtils::move_records(&mut records, 0, 10, -1).is_err());
    }

    #[test]
    fn test_count_records_in_range() {
        let mut records = BTreeMap::new();
        for i in 0..10 {
            records.insert(i, make_record(i, i as i32));
        }
        assert_eq!(DatabaseUtils::count_records_in_range(&records, 2, 5), 4);
        assert_eq!(DatabaseUtils::count_records_in_range(&records, 0, 9), 10);
        assert_eq!(DatabaseUtils::count_records_in_range(&records, 100, 200), 0);
    }

    #[test]
    fn test_get_records_in_range() {
        let mut records = BTreeMap::new();
        for i in 0..5 {
            records.insert(i, make_record(i, i as i32 * 10));
        }
        let result = DatabaseUtils::get_records_in_range(&records, 1, 3);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].get_key(), 1);
        assert_eq!(result[2].get_key(), 3);
    }

    #[test]
    fn test_delete_records_in_range() {
        let mut records = BTreeMap::new();
        for i in 0..10 {
            records.insert(i, make_record(i, i as i32));
        }
        let deleted = DatabaseUtils::delete_records_in_range(&mut records, 3, 6);
        assert_eq!(deleted, 4);
        assert_eq!(records.len(), 6);
        assert!(!records.contains_key(&3));
        assert!(!records.contains_key(&6));
        assert!(records.contains_key(&2));
        assert!(records.contains_key(&7));
    }

    #[test]
    fn test_create_temp_records() {
        let records = DatabaseUtils::create_temp_records();
        assert!(records.is_empty());
    }
}
