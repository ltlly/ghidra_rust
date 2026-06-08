//! Long-key index management ported from Java's `db.LongKeyIndex`.
//!
//! Provides [`LongKeyIndex`] -- a secondary index over `i64` keys that maps
//! each indexed column value to a set of primary keys. Used for fast
//! reverse-lookups on integer-keyed tables.

use rusqlite::params;

use super::db::{DbResult, FieldValue};
use super::db_record::DBRecord;

// ============================================================================
// LongKeyIndex — secondary index over long keys
// ============================================================================

/// A secondary index that maps column values to sets of `i64` primary keys.
///
/// Port of Java's `db.LongKeyIndex` concept. Each entry in the index stores
/// the indexed column value as the key and a serialized set of primary keys
/// as the value. This enables efficient reverse lookups: "given a column
/// value, find all records with that value."
///
/// The index is backed by a dedicated SQLite table with the schema:
/// ```sql
/// CREATE TABLE <name> (index_key TEXT PRIMARY KEY, primary_keys BLOB NOT NULL)
/// ```
pub struct LongKeyIndex {
    /// Name of the primary (parent) table.
    primary_table_name: String,
    /// Column index in the primary table that this index covers.
    column_index: usize,
    /// Name of the SQLite table backing this index.
    index_table_name: String,
}

impl LongKeyIndex {
    /// Create a new long-key index definition.
    ///
    /// `primary_table_name` is the name of the table being indexed.
    /// `column_index` is the 0-based column position of the indexed field.
    pub fn new(primary_table_name: &str, column_index: usize) -> Self {
        let index_table_name = format!("{}_lk_idx_{}", primary_table_name, column_index);
        Self {
            primary_table_name: primary_table_name.to_string(),
            column_index,
            index_table_name,
        }
    }

    /// Get the primary table name.
    pub fn primary_table_name(&self) -> &str {
        &self.primary_table_name
    }

    /// Get the indexed column index.
    pub fn column_index(&self) -> usize {
        self.column_index
    }

    /// Get the name of the backing SQLite table.
    pub fn index_table_name(&self) -> &str {
        &self.index_table_name
    }

    /// Create the index table in the database.
    pub fn create(&self, db: &super::db::Database) -> DbResult<()> {
        let conn = db.write()?;
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {} (\
                index_key TEXT PRIMARY KEY, \
                primary_keys BLOB NOT NULL\
            )",
            self.index_table_name
        ))?;
        Ok(())
    }

    /// Drop the index table from the database.
    pub fn drop(&self, db: &super::db::Database) -> DbResult<()> {
        let conn = db.write()?;
        conn.execute_batch(&format!(
            "DROP TABLE IF EXISTS {}",
            self.index_table_name
        ))?;
        Ok(())
    }

    /// Add a record's primary key to the index entry for its column value.
    ///
    /// If the indexed value does not yet have an entry, a new one is created.
    /// If the primary key is already present, this is a no-op.
    pub fn put(&self, db: &super::db::Database, record: &DBRecord) -> DbResult<()> {
        let indexed_value = record.get_at(self.column_index).cloned().unwrap_or(FieldValue::Null);
        let pk = record.key().cloned().unwrap_or(FieldValue::Null);
        let index_key = value_to_index_key(&indexed_value);
        let pk_long = pk.as_long().unwrap_or(0);

        // Check if entry exists
        let existing_blob: Option<Vec<u8>> = {
            let conn = db.read()?;
            conn.query_row(
                &format!("SELECT primary_keys FROM {} WHERE index_key=?1", self.index_table_name),
                params![index_key],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            ).unwrap_or(None)
        };

        match existing_blob {
            None => {
                // New entry
                let blob = encode_long_set(&[pk_long]);
                let conn = db.write()?;
                conn.execute(
                    &format!("INSERT INTO {} (index_key, primary_keys) VALUES (?1, ?2)", self.index_table_name),
                    params![index_key, blob],
                )?;
            }
            Some(blob) => {
                let mut pks = decode_long_set(&blob);
                if !pks.contains(&pk_long) {
                    pks.push(pk_long);
                    let conn = db.write()?;
                    conn.execute(
                        &format!("UPDATE {} SET primary_keys=?1 WHERE index_key=?2", self.index_table_name),
                        params![encode_long_set(&pks), index_key],
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Remove a record's primary key from the index entry for its column value.
    ///
    /// If the entry becomes empty after removal, it is deleted entirely.
    pub fn remove(&self, db: &super::db::Database, record: &DBRecord) -> DbResult<()> {
        let indexed_value = record.get_at(self.column_index).cloned().unwrap_or(FieldValue::Null);
        let pk = record.key().cloned().unwrap_or(FieldValue::Null);
        let index_key = value_to_index_key(&indexed_value);
        let pk_long = pk.as_long().unwrap_or(0);

        let existing_blob: Option<Vec<u8>> = {
            let conn = db.read()?;
            conn.query_row(
                &format!("SELECT primary_keys FROM {} WHERE index_key=?1", self.index_table_name),
                params![index_key],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            ).unwrap_or(None)
        };

        if let Some(blob) = existing_blob {
            let mut pks = decode_long_set(&blob);
            pks.retain(|k| *k != pk_long);
            if pks.is_empty() {
                let conn = db.write()?;
                conn.execute(
                    &format!("DELETE FROM {} WHERE index_key=?1", self.index_table_name),
                    params![index_key],
                )?;
            } else {
                let conn = db.write()?;
                conn.execute(
                    &format!("UPDATE {} SET primary_keys=?1 WHERE index_key=?2", self.index_table_name),
                    params![encode_long_set(&pks), index_key],
                )?;
            }
        }
        Ok(())
    }

    /// Get all primary keys associated with the given indexed column value.
    pub fn get_keys(
        &self,
        db: &super::db::Database,
        indexed_value: &FieldValue,
    ) -> DbResult<Vec<i64>> {
        let index_key = value_to_index_key(indexed_value);
        let conn = db.read();
        let conn = conn?;
        let blob: Option<Vec<u8>> = conn
            .query_row(
                &format!(
                    "SELECT primary_keys FROM {} WHERE index_key=?1",
                    self.index_table_name
                ),
                params![index_key],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .unwrap_or(None);

        match blob {
            Some(b) => Ok(decode_long_set(&b)),
            None => Ok(Vec::new()),
        }
    }

    /// Check whether the index has any entry for the given column value.
    pub fn contains_value(
        &self,
        db: &super::db::Database,
        indexed_value: &FieldValue,
    ) -> DbResult<bool> {
        let keys = self.get_keys(db, indexed_value)?;
        Ok(!keys.is_empty())
    }

    /// Delete all entries from the index (truncate).
    pub fn clear(&self, db: &super::db::Database) -> DbResult<()> {
        let conn = db.write()?;
        conn.execute_batch(&format!("DELETE FROM {}", self.index_table_name))?;
        Ok(())
    }
}

// ============================================================================
// Helpers — encoding/decoding long sets to/from blobs
// ============================================================================

/// Convert a `FieldValue` to a string key for the index table.
fn value_to_index_key(value: &FieldValue) -> String {
    match value {
        FieldValue::Int(v) => v.to_string(),
        FieldValue::Long(v) => v.to_string(),
        FieldValue::Short(v) => v.to_string(),
        FieldValue::String(s) => s.clone(),
        FieldValue::Boolean(v) => if *v { "1".to_string() } else { "0".to_string() },
        FieldValue::Float(v) => v.to_string(),
        FieldValue::Double(v) => v.to_string(),
        FieldValue::Binary(v) => format!("{:?}", v),
        FieldValue::Null => "NULL".to_string(),
    }
}

/// Encode a set of `i64` values into a compact binary blob.
///
/// Format: each key is stored as 8 bytes little-endian, packed contiguously.
fn encode_long_set(keys: &[i64]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(keys.len() * 8);
    for &k in keys {
        blob.extend_from_slice(&k.to_le_bytes());
    }
    blob
}

/// Decode a binary blob back into a set of `i64` values.
fn decode_long_set(blob: &[u8]) -> Vec<i64> {
    blob.chunks_exact(8)
        .map(|chunk| i64::from_le_bytes(chunk.try_into().unwrap_or([0; 8])))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::db::{Database, FieldType};
    use super::super::schema::{Field, Schema};

    #[test]
    fn test_long_key_index_put_and_get() {
        let mut db = Database::in_memory().unwrap();
        let schema = Schema::new("test_lki", 1)
            .with_field(Field::new("id", FieldType::Long).primary_key())
            .with_field(Field::new("category", FieldType::Int));
        db.create_table(schema.clone()).unwrap();

        let idx = LongKeyIndex::new("test_lki", 1); // index on "category" column
        idx.create(&db).unwrap();

        // Insert records
        for i in 1i64..=5 {
            let mut rec = DBRecord::new(schema.clone());
            rec.set("id", FieldValue::Long(i)).unwrap();
            rec.set("category", FieldValue::Int((i % 3) as i32)).unwrap();
            idx.put(&db, &rec).unwrap();
        }

        // All records with category=1 (ids 1 and 4)
        let keys = idx.get_keys(&db, &FieldValue::Int(1)).unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&1));
        assert!(keys.contains(&4));

        // All records with category=2 (ids 2 and 5)
        let keys = idx.get_keys(&db, &FieldValue::Int(2)).unwrap();
        assert_eq!(keys.len(), 2);

        // All records with category=0 (id 3)
        let keys = idx.get_keys(&db, &FieldValue::Int(0)).unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&3));
    }

    #[test]
    fn test_long_key_index_remove() {
        let mut db = Database::in_memory().unwrap();
        let schema = Schema::new("test_rm", 1)
            .with_field(Field::new("id", FieldType::Long).primary_key())
            .with_field(Field::new("tag", FieldType::String));
        db.create_table(schema.clone()).unwrap();

        let idx = LongKeyIndex::new("test_rm", 1);
        idx.create(&db).unwrap();

        let mut rec1 = DBRecord::new(schema.clone());
        rec1.set("id", FieldValue::Long(10)).unwrap();
        rec1.set("tag", FieldValue::String("alpha".into())).unwrap();
        idx.put(&db, &rec1).unwrap();

        let mut rec2 = DBRecord::new(schema.clone());
        rec2.set("id", FieldValue::Long(20)).unwrap();
        rec2.set("tag", FieldValue::String("alpha".into())).unwrap();
        idx.put(&db, &rec2).unwrap();

        // Remove one
        idx.remove(&db, &rec1).unwrap();

        let keys = idx.get_keys(&db, &FieldValue::String("alpha".into())).unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&20));
    }

    #[test]
    fn test_long_key_index_clear() {
        let mut db = Database::in_memory().unwrap();
        let schema = Schema::new("test_clr", 1)
            .with_field(Field::new("id", FieldType::Long).primary_key())
            .with_field(Field::new("val", FieldType::Int));
        db.create_table(schema.clone()).unwrap();

        let idx = LongKeyIndex::new("test_clr", 1);
        idx.create(&db).unwrap();

        let mut rec = DBRecord::new(schema.clone());
        rec.set("id", FieldValue::Long(1)).unwrap();
        rec.set("val", FieldValue::Int(42)).unwrap();
        idx.put(&db, &rec).unwrap();

        assert!(idx.contains_value(&db, &FieldValue::Int(42)).unwrap());

        idx.clear(&db).unwrap();
        assert!(!idx.contains_value(&db, &FieldValue::Int(42)).unwrap());
    }

    #[test]
    fn test_encode_decode_long_set() {
        let keys = vec![1i64, 100, -1, i64::MAX, i64::MIN];
        let blob = encode_long_set(&keys);
        let decoded = decode_long_set(&blob);
        assert_eq!(keys, decoded);
    }
}
