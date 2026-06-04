//! Secondary index table management ported from Java's `db.IndexTable`.

use crate::database::db::{DBRecord, Database, DbResult, FieldValue};
use crate::database::iterator::SqlFieldIterator;
use rusqlite::params;

/// Manages a secondary index on a column of a primary table.
///
/// Port of Java `db.IndexTable` and `db.FieldIndexTable`.
pub struct GhidraIndexTable {
    primary_table_name: String,
    column_index: usize,
    is_sparse_index: bool,
    index_table_name: String,
}

impl GhidraIndexTable {
    /// Create a new secondary index table definition.
    pub fn new(primary_table_name: &str, column_index: usize, is_sparse: bool) -> Self {
        let index_table_name = format!("{}_idx_{}", primary_table_name, column_index);
        Self {
            primary_table_name: primary_table_name.to_string(),
            column_index,
            is_sparse_index: is_sparse,
            index_table_name,
        }
    }

    pub fn get_column_index(&self) -> usize { self.column_index }
    pub fn is_sparse(&self) -> bool { self.is_sparse_index }
    pub fn index_table_name(&self) -> &str { &self.index_table_name }
    pub fn primary_table_name(&self) -> &str { &self.primary_table_name }

    /// Create the index table in the database.
    pub fn create_index_table(&self, db: &Database) -> DbResult<()> {
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

    /// Add an entry to the index.
    pub fn add_entry(&self, db: &Database, record: &DBRecord) -> DbResult<()> {
        let indexed_value = record.get_at(self.column_index).cloned().unwrap_or(FieldValue::Null);
        let pk = record.key().cloned().unwrap_or(FieldValue::Null);
        let index_key = format!("{}", indexed_value);

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
                let conn = db.write()?;
                conn.execute(
                    &format!("INSERT INTO {} (index_key, primary_keys) VALUES (?1, ?2)", self.index_table_name),
                    params![index_key, encode_pk(&pk)],
                )?;
            }
            Some(blob) => {
                // Append to existing if not already present
                let mut pks = decode_pks(&blob);
                if !pks.contains(&pk) {
                    pks.push(pk);
                    let conn = db.write()?;
                    conn.execute(
                        &format!("UPDATE {} SET primary_keys=?1 WHERE index_key=?2", self.index_table_name),
                        params![encode_pks(&pks), index_key],
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Delete an entry from the index.
    pub fn delete_entry(&self, db: &Database, record: &DBRecord) -> DbResult<()> {
        let indexed_value = record.get_at(self.column_index).cloned().unwrap_or(FieldValue::Null);
        let pk = record.key().cloned().unwrap_or(FieldValue::Null);
        let index_key = format!("{}", indexed_value);

        let existing_blob: Option<Vec<u8>> = {
            let conn = db.read()?;
            conn.query_row(
                &format!("SELECT primary_keys FROM {} WHERE index_key=?1", self.index_table_name),
                params![index_key],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            ).unwrap_or(None)
        };

        if let Some(blob) = existing_blob {
            let mut pks = decode_pks(&blob);
            pks.retain(|k| k != &pk);
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
                    params![encode_pks(&pks), index_key],
                )?;
            }
        }
        Ok(())
    }

    /// Find primary keys for the given indexed field value.
    pub fn find_primary_keys(&self, db: &Database, field: &FieldValue) -> DbResult<Vec<FieldValue>> {
        let index_key = format!("{}", field);
        let conn = db.read()?;
        let blob: Option<Vec<u8>> = conn.query_row(
            &format!("SELECT primary_keys FROM {} WHERE index_key=?1", self.index_table_name),
            params![index_key],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        ).unwrap_or(None);
        match blob {
            Some(b) => Ok(decode_pks(&b)),
            None => Ok(Vec::new()),
        }
    }

    /// Get the number of records with the given indexed field value.
    pub fn get_key_count(&self, db: &Database, field: &FieldValue) -> DbResult<usize> {
        let keys = self.find_primary_keys(db, field)?;
        Ok(keys.len())
    }

    /// Check if any record exists with the given indexed field value.
    pub fn has_record(&self, db: &Database, field: &FieldValue) -> DbResult<bool> {
        let count = self.get_key_count(db, field)?;
        Ok(count > 0)
    }

    /// Delete all entries from the index.
    pub fn delete_all(&self, db: &Database) -> DbResult<usize> {
        let conn = db.write()?;
        let rows = conn.execute(&format!("DELETE FROM {} WHERE 1=1", self.index_table_name), [])?;
        Ok(rows)
    }

    /// Get a key iterator over all unique index values.
    pub fn index_iterator(&self, db: &Database) -> DbResult<SqlFieldIterator> {
        let conn = db.read()?;
        let mut stmt = conn.prepare(&format!("SELECT index_key FROM {} ORDER BY index_key ASC", self.index_table_name))?;
        let fields: Vec<FieldValue> = stmt.query_map([], |row| {
            row.get::<_, String>(0).map(FieldValue::String)
        })?
        .filter_map(|r| r.ok())
        .collect();
        Ok(SqlFieldIterator::new(fields))
    }

    /// Rebuild this index from the primary table data.
    pub fn rebuild(&self, db: &Database) -> DbResult<()> {
        self.delete_all(db)?;
        // Read all records from the primary table
        let conn = db.read()?;
        let mut stmt = conn.prepare(&format!("SELECT * FROM {}", self.primary_table_name))?;
        let column_index = self.column_index;
        let col_count = {
            let cols = stmt.column_names();
            cols.len()
        };
        if column_index >= col_count {
            return Ok(());
        }
        drop(stmt);
        drop(conn);

        // For each record, add to the index
        let conn = db.read()?;
        let mut stmt = conn.prepare(&format!(
            "SELECT rowid, * FROM {}",
            self.primary_table_name
        ))?;
        let rows: Vec<(String, Vec<u8>)> = stmt.query_map([], |row| {
            let indexed_val: rusqlite::types::Value = row.get(column_index + 1)?; // +1 for rowid
            let pk: rusqlite::types::Value = row.get(1)?; // first column after rowid
            let index_key = match indexed_val {
                rusqlite::types::Value::Text(s) => s,
                rusqlite::types::Value::Integer(i) => format!("{}", i),
                rusqlite::types::Value::Real(r) => format!("{}", r),
                rusqlite::types::Value::Null => "NULL".to_string(),
                rusqlite::types::Value::Blob(b) => format!("{:?}", b),
            };
            let pk_bytes = match pk {
                rusqlite::types::Value::Integer(i) => i.to_be_bytes().to_vec(),
                _ => vec![],
            };
            Ok((index_key, pk_bytes))
        })?
        .filter_map(|r| r.ok())
        .collect();
        drop(stmt);
        drop(conn);

        for (index_key, pk_bytes) in rows {
            if self.is_sparse_index && index_key == "NULL" {
                continue;
            }
            let conn = db.write()?;
            // Try to insert or update
            let existing: Option<Vec<u8>> = conn.query_row(
                &format!("SELECT primary_keys FROM {} WHERE index_key=?1", self.index_table_name),
                params![index_key],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            ).unwrap_or(None);
            match existing {
                None => {
                    conn.execute(
                        &format!("INSERT INTO {} (index_key, primary_keys) VALUES (?1, ?2)", self.index_table_name),
                        params![index_key, pk_bytes],
                    )?;
                }
                Some(blob) => {
                    let mut pks = decode_pks(&blob);
                    let new_pk = FieldValue::Long(i64::from_be_bytes(pk_bytes.try_into().unwrap_or([0; 8])));
                    if !pks.contains(&new_pk) {
                        pks.push(new_pk);
                        conn.execute(
                            &format!("UPDATE {} SET primary_keys=?1 WHERE index_key=?2", self.index_table_name),
                            params![encode_pks(&pks), index_key],
                        )?;
                    }
                }
            }
        }
        Ok(())
    }
}

// ============================================================================
// PK encoding helpers
// ============================================================================

fn encode_pk(pk: &FieldValue) -> Vec<u8> {
    match pk {
        FieldValue::Long(v) => v.to_be_bytes().to_vec(),
        FieldValue::Int(v) => (*v as i64).to_be_bytes().to_vec(),
        FieldValue::String(s) => s.as_bytes().to_vec(),
        FieldValue::Binary(b) => b.clone(),
        _ => format!("{}", pk).into_bytes(),
    }
}

fn encode_pks(pks: &[FieldValue]) -> Vec<u8> {
    let mut result = Vec::new();
    for pk in pks {
        let encoded = encode_pk(pk);
        result.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        result.extend_from_slice(&encoded);
    }
    result
}

fn decode_pks(data: &[u8]) -> Vec<FieldValue> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset + 4 <= data.len() {
        let len = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if offset + len > data.len() { break; }
        let pk_data = &data[offset..offset + len];
        if len == 8 {
            let v = i64::from_be_bytes(pk_data.try_into().unwrap());
            result.push(FieldValue::Long(v));
        } else {
            result.push(FieldValue::Binary(pk_data.to_vec()));
        }
        offset += len;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::db::{Field, FieldType, Schema};

    fn create_test_table(db: &Database, name: &str, col2_type: &str) {
        db.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {} (id INTEGER PRIMARY KEY, val {} NOT NULL)",
            name, col2_type
        )).unwrap();
    }

    #[test]
    fn test_index_table_creation() {
        let idx = GhidraIndexTable::new("users", 2, false);
        assert_eq!(idx.get_column_index(), 2);
        assert_eq!(idx.index_table_name(), "users_idx_2");
        assert_eq!(idx.primary_table_name(), "users");
        assert!(!idx.is_sparse());
    }

    #[test]
    fn test_pk_encoding_roundtrip() {
        let pk = FieldValue::Long(42);
        let encoded = encode_pk(&pk);
        assert_eq!(encoded, vec![0, 0, 0, 0, 0, 0, 0, 42]);
    }

    #[test]
    fn test_pks_encoding_roundtrip() {
        let pks = vec![FieldValue::Long(1), FieldValue::Long(2), FieldValue::Long(3)];
        let encoded = encode_pks(&pks);
        let decoded = decode_pks(&encoded);
        assert_eq!(decoded, pks);
    }

    #[test]
    fn test_index_create_and_add_entry() {
        let db = Database::in_memory().unwrap();
        create_test_table(&db, "users", "TEXT");

        let idx = GhidraIndexTable::new("users", 1, false);
        idx.create_index_table(&db).unwrap();

        db.execute_batch("INSERT INTO users (id, val) VALUES (1, 'alice@test.com')").unwrap();

        // Read back
        let conn = db.read().unwrap();
        let val: String = conn.query_row("SELECT val FROM users WHERE id=1", [], |r| r.get(0)).unwrap();
        let pk_val = FieldValue::Long(1);
        let pk_bytes = encode_pk(&pk_val);
        drop(conn);

        // Manually add to index using parameterized query
        let conn = db.write().unwrap();
        conn.execute(
            &format!("INSERT INTO {} (index_key, primary_keys) VALUES (?1, ?2)", idx.index_table_name()),
            rusqlite::params![val, pk_bytes],
        ).unwrap();
        drop(conn);

        let keys = idx.find_primary_keys(&db, &FieldValue::String(val)).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], FieldValue::Long(1));
    }

    #[test]
    fn test_index_delete_all() {
        let db = Database::in_memory().unwrap();
        let idx = GhidraIndexTable::new("data", 1, false);
        idx.create_index_table(&db).unwrap();

        let pk_bytes = encode_pk(&FieldValue::Long(1));
        let hex_pk: String = pk_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        db.execute_batch(&format!(
            "INSERT INTO {} (index_key, primary_keys) VALUES ('A', X'{}')",
            idx.index_table_name(),
            hex_pk
        )).unwrap();

        idx.delete_all(&db).unwrap();
        assert_eq!(idx.get_key_count(&db, &FieldValue::String("A".into())).unwrap(), 0);
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
