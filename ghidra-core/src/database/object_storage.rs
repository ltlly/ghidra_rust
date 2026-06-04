//! ObjectStorageAdapterDB ported from Java's `db.ObjectStorageAdapterDB`.

use crate::database::db::{Database, DbResult};
use rusqlite::params;

const OBJECT_STORAGE_TABLE: &str = "OBJ_STORAGE";

/// Adapts a database table to store key-value pairs of primitive types.
///
/// Port of Java `db.ObjectStorageAdapterDB`.
pub struct ObjectStorageAdapter<'a> {
    db: &'a Database,
}

impl<'a> ObjectStorageAdapter<'a> {
    /// Create a new adapter for the given database.
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Ensure the object storage table exists.
    pub fn ensure_table(&self) -> DbResult<()> {
        let conn = self.db.read()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            params![OBJECT_STORAGE_TABLE],
            |row| row.get(0),
        ).unwrap_or(0);
        if count == 0 {
            drop(conn);
            let conn = self.db.write()?;
            conn.execute_batch(&format!(
                "CREATE TABLE IF NOT EXISTS {} (\
                    key INTEGER PRIMARY KEY, \
                    int_val INTEGER, \
                    long_val INTEGER, \
                    string_val TEXT, \
                    bytes_val BLOB\
                )",
                OBJECT_STORAGE_TABLE
            ))?;
        }
        Ok(())
    }

    /// Put an integer value.
    pub fn put_int(&self, key: i64, value: i32) -> DbResult<()> {
        self.ensure_table()?;
        let conn = self.db.write()?;
        conn.execute(
            &format!("INSERT OR REPLACE INTO {} (key, int_val) VALUES (?1, ?2)", OBJECT_STORAGE_TABLE),
            params![key, value],
        )?;
        Ok(())
    }

    /// Put a long value.
    pub fn put_long(&self, key: i64, value: i64) -> DbResult<()> {
        self.ensure_table()?;
        let conn = self.db.write()?;
        conn.execute(
            &format!("INSERT OR REPLACE INTO {} (key, long_val) VALUES (?1, ?2)", OBJECT_STORAGE_TABLE),
            params![key, value],
        )?;
        Ok(())
    }

    /// Put a string value.
    pub fn put_string(&self, key: i64, value: &str) -> DbResult<()> {
        self.ensure_table()?;
        let conn = self.db.write()?;
        conn.execute(
            &format!("INSERT OR REPLACE INTO {} (key, string_val) VALUES (?1, ?2)", OBJECT_STORAGE_TABLE),
            params![key, value],
        )?;
        Ok(())
    }

    /// Put a binary value.
    pub fn put_bytes(&self, key: i64, value: &[u8]) -> DbResult<()> {
        self.ensure_table()?;
        let conn = self.db.write()?;
        conn.execute(
            &format!("INSERT OR REPLACE INTO {} (key, bytes_val) VALUES (?1, ?2)", OBJECT_STORAGE_TABLE),
            params![key, value],
        )?;
        Ok(())
    }

    /// Get an integer value.
    pub fn get_int(&self, key: i64) -> DbResult<Option<i32>> {
        self.get_single_col("int_val", key)
    }

    /// Get a long value.
    pub fn get_long(&self, key: i64) -> DbResult<Option<i64>> {
        self.get_single_col("long_val", key)
    }

    /// Get a string value.
    pub fn get_string(&self, key: i64) -> DbResult<Option<String>> {
        self.get_single_col("string_val", key)
    }

    /// Get a binary value.
    pub fn get_bytes(&self, key: i64) -> DbResult<Option<Vec<u8>>> {
        self.get_single_col("bytes_val", key)
    }

    /// Remove a stored value.
    pub fn remove(&self, key: i64) -> DbResult<bool> {
        if !self.table_exists()? {
            return Ok(false);
        }
        let conn = self.db.write()?;
        let rows = conn.execute(
            &format!("DELETE FROM {} WHERE key=?1", OBJECT_STORAGE_TABLE),
            params![key],
        )?;
        Ok(rows > 0)
    }

    /// Check if a key exists.
    pub fn has_key(&self, key: i64) -> DbResult<bool> {
        if !self.table_exists()? {
            return Ok(false);
        }
        let conn = self.db.read()?;
        let count: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM {} WHERE key=?1", OBJECT_STORAGE_TABLE),
            params![key],
            |row| row.get(0),
        ).unwrap_or(0);
        Ok(count > 0)
    }

    /// Get all stored keys.
    pub fn get_keys(&self) -> DbResult<Vec<i64>> {
        if !self.table_exists()? {
            return Ok(Vec::new());
        }
        let conn = self.db.read()?;
        let mut stmt = conn.prepare(&format!("SELECT key FROM {} ORDER BY key", OBJECT_STORAGE_TABLE))?;
        let keys = stmt.query_map([], |row| row.get::<_, i64>(0))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(keys)
    }

    /// Clear all stored values.
    pub fn clear(&self) -> DbResult<usize> {
        if !self.table_exists()? {
            return Ok(0);
        }
        let conn = self.db.write()?;
        let rows = conn.execute(&format!("DELETE FROM {} WHERE 1=1", OBJECT_STORAGE_TABLE), [])?;
        Ok(rows)
    }

    fn get_single_col<T: rusqlite::types::FromSql>(&self, col: &str, key: i64) -> DbResult<Option<T>> {
        if !self.table_exists()? {
            return Ok(None);
        }
        let conn = self.db.read()?;
        let result = conn.query_row(
            &format!("SELECT {} FROM {} WHERE key=?1", col, OBJECT_STORAGE_TABLE),
            params![key],
            |row| row.get::<_, Option<T>>(0),
        ).unwrap_or(None);
        Ok(result)
    }

    fn table_exists(&self) -> DbResult<bool> {
        let conn = self.db.read()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            params![OBJECT_STORAGE_TABLE],
            |row| row.get(0),
        ).unwrap_or(0);
        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_storage_int() {
        let db = Database::in_memory().unwrap();
        let storage = ObjectStorageAdapter::new(&db);
        storage.put_int(1, 42).unwrap();
        assert_eq!(storage.get_int(1).unwrap(), Some(42));
        assert!(storage.has_key(1).unwrap());
        assert!(!storage.has_key(99).unwrap());
    }

    #[test]
    fn test_object_storage_long() {
        let db = Database::in_memory().unwrap();
        let storage = ObjectStorageAdapter::new(&db);
        storage.put_long(1, 0x100000000).unwrap();
        assert_eq!(storage.get_long(1).unwrap(), Some(0x100000000));
    }

    #[test]
    fn test_object_storage_string() {
        let db = Database::in_memory().unwrap();
        let storage = ObjectStorageAdapter::new(&db);
        storage.put_string(1, "hello world").unwrap();
        assert_eq!(storage.get_string(1).unwrap(), Some("hello world".to_string()));
    }

    #[test]
    fn test_object_storage_bytes() {
        let db = Database::in_memory().unwrap();
        let storage = ObjectStorageAdapter::new(&db);
        let data = vec![0x01, 0x02, 0x03];
        storage.put_bytes(1, &data).unwrap();
        assert_eq!(storage.get_bytes(1).unwrap(), Some(data));
    }

    #[test]
    fn test_object_storage_remove() {
        let db = Database::in_memory().unwrap();
        let storage = ObjectStorageAdapter::new(&db);
        storage.put_int(1, 10).unwrap();
        assert!(storage.has_key(1).unwrap());
        assert!(storage.remove(1).unwrap());
        assert!(!storage.has_key(1).unwrap());
    }

    #[test]
    fn test_object_storage_get_keys() {
        let db = Database::in_memory().unwrap();
        let storage = ObjectStorageAdapter::new(&db);
        storage.put_int(3, 30).unwrap();
        storage.put_int(1, 10).unwrap();
        storage.put_int(2, 20).unwrap();
        let keys = storage.get_keys().unwrap();
        assert_eq!(keys, vec![1, 2, 3]);
    }

    #[test]
    fn test_object_storage_clear() {
        let db = Database::in_memory().unwrap();
        let storage = ObjectStorageAdapter::new(&db);
        storage.put_int(1, 10).unwrap();
        storage.put_int(2, 20).unwrap();
        storage.clear().unwrap();
        assert_eq!(storage.get_keys().unwrap().len(), 0);
    }
}
