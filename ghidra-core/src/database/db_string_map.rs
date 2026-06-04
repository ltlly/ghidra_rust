//! String-to-string map adapter ported from Java's `DBStringMapAdapter`.
//!
//! Provides a named key-value map backed by a single-column SQLite table
//! (Key TEXT PRIMARY KEY, Value TEXT).  Used for program options, compiler
//! spec extensions, and other string-indexed metadata.

use crate::database::db::{Database, DbError, DbResult, Field, FieldType, Schema};
use std::collections::HashMap;
use std::fmt;

// ============================================================================
// DBStringMapAdapter (port of Java DBStringMapAdapter)
// ============================================================================

/// A simple string-to-string map backed by a database table.
///
/// Port of Java `ghidra.program.database.DBStringMapAdapter`.
///
/// Schema: `Key TEXT PRIMARY KEY, Value TEXT`.
#[derive(Debug)]
pub struct DBStringMapAdapter {
    /// The name of the backing table.
    table_name: String,
}

impl DBStringMapAdapter {
    /// Table name suffix used for the value column.
    const VALUE_COL: &'static str = "Value";
    const KEY_COL: &'static str = "Key";

    /// Create a new adapter, creating the backing table if `create` is true.
    ///
    /// Port of Java `DBStringMapAdapter(DBHandle, String, boolean)`.
    pub fn new(db: &mut Database, table_name: &str, create: bool) -> DbResult<Self> {
        if create {
            let schema = Self::make_schema(table_name);
            db.create_table(schema)?;
        } else if !db.table_exists(table_name)? {
            return Err(DbError::NotFound(format!(
                "Table not found: {}",
                table_name
            )));
        }
        Ok(Self {
            table_name: table_name.to_string(),
        })
    }

    fn make_schema(table_name: &str) -> Schema {
        Schema::new(table_name, 0)
            .with_field(Field::new(Self::KEY_COL, FieldType::String).primary_key())
            .with_field(Field::new(Self::VALUE_COL, FieldType::String))
    }

    /// Return the backing table name.
    pub fn table_name(&self) -> &str {
        &self.table_name
    }

    /// Get the value associated with `key`, or `None` if absent.
    ///
    /// Port of Java `DBStringMapAdapter.getString(String)`.
    pub fn get(&self, db: &Database, key: &str) -> DbResult<Option<String>> {
        let sql = format!(
            "SELECT {} FROM {} WHERE {} = ?1",
            Self::VALUE_COL,
            self.table_name,
            Self::KEY_COL,
        );
        let result: Option<String> = db.query_map(
            &sql,
            &[crate::database::db::FieldValue::String(key.to_string())],
            |row| row.get::<_, String>(0),
        )?.into_iter().next();
        Ok(result)
    }

    /// Store a key-value pair (insert or replace).
    ///
    /// Port of Java `DBStringMapAdapter.setString(String, String)`.
    pub fn put(&self, db: &Database, key: &str, value: &str) -> DbResult<usize> {
        let sql = format!(
            "INSERT OR REPLACE INTO {} ({}, {}) VALUES (?1, ?2)",
            self.table_name,
            Self::KEY_COL,
            Self::VALUE_COL,
        );
        db.execute(
            &sql,
            &[
                crate::database::db::FieldValue::String(key.to_string()),
                crate::database::db::FieldValue::String(value.to_string()),
            ],
        )
    }

    /// Remove a key-value pair.  Returns true if a row was deleted.
    ///
    /// Port of Java `DBStringMapAdapter.remove(String)`.
    pub fn remove(&self, db: &Database, key: &str) -> DbResult<bool> {
        let sql = format!("DELETE FROM {} WHERE {} = ?1", self.table_name, Self::KEY_COL);
        let rows = db.execute(
            &sql,
            &[crate::database::db::FieldValue::String(key.to_string())],
        )?;
        Ok(rows > 0)
    }

    /// Return true if the map contains the given key.
    pub fn contains_key(&self, db: &Database, key: &str) -> DbResult<bool> {
        let sql = format!(
            "SELECT COUNT(*) FROM {} WHERE {} = ?1",
            self.table_name,
            Self::KEY_COL,
        );
        let count: i64 = db.query_map(
            &sql,
            &[crate::database::db::FieldValue::String(key.to_string())],
            |row| row.get::<_, i64>(0),
        )?.into_iter().next().unwrap_or(0);
        Ok(count > 0)
    }

    /// Return all keys stored in the map.
    ///
    /// Port of Java `DBStringMapAdapter.getStringKeys()`.
    pub fn keys(&self, db: &Database) -> DbResult<Vec<String>> {
        let sql = format!("SELECT {} FROM {} ORDER BY {}", Self::KEY_COL, self.table_name, Self::KEY_COL);
        db.query_map(&sql, &[], |row| row.get::<_, String>(0))
    }

    /// Return all key-value pairs.
    pub fn entries(&self, db: &Database) -> DbResult<HashMap<String, String>> {
        let sql = format!(
            "SELECT {}, {} FROM {} ORDER BY {}",
            Self::KEY_COL,
            Self::VALUE_COL,
            self.table_name,
            Self::KEY_COL,
        );
        let pairs: Vec<(String, String)> = db.query_map(&sql, &[], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        Ok(pairs.into_iter().collect())
    }

    /// Return the number of entries.
    pub fn len(&self, db: &Database) -> DbResult<usize> {
        let sql = format!("SELECT COUNT(*) FROM {}", self.table_name);
        let count: i64 = db.query_map(&sql, &[], |row| row.get::<_, i64>(0))?
            .into_iter()
            .next()
            .unwrap_or(0);
        Ok(count as usize)
    }

    /// Return true if the map has no entries.
    pub fn is_empty(&self, db: &Database) -> DbResult<bool> {
        Ok(self.len(db)? == 0)
    }

    /// Remove all entries from the map.
    pub fn clear(&self, db: &Database) -> DbResult<usize> {
        let sql = format!("DELETE FROM {}", self.table_name);
        db.execute(&sql, &[])
    }
}

impl fmt::Display for DBStringMapAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DBStringMapAdapter(table={})", self.table_name)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_put_get() {
        let mut db = Database::in_memory().unwrap();
        let adapter = DBStringMapAdapter::new(&mut db, "test_map", true).unwrap();

        adapter.put(&mut db, "key1", "value1").unwrap();
        adapter.put(&mut db, "key2", "value2").unwrap();
        adapter.put(&mut db, "key3", "value3").unwrap();

        assert_eq!(adapter.get(&db, "key1").unwrap(), Some("value1".into()));
        assert_eq!(adapter.get(&db, "key2").unwrap(), Some("value2".into()));
        assert_eq!(adapter.get(&db, "missing").unwrap(), None);
    }

    #[test]
    fn test_overwrite() {
        let mut db = Database::in_memory().unwrap();
        let adapter = DBStringMapAdapter::new(&mut db, "ov_map", true).unwrap();

        adapter.put(&mut db, "k", "old").unwrap();
        assert_eq!(adapter.get(&db, "k").unwrap(), Some("old".into()));
        adapter.put(&mut db, "k", "new").unwrap();
        assert_eq!(adapter.get(&db, "k").unwrap(), Some("new".into()));
    }

    #[test]
    fn test_remove() {
        let mut db = Database::in_memory().unwrap();
        let adapter = DBStringMapAdapter::new(&mut db, "rm_map", true).unwrap();

        adapter.put(&mut db, "k", "v").unwrap();
        assert!(adapter.contains_key(&db, "k").unwrap());
        assert!(adapter.remove(&mut db, "k").unwrap());
        assert!(!adapter.contains_key(&db, "k").unwrap());
        assert!(!adapter.remove(&mut db, "k").unwrap()); // nothing to remove
    }

    #[test]
    fn test_keys_and_entries() {
        let mut db = Database::in_memory().unwrap();
        let adapter = DBStringMapAdapter::new(&mut db, "ke_map", true).unwrap();

        adapter.put(&mut db, "a", "1").unwrap();
        adapter.put(&mut db, "b", "2").unwrap();
        adapter.put(&mut db, "c", "3").unwrap();

        let keys = adapter.keys(&db).unwrap();
        assert_eq!(keys, vec!["a", "b", "c"]);

        let entries = adapter.entries(&db).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries.get("a").unwrap(), "1");
    }

    #[test]
    fn test_len_and_clear() {
        let mut db = Database::in_memory().unwrap();
        let adapter = DBStringMapAdapter::new(&mut db, "lc_map", true).unwrap();

        assert!(adapter.is_empty(&db).unwrap());
        assert_eq!(adapter.len(&db).unwrap(), 0);

        adapter.put(&mut db, "x", "y").unwrap();
        assert_eq!(adapter.len(&db).unwrap(), 1);

        adapter.clear(&db).unwrap();
        assert!(adapter.is_empty(&db).unwrap());
    }

    #[test]
    fn test_table_not_found() {
        let mut db = Database::in_memory().unwrap();
        let result = DBStringMapAdapter::new(&mut db, "nonexistent", false);
        assert!(result.is_err());
    }
}
