//! Database parameters ported from Java's `db.DBParms`.
//!
//! Provides [`DatabaseParms`], which stores database-level configuration
//! parameters in a dedicated SQLite table.

use crate::database::db::{Database, DbResult};
use rusqlite::params;

/// The name of the parameters table.
const DB_PARMS_TABLE: &str = "GHIDRA_DB_PARMS";

/// Key for the master table root buffer ID parameter.
pub const MASTER_TABLE_ROOT_BUFFER_ID_KEY: &str = "master_table_root_buffer_id";
/// Key for the database ID (high 32 bits).
pub const DATABASE_ID_HIGH_KEY: &str = "database_id_high";
/// Key for the database ID (low 32 bits).
pub const DATABASE_ID_LOW_KEY: &str = "database_id_low";

/// Stores and retrieves database-level configuration parameters.
///
/// Port of Java `db.DBParms`.
pub struct DatabaseParms;

impl DatabaseParms {
    /// Ensure the parameters table exists.
    pub fn ensure_table(db: &Database) -> DbResult<()> {
        let conn = db.read()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            params![DB_PARMS_TABLE],
            |row| row.get(0),
        ).unwrap_or(0);
        if count == 0 {
            drop(conn);
            let conn = db.write()?;
            conn.execute_batch(&format!(
                "CREATE TABLE IF NOT EXISTS {} (\
                    key TEXT PRIMARY KEY, \
                    int_val INTEGER, \
                    long_val INTEGER, \
                    str_val TEXT\
                )",
                DB_PARMS_TABLE
            ))?;
        }
        Ok(())
    }

    /// Set an integer parameter.
    pub fn set_int(db: &Database, key: &str, value: i32) -> DbResult<()> {
        Self::ensure_table(db)?;
        let conn = db.write()?;
        conn.execute(
            &format!("INSERT OR REPLACE INTO {} (key, int_val) VALUES (?1, ?2)", DB_PARMS_TABLE),
            params![key, value],
        )?;
        Ok(())
    }

    /// Get an integer parameter.
    pub fn get_int(db: &Database, key: &str) -> DbResult<Option<i32>> {
        if !Self::table_exists(db)? {
            return Ok(None);
        }
        let conn = db.read()?;
        let result = conn.query_row(
            &format!("SELECT int_val FROM {} WHERE key=?1", DB_PARMS_TABLE),
            params![key],
            |row| row.get::<_, Option<i32>>(0),
        ).unwrap_or(None);
        Ok(result)
    }

    /// Set a long parameter.
    pub fn set_long(db: &Database, key: &str, value: i64) -> DbResult<()> {
        Self::ensure_table(db)?;
        let conn = db.write()?;
        conn.execute(
            &format!("INSERT OR REPLACE INTO {} (key, long_val) VALUES (?1, ?2)", DB_PARMS_TABLE),
            params![key, value],
        )?;
        Ok(())
    }

    /// Get a long parameter.
    pub fn get_long(db: &Database, key: &str) -> DbResult<Option<i64>> {
        if !Self::table_exists(db)? {
            return Ok(None);
        }
        let conn = db.read()?;
        let result = conn.query_row(
            &format!("SELECT long_val FROM {} WHERE key=?1", DB_PARMS_TABLE),
            params![key],
            |row| row.get::<_, Option<i64>>(0),
        ).unwrap_or(None);
        Ok(result)
    }

    /// Set a string parameter.
    pub fn set_string(db: &Database, key: &str, value: &str) -> DbResult<()> {
        Self::ensure_table(db)?;
        let conn = db.write()?;
        conn.execute(
            &format!("INSERT OR REPLACE INTO {} (key, str_val) VALUES (?1, ?2)", DB_PARMS_TABLE),
            params![key, value],
        )?;
        Ok(())
    }

    /// Get a string parameter.
    pub fn get_string(db: &Database, key: &str) -> DbResult<Option<String>> {
        if !Self::table_exists(db)? {
            return Ok(None);
        }
        let conn = db.read()?;
        let result = conn.query_row(
            &format!("SELECT str_val FROM {} WHERE key=?1", DB_PARMS_TABLE),
            params![key],
            |row| row.get::<_, Option<String>>(0),
        ).unwrap_or(None);
        Ok(result)
    }

    /// Get the database ID (combining high and low parts).
    pub fn get_database_id(db: &Database) -> DbResult<Option<i64>> {
        let high = Self::get_int(db, DATABASE_ID_HIGH_KEY)?;
        let low = Self::get_int(db, DATABASE_ID_LOW_KEY)?;
        match (high, low) {
            (Some(h), Some(l)) => Ok(Some(((h as i64) << 32) | ((l as i64) & 0xFFFFFFFF))),
            _ => Ok(None),
        }
    }

    /// Set the database ID (splitting into high and low parts).
    pub fn set_database_id(db: &Database, id: i64) -> DbResult<()> {
        Self::set_int(db, DATABASE_ID_HIGH_KEY, (id >> 32) as i32)?;
        Self::set_int(db, DATABASE_ID_LOW_KEY, id as i32)?;
        Ok(())
    }

    /// Remove a parameter.
    pub fn remove(db: &Database, key: &str) -> DbResult<bool> {
        if !Self::table_exists(db)? {
            return Ok(false);
        }
        let conn = db.write()?;
        let rows = conn.execute(
            &format!("DELETE FROM {} WHERE key=?1", DB_PARMS_TABLE),
            params![key],
        )?;
        Ok(rows > 0)
    }

    fn table_exists(db: &Database) -> DbResult<bool> {
        let conn = db.read()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            params![DB_PARMS_TABLE],
            |row| row.get(0),
        ).unwrap_or(0);
        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_parms_int() {
        let db = Database::in_memory().unwrap();
        DatabaseParms::set_int(&db, "test_key", 42).unwrap();
        assert_eq!(DatabaseParms::get_int(&db, "test_key").unwrap(), Some(42));
        assert_eq!(DatabaseParms::get_int(&db, "missing").unwrap(), None);
    }

    #[test]
    fn test_db_parms_long() {
        let db = Database::in_memory().unwrap();
        DatabaseParms::set_long(&db, "counter", 0x100000000).unwrap();
        assert_eq!(DatabaseParms::get_long(&db, "counter").unwrap(), Some(0x100000000));
    }

    #[test]
    fn test_db_parms_string() {
        let db = Database::in_memory().unwrap();
        DatabaseParms::set_string(&db, "path", "/tmp/test.db").unwrap();
        assert_eq!(
            DatabaseParms::get_string(&db, "path").unwrap(),
            Some("/tmp/test.db".to_string())
        );
    }

    #[test]
    fn test_db_parms_database_id() {
        let db = Database::in_memory().unwrap();
        DatabaseParms::set_database_id(&db, 0x1234567890ABCDEF).unwrap();
        let id = DatabaseParms::get_database_id(&db).unwrap().unwrap();
        assert_eq!(id, 0x1234567890ABCDEFu64 as i64);
    }

    #[test]
    fn test_db_parms_remove() {
        let db = Database::in_memory().unwrap();
        DatabaseParms::set_int(&db, "temp", 1).unwrap();
        assert!(DatabaseParms::remove(&db, "temp").unwrap());
        assert_eq!(DatabaseParms::get_int(&db, "temp").unwrap(), None);
    }
}
