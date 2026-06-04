//! DBChangeSet ported from Java's `db.DBChangeSet`.

use crate::database::db::{Database, DbResult, FieldValue};
use rusqlite::params;

/// The name of the change set table.
const CHANGE_SET_TABLE: &str = "GHIDRA_CHANGE_SET";

/// Tracks changes made to the database since a baseline version.
///
/// Port of Java `db.DBChangeSet`. Stores a list of `(address, type)`
/// pairs indicating which addresses have been modified, added, or deleted.
pub struct DBChangeSet {
    /// Number of the baseline version.
    base_version: i32,
}

impl DBChangeSet {
    /// Create a new change set for the given baseline version.
    pub fn new(base_version: i32) -> Self {
        Self { base_version }
    }

    /// Ensure the change set table exists.
    pub fn ensure_table(db: &Database) -> DbResult<()> {
        let conn = db.read()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            params![CHANGE_SET_TABLE],
            |row| row.get(0),
        ).unwrap_or(0);
        if count == 0 {
            drop(conn);
            let conn = db.write()?;
            conn.execute_batch(&format!(
                "CREATE TABLE IF NOT EXISTS {} (\
                    addr INTEGER PRIMARY KEY, \
                    change_type INTEGER NOT NULL, \
                    version INTEGER NOT NULL\
                )",
                CHANGE_SET_TABLE
            ))?;
        }
        Ok(())
    }

    /// Record a change at the given address.
    pub fn add_change(&self, db: &Database, address: i64, change_type: i32) -> DbResult<()> {
        Self::ensure_table(db)?;
        let conn = db.write()?;
        conn.execute(
            &format!("INSERT OR REPLACE INTO {} (addr, change_type, version) VALUES (?1, ?2, ?3)", CHANGE_SET_TABLE),
            rusqlite::params![address, change_type, self.base_version],
        )?;
        Ok(())
    }

    /// Get all changed addresses.
    pub fn get_changed_addresses(&self, db: &Database) -> DbResult<Vec<i64>> {
        if !Self::table_exists(db)? {
            return Ok(Vec::new());
        }
        let conn = db.read()?;
        let mut stmt = conn.prepare(&format!("SELECT addr FROM {} ORDER BY addr ASC", CHANGE_SET_TABLE))?;
        let addrs = stmt.query_map([], |row| row.get::<_, i64>(0))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(addrs)
    }

    /// Check if an address has been changed.
    pub fn is_changed(&self, db: &Database, address: i64) -> DbResult<bool> {
        if !Self::table_exists(db)? {
            return Ok(false);
        }
        let conn = db.read()?;
        let count: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM {} WHERE addr=?1", CHANGE_SET_TABLE),
            params![address],
            |row| row.get(0),
        ).unwrap_or(0);
        Ok(count > 0)
    }

    /// Remove all change records.
    pub fn clear(&self, db: &Database) -> DbResult<usize> {
        if !Self::table_exists(db)? {
            return Ok(0);
        }
        let conn = db.write()?;
        let rows = conn.execute(&format!("DELETE FROM {} WHERE 1=1", CHANGE_SET_TABLE), [])?;
        Ok(rows)
    }

    /// Get the baseline version.
    pub fn base_version(&self) -> i32 {
        self.base_version
    }

    fn table_exists(db: &Database) -> DbResult<bool> {
        let conn = db.read()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            params![CHANGE_SET_TABLE],
            |row| row.get(0),
        ).unwrap_or(0);
        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_change_set_add_and_query() {
        let db = Database::in_memory().unwrap();
        let cs = DBChangeSet::new(1);

        cs.add_change(&db, 0x1000, 1).unwrap();
        cs.add_change(&db, 0x2000, 2).unwrap();

        assert!(cs.is_changed(&db, 0x1000).unwrap());
        assert!(cs.is_changed(&db, 0x2000).unwrap());
        assert!(!cs.is_changed(&db, 0x3000).unwrap());

        let addrs = cs.get_changed_addresses(&db).unwrap();
        assert_eq!(addrs, vec![0x1000, 0x2000]);
    }

    #[test]
    fn test_change_set_clear() {
        let db = Database::in_memory().unwrap();
        let cs = DBChangeSet::new(1);

        cs.add_change(&db, 0x1000, 1).unwrap();
        cs.clear(&db).unwrap();
        assert!(cs.get_changed_addresses(&db).unwrap().is_empty());
    }
}
