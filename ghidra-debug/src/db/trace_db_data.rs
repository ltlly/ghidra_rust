//! Database-backed data type storage.
//!
//! Ported from Ghidra's `ghidra.trace.database.data` package.
//! Provides SQLite-backed persistence for data definitions in trace listing.

use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};

use crate::model::lifespan::Lifespan;

/// A data definition entry in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataEntry {
    /// Row ID.
    pub id: i64,
    /// The address where this data is defined.
    pub address: u64,
    /// The data type name.
    pub type_name: String,
    /// The data type size in bytes.
    pub type_size: u32,
    /// The snap range.
    pub min_snap: i64,
    pub max_snap: i64,
}

/// Database-backed data definition manager.
#[derive(Debug)]
pub struct TraceDbDataManager<'a> {
    conn: &'a Connection,
}

impl<'a> TraceDbDataManager<'a> {
    /// Create a new data manager.
    pub fn new(conn: &'a Connection) -> SqlResult<Self> {
        let mgr = Self { conn };
        mgr.create_tables()?;
        Ok(mgr)
    }

    fn create_tables(&self) -> SqlResult<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS data_definitions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address INTEGER NOT NULL,
                type_name TEXT NOT NULL,
                type_size INTEGER NOT NULL DEFAULT 0,
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_data_addr ON data_definitions(address, min_snap);
            ",
        )?;
        Ok(())
    }

    /// Add a data definition.
    pub fn add(
        &self,
        address: u64,
        type_name: &str,
        type_size: u32,
        lifespan: Lifespan,
    ) -> SqlResult<i64> {
        self.conn.execute(
            "INSERT INTO data_definitions (address, type_name, type_size, min_snap, max_snap)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                address as i64,
                type_name,
                type_size,
                lifespan.lmin(),
                lifespan.lmax()
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Get the data definition at an address and snap.
    pub fn get_at(&self, address: u64, snap: i64) -> SqlResult<Option<DataEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, address, type_name, type_size, min_snap, max_snap
             FROM data_definitions
             WHERE address = ?1 AND min_snap <= ?2 AND max_snap >= ?2
             LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![address as i64, snap], |row| {
            Ok(DataEntry {
                id: row.get(0)?,
                address: row.get::<_, i64>(1)? as u64,
                type_name: row.get(2)?,
                type_size: row.get(3)?,
                min_snap: row.get(4)?,
                max_snap: row.get(5)?,
            })
        })?;
        match rows.next() {
            Some(Ok(e)) => Ok(Some(e)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// Remove data definitions at an address overlapping a lifespan.
    pub fn clear_at(&self, address: u64, lifespan: Lifespan) -> SqlResult<usize> {
        self.conn.execute(
            "DELETE FROM data_definitions
             WHERE address = ?1 AND min_snap <= ?2 AND max_snap >= ?3",
            params![address as i64, lifespan.lmax(), lifespan.lmin()],
        )
    }

    /// Count.
    pub fn count(&self) -> SqlResult<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM data_definitions", [], |row| row.get(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    #[test]
    fn test_add_and_get() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbDataManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);
        mgr.add(0x401000, "dword", 4, lifespan).unwrap();
        assert_eq!(mgr.count().unwrap(), 1);

        let entry = mgr.get_at(0x401000, 50).unwrap().unwrap();
        assert_eq!(entry.type_name, "dword");
        assert_eq!(entry.type_size, 4);
    }

    #[test]
    fn test_get_outside_snap() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbDataManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 10);
        mgr.add(0x401000, "byte", 1, lifespan).unwrap();
        assert!(mgr.get_at(0x401000, 50).unwrap().is_none());
    }

    #[test]
    fn test_clear() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbDataManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);
        mgr.add(0x401000, "qword", 8, lifespan).unwrap();
        mgr.clear_at(0x401000, lifespan).unwrap();
        assert_eq!(mgr.count().unwrap(), 0);
    }
}
