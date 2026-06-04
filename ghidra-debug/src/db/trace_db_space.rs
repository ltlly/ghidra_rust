//! Database-backed address space storage.
//!
//! Ported from Ghidra's `ghidra.trace.database.space.DBTraceSpaceManager`.
//! Provides SQLite-backed persistence for overlay address spaces in traces.

use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};

/// An overlay address space entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlaySpaceEntry {
    /// Row ID.
    pub id: i64,
    /// The overlay space name.
    pub name: String,
    /// The underlying (base) space name.
    pub base_space: String,
    /// The offset of the overlay within the base space.
    pub offset: u64,
    /// The length of the overlay.
    pub length: u64,
}

/// Database-backed address space manager.
#[derive(Debug)]
pub struct TraceDbSpaceManager<'a> {
    conn: &'a Connection,
}

impl<'a> TraceDbSpaceManager<'a> {
    /// Create a new space manager.
    pub fn new(conn: &'a Connection) -> SqlResult<Self> {
        let mgr = Self { conn };
        mgr.create_tables()?;
        Ok(mgr)
    }

    fn create_tables(&self) -> SqlResult<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS overlay_spaces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                base_space TEXT NOT NULL,
                offset INTEGER NOT NULL DEFAULT 0,
                length INTEGER NOT NULL DEFAULT 0
            );
            ",
        )?;
        Ok(())
    }

    /// Add an overlay address space.
    pub fn add_overlay(
        &self,
        name: &str,
        base_space: &str,
        offset: u64,
        length: u64,
    ) -> SqlResult<i64> {
        self.conn.execute(
            "INSERT INTO overlay_spaces (name, base_space, offset, length)
             VALUES (?1, ?2, ?3, ?4)",
            params![name, base_space, offset as i64, length as i64],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Get an overlay by name.
    pub fn get_overlay(&self, name: &str) -> SqlResult<Option<OverlaySpaceEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, base_space, offset, length FROM overlay_spaces WHERE name = ?1",
        )?;
        let mut rows = stmt.query_map(params![name], |row| {
            Ok(OverlaySpaceEntry {
                id: row.get(0)?,
                name: row.get(1)?,
                base_space: row.get(2)?,
                offset: row.get::<_, i64>(3)? as u64,
                length: row.get::<_, i64>(4)? as u64,
            })
        })?;
        match rows.next() {
            Some(Ok(e)) => Ok(Some(e)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// Delete an overlay by name.
    pub fn delete_overlay(&self, name: &str) -> SqlResult<usize> {
        self.conn
            .execute("DELETE FROM overlay_spaces WHERE name = ?1", params![name])
    }

    /// List all overlays.
    pub fn list_overlays(&self) -> SqlResult<Vec<OverlaySpaceEntry>> {
        let mut stmt =
            self.conn.prepare("SELECT id, name, base_space, offset, length FROM overlay_spaces")?;
        let rows = stmt.query_map([], |row| {
            Ok(OverlaySpaceEntry {
                id: row.get(0)?,
                name: row.get(1)?,
                base_space: row.get(2)?,
                offset: row.get::<_, i64>(3)? as u64,
                length: row.get::<_, i64>(4)? as u64,
            })
        })?;
        rows.collect()
    }

    /// Count overlays.
    pub fn count(&self) -> SqlResult<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM overlay_spaces", [], |row| row.get(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    #[test]
    fn test_add_overlay() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbSpaceManager::new(&conn).unwrap();
        let id = mgr.add_overlay("MyOverlay", "ram", 0x1000, 0x2000).unwrap();
        assert_eq!(id, 1);
        assert_eq!(mgr.count().unwrap(), 1);
    }

    #[test]
    fn test_get_overlay() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbSpaceManager::new(&conn).unwrap();
        mgr.add_overlay("MyOverlay", "ram", 0x1000, 0x2000).unwrap();
        let entry = mgr.get_overlay("MyOverlay").unwrap().unwrap();
        assert_eq!(entry.base_space, "ram");
        assert_eq!(entry.offset, 0x1000);
    }

    #[test]
    fn test_delete_overlay() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbSpaceManager::new(&conn).unwrap();
        mgr.add_overlay("MyOverlay", "ram", 0x1000, 0x2000).unwrap();
        mgr.delete_overlay("MyOverlay").unwrap();
        assert_eq!(mgr.count().unwrap(), 0);
    }

    #[test]
    fn test_list_overlays() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbSpaceManager::new(&conn).unwrap();
        mgr.add_overlay("O1", "ram", 0x1000, 0x1000).unwrap();
        mgr.add_overlay("O2", "ram", 0x2000, 0x1000).unwrap();
        let overlays = mgr.list_overlays().unwrap();
        assert_eq!(overlays.len(), 2);
    }
}
