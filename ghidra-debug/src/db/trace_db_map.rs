//! Database-backed address mapping storage.
//!
//! Ported from Ghidra's `ghidra.trace.database.map.DBTraceAddressMapManager`.
//! Provides SQLite-backed persistence for static-to-dynamic address mappings.

use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};

use crate::model::lifespan::Lifespan;

/// A mapping entry between static and dynamic addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressMapEntry {
    /// Row ID.
    pub id: i64,
    /// The static (program) address.
    pub static_addr: u64,
    /// The dynamic (trace) address.
    pub dynamic_addr: u64,
    /// The length of the mapped region.
    pub length: u64,
    /// The snap range for this mapping.
    pub min_snap: i64,
    pub max_snap: i64,
}

/// Database-backed address map manager.
#[derive(Debug)]
pub struct TraceDbMapManager<'a> {
    conn: &'a Connection,
}

impl<'a> TraceDbMapManager<'a> {
    /// Create a new map manager.
    pub fn new(conn: &'a Connection) -> SqlResult<Self> {
        let mgr = Self { conn };
        mgr.create_tables()?;
        Ok(mgr)
    }

    fn create_tables(&self) -> SqlResult<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS address_map (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                static_addr INTEGER NOT NULL,
                dynamic_addr INTEGER NOT NULL,
                length INTEGER NOT NULL DEFAULT 1,
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_map_static ON address_map(static_addr, min_snap);
            CREATE INDEX IF NOT EXISTS idx_map_dynamic ON address_map(dynamic_addr, min_snap);
            ",
        )?;
        Ok(())
    }

    /// Add an address mapping.
    pub fn add_mapping(
        &self,
        static_addr: u64,
        dynamic_addr: u64,
        length: u64,
        lifespan: Lifespan,
    ) -> SqlResult<i64> {
        self.conn.execute(
            "INSERT INTO address_map (static_addr, dynamic_addr, length, min_snap, max_snap)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                static_addr as i64,
                dynamic_addr as i64,
                length as i64,
                lifespan.lmin(),
                lifespan.lmax(),
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Look up the dynamic address for a static address at a given snap.
    pub fn get_dynamic(&self, static_addr: u64, snap: i64) -> SqlResult<Option<AddressMapEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, static_addr, dynamic_addr, length, min_snap, max_snap
             FROM address_map
             WHERE static_addr <= ?1 AND static_addr + length > ?1
               AND min_snap <= ?2 AND max_snap >= ?2
             LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![static_addr as i64, snap], |row| {
            Ok(AddressMapEntry {
                id: row.get(0)?,
                static_addr: row.get::<_, i64>(1)? as u64,
                dynamic_addr: row.get::<_, i64>(2)? as u64,
                length: row.get::<_, i64>(3)? as u64,
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

    /// Look up the static address for a dynamic address at a given snap.
    pub fn get_static(&self, dynamic_addr: u64, snap: i64) -> SqlResult<Option<AddressMapEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, static_addr, dynamic_addr, length, min_snap, max_snap
             FROM address_map
             WHERE dynamic_addr <= ?1 AND dynamic_addr + length > ?1
               AND min_snap <= ?2 AND max_snap >= ?2
             LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![dynamic_addr as i64, snap], |row| {
            Ok(AddressMapEntry {
                id: row.get(0)?,
                static_addr: row.get::<_, i64>(1)? as u64,
                dynamic_addr: row.get::<_, i64>(2)? as u64,
                length: row.get::<_, i64>(3)? as u64,
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

    /// Remove mappings overlapping a lifespan.
    pub fn clear(&self, lifespan: Lifespan) -> SqlResult<usize> {
        self.conn.execute(
            "DELETE FROM address_map WHERE min_snap <= ?1 AND max_snap >= ?2",
            params![lifespan.lmax(), lifespan.lmin()],
        )
    }

    /// Count of stored mappings.
    pub fn count(&self) -> SqlResult<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM address_map", [], |row| row.get(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    #[test]
    fn test_add_and_lookup() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbMapManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);
        mgr.add_mapping(0x00400000, 0x7FF00000, 0x1000, lifespan)
            .unwrap();
        assert_eq!(mgr.count().unwrap(), 1);

        let entry = mgr.get_dynamic(0x00400100, 50).unwrap().unwrap();
        assert_eq!(entry.dynamic_addr, 0x7FF00000);
        assert_eq!(entry.static_addr, 0x00400000);
    }

    #[test]
    fn test_reverse_lookup() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbMapManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);
        mgr.add_mapping(0x00400000, 0x7FF00000, 0x1000, lifespan)
            .unwrap();

        let entry = mgr.get_static(0x7FF00050, 50).unwrap().unwrap();
        assert_eq!(entry.static_addr, 0x00400000);
    }

    #[test]
    fn test_outside_snap() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbMapManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 10);
        mgr.add_mapping(0x00400000, 0x7FF00000, 0x1000, lifespan)
            .unwrap();
        assert!(mgr.get_dynamic(0x00400100, 50).unwrap().is_none());
    }

    #[test]
    fn test_clear() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbMapManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);
        mgr.add_mapping(0x00400000, 0x7FF00000, 0x1000, lifespan)
            .unwrap();
        mgr.clear(lifespan).unwrap();
        assert_eq!(mgr.count().unwrap(), 0);
    }
}
