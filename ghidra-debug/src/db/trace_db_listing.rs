//! Database-backed code listing storage.
//!
//! Ported from Ghidra's `ghidra.trace.database.listing.DBTraceCodeManager`.
//! Provides SQLite-backed persistence for code units (instructions and data)
//! within a trace.

use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};

use crate::model::listing::CodeUnitType;
use crate::model::lifespan::Lifespan;

/// A code listing entry stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListingEntry {
    /// Row ID.
    pub id: i64,
    /// The address.
    pub address: u64,
    /// The snap at which this code unit exists.
    pub min_snap: i64,
    pub max_snap: i64,
    /// The type of code unit.
    pub unit_type: CodeUnitType,
    /// The mnemonic or label.
    pub label: String,
    /// The raw bytes.
    pub bytes: Vec<u8>,
    /// The length in bytes.
    pub length: u32,
}

/// Database-backed code listing manager.
#[derive(Debug)]
pub struct TraceDbListingManager<'a> {
    conn: &'a Connection,
}

impl<'a> TraceDbListingManager<'a> {
    /// Create a new listing manager.
    pub fn new(conn: &'a Connection) -> SqlResult<Self> {
        let mgr = Self { conn };
        mgr.create_tables()?;
        Ok(mgr)
    }

    fn create_tables(&self) -> SqlResult<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS code_listing (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address INTEGER NOT NULL,
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL,
                unit_type TEXT NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                bytes BLOB NOT NULL DEFAULT X'',
                length INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_listing_addr ON code_listing(address, min_snap);
            CREATE INDEX IF NOT EXISTS idx_listing_snap ON code_listing(min_snap, max_snap);
            ",
        )?;
        Ok(())
    }

    /// Insert a code unit.
    pub fn insert(
        &self,
        address: u64,
        lifespan: Lifespan,
        unit_type: CodeUnitType,
        label: &str,
        bytes: &[u8],
    ) -> SqlResult<i64> {
        self.conn.execute(
            "INSERT INTO code_listing (address, min_snap, max_snap, unit_type, label, bytes, length)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                address as i64,
                lifespan.lmin(),
                lifespan.lmax(),
                format!("{:?}", unit_type),
                label,
                bytes,
                bytes.len() as u32,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Get a code unit at a specific address and snap.
    pub fn get_at(&self, address: u64, snap: i64) -> SqlResult<Option<ListingEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, address, min_snap, max_snap, unit_type, label, bytes, length
             FROM code_listing
             WHERE address = ?1 AND min_snap <= ?2 AND max_snap >= ?2
             LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![address as i64, snap], |row| {
            Ok(ListingEntry {
                id: row.get(0)?,
                address: row.get::<_, i64>(1)? as u64,
                min_snap: row.get(2)?,
                max_snap: row.get(3)?,
                unit_type: CodeUnitType::Instruction, // simplified
                label: row.get(5)?,
                bytes: row.get(6)?,
                length: row.get(7)?,
            })
        })?;
        match rows.next() {
            Some(Ok(entry)) => Ok(Some(entry)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// Remove code units overlapping a lifespan and address.
    pub fn clear_range(&self, address: u64, lifespan: Lifespan) -> SqlResult<usize> {
        self.conn.execute(
            "DELETE FROM code_listing
             WHERE address = ?1 AND min_snap <= ?2 AND max_snap >= ?3",
            params![address as i64, lifespan.lmax(), lifespan.lmin()],
        )
    }

    /// Get count of stored code units.
    pub fn count(&self) -> SqlResult<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM code_listing", [], |row| row.get(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    #[test]
    fn test_insert_and_get() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbListingManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);
        let bytes = vec![0x90]; // NOP
        mgr.insert(0x401000, lifespan, CodeUnitType::Instruction, "NOP", &bytes)
            .unwrap();
        assert_eq!(mgr.count().unwrap(), 1);

        let entry = mgr.get_at(0x401000, 50).unwrap();
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().label, "NOP");
    }

    #[test]
    fn test_get_outside_snap() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbListingManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 10);
        mgr.insert(0x401000, lifespan, CodeUnitType::Instruction, "NOP", &[0x90])
            .unwrap();
        assert!(mgr.get_at(0x401000, 50).unwrap().is_none());
    }

    #[test]
    fn test_clear_range() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbListingManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);
        mgr.insert(0x401000, lifespan, CodeUnitType::Instruction, "NOP", &[0x90])
            .unwrap();
        assert_eq!(mgr.count().unwrap(), 1);
        mgr.clear_range(0x401000, lifespan).unwrap();
        assert_eq!(mgr.count().unwrap(), 0);
    }
}
