//! Database-backed register context storage.
//!
//! Ported from Ghidra's `ghidra.trace.database.context.DBTraceRegisterContextManager`.
//! Provides SQLite-backed persistence for register context values that
//! affect instruction decoding at specific address/snap ranges.

use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};

use crate::model::context::ContextAddressRange;
use crate::model::lifespan::Lifespan;

/// A single register context entry stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextEntry {
    /// Row ID.
    pub id: i64,
    /// The language ID.
    pub language: String,
    /// The register name.
    pub register: String,
    /// Register size in bytes.
    pub register_size: u32,
    /// The value bytes.
    pub value: Vec<u8>,
    /// Optional mask bytes.
    pub mask: Option<Vec<u8>>,
    /// Minimum snap (inclusive).
    pub min_snap: i64,
    /// Maximum snap (inclusive).
    pub max_snap: i64,
    /// Minimum address (inclusive).
    pub min_addr: u64,
    /// Maximum address (inclusive).
    pub max_addr: u64,
}

/// Database-backed register context manager.
#[derive(Debug)]
pub struct TraceDbContextManager<'a> {
    conn: &'a Connection,
}

impl<'a> TraceDbContextManager<'a> {
    /// Create a new context manager using the given connection.
    pub fn new(conn: &'a Connection) -> SqlResult<Self> {
        let mgr = Self { conn };
        mgr.create_tables()?;
        Ok(mgr)
    }

    /// Create the context tables.
    fn create_tables(&self) -> SqlResult<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS register_context (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                language TEXT NOT NULL,
                register TEXT NOT NULL,
                register_size INTEGER NOT NULL DEFAULT 1,
                value BLOB NOT NULL,
                mask BLOB,
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL,
                min_addr INTEGER NOT NULL,
                max_addr INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ctx_snap ON register_context(min_snap, max_snap);
            CREATE INDEX IF NOT EXISTS idx_ctx_addr ON register_context(min_addr, max_addr);
            CREATE INDEX IF NOT EXISTS idx_ctx_lang_reg ON register_context(language, register);
            ",
        )?;
        Ok(())
    }

    /// Set a register context value.
    pub fn set_value(
        &self,
        language: &str,
        register: &str,
        register_size: u32,
        value: &[u8],
        mask: Option<&[u8]>,
        lifespan: Lifespan,
        range: &ContextAddressRange,
    ) -> SqlResult<i64> {
        self.conn.execute(
            "INSERT INTO register_context (language, register, register_size, value, mask, min_snap, max_snap, min_addr, max_addr)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                language,
                register,
                register_size,
                value,
                mask,
                lifespan.lmin(),
                lifespan.lmax(),
                range.min as i64,
                range.max as i64,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Query register context values at a specific snap and address.
    pub fn get_value(
        &self,
        language: &str,
        register: &str,
        snap: i64,
        address: u64,
    ) -> SqlResult<Option<ContextEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, language, register, register_size, value, mask, min_snap, max_snap, min_addr, max_addr
             FROM register_context
             WHERE language = ?1 AND register = ?2
               AND min_snap <= ?3 AND max_snap >= ?3
               AND min_addr <= ?4 AND max_addr >= ?4
             ORDER BY min_snap DESC, min_addr DESC
             LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![language, register, snap, address as i64], |row| {
            Ok(ContextEntry {
                id: row.get(0)?,
                language: row.get(1)?,
                register: row.get(2)?,
                register_size: row.get(3)?,
                value: row.get(4)?,
                mask: row.get(5)?,
                min_snap: row.get(6)?,
                max_snap: row.get(7)?,
                min_addr: row.get(8)?,
                max_addr: row.get(9)?,
            })
        })?;
        match rows.next() {
            Some(Ok(entry)) => Ok(Some(entry)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// Remove all context values overlapping the given lifespan and range.
    pub fn clear(&self, lifespan: Lifespan, range: &ContextAddressRange) -> SqlResult<usize> {
        self.conn.execute(
            "DELETE FROM register_context
             WHERE min_snap <= ?1 AND max_snap >= ?2
               AND min_addr <= ?3 AND max_addr >= ?4",
            params![
                lifespan.lmax(),
                lifespan.lmin(),
                range.max as i64,
                range.min as i64,
            ],
        )
    }

    /// Get the count of stored context entries.
    pub fn count(&self) -> SqlResult<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM register_context", [], |row| row.get(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    #[test]
    fn test_create_tables() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbContextManager::new(&conn).unwrap();
        assert_eq!(mgr.count().unwrap(), 0);
    }

    #[test]
    fn test_set_and_get_value() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbContextManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 10);
        let range = ContextAddressRange::new(0x1000, 0x2000);
        mgr.set_value("x86:LE:64", "TMode", 1, &[1], None, lifespan, &range)
            .unwrap();
        assert_eq!(mgr.count().unwrap(), 1);

        let entry = mgr.get_value("x86:LE:64", "TMode", 5, 0x1500).unwrap();
        assert!(entry.is_some());
        let e = entry.unwrap();
        assert_eq!(e.value, vec![1]);
    }

    #[test]
    fn test_get_value_outside_range() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbContextManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 10);
        let range = ContextAddressRange::new(0x1000, 0x2000);
        mgr.set_value("x86:LE:64", "TMode", 1, &[1], None, lifespan, &range)
            .unwrap();

        // Outside snap range
        assert!(mgr.get_value("x86:LE:64", "TMode", 20, 0x1500).unwrap().is_none());
        // Outside address range
        assert!(mgr.get_value("x86:LE:64", "TMode", 5, 0x3000).unwrap().is_none());
        // Different language
        assert!(mgr.get_value("ARM:LE:32", "TMode", 5, 0x1500).unwrap().is_none());
    }

    #[test]
    fn test_clear() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbContextManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 10);
        let range = ContextAddressRange::new(0x1000, 0x2000);
        mgr.set_value("x86:LE:64", "TMode", 1, &[1], None, lifespan, &range)
            .unwrap();
        assert_eq!(mgr.count().unwrap(), 1);
        mgr.clear(lifespan, &range).unwrap();
        assert_eq!(mgr.count().unwrap(), 0);
    }

    #[test]
    fn test_value_with_mask() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbContextManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 5);
        let range = ContextAddressRange::new(0x0, 0xFFFFFFFF);
        let mask = vec![0xFF, 0x0F];
        mgr.set_value(
            "ARM:LE:32",
            "CPSR",
            4,
            &[0x00, 0x00, 0x00, 0x00],
            Some(&mask),
            lifespan,
            &range,
        )
        .unwrap();

        let entry = mgr.get_value("ARM:LE:32", "CPSR", 3, 0x100).unwrap().unwrap();
        assert_eq!(entry.mask, Some(vec![0xFF, 0x0F]));
    }
}
