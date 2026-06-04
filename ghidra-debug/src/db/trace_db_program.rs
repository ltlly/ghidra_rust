//! Database-backed program view manager.
//!
//! Ported from Ghidra's `ghidra.trace.database.program.DBTraceProgramManager`.
//! Provides SQLite-backed management of program views for traces.

use rusqlite::{Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};

use crate::model::program::TraceProgramView;

/// Database-backed program manager.
#[derive(Debug)]
pub struct TraceDbProgramManager<'a> {
    conn: &'a Connection,
    /// The current program view snap.
    current_snap: i64,
}

impl<'a> TraceDbProgramManager<'a> {
    /// Create a new program manager.
    pub fn new(conn: &'a Connection) -> SqlResult<Self> {
        let mgr = Self {
            conn,
            current_snap: 0,
        };
        mgr.create_tables()?;
        Ok(mgr)
    }

    fn create_tables(&self) -> SqlResult<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS program_views (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                trace_id TEXT NOT NULL,
                snap INTEGER NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
            ",
        )?;
        Ok(())
    }

    /// Record a program view creation.
    pub fn record_view(&self, trace_id: &str, snap: i64) -> SqlResult<i64> {
        self.conn.execute(
            "INSERT INTO program_views (trace_id, snap) VALUES (?1, ?2)",
            rusqlite::params![trace_id, snap],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Get the current snap.
    pub fn current_snap(&self) -> i64 {
        self.current_snap
    }

    /// Set the current snap.
    pub fn set_current_snap(&mut self, snap: i64) {
        self.current_snap = snap;
    }

    /// Count recorded views.
    pub fn count(&self) -> SqlResult<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM program_views", [], |row| row.get(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn test_program_manager() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbProgramManager::new(&conn).unwrap();
        assert_eq!(mgr.current_snap(), 0);
        assert_eq!(mgr.count().unwrap(), 0);
    }

    #[test]
    fn test_record_view() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbProgramManager::new(&conn).unwrap();
        mgr.record_view("trace1", 5).unwrap();
        assert_eq!(mgr.count().unwrap(), 1);
    }

    #[test]
    fn test_set_snap() {
        let conn = Connection::open_in_memory().unwrap();
        let mut mgr = TraceDbProgramManager::new(&conn).unwrap();
        mgr.set_current_snap(10);
        assert_eq!(mgr.current_snap(), 10);
    }
}
