//! Database-backed stack frame storage.
//!
//! Ported from Ghidra's `ghidra.trace.database.stack.DBTraceStackManager`.
//! Provides SQLite-backed persistence for stack frames within a trace.

use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};

use crate::model::lifespan::Lifespan;
use crate::model::stack::{TraceStack, TraceStackFrame};

/// A stack frame entry stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrameEntry {
    /// Row ID.
    pub id: i64,
    /// The thread key this stack belongs to.
    pub thread_key: i64,
    /// Frame level (0 = innermost).
    pub level: u32,
    /// Program counter (return address for non-zero levels).
    pub pc: u64,
    /// Stack pointer.
    pub sp: u64,
    /// Frame pointer.
    pub fp: u64,
    /// The snap range.
    pub min_snap: i64,
    pub max_snap: i64,
}

/// Database-backed stack manager.
#[derive(Debug)]
pub struct TraceDbStackManager<'a> {
    conn: &'a Connection,
}

impl<'a> TraceDbStackManager<'a> {
    /// Create a new stack manager.
    pub fn new(conn: &'a Connection) -> SqlResult<Self> {
        let mgr = Self { conn };
        mgr.create_tables()?;
        Ok(mgr)
    }

    fn create_tables(&self) -> SqlResult<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS stack_frames (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                thread_key INTEGER NOT NULL,
                level INTEGER NOT NULL DEFAULT 0,
                pc INTEGER NOT NULL DEFAULT 0,
                sp INTEGER NOT NULL DEFAULT 0,
                fp INTEGER NOT NULL DEFAULT 0,
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_stack_thread ON stack_frames(thread_key, min_snap);
            ",
        )?;
        Ok(())
    }

    /// Add a stack frame.
    pub fn add_frame(
        &self,
        thread_key: i64,
        level: u32,
        pc: u64,
        sp: u64,
        fp: u64,
        lifespan: Lifespan,
    ) -> SqlResult<i64> {
        self.conn.execute(
            "INSERT INTO stack_frames (thread_key, level, pc, sp, fp, min_snap, max_snap)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                thread_key,
                level,
                pc as i64,
                sp as i64,
                fp as i64,
                lifespan.lmin(),
                lifespan.lmax()
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Get stack frames for a thread at a given snap.
    pub fn get_frames(&self, thread_key: i64, snap: i64) -> SqlResult<Vec<StackFrameEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, thread_key, level, pc, sp, fp, min_snap, max_snap
             FROM stack_frames
             WHERE thread_key = ?1 AND min_snap <= ?2 AND max_snap >= ?2
             ORDER BY level ASC",
        )?;
        let rows = stmt.query_map(params![thread_key, snap], |row| {
            Ok(StackFrameEntry {
                id: row.get(0)?,
                thread_key: row.get(1)?,
                level: row.get(2)?,
                pc: row.get::<_, i64>(3)? as u64,
                sp: row.get::<_, i64>(4)? as u64,
                fp: row.get::<_, i64>(5)? as u64,
                min_snap: row.get(6)?,
                max_snap: row.get(7)?,
            })
        })?;
        rows.collect()
    }

    /// Count frames.
    pub fn count(&self) -> SqlResult<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM stack_frames", [], |row| row.get(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    #[test]
    fn test_add_frame() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbStackManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);
        mgr.add_frame(1, 0, 0x401000, 0x7FFE0000, 0x7FFE0010, lifespan)
            .unwrap();
        assert_eq!(mgr.count().unwrap(), 1);
    }

    #[test]
    fn test_get_frames() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbStackManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);
        mgr.add_frame(1, 0, 0x401000, 0x7FFE0000, 0x7FFE0010, lifespan).unwrap();
        mgr.add_frame(1, 1, 0x400F00, 0x7FFE0020, 0x7FFE0030, lifespan).unwrap();
        let frames = mgr.get_frames(1, 50).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].level, 0);
        assert_eq!(frames[1].level, 1);
    }

    #[test]
    fn test_no_frames_outside_snap() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbStackManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 10);
        mgr.add_frame(1, 0, 0x401000, 0x7FFE0000, 0x7FFE0010, lifespan).unwrap();
        assert!(mgr.get_frames(1, 50).unwrap().is_empty());
    }
}
